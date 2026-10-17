// SPDX-License-Identifier: Apache-2.0
//! `agentfw self-test` end-to-end checks against the built binary, run from
//! outside the repository with explicit classifier inputs.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

const AGENT: &str = env!("CARGO_BIN_EXE_agentfw");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn classifier() -> PathBuf {
    repo().join("rule_baseline/rule_baseline.py")
}

fn sha(path: &Path) -> String {
    format!("{:x}", Sha256::digest(std::fs::read(path).unwrap()))
}

fn python() -> Option<PathBuf> {
    [
        "/usr/bin/python3",
        "/usr/local/bin/python3",
        "/opt/homebrew/bin/python3",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| {
        p.is_file()
            && Command::new(p)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
    })
}

struct Run {
    dir: tempfile::TempDir,
}

impl Run {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("work")).unwrap();
        Self { dir }
    }
    fn report_path(&self) -> PathBuf {
        self.dir.path().join("report.json")
    }
    fn work(&self) -> PathBuf {
        self.dir.path().join("work")
    }
    fn command(&self, python: &Path, extra: &[&str]) -> Command {
        self.command_for(Path::new(AGENT), python, extra)
    }
    fn command_for(&self, agent: &Path, python: &Path, extra: &[&str]) -> Command {
        let mut command = Command::new(AGENT);
        command
            .current_dir(self.dir.path())
            .env_remove("AGENTFW_CLASSIFIER")
            .args(["self-test", "--agent"])
            .arg(agent)
            .args(["--classifier", "rule-baseline", "--classifier-script"])
            .arg(classifier())
            .arg("--classifier-sha256")
            .arg(sha(&classifier()))
            .arg("--classifier-python")
            .arg(python)
            .arg("--report")
            .arg(self.report_path())
            .arg("--work-parent")
            .arg(self.work())
            .args(extra);
        command
    }
    fn report(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.report_path()).unwrap()).unwrap()
    }
    fn work_is_empty(&self) -> bool {
        std::fs::read_dir(self.work()).unwrap().next().is_none()
    }
}

fn statuses(report: &Value) -> Vec<String> {
    report["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["status"].as_str().unwrap().to_owned())
        .collect()
}

/// No process may still reference this run's workspace after the command exits.
fn no_owned_processes(work: &Path) -> bool {
    let needle = work.to_string_lossy().into_owned();
    let canonical = work
        .canonicalize()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| needle.clone());
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc").unwrap().flatten().all(|entry| {
            std::fs::read(entry.path().join("cmdline"))
                .map(|cmdline| {
                    let s = String::from_utf8_lossy(&cmdline);
                    !s.contains(&needle) && !s.contains(&canonical)
                })
                .unwrap_or(true)
        })
    }
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/bin/ps")
            .args(["-axww", "-o", "command="])
            .output()
            .expect("ps command failed");
        assert!(output.status.success(), "ps exit failure");
        let stdout = String::from_utf8_lossy(&output.stdout);
        !stdout
            .lines()
            .any(|line| line.contains(&needle) || line.contains(&canonical))
    }
}

#[test]
fn installed_agent_passes_every_scenario_after_a_port_collision() {
    let Some(python) = python() else {
        eprintln!("skipped: no Python 3 for the selected classifier");
        return;
    };
    let run = Run::new();
    // An unrelated listener holds the preferred port; it must be replaced, not touched.
    let busy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let busy_port = busy.local_addr().unwrap().port().to_string();
    let output = run
        .command(&python, &["--daemon-port", &busy_port])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{text}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("Result: PASSED (exit 0)"));
    let report = run.report();
    assert_eq!(report["schema_version"], "sw-self-test/1");
    assert_eq!(report["result"], "passed");
    assert_eq!(statuses(&report), vec!["passed"; 5]);
    let attempts = report["configured"]["daemon"]["start_attempts"]
        .as_array()
        .unwrap();
    assert!(attempts.len() >= 2, "{attempts:?}");
    assert_ne!(attempts[0]["outcome"], "started");
    assert_eq!(attempts.last().unwrap()["outcome"], "started");
    assert_eq!(
        report["configured"]["daemon"]["authenticated_status"]["pid_matches_owned_daemon"],
        true
    );
    let send = &report["scenarios"][2];
    assert_eq!(send["observed"]["outcome"], "invocation_refused");
    assert_eq!(send["observed"]["mcp_child_executions"], 0);
    assert_eq!(send["observed"]["receiver_connections"], 0);
    assert_eq!(send["receipts"]["native_audit"][0]["verdict"], "deny");
    assert_eq!(
        report["scenarios"][0]["observed"]["checks"]["exact_expected_bytes"],
        true
    );
    assert_eq!(
        report["scenarios"][1]["observed"]["marker_reached_client"],
        false
    );
    assert_eq!(report["scenarios"][4]["observed"]["collector_exited"], true);
    for scenario in report["scenarios"].as_array().unwrap().iter().take(4) {
        assert_eq!(
            scenario["receipts"]["classification"]["classifier_sha256_matches"],
            true
        );
    }
    assert_eq!(
        report["identities"]["classifier"]["source_sha256"],
        sha(&classifier())
    );
    assert_eq!(
        report["identities"]["agent"]["sha256"],
        sha(Path::new(AGENT))
    );
    assert_eq!(report["cleanup"]["workspace"], "removed");
    let raw = std::fs::read_to_string(run.report_path()).unwrap();
    for private in [
        "AKIAIOSFODNN7EXAMPLE",
        "SOUP-WALL-SELF-TEST-MARKER",
        run.dir.path().to_str().unwrap(),
    ] {
        assert!(!raw.contains(private), "report leaked {private}");
    }
    assert!(run.work_is_empty());
    assert!(no_owned_processes(&run.work()));
    drop(busy);
}

#[test]
fn interruption_stops_owned_processes_and_reports_incomplete() {
    let Some(python) = python() else {
        eprintln!("skipped: no Python 3 for the selected classifier");
        return;
    };
    let run = Run::new();
    let child = run
        .command(&python, &[])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Wait until the owned daemon has been launched inside the workspace.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let started = std::fs::read_dir(run.work())
            .unwrap()
            .flatten()
            .any(|ws| ws.path().join("home/.agentfw/config.yaml").exists());
        if started || Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(500));
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    let output: Output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report = run.report();
    assert_eq!(report["result"], "incomplete");
    assert!(report["explanation"]
        .as_str()
        .unwrap()
        .starts_with("Interrupted"));
    let observed = statuses(&report);
    assert!(!observed.iter().any(|s| s == "failed"), "{observed:?}");
    assert!(observed.iter().any(|s| s != "passed"), "{observed:?}");
    assert_eq!(report["cleanup"]["workspace"], "removed");
    assert!(run.work_is_empty());
    assert!(no_owned_processes(&run.work()));
}

#[test]
fn missing_or_wrong_classifier_is_incomplete_before_anything_starts() {
    let Some(python) = python() else {
        eprintln!("skipped: no Python 3 for the selected classifier");
        return;
    };
    let run = Run::new();
    let output = Command::new(AGENT)
        .args([
            "self-test",
            "--agent",
            AGENT,
            "--classifier",
            "rule-baseline",
            "--classifier-script",
        ])
        .arg(run.dir.path().join("missing.py"))
        .args([
            "--classifier-sha256",
            &"0".repeat(64),
            "--classifier-python",
        ])
        .arg(&python)
        .arg("--report")
        .arg(run.report_path())
        .arg("--work-parent")
        .arg(run.work())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let report = run.report();
    assert_eq!(report["result"], "incomplete");
    assert!(report["input_problems"][0]
        .as_str()
        .unwrap()
        .contains("--classifier-script"));
    assert_eq!(statuses(&report), vec!["unavailable"; 5]);
    assert!(run.work_is_empty());

    let wrong = Run::new();
    let output = Command::new(AGENT)
        .args([
            "self-test",
            "--agent",
            AGENT,
            "--classifier",
            "rule-baseline",
            "--classifier-script",
        ])
        .arg(classifier())
        .args([
            "--classifier-sha256",
            &"0".repeat(64),
            "--classifier-python",
        ])
        .arg(&python)
        .arg("--report")
        .arg(wrong.report_path())
        .arg("--work-parent")
        .arg(wrong.work())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let report = wrong.report();
    assert!(report["input_problems"]
        .to_string()
        .contains("wrong revision"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("Result: INCOMPLETE (exit 4)"));
}

#[test]
fn agent_without_a_working_daemon_is_incomplete_with_start_attempts() {
    let Some(python) = python() else {
        eprintln!("skipped: no Python 3 for the selected classifier");
        return;
    };
    let run = Run::new();
    // A stand-in executable that passes input validation and install, but whose daemon exits.
    let fake = run.dir.path().join("fake-agent");
    std::fs::write(&fake, "#!/bin/sh\ncase \"$1\" in\n  mcp) echo '--native-admission'; exit 0;;\n  install) mkdir -p \"$HOME/.agentfw\" && echo token > \"$HOME/.agentfw/token\"; exit 0;;\n  serve) echo 'Address already in use' >&2; exit 1;;\nesac\nexit 1\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = run
        .command_for(&fake, &python, &["--timeout-seconds", "60"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report = run.report();
    assert_eq!(report["result"], "incomplete");
    let attempts = report["configured"]["daemon"]["start_attempts"]
        .as_array()
        .unwrap();
    assert_eq!(attempts.len(), 3);
    assert!(attempts.iter().all(|a| a["outcome"] == "port_in_use"));
    assert_eq!(statuses(&report), vec!["unavailable"; 5]);
    assert_eq!(report["cleanup"]["workspace"], "removed");
    assert!(run.work_is_empty());
}

#[test]
fn existing_report_is_never_replaced() {
    let run = Run::new();
    let py = python().unwrap_or_else(|| PathBuf::from("/usr/bin/python3"));
    std::fs::write(run.report_path(), b"operator data").unwrap();
    let output = Command::new(AGENT)
        .args([
            "self-test",
            "--agent",
            AGENT,
            "--classifier",
            "rule-baseline",
            "--classifier-script",
        ])
        .arg(classifier())
        .args([
            "--classifier-sha256",
            &"0".repeat(64),
            "--classifier-python",
        ])
        .arg(&py)
        .arg("--report")
        .arg(run.report_path())
        .arg("--work-parent")
        .arg(run.work())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(std::fs::read(run.report_path()).unwrap(), b"operator data");
    assert!(String::from_utf8_lossy(&output.stderr).contains("nothing ran"));
    assert!(run.work_is_empty());
}

#[test]
fn fixture_server_refuses_destinations_other_than_its_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(AGENT)
        .args(["self-test-fixture", "--notes"])
        .arg(dir.path())
        .arg("--ledger")
        .arg(dir.path().join("l"))
        .arg("--responses")
        .arg(dir.path().join("r"))
        .args(["--recipient", "http://example.com/capture"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn no_owned_processes_witness_detects_live_process_and_clears_on_exit() {
    let Some(py) = python() else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let work = temp.path().join("work");
    std::fs::create_dir(&work).unwrap();
    assert!(no_owned_processes(&work));
    let mut child = Command::new(&py)
        .args(["-c", "import time; time.sleep(5)"])
        .arg(&work)
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !no_owned_processes(&work),
        "scanner must detect live process with work path in args"
    );
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        no_owned_processes(&work),
        "scanner must clear after process exits"
    );
}
