use serde_json::Value;
#[cfg(target_os = "linux")]
use std::fs;
use std::{path::Path, process::Command};

fn invoke(home: &Path, structured: bool, action: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentfw"));
    command.args(["pilot-approval", "--run", &"a".repeat(32), "--home"]);
    command.arg(home);
    if structured {
        command.args(["--output", "json-v1"]);
    }
    command.args(action).output().unwrap()
}

fn refused(home: &Path, action: &[&str]) -> Value {
    let output = invoke(home, true, action);
    assert!(!output.status.success());
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["format"], "sw-pilot-operator-result/1");
    assert_eq!(value["operation"], action[0]);
    assert!(value["identity"].is_null());
    assert!(value["data"].is_null());
    assert_ne!(value["outcome"], "decision_submitted");
    assert_ne!(value["outcome"], "stop_confirmed");
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("private-sentinel"));
    value
}

#[test]
fn missing_run_is_a_single_safe_result_for_every_command() {
    let home = tempfile::tempdir().unwrap();
    for action in [
        vec!["list"],
        vec!["inspect", "one"],
        vec!["approve", "one", "--binding", "private-sentinel"],
        vec!["reject", "one", "--binding", "private-sentinel"],
        vec!["stop"],
    ] {
        let value = refused(home.path(), &action);
        assert_eq!(
            value["reason"],
            if cfg!(target_os = "linux") {
                "run_unavailable"
            } else {
                "unsupported_platform"
            }
        );
    }
}

#[test]
fn legacy_failure_keeps_empty_stdout_and_nonzero_exit() {
    let home = tempfile::tempdir().unwrap();
    let output = invoke(home.path(), false, &["list"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn closed_output_does_not_report_success_or_raw_error() {
    use std::process::Stdio;
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .args(["pilot-approval", "--run", &"a".repeat(32), "--home"])
        .arg(home.path())
        .args(["--output", "json-v1", "list"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(6));
    assert!(output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
fn run_dir(home: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let root = home.join("pilot-runs");
    let dir = root.join("a".repeat(32));
    fs::create_dir_all(&dir).unwrap();
    for path in [&root, &dir] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

#[test]
#[cfg(target_os = "linux")]
fn malformed_oversized_and_symlink_records_never_claim_an_identity() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for variant in ["malformed", "oversized", "symlink", "foreign"] {
        let home = tempfile::tempdir().unwrap();
        let dir = run_dir(home.path());
        let record = dir.join("run.json");
        match variant {
            "malformed" => fs::write(&record, b"{private-sentinel").unwrap(),
            "oversized" => fs::write(&record, vec![b'x'; 2 * 1024 * 1024 + 1]).unwrap(),
            "symlink" => {
                let target = home.path().join("private-sentinel");
                fs::write(&target, b"{}").unwrap();
                symlink(target, &record).unwrap();
            }
            _ => fs::write(&record, b"{\"contract\":\"private-sentinel\"}").unwrap(),
        }
        if variant != "symlink" {
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let value = refused(home.path(), &["list"]);
        assert_eq!(value["reason"], "unsafe_run_record", "{variant}");
    }
}

#[test]
#[cfg(target_os = "linux")]
fn foreign_complete_record_cannot_select_or_stop_a_process() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    let dir = run_dir(&home_path);
    let path = dir.join("run.json");
    fs::write(
        &path,
        serde_json::json!({
            "contract":"sw-pilot-run/1", "run_id":"a".repeat(32), "home":home_path,
            "instance_id":"private-sentinel", "registry_sha256":"b".repeat(64),
            "host_session":"foreign", "launcher_pid":std::process::id(), "launcher_start":1,
            "manifest_fd":3, "expires_at_ms":u64::MAX, "authority_expires_at_ms":u64::MAX,
            "authorities":{"filesystem":"c".repeat(64), "git":"d".repeat(64)}, "files":[]
        })
        .to_string(),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        refused(&home_path, &["list"])["reason"],
        "unsafe_run_record"
    );
    assert_eq!(
        refused(&home_path, &["stop"])["reason"],
        "stop_ownership_unverified"
    );
    assert!(!dir.join("stop.json").exists());
}
