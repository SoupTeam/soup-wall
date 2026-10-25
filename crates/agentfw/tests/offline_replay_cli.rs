// SPDX-License-Identifier: Apache-2.0
//! Public owned synthetic CLI parity and independently calibrated effect witnesses.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soup_wall_agent::{AgentEvent, AgentFirewall, AgentPolicySet, DEFAULT_TAINT_CAP};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

const SHIPPED: &str = include_str!("../../agent/policies/agent-default.yaml");
const SEQUENCE: &str = include_str!("fixtures/offline-replay/sequence.json");
const WEAK: &str = include_str!("fixtures/offline-replay/weak-policy.yaml");
const DENY: &str = include_str!("fixtures/offline-replay/deny-policy.yaml");
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn temp() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}
fn binary() -> PathBuf {
    std::env::var_os("SOU152_AGENTFW_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_agentfw")))
}
fn cli(home: &Path) -> Command {
    let mut cmd = Command::new(binary());
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("AGENTFW_CLASSIFIER", "forged-never-start")
        .env("AGENTFW_RULE_BASELINE", "/forged-no-runtime");
    cmd
}
fn run(mut cmd: Command) -> Output {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let collect = |mut input: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut data = Vec::new();
            input
                .by_ref()
                .take(1024 * 1024 + 4096)
                .read_to_end(&mut data)
                .unwrap();
            data
        })
    };
    let out = collect(Box::new(stdout));
    let err = collect(Box::new(stderr));
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            panic!("bounded owned offline CLI timed out");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    Output {
        status,
        stdout: out.join().unwrap(),
        stderr: err.join().unwrap(),
    }
}
fn invocation(home: &Path, input: &Path, policy: &Path) -> Command {
    let mut cmd = cli(home);
    cmd.args(["replay", "--offline", "--input"])
        .arg(input)
        .arg("--policy")
        .arg(policy);
    cmd
}
fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).unwrap();
}
fn snapshot(root: &Path) -> Value {
    fn walk(root: &Path, path: &Path, rows: &mut serde_json::Map<String, Value>) {
        let meta = fs::symlink_metadata(path).unwrap();
        let mut value = json!({"directory":meta.is_dir(),"file":meta.is_file(),"bytes":meta.len()});
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            value["inode"] = json!(meta.ino());
            value["mode"] = json!(meta.mode());
        }
        if meta.is_file() {
            value["sha256"] = json!(digest(&fs::read(path).unwrap()));
        }
        rows.insert(
            path.strip_prefix(root).unwrap().to_string_lossy().into(),
            value,
        );
        if meta.is_dir() {
            for item in fs::read_dir(path).unwrap() {
                walk(root, &item.unwrap().path(), rows);
            }
        }
    }
    let mut rows = serde_json::Map::new();
    walk(root, root, &mut rows);
    json!(rows)
}

#[test]
fn offline_policy_cli_parity_and_effect_witnesses() {
    let temporary = temp();
    let root = temporary.path();
    let home = root.join("home");
    fs::create_dir(&home).unwrap();
    let input = root.join("input.json");
    write(&input, SEQUENCE);
    let policies = [("shipped", SHIPPED), ("weak", WEAK), ("deny", DENY)];
    let raw: Value = serde_json::from_str(SEQUENCE).unwrap();
    let mut cases = Vec::new();
    for (name, yaml) in policies {
        let path = root.join(format!("{name}.yaml"));
        write(&path, yaml);
        let before = snapshot(root);
        let output = run(invocation(&home, &input, &path));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let mut reference =
            AgentFirewall::new(AgentPolicySet::from_yaml(yaml).unwrap(), DEFAULT_TAINT_CAP);
        let mut traced =
            AgentFirewall::new(AgentPolicySet::from_yaml(yaml).unwrap(), DEFAULT_TAINT_CAP);
        let mut verdicts = Vec::new();
        for (index, row) in raw["events"].as_array().unwrap().iter().enumerate() {
            let event: AgentEvent = serde_json::from_value(row["event"].clone()).unwrap();
            let plain = reference.inspect(&event);
            let (observed, trace) = traced.inspect_with_trace(&event);
            assert_eq!(plain, observed, "trace changed production outcome");
            assert_eq!(
                reference.provenance_snapshot(),
                traced.provenance_snapshot()
            );
            let resolved =
                soup_wall_agent::resolution::resolve(plain.verdict, plain.fallback, false);
            let row = &report["policies"][0]["events"][index];
            assert_eq!(
                row["simulated_verdict"],
                serde_json::to_value(resolved).unwrap()
            );
            assert_eq!(
                row["trace"]["pre_resolution_verdict"],
                serde_json::to_value(plain.verdict).unwrap()
            );
            assert_eq!(
                row["trace"]["fallback"],
                serde_json::to_value(plain.fallback).unwrap()
            );
            assert_eq!(
                row["trace"]["operator_rule"]["index"].as_u64(),
                trace.unwrap().policy.operator_rule.map(|n| n as u64)
            );
            assert!(
                reference
                    .agent_tools(&event.session, &event.agent)
                    .is_none(),
                "simulation created authority"
            );
            verdicts.push(row["simulated_verdict"].clone());
        }
        assert_eq!(
            snapshot(root),
            before,
            "offline CLI mutated state or inputs"
        );
        assert_eq!(report["protection_claim"], false);
        cases.push(json!({"policy":name,"policy_sha256":digest(yaml.as_bytes()),"input_sha256":digest(SEQUENCE.as_bytes()),
            "report_sha256":digest(&output.stdout),"events":verdicts,"production_parity":true,"trace_state_parity":true,"persistent_state_unchanged":true}));
    }
    // Explicit B has its own fresh reference context; comparisons cannot carry
    // taint from the first policy's run or silently select a default policy.
    let a = root.join("shipped.yaml");
    let b = root.join("deny.yaml");
    let mut compare = invocation(&home, &input, &a);
    compare.arg("--compare-policy").arg(&b);
    let compared = run(compare);
    assert!(compared.status.success());
    let compared: Value = serde_json::from_slice(&compared.stdout).unwrap();
    assert_eq!(compared["policies"].as_array().unwrap().len(), 2);
    assert_eq!(compared["comparison"][0]["verdict_changed"], true);

    let effects = effect_witnesses(root, &home);
    let qualification = json!({"format":"sou152-offline-parity/1","scope":"public-owned-synthetic-supported-context-not-protection-rate",
        "cases":cases,"comparison":true,"effects":effects,"no_authority_created":true});
    if let Some(path) = std::env::var_os("SOU152_PARITY_REPORT") {
        let bytes = serde_json::to_vec_pretty(&qualification).unwrap();
        assert!(bytes.len() < 65536);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        options.open(path).unwrap().write_all(&bytes).unwrap();
    }
}

#[cfg(unix)]
fn effect_witnesses(root: &Path, home: &Path) -> Value {
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let state = home.join(".agentfw");
    fs::create_dir(&state).unwrap();
    for name in [
        "config.yaml",
        "audit.jsonl",
        "token",
        "grants.json",
        "sessions.json",
    ] {
        write(&state.join(name), b"owned state canary");
        assert_eq!(fs::read(state.join(name)).unwrap(), b"owned state canary");
    }
    let command = root.join("owned-command");
    let marker = root.join("command-marker");
    write(
        &command,
        b"#!/bin/sh\nprintf 'owned executed' > \"$SOU152_COMMAND_MARKER\"\n",
    );
    fs::set_permissions(&command, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(Command::new(&command)
        .env_clear()
        .env("SOU152_COMMAND_MARKER", &marker)
        .status()
        .unwrap()
        .success());
    assert_eq!(fs::read(&marker).unwrap(), b"owned executed");
    fs::remove_file(&marker).unwrap();
    let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
    receiver.set_nonblocking(true).unwrap();
    let address = receiver.local_addr().unwrap();
    drop(TcpStream::connect(address).unwrap());
    drop(receiver.accept().unwrap());
    let fifo = root.join("target-fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let reader = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    drop(
        fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap(),
    );
    drop(reader);
    let stop = Arc::new(AtomicBool::new(false));
    let opened = Arc::new(AtomicBool::new(false));
    let (stopping, observed, target) = (stop.clone(), opened.clone(), fifo.clone());
    let witness = std::thread::spawn(move || {
        while !stopping.load(Ordering::SeqCst) {
            if fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&target)
                .is_ok()
            {
                observed.store(true, Ordering::SeqCst);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let mut input: Value = serde_json::from_str(SEQUENCE).unwrap();
    let base = input["events"][0]["event"].clone();
    let mut events = Vec::new();
    for (index, (tool, args)) in [
        ("Bash", json!({"command":command})),
        ("WebFetch", json!({"url":format!("http://{address}/owned")})),
        ("Read", json!({"file_path":fifo})),
    ]
    .into_iter()
    .enumerate()
    {
        let mut event = base.clone();
        event["seq"] = json!(index + 1);
        event["tool"] = json!(tool);
        event["args"] = args;
        events.push(json!({"complete":true,"event":event}));
    }
    input["events"] = json!(events);
    let input_path = root.join("witness.json");
    write(&input_path, serde_json::to_vec(&input).unwrap());
    let policy = root.join("witness.yaml");
    write(&policy, b"default: allow\n");
    let before = snapshot(root);
    let mut cmd = invocation(home, &input_path, &policy);
    cmd.env("SOU152_COMMAND_MARKER", &marker);
    let output = run(cmd);
    stop.store(true, Ordering::SeqCst);
    witness.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists());
    assert!(!opened.load(Ordering::SeqCst), "tool target was opened");
    assert_eq!(
        receiver.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(snapshot(root), before);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["policies"][0]["events"].as_array().unwrap().len(), 3);
    let sandbox = host_sandbox(home, &input_path, &policy);
    let missing = root.join("absent-home");
    assert!(!missing.exists());
    let output = run(invocation(&missing, &input_path, &policy));
    assert!(output.status.success());
    assert!(!missing.exists());
    json!({"command_calibrated":true,"network_receiver_calibrated":true,"state_canaries_readable_control":true,
        "target_fifo_calibrated":true,"command_marker_absent":true,"network_connections":0,"target_fifo_opens":0,
        "state_and_inputs_unchanged":true,"no_home_discovery":true,"host_sandbox":sandbox})
}
#[cfg(not(unix))]
fn effect_witnesses(_: &Path, _: &Path) -> Value {
    json!({"status":"unsupported_platform"})
}

#[cfg(target_os = "macos")]
fn host_sandbox(home: &Path, input: &Path, policy: &Path) -> Value {
    let root = input.parent().unwrap();
    let profile = format!("(version 1)(allow default)(deny network*)(deny process-fork)(deny file-write*)(deny file-read* (subpath {:?}))(deny file-read* (literal {:?}))", home.to_str().unwrap(), root.join("target-fifo").to_str().unwrap());
    let sandboxed = |program: &Path, args: &[&std::ffi::OsStr]| {
        let mut cmd = Command::new("/usr/bin/sandbox-exec");
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", home)
            .args(["-p", &profile])
            .arg(program)
            .args(args);
        run(cmd)
    };
    // First distinguish an unavailable sandbox from a tested denial. Every
    // denied operation below has an independently successful owned control.
    let available = sandboxed(Path::new("/usr/bin/true"), &[]);
    if !available.status.success() {
        return json!({"status":"unavailable","exit_code":available.status.code(),"stderr_sha256":digest(&available.stderr)});
    }
    let canary = home.join(".agentfw/token");
    let write_target = root.join("sandbox-write-control");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let controls: Vec<(&str, &Path, Vec<&std::ffi::OsStr>)> = vec![
        (
            "state_read",
            Path::new("/bin/cat"),
            vec![canary.as_os_str()],
        ),
        (
            "file_write",
            Path::new("/usr/bin/touch"),
            vec![write_target.as_os_str()],
        ),
        (
            "process_fork",
            Path::new("/bin/sh"),
            vec!["-c".as_ref(), "/usr/bin/true; :".as_ref()],
        ),
        (
            "network",
            Path::new("/usr/bin/nc"),
            vec![
                "-z".as_ref(),
                "-w".as_ref(),
                "1".as_ref(),
                "127.0.0.1".as_ref(),
                port.as_ref(),
            ],
        ),
    ];
    let mut calibrated = Vec::new();
    for (name, program, args) in controls {
        let mut cmd = Command::new(program);
        cmd.env_clear().env("PATH", "/usr/bin:/bin").args(&args);
        assert!(
            run(cmd).status.success(),
            "owned sandbox positive control failed: {name}"
        );
        if write_target.exists() {
            fs::remove_file(&write_target).unwrap();
        }
        let denied = sandboxed(program, &args);
        assert!(
            !denied.status.success(),
            "sandbox did not deny calibrated {name}"
        );
        assert!(!write_target.exists());
        calibrated.push(name);
    }
    let output = sandboxed(
        &binary(),
        &[
            "replay".as_ref(),
            "--offline".as_ref(),
            "--input".as_ref(),
            input.as_os_str(),
            "--policy".as_ref(),
            policy.as_os_str(),
        ],
    );
    assert!(
        output.status.success(),
        "offline simulation failed under calibrated denials"
    );
    json!({"status":"passed","calibrated_denials":calibrated,"offline_cli_under_denials":true,"target_read_denied":true})
}
#[cfg(not(target_os = "macos"))]
fn host_sandbox(_: &Path, _: &Path, _: &Path) -> Value {
    json!({"status":"unavailable_on_this_host"})
}

#[test]
fn cli_missing_context_unsafe_io_and_legacy_replay_stay_explicit() {
    let temp = temp();
    let root = temp.path();
    let home = root.join("home");
    fs::create_dir(&home).unwrap();
    let input = root.join("input.json");
    write(
        &input,
        include_bytes!("fixtures/offline-replay/missing-context.json"),
    );
    let policy = root.join("policy.yaml");
    write(&policy, SHIPPED);
    let output = run(invocation(&home, &input, &policy));
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "incomplete");
    assert!(report["policies"][0]["events"][1]["simulated_verdict"].is_null());
    write(&input, SEQUENCE);
    // The actual CLI must retain both floors when an early rule would allow
    // or resolve Escalate through its weaker Allow fallback.
    let mut incomplete: Value = serde_json::from_str(SEQUENCE).unwrap();
    incomplete["context"]["history"] = json!("incomplete");
    write(&input, serde_json::to_vec(&incomplete).unwrap());
    for yaml in [
        WEAK,
        "agent_policies:\n- name: early-allow\n  when: {}\n  action: allow\ndefault: ask\n",
    ] {
        write(&policy, yaml);
        let output = run(invocation(&home, &input, &policy));
        assert_eq!(output.status.code(), Some(2));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let events = &report["policies"][0]["events"];
        assert_eq!(
            events[2]["trace"]["applied_floor"]["kind"],
            "incomplete_provenance_ask"
        );
        assert_eq!(
            events[4]["trace"]["applied_floor"]["kind"],
            "shipped_hard_deny"
        );
        assert_eq!(events[4]["trace"]["pre_resolution_verdict"], "deny");
        assert!(events
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["simulated_verdict"].is_null()));
    }
    let mut unknown = incomplete.clone();
    unknown["context"]["history"] = json!("complete_from_start");
    unknown["events"][0]["event"]["tool"] = json!("UnknownRuntimeTool");
    write(&input, serde_json::to_vec(&unknown).unwrap());
    let output = run(invocation(&home, &input, &policy));
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["policies"][0]["events"][0]["status"], "unsupported");
    assert!(report["policies"][0]["events"][0]["trace"].is_null());
    assert!(report["policies"][0]["events"][1]["simulated_verdict"].is_null());
    write(&input, SEQUENCE);
    write(&policy, SHIPPED);
    for format in ["json", "text"] {
        let mut cmd = invocation(&home, &input, &policy);
        cmd.args(["--format", format]);
        let output = run(cmd);
        assert!(output.status.success());
        let rendered = String::from_utf8(output.stdout).unwrap();
        for private in [
            "/owned/",
            "receiver.example.invalid",
            "BEGIN RSA PRIVATE KEY",
        ] {
            assert!(!rendered.contains(private));
        }
    }
    let export = root.join("report.json");
    let mut cmd = invocation(&home, &input, &policy);
    cmd.arg("--output").arg(&export);
    assert!(run(cmd).status.success());
    let original = fs::read(&export).unwrap();
    let mut cmd = invocation(&home, &input, &policy);
    cmd.arg("--output").arg(&export);
    assert_eq!(run(cmd).status.code(), Some(1));
    assert_eq!(fs::read(&export).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;
        let fifo = root.join("private-path-never-print");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let rejected = run(invocation(&home, &fifo, &policy));
        assert_eq!(rejected.status.code(), Some(1));
        assert!(rejected.stdout.is_empty());
        assert!(!String::from_utf8(rejected.stderr)
            .unwrap()
            .contains("private-path-never-print"));
        let link = root.join("input-link");
        symlink(&input, &link).unwrap();
        assert_eq!(
            run(invocation(&home, &link, &policy)).status.code(),
            Some(1)
        );
    }
    let mut cmd = cli(&home);
    cmd.args(["replay", "--offline"]);
    assert!(!run(cmd).status.success());
    let mut cmd = invocation(&home, &input, &policy);
    cmd.arg("--log").arg(&input);
    assert!(!run(cmd).status.success());
    let audit = root.join("historical.jsonl");
    write(
        &audit,
        b"{\"session\":\"owned\",\"verdict\":\"deny\",\"latency_us\":10}\nnot-json\n",
    );
    let mut cmd = cli(&home);
    cmd.args(["replay", "--log"]).arg(&audit);
    let output = run(cmd);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("deny: 1"));
    assert!(text.contains("malformed: 1"));
    assert!(!text.contains("OFFLINE SIMULATION"));
}

#[test]
fn cli_closed_stdout_is_a_failure() {
    let tmp = temp();
    let root = tmp.path();
    let home = root.join("home");
    let input = root.join("input.json");
    let policy = root.join("policy.yaml");
    write(&input, SEQUENCE);
    write(&policy, SHIPPED);
    let mut child = invocation(&home, &input, &policy)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(1));
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("closed stdout did not terminate");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
