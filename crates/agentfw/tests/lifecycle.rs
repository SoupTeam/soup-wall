use agentfw::lifecycle::{sha256_file, Manager, Status};
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn agent_binary() -> PathBuf {
    std::env::var_os("AGENTFW_LIFECYCLE_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_agentfw")))
}

fn run(profile: &Path, args: &[&str]) -> Output {
    eprintln!("Lifecycle command: {args:?}");
    let mut command = Command::new(agent_binary());
    command.arg("lifecycle").args(args);
    #[cfg(unix)]
    command.env("HOME", profile);
    #[cfg(windows)]
    command.env("USERPROFILE", profile);
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (send, receive) = mpsc::channel();
    for (name, mut stream) in [
        ("stdout", Box::new(stdout) as Box<dyn Read + Send>),
        ("stderr", Box::new(stderr) as Box<dyn Read + Send>),
    ] {
        let send = send.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stream.read_to_end(&mut bytes);
            let _ = send.send((name, result, bytes));
        });
    }
    drop(send);
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = Manager::new(profile.join(".agentfw")).stop();
            panic!("lifecycle {args:?} did not exit within 90 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut output = Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    for _ in 0..2 {
        let (name, result, bytes) = receive.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|error| {
            // A daemon must not retain the CLI's output pipes after the CLI exits.
            // Stop only the authenticated daemon in this disposable profile.
            let manager = Manager::new(profile.join(".agentfw"));
            let running = manager.status().map(|s| s.running);
            let stopped = manager.stop();
            panic!("lifecycle {args:?} exited ({status}) but output did not close within 5 seconds: {error}; managed running={running:?}; cleanup={stopped:?}");
        });
        result.unwrap();
        if name == "stdout" {
            output.stdout = bytes;
        } else {
            output.stderr = bytes;
        }
    }
    output
}

fn success(profile: &Path, args: &[&str]) -> String {
    let output = run(profile, args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn failure(profile: &Path, args: &[&str]) -> String {
    let output = run(profile, args);
    assert!(!output.status.success(), "{args:?} unexpectedly succeeded");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn status(profile: &Path) -> Status {
    serde_json::from_str(&success(profile, &["status"])).unwrap()
}

fn require_owned_profile(home: &Path) {
    Manager::new(home)
        .status()
        .expect("lifecycle tests require an owned accessible profile; no early success is allowed");
}

fn installed_binary(home: &Path, version: &str) -> PathBuf {
    home.join("versions")
        .join(format!("agentfw-{version}{}", std::env::consts::EXE_SUFFIX))
}

fn candidate(dir: &Path, name: &str, append: &[u8]) -> (PathBuf, String) {
    let path = dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    fs::copy(agent_binary(), &path).unwrap();
    if !append.is_empty() {
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(append)
            .unwrap();
    }
    (path.clone(), sha256_file(&path).unwrap())
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires standard-user lifecycle job; run explicitly with --ignored"
)]
fn managed_lifecycle_restores_last_working_version() {
    let dir = tempdir().unwrap();
    let profile = dir.path().join("profile");
    let home = profile.join(".agentfw");
    fs::create_dir_all(&home).unwrap();
    require_owned_profile(&home);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    fs::write(home.join("config.yaml"), format!("port: {port}\n")).unwrap();
    fs::write(home.join("foreign.txt"), "keep").unwrap();
    let (first, first_hash) = candidate(dir.path(), "first", &[]);
    let (second, second_hash) = candidate(dir.path(), "second", b"\nsecond-version");
    let manager = Manager::new(&home);

    failure(
        &profile,
        &[
            "install",
            "one",
            first.to_str().unwrap(),
            "--sha256",
            &"0".repeat(64),
        ],
    );
    assert!(status(&profile).active.is_none());
    success(
        &profile,
        &[
            "install",
            "one",
            first.to_str().unwrap(),
            "--sha256",
            &first_hash,
        ],
    );
    failure(
        &profile,
        &[
            "install",
            "one",
            first.to_str().unwrap(),
            "--sha256",
            &first_hash,
        ],
    );
    success(&profile, &["start"]);
    assert!(status(&profile).running);
    failure(&profile, &["start"]);
    fs::write(
        home.join("config.yaml"),
        format!("port: {port}\nenforce: false\n"),
    )
    .unwrap();
    let changed = status(&profile);
    assert!(changed.running);
    assert!(changed.detail.contains("changed config"));
    success(&profile, &["stop"]);
    fs::write(home.join("config.yaml"), format!("port: {port}\n")).unwrap();
    success(&profile, &["start"]);

    success(
        &profile,
        &[
            "upgrade",
            "two",
            second.to_str().unwrap(),
            "--sha256",
            &second_hash,
        ],
    );
    let updated = status(&profile);
    assert_eq!(updated.active.unwrap().version, "two");
    assert!(updated.running);
    success(&profile, &["rollback"]);
    let restored = status(&profile);
    assert_eq!(restored.active.unwrap().version, "one");
    assert!(restored.running);

    let failed = dir.path().join("failed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&failed, b"#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&failed, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    fs::write(&failed, b"not a PE executable").unwrap();
    let failed_hash = sha256_file(&failed).unwrap();
    failure(
        &profile,
        &[
            "upgrade",
            "broken",
            failed.to_str().unwrap(),
            "--sha256",
            &failed_hash,
        ],
    );
    let after_failure = status(&profile);
    assert_eq!(after_failure.active.unwrap().version, "one");
    assert!(after_failure.running);
    assert!(!after_failure.interrupted);

    success(&profile, &["stop"]);
    assert!(!status(&profile).running);
    success(&profile, &["start"]);
    success(&profile, &["restart"]);
    assert!(status(&profile).running);
    success(&profile, &["remove"]);
    assert!(status(&profile).active.is_none());
    assert!(home.join("config.yaml").exists());
    assert!(home.join("token").exists());
    assert!(home.join("audit.jsonl").exists());
    assert!(home.join("foreign.txt").exists());
    assert!(!installed_binary(&home, "one").exists());
    assert!(!installed_binary(&home, "two").exists());
    assert!(!installed_binary(&home, "broken").exists());
    assert!(manager.status().unwrap().active.is_none());
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires standard-user lifecycle job; run explicitly with --ignored"
)]
fn managed_storage_rejects_unsafe_inputs_and_preserves_foreign_files() {
    let dir = tempdir().unwrap();
    let home = dir.path().join(".agentfw");
    require_owned_profile(&home);
    let manager = Manager::new(&home);
    let candidate = dir.path().join("candidate");
    fs::write(&candidate, b"candidate").unwrap();
    let digest = sha256_file(&candidate).unwrap();

    assert!(manager
        .install("missing", &dir.path().join("missing"), &digest)
        .is_err());
    assert!(manager.install("../outside", &candidate, &digest).is_err());
    assert!(manager.install("one", &candidate, &"0".repeat(64)).is_err());
    let foreign = installed_binary(&home, "one");
    fs::write(&foreign, "foreign").unwrap();
    assert!(manager.install("one", &candidate, &digest).is_err());
    assert_eq!(fs::read_to_string(&foreign).unwrap(), "foreign");
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires standard-user lifecycle job; run explicitly with --ignored"
)]
fn recovery_restores_the_version_before_an_interrupted_upgrade() {
    let dir = tempdir().unwrap();
    let home = dir.path().join(".agentfw");
    require_owned_profile(&home);
    let manager = Manager::new(&home);
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();
    let from = manager
        .install("one", &first, &sha256_file(&first).unwrap())
        .unwrap();
    let to = manager
        .upgrade("two", &second, &sha256_file(&second).unwrap())
        .unwrap();
    let manifest = home.join("versions/lifecycle.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    state["operation"] = serde_json::json!({"from": from, "to": to, "was_running": false});
    fs::write(&manifest, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(manager.status().unwrap().interrupted);
    manager.recover().unwrap();
    let recovered = manager.status().unwrap();
    assert_eq!(recovered.active.unwrap().version, "one");
    assert!(!recovered.interrupted);
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires standard-user lifecycle job; run explicitly with --ignored"
)]
fn recovery_removes_only_the_recorded_incomplete_stage() {
    let dir = tempdir().unwrap();
    let home = dir.path().join(".agentfw");
    require_owned_profile(&home);
    let manager = Manager::new(&home);
    let candidate = dir.path().join("candidate");
    fs::write(&candidate, b"candidate").unwrap();
    manager
        .install("one", &candidate, &sha256_file(&candidate).unwrap())
        .unwrap();
    let versions = home.join("versions");
    let stage = format!(".{}.stage", "a".repeat(43));
    fs::write(versions.join(&stage), b"partial").unwrap();
    let target = format!("agentfw-two{}", std::env::consts::EXE_SUFFIX);
    fs::write(versions.join(&target), b"incomplete").unwrap();
    fs::write(versions.join("foreign.stage"), b"keep").unwrap();
    let manifest = versions.join("lifecycle.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    state["pending_stage"] = serde_json::json!({"stage": &stage, "target": &target});
    fs::write(&manifest, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(manager.status().unwrap().interrupted);
    manager.recover().unwrap();
    assert!(!versions.join(stage).exists());
    assert!(!versions.join(target).exists());
    assert!(versions.join("foreign.stage").exists());
    assert_eq!(manager.status().unwrap().active.unwrap().version, "one");
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires standard-user lifecycle job; run explicitly with --ignored"
)]
fn an_unowned_listener_is_reported_and_never_stopped() {
    let dir = tempdir().unwrap();
    let home = dir.path().join(".agentfw");
    fs::create_dir_all(&home).unwrap();
    require_owned_profile(&home);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    fs::write(home.join("config.yaml"), format!("port: {port}\n")).unwrap();
    let candidate = dir.path().join("candidate");
    fs::write(&candidate, b"candidate").unwrap();
    let manager = Manager::new(&home);
    manager
        .install("one", &candidate, &sha256_file(&candidate).unwrap())
        .unwrap();
    assert!(manager.status().unwrap().detail.contains("unowned"));
    assert!(manager.start().is_err());
    assert!(manager.stop().is_err());
    assert!(listener.local_addr().is_ok());
}
