use agentfw::lifecycle::{sha256_file, Manager, Status};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::tempdir;

fn run(profile: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentfw"));
    command.arg("lifecycle").args(args);
    #[cfg(unix)]
    command.env("HOME", profile);
    #[cfg(windows)]
    command.env("USERPROFILE", profile);
    command.output().unwrap()
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

fn profile_accessible(home: &Path) -> bool {
    #[cfg(windows)]
    if let Err(error) = Manager::new(home).status() {
        assert!(
            error.to_string().contains("untrusted owner: S-1-5-32-544"),
            "unexpected profile error: {error:#}"
        );
        assert!(!home.join("versions/lifecycle.json").exists());
        eprintln!(
            "Windows runner uses an Administrators-owned profile; lifecycle access was refused"
        );
        return false;
    }
    #[cfg(not(windows))]
    let _ = home;
    true
}

fn candidate(dir: &Path, name: &str, append: &[u8]) -> (PathBuf, String) {
    let path = dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    fs::copy(env!("CARGO_BIN_EXE_agentfw"), &path).unwrap();
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
fn managed_lifecycle_restores_last_working_version() {
    let dir = tempdir().unwrap();
    let profile = dir.path().join("profile");
    let home = profile.join(".agentfw");
    fs::create_dir_all(&home).unwrap();
    if !profile_accessible(&home) {
        return;
    }
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
    assert!(!home.join("versions/agentfw-one").exists());
    assert!(!home.join("versions/agentfw-two").exists());
    assert!(!home.join("versions/agentfw-broken").exists());
    assert!(manager.status().unwrap().active.is_none());
}

#[test]
fn managed_storage_rejects_unsafe_inputs_and_preserves_foreign_files() {
    let dir = tempdir().unwrap();
    let home = dir.path().join(".agentfw");
    if !profile_accessible(&home) {
        return;
    }
    let manager = Manager::new(&home);
    let candidate = dir.path().join("candidate");
    fs::write(&candidate, b"candidate").unwrap();
    let digest = sha256_file(&candidate).unwrap();

    assert!(manager
        .install("missing", &dir.path().join("missing"), &digest)
        .is_err());
    assert!(manager.install("../outside", &candidate, &digest).is_err());
    assert!(manager.install("one", &candidate, &"0".repeat(64)).is_err());
    let foreign = home.join("versions/agentfw-one");
    fs::write(&foreign, "foreign").unwrap();
    assert!(manager.install("one", &candidate, &digest).is_err());
    assert_eq!(fs::read_to_string(&foreign).unwrap(), "foreign");
}

#[test]
fn recovery_restores_the_version_before_an_interrupted_upgrade() {
    let dir = tempdir().unwrap();
    let home = dir.path().join(".agentfw");
    if !profile_accessible(&home) {
        return;
    }
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
fn recovery_removes_only_the_recorded_incomplete_stage() {
    let dir = tempdir().unwrap();
    let home = dir.path().join(".agentfw");
    if !profile_accessible(&home) {
        return;
    }
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
fn an_unowned_listener_is_reported_and_never_stopped() {
    let dir = tempdir().unwrap();
    let home = dir.path().join(".agentfw");
    fs::create_dir_all(&home).unwrap();
    if !profile_accessible(&home) {
        return;
    }
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
