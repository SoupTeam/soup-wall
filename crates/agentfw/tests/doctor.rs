// SPDX-License-Identifier: Apache-2.0
//! Exercise the installed CLI from a directory outside the source checkout.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn doctor(home: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .arg("doctor")
        .arg("--json")
        .arg("--home")
        .arg(home)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}

fn private(path: &Path, contents: &[u8]) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn missing_profile_is_fail_closed_and_does_not_create_installation() {
    let work = tempfile::tempdir().unwrap();
    let home = work.path().join(".agentfw");
    let result = doctor(&home, work.path(), &[]);
    assert_eq!(result.status.code(), Some(3));
    assert!(!home.exists());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["schema"], "sw-agent-doctor/1");
    assert_eq!(report["active_host_call_protection"], "unknown");
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["reason_code"] == "config_missing_or_unsafe"));
}

#[test]
fn shadow_and_invalid_classifier_have_actionable_sanitized_report() {
    let work = tempfile::tempdir().unwrap();
    let home = work.path().join(".agentfw");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    private(
        &home.join("config.yaml"),
        b"enforce: false\n# SENSITIVE-DO-NOT-EXPORT\n",
    );
    private(&home.join("token"), b"supersecret-AUTH-SENTINEL");
    let classifier = work.path().join("rule_baseline.py");
    private(&classifier, b"# another-classifier-SENTINEL");
    let folder = work.path().join("exports");
    std::fs::create_dir(&folder).unwrap();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bundle = folder.join("report");
    let result = doctor(
        &home,
        work.path(),
        &[
            "--classifier-script",
            classifier.to_str().unwrap(),
            "--classifier-sha256",
            &"a".repeat(64),
            "--support-bundle",
            bundle.to_str().unwrap(),
        ],
    );
    assert_eq!(result.status.code(), Some(3));
    let exported = std::fs::read(bundle.join("report.json")).unwrap();
    let manifest = std::fs::read(bundle.join("manifest.json")).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["reason_code"] == "shadow_mode"));
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["reason_code"] == "classifier_pin_mismatch"));
    let bundle_report: serde_json::Value = serde_json::from_slice(&exported).unwrap();
    assert_eq!(bundle_report, report);
    for data in [&result.stdout[..], &exported[..], &manifest[..]] {
        let text = String::from_utf8_lossy(data);
        assert!(!text.contains("supersecret-AUTH-SENTINEL"));
        assert!(!text.contains("SENSITIVE-DO-NOT-EXPORT"));
        assert!(!text.contains("another-classifier-SENTINEL"));
        assert!(!text.contains(work.path().to_str().unwrap()));
    }
    let original = std::fs::read(home.join("config.yaml")).unwrap();
    assert!(String::from_utf8_lossy(&original).contains("SENSITIVE-DO-NOT-EXPORT"));
    assert!(!home.join("versions").exists()); // doctor must not create a lifecycle lock
    let repeated = doctor(
        &home,
        work.path(),
        &["--support-bundle", bundle.to_str().unwrap()],
    );
    assert_eq!(repeated.status.code(), Some(4));
    assert_eq!(std::fs::read(bundle.join("report.json")).unwrap(), exported);
}

#[test]
fn symlink_and_public_inputs_refused_without_unsafe_fallback() {
    let work = tempfile::tempdir().unwrap();
    let home = work.path().join(".agentfw");
    std::fs::create_dir(&home).unwrap();
    private(&home.join("actual-config.yaml"), b"enforce: true\n");
    std::os::unix::fs::symlink(home.join("actual-config.yaml"), home.join("config.yaml")).unwrap();
    let result = doctor(&home, work.path(), &[]);
    assert_eq!(result.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["reason_code"] == "config_missing_or_unsafe"));
    std::fs::remove_file(home.join("config.yaml")).unwrap();
    private(&home.join("config.yaml"), b"enforce: true\n");
    std::fs::set_permissions(
        home.join("config.yaml"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let result = doctor(&home, work.path(), &[]);
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["reason_code"] == "config_missing_or_unsafe"));
}

#[test]
fn real_owned_linux_install_reaches_authenticated_ready_without_host_execution() {
    use agentfw::lifecycle::{sha256_file, Manager};
    use std::net::TcpListener;
    struct Cleanup(Manager);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.0.stop();
        }
    }

    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join(".agentfw");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let available = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = available.local_addr().unwrap().port();
    drop(available);
    let config = format!("enforce: true\nport: {port}\n");
    private(&home.join("config.yaml"), config.as_bytes());

    let manager = Manager::new(&home);
    let original_binary = Path::new(env!("CARGO_BIN_EXE_agentfw"));
    let binary_digest = sha256_file(original_binary).unwrap();
    let installed = manager
        .install("doctor-one", original_binary, &binary_digest)
        .unwrap();
    assert_eq!(installed.digest, binary_digest);
    let cleanup = Cleanup(manager);
    cleanup.0.start().unwrap();
    let installed_bin = home.join("versions").join("agentfw-doctor-one");
    assert!(installed_bin.is_file());
    let config_before = std::fs::read(home.join("config.yaml")).unwrap();
    let token_before = std::fs::read(home.join("token")).unwrap();
    let state_before = std::fs::read(home.join("versions/lifecycle.json")).unwrap();

    let output = doctor(
        &home,
        scratch.path(),
        &["--agent", installed_bin.to_str().unwrap()],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["setup"], "ready");
    assert_eq!(report["active_host_call_protection"], "unknown");
    for reason in [
        "runtime_identity_verified",
        "runtime_matches_managed_process",
        "enforce_requested_on_disk",
    ] {
        assert!(
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["reason_code"] == reason),
            "missing {reason}: {report}"
        );
    }
    assert_eq!(
        std::fs::read(home.join("config.yaml")).unwrap(),
        config_before
    );
    assert_eq!(std::fs::read(home.join("token")).unwrap(), token_before);
    assert_eq!(
        std::fs::read(home.join("versions/lifecycle.json")).unwrap(),
        state_before
    );

    // A modified on-disk setting must not silently become a claimed runtime
    // fact. The actual running owned daemon remains on the old configuration.
    private(
        &home.join("config.yaml"),
        format!("enforce: false\nport: {port}\n").as_bytes(),
    );
    let negative = doctor(
        &home,
        scratch.path(),
        &["--agent", installed_bin.to_str().unwrap()],
    );
    assert_eq!(negative.status.code(), Some(3));
    let negative_report: serde_json::Value = serde_json::from_slice(&negative.stdout).unwrap();
    assert_eq!(negative_report["active_host_call_protection"], "unknown");
    assert!(negative_report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["reason_code"] == "host_config_drift"));
    assert!(negative_report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["reason_code"] == "shadow_mode"));
}

#[test]
fn cancellation_before_completion_never_publishes_support_bundle() {
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};
    let work = tempfile::tempdir().unwrap();
    let home = work.path().join(".agentfw");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    private(
        &home.join("config.yaml"),
        format!("enforce: true\nport: {port}\n").as_bytes(),
    );
    private(&home.join("token"), b"private-fixture-token");
    let out_parent = work.path().join("private");
    std::fs::create_dir(&out_parent).unwrap();
    std::fs::set_permissions(&out_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bundle = out_parent.join("bundle");
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .arg("doctor")
        .arg("--json")
        .arg("--home")
        .arg(&home)
        .arg("--support-bundle")
        .arg(&bundle)
        .current_dir(work.path())
        .spawn()
        .unwrap();
    // Bound the wait for the owned listener; never sleep until a remote timeout.
    let deadline = Instant::now() + Duration::from_secs(5);
    let opened = loop {
        match listener.accept() {
            Ok((stream, _)) => break Some(stream),
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                if child.try_wait().unwrap().is_some() {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => break None,
        }
    };
    // Keep the local probe pending; cancel before reporting or export.
    assert!(opened.is_some(), "doctor never reached the owned listener");
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    assert!(!bundle.exists());
    assert_eq!(std::fs::read_dir(&out_parent).unwrap().count(), 0);
}
