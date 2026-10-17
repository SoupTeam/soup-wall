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
