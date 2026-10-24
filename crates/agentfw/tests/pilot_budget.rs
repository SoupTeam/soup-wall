// SPDX-License-Identifier: Apache-2.0
//! Actual CLI refusal witnesses: a dropped binding must never start a tool.
use std::fs;
use std::process::Command;

#[test]
fn prepared_command_losing_environment_refuses_before_original_execution() {
    let private = tempfile::tempdir().unwrap();
    let marker = private.path().join("must-not-execute");
    let result = Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .env_clear()
        .args([
            "mcp",
            "--id",
            "filesystem",
            "--native-admission",
            "--host-session",
            "owned-host",
            "--child-authority",
            "owned-opaque-authority",
            "--pilot-budget-binding",
        ])
        .arg(private.path().join("missing-binding.json"))
        .args(["--pilot-budget-sha256", &"a".repeat(64)])
        .args(["--", "/usr/bin/touch"])
        .arg(&marker)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("pilot_budget_binding_required"));
    assert!(!marker.exists());
}

#[test]
fn strict_selection_is_read_only_and_never_claims_active_without_a_probe() {
    let private = tempfile::tempdir().unwrap();
    let path = private.path().join("budget.json");
    fs::write(&path, br#"{"format":"sw-mcp/linux-cgroup-budget/1","delegationRoot":"/sys/fs/cgroup/owned-pilot","memoryMaxBytes":268435456,"pidsMax":64,"cpuQuotaMicros":100000,"wallMillis":30000}"#).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let before = fs::read(&path).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .env_clear()
        .args(["pilot-budget", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["status"], "selected-not-active");
    assert_eq!(value["protected_children_started"], false);
    assert_eq!(value["budget_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(fs::read(path).unwrap(), before);
    assert_eq!(fs::read_dir(private.path()).unwrap().count(), 1);
}
