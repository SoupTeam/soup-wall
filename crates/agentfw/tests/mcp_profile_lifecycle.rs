// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! End-to-end integration tests for transactional MCP profile lifecycle management (SOU-78).
//! Verifies install, upgrade, rollback, zero stale authority, and crash recovery.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use agentfw::config::Config;
use agentfw::mcp::profile_lifecycle::{bundle_digest, ProfileManager, ProfileStatus};
use serde_json::json;
use tempfile::tempdir;

fn agent_binary() -> PathBuf {
    std::env::var_os("AGENTFW_LIFECYCLE_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_agentfw")))
}

fn create_test_profile_bundle(dir: &Path, server_id: &str, tool_name: &str) -> String {
    fs::create_dir_all(dir).unwrap();
    let registry = json!([
        {
            "name": tool_name,
            "description": format!("test tool {tool_name}"),
            "authority": "ReadOnly",
            "inputSchema": { "type": "object" }
        }
    ]);
    let reg_bytes = serde_json::to_vec(&registry).unwrap();
    let reg_hash = agentfw::mcp::profile_lifecycle::sha256_bytes(&reg_bytes);

    let profile = json!({
        "format": "sw-mcp/operator-profile/1",
        "server_id": server_id,
        "server_version": "1.0",
        "snapshot_sha256": "0".repeat(64),
        "declaration_sha256": "0".repeat(64),
        "registry_sha256": reg_hash,
        "tools": {
            tool_name: {
                "schema_sha256": "0".repeat(64),
                "definition_sha256": "0".repeat(64),
                "action_class": "read",
                "result_provenance": "untrusted",
                "authority_sha256": "0".repeat(64),
                "review_sha256": "0".repeat(64),
                "workspace": null,
                "scoped_resources": [],
                "egress_selectors": []
            }
        },
        "limits": []
    });
    let native_config = json!({
        "native": {
            "registry_path": dir.join("registry.json"),
            "registry_sha256": reg_hash
        }
    });

    fs::write(dir.join("registry.json"), reg_bytes).unwrap();
    fs::write(
        dir.join("profile.json"),
        serde_json::to_vec(&profile).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("native-config.json"),
        serde_json::to_vec(&native_config).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("operator-declarations.json"),
        b"{\"format\":\"sw-mcp/operator-declaration/1\"}\n",
    )
    .unwrap();
    fs::write(dir.join("resource-profiles.json"), b"[]\n").unwrap();
    fs::write(
        dir.join("source-snapshot.json"),
        b"{\"format\":\"sw-mcp/operator-discovery/1\"}\n",
    )
    .unwrap();

    bundle_digest(dir).unwrap()
}

#[test]
fn cli_mcp_profile_lifecycle_e2e() {
    let temp = tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let p1_dir = home.join("profile1");
    let p2_dir = home.join("profile2");

    let h1 = create_test_profile_bundle(&p1_dir, "srv-1", "tool_read");
    let h2 = create_test_profile_bundle(&p2_dir, "srv-1", "tool_write");

    // 1. Install Profile 1 via CLI
    let install_output = Command::new(agent_binary())
        .args([
            "mcp-profile",
            "--home",
            home.to_str().unwrap(),
            "install",
            "--profile",
            p1_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute agentfw mcp-profile install");
    assert!(
        install_output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&install_output.stderr)
    );

    // 2. Status via CLI
    let status_output = Command::new(agent_binary())
        .args(["mcp-profile", "--home", home.to_str().unwrap(), "status"])
        .output()
        .expect("failed to execute agentfw mcp-profile status");
    assert!(status_output.status.success());
    let status: ProfileStatus = serde_json::from_slice(&status_output.stdout).unwrap();
    assert_eq!(status.generation, 1);
    assert_eq!(status.active_bundle_sha256.as_deref(), Some(h1.as_str()));
    assert_eq!(status.revisions_count, 1);

    // 3. Upgrade to Profile 2 via CLI
    // First try without --accept-diff (must fail closed due to authority change)
    let upgrade_fail = Command::new(agent_binary())
        .args([
            "mcp-profile",
            "--home",
            home.to_str().unwrap(),
            "upgrade",
            "--profile",
            p2_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute upgrade");
    assert!(
        !upgrade_fail.status.success(),
        "upgrade without accept-diff should fail"
    );

    // Now upgrade with --accept-diff yes
    let upgrade_success = Command::new(agent_binary())
        .args([
            "mcp-profile",
            "--home",
            home.to_str().unwrap(),
            "upgrade",
            "--profile",
            p2_dir.to_str().unwrap(),
            "--expect-generation",
            "1",
            "--accept-diff",
            "yes",
        ])
        .output()
        .expect("failed to execute upgrade with accept-diff");
    assert!(
        upgrade_success.status.success(),
        "upgrade failed: {}",
        String::from_utf8_lossy(&upgrade_success.stderr)
    );

    // Verify status after upgrade: generation = 2
    let mgr = ProfileManager::new(&home);
    let st2 = mgr.status().unwrap();
    assert_eq!(st2.generation, 2);
    assert_eq!(st2.active_bundle_sha256.as_deref(), Some(h2.as_str()));
    assert_eq!(st2.previous_bundle_sha256.as_deref(), Some(h1.as_str()));

    // 4. Rollback via CLI
    // ZERO STALE AUTHORITY: generation MUST advance to 3!
    let rollback_output = Command::new(agent_binary())
        .args([
            "mcp-profile",
            "--home",
            home.to_str().unwrap(),
            "rollback",
            "--expect-generation",
            "2",
            "--accept-diff",
            "yes",
        ])
        .output()
        .expect("failed to execute rollback");
    assert!(
        rollback_output.status.success(),
        "rollback failed: {}",
        String::from_utf8_lossy(&rollback_output.stderr)
    );

    let st3 = mgr.status().unwrap();
    assert_eq!(st3.generation, 3);
    assert_eq!(st3.active_bundle_sha256.as_deref(), Some(h1.as_str()));
    assert_eq!(st3.previous_bundle_sha256.as_deref(), Some(h2.as_str()));

    // Verify active config.yaml
    let cfg = Config::from_yaml(&fs::read_to_string(home.join("config.yaml")).unwrap()).unwrap();
    assert!(cfg.native.is_some());
    assert_eq!(
        cfg.native.unwrap().registry_path,
        home.join("mcp-profiles")
            .join("revisions")
            .join(&h1)
            .join("registry.json")
    );
}

#[test]
fn zero_stale_authority_monotonicity() {
    let temp = tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let p1_dir = home.join("p1");
    let p2_dir = home.join("p2");
    let h1 = create_test_profile_bundle(&p1_dir, "srv-1", "tool_a");
    let h2 = create_test_profile_bundle(&p2_dir, "srv-1", "tool_b");

    // Install p1 -> gen 1
    let r1 = mgr.install(&p1_dir, None).unwrap();
    assert_eq!(r1.generation, 1);

    // Upgrade to p2 -> gen 2
    let r2 = mgr.upgrade(&p2_dir, None, Some(1), Some("yes")).unwrap();
    assert_eq!(r2.generation, 2);

    // Rollback to p1 -> gen 3 (even though bundle bytes are identical to gen 1!)
    let r3 = mgr.rollback(None, Some(2), Some("yes")).unwrap();
    assert_eq!(r3.generation, 3);
    assert_eq!(r3.bundle_sha256, h1);

    // Rollback again to p2 -> gen 4
    let r4 = mgr.rollback(Some(&h2), Some(3), Some("yes")).unwrap();
    assert_eq!(r4.generation, 4);
    assert_eq!(r4.bundle_sha256, h2);

    // Any attempt to present an older generation (e.g. gen 1 or gen 2 or gen 3)
    // with expect_generation fails closed
    assert!(mgr.rollback(None, Some(1), Some("yes")).is_err());
    assert!(mgr.rollback(None, Some(2), Some("yes")).is_err());
    assert!(mgr.rollback(None, Some(3), Some("yes")).is_err());
}

#[test]
fn crash_recovery_restores_clean_baseline() {
    let temp = tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let p1_dir = home.join("p1");
    let _ = create_test_profile_bundle(&p1_dir, "srv-1", "tool_a");
    mgr.install(&p1_dir, None).unwrap();

    let baseline_config = fs::read_to_string(home.join("config.yaml")).unwrap();

    // Trigger recover via CLI when no operation was pending -> succeeds as no-op
    let rec_output = Command::new(agent_binary())
        .args(["mcp-profile", "--home", home.to_str().unwrap(), "recover"])
        .output()
        .unwrap();
    assert!(rec_output.status.success());

    // Corrupt config during an interrupted transaction
    fs::write(home.join("config.yaml"), "invalid: [yaml: broken\n").unwrap();
    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(agentfw::mcp::profile_lifecycle::OperationJournal {
        operation_id: "op-test".into(),
        kind: agentfw::mcp::profile_lifecycle::OperationKind::Upgrade,
        phase: agentfw::mcp::profile_lifecycle::OperationPhase::ConfigWritten,
        reserved_generation: 2,
        source_bundle_sha256: state.active_bundle_sha256.clone(),
        target_bundle_sha256: "0".repeat(64),
        pre_operation_config: Some(baseline_config.clone()),
        pre_operation_config_digest: Some(agentfw::mcp::profile_lifecycle::sha256_bytes(
            baseline_config.as_bytes(),
        )),
        target_config_digest: agentfw::mcp::profile_lifecycle::sha256_bytes(
            b"invalid: [yaml: broken\n",
        ),
        was_daemon_running: false,
        pre_daemon_instance: None,
        started_at_utc: "12345".into(),
    });
    mgr.save_state(&state).unwrap();

    // Run recover via CLI
    let rec_output2 = Command::new(agent_binary())
        .args(["mcp-profile", "--home", home.to_str().unwrap(), "recover"])
        .output()
        .unwrap();
    assert!(rec_output2.status.success());

    // Verify baseline configuration restored
    let restored_config = fs::read_to_string(home.join("config.yaml")).unwrap();
    assert_eq!(restored_config, baseline_config);
}
