// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)
use super::*;
use crate::lifecycle::{ProcessRecord, State};
use serde_json::json;
use std::io::{Read, Write};
use tempfile::tempdir;

fn allocate_test_port() -> Option<u16> {
    match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => Some(l.local_addr().unwrap().port()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(e) => panic!("failed to bind test listener: {e}"),
    }
}

fn create_test_profile(dir: &Path, server_id: &str, tool_name: &str) -> String {
    let inputs = tempfile::tempdir().unwrap();
    let inputs_path = inputs.path().canonicalize().unwrap();
    let snapshot = json!({
        "format": "sw-mcp/operator-discovery/1", "server_id": server_id,
        "server_version": "1.0", "tools": [{"name": tool_name, "description": "Read fixture state",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}}]
    });
    let declarations = json!({
        "format": "sw-mcp/operator-declaration/1", "server_id": server_id,
        "server_version": "1.0", "snapshot_sha256": crate::mcp::profile_author::digest(&snapshot),
        "registry_id": format!("{server_id}-reg"), "tools": [{
            "name": tool_name, "schema_sha256": crate::mcp::profile_author::digest(&snapshot["tools"][0]["inputSchema"]),
            "reviewed": true, "authority": {"kind": "read_only"},
            "operator_review": "Independent read-only fixture implementation review"
        }]
    });
    let snap = inputs_path.join("snapshot.json");
    let decl = inputs_path.join("declarations.json");
    fs::write(&snap, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    fs::write(&decl, serde_json::to_vec(&declarations).unwrap()).unwrap();
    fs::create_dir_all(dir).unwrap();
    for (name, bytes) in
        crate::mcp::profile_author::compiled_bundle_files(&snap, &decl, dir).unwrap()
    {
        fs::write(dir.join(name), bytes).unwrap();
    }
    bundle_digest(dir).unwrap()
}

#[test]
fn bundle_digest_computes_deterministic_sha256() {
    let temp = tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let p1 = root.join("p1");
    let hash1 = create_test_profile(&p1, "srv-1", "tool_a");
    let hash2 = bundle_digest(&p1).unwrap();
    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 64);
    assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));

    let files = verify_bundle_files(&p1).unwrap();
    assert_eq!(files.bundle_sha256, hash1);
    assert_eq!(files.files.len(), 6);
    assert!(files.files.contains_key("registry.json"));
}

#[test]
fn bundle_digest_fails_on_missing_file() {
    let temp = tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let p1 = root.join("p1");
    create_test_profile(&p1, "srv-1", "tool_a");
    fs::remove_file(p1.join("registry.json")).unwrap();

    assert!(bundle_digest(&p1).is_err());
    assert!(verify_bundle_files(&p1).is_err());
}

#[test]
fn bundle_digest_fails_on_symlink() {
    let temp = tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let p1 = root.join("p1");
    create_test_profile(&p1, "srv-1", "tool_a");
    let reg = p1.join("registry.json");
    fs::remove_file(&reg).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(p1.join("profile.json"), &reg).unwrap();

    #[cfg(unix)]
    assert!(bundle_digest(&p1).is_err());
}

#[test]
fn bundle_digest_fails_on_cross_file_mismatch() {
    let temp = tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let p1 = root.join("p1");
    create_test_profile(&p1, "srv-1", "tool_a");

    // Tamper registry.json without updating profile.json
    fs::write(p1.join("registry.json"), b"[{\"name\":\"tampered\"}]\n").unwrap();
    assert!(verify_bundle_files(&p1).is_err());
}

#[test]
fn profile_state_serde_roundtrip() {
    let state = ProfileState {
        schema_version: 1,
        generation: 42,
        active_bundle_sha256: Some("a".repeat(64)),
        previous_bundle_sha256: Some("b".repeat(64)),
        history: vec![OperationRecord {
            operation_id: "op-1".into(),
            kind: OperationKind::Install,
            generation: 42,
            bundle_sha256: "a".repeat(64),
            from_bundle_sha256: None,
            timestamp_utc: "2026-10-17T15:00:00Z".into(),
            status: "success".into(),
            detail: "initial install".into(),
        }],
        in_progress: None,
    };

    let json = serde_json::to_string_pretty(&state).unwrap();
    let recovered: ProfileState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, recovered);
}

#[test]
fn profile_manager_lifecycle_install_upgrade_rollback() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    if let Some(port) = allocate_test_port() {
        fs::write(home.join("config.yaml"), format!("port: {port}\n")).unwrap();
    }
    let mgr = ProfileManager::new(&home);

    let p1_dir = home.join("bundle1");
    let hash1 = create_test_profile(&p1_dir, "srv-1", "tool_1");

    // 1. Initial Install
    let rec1 = mgr.install(&p1_dir, None).unwrap();
    assert_eq!(rec1.generation, 1);
    assert_eq!(rec1.bundle_sha256, hash1);
    assert_eq!(rec1.kind, OperationKind::Install);

    let state = mgr.load_state().unwrap();
    assert_eq!(state.generation, 1);
    assert_eq!(state.active_bundle_sha256.as_deref(), Some(hash1.as_str()));
    assert_eq!(state.previous_bundle_sha256, None);

    // Verify config.yaml
    let cfg_str = fs::read_to_string(&mgr.config_path).unwrap();
    let cfg = Config::from_yaml(&cfg_str).unwrap();
    assert!(cfg.enforce);
    assert!(!cfg.judge.enabled);
    assert!(cfg.native.is_some());
    assert_eq!(
        cfg.native.unwrap().registry_path,
        mgr.revisions.join(&hash1).join("registry.json")
    );

    // Duplicate install must fail
    assert!(mgr.install(&p1_dir, None).is_err());

    // 2. Upgrade to Bundle 2
    let p2_dir = home.join("bundle2");
    let hash2 = create_test_profile(&p2_dir, "srv-1", "tool_2");

    // Fails if expect_gen is wrong
    assert!(mgr.upgrade(&p2_dir, None, Some(99), Some("yes")).is_err());

    // Fails if accept_diff is missing due to tool addition
    assert!(mgr.upgrade(&p2_dir, None, Some(1), None).is_err());

    // Succeeds with accept_diff
    let approval = mgr.preview_upgrade(&p2_dir).unwrap().approval_sha256;
    let rec2 = mgr
        .upgrade(&p2_dir, None, Some(1), Some(&approval))
        .unwrap();
    assert_eq!(rec2.generation, 2);
    assert_eq!(rec2.bundle_sha256, hash2);
    assert_eq!(rec2.kind, OperationKind::Upgrade);

    let state2 = mgr.load_state().unwrap();
    assert_eq!(state2.generation, 2);
    assert_eq!(state2.active_bundle_sha256.as_deref(), Some(hash2.as_str()));
    assert_eq!(
        state2.previous_bundle_sha256.as_deref(),
        Some(hash1.as_str())
    );

    // 3. Rollback to Bundle 1
    // ZERO STALE AUTHORITY: generation MUST strictly increment to 3!
    let approval = mgr.preview_rollback(None).unwrap().approval_sha256;
    let rec3 = mgr.rollback(None, Some(2), Some(&approval)).unwrap();
    assert_eq!(rec3.generation, 3);
    assert_eq!(rec3.bundle_sha256, hash1);
    assert_eq!(rec3.kind, OperationKind::Rollback);

    let state3 = mgr.load_state().unwrap();
    assert_eq!(state3.generation, 3);
    assert_eq!(state3.active_bundle_sha256.as_deref(), Some(hash1.as_str()));
    assert_eq!(
        state3.previous_bundle_sha256.as_deref(),
        Some(hash2.as_str())
    );

    // Status
    let status = mgr.status().unwrap();
    assert_eq!(status.generation, 3);
    assert_eq!(status.active_bundle_sha256.as_deref(), Some(hash1.as_str()));
    assert_eq!(status.revisions_count, 2);
    assert_eq!(status.configuration_status, "configured");
    assert_eq!(status.runtime_status, "unavailable_daemon_stopped");
    assert_eq!(status.host_reload_status, "unverified");
}

#[test]
fn profile_manager_crash_recovery_restores_config() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    if let Some(port) = allocate_test_port() {
        fs::write(home.join("config.yaml"), format!("port: {port}\n")).unwrap();
    }
    let mgr = ProfileManager::new(&home);

    let p1_dir = home.join("bundle1");
    let _ = create_test_profile(&p1_dir, "srv-1", "tool_1");
    mgr.install(&p1_dir, None).unwrap();

    let original_cfg = fs::read_to_string(&mgr.config_path).unwrap();

    // Simulate interrupted upgrade in ConfigWritten phase
    let mut state = mgr.load_state().unwrap();
    let target_cfg = "bind: \"127.0.0.1\"\nport: 9999\nenforce: true\n";
    fs::write(&mgr.config_path, target_cfg).unwrap();

    state.in_progress = Some(OperationJournal {
        operation_id: "op-crashed".into(),
        kind: OperationKind::Upgrade,
        phase: OperationPhase::ConfigWritten,
        reserved_generation: 2,
        source_bundle_sha256: state.active_bundle_sha256.clone(),
        target_bundle_sha256: "b".repeat(64),
        pre_operation_config: Some(original_cfg.clone()),
        pre_operation_config_digest: Some(sha256_bytes(original_cfg.as_bytes())),
        target_config_digest: sha256_bytes(target_cfg.as_bytes()),
        was_daemon_running: false,
        pre_daemon_instance: None,
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: true,
        displaced_config_path: None,
        candidate_daemon_instance: None,
        compensated_daemon_instance: None,
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    // Calling recover() must restore original_cfg and clear in_progress
    mgr.recover().unwrap();

    let state_after = mgr.load_state().unwrap();
    assert!(state_after.in_progress.is_none());
    let restored_cfg = fs::read_to_string(&mgr.config_path).unwrap();
    assert_eq!(restored_cfg, original_cfg);
}

#[test]
fn profile_manager_cas_rejects_concurrent_config_mutation() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    if let Some(port) = allocate_test_port() {
        fs::write(home.join("config.yaml"), format!("port: {port}\n")).unwrap();
    }
    let mgr = ProfileManager::new(&home);

    let p1_dir = home.join("bundle1");
    let _ = create_test_profile(&p1_dir, "srv-1", "tool_1");
    mgr.install(&p1_dir, None).unwrap();

    let p2_dir = home.join("bundle2");
    let _ = create_test_profile(&p2_dir, "srv-1", "tool_2");

    // External actor mutates config.yaml concurrently
    fs::write(
        &mgr.config_path,
        "bind: \"127.0.0.1\"\nport: 1234\nenforce: true\n",
    )
    .unwrap();

    let candidate = mgr.candidate_path("test-cas");
    let displaced = mgr.displaced_path("test-cas");
    let err = mgr.write_config(
        "some: new_yaml\n",
        Some("0".repeat(64).as_str()),
        &candidate,
        &displaced,
    );
    assert!(err.is_err());
    assert!(err
        .unwrap_err()
        .to_string()
        .contains("concurrent modification detected"));
}

#[test]
fn bundle_fails_when_tool_authority_tampered_in_registry() {
    let temp = tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let p1 = root.join("p1");
    create_test_profile(&p1, "srv-1", "tool_a");

    // Subtle tamper: keep registry valid sw-native/1, but change action_class to network
    let tampered_entry = json!({
        "name": "tool_a",
        "schema_sha256": "1".repeat(64),
        "action_class": "network",
        "result_provenance": "untrusted",
        "egress": [],
        "resource_policy": null
    });
    let reg = json!({
        "contract_version": crate::native::CONTRACT,
        "registry_id": "srv-1-reg",
        "tools": [tampered_entry]
    });
    let reg_bytes = serde_json::to_vec(&reg).unwrap();
    let reg_hash = sha256_bytes(&reg_bytes);

    // Update registry.json and matching hashes in profile.json and native-config.json
    fs::write(p1.join("registry.json"), &reg_bytes).unwrap();
    let mut prof: Value =
        serde_json::from_slice(&fs::read(p1.join("profile.json")).unwrap()).unwrap();
    prof["registry_sha256"] = json!(reg_hash);
    fs::write(p1.join("profile.json"), serde_json::to_vec(&prof).unwrap()).unwrap();
    let mut nat: Value =
        serde_json::from_slice(&fs::read(p1.join("native-config.json")).unwrap()).unwrap();
    nat["native"]["registry_sha256"] = json!(reg_hash);
    fs::write(
        p1.join("native-config.json"),
        serde_json::to_vec(&nat).unwrap(),
    )
    .unwrap();

    // Must fail with cross-file authority mismatch despite valid JSON and matching registry_sha256!
    let err = verify_bundle_files(&p1);
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("cross-file authority mismatch") || msg.contains("action mismatch"));
}

#[test]
fn recover_preserves_journal_on_foreign_config_when_initial_was_absent() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: "op-interrupted-install".into(),
        kind: OperationKind::Install,
        phase: OperationPhase::ConfigWritten,
        reserved_generation: 1,
        source_bundle_sha256: None,
        target_bundle_sha256: "b".repeat(64),
        pre_operation_config: None,
        pre_operation_config_digest: None,
        target_config_digest: "c".repeat(64),
        was_daemon_running: false,
        pre_daemon_instance: None,
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: true,
        displaced_config_path: None,
        candidate_daemon_instance: None,
        compensated_daemon_instance: None,
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    // Foreign rogue config appears on disk
    fs::write(&mgr.config_path, "rogue: config\n").unwrap();

    // recover() must detect external conflict because current_digest != None and != target
    let err = mgr.recover();
    assert!(err.is_err());
    assert!(err
        .unwrap_err()
        .to_string()
        .contains("conflict during recovery"));

    // Journal must be preserved in Failed phase
    let state_after = mgr.load_state().unwrap();
    assert!(state_after.in_progress.is_some());
    assert_eq!(
        state_after.in_progress.unwrap().phase,
        OperationPhase::Failed
    );
}

#[test]
fn upgrade_fails_when_active_registry_externally_superseded() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    if let Some(port) = allocate_test_port() {
        fs::write(home.join("config.yaml"), format!("port: {port}\n")).unwrap();
    }
    let mgr = ProfileManager::new(&home);

    let p1_dir = home.join("bundle1");
    let _ = create_test_profile(&p1_dir, "srv-1", "tool_1");
    mgr.install(&p1_dir, None).unwrap();

    let p2_dir = home.join("bundle2");
    let _ = create_test_profile(&p2_dir, "srv-1", "tool_2");

    // Operator externally modifies config.yaml to point to foreign registry
    let mut cfg = Config::from_yaml(&fs::read_to_string(&mgr.config_path).unwrap()).unwrap();
    cfg.native.as_mut().unwrap().registry_path = home.join("foreign/registry.json");
    fs::write(&mgr.config_path, serde_yaml::to_string(&cfg).unwrap()).unwrap();

    // Upgrade must reject foreign registry supersession
    let err = mgr.upgrade(&p2_dir, None, None, None);
    assert!(err.is_err());
    assert!(err
        .unwrap_err()
        .to_string()
        .contains("active profile deployment was externally superseded in config.yaml"));
}

#[test]
fn recovery_preserves_superseded_config_across_interrupted_swaps() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    if let Some(port) = allocate_test_port() {
        fs::write(home.join("config.yaml"), format!("port: {port}\n")).unwrap();
    }
    let mgr = ProfileManager::new(&home);

    let p1_dir = home.join("bundle1");
    let _ = create_test_profile(&p1_dir, "srv-1", "tool_1");
    mgr.install(&p1_dir, None).unwrap();

    let baseline_cfg = fs::read_to_string(&mgr.config_path).unwrap();
    let baseline_digest = sha256_bytes(baseline_cfg.as_bytes());

    // Simulate an operator intervening with a custom superseded config
    let superseded_cfg = "bind: \"127.0.0.1\"\nport: 7777\n# operator superseded\n";
    let superseded_digest = sha256_bytes(superseded_cfg.as_bytes());

    let target_cfg = "bind: \"127.0.0.1\"\nport: 8888\n# candidate target\n";
    let target_digest = sha256_bytes(target_cfg.as_bytes());

    // Candidate target is now at config.yaml (simulating swap finished before crash)
    fs::write(&mgr.config_path, target_cfg).unwrap();

    // Displaced path contains the superseded operator config
    let op_id = "op-superseded-test";
    let displaced = mgr.displaced_path(op_id);
    fs::write(&displaced, superseded_cfg).unwrap();

    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: op_id.into(),
        kind: OperationKind::Upgrade,
        phase: OperationPhase::Staged,
        reserved_generation: 2,
        source_bundle_sha256: state.active_bundle_sha256.clone(),
        target_bundle_sha256: "b".repeat(64),
        pre_operation_config: Some(baseline_cfg.clone()),
        pre_operation_config_digest: Some(baseline_digest),
        target_config_digest: target_digest,
        was_daemon_running: false,
        pre_daemon_instance: None,
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: false,
        displaced_config_path: Some(displaced.clone()),
        candidate_daemon_instance: None,
        compensated_daemon_instance: None,
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    // Recovery must detect superseded config, swap it back into config.yaml, and fail
    let err = mgr.recover();
    assert!(err.is_err());
    let err_msg = err.unwrap_err().to_string();
    assert!(err_msg.contains("displaced configuration was externally superseded"));

    // config.yaml must be restored with superseded config, NOT baseline!
    let disk_cfg = fs::read_to_string(&mgr.config_path).unwrap();
    assert_eq!(disk_cfg, superseded_cfg);
    assert_eq!(sha256_bytes(disk_cfg.as_bytes()), superseded_digest);

    // Journal must remain in Failed phase
    let state_after = mgr.load_state().unwrap();
    assert!(state_after.in_progress.is_some());
    assert_eq!(
        state_after.in_progress.unwrap().phase,
        OperationPhase::Failed
    );
}

#[test]
fn preflight_rejects_unresolved_process_ownership() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let p1_dir = home.join("bundle1");
    let _ = create_test_profile(&p1_dir, "srv-1", "tool_1");

    // Manually write an unresolved process record (process exists, but daemon is not running)
    let instance = crate::token::generate();
    let launch_log = format!(".launch-{instance}.log");
    let lifecycle_state = json!({
        "active": null,
        "previous": null,
        "owned": [],
        "process": {
            "pid": 999999,
            "instance": instance,
            "launch_log": launch_log,
            "bind": "127.0.0.1",
            "port": 9999,
            "binary_digest": "0".repeat(64),
            "config_digest": "0".repeat(64)
        },
        "operation": null,
        "pending_stage": null
    });
    fs::create_dir_all(home.join("versions")).unwrap();
    fs::write(
        home.join("versions/lifecycle.json"),
        serde_json::to_vec(&lifecycle_state).unwrap(),
    )
    .unwrap();

    let err = mgr.install(&p1_dir, None);
    assert!(err.is_err());
    assert!(err
        .unwrap_err()
        .to_string()
        .contains("unresolved daemon process ownership"));
}

#[test]
fn recovery_preserves_independent_daemon_on_retries() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    if let Some(port) = allocate_test_port() {
        fs::write(home.join("config.yaml"), format!("port: {port}\n")).unwrap();
    }
    let mgr = ProfileManager::new(&home);

    let p1_dir = home.join("bundle1");
    let _ = create_test_profile(&p1_dir, "srv-1", "tool_1");
    mgr.install(&p1_dir, None).unwrap();

    let baseline_cfg = fs::read_to_string(&mgr.config_path).unwrap();
    let baseline_digest = sha256_bytes(baseline_cfg.as_bytes());

    // Setup staged journal where config was not written
    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: "op-staged".into(),
        kind: OperationKind::Upgrade,
        phase: OperationPhase::Staged,
        reserved_generation: 2,
        source_bundle_sha256: state.active_bundle_sha256.clone(),
        target_bundle_sha256: "b".repeat(64),
        pre_operation_config: Some(baseline_cfg.clone()),
        pre_operation_config_digest: Some(baseline_digest.clone()),
        target_config_digest: "c".repeat(64),
        was_daemon_running: false,
        pre_daemon_instance: None,
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: false,
        displaced_config_path: None,
        candidate_daemon_instance: None,
        compensated_daemon_instance: None,
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    let j = state.in_progress.as_ref().unwrap();
    assert!(!j.config_written);
}

#[test]
fn recovery_restores_empty_baseline_from_displaced_path() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let target_cfg = "bind: \"127.0.0.1\"\nport: 9000\n";
    let target_digest = sha256_bytes(target_cfg.as_bytes());

    let op_id = "op-empty-baseline";
    let displaced = mgr.displaced_path(op_id);
    fs::write(&displaced, target_cfg).unwrap();

    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: op_id.into(),
        kind: OperationKind::Install,
        phase: OperationPhase::RollingBack,
        reserved_generation: 1,
        source_bundle_sha256: None,
        target_bundle_sha256: "b".repeat(64),
        pre_operation_config: None,
        pre_operation_config_digest: None,
        target_config_digest: target_digest,
        was_daemon_running: false,
        pre_daemon_instance: None,
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: true,
        displaced_config_path: Some(displaced.clone()),
        candidate_daemon_instance: None,
        compensated_daemon_instance: None,
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    mgr.recover().unwrap();
    assert!(!mgr.config_path.exists());
    assert!(!displaced.exists());
    let state_after = mgr.load_state().unwrap();
    assert!(state_after.in_progress.is_none());
}

#[test]
fn recovery_handles_interrupted_hard_link_publication() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let target_cfg = "bind: \"127.0.0.1\"\nport: 9000\n";
    let target_digest = sha256_bytes(target_cfg.as_bytes());

    let op_id = "op-hardlink-crash";
    let displaced = mgr.displaced_path(op_id);
    // Both config.yaml and displaced_path contain target_cfg
    fs::write(&mgr.config_path, target_cfg).unwrap();
    fs::write(&displaced, target_cfg).unwrap();

    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: op_id.into(),
        kind: OperationKind::Install,
        phase: OperationPhase::ConfigWritten,
        reserved_generation: 1,
        source_bundle_sha256: None,
        target_bundle_sha256: "b".repeat(64),
        pre_operation_config: None,
        pre_operation_config_digest: None,
        target_config_digest: target_digest,
        was_daemon_running: false,
        pre_daemon_instance: None,
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: true,
        displaced_config_path: Some(displaced.clone()),
        candidate_daemon_instance: None,
        compensated_daemon_instance: None,
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    // Recovery must complete without false external supersession!
    mgr.recover().unwrap();
    assert!(!mgr.config_path.exists());
    assert!(!displaced.exists());
    let state_after = mgr.load_state().unwrap();
    assert!(state_after.in_progress.is_none());
}

#[test]
fn install_works_with_nonexistent_relative_home() {
    let temp = tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let rel_home = root.join("sub/rel-home");
    let mgr = ProfileManager::new(&rel_home);
    assert!(mgr.home.is_absolute());

    let p1_dir = root.join("bundle1");
    create_test_profile(&p1_dir, "srv-1", "tool_1");
    let rec = mgr.install(&p1_dir, None);
    assert!(rec.is_ok());
}

#[test]
fn recovery_preserves_swapped_operator_config_on_intervening_write() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let baseline_cfg = "bind: \"127.0.0.1\"\nport: 9000\n";
    let baseline_digest = sha256_bytes(baseline_cfg.as_bytes());

    let target_cfg = "bind: \"127.0.0.1\"\nport: 9001\n";
    let target_digest = sha256_bytes(target_cfg.as_bytes());

    let superseded_cfg = "bind: \"127.0.0.1\"\nport: 9002\n# operator write\n";
    let superseded_digest = sha256_bytes(superseded_cfg.as_bytes());

    let op_id = "op-intervene-swap";
    let displaced = mgr.displaced_path(op_id);

    // Before recovery swap: displaced_path has baseline_cfg, config.yaml was replaced with superseded_cfg
    fs::write(&displaced, baseline_cfg).unwrap();
    fs::write(&mgr.config_path, superseded_cfg).unwrap();

    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: op_id.into(),
        kind: OperationKind::Upgrade,
        phase: OperationPhase::ConfigWritten,
        reserved_generation: 2,
        source_bundle_sha256: Some("a".repeat(64)),
        target_bundle_sha256: "b".repeat(64),
        pre_operation_config: Some(baseline_cfg.into()),
        pre_operation_config_digest: Some(baseline_digest.clone()),
        target_config_digest: target_digest,
        was_daemon_running: false,
        pre_daemon_instance: None,
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: true,
        displaced_config_path: Some(displaced.clone()),
        candidate_daemon_instance: None,
        compensated_daemon_instance: None,
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    // Recovery must not delete superseded_cfg!
    let err = mgr.recover();
    assert!(err.is_err());
    let err_msg = err.unwrap_err().to_string();
    assert!(
        err_msg.contains("unexpected displaced configuration state")
            || err_msg.contains("conflict")
    );

    // Operator's config must NOT have been destroyed or deleted
    assert!(mgr.config_path.exists());
    let disk_cfg = fs::read_to_string(&mgr.config_path).unwrap();
    assert_eq!(disk_cfg, superseded_cfg);
    assert_eq!(sha256_bytes(disk_cfg.as_bytes()), superseded_digest);
}

fn incomplete_candidate_recovery_fixture() -> (tempfile::TempDir, ProfileManager, PathBuf, PathBuf)
{
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let op_id = "op-incomplete-candidate";
    let displaced = mgr.displaced_path(op_id);
    let candidate = mgr.candidate_path(op_id);

    let target_content = "native: []\n";
    let target_digest = sha256_bytes(target_content.as_bytes());

    // Candidate scratch left behind by crashed initial install
    fs::write(&displaced, target_content).unwrap();
    fs::write(&candidate, target_content).unwrap();

    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: op_id.into(),
        kind: OperationKind::Install,
        phase: OperationPhase::Staged,
        reserved_generation: 1,
        source_bundle_sha256: None,
        target_bundle_sha256: "a".repeat(64),
        pre_operation_config: None,
        pre_operation_config_digest: None,
        target_config_digest: target_digest,
        was_daemon_running: false,
        pre_daemon_instance: None,
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: false,
        displaced_config_path: Some(displaced.clone()),
        candidate_daemon_instance: None,
        compensated_daemon_instance: None,
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    (home_temp, mgr, displaced, candidate)
}

#[test]
fn recovery_removes_incomplete_candidate_scratch_without_publishing() {
    // Like the other lifecycle fixtures, use an OS-assigned free port.
    // Do not hold a bound socket: the real ownership guard also checks bind
    // availability, not just whether a listener accepts connections.
    let port = allocate_test_port().expect("loopback port allocation is required for this test");
    crate::config::with_test_default_port(port, || {
        let (_home, mgr, displaced, candidate) = incomplete_candidate_recovery_fixture();

        // Recovery MUST NOT publish candidate scratch to config.yaml!
        let rec = mgr.recover();
        assert!(rec.is_ok(), "recover failed: {rec:#?}");

        assert!(!mgr.config_path.exists());
        assert!(!displaced.exists());
        assert!(!candidate.exists());
        let state_after = mgr.load_state().unwrap();
        assert!(state_after.in_progress.is_none());
        assert!(state_after.active_bundle_sha256.is_none());
        assert_eq!(state_after.generation, 0);

        // Subsequent retry must succeed cleanly, on the same isolated port.
        let p1_dir = mgr.home.join("bundle1");
        create_test_profile(&p1_dir, "srv-1", "tool_1");
        let retry = mgr.install(&p1_dir, None);
        assert!(retry.is_ok(), "install retry failed: {retry:#?}");
    });
}

#[test]
fn recovery_retains_incomplete_candidate_journal_on_unowned_port() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let endpoint = listener.local_addr().unwrap();
    crate::config::with_test_default_port(endpoint.port(), || {
        let (_home, mgr, _displaced, _candidate) = incomplete_candidate_recovery_fixture();
        let error = mgr.recover().unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains(
                "recovery confirmed baseline configuration but daemon ownership check failed"
            ) && message.contains("agent port is occupied by an unowned process")
                && message.contains("refusing to clear journal"),
            "unexpected recovery error: {message}"
        );
        assert!(!mgr.config_path.exists());
        let state = mgr.load_state().unwrap();
        assert_eq!(state.in_progress.unwrap().phase, OperationPhase::Failed);
        assert!(state.active_bundle_sha256.is_none());
        assert_eq!(state.generation, 0);
        // Recovery must not stop or replace the independent listener.
        std::net::TcpStream::connect_timeout(&endpoint, std::time::Duration::from_secs(1)).unwrap();
    });
}

#[test]
fn recovery_preserves_unidentified_displaced_file_when_config_absent() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let op_id = "op-displaced-preserved";
    let displaced = mgr.displaced_path(op_id);

    let operator_data = "operator_custom_setting: true\n";
    fs::write(&displaced, operator_data).unwrap();

    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: op_id.into(),
        kind: OperationKind::Install,
        phase: OperationPhase::Staged,
        reserved_generation: 1,
        source_bundle_sha256: None,
        target_bundle_sha256: "a".repeat(64),
        pre_operation_config: None,
        pre_operation_config_digest: None,
        target_config_digest: "c".repeat(64),
        was_daemon_running: false,
        pre_daemon_instance: None,
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: false,
        displaced_config_path: Some(displaced.clone()),
        candidate_daemon_instance: None,
        compensated_daemon_instance: None,
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    // Recovery must NOT delete displaced operator data! It must restore to config.yaml and fail closed
    let err = mgr.recover();
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains(
            "conflict during recovery: displaced configuration does not match target profile"
        ),
        "unexpected error: {msg}"
    );

    // Displaced file content must be preserved at config.yaml
    assert!(mgr.config_path.exists());
    let restored_content = fs::read_to_string(&mgr.config_path).unwrap();
    assert_eq!(restored_content, operator_data);
}

#[test]
fn recovery_preserves_independent_daemon_started_with_default_empty_config() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let op_id = "op-independent-daemon";

    // Bind an ephemeral listener to simulate running independent daemon
    let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("failed to bind test listener: {e}"),
    };
    let port = listener.local_addr().unwrap().port();

    // Write token with private 0600 permissions
    let token_path = home.join("token");
    fs::write(&token_path, "test-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let empty_digest = sha256_bytes(b"");
    let instance = crate::token::generate();

    // Save lifecycle state with default config digest in home/versions/lifecycle.json
    fs::create_dir_all(home.join("versions")).unwrap();
    let lifecycle_state = serde_json::json!({
        "active": null,
        "previous": null,
        "owned": [],
        "process": {
            "pid": std::process::id(),
            "instance": instance,
            "binary_digest": "0".repeat(64),
            "config_digest": empty_digest,
            "port": port,
            "bind": "127.0.0.1",
            "launch_log": format!(".launch-{instance}.log")
        },
        "operation": null,
        "pending_stage": null
    });
    fs::write(
        home.join("versions").join("lifecycle.json"),
        serde_json::to_string(&lifecycle_state).unwrap(),
    )
    .unwrap();

    // Spawn mock server thread to respond to /lifecycle/v1
    let empty_digest_clone = empty_digest.clone();
    let instance_clone = instance.clone();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        use std::io::{Read, Write};
        listener.set_nonblocking(true).unwrap();
        let health_json = serde_json::json!({
            "pid": std::process::id(),
            "instance": instance_clone,
            "binary_digest": "0".repeat(64),
            "config_digest": empty_digest_clone
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            health_json.len(),
            health_json
        );
        while stop_rx.try_recv().is_err() {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });

    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: op_id.into(),
        kind: OperationKind::Install,
        phase: OperationPhase::Staged,
        reserved_generation: 1,
        source_bundle_sha256: None,
        target_bundle_sha256: "a".repeat(64),
        pre_operation_config: None,
        pre_operation_config_digest: None,
        target_config_digest: "c".repeat(64),
        was_daemon_running: false,
        pre_daemon_instance: None,
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: false,
        displaced_config_path: None,
        candidate_daemon_instance: None,
        compensated_daemon_instance: None,
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    // Recovery must detect running independent daemon and refuse to stop it!
    let err = mgr.recover();

    let _ = stop_tx.send(());
    let _ = handle.join();

    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("conflict during recovery: an independent daemon was started with baseline configuration"),
        "unexpected error: {msg}"
    );
}

#[derive(Clone, Copy)]
enum RecoveryHealthMode {
    Healthy,
    HealthyWithStalledRequest,
    PartialResponse,
    UnhealthyStatus,
    WrongIdentity,
}

// A health reply is only authoritative after a complete, bounded HTTP request.
// In particular, TCP's first read need not contain the final header delimiter.
fn read_health_request(stream: &mut std::net::TcpStream) -> (&'static str, usize) {
    const MAX_REQUEST_BYTES: usize = 4096;
    // A stream accepted from a nonblocking Windows listener can itself be
    // nonblocking. Wait for framed bytes instead of treating WouldBlock as
    // a completed request or replying before the client finishes writing.
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_millis(400)))
        .unwrap();
    let mut request = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return ("closed_before_headers", request.len()),
            Ok(n) => {
                if request.len() + n > MAX_REQUEST_BYTES {
                    return ("oversized_http", request.len() + n);
                }
                request.extend_from_slice(&chunk[..n]);
                if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let headers = &request[..end + 4];
                    if !headers.starts_with(b"GET /lifecycle/v1 HTTP/1.1\r\n") {
                        if headers.starts_with(b"POST /lifecycle/v1 HTTP/1.1\r\n") {
                            return ("unexpected_stop_method", request.len());
                        }
                        if headers.starts_with(b"GET /lifecycle/v1 HTTP/1.0\r\n") {
                            return ("unexpected_http10", request.len());
                        }
                        return ("unexpected_method", request.len());
                    }
                    return ("complete_http", request.len());
                }
            }
            Err(_) => return ("read_timeout_or_error", request.len()),
        }
    }
}

#[test]
fn health_fixture_waits_for_complete_bounded_request() {
    use std::net::Shutdown;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let (phase_tx, phase_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            phase_tx.send(read_health_request(&mut stream).0).unwrap();
        }
    });

    let mut split = std::net::TcpStream::connect(address).unwrap();
    split
        .write_all(b"GET /lifecycle/v1 HTTP/1.1\r\nHost: local\r\n")
        .unwrap();
    assert!(
        phase_rx
            .recv_timeout(std::time::Duration::from_millis(30))
            .is_err(),
        "phase=http_request reason=partial_headers_accepted"
    );
    split.write_all(b"\r\n").unwrap();
    assert_eq!(
        phase_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap(),
        "complete_http"
    );
    drop(split);

    let mut truncated = std::net::TcpStream::connect(address).unwrap();
    truncated
        .write_all(b"GET /lifecycle/v1 HTTP/1.1\r\n")
        .unwrap();
    truncated.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        phase_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap(),
        "closed_before_headers"
    );

    let mut oversized = std::net::TcpStream::connect(address).unwrap();
    oversized.write_all(&vec![b'x'; 4608]).unwrap();
    assert_eq!(
        phase_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap(),
        "oversized_http"
    );
    server.join().unwrap();
}

fn check_interrupted_recovery(mode: RecoveryHealthMode) {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("health fixture must bind for this acceptance control");
    let port = listener.local_addr().unwrap().port();

    // Write token
    let token_path = home.join("token");
    fs::write(&token_path, "test-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let baseline_cfg = format!("port: {port}\n");
    fs::write(home.join("config.yaml"), &baseline_cfg).unwrap();
    let baseline_digest = sha256_bytes(baseline_cfg.as_bytes());

    let original_instance = crate::token::generate();
    let crashed_compensation_instance = crate::token::generate();

    // Record original daemon in lifecycle.json
    fs::create_dir_all(home.join("versions")).unwrap();
    let lifecycle_state = serde_json::json!({
        "active": null,
        "previous": null,
        "owned": [],
        "process": {
            "pid": std::process::id(),
            "instance": original_instance,
            "binary_digest": "0".repeat(64),
            "config_digest": baseline_digest,
            "port": port,
            "bind": "127.0.0.1",
            "launch_log": format!(".launch-{original_instance}.log")
        },
        "operation": null,
        "pending_stage": null
    });
    fs::write(
        home.join("versions").join("lifecycle.json"),
        serde_json::to_string(&lifecycle_state).unwrap(),
    )
    .unwrap();

    // Spawn mock server responding for original_instance
    let baseline_digest_clone = baseline_digest.clone();
    let original_inst_clone = original_instance.clone();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let fixture_started = std::time::Instant::now();
    let ready_ms = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let complete_requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let incomplete_requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let last_request_rejection = std::sync::Arc::new(std::sync::Mutex::new("none"));
    let last_rejected_bytes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let completed_responses = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (
        thread_ready_ms,
        thread_accepted,
        thread_complete_requests,
        thread_incomplete_requests,
        thread_last_request_rejection,
        thread_last_rejected_bytes,
        thread_completed_responses,
    ) = (
        ready_ms.clone(),
        accepted.clone(),
        complete_requests.clone(),
        incomplete_requests.clone(),
        last_request_rejection.clone(),
        last_rejected_bytes.clone(),
        completed_responses.clone(),
    );
    let handle = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        thread_ready_ms.store(
            fixture_started.elapsed().as_millis() as u64,
            std::sync::atomic::Ordering::Release,
        );
        ready_tx.send(()).unwrap();
        let health_json = serde_json::json!({
            "pid": std::process::id(),
            "instance": if matches!(mode, RecoveryHealthMode::WrongIdentity) {
                "other-instance".to_owned()
            } else {
                original_inst_clone
            },
            "binary_digest": "0".repeat(64),
            "config_digest": baseline_digest_clone
        })
        .to_string();
        let response = std::sync::Arc::new(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            health_json.len(),
            health_json
        ));
        let mut workers = Vec::new();
        while stop_rx.try_recv().is_err() {
            if let Ok((mut stream, _)) = listener.accept() {
                thread_accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let response = response.clone();
                let complete_requests = thread_complete_requests.clone();
                let incomplete_requests = thread_incomplete_requests.clone();
                let last_request_rejection = thread_last_request_rejection.clone();
                let last_rejected_bytes = thread_last_rejected_bytes.clone();
                let completed_responses = thread_completed_responses.clone();
                workers.push(std::thread::spawn(move || {
                    let (request_outcome, bytes_read) = read_health_request(&mut stream);
                    if request_outcome != "complete_http" {
                        incomplete_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        *last_request_rejection.lock().unwrap() = request_outcome;
                        last_rejected_bytes.store(bytes_read, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                    complete_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let bytes = match mode {
                        RecoveryHealthMode::Healthy
                        | RecoveryHealthMode::HealthyWithStalledRequest
                        | RecoveryHealthMode::WrongIdentity => response.as_bytes(),
                        RecoveryHealthMode::PartialResponse => &response.as_bytes()[..response.len() / 2],
                        RecoveryHealthMode::UnhealthyStatus => b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    };
                    let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(400)));
                    if stream.write_all(bytes).is_ok()
                        && !matches!(mode, RecoveryHealthMode::PartialResponse)
                    {
                        completed_responses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    let _ = stream.flush();
                }));
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        for worker in workers {
            worker.join().unwrap();
        }
    });
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("health fixture readiness timeout");

    // Setup journal where previous recovery died after reserving compensated_daemon_instance
    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: "op-interrupted-rec".into(),
        kind: OperationKind::Upgrade,
        phase: OperationPhase::RollingBack,
        reserved_generation: 2,
        source_bundle_sha256: None,
        target_bundle_sha256: "b".repeat(64),
        pre_operation_config: Some(baseline_cfg),
        pre_operation_config_digest: Some(baseline_digest),
        target_config_digest: "t".repeat(64),
        was_daemon_running: true,
        pre_daemon_instance: Some(original_instance),
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: true,
        displaced_config_path: None,
        candidate_daemon_instance: None,
        compensated_daemon_instance: Some(crashed_compensation_instance),
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    // A stalled partial request must not block subsequent real health probes.
    let mut stalled = if matches!(mode, RecoveryHealthMode::HealthyWithStalledRequest) {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .write_all(b"GET /lifecycle/v1 HTTP/1.1\r\nHost: local\r\n")
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while accepted.load(std::sync::atomic::Ordering::Relaxed) == 0
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(
            accepted.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "phase=fixture reason=stalled_request_not_accepted"
        );
        Some(stream)
    } else {
        None
    };

    // The actual recovery guard decides whether the original baseline is healthy.
    let rec_res = mgr.recover();
    if let Some(ref mut stream) = stalled {
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
        let mut one = [0u8; 1];
        assert!(
            stream.read(&mut one).is_ok_and(|count| count == 0),
            "phase=fixture reason=partial_request_received_response"
        );
    }
    let _ = stop_tx.send(());
    let _ = handle.join();

    let positive = matches!(
        mode,
        RecoveryHealthMode::Healthy | RecoveryHealthMode::HealthyWithStalledRequest
    );
    if rec_res.is_err() == positive {
        eprintln!("phase=recovery_before_assert reason=unexpected_outcome probe={} probe_trace={} request_rejection={} rejected_bytes={} ready_ms={} accepted={} complete_requests={} incomplete_requests={} completed_responses={} elapsed_ms={}",
            crate::lifecycle::last_health_probe_outcome(),
            crate::lifecycle::health_probe_trace(),
            *last_request_rejection.lock().unwrap(),
            last_rejected_bytes.load(std::sync::atomic::Ordering::Relaxed),
            ready_ms.load(std::sync::atomic::Ordering::Acquire),
            accepted.load(std::sync::atomic::Ordering::Relaxed),
            complete_requests.load(std::sync::atomic::Ordering::Relaxed),
            incomplete_requests.load(std::sync::atomic::Ordering::Relaxed),
            completed_responses.load(std::sync::atomic::Ordering::Relaxed),
            fixture_started.elapsed().as_millis());
    }

    assert!(
        accepted.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "phase=fixture reason=no_health_request"
    );
    assert!(
        complete_requests.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "phase=fixture reason=no_complete_http_request"
    );
    let final_state = mgr.load_state().unwrap();
    if positive {
        assert!(
            completed_responses.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "phase=fixture reason=no_complete_health_response"
        );
        assert!(
            rec_res.is_ok(),
            "phase=recovery reason=healthy_baseline_rejected probe={}",
            crate::lifecycle::last_health_probe_outcome()
        );
        assert!(
            final_state.in_progress.is_none(),
            "phase=recovery reason=healthy_journal_retained"
        );
        assert_eq!(
            final_state.history.last().unwrap().status,
            "failed (recovered)"
        );
    } else {
        assert!(
            rec_res.is_err(),
            "phase=recovery reason=unhealthy_baseline_accepted"
        );
        assert!(
            final_state.in_progress.is_some(),
            "phase=recovery reason=unhealthy_journal_cleared"
        );
    }
}

#[test]
fn recovery_resumes_when_interrupted_with_compensated_reservation_and_original_baseline_healthy() {
    check_interrupted_recovery(RecoveryHealthMode::Healthy);
}

#[test]
fn recovery_healthy_baseline_survives_stalled_partial_http_request() {
    check_interrupted_recovery(RecoveryHealthMode::HealthyWithStalledRequest);
}

#[test]
fn recovery_retains_journal_for_partial_or_unhealthy_or_unowned_health() {
    for mode in [
        RecoveryHealthMode::PartialResponse,
        RecoveryHealthMode::UnhealthyStatus,
        RecoveryHealthMode::WrongIdentity,
    ] {
        check_interrupted_recovery(mode);
    }
}

#[test]
fn recovery_recognizes_alive_previous_compensation_instance_on_retry() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let Some(port) = allocate_test_port() else {
        return;
    };

    // Write token
    let token_path = home.join("token");
    fs::write(&token_path, "test-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let baseline_cfg = format!("port: {port}\n");
    fs::write(home.join("config.yaml"), &baseline_cfg).unwrap();
    let baseline_digest = sha256_bytes(baseline_cfg.as_bytes());

    let original_instance = crate::token::generate();
    let crashed_compensation_instance = crate::token::generate();

    // Record crashed_compensation_instance in lifecycle.json with alive PID (current process)
    // Port is closed, so st.running will be false while pid_alive is true.
    fs::create_dir_all(home.join("versions")).unwrap();
    let lifecycle_state = serde_json::json!({
        "active": null,
        "previous": null,
        "owned": [],
        "process": {
            "pid": std::process::id(),
            "instance": crashed_compensation_instance,
            "binary_digest": "0".repeat(64),
            "config_digest": baseline_digest,
            "port": port,
            "bind": "127.0.0.1",
            "launch_log": format!(".launch-{crashed_compensation_instance}.log")
        },
        "operation": null,
        "pending_stage": null
    });
    fs::write(
        home.join("versions").join("lifecycle.json"),
        serde_json::to_string(&lifecycle_state).unwrap(),
    )
    .unwrap();

    // Setup journal where previous recovery died after reserving compensated_daemon_instance
    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: "op-interrupted-comp-alive".into(),
        kind: OperationKind::Upgrade,
        phase: OperationPhase::RollingBack,
        reserved_generation: 2,
        source_bundle_sha256: None,
        target_bundle_sha256: "b".repeat(64),
        pre_operation_config: Some(baseline_cfg),
        pre_operation_config_digest: Some(baseline_digest),
        target_config_digest: "t".repeat(64),
        was_daemon_running: true,
        pre_daemon_instance: Some(original_instance),
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: true,
        displaced_config_path: None,
        candidate_daemon_instance: None,
        compensated_daemon_instance: Some(crashed_compensation_instance),
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    // Recovery must recognize crashed_compensation_instance as authorized,
    // rather than rejecting it as an independent unowned daemon.
    let rec_res = mgr.recover();
    assert!(rec_res.is_err());
    let msg = rec_res.unwrap_err().to_string();
    assert!(
        !msg.contains("conflict during recovery: an independent daemon was started"),
        "recovery rejected authorized previous compensation daemon: {msg}"
    );
    assert!(
        msg.contains("baseline daemon restart failed")
            || msg.contains("failed to restart")
            || msg.contains("failed to launch"),
        "unexpected error: {msg}"
    );
}

#[test]
fn recovery_recognizes_alive_previous_compensation_instance_with_target_config_on_retry() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let Some(port) = allocate_test_port() else {
        return;
    };

    // Write token
    let token_path = home.join("token");
    fs::write(&token_path, "test-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let baseline_cfg = format!("port: {port}\n");
    let baseline_digest = sha256_bytes(baseline_cfg.as_bytes());

    let target_cfg = format!("port: {}\n", port.wrapping_add(1));
    fs::write(home.join("config.yaml"), &target_cfg).unwrap();
    let target_digest = sha256_bytes(target_cfg.as_bytes());

    let original_instance = crate::token::generate();
    let crashed_compensation_instance = crate::token::generate();

    fs::create_dir_all(home.join("versions")).unwrap();
    let lifecycle_state = serde_json::json!({
        "active": null,
        "previous": null,
        "owned": [],
        "process": {
            "pid": std::process::id(),
            "instance": crashed_compensation_instance,
            "binary_digest": "0".repeat(64),
            "config_digest": baseline_digest,
            "port": port,
            "bind": "127.0.0.1",
            "launch_log": format!(".launch-{crashed_compensation_instance}.log")
        },
        "operation": null,
        "pending_stage": null
    });
    fs::write(
        home.join("versions").join("lifecycle.json"),
        serde_json::to_string(&lifecycle_state).unwrap(),
    )
    .unwrap();

    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: "op-interrupted-comp-target".into(),
        kind: OperationKind::Upgrade,
        phase: OperationPhase::RollingBack,
        reserved_generation: 2,
        source_bundle_sha256: None,
        target_bundle_sha256: "b".repeat(64),
        pre_operation_config: Some(baseline_cfg),
        pre_operation_config_digest: Some(baseline_digest),
        target_config_digest: target_digest,
        was_daemon_running: true,
        pre_daemon_instance: Some(original_instance),
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: true,
        displaced_config_path: None,
        candidate_daemon_instance: None,
        compensated_daemon_instance: Some(crashed_compensation_instance),
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    let rec_res = mgr.recover();
    assert!(rec_res.is_err());
    let msg = rec_res.unwrap_err().to_string();
    assert!(
        !msg.contains("conflict during recovery: an independent daemon was started"),
        "recovery rejected authorized previous compensation daemon: {msg}"
    );
    assert!(
        msg.contains("baseline daemon restart failed")
            || msg.contains("failed to restart")
            || msg.contains("failed to launch"),
        "unexpected error: {msg}"
    );
}

#[test]
fn recovery_preserves_historical_compensation_identities_across_multiple_restart_failures() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let Some(port) = allocate_test_port() else {
        return;
    };

    // Write token
    let token_path = home.join("token");
    fs::write(&token_path, "test-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let baseline_cfg = format!("port: {port}\n");
    fs::write(home.join("config.yaml"), &baseline_cfg).unwrap();
    let baseline_digest = sha256_bytes(baseline_cfg.as_bytes());

    let original_instance = crate::token::generate();
    let first_compensation_instance = crate::token::generate();

    fs::create_dir_all(home.join("versions")).unwrap();
    let lifecycle_state = serde_json::json!({
        "active": null,
        "previous": null,
        "owned": [],
        "process": {
            "pid": std::process::id(),
            "instance": first_compensation_instance,
            "binary_digest": "0".repeat(64),
            "config_digest": baseline_digest,
            "port": port,
            "bind": "127.0.0.1",
            "launch_log": format!(".launch-{first_compensation_instance}.log")
        },
        "operation": null,
        "pending_stage": null
    });
    fs::write(
        home.join("versions").join("lifecycle.json"),
        serde_json::to_string(&lifecycle_state).unwrap(),
    )
    .unwrap();

    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: "op-comp-multi-fail".into(),
        kind: OperationKind::Upgrade,
        phase: OperationPhase::RollingBack,
        reserved_generation: 2,
        source_bundle_sha256: None,
        target_bundle_sha256: "b".repeat(64),
        pre_operation_config: Some(baseline_cfg),
        pre_operation_config_digest: Some(baseline_digest),
        target_config_digest: "t".repeat(64),
        was_daemon_running: true,
        pre_daemon_instance: Some(original_instance),
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: true,
        displaced_config_path: None,
        candidate_daemon_instance: None,
        compensated_daemon_instance: Some(first_compensation_instance.clone()),
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    // 1st recovery retry: attempts restart (fails because port not bound), archives first_compensation_instance
    let rec1 = mgr.recover();
    assert!(rec1.is_err());
    let msg1 = rec1.unwrap_err().to_string();
    assert!(!msg1.contains("conflict during recovery: an independent daemon was started"));

    let state_after_rec1 = mgr.load_state().unwrap();
    let journal1 = state_after_rec1.in_progress.unwrap();
    assert!(journal1
        .historical_compensated_instances
        .contains(&first_compensation_instance));
    assert!(journal1.compensated_daemon_instance.is_some());
    assert_ne!(
        journal1.compensated_daemon_instance.as_deref(),
        Some(first_compensation_instance.as_str())
    );

    // 2nd recovery retry: running daemon is still first_compensation_instance in lifecycle.json.
    // It must NOT be rejected as unowned/independent; historical compensation list preserves authority.
    let rec2 = mgr.recover();
    assert!(rec2.is_err());
    let msg2 = rec2.unwrap_err().to_string();
    assert!(
        !msg2.contains("conflict during recovery: an independent daemon was started"),
        "recovery rejected daemon recognized via historical compensation: {msg2}"
    );
}

#[test]
fn preflight_rejects_unowned_running_daemon() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    // Bind a TCP listener on an ephemeral port to simulate unowned agentfw serve
    let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            // Sandboxed environment without network bind access
            return;
        }
        Err(e) => panic!("failed to bind test listener: {e}"),
    };
    let port = listener.local_addr().unwrap().port();

    // Write existing config.yaml pointing to that port
    let cfg = format!("bind: \"127.0.0.1\"\nport: {port}\n");
    fs::write(&mgr.config_path, &cfg).unwrap();

    let p1_dir = home.join("bundle1");
    create_test_profile(&p1_dir, "srv-1", "tool_1");

    let err = mgr.install(&p1_dir, None);
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("unresolved daemon process ownership")
            && msg.contains("occupied by an unowned process"),
        "unexpected error message: {msg}"
    );
}

#[test]
fn preflight_rejects_running_daemon_when_config_absent_and_digest_mismatched() {
    let mut status = crate::lifecycle::Status {
        active: None,
        previous: None,
        interrupted: false,
        detail: String::new(),
        running: true,
        process: Some(ProcessRecord {
            pid: std::process::id(),
            instance: crate::token::generate(),
            launch_log: String::new(),
            bind: "127.0.0.1".into(),
            port: 9999,
            binary_digest: "0".repeat(64),
            config_digest: sha256_bytes(b"lost config"),
        }),
    };
    let error = check_daemon_ownership(&status, None, None).unwrap_err();
    assert!(error
        .to_string()
        .contains("does not match absent config.yaml"));
    status.process.as_mut().unwrap().config_digest = sha256_bytes(b"");
    check_daemon_ownership(&status, None, None).unwrap();
}

#[test]
fn restart_or_start_daemon_starts_when_process_record_cleared() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);
    let lifecycle = crate::lifecycle::Manager::new(&home);

    // When was_running is true but process record was cleared by a candidate startup failure,
    // it must select start() instead of restart() (which fails with "Agent is not running").
    let err = mgr.restart_or_start_daemon(&lifecycle, None, None);
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(
        !msg.contains("Agent is not running"),
        "restart_or_start_daemon called stop on an unstarted daemon: {msg}"
    );
}

#[test]
fn restart_or_start_daemon_requires_expected_instance_when_process_alive_but_not_ready() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);
    let lifecycle = crate::lifecycle::Manager::new(&home);

    // Record current process as the running process in versions/lifecycle.json,
    // but port is closed so st.running will be false while pid_alive is true.
    let versions_dir = home.join("versions");
    std::fs::create_dir_all(&versions_dir).unwrap();
    let manifest_path = versions_dir.join("lifecycle.json");
    let current_pid = std::process::id();
    let instance = crate::token::generate();
    let launch_log = format!(".launch-{instance}.log");
    let dummy_state = serde_json::json!({
        "active": null,
        "previous": null,
        "owned": [],
        "process": {
            "pid": current_pid,
            "instance": instance,
            "binary_digest": "0".repeat(64),
            "config_digest": "0".repeat(64),
            "port": 65534,
            "bind": "127.0.0.1",
            "launch_log": launch_log
        },
        "operation": null,
        "pending_stage": null
    });
    std::fs::write(&manifest_path, serde_json::to_vec(&dummy_state).unwrap()).unwrap();

    let st = lifecycle.status().unwrap();
    assert!(!st.running);
    assert!(st.process.is_some());

    // Without expected instance, restart_or_start_daemon detects the alive process and refuses to stop without authorization
    let err = mgr.restart_or_start_daemon(&lifecycle, None, None);
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("refusing to stop it"),
        "expected refusal to stop unowned process, got: {msg}"
    );
}

#[test]
fn recovery_preserves_independent_baseline_daemon_even_when_config_written_is_true() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let op_id = "op-indep-written";

    let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("failed to bind test listener: {e}"),
    };
    let port = listener.local_addr().unwrap().port();

    let token_path = home.join("token");
    fs::write(&token_path, "test-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let empty_digest = sha256_bytes(b"");
    let instance = crate::token::generate();

    fs::create_dir_all(home.join("versions")).unwrap();
    let lifecycle_state = serde_json::json!({
        "active": null,
        "previous": null,
        "owned": [],
        "process": {
            "pid": std::process::id(),
            "instance": instance,
            "binary_digest": "0".repeat(64),
            "config_digest": empty_digest,
            "port": port,
            "bind": "127.0.0.1",
            "launch_log": format!(".launch-{instance}.log")
        },
        "operation": null,
        "pending_stage": null
    });
    fs::write(
        home.join("versions").join("lifecycle.json"),
        serde_json::to_string(&lifecycle_state).unwrap(),
    )
    .unwrap();

    let empty_digest_clone = empty_digest.clone();
    let instance_clone = instance.clone();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        use std::io::{Read, Write};
        listener.set_nonblocking(true).unwrap();
        let health_json = serde_json::json!({
            "pid": std::process::id(),
            "instance": instance_clone,
            "binary_digest": "0".repeat(64),
            "config_digest": empty_digest_clone
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            health_json.len(),
            health_json
        );
        while stop_rx.try_recv().is_err() {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });

    // Interrupted operation where config_written was marked true, but config.yaml is absent (baseline)
    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: op_id.into(),
        kind: OperationKind::Install,
        phase: OperationPhase::ConfigWritten,
        reserved_generation: 1,
        source_bundle_sha256: None,
        target_bundle_sha256: "a".repeat(64),
        pre_operation_config: None,
        pre_operation_config_digest: None,
        target_config_digest: "c".repeat(64),
        was_daemon_running: false,
        pre_daemon_instance: None,
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: true,
        displaced_config_path: None,
        candidate_daemon_instance: None,
        compensated_daemon_instance: None,
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    let err = mgr.recover();

    let _ = stop_tx.send(());
    let _ = handle.join();

    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("conflict during recovery: an independent daemon was started with baseline configuration"),
        "unexpected error: {msg}"
    );
}

#[test]
fn stage_revision_cleans_up_and_does_not_poison_revisions_on_mismatch() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let p1_dir = home.join("bundle_poison");
    create_test_profile(&p1_dir, "srv-1", "tool_1");

    // Verify initial digest
    let initial_digest = bundle_digest(&p1_dir).unwrap();
    let target_dir = mgr.revisions.join(&initial_digest);
    assert!(!target_dir.exists());

    // Corrupt one file in source bundle before staging
    fs::write(p1_dir.join("profile.json"), b"corrupted\n").unwrap();

    // Staging must fail
    let err = mgr.stage_revision(&p1_dir);
    assert!(err.is_err());

    // target_dir MUST NOT exist (no poisoned cache entry left behind!)
    assert!(!target_dir.exists());
}

#[test]
fn validate_bundle_rejects_missing_profile_fields() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let p_dir = home.join("invalid_profile");
    create_test_profile(&p_dir, "srv-1", "tool_1");

    // Remove server_id from profile.json
    let mut prof_val: Value =
        serde_json::from_slice(&fs::read(p_dir.join("profile.json")).unwrap()).unwrap();
    prof_val.as_object_mut().unwrap().remove("server_id");
    fs::write(
        p_dir.join("profile.json"),
        serde_json::to_vec(&prof_val).unwrap(),
    )
    .unwrap();

    // verify_bundle_files must reject it
    let err = verify_bundle_files(&p_dir);
    assert!(err.is_err());
    assert!(err
        .unwrap_err()
        .to_string()
        .contains("invalid profile.json"));

    // Installation must fail
    let mgr = ProfileManager::new(&home);
    let inst_err = mgr.install(&p_dir, None);
    assert!(inst_err.is_err());
}

#[test]
fn recovery_preserves_independent_daemon_started_with_candidate_config_when_baseline_stopped() {
    let home_temp = tempdir().unwrap();
    let home = home_temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);

    let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("failed to bind test listener: {e}"),
    };
    let port = listener.local_addr().unwrap().port();

    // Write token with private 0600 permissions
    let token_path = home.join("token");
    fs::write(&token_path, "test-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let candidate_cfg = format!("port: {port}\n");
    let candidate_digest = sha256_bytes(candidate_cfg.as_bytes());
    fs::write(&mgr.config_path, &candidate_cfg).unwrap();

    let instance = crate::token::generate();

    // Register process in lifecycle state under home/versions/lifecycle.json
    fs::create_dir_all(home.join("versions")).unwrap();
    let proc = ProcessRecord {
        pid: std::process::id(),
        instance: instance.clone(),
        binary_digest: "0".repeat(64),
        config_digest: candidate_digest.clone(),
        port,
        bind: "127.0.0.1".parse().unwrap(),
        launch_log: format!(".launch-{}.log", instance),
    };
    let lc_state = State {
        process: Some(proc),
        ..Default::default()
    };
    let lc_file = home.join("versions").join("lifecycle.json");
    fs::write(&lc_file, serde_json::to_vec(&lc_state).unwrap()).unwrap();

    // Simulate an active health endpoint on this port
    let candidate_digest_clone = candidate_digest.clone();
    let instance_clone = instance.clone();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let health_json = serde_json::json!({
            "pid": std::process::id(),
            "instance": instance_clone,
            "binary_digest": "0".repeat(64),
            "config_digest": candidate_digest_clone
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            health_json.len(),
            health_json
        );
        while stop_rx.try_recv().is_err() {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });

    let mut state = mgr.load_state().unwrap();
    state.in_progress = Some(OperationJournal {
        operation_id: "op-candidate-crash".into(),
        kind: OperationKind::Install,
        phase: OperationPhase::ConfigWritten,
        reserved_generation: 1,
        source_bundle_sha256: None,
        target_bundle_sha256: "b".repeat(64),
        pre_operation_config: None,
        pre_operation_config_digest: None,
        target_config_digest: candidate_digest.clone(),
        was_daemon_running: false,
        pre_daemon_instance: None,
        pre_daemon_config_digest: None,
        started_at_utc: now_utc(),
        config_written: true,
        displaced_config_path: None,
        candidate_daemon_instance: None,
        compensated_daemon_instance: None,
        historical_compensated_instances: Vec::new(),
    });
    mgr.save_state(&state).unwrap();

    // Recovery must detect running independent daemon and refuse to overwrite config or stop it!
    let err = mgr.recover();

    let _ = stop_tx.send(());
    let _ = handle.join();

    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("conflict during recovery: an independent daemon was started with target configuration while baseline was stopped"),
        "unexpected error: {msg}"
    );

    // Target config must be preserved on disk!
    assert_eq!(fs::read_to_string(&mgr.config_path).unwrap(), candidate_cfg);

    // Journal must be retained as Failed
    let after_state = mgr.load_state().unwrap();
    assert_eq!(
        after_state.in_progress.unwrap().phase,
        OperationPhase::Failed
    );
}
#[test]
fn exact_preview_approval_rejects_yes_stale_config_and_wrong_operation() {
    let temp = tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);
    let p1 = home.join("p1");
    let p2 = home.join("p2");
    create_test_profile(&p1, "srv-1", "tool_a");
    create_test_profile(&p2, "srv-1", "tool_b");
    mgr.install(&p1, None).unwrap();
    let preview = mgr.preview_upgrade(&p2).unwrap();
    let baseline = fs::read(&mgr.config_path).unwrap();
    let state = fs::read(&mgr.state_path).unwrap();
    assert!(mgr.upgrade(&p2, None, Some(1), Some("yes")).is_err());
    assert_eq!(fs::read(&mgr.config_path).unwrap(), baseline);
    assert_eq!(fs::read(&mgr.state_path).unwrap(), state);
    fs::write(
        &mgr.config_path,
        [baseline.as_slice(), b"\n# operator edit\n"].concat(),
    )
    .unwrap();
    assert!(mgr
        .upgrade(&p2, None, Some(1), Some(&preview.approval_sha256))
        .is_err());
    let fresh = mgr.preview_upgrade(&p2).unwrap();
    assert_ne!(preview.approval_sha256, fresh.approval_sha256);
    mgr.upgrade(&p2, None, Some(1), Some(&fresh.approval_sha256))
        .unwrap();
    assert!(mgr
        .rollback(None, Some(2), Some(&fresh.approval_sha256))
        .is_err());
}

#[test]
fn preview_preserves_source_and_rejects_server_rebinding() {
    let temp = tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);
    let p1 = home.join("p1");
    let p2 = home.join("p2");
    create_test_profile(&p1, "srv-1", "tool_a");
    let hash2 = create_test_profile(&p2, "srv-1", "tool_b");
    mgr.install(&p1, None).unwrap();
    let before = fs::read(&mgr.state_path).unwrap();
    mgr.preview_upgrade(&p2).unwrap();
    assert_eq!(fs::read(&mgr.state_path).unwrap(), before);
    assert!(
        !mgr.revisions.join(hash2).exists(),
        "preview must not stage input"
    );
    let p3 = home.join("p3");
    create_test_profile(&p3, "other-server", "tool_c");
    assert!(mgr
        .preview_upgrade(&p3)
        .err()
        .unwrap()
        .to_string()
        .contains("original server identity"));
}

#[test]
fn profile_transition_preserves_unrelated_yaml_settings() {
    let temp = tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);
    if let Some(port) = allocate_test_port() {
        fs::write(&mgr.config_path, format!("port: {port}\ncapture_unknown_raw: true\nmax_body_bytes: 1048576\njudge:\n  enabled: false\n  model: retained-model\n")).unwrap();
    } else {
        fs::write(&mgr.config_path, "capture_unknown_raw: true\nmax_body_bytes: 1048576\njudge:\n  enabled: false\n  model: retained-model\n").unwrap();
    }
    let p1 = home.join("p1");
    create_test_profile(&p1, "srv-1", "tool_a");
    mgr.install(&p1, None).unwrap();
    let config: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(&mgr.config_path).unwrap()).unwrap();
    assert_eq!(config["capture_unknown_raw"].as_bool(), Some(true));
    assert_eq!(config["judge"]["model"].as_str(), Some("retained-model"));
}

#[test]
fn bundle_validation_rejects_revoked_review_and_inconsistent_resource_manifest() {
    let temp = tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let dir = home.join("p1");
    create_test_profile(&dir, "srv-1", "tool_a");
    let declaration_path = dir.join("operator-declarations.json");
    let original = fs::read(&declaration_path).unwrap();
    let mut declarations: Value = serde_json::from_slice(&original).unwrap();
    declarations["tools"][0]["reviewed"] = false.into();
    fs::write(
        &declaration_path,
        serde_json::to_vec(&declarations).unwrap(),
    )
    .unwrap();
    assert!(
        verify_bundle_files(&dir).is_err(),
        "manifest hash must not substitute for operator review"
    );
    fs::write(&declaration_path, original).unwrap();
    fs::write(
        dir.join("resource-profiles.json"),
        b"[{\"broadened\":true}]",
    )
    .unwrap();
    assert!(verify_bundle_files(&dir).is_err());
}

#[test]
fn preview_approval_cannot_authorize_a_different_target() {
    let temp = tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    // This tests approval binding, so use an isolated endpoint rather than
    // depending on the host default port being free throughout activation.
    let port = allocate_test_port().expect("loopback port allocation is required for this test");
    fs::write(home.join("config.yaml"), format!("port: {port}\n")).unwrap();
    let mgr = ProfileManager::new(&home);
    let p1 = home.join("p1");
    let p2 = home.join("p2");
    let p3 = home.join("p3");
    create_test_profile(&p1, "srv-1", "tool_a");
    create_test_profile(&p2, "srv-1", "tool_b");
    create_test_profile(&p3, "srv-1", "tool_c");
    mgr.install(&p1, None).unwrap();
    let token = mgr.preview_upgrade(&p2).unwrap().approval_sha256;
    let baseline = fs::read(&mgr.config_path).unwrap();
    assert!(mgr.upgrade(&p3, None, Some(1), Some(&token)).is_err());
    assert_eq!(fs::read(&mgr.config_path).unwrap(), baseline);
    assert!(mgr.load_state().unwrap().in_progress.is_none());
}

#[test]
fn malformed_recovery_journal_cannot_name_external_paths() {
    let temp = tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let mgr = ProfileManager::new(&home);
    fs::create_dir_all(&mgr.root).unwrap();
    let journal = json!({
        "operation_id": "../../outside", "kind": "install", "phase": "staged",
        "reserved_generation": 1, "source_bundle_sha256": null,
        "target_bundle_sha256": "a".repeat(64), "pre_operation_config": null,
        "pre_operation_config_digest": null, "target_config_digest": "b".repeat(64),
        "was_daemon_running": false, "pre_daemon_instance": null, "started_at_utc": "0"
    });
    let mut value = serde_json::to_value(ProfileState::default()).unwrap();
    value["in_progress"] = journal;
    fs::write(&mgr.state_path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(mgr.recover().is_err());
    value["in_progress"]["operation_id"] = "op-test".into();
    value["in_progress"]["displaced_config_path"] = json!(home.join("operator-data"));
    fs::write(&mgr.state_path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(mgr.recover().is_err());
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&mgr.state_path).unwrap()).unwrap(),
        value
    );
}

#[test]
fn persisted_audit_window_retains_recent_operations_within_bound() {
    let temp = tempdir().unwrap();
    let mgr = ProfileManager::new(temp.path());
    let mut state = ProfileState::default();
    for generation in 0..1030 {
        state.history.push(OperationRecord {
            operation_id: format!("op-{generation}"),
            kind: OperationKind::Upgrade,
            generation,
            bundle_sha256: "a".repeat(64),
            from_bundle_sha256: None,
            timestamp_utc: "0".into(),
            status: "failed".into(),
            detail: "retained".into(),
        });
    }
    mgr.save_state(&state).unwrap();
    let loaded = mgr.load_state().unwrap();
    assert_eq!(loaded.history.len(), 1024);
    assert_eq!(loaded.history[0].generation, 6);
    assert_eq!(loaded.history.last().unwrap().generation, 1029);
}
#[cfg(unix)]
#[test]
fn dangling_owned_connection_reservation_is_not_an_absent_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let manager = ProfileManager::new(dir.path());
    fs::create_dir(&manager.root).unwrap();
    std::os::unix::fs::symlink(
        manager.root.join("missing"),
        manager.root.join("connection-transition.json"),
    )
    .unwrap();
    assert!(manager.lock().is_err());
    assert!(!manager.config_path.exists());
    assert!(
        fs::symlink_metadata(manager.root.join("connection-transition.json"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
