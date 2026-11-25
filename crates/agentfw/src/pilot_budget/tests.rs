// SPDX-License-Identifier: Apache-2.0
use super::*;

fn fixture() -> (tempfile::TempDir, Binding, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = Config::read(br#"{"format":"sw-mcp/linux-cgroup-budget/1","delegationRoot":"/sys/fs/cgroup/owned-pilot","memoryMaxBytes":268435456,"pidsMax":64,"cpuQuotaMicros":100000,"wallMillis":30000}"#).unwrap();
    let records = directory.join("budget-records");
    fs::create_dir(&records).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&records, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config_path = directory.join("linux-budget.json");
    write_json(&config_path, &config).unwrap();
    let binding = Binding {
        format: FORMAT.into(),
        host_session: "owned-host".into(),
        budget_sha256: config.identity(),
        config: config_path,
        root: RootIdentity {
            device: 0,
            inode: 0,
        },
        records,
    };
    let path = directory.join("linux-budget-binding.json");
    write_json(&path, &binding).unwrap();
    (temp, binding, path)
}

#[cfg(unix)]
fn metadata(binding: &Binding, failed: bool, cleanup: bool) -> Value {
    json!({"format":crate::mcp::linux_budget::FORMAT,"budget_sha256":binding.budget_sha256,
        "failed":failed,"cleanup_verified":cleanup,"reason":if failed {"mcp_budget_wall_expired"}
        else {"mcp_budget_enforced"},"stats":{"pids_current":0,"pids_peak_kernel":false},
        "leaf":"agentfw-mcp-00000000000000000000000000000000",
        "membership_failure":{"private_pid":12345}})
}

#[cfg(unix)]
fn selection(binding: &Binding) -> VerifiedSelection {
    VerifiedSelection {
        binding: binding.clone(),
        bound: BoundConfig {
            config: Config::load_file(&binding.config).unwrap(),
            root: (binding.root.device, binding.root.inode),
        },
        records: pin_records_directory(&binding.records).unwrap(),
    }
}

#[test]
fn drift_between_validation_and_snapshot_refuses_before_root_access() {
    let (temp, binding, _path) = fixture();
    let result = RunBudget::prepare(
        &binding.config,
        temp.path(),
        "owned-host",
        "changed-identity",
    );
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("pilot_budget_selection_changed"));
    assert!(!temp.path().join("selection-status.json").exists());
}

#[test]
#[cfg(unix)]
fn dead_child_without_terminal_receipt_stays_unresolved() {
    let (_temp, binding, path) = fixture();
    let mut record = selection(&binding).reserve("filesystem").unwrap();
    record
        .record(metadata(&binding, false, false), false)
        .unwrap();
    assert_eq!(summarize(&path).unwrap()["status"], "unresolved");
}

#[test]
#[cfg(unix)]
fn verified_selection_never_reloads_replaced_config_bytes() {
    let (_temp, binding, _path) = fixture();
    let selected = selection(&binding);
    let accepted = selected.bound().config.identity();
    fs::write(&binding.config, b"operator replacement").unwrap();
    assert_eq!(selected.bound().config.identity(), accepted);
    let record = selected.reserve("filesystem").unwrap();
    assert_eq!(record.value.budget_sha256, accepted);
    assert_eq!(fs::read(&binding.config).unwrap(), b"operator replacement");
}

#[test]
#[cfg(unix)]
fn replaced_records_directory_cannot_redirect_reservation_into_workspace() {
    let (temp, binding, _path) = fixture();
    let selected = selection(&binding);
    let original = temp.path().join("original-records");
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let marker = workspace.join("notes.txt");
    fs::write(&marker, b"operator workspace").unwrap();
    fs::rename(&binding.records, &original).unwrap();
    std::os::unix::fs::symlink(&workspace, &binding.records).unwrap();

    assert!(selected
        .reserve("filesystem")
        .err()
        .unwrap()
        .to_string()
        .contains("pilot_budget_records_replaced"));
    assert_eq!(fs::read(&marker).unwrap(), b"operator workspace");
    assert_eq!(fs::read_dir(&workspace).unwrap().count(), 1);
    assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
    assert!(fs::symlink_metadata(&binding.records)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
#[cfg(unix)]
fn replaced_records_directory_preserves_both_inventories() {
    use std::os::unix::fs::PermissionsExt;
    let (temp, binding, _path) = fixture();
    let selected = selection(&binding);
    let original = temp.path().join("original-records");
    fs::rename(&binding.records, &original).unwrap();
    fs::create_dir(&binding.records).unwrap();
    fs::set_permissions(&binding.records, fs::Permissions::from_mode(0o700)).unwrap();
    let replacement = binding.records.join("00.json");
    fs::write(&replacement, b"operator replacement").unwrap();

    assert!(selected
        .reserve("git")
        .err()
        .unwrap()
        .to_string()
        .contains("pilot_budget_records_replaced"));
    assert_eq!(fs::read(&replacement).unwrap(), b"operator replacement");
    assert_eq!(fs::read_dir(&binding.records).unwrap().count(), 1);
    assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
}

#[test]
#[cfg(unix)]
fn directory_replacement_after_reservation_refuses_record_updates() {
    use std::os::unix::fs::PermissionsExt;
    let (temp, binding, _path) = fixture();
    let mut record = selection(&binding).reserve("filesystem").unwrap();
    let before = fs::read(&record.path).unwrap();
    let original = temp.path().join("original-records");
    fs::rename(&binding.records, &original).unwrap();
    fs::create_dir(&binding.records).unwrap();
    fs::set_permissions(&binding.records, fs::Permissions::from_mode(0o700)).unwrap();
    let replacement = binding.records.join("00.json");
    fs::write(&replacement, b"operator replacement").unwrap();

    assert!(record
        .record(metadata(&binding, false, true), true)
        .err()
        .unwrap()
        .to_string()
        .contains("pilot_budget_records_replaced"));
    drop(record);
    assert_eq!(fs::read(&replacement).unwrap(), b"operator replacement");
    assert_eq!(fs::read(original.join("00.json")).unwrap(), before);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an explicit empty already-delegated owned SOU142_BUDGET_CONFIG"]
fn native_readonly_preflight_and_bound_root_identity() {
    use std::os::unix::fs::MetadataExt;
    let path = std::env::var_os("SOU142_BUDGET_CONFIG").expect("explicit owned config");
    let config = Config::load_file(Path::new(&path)).unwrap();
    let names = || {
        fs::read_dir(&config.delegation_root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>()
    };
    let before = names();
    config.probe_delegation().unwrap();
    assert_eq!(names(), before, "preflight must not create a cgroup");
    let meta = fs::metadata(&config.delegation_root).unwrap();
    let wrong = BoundConfig {
        config: config.clone(),
        root: (meta.dev(), meta.ino() ^ 1),
    };
    assert!(crate::mcp::linux_budget::OwnedBudget::prepare_bound(&wrong)
        .err()
        .unwrap()
        .to_string()
        .contains("pilot_budget_root_changed"));
    assert_eq!(
        names(),
        before,
        "root drift must refuse before leaf creation"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "private child helper; requires the explicit native witness controller"]
fn native_owner_first_collector_child() -> Result<()> {
    preowner_witness::child()
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicit SOU142_BUDGET_CONFIG, SOU142_OWNER_PROFILE and SOU86_TEST_AGENTFW"]
fn native_owner_first_preparation_parent_loss() -> Result<()> {
    preowner_witness::reproduce(false).map_err(|_| {
        println!(
            "{}",
            json!({"format":"sou142-owner-first-parent-loss/1","status":"incomplete",
                "reason":"preowner_witness_setup_or_cleanup_unverified","acceptance_pass":false})
        );
        anyhow::anyhow!("preowner_witness_setup_or_cleanup_unverified")
    })
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicit SOU142_BUDGET_CONFIG, SOU142_OWNER_PROFILE and SOU86_TEST_AGENTFW"]
fn native_owner_first_handback_parent_loss() -> Result<()> {
    preowner_witness::reproduce(true).map_err(|_| {
        println!(
            "{}",
            json!({"format":"sou142-owner-first-parent-loss/1","status":"incomplete",
            "reason":"preowner_witness_setup_or_cleanup_unverified","acceptance_pass":false})
        );
        anyhow::anyhow!("preowner_witness_setup_or_cleanup_unverified")
    })
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicit SOU142_BUDGET_CONFIG, SOU142_OWNER_PROFILE and SOU86_TEST_AGENTFW"]
fn native_outside_owner_sigkill_before_descriptor_handback() -> Result<()> {
    preowner_witness::reproduce_owner_loss().map_err(|error| {
        let message = error.to_string();
        let reason = match message.as_str() {
            "preowner_witness_child_failed_before_ready"
            | "preowner_witness_ready_timeout"
            | "preowner_witness_leaf_replaced"
            | "preowner_witness_leaf_populated"
            | "owner_loss_witness_one_outside_owner_required"
            | "owner_loss_witness_task_bound_exceeded"
            | "owner_loss_witness_child_bound_exceeded"
            | "owner_loss_witness_task_inventory_empty"
            | "owner_loss_witness_owner_image_changed"
            | "owner_loss_witness_owner_command_changed"
            | "owner_loss_witness_original_process_started"
            | "owner_loss_witness_owner_did_not_hold_leaf"
            | "owner_loss_witness_leaf_already_handed_back"
            | "owner_loss_witness_pidfd_unavailable"
            | "owner_loss_witness_parent_unverified"
            | "owner_loss_witness_owner_exited_before_signal"
            | "owner_loss_witness_sigkill_failed"
            | "owner_loss_witness_generic_startup_failure"
            | "owner_loss_witness_collector_failed"
            | "owner_loss_witness_outcome_unverified"
            | "owner_loss_witness_inventory_not_restored" => message.as_str(),
            _ => "outside_owner_loss_or_custody_unverified",
        };
        println!(
            "{}",
            json!({"format":"sou142-owner-first-parent-loss/1","status":"incomplete",
                "stage":"owner-loss-before-descriptor-handback",
                "reason":reason,"acceptance_pass":false})
        );
        anyhow::anyhow!("outside_owner_loss_or_custody_unverified")
    })
}

#[test]
#[cfg(unix)]
fn selected_is_not_active_and_unfinished_children_never_claim_success() {
    let (_temp, binding, path) = fixture();
    assert_eq!(
        summarize(&path).unwrap()["status"],
        "configured-not-observed"
    );
    let record = selection(&binding).reserve("filesystem").unwrap();
    assert_eq!(summarize(&path).unwrap()["status"], "unresolved");
    drop(record);
    assert_eq!(summarize(&path).unwrap()["unresolved_children"], 1);
}

#[test]
#[cfg(unix)]
fn terminal_refusals_and_missing_cleanup_are_honest_and_public_fields_are_finite() {
    let (_temp, binding, path) = fixture();
    let mut record = selection(&binding).reserve("git").unwrap();
    record
        .record(metadata(&binding, false, true), true)
        .unwrap();
    let value = summarize(&path).unwrap();
    assert_eq!(value["status"], "closed-enforced");
    assert_eq!(value["observations"][0]["counters"]["pids_current"], 0);
    let serialized = value.to_string();
    assert!(!serialized.contains("private_pid"));
    assert!(!serialized.contains("leaf"));
    record.record(metadata(&binding, true, true), true).unwrap();
    assert_eq!(summarize(&path).unwrap()["status"], "refused");
    record
        .record(metadata(&binding, true, false), true)
        .unwrap();
    assert_eq!(summarize(&path).unwrap()["status"], "unresolved");
}

#[test]
#[cfg(unix)]
fn changed_selection_or_record_identity_is_rejected() {
    let (_temp, binding, path) = fixture();
    let mut record = selection(&binding).reserve("git").unwrap();
    let mut wrong = metadata(&binding, false, true);
    wrong["budget_sha256"] = json!("other-run");
    assert!(record.record(wrong, true).is_err());
    record.value.host_session = "another-host".into();
    let value = record.value.clone();
    record.write(&value).unwrap();
    assert!(summarize(&path).is_err());
}

#[test]
#[cfg(unix)]
fn record_replacement_is_preserved_and_cannot_be_reported_successful() {
    let (_temp, binding, path) = fixture();
    let mut record = selection(&binding).reserve("filesystem").unwrap();
    fs::remove_file(&record.path).unwrap();
    fs::write(&record.path, b"operator replacement").unwrap();
    assert!(record
        .record(metadata(&binding, false, true), true)
        .is_err());
    let record_path = record.path.clone();
    drop(record);
    assert_eq!(fs::read(record_path).unwrap(), b"operator replacement");
    assert!(summarize(&path).is_err());
}

#[test]
#[cfg(unix)]
fn retained_attempts_are_bounded_and_cannot_overwrite_each_other() {
    let (_temp, binding, path) = fixture();
    let selected = selection(&binding);
    let mut records = Vec::new();
    for _ in 0..64 {
        records.push(selected.reserve("git").unwrap());
    }
    assert!(selected.reserve("git").is_err());
    assert_eq!(summarize(&path).unwrap()["observed_children"], 64);
}

#[test]
fn strict_binding_rejects_duplicate_fields_and_symlinks() {
    let (_temp, _binding, path) = fixture();
    fs::write(&path, br#"{"format":"x","format":"x"}"#).unwrap();
    assert!(private_json::<Binding>(&path).is_err());
    #[cfg(unix)]
    {
        let link = _temp.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(private_json::<Binding>(&link).is_err());
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_kernel_refuses_before_creating_an_engine_leaf() {
    let (_temp, binding, _path) = fixture();
    let config = Config::load_file(&binding.config).unwrap();
    assert!(lease_root(&config).is_err());
    assert!(probe(&config).is_err());
}
