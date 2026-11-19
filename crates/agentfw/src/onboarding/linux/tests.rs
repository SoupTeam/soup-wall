// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn plain_path_refuses_relative_aliases_and_links() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().canonicalize().unwrap();
    assert!(plain_path(&real.join("missing/child")).is_ok());
    assert!(plain_path(Path::new("relative")).is_err());
    assert!(plain_path(&real.join("a/../b")).is_err());
    std::os::unix::fs::symlink(&real, real.join("link")).unwrap();
    assert!(plain_path(&real.join("link/x")).is_err());
}

#[test]
fn policy_digest_matches_the_daemon_serialization() {
    let (digest, rules) =
        expected_policy_digest(crate::self_test::fixture::SHIPPED_POLICY).unwrap();
    assert!(hex64(&digest));
    assert!(rules > 0);
    assert!(expected_policy_digest("agent_policies: [").is_none());
}

#[test]
fn runtime_entry_check_refuses_unknown_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.yaml"), b"x").unwrap();
    std::fs::create_dir(dir.path().join("versions")).unwrap();
    assert!(only_known_entries(dir.path()));
    std::fs::write(dir.path().join("notes.txt"), b"operator").unwrap();
    assert!(!only_known_entries(dir.path()));
}

/// A created home with one owned file, Agent runtime entries and an audit log,
/// plus the journal that onboarding would have recorded for it.
fn recorded_home() -> (tempfile::TempDir, Paths, Journal) {
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().canonicalize().unwrap();
    let home = profile.join(".agentfw");
    std::fs::create_dir_all(home.join("grants")).unwrap();
    std::fs::create_dir_all(home.join(OWNED_DIR)).unwrap();
    std::fs::write(home.join("config.yaml"), b"enforce: true\n").unwrap();
    std::fs::write(home.join("grants/g1.json"), b"{}").unwrap();
    std::fs::write(home.join("audit.jsonl"), b"{\"event\":1}\n").unwrap();
    let mut journal = Journal {
        agent_home: home.to_string_lossy().into_owned(),
        created_home: true,
        inventory: inventory(&home),
        ..Journal::default()
    };
    journal.files.insert(
        "config".into(),
        sha256_file(&home.join("config.yaml")).unwrap(),
    );
    let paths = paths(&home).unwrap();
    (dir, paths, journal)
}

fn home_outcome(results: &[Value]) -> (String, String) {
    let line = results.iter().find(|r| r["step"] == "agent_home").unwrap();
    (
        line["outcome"].as_str().unwrap().into(),
        line["detail"].as_str().unwrap().into(),
    )
}

fn run_rollback(journal: &mut Journal, paths: &Paths, purge: bool) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(60);
    rollback(
        journal,
        Path::new("/nonexistent/agentfw"),
        paths,
        purge,
        deadline,
    )
}

#[test]
fn rollback_preserves_foreign_files_inside_recognized_directories() {
    // The automatic rollback after a failed apply calls this with purge = false.
    let (_dir, paths, mut journal) = recorded_home();
    let home = PathBuf::from(&journal.agent_home);
    std::fs::write(home.join("grants/operator-notes.txt"), b"operator bytes").unwrap();
    std::fs::write(home.join(OWNED_DIR).join("operator.txt"), b"more").unwrap();
    let (outcome, detail) = home_outcome(&run_rollback(&mut journal, &paths, false));
    assert_eq!(outcome, "conflict");
    assert!(detail.starts_with("2 untracked"), "{detail}");
    assert!(!detail.contains(&*paths.profile.to_string_lossy()));
    assert_eq!(
        std::fs::read(home.join("grants/operator-notes.txt")).unwrap(),
        b"operator bytes"
    );
    assert_eq!(
        std::fs::read(home.join(OWNED_DIR).join("operator.txt")).unwrap(),
        b"more"
    );
    // Recorded entries were removed; the audit log is never purged implicitly.
    assert!(!home.join("grants/g1.json").exists());
    assert!(!home.join("config.yaml").exists());
    assert!(home.join("audit.jsonl").exists());
    assert!(journal.created_home);

    // An explicit purge still never deletes untracked bytes.
    let (outcome, _) = home_outcome(&run_rollback(&mut journal, &paths, true));
    assert_eq!(outcome, "conflict");
    assert!(home.join("grants/operator-notes.txt").exists());
    assert!(!home.join("audit.jsonl").exists());

    // Once the operator removes them, the created home is removed.
    std::fs::remove_file(home.join("grants/operator-notes.txt")).unwrap();
    std::fs::remove_file(home.join(OWNED_DIR).join("operator.txt")).unwrap();
    let (outcome, _) = home_outcome(&run_rollback(&mut journal, &paths, false));
    assert_eq!(outcome, "reversed");
    assert!(!home.exists());
}

#[test]
fn rollback_preserves_changed_runtime_files_and_keeps_audit_without_purge() {
    let (_dir, paths, mut journal) = recorded_home();
    let home = PathBuf::from(&journal.agent_home);
    std::fs::write(home.join("grants/g1.json"), b"{\"changed\":true}").unwrap();
    let (outcome, detail) = home_outcome(&run_rollback(&mut journal, &paths, false));
    assert_eq!(outcome, "conflict");
    assert!(detail.starts_with("1 untracked or changed"), "{detail}");
    assert_eq!(
        std::fs::read(home.join("grants/g1.json")).unwrap(),
        b"{\"changed\":true}"
    );
    std::fs::remove_file(home.join("grants/g1.json")).unwrap();
    let (outcome, _) = home_outcome(&run_rollback(&mut journal, &paths, false));
    assert_eq!(outcome, "retained");
    assert_eq!(
        std::fs::read(home.join("audit.jsonl")).unwrap(),
        b"{\"event\":1}\n"
    );
    let (outcome, _) = home_outcome(&run_rollback(&mut journal, &paths, true));
    assert_eq!(outcome, "reversed");
    assert!(!home.exists());
}

#[test]
fn retried_read_only_step_does_not_adopt_operator_changes() {
    // End to end through Session::step and the production rollback: a recorded
    // runtime file is replaced by the operator, then a verification step is retried
    // with a helper that fails without touching the home.
    let (_dir, paths, journal) = recorded_home();
    let home = PathBuf::from(&journal.agent_home);
    let recorded_before = journal.inventory["grants/g1.json"].clone();
    std::fs::write(home.join("grants/g1.json"), b"operator replacement").unwrap();
    std::fs::write(home.join("grants/new.txt"), b"operator new").unwrap();
    std::fs::create_dir(&paths.state).unwrap();
    let inputs = Inputs {
        agent: PathBuf::from("/bin/false"),
        agent_sha256: String::new(),
        classifier: "rule-baseline".into(),
        classifier_script: PathBuf::new(),
        classifier_sha256: String::new(),
        classifier_python: PathBuf::new(),
        registry: PathBuf::new(),
        registry_sha256: String::new(),
        policy: None,
        policy_sha256: None,
        server_profile: None,
        server_profile_sha256: None,
        workspace: PathBuf::new(),
        agent_home: home.clone(),
        host_config: PathBuf::new(),
        server: "notes".into(),
        port: 9,
        probe_tool: None,
        probe_args: None,
        report: PathBuf::new(),
        timeout_seconds: 60,
    };
    let facts = Facts::default();
    let mut session = Session {
        inputs: &inputs,
        facts: &facts,
        state: paths.state.clone(),
        profile: paths.profile.clone(),
        journal,
        deadline: Instant::now() + Duration::from_secs(60),
        evidence: serde_json::Map::new(),
    };
    session
        .journal
        .steps
        .insert("verify_identity".into(), "done".into());
    assert!(session.step("verify_identity").is_err());
    assert_eq!(session.journal.inventory["grants/g1.json"], recorded_before);
    assert!(!session.journal.inventory.contains_key("grants/new.txt"));
    let mut journal = session.journal;
    let (outcome, detail) = home_outcome(&run_rollback(&mut journal, &paths, false));
    assert_eq!(outcome, "conflict");
    assert!(detail.starts_with("2 untracked or changed"), "{detail}");
    assert_eq!(
        std::fs::read(home.join("grants/g1.json")).unwrap(),
        b"operator replacement"
    );
    assert_eq!(
        std::fs::read(home.join("grants/new.txt")).unwrap(),
        b"operator new"
    );
}

#[test]
fn concurrent_operator_file_during_a_read_only_step_is_not_adopted() {
    // Reviewer regression: a helper outside the Agent home signals a marker, sleeps
    // and fails; meanwhile the operator creates a file inside a runtime directory.
    let (_dir, paths, journal) = recorded_home();
    let home = PathBuf::from(&journal.agent_home);
    std::fs::write(home.join("grants/g1.json"), b"operator replacement").unwrap();
    std::fs::write(home.join("grants/new.txt"), b"operator new").unwrap();
    std::fs::create_dir(&paths.state).unwrap();
    let helper_dir = tempfile::tempdir().unwrap();
    let helper_root = helper_dir.path().canonicalize().unwrap();
    let marker = helper_root.join("started");
    let helper = helper_root.join("helper.sh");
    std::fs::write(
        &helper,
        format!("#!/bin/sh\n: > '{}'\nsleep 0.3\nexit 1\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let inputs = Inputs {
        agent: helper,
        agent_sha256: String::new(),
        classifier: "rule-baseline".into(),
        classifier_script: PathBuf::new(),
        classifier_sha256: String::new(),
        classifier_python: PathBuf::new(),
        registry: PathBuf::new(),
        registry_sha256: String::new(),
        policy: None,
        policy_sha256: None,
        server_profile: None,
        server_profile_sha256: None,
        workspace: PathBuf::new(),
        agent_home: home.clone(),
        host_config: PathBuf::new(),
        server: "notes".into(),
        port: 9,
        probe_tool: None,
        probe_args: None,
        report: PathBuf::new(),
        timeout_seconds: 60,
    };
    let facts = Facts::default();
    let mut session = Session {
        inputs: &inputs,
        facts: &facts,
        state: paths.state.clone(),
        profile: paths.profile.clone(),
        journal,
        deadline: Instant::now() + Duration::from_secs(60),
        evidence: serde_json::Map::new(),
    };
    let during = home.join("grants/during-step.txt");
    let operator = {
        let (marker, during) = (marker.clone(), during.clone());
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            while !marker.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            std::fs::write(&during, b"operator during step").unwrap();
        })
    };
    assert!(session.step("verify_identity").is_err());
    operator.join().unwrap();
    assert!(marker.exists(), "the helper ran");
    assert!(!session
        .journal
        .inventory
        .contains_key("grants/during-step.txt"));
    let mut journal = session.journal;
    let (outcome, detail) = home_outcome(&run_rollback(&mut journal, &paths, false));
    assert_eq!(outcome, "conflict");
    assert!(detail.starts_with("3 untracked or changed"), "{detail}");
    assert_eq!(std::fs::read(&during).unwrap(), b"operator during step");
    assert_eq!(
        std::fs::read(home.join("grants/g1.json")).unwrap(),
        b"operator replacement"
    );
    assert_eq!(
        std::fs::read(home.join("grants/new.txt")).unwrap(),
        b"operator new"
    );
}

#[test]
fn only_known_outputs_of_each_step_are_adopted() {
    let version = version_label(&"a".repeat(64));
    for step in [
        "create_agent_home",
        "verify_identity",
        "connect_server",
        "self_test",
    ] {
        assert!(step_outputs(step, &version).is_empty(), "{step}");
    }
    let adopts = |step: &str, rel: &str| {
        step_outputs(step, &version)
            .iter()
            .any(|p| output_matches(p, rel))
    };
    assert!(adopts(
        "lifecycle_install",
        &format!("versions/agentfw-{version}")
    ));
    assert!(!adopts("lifecycle_install", "versions/agentfw-other"));
    assert!(adopts("lifecycle_start", "grants"));
    assert!(adopts("lifecycle_start", "versions/.launch-x.log"));
    assert!(!adopts("lifecycle_start", "versions/.launch-x/y.log"));
    assert!(adopts("verify_server", "manifests/claude-abc-1.json"));
    assert!(!adopts("verify_server", "manifests/notes.json"));
    // Directory contents are never implied by the directory, for any step.
    for step in STEPS {
        assert!(!adopts(step, "grants/during-step.txt"), "{step}");
        assert!(!adopts(step, "onboarding/operator.txt"), "{step}");
    }
    // A file appearing during a step is adopted only if it is that step's output.
    let entry = InventoryEntry {
        kind: "file".into(),
        sha256: Some("x".into()),
    };
    let after = BTreeMap::from([
        ("token".to_string(), entry.clone()),
        ("grants/during-step.txt".to_string(), entry.clone()),
    ]);
    let mut recorded = BTreeMap::new();
    adopt_step_changes(
        &mut recorded,
        &BTreeMap::new(),
        &after,
        &step_outputs("self_test", &version),
    );
    assert!(recorded.is_empty());
    adopt_step_changes(
        &mut recorded,
        &BTreeMap::new(),
        &after,
        &step_outputs("create_token", &version),
    );
    assert_eq!(recorded.keys().collect::<Vec<_>>(), vec!["token"]);
}

#[test]
fn step_adoption_keeps_prior_digest_and_refuses_foreign_entries() {
    let entry = |d: &str| InventoryEntry {
        kind: "file".into(),
        sha256: Some(d.into()),
    };
    let mut recorded = BTreeMap::from([
        ("ours".to_string(), entry("a")),
        ("edited".to_string(), entry("a")),
    ]);
    let before = BTreeMap::from([
        ("ours".to_string(), entry("a")),
        ("edited".to_string(), entry("operator")),
        ("foreign".to_string(), entry("f")),
    ]);
    let after = BTreeMap::from([
        ("ours".to_string(), entry("b")),
        ("edited".to_string(), entry("agent")),
        ("foreign".to_string(), entry("g")),
        ("created".to_string(), entry("c")),
    ]);
    let all = vec!["*".to_string()];
    adopt_step_changes(&mut recorded, &before, &after, &all);
    assert_eq!(recorded["ours"], entry("b"));
    assert_eq!(recorded["edited"], entry("a"));
    assert!(!recorded.contains_key("foreign"));
    assert_eq!(recorded["created"], entry("c"));
    // An unchanged entry keeps its recorded digest even when the file differs from it.
    let mut recorded = BTreeMap::from([("x".to_string(), entry("a"))]);
    let same = BTreeMap::from([("x".to_string(), entry("operator"))]);
    adopt_step_changes(&mut recorded, &same, &same, &all);
    assert_eq!(recorded["x"], entry("a"));
}

#[test]
fn the_owned_profile_classifier_is_removed_only_with_its_recorded_bytes() {
    let (_dir, paths, mut journal) = recorded_home();
    let home = PathBuf::from(&journal.agent_home);
    let classifier = home.join(OWNED_DIR).join(PROFILE_CLASSIFIER);
    // write_owned_files records the copy it created, by digest and in the inventory.
    let before = inventory(&home);
    std::fs::write(&classifier, b"print('reviewed')").unwrap();
    let after = inventory(&home);
    let outputs = step_outputs("write_owned_files", "onboard-x");
    adopt_step_changes(&mut journal.inventory, &before, &after, &outputs);
    journal
        .files
        .insert("classifier".into(), sha256(b"print('reviewed')"));
    std::fs::write(&classifier, b"print('operator edit')").unwrap();
    let results = run_rollback(&mut journal, &paths, false);
    assert!(results
        .iter()
        .any(|r| r["step"] == "classifier" && r["outcome"] == "conflict"));
    assert_eq!(
        std::fs::read(&classifier).unwrap(),
        b"print('operator edit')"
    );
    std::fs::write(&classifier, b"print('reviewed')").unwrap();
    let results = run_rollback(&mut journal, &paths, true);
    assert!(results
        .iter()
        .any(|r| r["step"] == "classifier" && r["outcome"] == "reversed"));
    assert!(!classifier.exists());
}

#[test]
fn only_this_connections_manifest_record_is_cleaned_after_use() {
    let (_dir, paths, mut journal) = recorded_home();
    let home = PathBuf::from(&journal.agent_home);
    let host = paths.profile.join(".claude/mcp.json");
    journal.host_config = host.to_string_lossy().into_owned();
    journal.server = "selected".into();
    std::fs::create_dir(home.join("manifests")).unwrap();
    journal.inventory = inventory(&home);
    let name = crate::mcp::store::ManifestStore::record_name(&crate::mcp::connection::server_id(
        &host, "selected",
    ));
    // Written by the Agent while the connected server was used after apply.
    std::fs::write(
        home.join("manifests").join(&name),
        br#"{"current":null,"history":[]}"#,
    )
    .unwrap();
    let foreign = home.join("manifests/claude-other-0000.json");
    std::fs::write(&foreign, br#"{"current":null,"history":[]}"#).unwrap();
    let (outcome, detail) = home_outcome(&run_rollback(&mut journal, &paths, true));
    assert_eq!(outcome, "conflict");
    assert!(detail.starts_with("1 untracked"), "{detail}");
    assert!(!home.join("manifests").join(&name).exists());
    assert!(foreign.exists());
    // A file with this name that is not a manifest record is preserved.
    std::fs::remove_file(&foreign).unwrap();
    std::fs::write(home.join("manifests").join(&name), b"operator notes").unwrap();
    let (outcome, _) = home_outcome(&run_rollback(&mut journal, &paths, true));
    assert_eq!(outcome, "conflict");
    assert!(home.join("manifests").join(&name).exists());
    std::fs::remove_file(home.join("manifests").join(&name)).unwrap();
    let (outcome, _) = home_outcome(&run_rollback(&mut journal, &paths, true));
    assert_eq!(outcome, "reversed");
}

#[test]
fn only_fixed_command_errors_are_reported() {
    let output = |stderr: &[u8]| Output {
        code: Some(1),
        stdout: Vec::new(),
        stderr: stderr.to_vec(),
        timed_out: false,
    };
    assert_eq!(
        output(b"warning\nError: unsafe or unavailable executable\n").safe_error(),
        Some("unsafe or unavailable executable".into())
    );
    // Paths, values and anything unusual are withheld.
    assert_eq!(
        output(b"Error: cannot open /home/me/secret\n").safe_error(),
        None
    );
    assert_eq!(output(b"Error: token=abc\n").safe_error(), None);
    assert_eq!(output(b"no error line").safe_error(), None);
}

#[test]
fn sandbox_support_refuses_an_unusable_bubblewrap() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let config = crate::mcp::server_profile::ProfileConfig::read(
        json!({"format": crate::mcp::server_profile::FORMAT, "workspace": root,
               "runtimePath": "/usr/bin/true", "runtimeSha256": "0".repeat(64),
               "packageRoot": root, "packageTreeSha256": "0".repeat(64),
               "bwrapPath": root.join("missing-bwrap"), "bwrapSha256": "0".repeat(64),
               "libraries": []})
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    assert!(sandbox_support(&config).is_err());
    // A program without --ro-bind-fd is not an accepted bubblewrap.
    let mut fake = config.clone();
    fake.bwrap_path = PathBuf::from("/usr/bin/true");
    assert_eq!(
        sandbox_support(&fake).err(),
        Some("bubblewrap lacks --ro-bind-fd")
    );
}

#[test]
fn inventory_does_not_follow_links() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("keep.txt"), b"x").unwrap();
    std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();
    let recorded = inventory(&root);
    assert_eq!(recorded["link"].kind, "symlink");
    assert!(!recorded.contains_key("link/keep.txt"));
    let (preserved, _) = clean_recorded(&root, &recorded, true);
    assert!(preserved.is_empty());
    assert!(outside.path().join("keep.txt").exists());
}

#[test]
fn state_cleanup_removes_only_own_files() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join(STATE_DIR);
    std::fs::create_dir(&state).unwrap();
    std::fs::write(state.join(JOURNAL), b"{}").unwrap();
    std::fs::write(state.join("other.txt"), b"keep").unwrap();
    assert!(remove_state(&state).is_err());
    assert!(state.join("other.txt").exists());
    assert!(!state.join(JOURNAL).exists());
}
