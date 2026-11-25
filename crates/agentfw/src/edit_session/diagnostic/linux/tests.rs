// SPDX-License-Identifier: Apache-2.0
use super::*;
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt};
fn private(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn dir(path: &std::path::Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn fixture() -> (tempfile::TempDir, Args, Profile, Context) {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let run = temp.path().join("run");
    dir(&run);
    let home = run.join("h".repeat(43));
    dir(&home);
    let mut p = crate::edit_session::profile::fixture();
    p.policy_sha256 = profile::digest(&crate::edit_session::launch::policy().unwrap()).unwrap();
    let root = temp.path().join("outputs");
    dir(&root);
    p.root = root;
    let root_meta = fs::metadata(&p.root).unwrap();
    p.root_identity = crate::mcp::replace_file::RootIdentity {
        device: root_meta.dev(),
        inode: root_meta.ino(),
    };
    let c = Context {
        format: record::FORMAT.into(),
        run: run.clone(),
        home: home.clone(),
        profile_sha256: profile::digest(&p).unwrap(),
        host_session: "host-1".into(),
        instance_id: "instance-1".into(),
        started_at_ms: crate::protection_status::now_ms(),
        owner: record::process_identity(std::process::id()).unwrap(),
        config_sha256: "d".repeat(64),
        listener: record::ListenerIdentity {
            fd: 3,
            device: 1,
            inode: 1,
        },
    };
    private(
        &run.join("diagnostic-context.json"),
        &profile::canonical(&c).unwrap(),
    );
    private(&run.join("run.json"),&serde_json::to_vec(&json!({"format":FORMAT,"run":run,"home":home,"profile_sha256":c.profile_sha256,"host_session":c.host_session,"instance_id":c.instance_id})).unwrap());
    private(&run.join("profile.json"), &profile::canonical(&p).unwrap());
    private(&run.join("profile.sha256"), c.profile_sha256.as_bytes());
    private(
        &home.join("registry.json"),
        &profile::canonical(&p.registry().unwrap()).unwrap(),
    );
    private(
        &home.join("policy.yaml"),
        crate::edit_session::launch::POLICY.as_bytes(),
    );
    (
        temp,
        Args {
            run,
            json: true,
            check_output: false,
            support_bundle: None,
        },
        p,
        c,
    )
}
#[test]
fn missing_audit_never_means_not_executed_and_default_creates_no_state_or_target_reads() {
    let (_temp, args, p, c) = fixture();
    let canary = b"private-content-secret-canary";
    private(&p.root.join("draft.txt"), canary);
    let before = fs::read_dir(&args.run).unwrap().count();
    let target = fs::metadata(p.root.join("draft.txt")).unwrap();
    let report = super::super::inspect(&args);
    assert_eq!(report.reason_code, "audit_empty_or_missing");
    assert!(report.outputs.is_empty());
    assert_eq!(report.effects, "indeterminate");
    assert!(report.audit.calls.is_empty());
    assert_eq!(fs::read_dir(&args.run).unwrap().count(), before);
    let after = fs::metadata(p.root.join("draft.txt")).unwrap();
    assert!(super::super::io::stable(&target, &after));
    assert_eq!(fs::read(p.root.join("draft.txt")).unwrap(), canary);
    let rendered = format!(
        "{}{}",
        serde_json::to_string(&report).unwrap(),
        super::super::text(&report)
    );
    for secret in [
        "private-content-secret-canary",
        c.home.to_str().unwrap(),
        p.root.to_str().unwrap(),
        "draft.txt",
        "create_output_0",
    ] {
        assert!(!rendered.contains(secret));
    }
    assert!(!rendered.contains("not executed"));
}
#[test]
fn quota_terminal_requires_exact_bounded_profile_metadata_without_promoting_commit_proof() {
    let (_temp, _args, mut profile, mut context) = fixture();
    let limits = Limits::new(1, 4).unwrap();
    profile.format = crate::edit_session::QUOTA_PROFILE.into();
    profile.mutation_quota = Some(limits.clone());
    context.profile_sha256 = profile::digest(&profile).unwrap();
    let ledger =
        crate::edit_session::quota::Ledger::new(limits.clone(), "a".repeat(64), "host".into())
            .unwrap();
    let usage = serde_json::to_value(ledger.snapshot().unwrap()).unwrap();
    let mut row = json!({"format":FORMAT,"state":"host_completed","reason":"host_completed",
        "run":context.run,"profile_sha256":context.profile_sha256,
        "cleanup":{"cleaned":true,"reaped":true,"exit_success":true,
            "graceful_observed":true,"ownership":"owned-process-group","failure":null},
        "daemon_clean":true,"mutation_dispatches":0,"mutation_quota":usage,
        "effect_status":"consult-native-audit; interrupted-or-withheld-result-is-indeterminate; no-automatic-retry"});
    let encode = |v: &Value| serde_json::to_vec(v).unwrap();
    assert_eq!(
        terminal(&encode(&row), &context, Some(&limits)).unwrap(),
        "recorded_host_completed"
    );
    assert!(terminal(&encode(&row), &context, None).is_err());
    let other = crate::edit_session::quota::Ledger::new(
        Limits::new(2, 4).unwrap(),
        "a".repeat(64),
        "host".into(),
    )
    .unwrap();
    row["mutation_quota"] = serde_json::to_value(other.snapshot().unwrap()).unwrap();
    assert!(terminal(&encode(&row), &context, Some(&limits)).is_err());
    row["mutation_quota"] = usage.clone();
    row["mutation_quota"]["remaining_mutations"] = json!(2);
    assert!(terminal(&encode(&row), &context, Some(&limits)).is_err());
    row["mutation_quota"] = json!(null);
    assert!(terminal(&encode(&row), &context, Some(&limits)).is_err());
    row["mutation_quota"] = serde_json::to_value(RetainedQuota::unavailable()).unwrap();
    assert!(terminal(&encode(&row), &context, Some(&limits)).is_err());
    row["state"] = json!("failed");
    assert_eq!(
        terminal(&encode(&row), &context, Some(&limits)).unwrap(),
        "recorded_indeterminate_mutation_quota"
    );
    row["mutation_quota"]["authenticated_commit"] = json!(true);
    assert!(terminal(&encode(&row), &context, Some(&limits)).is_err());
    row["mutation_quota"] = usage;
    row["mutation_quota"]["admitted_mutation_attempts"] = json!(1);
    row["mutation_quota"]["remaining_mutations"] = json!(0);
    row["mutation_quota"]["pending_prepublication_attempts"] = json!(1);
    assert_eq!(
        terminal(&encode(&row), &context, Some(&limits)).unwrap(),
        "recorded_indeterminate_mutation_quota"
    );
    row["state"] = json!("host_completed");
    assert!(terminal(&encode(&row), &context, Some(&limits)).is_err());
}

#[test]
fn unsuccessful_reaped_host_is_distinct_from_missing_exit_or_cleanup_failure() {
    let (_temp, _args, _profile, context) = fixture();
    let mut row = json!({"format":FORMAT,"state":"failed","reason":"host_completed",
        "run":context.run,"profile_sha256":context.profile_sha256,
        "cleanup":{"cleaned":true,"reaped":true,"exit_success":false,
            "graceful_observed":true,"ownership":"owned-process-group","failure":null},
        "daemon_clean":true,"mutation_dispatches":0,
        "effect_status":"consult-native-audit; interrupted-or-withheld-result-is-indeterminate; no-automatic-retry"});
    assert_eq!(
        terminal(&serde_json::to_vec(&row).unwrap(), &context, None).unwrap(),
        "recorded_unsuccessful_host_exit"
    );
    for (reason, expected) in [
        ("operator_stop", "recorded_operator_stop"),
        ("invalid_stop_request", "recorded_invalid_stop_request"),
    ] {
        row["reason"] = json!(reason);
        assert_eq!(
            terminal(&serde_json::to_vec(&row).unwrap(), &context, None).unwrap(),
            expected
        );
        row["state"] = json!("host_completed");
        assert!(terminal(&serde_json::to_vec(&row).unwrap(), &context, None).is_err());
        row["state"] = json!("failed");
    }
    row["reason"] = json!("host_completed");
    // A failed or missing reap does not establish how the host exited.
    row["cleanup"]["reaped"] = json!(false);
    row["cleanup"]["cleaned"] = json!(false);
    assert_eq!(
        terminal(&serde_json::to_vec(&row).unwrap(), &context, None).unwrap(),
        "recorded_cleanup_or_stream_failure"
    );
    // A successful host can still leave incomplete owned cleanup.
    row["cleanup"]["reaped"] = json!(true);
    row["cleanup"]["exit_success"] = json!(true);
    assert_eq!(
        terminal(&serde_json::to_vec(&row).unwrap(), &context, None).unwrap(),
        "recorded_cleanup_or_stream_failure"
    );
}
#[tokio::test]
async fn live_policy_identity_matches_authenticated_producer_without_reusing_profile_hash_format() {
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;
    let directory = tempfile::tempdir().unwrap();
    let policy = crate::edit_session::launch::policy().unwrap();
    let config = crate::Config {
        enforce: true,
        ..Default::default()
    };
    let token = crate::token::generate();
    let state = Arc::new(crate::AppState {
        native: None,
        firewall: Mutex::new(
            soup_wall_agent::AgentFirewall::with_taint_limits(
                policy.clone(),
                soup_wall_agent::DEFAULT_TAINT_CAP,
                config.provenance.clone(),
            )
            .unwrap(),
        ),
        sessions: Default::default(),
        audit: crate::audit::AuditSink::open(&directory.path().join("audit")).unwrap(),
        config: config.clone(),
        token: token.clone(),
        spans: crate::spans::SpanCache::new(64, 262144),
        judge: crate::judge::Judge::new(Default::default()),
        manifests: crate::mcp::store::ManifestStore::new(&directory.path().join("manifests")),
        tools: crate::mcp::store::ToolRegistry::with_builtins(),
        grants: crate::grant::GrantStore::new(&directory.path().join("grants")),
        grant_ledger: crate::grant::GrantLedger::open(&directory.path().join("spent")),
        grant_key: crate::grant::derive_key(&token),
    });
    let nonce = crate::token::generate();
    let request = axum::http::Request::get(crate::protection_status::ENDPOINT)
        .header("authorization", format!("Bearer {token}"))
        .header(crate::protection_status::NONCE_HEADER, &nonce)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = crate::app(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let raw = axum::body::to_bytes(response.into_body(), 32768)
        .await
        .unwrap();
    let observed: crate::protection_status::Snapshot = serde_json::from_slice(&raw).unwrap();
    let live = live_policy_digest(&policy).unwrap();
    let retained = profile::digest(&policy).unwrap();
    assert_ne!(retained, live);
    let mut expected = crate::protection_status::Expectations {
        policy_sha256: Some(live),
        config_sha256: Some(crate::protection_status::config_digest(&config)),
        ..Default::default()
    };
    crate::protection_status::validate(
        &observed,
        &nonce,
        crate::protection_status::now_ms(),
        &expected,
    )
    .unwrap();
    expected.policy_sha256 = Some(retained);
    let mismatch = crate::protection_status::validate(
        &observed,
        &nonce,
        crate::protection_status::now_ms(),
        &expected,
    )
    .unwrap_err();
    assert_eq!(mismatch, "status_identity_mismatch");
    assert_eq!(protection_failure(mismatch), "invalid_or_mismatched");
}
#[test]
fn unavailable_transport_and_invalid_authenticated_evidence_remain_distinct_and_allowlisted() {
    for code in [
        "status_unavailable",
        "status_client_unavailable",
        "status_query_rejected",
    ] {
        assert_eq!(protection_failure(code), "unavailable");
    }
    for code in [
        "status_identity_mismatch",
        "status_invalid_or_stale",
        "status_invalid_response",
        "status_response_over_cap",
        "status_invalid_config",
        "status_invalid_registry",
        "status_invalid_coverage",
        "arbitrary-private-error-canary",
    ] {
        assert_eq!(protection_failure(code), "invalid_or_mismatched");
        assert!(!protection_failure(code).contains("canary"));
    }
}
#[test]
fn output_digest_is_only_an_explicit_postcondition_observation() {
    let (_temp, mut args, p, _c) = fixture();
    private(&p.root.join("draft.txt"), b"changed independently");
    args.check_output = true;
    let report = super::super::inspect(&args);
    assert_eq!(report.outputs.len(), 1);
    assert_eq!(report.outputs[0].observation, "present");
    assert_eq!(
        report.outputs[0].attribution,
        "observed_postcondition_not_writer_or_commit_proof"
    );
    assert_eq!(report.effects, "indeterminate");
}
#[test]
fn tampered_profile_foreign_run_and_duplicate_context_do_not_trigger_network_or_output_reads() {
    let (_temp, args, _p, c) = fixture();
    let original = fs::read(args.run.join("run.json")).unwrap();
    let mut changed: Value = serde_json::from_slice(&original).unwrap();
    changed["run"] = json!("/foreign");
    private(
        &args.run.join("run.json"),
        &serde_json::to_vec(&changed).unwrap(),
    );
    let report = super::super::inspect(&args);
    assert_eq!(report.reason_code, "run_context_binding_mismatch");
    assert_eq!(report.authenticated_daemon, "not_queried");
    private(&args.run.join("run.json"), &original);
    private(&args.run.join("profile.json"), b"{}");
    assert_eq!(
        super::super::inspect(&args).reason_code,
        "selected_state_schema_invalid"
    );
    private(
        &args.run.join("diagnostic-context.json"),
        format!(
            "{{\"format\":\"{}\",\"format\":\"private-secret-canary\"}}",
            c.format
        )
        .as_bytes(),
    );
    let report = super::super::inspect(&args);
    assert_eq!(report.reason_code, "selected_json_malformed_or_duplicate");
    assert!(!super::super::text(&report).contains("private-secret-canary"));
}
#[test]
fn changed_config_and_coherent_local_hash_tampering_send_no_credentials_to_foreign_listener() {
    use std::{net::TcpListener, os::fd::AsRawFd};
    let (_temp, args, profile, mut context) = fixture();
    let original = TcpListener::bind("127.0.0.1:0").unwrap();
    let foreign = TcpListener::bind("127.0.0.1:0").unwrap();
    foreign.set_nonblocking(true).unwrap();
    let mut config = crate::Config {
        bind: "127.0.0.1".into(),
        port: original.local_addr().unwrap().port(),
        enforce: true,
        policy: Some(context.home.join("policy.yaml")),
        audit: Some(context.home.join("audit.jsonl")),
        native: Some(crate::config::NativeCfg {
            execution: None,
            git_execution: None,
            registry_path: context.home.join("registry.json"),
            registry_sha256: profile::digest(&profile.registry().unwrap()).unwrap(),
            approval: None,
            liveness: None,
        }),
        ..Default::default()
    };
    context.config_sha256 = crate::protection_status::config_digest(&config);
    context.listener = record::listener_identity(original.as_raw_fd()).unwrap();
    private(
        &context.home.join("token"),
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    private(
        &context.home.join("native-token"),
        b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    );
    config.port = foreign.local_addr().unwrap().port();
    private(
        &context.home.join("config.yaml"),
        serde_yaml::to_string(&config).unwrap().as_bytes(),
    );
    for coherently_changed_hash in [false, true] {
        if coherently_changed_hash {
            context.config_sha256 = crate::protection_status::config_digest(&config);
        }
        private(
            &args.run.join("diagnostic-context.json"),
            &profile::canonical(&context).unwrap(),
        );
        let report = super::super::inspect(&args);
        assert_eq!(report.authenticated_daemon, "invalid_or_mismatched");
        assert_eq!(
            foreign.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("AAAAAAAAAAAA"));
        assert!(!encoded.contains("BBBBBBBBBBBB"));
    }
}
#[test]
fn live_view_requires_exact_instance_profile_host_and_nonduplicate_correlated_requests() {
    let (_temp, _args, p, c) = fixture();
    let registry = profile::digest(&p.registry().unwrap()).unwrap();
    let row = json!({"pending_id":"pending-1","session_epoch":"native:epoch-1","tool":"create_output_0","binding_sha256":"a".repeat(64),"args_sha256":"b".repeat(64),"expires_at_ms":c.started_at_ms+120000,"state":"pending"});
    let good = json!({"instance_id":c.instance_id,"registry_sha256":registry,"edit_diagnostic":{"format":"sw-installed-edit-live/1","profile_sha256":c.profile_sha256,"host_session":c.host_session,
        "collectors":[{"session_epoch":"native:epoch-1","host_session":c.host_session,"server_id":"private-output","active":true}],"pending":[row],"decisions":[]}});
    let observed = validate_live(good.clone(), &p, &c, &registry).unwrap();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].state, "pending");
    let mut stale = good.clone();
    stale["instance_id"] = json!("stale");
    assert_eq!(
        validate_live(stale, &p, &c, &registry).unwrap_err(),
        "stale_epoch"
    );
    let mut duplicate = good.clone();
    duplicate["edit_diagnostic"]["pending"]
        .as_array_mut()
        .unwrap()
        .push(row.clone());
    assert!(validate_live(duplicate, &p, &c, &registry).is_err());
    let mut foreign = good;
    foreign["edit_diagnostic"]["host_session"] = json!("foreign");
    assert!(validate_live(foreign, &p, &c, &registry).is_err());
}
