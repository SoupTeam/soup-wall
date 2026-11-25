// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn sou63_child_authority_binds_authenticated_agent_and_parent_identity() {
    use agentfw::native::child_authority;
    let fixture = Fixture::new(ALLOW);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let key = child_authority::derive_key(NATIVE_TOKEN);

    // 1. Unauthenticated parent claim is rejected.
    let mut unauth = fixture.event("unauth-session", "session_start");
    unauth["parent_id"] = json!("orchestrator");
    let (status, reply) = fixture.post(&unauth).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reply["error_code"], "native_invalid_identity");

    // 2. Mismatched agent_id or parent_id against signed grant is rejected.
    let grant = child_authority::mint_scoped(
        &key,
        "host-1",
        "docs-server",
        &["read_document".into()],
        now,
        60_000,
        format!(
            "{}.{}",
            fixture.state.native.as_ref().unwrap().instance_id(),
            agentfw::token::generate()
        ),
        Some("worker-1".into()),
        Some("orch-1".into()),
        None,
    );
    let token = child_authority::encode_token(&grant);

    let mut mismatch_agent = fixture.event("mismatch-agent", "session_start");
    mismatch_agent["host_session"] = json!("host-1");
    mismatch_agent["server_id"] = json!("docs-server");
    mismatch_agent["child_authority"] = json!(token);
    mismatch_agent["agent_id"] = json!("impostor");
    mismatch_agent["parent_id"] = json!("orch-1");
    let (status, reply) = fixture.post(&mismatch_agent).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reply["error_code"], "native_invalid_identity");

    let parent_grant = child_authority::mint_scoped(
        &key,
        "host-1",
        "docs-server",
        &["read_document".into()],
        now,
        60_000,
        format!(
            "{}.{}",
            fixture.state.native.as_ref().unwrap().instance_id(),
            agentfw::token::generate()
        ),
        Some("orch-1".into()),
        None,
        None,
    );
    let mut parent_start = fixture.event("parent-root", "session_start");
    parent_start["host_session"] = json!("host-1");
    parent_start["server_id"] = json!("docs-server");
    parent_start["child_authority"] = json!(child_authority::encode_token(&parent_grant));
    let (status, reply) = fixture.post(&parent_start).await;
    assert_allow(status, &reply);

    let grant = child_authority::mint_scoped(
        &key,
        "host-1",
        "docs-server",
        &["read_document".into()],
        now,
        60_000,
        scoped_fixture_nonce(&fixture, "host-1", Some("orch-1")),
        Some("worker-1".into()),
        Some("orch-1".into()),
        None,
    );
    let token = child_authority::encode_token(&grant);
    // 3. Valid authenticated agent and parent binds cleanly.
    let mut valid_start = fixture.event("child-valid", "session_start");
    valid_start["host_session"] = json!("host-1");
    valid_start["server_id"] = json!("docs-server");
    valid_start["child_authority"] = json!(token);
    valid_start["agent_id"] = json!("worker-1");
    valid_start["parent_id"] = json!("orch-1");
    let (status, reply) = fixture.post(&valid_start).await;
    assert_allow(status, &reply);

    let call = fixture.call("child-valid", "read_document", &json!({}));
    let (status, reply) = fixture.post(&call).await;
    assert_allow(status, &reply);

    let audit = fixture.audit();
    let call_line = audit
        .iter()
        .find(|line| line["event"] == "native_call")
        .expect("native_call audit line");
    assert_eq!(call_line["agent_id"], "worker-1");
    assert_eq!(call_line["parent_id"], "orch-1");
    assert_eq!(call_line["host_session"], "host-1");

    // 4. Hook endpoint also records agent_id and parent_id when present.
    // Unauthenticated subagent delegation via hook is blocked by subagent escalation policy.
    let hook_body = json!({
        "session_id": "host-1",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo test"},
        "agent_id": "hook-worker",
        "parent_id": "hook-orch"
    });
    let (status, reply) = post(fixture.state.clone(), "/hook", &hook_body, Some(HOOK_TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(reply["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("native_hook_authority_required"));

    let audit_hook = fixture.audit();
    let hook_line = audit_hook
        .iter()
        .find(|line| line["agent_id"] == "hook-worker")
        .expect("hook audit line with agent_id");
    assert_eq!(hook_line["agent_id"], "hook-worker");
    assert_eq!(hook_line["parent_id"], "hook-orch");
}

#[tokio::test]
async fn sou63_child_authority_narrows_resources_and_destinations_relative_to_parent() {
    use agentfw::native::child_authority;
    let permitted = url_resource("http://127.0.0.1:8000/allowed");
    let (fixture, profile) = resource_fixture(
        "retrieve_page",
        "/url",
        "url",
        json!([permitted["resource"]]),
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let key = child_authority::derive_key(NATIVE_TOKEN);

    let parent_grant = child_authority::mint_scoped(
        &key,
        "host-parent",
        "mail-server",
        &["send_email".into(), "retrieve_page".into()],
        now,
        60_000,
        format!(
            "{}.{}",
            fixture.state.native.as_ref().unwrap().instance_id(),
            agentfw::token::generate()
        ),
        Some("parent-agent".into()),
        None,
        Some(vec!["internal.corp".into()]),
    );
    let mut parent_start = fixture.event("parent-root", "session_start");
    parent_start["host_session"] = json!("host-parent");
    parent_start["server_id"] = json!("mail-server");
    parent_start["child_authority"] = json!(child_authority::encode_token(&parent_grant));
    let (status, reply) = fixture.post(&parent_start).await;
    assert_allow(status, &reply);

    // 1. Grant narrowed destinations for send_email
    let grant = child_authority::mint_scoped(
        &key,
        "host-parent",
        "mail-server",
        &["send_email".into()],
        now,
        60_000,
        scoped_fixture_nonce(&fixture, "host-parent", Some("parent-agent")),
        Some("emailer".into()),
        Some("parent-agent".into()),
        Some(vec!["internal.corp".into()]),
    );
    let token = child_authority::encode_token(&grant);

    let mut start = fixture.event("child-narrow", "session_start");
    start["host_session"] = json!("host-parent");
    start["server_id"] = json!("mail-server");
    start["child_authority"] = json!(token);
    start["agent_id"] = json!("emailer");
    start["parent_id"] = json!("parent-agent");
    let (status, reply) = fixture.post(&start).await;
    assert_allow(status, &reply);

    // Call with permitted destination internal.corp -> Allowed
    let allowed_call = fixture.call(
        "child-narrow",
        "send_email",
        &json!({"to": "alice@internal.corp"}),
    );
    let (status, reply) = fixture.post(&allowed_call).await;
    assert_allow(status, &reply);

    // Call with destination outside parent narrowing -> Escalation refusal
    let denied_call = fixture.call(
        "child-narrow",
        "send_email",
        &json!({"to": "mallory@external-attacker.com"}),
    );
    let (status, reply) = fixture.post(&denied_call).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reply["error_code"], "native_child_authority_escalation");

    // 2. Unprovable delegation: tool with resource_policy called by child without granted_resources
    let unprovable_grant = child_authority::mint_scoped(
        &key,
        "host-parent",
        "docs-server",
        &["retrieve_page".into()],
        now,
        60_000,
        scoped_fixture_nonce(&fixture, "host-parent", Some("parent-agent")),
        Some("reader-2".into()),
        Some("parent-agent".into()),
        None, // No resources granted!
    );
    let unprovable_token = child_authority::encode_token(&unprovable_grant);

    let mut start2 = fixture.event("child-unprovable", "session_start");
    start2["host_session"] = json!("host-parent");
    start2["server_id"] = json!("docs-server");
    start2["child_authority"] = json!(unprovable_token);
    let (status, reply) = fixture.post(&start2).await;
    assert_allow(status, &reply);

    let mut unprovable_call = fixture.call(
        "child-unprovable",
        "retrieve_page",
        &json!({"url": "http://127.0.0.1:8000/allowed"}),
    );
    unprovable_call["contract_version"] = json!(agentfw::native::resource::CONTRACT);
    unprovable_call["resource_admission"] = resource_context(&profile, json!([permitted]));
    let (status, reply) = fixture.post(&unprovable_call).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reply["error_code"], "native_child_authority_escalation");
}

#[tokio::test]
async fn review8dd_parent_claim_without_host_must_verify_signature() {
    let f = Fixture::new(ALLOW);
    let mut start = f.event("forged-child", "session_start");
    start["agent_id"] = json!("forged-worker");
    start["parent_id"] = json!("victim-parent");
    start["child_authority"] = json!("not-a-valid-signature");
    let (s, r) = f.post(&start).await;
    assert!(
        s != StatusCode::OK || r["release"] != true,
        "unsigned identity accepted: {r}"
    );
}

#[tokio::test]
async fn review8dd_child_must_not_exceed_registered_parent() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent-session",
        "narrow-parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
    let (s, r) = review8dd_start(
        &f,
        "overbroad-child",
        "worker",
        Some("narrow-parent"),
        &["delete_document"],
        Some(vec![]),
    )
    .await;
    if s != StatusCode::OK || r["release"] != true {
        return;
    }
    let (s, r) = f
        .post(&f.call("overbroad-child", "delete_document", &json!({})))
        .await;
    assert!(
        s != StatusCode::OK || r["release"] != true,
        "child exceeded actual parent grant: {r}"
    );
}

#[tokio::test]
async fn review8dd_missing_resources_must_not_allow_network() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(&f, "missing-scope", "mailer", None, &["send_email"], None).await;
    if s != StatusCode::OK || r["release"] != true {
        return;
    }
    let (s, r) = f
        .post(&f.call(
            "missing-scope",
            "send_email",
            &json!({"to":"outside@attacker.invalid"}),
        ))
        .await;
    assert!(
        s != StatusCode::OK || r["release"] != true,
        "unprovable destination scope allowed: {r}"
    );
}

#[tokio::test]
async fn review8dd_child_path_grant_must_respect_component_boundary() {
    let mut f = Fixture::new(ALLOW);
    let root = f.dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("allowed")).unwrap();
    let target = root.join("allowed-secret.txt");
    std::fs::write(&target, "synthetic private data").unwrap();
    let profile = json!({"server_id":"resource-fixture","tool_name":"read_document","schema_sha256":schema(),"selectors":[{"pointer":"/path","kind":"path"}]});
    let mut reg = registry();
    reg["tools"][0]["resource_policy"] = json!({"profile":profile,"workspace":root,"cwd":root,"executor_sha256":"e".repeat(64),"classifier_sha256":"c".repeat(64),"allowed_resources":[{"kind":"path","canonical":target}]});
    let bytes = reg.to_string().into_bytes();
    f.registry_sha256 = sha256_hex(&bytes);
    f.state = make_state(
        f.dir.path(),
        Config {
            enforce: true,
            ..Config::default()
        },
        ALLOW,
        &bytes,
        &f.registry_sha256,
    );
    let (s, r) = review8dd_start(
        &f,
        "path-child",
        "reader",
        None,
        &["read_document"],
        Some(vec![root.join("allowed").to_string_lossy().into_owned()]),
    )
    .await;
    assert_allow(s, &r);
    let context = resource_context(
        &profile,
        json!([{"pointer":"/path","source":"argument","resource":{"kind":"path","canonical":target}}]),
    );
    let body = resource_call(
        &f,
        "path-child",
        "read_document",
        json!({"path":"allowed-secret.txt"}),
        context,
    );
    let (s, r) = f.post(&body).await;
    assert!(
        s != StatusCode::OK || r["release"] != true,
        "sibling outside granted directory admitted: {r}"
    );
}

#[tokio::test]
async fn review8dd_hook_must_not_drop_authenticated_parent_identity() {
    let f = Fixture::new(ALLOW);
    let (ps, pr) = review8dd_start(
        &f,
        "parent-root",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(ps, &pr);
    let (s, r) = review8dd_start(
        &f,
        "bound-reader",
        "reader",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
    let mut hook = json!({"session_id":"review-host","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo harmless"},"agent_id":"reader","parent_id":"parent"});
    let (_, r) = post(f.state.clone(), "/hook", &hook, Some(HOOK_TOKEN)).await;
    assert_eq!(
        r["hookSpecificOutput"]["permissionDecision"], "deny",
        "control: {r}"
    );
    hook.as_object_mut().unwrap().remove("parent_id");
    let (_, r) = post(f.state.clone(), "/hook", &hook, Some(HOOK_TOKEN)).await;
    assert_eq!(
        r["hookSpecificOutput"]["permissionDecision"], "deny",
        "omitting parent bypassed the bound agent's grant: {r}"
    );
}

#[tokio::test]
async fn review8dd_exact_granted_url_must_remain_usable() {
    let url = "http://127.0.0.1:8000/allowed";
    let permitted = url_resource(url);
    let (f, profile) = resource_fixture(
        "retrieve_page",
        "/url",
        "url",
        json!([permitted["resource"]]),
    );
    let (s, r) = review8dd_start(
        &f,
        "url-child",
        "reader",
        None,
        &["retrieve_page"],
        Some(vec![url.into()]),
    )
    .await;
    assert_allow(s, &r);
    let body = resource_call(
        &f,
        "url-child",
        "retrieve_page",
        json!({"url":url}),
        resource_context(&profile, json!([permitted])),
    );
    let (s, r) = f.post(&body).await;
    assert_eq!(s, StatusCode::OK, "exact granted URL refused: {r}");
    assert_eq!(r["release"], true, "exact granted URL refused: {r}");
}

#[tokio::test]
async fn review36_unknown_hook_agent_must_not_bypass_binding() {
    let f = Fixture::new(ALLOW);
    let (ps, pr) = review8dd_start(
        &f,
        "parent-root",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(ps, &pr);
    let (s, r) = review8dd_start(
        &f,
        "reader-session",
        "reader",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
    let mut hook = json!({"session_id":"review-host","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo harmless"},"agent_id":"reader"});
    let (_, r) = post(f.state.clone(), "/hook", &hook, Some(HOOK_TOKEN)).await;
    assert_eq!(
        r["hookSpecificOutput"]["permissionDecision"], "deny",
        "control: {r}"
    );
    hook["agent_id"] = json!("unregistered-impostor");
    let (_, r) = post(f.state.clone(), "/hook", &hook, Some(HOOK_TOKEN)).await;
    assert_eq!(
        r["hookSpecificOutput"]["permissionDecision"], "deny",
        "changing only agent_id bypassed verified binding: {r}"
    );
}

#[tokio::test]
async fn review36_missing_parent_must_not_register_child_as_root() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "orphan",
        "worker",
        Some("nonexistent-parent"),
        &["delete_document"],
        Some(vec![]),
    )
    .await;
    if s != StatusCode::OK || r["release"] != true {
        return;
    }
    let (s, r) = f
        .post(&f.call("orphan", "delete_document", &json!({})))
        .await;
    assert!(
        s != StatusCode::OK || r["release"] != true,
        "unprovable parent granted destructive authority: {r}"
    );
}

#[tokio::test]
async fn review36_parent_end_must_not_drop_resource_constraints() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent",
        "parent-agent",
        None,
        &["send_email"],
        Some(vec!["internal.corp".into()]),
    )
    .await;
    assert_allow(s, &r);
    let (s, r) = review8dd_start(
        &f,
        "blocked-child",
        "worker",
        Some("parent-agent"),
        &["send_email"],
        Some(vec!["attacker.invalid".into()]),
    )
    .await;
    assert!(
        s != StatusCode::OK || r["release"] != true,
        "control must reject escalation: {r}"
    );
    let (s, r) = f.post(&f.event("parent", "session_end")).await;
    assert_allow(s, &r);
    let (s, r) = review8dd_start(
        &f,
        "after-end",
        "worker",
        Some("parent-agent"),
        &["send_email"],
        Some(vec!["attacker.invalid".into()]),
    )
    .await;
    if s != StatusCode::OK || r["release"] != true {
        return;
    }
    let (s, r) = f
        .post(&f.call(
            "after-end",
            "send_email",
            &json!({"to":"outside@attacker.invalid"}),
        ))
        .await;
    assert!(
        s != StatusCode::OK || r["release"] != true,
        "ending parent erased destination narrowing but retained tool grant: {r}"
    );
}

#[tokio::test]
async fn review36_unknown_parent_scope_must_not_become_proven_child_scope() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(&f, "parent", "parent-agent", None, &["send_email"], None).await;
    assert_allow(s, &r);
    let (s, r) = f
        .post(&f.call(
            "parent",
            "send_email",
            &json!({"to":"outside@attacker.invalid"}),
        ))
        .await;
    assert!(
        s != StatusCode::OK || r["release"] != true,
        "control: parent destination authority is unprovable"
    );
    let (s, r) = review8dd_start(
        &f,
        "child",
        "worker",
        Some("parent-agent"),
        &["send_email"],
        Some(vec!["attacker.invalid".into()]),
    )
    .await;
    if s != StatusCode::OK || r["release"] != true {
        return;
    }
    let (s, r) = f
        .post(&f.call(
            "child",
            "send_email",
            &json!({"to":"outside@attacker.invalid"}),
        ))
        .await;
    assert!(
        s != StatusCode::OK || r["release"] != true,
        "child obtained destination denied to its parent: {r}"
    );
}

#[tokio::test]
async fn review36_legitimate_mailbox_narrowing_must_be_usable() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent",
        "parent-agent",
        None,
        &["send_email"],
        Some(vec!["internal.corp".into()]),
    )
    .await;
    assert_allow(s, &r);
    let (s, r) = review8dd_start(
        &f,
        "child",
        "worker",
        Some("parent-agent"),
        &["send_email"],
        Some(vec!["alice@internal.corp".into()]),
    )
    .await;
    assert_allow(s, &r);
    let (s, r) = f
        .post(&f.call("child", "send_email", &json!({"to":"alice@internal.corp"})))
        .await;
    assert_allow(s, &r);
}

#[tokio::test]
async fn review36_expired_child_authority_must_not_authorize_hooks() {
    use agentfw::native::child_authority as ca;
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent",
        "parent-agent",
        None,
        &["read_document", "Bash"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // Give the useful control enough real time to run even on a cold Windows
    // worker. Expiry itself is tested below without sleeping on that control.
    let grant = ca::mint_scoped(
        &ca::derive_key(NATIVE_TOKEN),
        "review-host",
        "resource-fixture",
        &["read_document".into(), "Bash".into()],
        now,
        30_000,
        scoped_fixture_nonce(&f, "review-host", Some("parent-agent")),
        Some("worker".into()),
        Some("parent-agent".into()),
        Some(vec![]),
    );
    let mut start = f.event("short-child", "session_start");
    start["host_session"] = json!("review-host");
    start["server_id"] = json!("resource-fixture");
    start["child_authority"] = json!(ca::encode_token(&grant));
    let (s, r) = f.post(&start).await;
    assert!(
        s == StatusCode::OK && r["release"] == true,
        "phase=child_start reason=valid_authority_rejected"
    );
    let hook = json!({"session_id":"review-host","hook_event_name":"PreToolUse","tool_name":"read_document","tool_input":{},"agent_id":"worker"});
    let r = post_with_proof(&f, &hook, start["child_authority"].as_str().unwrap()).await;
    let check_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert_eq!(r, json!({}),
        "phase=useful_hook reason=valid_authority_rejected issue_to_check_ms={} expiry_after_check_ms={}",
        check_ms.saturating_sub(now), grant.expires_at_ms.saturating_sub(check_ms));
    f.state
        .native
        .as_ref()
        .unwrap()
        .advance_test_time_ms(30_001);
    let (_, r) = f
        .post(&f.call("short-child", "read_document", &json!({})))
        .await;
    assert_eq!(
        r["error_code"], "native_child_authority_expired",
        "phase=child_call reason=expired_authority_accepted"
    );
    // The hook verifier reads the production wall clock. Present a separately
    // signed, already expired proof to verify that path without changing its clock.
    let real_check_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let expired = ca::mint_scoped(
        &ca::derive_key(NATIVE_TOKEN),
        "review-host",
        "resource-fixture",
        &["read_document".into()],
        real_check_ms.saturating_sub(2_000),
        500,
        scoped_fixture_nonce(&f, "review-host", Some("parent-agent")),
        Some("worker".into()),
        Some("parent-agent".into()),
        Some(vec![]),
    );
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let r = post_with_proof(&f, &hook, &ca::encode_token(&expired)).await;
    assert_eq!(
        r["hookSpecificOutput"]["permissionDecision"], "deny",
        "phase=hook_real_clock reason=expired_authority_accepted issue_to_check_ms={} expiry_before_check_ms={}",
        real_check_ms.saturating_sub(expired.issued_at_ms), real_check_ms.saturating_sub(expired.expires_at_ms)
    );
    assert!(
        r.to_string().contains("native_hook_authority_invalid"),
        "phase=hook_real_clock reason=wrong_denial_for_expiry"
    );
}

#[tokio::test]
async fn review36_conflicting_posttool_identity_must_mark_history_loss() {
    let f = Fixture::new(ALLOW);
    let (ps, pr) = review8dd_start(
        &f,
        "parent-root",
        "parent",
        None,
        &["read_document", "delete_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(ps, &pr);
    let (s, r) = review8dd_start(
        &f,
        "reader",
        "reader-agent",
        Some("parent"),
        &["read_document", "delete_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
    let hook = json!({"session_id":"review-host","hook_event_name":"PostToolUse","tool_name":"WebFetch","tool_input":{"url":"https://fixture.invalid"},"tool_response":INJECTION,"agent_id":"reader-agent","parent_id":"wrong-parent"});
    let (s, _) = post(f.state.clone(), "/hook", &hook, Some(HOOK_TOKEN)).await;
    assert_eq!(s, StatusCode::OK);
    let fw = f.state.firewall.lock().unwrap();
    assert!(fw.provenance_incomplete("review-host") || fw.taint_len("review-host") > 0,"identity conflict silently discarded consumed untrusted result without sticky incomplete history");
}

#[tokio::test]
async fn scoped_hook_proof_authenticates_identity_and_rejects_claim_swaps() {
    for change in [
        "none",
        "qualified",
        "wrong-server",
        "agent",
        "parent",
        "session",
        "signature",
        "missing",
        "tool",
    ] {
        let f = Fixture::new(ALLOW);
        let (s, r) = review8dd_start(
            &f,
            "parent-root",
            "parent",
            None,
            &["read_document"],
            Some(vec![]),
        )
        .await;
        assert_allow(s, &r);
        let (s, r, proof) = scoped_start_with_ttl(
            &f,
            "worker",
            "worker",
            Some("parent"),
            &["read_document"],
            Some(vec![]),
            60_000,
        )
        .await;
        assert_allow(s, &r);
        let mut hook = json!({"session_id":"review-host","hook_event_name":"PreToolUse","tool_name":"read_document","tool_input":{}});
        match change {
            "qualified" => hook["tool_name"] = json!("mcp__resource-fixture__read_document"),
            "wrong-server" => hook["tool_name"] = json!("mcp__wrong__read_document"),
            "agent" => hook["agent_id"] = json!("parent"),
            "parent" => hook["parent_id"] = json!("unknown"),
            "session" => hook["session_id"] = json!("other-host"),
            "tool" => hook["tool_name"] = json!("delete_document"),
            _ => {}
        }
        let r = if change == "missing" {
            post(f.state.clone(), "/hook", &hook, Some(HOOK_TOKEN))
                .await
                .1
        } else {
            post_with_proof(
                &f,
                &hook,
                if change == "signature" {
                    "forged-proof"
                } else {
                    &proof
                },
            )
            .await
        };
        if change == "none" || change == "qualified" {
            assert_eq!(r, json!({}), "valid signed hook remains useful");
        } else {
            assert_eq!(
                r["hookSpecificOutput"]["permissionDecision"], "deny",
                "{change}: {r}"
            );
        }
        assert!(!std::fs::read_to_string(f.dir.path().join("audit.jsonl"))
            .unwrap()
            .contains(&proof));
    }
}

#[tokio::test]
async fn ending_or_replacing_parent_never_resurrects_existing_child() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent-root",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
    let (s, r, proof) = scoped_start_with_ttl(
        &f,
        "worker",
        "worker",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        60_000,
    )
    .await;
    assert_allow(s, &r);
    let (s, r) = f.post(&f.call("worker", "read_document", &json!({}))).await;
    assert_allow(s, &r);
    let (s, r) = f.post(&f.event("parent-root", "session_end")).await;
    assert_allow(s, &r);
    assert_eq!(
        f.state
            .firewall
            .lock()
            .unwrap()
            .agent_tools("review-host", "parent"),
        None
    );
    assert_eq!(
        f.state
            .firewall
            .lock()
            .unwrap()
            .agent_tools("review-host", "worker"),
        Some(vec!["read_document".into()])
    );
    for restart in [false, true] {
        if restart {
            let (s, r) = review8dd_start(
                &f,
                "parent-new",
                "parent",
                None,
                &["read_document"],
                Some(vec![]),
            )
            .await;
            assert_allow(s, &r);
        }
        let (_, r) = f.post(&f.call("worker", "read_document", &json!({}))).await;
        assert_eq!(r["error_code"], "native_child_parent_unavailable");
        let r = post_with_proof(&f,&json!({"session_id":"review-host","hook_event_name":"PreToolUse","tool_name":"read_document","tool_input":{}}),&proof).await;
        assert_eq!(r["hookSpecificOutput"]["permissionDecision"], "deny");
    }
}

#[tokio::test]
async fn expired_parent_cannot_authorize_a_long_lived_descendant() {
    let f = Fixture::new(ALLOW);
    let (s, r, _) = scoped_start_with_ttl(
        &f,
        "parent-root",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
        500,
    )
    .await;
    assert_allow(s, &r);
    let (s, r, proof) = scoped_start_with_ttl(
        &f,
        "worker",
        "worker",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        60_000,
    )
    .await;
    assert_allow(s, &r);
    tokio::time::sleep(std::time::Duration::from_millis(550)).await;
    let (_, r) = f.post(&f.call("worker", "read_document", &json!({}))).await;
    assert_eq!(r["error_code"], "native_child_authority_expired");
    let r = post_with_proof(&f,&json!({"session_id":"review-host","hook_event_name":"PreToolUse","tool_name":"read_document","tool_input":{}}),&proof).await;
    assert_eq!(r["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[tokio::test]
async fn signed_hook_result_preserves_server_origin_and_conflicts_mark_loss_even_in_shadow() {
    for enforce in [true, false] {
        let mut f = Fixture::new(ALLOW);
        let (s, r) = review8dd_start(
            &f,
            "parent-root",
            "parent",
            None,
            &["read_document"],
            Some(vec![]),
        )
        .await;
        assert_allow(s, &r);
        let (s, r, proof) = scoped_start_with_ttl(
            &f,
            "worker",
            "worker",
            Some("parent"),
            &["read_document"],
            Some(vec![]),
            60_000,
        )
        .await;
        assert_allow(s, &r);
        Arc::get_mut(&mut f.state).unwrap().config.enforce = enforce;
        let mut hook = json!({"session_id":"review-host","hook_event_name":"PostToolUse","tool_name":"read_document","tool_input":{},"tool_response":UNTRUSTED_TEXT});
        assert_eq!(post_with_proof(&f, &hook, &proof).await, json!({}));
        assert!(f.state.firewall.lock().unwrap().taint_len("review-host") > 0);
        hook["parent_id"] = json!("wrong-parent");
        assert_eq!(post_with_proof(&f, &hook, &proof).await, json!({}));
        assert!(f
            .state
            .firewall
            .lock()
            .unwrap()
            .provenance_incomplete("review-host"));
        assert!(f
            .audit()
            .iter()
            .any(|r| r["rule"] == "native_hook_identity_mismatch"));
    }
}

#[tokio::test]
async fn completed_scoped_host_never_falls_back_to_unsigned_hooks() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(&f, "root", "root", None, &["read_document"], Some(vec![])).await;
    assert_allow(s, &r);
    let (s, r) = f.post(&f.event("root", "session_end")).await;
    assert_allow(s, &r);
    let (_,r) = post(f.state.clone(),"/hook",&json!({"session_id":"review-host","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo harmless"}}),Some(HOOK_TOKEN)).await;
    assert_eq!(r["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[tokio::test]
async fn scoped_grant_cannot_replay_into_a_restarted_daemon() {
    let mut f = Fixture::new(ALLOW);
    let (s, r, proof) = scoped_start_with_ttl(
        &f,
        "root",
        "root",
        None,
        &["read_document"],
        Some(vec![]),
        60_000,
    )
    .await;
    assert_allow(s, &r);
    let old_instance = f.state.native.as_ref().unwrap().instance_id().to_string();
    let bytes = serde_json::to_vec(&registry()).unwrap();
    f.state = make_state(
        f.dir.path(),
        Config {
            enforce: true,
            ..Config::default()
        },
        ALLOW,
        &bytes,
        &f.registry_sha256,
    );
    assert_ne!(old_instance, f.state.native.as_ref().unwrap().instance_id());
    let mut start = f.event("replay", "session_start");
    start["host_session"] = json!("review-host");
    start["server_id"] = json!("resource-fixture");
    start["child_authority"] = json!(proof);
    let (_, r) = f.post(&start).await;
    assert_eq!(r["error_code"], "native_child_authority_instance_mismatch");
    let (s, r) = review8dd_start(&f, "fresh", "root", None, &["read_document"], Some(vec![])).await;
    assert_allow(s, &r);
}

#[tokio::test]
async fn instance_bootstrap_requires_the_native_issuer_bearer() {
    let f = Fixture::new(ALLOW);
    for token in [None, Some(HOOK_TOKEN), Some(NATIVE_TOKEN)] {
        let mut builder = Request::builder().uri("/native/v1/instance");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let res = app(f.state.clone())
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            if token == Some(NATIVE_TOKEN) {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
        if token == Some(NATIVE_TOKEN) {
            let body: Value =
                serde_json::from_slice(&to_bytes(res.into_body(), 1024).await.unwrap()).unwrap();
            assert_eq!(
                body["instance_id"],
                f.state.native.as_ref().unwrap().instance_id()
            );
            assert_eq!(body["registry_sha256"], f.registry_sha256);
        }
    }
}

#[tokio::test]
async fn duplicate_agent_bootstrap_never_overwrites_an_active_grant() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "original",
        "worker",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
    let (_, r) = review8dd_start(
        &f,
        "replacement",
        "worker",
        None,
        &["read_document", "delete_document"],
        Some(vec![]),
    )
    .await;
    assert_eq!(r["error_code"], "native_agent_already_bound");
    assert_eq!(
        f.state
            .firewall
            .lock()
            .unwrap()
            .agent_tools("review-host", "worker"),
        Some(vec!["read_document".into()])
    );
    let (s, r) = f
        .post(&f.call("original", "read_document", &json!({})))
        .await;
    assert_allow(s, &r);
}

#[tokio::test]
async fn scoped_host_capacity_never_evicts_completed_identity_tombstones() {
    use agentfw::native::child_authority as ca;
    let f = Fixture::new(ALLOW);
    for n in 0..=64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let host = format!("host-{n}");
        let grant = ca::mint_scoped(
            &ca::derive_key(NATIVE_TOKEN),
            &host,
            "resource-fixture",
            &["read_document".into()],
            now,
            60_000,
            format!(
                "{}.{}",
                f.state.native.as_ref().unwrap().instance_id(),
                agentfw::token::generate()
            ),
            Some("root".into()),
            None,
            Some(vec![]),
        );
        let mut start = f.event(&format!("root-{n}"), "session_start");
        start["host_session"] = json!(host);
        start["server_id"] = json!("resource-fixture");
        start["child_authority"] = json!(ca::encode_token(&grant));
        let (s, r) = f.post(&start).await;
        if n == 64 {
            assert_eq!(r["error_code"], "native_host_binding_cap");
        } else {
            assert_allow(s, &r);
            let (s, r) = f.post(&f.event(&format!("root-{n}"), "session_end")).await;
            assert_allow(s, &r);
        }
    }
    let (_,r)=post(f.state.clone(),"/hook",&json!({"session_id":"host-0","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo harmless"}}),Some(HOOK_TOKEN)).await;
    assert_eq!(r["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[tokio::test]
async fn a_child_grant_cannot_bootstrap_under_a_replacement_parent_epoch() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent-first",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
    let (s, r, proof) = scoped_start_with_ttl(
        &f,
        "child-first",
        "worker",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        60_000,
    )
    .await;
    assert_allow(s, &r);
    let (s, r) = f.post(&f.event("child-first", "session_end")).await;
    assert_allow(s, &r);
    let mut start = f.event("child-retry", "session_start");
    start["host_session"] = json!("review-host");
    start["server_id"] = json!("resource-fixture");
    start["child_authority"] = json!(proof);
    let (s, r) = f.post(&start).await;
    assert_allow(s, &r);
    let (s, r) = f.post(&f.event("child-retry", "session_end")).await;
    assert_allow(s, &r);
    let (s, r) = f.post(&f.event("parent-first", "session_end")).await;
    assert_allow(s, &r);
    let (s, r) = review8dd_start(
        &f,
        "parent-replacement",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
    start["session_id"] = json!("child-stale");
    let (_, r) = f.post(&start).await;
    assert_eq!(r["error_code"], "native_child_parent_binding_mismatch");
    let (s, r) = review8dd_start(
        &f,
        "child-fresh",
        "worker",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
}
