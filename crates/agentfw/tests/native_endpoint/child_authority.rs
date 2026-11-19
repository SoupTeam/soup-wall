// SPDX-License-Identifier: Apache-2.0

use super::*;

fn legacy_host_start(fixture: &Fixture, collector: &str) -> Value {
    use agentfw::native::child_authority as ca;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let key = ca::derive_key(NATIVE_TOKEN);
    let grant = ca::mint(
        &key,
        "host",
        "documents",
        &["read_document".into(), "delete_document".into()],
        now,
        60_000,
        agentfw::token::generate(),
    );
    let proof = ca::encode_token(&grant);
    assert!(ca::verify_token(&key, &proof, "host", "documents", now).is_ok(),
        "legacy wire signatures remain compatible; shared-host admission must reject the weaker authority");
    let mut start = fixture.event(collector, "session_start");
    start["host_session"] = json!("host");
    start["server_id"] = json!("documents");
    start["child_authority"] = json!(proof);
    start
}

#[tokio::test]
async fn reviewc757_legacy_host_grant_cannot_reset_history_after_session_end() {
    let f = Fixture::new("agent_policies:\n  - name: shared-mcp-deny\n    when: { taint: [mcp], action_class: destructive }\n    action: deny\ndefault: allow\n");
    let mut start = legacy_host_start(&f, "original");
    let (s, r) = f.post(&start).await;
    if r["release"] != true {
        assert_failure(s, &r, StatusCode::CONFLICT);
        assert_eq!(r["error_code"], "native_child_authority_identity_required");
        assert!(
            f.audit().is_empty(),
            "refusal must precede session allocation/audit admission"
        );
        // Genuinely isolated operation without a host binding remains supported.
        f.start("independent").await;
        f.allowed_call("independent", "delete_document", &json!({}))
            .await;
        return;
    }
    // Original reviewer witness: if legacy bootstrap is ever restored, it must
    // not permit an ended host's taint to be discarded and the token replayed.
    assert_allow(s, &r);
    let (s, r) = f
        .post(&child_result(&f, "original", UNTRUSTED_TEXT).await)
        .await;
    assert_allow(s, &r);
    let (_, denied) = f
        .post(&f.call(
            "original",
            "delete_document",
            &json!({"path":UNTRUSTED_TEXT}),
        ))
        .await;
    assert_eq!(denied["verdict"], "deny");
    let (s, r) = f.post(&f.event("original", "session_end")).await;
    assert_allow(s, &r);
    post(
        f.state.clone(),
        "/hook",
        &json!({"session_id":"host","hook_event_name":"SessionEnd"}),
        Some(HOOK_TOKEN),
    )
    .await;
    start["session_id"] = json!("replacement");
    let (_, replay) = f.post(&start).await;
    assert_ne!(
        replay["release"], true,
        "legacy token resurrected an ended host: {replay}"
    );
}

#[tokio::test]
async fn reviewc757_legacy_host_grant_cannot_replay_after_daemon_restart() {
    let mut f = Fixture::new(ALLOW);
    let mut start = legacy_host_start(&f, "original");
    let bytes = serde_json::to_vec(&registry()).unwrap();
    let old_instance = f.state.native.as_ref().unwrap().instance_id().to_string();
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
    start["session_id"] = json!("replacement");
    let (s, r) = f.post(&start).await;
    assert_failure(s, &r, StatusCode::CONFLICT);
    assert_eq!(r["error_code"], "native_child_authority_identity_required");
    assert!(f.audit().is_empty());
    // Both truly isolated requests and freshly authenticated host bindings work.
    f.start("independent").await;
    f.allowed_call("independent", "read_document", &json!({}))
        .await;
    let (s, r) = f
        .post(&child_start(&f, "fresh", "host", Some("documents")))
        .await;
    assert_allow(s, &r);
}

#[tokio::test]
async fn reviewc757_current_instance_prefix_cannot_upgrade_legacy_host_authority() {
    use agentfw::native::child_authority as ca;
    let f = Fixture::new(ALLOW);
    // Establish and complete a real scoped host before trying the weaker format.
    let (s, r) = f
        .post(&child_start(&f, "scoped", "host", Some("documents")))
        .await;
    assert_allow(s, &r);
    let (s, r) = f.post(&f.event("scoped", "session_end")).await;
    assert_allow(s, &r);
    for resources in [None, Some(vec![])] {
        let mut start = legacy_host_start(&f, "downgrade");
        let original = ca::decode_token(start["child_authority"].as_str().unwrap()).unwrap();
        let grant = ca::mint_scoped(
            &ca::derive_key(NATIVE_TOKEN),
            "host",
            "documents",
            &original.granted_tools,
            original.issued_at_ms,
            60_000,
            scoped_fixture_nonce(&f, "host", None),
            None,
            None,
            resources,
        );
        start["child_authority"] = json!(ca::encode_token(&grant));
        let (s, r) = f.post(&start).await;
        assert_failure(s, &r, StatusCode::CONFLICT);
        assert_eq!(r["error_code"], "native_child_authority_identity_required");
    }
    let (_, r) = post(
        f.state.clone(),
        "/hook",
        &json!({"session_id":"host",
        "hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo safe"}}),
        Some(HOOK_TOKEN),
    )
    .await;
    assert_eq!(r["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[tokio::test]
async fn child_authority_binds_host_taint_spans_and_audit() {
    for server in [Some("documents"), None] {
        let fixture = Fixture::new(ALLOW);
        // Share the hook sequence allocator and preserve existing host spans.
        assert_eq!(fixture.state.sessions.next("host"), 1);
        fixture.state.spans.put("host", 1, "existing host content");
        let start = child_start(&fixture, "collector", "host", server);
        let (status, reply) = fixture.post(&start).await;
        assert_allow(status, &reply);
        let result = child_result(&fixture, "collector", UNTRUSTED_TEXT).await;
        let (status, reply) = fixture.post(&result).await;
        assert_allow(status, &reply);
        let audit = fixture.audit();
        let epoch = audit[0]["session"].as_str().unwrap();
        let seq = audit.last().unwrap()["seq"].as_u64().unwrap();
        assert!(audit.iter().all(|record| record["host_session"] == "host"));
        {
            let firewall = fixture.state.firewall.lock().unwrap();
            assert!(firewall.taint_len(epoch) > 0);
            assert!(firewall.taint_len("host") > 0);
            assert_eq!(firewall.taint_len("unrelated-host"), 0);
        }
        assert_eq!(
            fixture.state.spans.get(epoch, seq).as_deref(),
            Some(UNTRUSTED_TEXT)
        );
        assert_eq!(
            fixture.state.spans.get("host", 2).as_deref(),
            Some(UNTRUSTED_TEXT)
        );
        assert_eq!(
            fixture.state.spans.get("host", 1).as_deref(),
            Some("existing host content")
        );
        let (status, replay) = fixture.post(&result).await;
        assert_failure(status, &replay, StatusCode::CONFLICT);
        assert_eq!(fixture.state.sessions.next("host"), 3);
        let (status, ended) = fixture
            .post(&fixture.event("collector", "session_end"))
            .await;
        assert_allow(status, &ended);
        assert_eq!(fixture.audit().last().unwrap()["host_session"], "host");
        assert!(fixture.state.firewall.lock().unwrap().taint_len("host") > 0);
        assert!(fixture.state.spans.get("host", 2).is_some());
    }
}

#[tokio::test]
async fn child_authority_refuses_missing_expired_forged_and_mismatched_grants() {
    use agentfw::native::child_authority;
    let fixture = Fixture::new(ALLOW);
    let original = child_start(&fixture, "collector", "host", Some("documents"));
    for (case, expected) in [
        ("missing", "native_child_authority_missing"),
        ("expired", "native_child_authority_expired"),
        ("forged", "native_child_authority_bad_signature"),
        ("future", "native_child_authority_not_yet_valid"),
        ("host", "native_child_authority_host_mismatch"),
        ("server", "native_child_authority_server_mismatch"),
        ("malformed", "native_child_authority_malformed"),
    ] {
        let mut request = original.clone();
        match case {
            "missing" => {
                request.as_object_mut().unwrap().remove("child_authority");
            }
            "host" => request["host_session"] = json!("another-host"),
            "server" => request["server_id"] = json!("another-server"),
            "malformed" => request["child_authority"] = json!("!malformed!"),
            _ => {
                let mut grant =
                    child_authority::decode_token(original["child_authority"].as_str().unwrap())
                        .unwrap();
                if case == "forged" {
                    grant.granted_tools.push("delete_document".into());
                } else {
                    let issued = if case == "expired" {
                        0
                    } else {
                        grant.issued_at_ms + 120_000
                    };
                    grant = child_authority::mint_scoped(
                        &child_authority::derive_key(NATIVE_TOKEN),
                        "host",
                        "documents",
                        &grant.granted_tools,
                        issued,
                        60_000,
                        grant.nonce.clone(),
                        grant.agent_id.clone(),
                        None,
                        None,
                    );
                }
                request["child_authority"] = json!(child_authority::encode_token(&grant));
            }
        }
        let (status, reply) = fixture.post(&request).await;
        assert_failure(status, &reply, StatusCode::CONFLICT);
        assert_eq!(reply["error_code"], expected, "{case}: {reply}");
        assert_eq!(fixture.state.firewall.lock().unwrap().taint_len("host"), 0);
        assert!(fixture.state.spans.get("host", 1).is_none());
    }
    assert!(fixture.audit().is_empty());
    // Refusals cannot reserve the collector ID.
    let (status, reply) = fixture.post(&original).await;
    assert_allow(status, &reply);
}

#[tokio::test]
async fn child_authority_restricts_tools_and_binding_fields_to_session_start() {
    let fixture = Fixture::new(ALLOW);
    let start = child_start(&fixture, "collector", "host", Some("documents"));
    let (status, reply) = fixture.post(&start).await;
    assert_allow(status, &reply);
    let call = fixture.call("collector", "delete_document", &json!({}));
    let (status, reply) = fixture.post(&call).await;
    assert_failure(status, &reply, StatusCode::CONFLICT);
    assert_eq!(reply["error_code"], "native_child_authority_escalation");
    for field in ["host_session", "server_id", "child_authority"] {
        let mut forged = fixture.call("collector", "read_document", &json!({}));
        forged[field] = start[field].clone();
        let (status, reply) = fixture.post(&forged).await;
        assert_failure(status, &reply, StatusCode::BAD_REQUEST);
        assert_eq!(reply["error_code"], "native_invalid_fields");
    }
    fixture
        .allowed_call("collector", "read_document", &json!({}))
        .await;
    for field in ["host_session", "server_id"] {
        let mut invalid = child_start(&fixture, "invalid", "host", Some("documents"));
        invalid[field] = json!("invalid identifier!");
        let (status, reply) = fixture.post(&invalid).await;
        assert_failure(status, &reply, StatusCode::BAD_REQUEST);
        assert_eq!(reply["error_code"], "native_invalid_identity");
    }
}

#[tokio::test]
async fn bound_host_withheld_result_does_not_admit_taint_or_spans() {
    let fixture = Fixture::new(INJECTION_POLICY);
    let (status, reply) = fixture
        .post(&child_start(
            &fixture,
            "collector",
            "host",
            Some("documents"),
        ))
        .await;
    assert_allow(status, &reply);
    let result = child_result(&fixture, "collector", INJECTION).await;
    let (status, reply) = fixture.post(&result).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["release"], false);
    let audit = fixture.audit();
    let epoch = audit[0]["session"].as_str().unwrap();
    assert_eq!(fixture.state.firewall.lock().unwrap().taint_len(epoch), 0);
    assert_eq!(fixture.state.firewall.lock().unwrap().taint_len("host"), 0);
    assert!(fixture.state.spans.get("host", 1).is_none());
    assert_eq!(fixture.state.sessions.next("host"), 1);
}

#[tokio::test]
async fn bound_host_concurrent_completion_admits_once() {
    let fixture = Fixture::new(ALLOW);
    let (status, reply) = fixture
        .post(&child_start(
            &fixture,
            "collector",
            "host",
            Some("documents"),
        ))
        .await;
    assert_allow(status, &reply);
    let result = child_result(&fixture, "collector", UNTRUSTED_TEXT).await;
    let (first, second) = tokio::join!(fixture.post(&result), fixture.post(&result));
    assert!(matches!(
        (first.0, second.0),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    assert_eq!(
        fixture.state.spans.get("host", 1).as_deref(),
        Some(UNTRUSTED_TEXT)
    );
    assert_eq!(fixture.state.sessions.next("host"), 2);
}

#[tokio::test]
async fn bound_mcp_provenance_reaches_hook_policy_and_audit() {
    let fixture = Fixture::new(
        "agent_policies:\n  - name: fixture-mcp-reuse\n    when: { taint: [mcp], action_class: destructive }\n    action: deny\ndefault: allow\n",
    );
    let start = reviewer_start(
        &fixture,
        "documents",
        &["read_document", "delete_document"],
        60_000,
    );
    let (status, reply) = fixture.post(&start).await;
    assert_allow(status, &reply);
    let result = child_result(&fixture, "documents", UNTRUSTED_TEXT).await;
    let (status, reply) = fixture.post(&result).await;
    assert_allow(status, &reply);
    let hook = json!({"session_id":"host","hook_event_name":"PreToolUse",
        "tool_name":"mcp__documents__delete_document","tool_input":{"path":UNTRUSTED_TEXT}});
    let reply = post_with_proof(&fixture, &hook, start["child_authority"].as_str().unwrap()).await;
    assert_eq!(
        reply["hookSpecificOutput"]["permissionDecision"], "deny",
        "{reply}"
    );
    let audit = fixture.audit();
    let record = audit.last().unwrap();
    assert_eq!(record["rule"], "fixture-mcp-reuse");
    assert_eq!(record["taint"]["origin"], "mcp");
    assert_eq!(record["taint"]["source_name"], "documents");
    assert_eq!(record["taint"]["seq"], 1);
    assert_eq!(
        fixture.state.spans.get("host", 1).as_deref(),
        Some(UNTRUSTED_TEXT)
    );
    let public = serde_json::to_string(&audit).unwrap();
    assert!(!public.contains(start["child_authority"].as_str().unwrap()));
    assert!(!public.contains(UNTRUSTED_TEXT));
}

#[tokio::test]
async fn ending_bound_collector_cancels_pending_result_without_host_admission() {
    let fixture = Fixture::new(ALLOW);
    let (status, reply) = fixture
        .post(&child_start(
            &fixture,
            "collector",
            "host",
            Some("documents"),
        ))
        .await;
    assert_allow(status, &reply);
    let result = child_result(&fixture, "collector", UNTRUSTED_TEXT).await;
    let (status, reply) = fixture
        .post(&fixture.event("collector", "session_end"))
        .await;
    assert_allow(status, &reply);
    let (status, reply) = fixture.post(&result).await;
    assert_failure(status, &reply, StatusCode::CONFLICT);
    assert_eq!(reply["error_code"], "native_session_unknown");
    assert_eq!(fixture.state.firewall.lock().unwrap().taint_len("host"), 0);
    assert!(fixture.state.spans.get("host", 1).is_none());
    let (status, reply) = fixture
        .post(&child_start(
            &fixture,
            "collector",
            "other-host",
            Some("documents"),
        ))
        .await;
    assert_allow(status, &reply);
    let (status, reply) = fixture.post(&result).await;
    assert_failure(status, &reply, StatusCode::CONFLICT);
    assert_eq!(reply["error_code"], "native_call_unknown_or_spent");
    assert_eq!(
        fixture
            .state
            .firewall
            .lock()
            .unwrap()
            .taint_len("other-host"),
        0
    );
}

#[tokio::test]
async fn bound_trusted_result_keeps_registry_provenance() {
    use agentfw::native::child_authority;
    let fixture = Fixture::new(ALLOW);
    let mut start = child_start(&fixture, "collector", "host", Some("documents"));
    let original =
        child_authority::decode_token(start["child_authority"].as_str().unwrap()).unwrap();
    let grant = child_authority::mint_scoped(
        &child_authority::derive_key(NATIVE_TOKEN),
        "host",
        "documents",
        &["delete_document".into()],
        original.issued_at_ms,
        60_000,
        original.nonce.clone(),
        original.agent_id.clone(),
        None,
        None,
    );
    start["child_authority"] = json!(child_authority::encode_token(&grant));
    let (status, reply) = fixture.post(&start).await;
    assert_allow(status, &reply);
    let call = fixture
        .allowed_call("collector", "delete_document", &json!({}))
        .await;
    let content = json!({"jsonrpc":"2.0","id":1,"result":{
        "content":[{"type":"text","text":UNTRUSTED_TEXT}]}})
    .to_string();
    let mut result = fixture.result(
        "collector",
        &call,
        "delete_document",
        &json!({}),
        "value",
        &content,
    );
    result["delivery"] = json!("mcp_host");
    let (status, reply) = fixture.post(&result).await;
    assert_allow(status, &reply);
    let audit = fixture.audit();
    let epoch = audit[0]["session"].as_str().unwrap();
    assert_eq!(fixture.state.firewall.lock().unwrap().taint_len(epoch), 0);
    assert_eq!(fixture.state.firewall.lock().unwrap().taint_len("host"), 0);
    assert!(fixture.state.spans.get("host", 1).is_none());
    assert_eq!(fixture.state.sessions.next("host"), 2);
}
