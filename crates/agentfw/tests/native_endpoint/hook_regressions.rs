// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn reviewer_cross_collector_must_enforce_shared_host_taint() {
    let f = Fixture::new("agent_policies:\n  - name: shared-mcp-deny\n    when: { taint: [mcp], action_class: destructive }\n    action: deny\ndefault: allow\n");
    for (collector, tools) in [("a", vec!["read_document"]), ("b", vec!["delete_document"])] {
        let (s, r) = f.post(&reviewer_start(&f, collector, &tools, 60_000)).await;
        assert_allow(s, &r);
    }
    let result = child_result(&f, "a", UNTRUSTED_TEXT).await;
    let (s, r) = f.post(&result).await;
    assert_allow(s, &r);
    assert!(f.state.firewall.lock().unwrap().taint_len("host") > 0);
    let (s, r) = f
        .post(&f.call("b", "delete_document", &json!({"text":UNTRUSTED_TEXT})))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["verdict"], "deny", "cross-collector result: {r}");
}

#[tokio::test]
async fn reviewer_empty_scope_must_not_grant_destructive_tool() {
    let f = Fixture::new(ALLOW);
    let (s, r) = f.post(&reviewer_start(&f, "empty", &[], 60_000)).await;
    assert_allow(s, &r);
    let (s, r) = f
        .post(&f.call("empty", "delete_document", &json!({})))
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "empty scope: {r}");
    assert_eq!(r["error_code"], "native_child_authority_escalation");
}

#[tokio::test]
async fn reviewer_expired_grant_must_not_authorize_new_calls() {
    let f = Fixture::new(ALLOW);
    let (s, r) = f
        .post(&reviewer_start(&f, "short", &["delete_document"], 100))
        .await;
    assert_allow(s, &r);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let (s, r) = f
        .post(&f.call("short", "delete_document", &json!({})))
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "expired scope: {r}");
}

#[tokio::test]
async fn reviewer_hook_session_end_must_not_erase_active_child_history() {
    let f = Fixture::new(ALLOW);
    let (s, r) = f
        .post(&reviewer_start(&f, "a", &["read_document"], 60_000))
        .await;
    assert_allow(s, &r);
    let result = child_result(&f, "a", UNTRUSTED_TEXT).await;
    let (s, r) = f.post(&result).await;
    assert_allow(s, &r);
    assert!(f.state.firewall.lock().unwrap().taint_len("host") > 0);
    let hook = json!({"session_id":"host","hook_event_name":"SessionEnd"});
    let _ = post(f.state.clone(), "/hook", &hook, Some(HOOK_TOKEN)).await;
    assert!(
        f.state.firewall.lock().unwrap().taint_len("host") > 0,
        "unbound hook SessionEnd cleared history of active authenticated child"
    );
}

#[tokio::test]
async fn reviewer_oversized_hook_must_mark_shared_history_incomplete() {
    let f = Fixture::configured(
        ALLOW,
        Config {
            enforce: true,
            max_body_bytes: 1024,
            ..Config::default()
        },
    );
    let (s, r) = f
        .post(&reviewer_start(&f, "a", &["read_document"], 60_000))
        .await;
    assert_allow(s, &r);
    let hook = json!({"session_id":"host","hook_event_name":"PostToolUse",
        "tool_name":"mcp__documents__read_document","tool_response":"x".repeat(2048)});
    let (s, _) = post(f.state.clone(), "/hook", &hook, Some(HOOK_TOKEN)).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        f.state
            .firewall
            .lock()
            .unwrap()
            .provenance_incomplete("host"),
        "oversized hook lost without incomplete-history floor"
    );
}

#[tokio::test]
async fn reviewer_hook_extractor_must_return_explicit_enforce_disposition() {
    let f = Fixture::new(ALLOW);
    let (s, r) = f
        .post(&reviewer_start(&f, "a", &["read_document"], 60_000))
        .await;
    assert_allow(s, &r);
    let body = json!({"session_id":"host","hook_event_name":"PreToolUse",
        "tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/reviewer-no-execution"},
        "padding":"x".repeat(2*1024*1024)})
    .to_string();
    let response = app(f.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/hook")
                .header("authorization", format!("Bearer {HOOK_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "Axum extractor emitted accidental 413 instead of documented hook disposition"
    );
}

#[tokio::test]
async fn rereview_host_ask_must_survive_collector_merge() {
    let f = Fixture::new("agent_policies:\n  - name: shared-mcp-ask\n    when: { taint: [mcp], action_class: network }\n    action: ask\ndefault: allow\n");
    for (collector, tools) in [("a", vec!["read_document"]), ("b", vec!["send_email"])] {
        let (s, r) = f.post(&reviewer_start(&f, collector, &tools, 60_000)).await;
        assert_allow(s, &r);
    }
    let result = child_result(&f, "a", UNTRUSTED_TEXT).await;
    let (s, r) = f.post(&result).await;
    assert_allow(s, &r);
    let (s, r) = f
        .post(&f.call(
            "b",
            "send_email",
            &json!({"to":"review@allowed.test","text":UNTRUSTED_TEXT}),
        ))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["verdict"], "ask", "host Ask lost: {r}");
    assert_eq!(r["release"], false);
    assert!(r["call_id"].is_null());
}

#[tokio::test]
async fn rereview_host_incomplete_floor_must_block_collector_execution() {
    let f = Fixture::configured(
        ALLOW,
        Config {
            enforce: true,
            max_body_bytes: 1024,
            ..Config::default()
        },
    );
    let (s, r) = f
        .post(&reviewer_start(&f, "b", &["delete_document"], 60_000))
        .await;
    assert_allow(s, &r);
    let hook = json!({"session_id":"host","hook_event_name":"PostToolUse",
        "tool_name":"mcp__documents__read_document","tool_response":"x".repeat(2048)});
    let _ = post(f.state.clone(), "/hook", &hook, Some(HOOK_TOKEN)).await;
    assert!(f
        .state
        .firewall
        .lock()
        .unwrap()
        .provenance_incomplete("host"));
    let (s, r) = f.post(&f.call("b", "delete_document", &json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["verdict"], "ask", "host incomplete floor lost: {r}");
    assert_eq!(r["release"], false);
}

#[tokio::test]
async fn rereview_hook_reader_must_be_bounded_before_authentication() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let f = Fixture::configured(
        ALLOW,
        Config {
            enforce: true,
            max_body_bytes: 1024,
            ..Config::default()
        },
    );
    let pulled = Arc::new(AtomicUsize::new(0));
    let seen = pulled.clone();
    let chunks = futures_util::stream::iter((0..8).map(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        Ok::<_, std::io::Error>(vec![b'x'; 1024])
    }));
    let response = app(f.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/hook")
                .header("content-type", "application/json")
                .body(Body::from_stream(chunks))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        pulled.load(Ordering::SeqCst) <= 2,
        "unauthenticated reader consumed {} KiB despite a 1 KiB configured cap",
        pulled.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn rereview_oversized_pretooluse_must_return_explicit_refusal() {
    let f = Fixture::configured(
        ALLOW,
        Config {
            enforce: true,
            max_body_bytes: 1024,
            ..Config::default()
        },
    );
    let hook = json!({"session_id":"host","hook_event_name":"PreToolUse",
        "tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/reviewer-no-execution"},
        "padding":"x".repeat(2048)});
    let (s, r) = post(f.state.clone(), "/hook", &hook, Some(HOOK_TOKEN)).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        matches!(
            r["hookSpecificOutput"]["permissionDecision"].as_str(),
            Some("ask" | "deny")
        ),
        "protected enforce request received no explicit refusal: {r}"
    );
}

#[tokio::test]
async fn rereview_truncated_posttooluse_must_mark_incomplete_history() {
    let f = Fixture::configured(
        ALLOW,
        Config {
            enforce: true,
            max_record_bytes: 64,
            ..Config::default()
        },
    );
    let start = reviewer_start(&f, "documents", &["read_document"], 60_000);
    let (s, r) = f.post(&start).await;
    assert_allow(s, &r);
    let hook = json!({"session_id":"host","hook_event_name":"PostToolUse",
        "tool_name":"mcp__documents__read_document","tool_response":"x".repeat(2048)});
    post_with_proof(&f, &hook, start["child_authority"].as_str().unwrap()).await;
    assert_eq!(f.audit().last().unwrap()["truncated"], true);
    assert!(
        f.state
            .firewall
            .lock()
            .unwrap()
            .provenance_incomplete("host"),
        "PostToolUse was truncated but loss of history was not recorded"
    );
}

async fn review137_raw_hook(f: &Fixture, body: Body) -> (StatusCode, Value) {
    let response = app(f.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/hook")
                .header("authorization", format!("Bearer {HOOK_TOKEN}"))
                .header("content-type", "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn review137_late_fields_must_not_bypass_oversized_pretooluse_refusal() {
    let f = Fixture::configured(
        ALLOW,
        Config {
            enforce: true,
            max_body_bytes: 1024,
            ..Config::default()
        },
    );
    // JSON member order is immaterial; an ordinary unknown field precedes the event.
    let body = format!(
        "{{\"session_id\":\"host\",\"padding\":\"{}\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"rm -rf /tmp/reviewer-no-execution\"}}}}",
        "x".repeat(6000)
    );
    assert!(serde_json::from_str::<Value>(&body).is_ok());
    let (s, r) = review137_raw_hook(&f, Body::from(body)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        r["hookSpecificOutput"]["permissionDecision"], "deny",
        "valid protected oversized request got no enforce refusal when fields followed padding: {r}"
    );
}

#[tokio::test]
async fn review137_read_error_must_not_be_accepted_as_complete_history() {
    let f = Fixture::new(ALLOW);
    let (s, r) = f
        .post(&reviewer_start(&f, "a", &["read_document"], 60_000))
        .await;
    assert_allow(s, &r);
    let prefix = serde_json::to_vec(&json!({"session_id":"host","hook_event_name":"PostToolUse",
        "tool_name":"mcp__documents__read_document","tool_response":"benign prefix"}))
    .unwrap();
    let chunks = futures_util::stream::iter(vec![
        Ok(prefix),
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "owned synthetic transport error",
        )),
    ]);
    let _ = review137_raw_hook(&f, Body::from_stream(chunks)).await;
    assert!(
        f.state
            .firewall
            .lock()
            .unwrap()
            .provenance_incomplete("host"),
        "body transport failure was swallowed as successful EOF, history remains complete"
    );
}

#[tokio::test]
async fn review137_empty_session_must_not_bypass_protected_enforce_disposition() {
    let f = Fixture::new(ALLOW);
    let hook = json!({"session_id":"","hook_event_name":"PreToolUse","tool_name":"Bash",
        "tool_input":{"command":"rm -rf /tmp/reviewer-no-execution"}});
    let (s, r) = post(f.state.clone(), "/hook", &hook, Some(HOOK_TOKEN)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        r["hookSpecificOutput"]["permissionDecision"], "deny",
        "protected PreToolUse with invalid session silently allowed: {r}"
    );
}

#[tokio::test]
async fn review137_invalid_utf8_must_not_be_silently_repaired_before_inspection() {
    let f = Fixture::new(ALLOW);
    let mut body =
        b"{\"session_id\":\"host\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"printf ".to_vec();
    body.push(255);
    body.extend_from_slice(b"\"}}");
    assert!(std::str::from_utf8(&body).is_err());
    let (s, r) = review137_raw_hook(&f, Body::from(body)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        r["hookSpecificOutput"]["permissionDecision"], "deny",
        "malformed protected hook was silently transformed into valid input: {r}"
    );
}

#[tokio::test]
async fn reviewb2_nested_event_must_not_prove_oversized_pretooluse_safe() {
    let f = Fixture::configured(
        ALLOW,
        Config {
            enforce: true,
            max_body_bytes: 1024,
            ..Config::default()
        },
    );
    let body = format!("{{\"session_id\":\"host\",\"metadata\":{{\"hook_event_name\":\"PostToolUse\"}},\"padding\":\"{}\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"rm -rf /tmp/reviewer-no-execution\"}}}}", "x".repeat(6000));
    let complete: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(complete["hook_event_name"], "PreToolUse");
    let (s, r) = review137_raw_hook(&f, Body::from(body)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        r["hookSpecificOutput"]["permissionDecision"], "deny",
        "nested metadata was trusted as proof of a safe top-level event: {r}"
    );
}

#[tokio::test]
async fn reviewb2_nested_session_must_not_redirect_incomplete_host_history() {
    let f = Fixture::configured(
        ALLOW,
        Config {
            enforce: true,
            max_body_bytes: 1024,
            ..Config::default()
        },
    );
    let (s, r) = f
        .post(&reviewer_start(&f, "a", &["read_document"], 60_000))
        .await;
    assert_allow(s, &r);
    let body = format!("{{\"hook_event_name\":\"PostToolUse\",\"metadata\":{{\"session_id\":\"unrelated\"}},\"padding\":\"{}\",\"session_id\":\"host\",\"tool_name\":\"mcp__a__read_document\",\"tool_response\":\"discarded untrusted content\"}}", "x".repeat(6000));
    let complete: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(complete["session_id"], "host");
    let (s, _) = review137_raw_hook(&f, Body::from(body)).await;
    assert_eq!(s, StatusCode::OK);
    let fw = f.state.firewall.lock().unwrap();
    assert!(fw.provenance_incomplete("host"),
        "actual authenticated host stays complete while nested unrelated session is marked: unrelated={}",fw.provenance_incomplete("unrelated"));
}

#[tokio::test]
async fn reviewe358_duplicate_event_must_not_downgrade_to_no_opinion() {
    let f = Fixture::new(ALLOW);
    let body = r#"{"session_id":"host","hook_event_name":"PostToolUse","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/reviewer-no-execution"}}"#;
    assert!(serde_json::from_str::<agentfw::hook::HookPayload>(body).is_err());
    let scan = agentfw::handlers::RootJsonScan::scan(body);
    assert!(scan.duplicate_keys.contains("hook_event_name"));
    let (s, r) = review137_raw_hook(&f, Body::from(body)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        r["hookSpecificOutput"]["permissionDecision"], "deny",
        "scanner found ambiguity, but protected enforce request got no refusal: {r}"
    );
}

#[tokio::test]
async fn reviewe358_unseen_duplicate_must_not_make_partial_root_proven_safe() {
    let f = Fixture::configured(
        ALLOW,
        Config {
            enforce: true,
            max_body_bytes: 1024,
            ..Config::default()
        },
    );
    let body = format!("{{\"session_id\":\"host\",\"hook_event_name\":\"PostToolUse\",\"padding\":\"{}\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"rm -rf /tmp/reviewer-no-execution\"}}}}", "x".repeat(6000));
    assert!(serde_json::from_str::<agentfw::hook::HookPayload>(&body).is_err());
    let prefix = &body[..5120];
    let scan = agentfw::handlers::RootJsonScan::scan(prefix);
    assert!(!scan.closed_object);
    assert!(
        scan.is_proven_non_pre(),
        "witness must reach premature proof branch"
    );
    let (s, r) = review137_raw_hook(&f, Body::from(body)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        r["hookSpecificOutput"]["permissionDecision"], "deny",
        "unclosed root prefix was accepted as proof before duplicate tail: {r}"
    );
}

#[tokio::test]
async fn review2c_escaped_command_key_must_not_disable_malformed_refusal() {
    let f = Fixture::new(ALLOW);
    for key in [r#"command"#, r#"\u0063ommand"#] {
        let body=format!("{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{{\"{key}\":\"rm -rf /tmp/reviewer-no-execution\"}}}}");
        let decoded: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            decoded["tool_input"]["command"],
            "rm -rf /tmp/reviewer-no-execution"
        );
        assert!(
            serde_json::from_str::<agentfw::hook::HookPayload>(&body).is_err(),
            "session is deliberately missing"
        );
        let (s, r) = review137_raw_hook(&f, Body::from(body)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            r["hookSpecificOutput"]["permissionDecision"], "deny",
            "equivalent command-key spelling {key} bypassed protected refusal: {r}"
        );
    }
}

#[tokio::test]
async fn review2c_unclosed_session_prefix_must_not_skip_active_host_loss_floor() {
    let f = Fixture::configured(
        ALLOW,
        Config {
            enforce: true,
            max_body_bytes: 1024,
            ..Config::default()
        },
    );
    let (s, r) = f
        .post(&reviewer_start(&f, "b", &["delete_document"], 60_000))
        .await;
    assert_allow(s, &r);
    let body=format!("{{\"session_id\":\"unrelated\",\"hook_event_name\":\"PostToolUse\",\"padding\":\"{}\",\"session_id\":\"host\",\"tool_name\":\"mcp__a__read_document\",\"tool_response\":\"discarded untrusted content\"}}","x".repeat(6000));
    assert!(
        serde_json::from_str::<agentfw::hook::HookPayload>(&body).is_err(),
        "duplicate root session is deliberately ambiguous"
    );
    let (s, _) = review137_raw_hook(&f, Body::from(body)).await;
    assert_eq!(s, StatusCode::OK);
    let (host_incomplete, unrelated_incomplete) = {
        let fw = f.state.firewall.lock().unwrap();
        (
            fw.provenance_incomplete("host"),
            fw.provenance_incomplete("unrelated"),
        )
    };
    let (s, r) = f.post(&f.call("b", "delete_document", &json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["verdict"],"ask",
        "incomplete prefix directed loss marker away from possibly affected active host: host={host_incomplete}, unrelated={unrelated_incomplete}; call={r}");
    assert_eq!(r["release"], false);
}

#[tokio::test]
async fn reviewcec_incomplete_tool_identity_must_not_make_known_pretooluse_safe() {
    let f = Fixture::new(ALLOW);
    let body = r#"{"session_id":"host","hook_event_name":"PreToolUse","tool_name":"Ba"#;
    let scan = agentfw::handlers::RootJsonScan::scan(body);
    assert_eq!(scan.get_root_string("hook_event_name"), Some("PreToolUse"));
    assert!(scan.incomplete_keys.contains("tool_name"));
    let (s, r) = review137_raw_hook(&f, Body::from(body)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        r["hookSpecificOutput"]["permissionDecision"], "deny",
        "known enforce PreToolUse became no-opinion because tool identity was truncated: {r}"
    );
}

#[tokio::test]
async fn reviewe311_unsupported_pretooluse_shapes_must_not_be_no_opinion() {
    let f = Fixture::new(ALLOW);
    let command = json!({"command":"rm -rf /tmp/reviewer-no-execution"});
    let cases = [
        (
            "missing_tool",
            json!({"session_id":"host","hook_event_name":"PreToolUse","tool_input":command}),
        ),
        (
            "null_tool",
            json!({"session_id":"host","hook_event_name":"PreToolUse","tool_name":null,"tool_input":command}),
        ),
        (
            "empty_tool",
            json!({"session_id":"host","hook_event_name":"PreToolUse","tool_name":"","tool_input":command}),
        ),
        (
            "missing_bash_input",
            json!({"session_id":"host","hook_event_name":"PreToolUse","tool_name":"Bash"}),
        ),
        (
            "missing_bash_command",
            json!({"session_id":"host","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{}}),
        ),
        (
            "nonstring_bash_command",
            json!({"session_id":"host","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":42}}),
        ),
    ];
    let mut gaps = Vec::new();
    for (name, body) in cases {
        let (s, r) = post(f.state.clone(), "/hook", &body, Some(HOOK_TOKEN)).await;
        eprintln!("{name}: status={s} response={r}");
        if !matches!(
            r["hookSpecificOutput"]["permissionDecision"].as_str(),
            Some("deny" | "ask")
        ) {
            gaps.push(name);
        }
    }
    assert!(gaps.is_empty(),"authenticated enforce PreToolUse with invalid/missing identity or unsupported Bash args returned no opinion: {gaps:?}");
}

#[tokio::test]
async fn review65_shadow_unsupported_shapes_stay_nonblocking_without_sequence_allocation() {
    let f = Fixture::configured(
        ALLOW,
        Config {
            enforce: false,
            ..Config::default()
        },
    );
    let cases = [
        json!({"session_id":"host","hook_event_name":"PreToolUse","tool_input":{"command":"synthetic"}}),
        json!({"session_id":"host","hook_event_name":"PreToolUse","tool_name":null}),
        json!({"session_id":"host","hook_event_name":"PreToolUse","tool_name":""}),
        json!({"session_id":"host","hook_event_name":"PreToolUse","tool_name":"Bash"}),
        json!({"session_id":"host","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{}}),
        json!({"session_id":"host","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":42}}),
    ];
    for body in cases {
        let (s, r) = post(f.state.clone(), "/hook", &body, Some(HOOK_TOKEN)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(r, json!({}));
    }
    assert_eq!(f.state.sessions.next("host"), 1);
}

#[tokio::test]
async fn review65_supported_benign_read_and_bash_remain_usable() {
    let f = Fixture::new(ALLOW);
    for (tool, args) in [
        ("Read", json!({"file_path":"/tmp/reviewer-example.txt"})),
        ("Bash", json!({"command":"printf hello"})),
    ] {
        let body = json!({"session_id":"host","hook_event_name":"PreToolUse","tool_name":tool,"tool_input":args});
        let (s, r) = post(f.state.clone(), "/hook", &body, Some(HOOK_TOKEN)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(r, json!({}), "valid benign {tool} should remain allowed");
    }
}
