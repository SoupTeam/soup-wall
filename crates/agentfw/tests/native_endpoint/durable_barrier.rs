// SPDX-License-Identifier: Apache-2.0

use super::*;

fn sou78_durable_state(dir: &Path) -> agentfw::Shared {
    let bytes = serde_json::to_vec(&registry()).unwrap();
    let mut state = Arc::try_unwrap(make_state(
        dir,
        Config {
            enforce: true,
            ..Config::default()
        },
        ALLOW,
        &bytes,
        &sha256_hex(&bytes),
    ))
    .unwrap_or_else(|_| panic!("fixture state was shared"));
    let native = state.native.take().unwrap();
    state.native = Some(
        native
            .with_continuity(dir, state.firewall.get_mut().unwrap())
            .unwrap(),
    );
    Arc::new(state)
}

#[tokio::test]
async fn sou78_barrier_commits_before_response_and_restart_preserves_hook_risk() {
    let dir = tempfile::tempdir().unwrap();
    let state = sou78_durable_state(dir.path());
    let hook = json!({"hook_event_name":"PostToolUse","session_id":"profile-host", "tool_name":"WebFetch",
        "tool_input":{"url":"https://untrusted.example.test/inventory"},"tool_response":UNTRUSTED_TEXT});
    assert_eq!(
        post(state.clone(), "/hook", &hook, Some(HOOK_TOKEN))
            .await
            .0,
        StatusCode::OK
    );
    let taint = state.firewall.lock().unwrap().taint_len("profile-host");
    assert!(taint > 0);
    let response = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(agentfw::native::continuity::BARRIER)
                .header("authorization", format!("Bearer {NATIVE_TOKEN}"))
                .header("x-agentfw-host-session", "profile-host")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let root = dir.path().join("mcp-profiles");
    assert!(root.join("risk-checkpoint.json").is_file());
    assert!(!root.join("risk-inflight.json").exists());
    let checkpoint: Value =
        serde_json::from_slice(&std::fs::read(root.join("risk-checkpoint.json")).unwrap()).unwrap();
    assert_eq!(checkpoint["scoped_hosts"], json!(["profile-host"]));
    let replacement = sou78_durable_state(dir.path());
    assert_eq!(
        replacement
            .firewall
            .lock()
            .unwrap()
            .taint_len("profile-host"),
        taint
    );
    assert!(!replacement
        .firewall
        .lock()
        .unwrap()
        .provenance_incomplete("future-host"));
    assert_ne!(
        state.native.as_ref().unwrap().instance_id(),
        replacement.native.as_ref().unwrap().instance_id()
    );
    // An unauthenticated lifecycle claim cannot launder a restored scoped host.
    post(
        replacement.clone(),
        "/hook",
        &json!({"hook_event_name":"SessionEnd","session_id":"profile-host"}),
        Some(HOOK_TOKEN),
    )
    .await;
    assert_eq!(
        replacement
            .firewall
            .lock()
            .unwrap()
            .taint_len("profile-host"),
        taint
    );
    assert!(replacement
        .firewall
        .lock()
        .unwrap()
        .provenance_incomplete("profile-host"));
}

#[tokio::test]
async fn sou78_barrier_authentication_precedes_body_and_checkpoint_allocation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let state = sou78_durable_state(dir.path());
    for auth in ["Bearer invalid".to_string(), format!("Bearer {HOOK_TOKEN}")] {
        let reads = Arc::new(AtomicUsize::new(0));
        let count = reads.clone();
        let stream = futures_util::stream::once(async move {
            count.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"not JSON"))
        });
        let response = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(agentfw::native::continuity::BARRIER)
                    .header("authorization", auth)
                    .header("x-agentfw-host-session", "host")
                    .body(Body::from_stream(stream))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert!(!dir.path().join("mcp-profiles").exists());
    }
}

#[tokio::test]
async fn sou78_persistence_failure_returns_documented_hook_deny_before_execution() {
    let dir = tempfile::tempdir().unwrap();
    let state = sou78_durable_state(dir.path());
    let response = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(agentfw::native::continuity::BARRIER)
                .header("authorization", format!("Bearer {NATIVE_TOKEN}"))
                .header("x-agentfw-host-session", "host")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    std::fs::create_dir(dir.path().join("mcp-profiles/risk-inflight.json")).unwrap();
    let (status, reply) = post(
        state.clone(),
        "/hook",
        &json!({"hook_event_name":"PreToolUse",
        "session_id":"other","tool_name":"Bash","tool_input":{"command":"rm -rf /owned-fixture"}}),
        Some(HOOK_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        state.firewall.lock().unwrap().agent_tools("other", "main"),
        None
    );
}

#[tokio::test]
async fn sou78_activation_retires_unversioned_launchers_and_persists_required_authority() {
    let dir = tempfile::tempdir().unwrap();
    let state = sou78_durable_state(dir.path());
    let event = json!({"contract_version":CONTRACT,"registry_sha256":sha256_hex(&serde_json::to_vec(&registry()).unwrap()),
        "session_id":"before-activation","event":"session_start"});
    let (status, reply) = post(state.clone(), "/native/v1", &event, Some(NATIVE_TOKEN)).await;
    assert_allow(status, &reply);
    let response = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(agentfw::native::continuity::BARRIER)
                .header("authorization", format!("Bearer {NATIVE_TOKEN}"))
                .header("x-agentfw-host-session", "profile-host")
                .header("x-agentfw-profile-activation", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    for current in [state, sou78_durable_state(dir.path())] {
        let (_, reply) = post(current, "/native/v1", &event, Some(NATIVE_TOKEN)).await;
        assert_eq!(reply["release"], false);
        assert_eq!(reply["error_code"], "native_profile_authority_required");
    }
}

#[tokio::test]
async fn sou78_pending_connection_refuses_native_calls_before_body_or_state_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let state = sou78_durable_state(dir.path());
    let root = dir.path().join("mcp-profiles");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("connection-transition.json"), b"owned-operation").unwrap();
    let response = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/native/v1")
                .header("authorization", format!("Bearer {NATIVE_TOKEN}"))
                .body(Body::from_stream(futures_util::stream::pending::<
                    Result<axum::body::Bytes, std::io::Error>,
                >()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["error_code"],
        "native_profile_transition_pending"
    );
    assert!(!root.join("risk-inflight.json").exists());
    assert!(!root.join("risk-checkpoint.json").exists());
}
