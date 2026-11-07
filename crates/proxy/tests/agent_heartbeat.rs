// SPDX-License-Identifier: Apache-2.0
//! Opt-in Agent heartbeat over HTTP (SQLite): registration, replay and
//! out-of-order refusal, credential rotation and revocation, tenant scope,
//! Console restart and the admin status read. The real dual-store witness
//! with agentfw is scripts/console-agent-heartbeat-acceptance.py.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use llm_firewall::{
    app,
    handlers::AppState,
    tenant_store::{AdminRole, RotationRequest, TenantStore},
    test_config,
};
use serde_json::{json, Value};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;

fn state(store: TenantStore) -> Arc<AppState> {
    let mut config = test_config("http://127.0.0.1:1".into());
    config.tenant_store.enabled = true;
    Arc::new(AppState {
        firewall: Firewall::new(
            vec![Box::new(InjectionDetector::new())],
            PolicySet::from_yaml("default: allow").unwrap(),
        ),
        http: reqwest::Client::new(),
        openai_api_key: None,
        proxy_auth_token: None,
        tenant_store: Some(store),
        admin_token: Some("admin-test-token".into()),
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
        config: {
            let mut c = config;
            c.spend_limit.model_prices = BTreeMap::new();
            c
        },
    })
}

async fn get(
    router: axum::Router,
    path: &str,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut r = Request::get(path);
    if let Some(token) = token {
        r = r.header("x-llm-firewall-admin-token", format!("Bearer {token}"));
    }
    let response = router
        .oneshot(r.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let code = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (
        code,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn post(
    state: &Arc<AppState>,
    path: &str,
    bearer: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut r = Request::post(path).header("content-type", "application/json");
    if let Some(token) = bearer {
        r = r.header("authorization", format!("Bearer {token}"));
    }
    let response = app(state.clone())
        .oneshot(r.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let code = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}
const INSTANCE: &str = "0123456789abcdef0123456789abcdef";
fn registration(tenant: &str, agent: &str, generation: i64, instance: &str) -> Value {
    json!({"contract_version": "sw-agent-heartbeat/1", "tenant_id": tenant, "agent_id": agent,
           "credential_generation": generation, "instance_id": instance})
}
fn beat(
    tenant: &str,
    agent: &str,
    generation: i64,
    instance: &str,
    registration: &str,
    sequence: i64,
) -> Value {
    json!({"contract_version": "sw-agent-heartbeat/1", "tenant_id": tenant, "agent_id": agent,
           "credential_generation": generation, "instance_id": instance, "registration_id": registration,
           "sequence": sequence, "observed_policy": {"deployment_sequence": 1, "revision": "r1", "policy_sha256": "a".repeat(64)}})
}
async fn status(
    state: &Arc<AppState>,
    tenant: &str,
    agent: &str,
    token: &str,
) -> (StatusCode, Value) {
    get(
        app(state.clone()),
        &format!("/admin/v1/tenants/{tenant}/agent-fleet/{agent}/heartbeat"),
        Some(token),
    )
    .await
}
const REG: &str = "/agent/v1/heartbeat/registrations";
const BEAT: &str = "/agent/v1/heartbeats";

#[tokio::test]
async fn heartbeat_contract_freshness_and_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("console.sqlite");
    let db = TenantStore::open(path.to_str().unwrap()).unwrap();
    let t = db.create_tenant("heartbeat").unwrap().id;
    let other = db.create_tenant("heartbeat-other").unwrap().id;
    let agent = db.enroll_managed_agent(&t, "edge").unwrap().token;
    let unopted = db.enroll_managed_agent(&t, "legacy").unwrap();
    let foreign = db.enroll_managed_agent(&other, "edge").unwrap().token;
    let viewer = db
        .create_admin("hb-viewer", AdminRole::Viewer)
        .unwrap()
        .token;
    let st = state(db);

    // Existing Agents without the capability stay unknown/unsupported.
    let (code, s) = status(&st, &t, "legacy", &viewer).await;
    assert_eq!(
        (code, s["status"].as_str()),
        (StatusCode::OK, Some("unsupported"))
    );
    assert!(s["reported"].is_null() && !unopted.token.is_empty());

    // Authentication, identity and shape.
    assert_eq!(
        post(&st, REG, None, registration(&t, "edge", 1, INSTANCE))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(
            &st,
            REG,
            Some("admin-test-token"),
            registration(&t, "edge", 1, INSTANCE)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (code, body) = post(
        &st,
        REG,
        Some(&foreign),
        registration(&t, "edge", 1, INSTANCE),
    )
    .await;
    assert_eq!(
        (code, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("wrong_agent"))
    );
    let (code, body) = post(
        &st,
        REG,
        Some(&agent),
        registration(&t, "edge", 2, INSTANCE),
    )
    .await;
    assert_eq!(
        (code, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("epoch_mismatch"))
    );
    let mut extra = registration(&t, "edge", 1, INSTANCE);
    extra["prompt"] = json!("never accepted");
    assert_eq!(
        post(&st, REG, Some(&agent), extra).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(&st, REG, Some(&agent), registration(&t, "edge", 1, "XYZ"))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut big = registration(&t, "edge", 1, INSTANCE);
    big["pad"] = json!("x".repeat(4096));
    assert_eq!(
        post(&st, REG, Some(&agent), big).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // Not registered yet.
    let (code, body) = post(
        &st,
        BEAT,
        Some(&agent),
        beat(&t, "edge", 1, INSTANCE, &"0".repeat(32), 1),
    )
    .await;
    assert_eq!(
        (code, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("not_registered"))
    );

    let (code, reg) = post(
        &st,
        REG,
        Some(&agent),
        registration(&t, "edge", 1, INSTANCE),
    )
    .await;
    assert_eq!(code, StatusCode::CREATED);
    assert_eq!(
        (
            reg["expires_after_seconds"].as_i64(),
            reg["credential_generation"].as_i64()
        ),
        (Some(90), Some(1))
    );
    let id = reg["registration_id"].as_str().unwrap().to_owned();
    assert_eq!(
        status(&st, &t, "edge", &viewer).await.1["status"],
        "registered_no_report"
    );
    assert_eq!(
        post(
            &st,
            BEAT,
            Some(&agent),
            beat(&t, "edge", 1, INSTANCE, &id, 3)
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let s = status(&st, &t, "edge", &viewer).await.1;
    assert_eq!(s["status"], "fresh");
    assert_eq!(s["reported"]["sequence"], 3);
    assert_eq!(s["reported"]["observed_policy"]["revision"], "r1");
    assert!(s["note"]
        .as_str()
        .unwrap()
        .contains("not runtime attestation"));
    // Replay and out-of-order sequences.
    for seq in [3, 2] {
        let (code, body) = post(
            &st,
            BEAT,
            Some(&agent),
            beat(&t, "edge", 1, INSTANCE, &id, seq),
        )
        .await;
        assert_eq!(
            (code, body["error"].as_str()),
            (StatusCode::CONFLICT, Some("sequence_replay"))
        );
    }
    // Faster than the minimum interval.
    let (code, body) = post(
        &st,
        BEAT,
        Some(&agent),
        beat(&t, "edge", 1, INSTANCE, &id, 4),
    )
    .await;
    assert_eq!(
        (code, body["error"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("too_frequent"))
    );
    // A forged registration ID and another instance are superseded.
    let (code, body) = post(
        &st,
        BEAT,
        Some(&agent),
        beat(&t, "edge", 1, INSTANCE, &"f".repeat(32), 9),
    )
    .await;
    assert_eq!(
        (code, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("registration_superseded"))
    );
    // A restarted process registers again; the old registration is superseded
    // and cannot be revived by replaying its requests.
    let restarted = "fedcba9876543210fedcba9876543210";
    let (_, again) = post(
        &st,
        REG,
        Some(&agent),
        registration(&t, "edge", 1, restarted),
    )
    .await;
    let new_id = again["registration_id"].as_str().unwrap().to_owned();
    assert_ne!(new_id, id);
    assert_eq!(
        status(&st, &t, "edge", &viewer).await.1["status"],
        "registered_no_report"
    );
    let (code, body) = post(
        &st,
        BEAT,
        Some(&agent),
        beat(&t, "edge", 1, INSTANCE, &id, 10),
    )
    .await;
    assert_eq!(
        (code, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("registration_superseded"))
    );
    assert_eq!(
        post(
            &st,
            BEAT,
            Some(&agent),
            beat(&t, "edge", 1, restarted, &new_id, 1)
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );

    // Rotation: the old credential stops; the new one must register under the
    // new generation; the earlier report no longer counts.
    let replacement = format!("sw_agent_{}", "R".repeat(43));
    st.tenant_store
        .as_ref()
        .unwrap()
        .rotate_managed_agent(
            &t,
            "edge",
            &RotationRequest {
                expected_generation: 1,
                operation_id: "0".repeat(32),
                replacement_token: replacement.clone(),
            },
        )
        .unwrap();
    assert_eq!(
        status(&st, &t, "edge", &viewer).await.1["status"],
        "credential_changed"
    );
    assert_eq!(
        post(
            &st,
            BEAT,
            Some(&agent),
            beat(&t, "edge", 1, restarted, &new_id, 2)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (code, body) = post(
        &st,
        BEAT,
        Some(&replacement),
        beat(&t, "edge", 1, restarted, &new_id, 2),
    )
    .await;
    assert_eq!(
        (code, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("epoch_mismatch"))
    );
    let (code, body) = post(
        &st,
        BEAT,
        Some(&replacement),
        beat(&t, "edge", 2, restarted, &new_id, 2),
    )
    .await;
    assert_eq!(
        (code, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("registration_superseded"))
    );
    let (_, rotated) = post(
        &st,
        REG,
        Some(&replacement),
        registration(&t, "edge", 2, restarted),
    )
    .await;
    let rotated_id = rotated["registration_id"].as_str().unwrap().to_owned();
    assert_eq!(
        post(
            &st,
            BEAT,
            Some(&replacement),
            beat(&t, "edge", 2, restarted, &rotated_id, 1)
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(status(&st, &t, "edge", &viewer).await.1["status"], "fresh");

    // Admin read scope.
    assert_eq!(
        status(&st, &other, "legacy", &viewer).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(
            app(st.clone()),
            &format!("/admin/v1/tenants/{t}/agent-fleet/edge/heartbeat"),
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (_, foreign_view) = status(&st, &other, "edge", &viewer).await;
    assert_eq!(foreign_view["status"], "unsupported");

    // Revocation stops everything and is shown as such.
    st.tenant_store
        .as_ref()
        .unwrap()
        .revoke_managed_agent(&t, "edge")
        .unwrap();
    assert_eq!(
        status(&st, &t, "edge", &viewer).await.1["status"],
        "revoked"
    );
    assert_eq!(
        post(
            &st,
            REG,
            Some(&replacement),
            registration(&t, "edge", 2, restarted)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn sqlite_console_restart_forgets_observations_and_refuses_old_registrations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("console.sqlite");
    let (t, agent, viewer, id) = {
        let db = TenantStore::open(path.to_str().unwrap()).unwrap();
        let t = db.create_tenant("restart").unwrap().id;
        let agent = db.enroll_managed_agent(&t, "edge").unwrap().token;
        let viewer = db
            .create_admin("restart-viewer", AdminRole::Viewer)
            .unwrap()
            .token;
        let st = state(db);
        let (_, reg) = post(
            &st,
            REG,
            Some(&agent),
            registration(&t, "edge", 1, INSTANCE),
        )
        .await;
        let id = reg["registration_id"].as_str().unwrap().to_owned();
        assert_eq!(
            post(
                &st,
                BEAT,
                Some(&agent),
                beat(&t, "edge", 1, INSTANCE, &id, 1)
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(status(&st, &t, "edge", &viewer).await.1["status"], "fresh");
        (t, agent, viewer, id)
    };
    let st = state(TenantStore::open(path.to_str().unwrap()).unwrap());
    assert_eq!(
        status(&st, &t, "edge", &viewer).await.1["status"],
        "unsupported"
    );
    let (code, body) = post(
        &st,
        BEAT,
        Some(&agent),
        beat(&t, "edge", 1, INSTANCE, &id, 2),
    )
    .await;
    assert_eq!(
        (code, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("not_registered"))
    );
}
