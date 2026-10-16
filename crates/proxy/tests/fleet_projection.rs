// SPDX-License-Identifier: Apache-2.0
//! Fleet projection regressions; the real dual-store/browser witness is separate.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use llm_firewall::{
    app,
    handlers::AppState,
    tenant_store::{fleet::FleetQuery, AdminRole, AppliedReport, ManagedIssuer, TenantStore},
    test_config,
};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;
fn tenant_state(base: String) -> Arc<AppState> {
    let mut config = test_config(base);
    config.tenant_store.enabled = true;
    config.spend_limit.model_prices = BTreeMap::from([(
        "gpt-test".into(),
        llm_firewall::config::ModelPrice {
            input_usd_micros_per_million: 1_000_000,
            output_usd_micros_per_million: 1_000_000,
        },
    )]);
    Arc::new(AppState {
        firewall: Firewall::new(
            vec![Box::new(InjectionDetector::new())],
            PolicySet::from_yaml("default: allow").unwrap(),
        ),
        http: reqwest::Client::new(),
        openai_api_key: None,
        proxy_auth_token: None,
        tenant_store: Some(TenantStore::open(":memory:").unwrap()),
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
        config,
    })
}

async fn read(
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
#[tokio::test]
async fn fleet_http_auth_scope_and_bounded_queries() {
    let state = tenant_state("http://127.0.0.1:1".into());
    let db = state.tenant_store.as_ref().unwrap();
    let a = db.create_tenant("fleet-a").unwrap();
    let b = db.create_tenant("fleet-b").unwrap();
    let agent = db.enroll_managed_agent(&a.id, "only-a").unwrap();
    let viewer = db.create_admin("fleet-viewer", AdminRole::Viewer).unwrap();
    let base = format!("/admin/v1/tenants/{}/agent-fleet", a.id);
    for credential in [None, Some("invalid"), Some(agent.token.as_str())] {
        assert_eq!(
            read(app(state.clone()), &base, credential).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let (code, body) = read(app(state.clone()), &base, Some(&viewer.token)).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["agents"][0]["agent_id"], "only-a");
    assert_eq!(body["agents"][0]["runtime_coverage"], "unknown");
    let text = body.to_string();
    for forbidden in [
        "token_hash",
        "policy_yaml",
        "bundle_json",
        "signature_hex",
        &agent.token,
    ] {
        assert!(!text.contains(forbidden));
    }
    let other = format!("/admin/v1/tenants/{}/agent-fleet/only-a", b.id);
    assert_eq!(
        read(app(state.clone()), &other, Some(&viewer.token))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    for suffix in [
        "?limit=0",
        "?limit=101",
        "?after=../x",
        "?enrollment=bogus",
        "?delivery=bogus",
        "?before_sequence=2",
        "?extra=x",
    ] {
        assert_eq!(
            read(
                app(state.clone()),
                &format!("{base}{suffix}"),
                Some(&viewer.token)
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let response = app(state.clone())
        .oneshot(
            Request::post(format!("/admin/v1/tenants/{}/agents", a.id))
                .header(
                    "x-llm-firewall-admin-token",
                    format!("Bearer {}", viewer.token),
                )
                .header("content-type", "application/json")
                .body(Body::from(r#"{"agent_id":"forbidden"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
#[tokio::test]
async fn fleet_empty_database_read_does_not_create_managed_tables() {
    let db = TenantStore::open(":memory:").unwrap();
    let t = db.create_tenant("empty-fleet").unwrap();
    let p = db
        .fleet_page(&t.id, FleetQuery::default())
        .await
        .unwrap()
        .unwrap();
    assert!(p.agents.is_empty());
    assert!(db
        .fleet_detail(&t.id, "absent", FleetQuery::default())
        .await
        .unwrap()
        .is_none());
    assert!(db
        .fleet_page("unknown", FleetQuery::default())
        .await
        .unwrap()
        .is_none());
}
#[tokio::test]
async fn fleet_keyset_filters_and_revoked_without_history() {
    let db = TenantStore::open(":memory:").unwrap();
    let t = db.create_tenant("paged-fleet").unwrap();
    for id in ["z", "A", "a_1", "a_2"] {
        db.enroll_managed_agent(&t.id, id).unwrap();
    }
    db.revoke_managed_agent(&t.id, "a_2").unwrap();
    let mut q = FleetQuery {
        limit: 2,
        ..Default::default()
    };
    let a = db.fleet_page(&t.id, q.clone()).await.unwrap().unwrap();
    assert_eq!(
        a.agents
            .iter()
            .map(|a| a.agent_id.as_str())
            .collect::<Vec<_>>(),
        vec!["A", "a_1"]
    );
    q.after = a.next_after.unwrap();
    let b = db.fleet_page(&t.id, q).await.unwrap().unwrap();
    assert_eq!(
        b.agents
            .iter()
            .map(|a| a.agent_id.as_str())
            .collect::<Vec<_>>(),
        vec!["a_2", "z"]
    );
    assert!(b.next_after.is_none());
    let q = FleetQuery {
        prefix: "a_".into(),
        enrollment: "revoked".into(),
        delivery: "no_history".into(),
        ..Default::default()
    };
    let p = db.fleet_page(&t.id, q).await.unwrap().unwrap();
    assert_eq!(p.agents.len(), 1);
    assert_eq!(p.agents[0].agent_id, "a_2");
    assert!(p.agents[0].latest_issued.is_none());
}
#[tokio::test]
async fn fleet_last_applied_survives_newer_pending_rejected_and_history_paging() {
    let db = TenantStore::open(":memory:").unwrap();
    let t = db.create_tenant("history-fleet").unwrap();
    db.enroll_managed_agent(&t.id, "agent").unwrap();
    let seed = (0..32)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect::<String>();
    let issuer = ManagedIssuer::new("fixture".into(), &seed).unwrap();
    db.create_managed_revision(&t.id, "agent", "r1", "default: deny")
        .unwrap();
    db.approve_managed_revision(&t.id, "agent", "r1").unwrap();
    let first = db
        .deploy_managed_revision(&t.id, "agent", "r1", false, &issuer)
        .unwrap();
    assert!(db
        .acknowledge_managed_bundle(
            &t.id,
            "agent",
            &AppliedReport {
                deployment_sequence: first.deployment_sequence,
                revision: first.revision,
                policy_sha256: first.policy_sha256,
                status: "applied".into()
            }
        )
        .unwrap());
    let second = db
        .deploy_managed_revision(&t.id, "agent", "r1", false, &issuer)
        .unwrap();
    assert!(db
        .acknowledge_managed_bundle(
            &t.id,
            "agent",
            &AppliedReport {
                deployment_sequence: second.deployment_sequence,
                revision: second.revision,
                policy_sha256: second.policy_sha256,
                status: "rejected".into()
            }
        )
        .unwrap());
    let d = db
        .fleet_detail(&t.id, "agent", FleetQuery::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d.agent.latest_issued.unwrap().recorded_state, "rejected");
    assert_eq!(d.agent.last_reported_applied.unwrap().sequence, "1");
    for _ in 0..55 {
        db.deploy_managed_revision(&t.id, "agent", "r1", false, &issuer)
            .unwrap();
    }
    let d = db
        .fleet_detail(
            &t.id,
            "agent",
            FleetQuery {
                limit: 2,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d.agent.latest_issued.unwrap().sequence, "57");
    assert_eq!(d.agent.last_reported_applied.unwrap().sequence, "1");
    assert_eq!(d.next_before_sequence, Some("56".into()));
    let d = db
        .fleet_detail(
            &t.id,
            "agent",
            FleetQuery {
                limit: 2,
                before_sequence: Some(56),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d.deployments[0].sequence, "55");
    assert_eq!(d.agent.last_reported_applied.unwrap().sequence, "1");
}
