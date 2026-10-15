// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Integration tests for SOU-47: Managed Agent Group Staged Policy Rollout
//! (pilot / canary group first, verification, and automated rollback on failure).

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use llm_firewall::handlers::AppState;
use llm_firewall::tenant_store::TenantStore;
use llm_firewall::{app, test_config};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
use tower::ServiceExt;

const OWNER_HEADER: &str = "Bearer admin-test-token";
const TEST_KEY_ID: &str = "group-rollout-key";
const TEST_SEED_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn test_state() -> Arc<AppState> {
    std::env::set_var("SOUP_AGENT_POLICY_KEY_ID", TEST_KEY_ID);
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", TEST_SEED_HEX);

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
        tenant_store: Some(
            TenantStore::open(":memory:")
                .unwrap()
                .with_webhook_signing_key_base64url(&URL_SAFE_NO_PAD.encode([6_u8; 32]))
                .unwrap(),
        ),
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

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let status = response.status();
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    assert!(
        status.is_success(),
        "unexpected status {status}: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn test_managed_group_crud_and_membership() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Group Test Tenant").unwrap();

    // 1. Create group
    let create_resp = app(state.clone())
        .oneshot(
            Request::post(format!("/admin/v1/tenants/{}/groups", tenant.id))
                .header("content-type", "application/json")
                .header("x-llm-firewall-admin-token", OWNER_HEADER)
                .body(axum::body::Body::from(
                    r#"{"group_id":"cluster-a","name":"Cluster A"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let group = json_body(create_resp).await;
    assert_eq!(group["group_id"], "cluster-a");
    assert_eq!(group["name"], "Cluster A");

    // 2. List groups
    let list_resp = app(state.clone())
        .oneshot(
            Request::get(format!("/admin/v1/tenants/{}/groups", tenant.id))
                .header("x-llm-firewall-admin-token", OWNER_HEADER)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let groups = json_body(list_resp).await;
    assert_eq!(groups.as_array().unwrap().len(), 1);

    // 3. Get group
    let get_resp = app(state.clone())
        .oneshot(
            Request::get(format!("/admin/v1/tenants/{}/groups/cluster-a", tenant.id))
                .header("x-llm-firewall-admin-token", OWNER_HEADER)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);

    // 4. Enroll 2 agents
    store.enroll_managed_agent(&tenant.id, "agent-1").unwrap();
    store.enroll_managed_agent(&tenant.id, "agent-2").unwrap();

    // 5. Add members
    let add_m1 = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/cluster-a/members",
                tenant.id
            ))
            .header("content-type", "application/json")
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::from(
                r#"{"agent_id":"agent-1","is_pilot":true}"#,
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(add_m1.status(), StatusCode::CREATED);
    let m1 = json_body(add_m1).await;
    assert_eq!(m1["is_pilot"], true);

    let add_m2 = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/cluster-a/members",
                tenant.id
            ))
            .header("content-type", "application/json")
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::from(
                r#"{"agent_id":"agent-2","is_pilot":false}"#,
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(add_m2.status(), StatusCode::CREATED);

    // 6. List members
    let members_resp = app(state.clone())
        .oneshot(
            Request::get(format!(
                "/admin/v1/tenants/{}/groups/cluster-a/members",
                tenant.id
            ))
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(members_resp.status(), StatusCode::OK);
    let members = json_body(members_resp).await;
    assert_eq!(members.as_array().unwrap().len(), 2);

    // 7. Remove member
    let rem_resp = app(state.clone())
        .oneshot(
            Request::delete(format!(
                "/admin/v1/tenants/{}/groups/cluster-a/members/agent-2",
                tenant.id
            ))
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rem_resp.status(), StatusCode::NO_CONTENT);

    // 8. Delete group
    let del_resp = app(state.clone())
        .oneshot(
            Request::delete(format!("/admin/v1/tenants/{}/groups/cluster-a", tenant.id))
                .header("x-llm-firewall-admin-token", OWNER_HEADER)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_staged_group_rollout_full_canary_success() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Rollout Canary Tenant").unwrap();

    // Create group
    store
        .create_managed_group(&tenant.id, "canary-grp", "Canary Group")
        .unwrap();

    // Enroll 1 pilot and 2 standard workers
    let cred_pilot = store
        .enroll_managed_agent(&tenant.id, "pilot-node")
        .unwrap();
    let cred_worker1 = store
        .enroll_managed_agent(&tenant.id, "worker-node-1")
        .unwrap();
    let cred_worker2 = store
        .enroll_managed_agent(&tenant.id, "worker-node-2")
        .unwrap();

    store
        .add_managed_group_member(&tenant.id, "canary-grp", "pilot-node", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "canary-grp", "worker-node-1", false)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "canary-grp", "worker-node-2", false)
        .unwrap();

    // Create and approve revision rev-1
    let rev_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/canary-grp/revisions",
                tenant.id
            ))
            .header("content-type", "application/json")
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::from(
                r#"{"revision":"rev-1","policy_yaml":"default: allow\n"}"#,
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rev_resp.status(), StatusCode::CREATED);

    let app_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/canary-grp/revisions/rev-1/approve",
                tenant.id
            ))
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(app_resp.status(), StatusCode::NO_CONTENT);

    // Start rollout
    let start_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/canary-grp/rollout",
                tenant.id
            ))
            .header("content-type", "application/json")
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::from(r#"{"revision":"rev-1"}"#))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_resp.status(), StatusCode::CREATED);
    let rollout = json_body(start_resp).await;
    assert_eq!(rollout["phase"], "pilot");

    // Attempting to start another rollout while one is active returns 409 Conflict
    let conflict_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/canary-grp/rollout",
                tenant.id
            ))
            .header("content-type", "application/json")
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::from(r#"{"revision":"rev-1"}"#))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflict_resp.status(), StatusCode::CONFLICT);

    // Standard workers fetch policy -> 204 No Content (not deployed yet!)
    let w1_fetch = app(state.clone())
        .oneshot(
            Request::get("/agent/v1/policy")
                .header("authorization", format!("Bearer {}", cred_worker1.token))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(w1_fetch.status(), StatusCode::NO_CONTENT);

    // Pilot fetches policy -> 200 OK with bundle
    let p_fetch = app(state.clone())
        .oneshot(
            Request::get("/agent/v1/policy")
                .header("authorization", format!("Bearer {}", cred_pilot.token))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(p_fetch.status(), StatusCode::OK);
    let pilot_bundle = json_body(p_fetch).await;
    assert_eq!(pilot_bundle["revision"], "rev-1");

    // Pilot acknowledges policy as applied
    let p_ack = app(state.clone())
        .oneshot(
            Request::post("/agent/v1/policy/ack")
                .header("authorization", format!("Bearer {}", cred_pilot.token))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "deployment_sequence": pilot_bundle["deployment_sequence"],
                        "revision": pilot_bundle["revision"],
                        "policy_sha256": pilot_bundle["policy_sha256"],
                        "status": "applied",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(p_ack.status(), StatusCode::NO_CONTENT);

    // Verify rollout automatically transitioned to standard phase
    let get_ro = app(state.clone())
        .oneshot(
            Request::get(format!(
                "/admin/v1/tenants/{}/groups/canary-grp/rollout",
                tenant.id
            ))
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_ro.status(), StatusCode::OK);
    let ro_state = json_body(get_ro).await;
    assert_eq!(ro_state["phase"], "standard");

    // Standard workers now fetch policy -> 200 OK
    let w1_fetch2 = app(state.clone())
        .oneshot(
            Request::get("/agent/v1/policy")
                .header("authorization", format!("Bearer {}", cred_worker1.token))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(w1_fetch2.status(), StatusCode::OK);
    let w1_bundle = json_body(w1_fetch2).await;
    assert_eq!(w1_bundle["revision"], "rev-1");

    let w2_fetch = app(state.clone())
        .oneshot(
            Request::get("/agent/v1/policy")
                .header("authorization", format!("Bearer {}", cred_worker2.token))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(w2_fetch.status(), StatusCode::OK);
    let w2_bundle = json_body(w2_fetch).await;
    assert_eq!(w2_bundle["revision"], "rev-1");

    // Worker 1 acks
    let w1_ack = app(state.clone())
        .oneshot(
            Request::post("/agent/v1/policy/ack")
                .header("authorization", format!("Bearer {}", cred_worker1.token))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "deployment_sequence": w1_bundle["deployment_sequence"],
                        "revision": w1_bundle["revision"],
                        "policy_sha256": w1_bundle["policy_sha256"],
                        "status": "applied",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(w1_ack.status(), StatusCode::NO_CONTENT);

    // Rollout still in standard
    let ro_check = app(state.clone())
        .oneshot(
            Request::get(format!(
                "/admin/v1/tenants/{}/groups/canary-grp/rollout",
                tenant.id
            ))
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json_body(ro_check).await["phase"], "standard");

    // Worker 2 acks
    let w2_ack = app(state.clone())
        .oneshot(
            Request::post("/agent/v1/policy/ack")
                .header("authorization", format!("Bearer {}", cred_worker2.token))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "deployment_sequence": w2_bundle["deployment_sequence"],
                        "revision": w2_bundle["revision"],
                        "policy_sha256": w2_bundle["policy_sha256"],
                        "status": "applied",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(w2_ack.status(), StatusCode::NO_CONTENT);

    // Rollout is now completed!
    let ro_final = app(state.clone())
        .oneshot(
            Request::get(format!(
                "/admin/v1/tenants/{}/groups/canary-grp/rollout",
                tenant.id
            ))
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json_body(ro_final).await["phase"], "completed");
}

#[tokio::test]
async fn test_staged_group_rollout_pilot_failure_automatic_rollback() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Rollout Rollback Tenant").unwrap();

    // Create group
    store
        .create_managed_group(&tenant.id, "prod-grp", "Prod Group")
        .unwrap();

    // Enroll 1 pilot and 1 standard worker
    let cred_pilot = store
        .enroll_managed_agent(&tenant.id, "pilot-node")
        .unwrap();
    let cred_worker = store
        .enroll_managed_agent(&tenant.id, "worker-node")
        .unwrap();

    store
        .add_managed_group_member(&tenant.id, "prod-grp", "pilot-node", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "prod-grp", "worker-node", false)
        .unwrap();

    // Create rev-1 (baseline known-good) and roll out through group rollout to establish baseline
    store
        .create_managed_group_revision(&tenant.id, "prod-grp", "v1.0", "default: allow\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "prod-grp", "v1.0")
        .unwrap();
    let issuer = llm_firewall::tenant_store::ManagedIssuer::from_environment_for_key(None).unwrap();
    store
        .start_managed_group_rollout(&tenant.id, "prod-grp", "v1.0", &issuer)
        .unwrap();

    // Both ack v1.0
    let b_p = store
        .deliver_managed_bundle(&tenant.id, "pilot-node")
        .unwrap()
        .unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-node",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: b_p.deployment_sequence,
                revision: b_p.revision.clone(),
                policy_sha256: b_p.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    let b_w = store
        .deliver_managed_bundle(&tenant.id, "worker-node")
        .unwrap()
        .unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "worker-node",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: b_w.deployment_sequence,
                revision: b_w.revision.clone(),
                policy_sha256: b_w.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Create rev-2 (bad policy)
    store
        .create_managed_group_revision(&tenant.id, "prod-grp", "v2.0-bad", "default: deny\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "prod-grp", "v2.0-bad")
        .unwrap();

    // Start rollout of v2.0-bad
    let start_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/prod-grp/rollout",
                tenant.id
            ))
            .header("content-type", "application/json")
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::from(r#"{"revision":"v2.0-bad"}"#))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_resp.status(), StatusCode::CREATED);
    assert_eq!(json_body(start_resp).await["phase"], "pilot");

    // Worker fetches policy -> 204 No Content (worker is insulated!)
    let w_fetch = app(state.clone())
        .oneshot(
            Request::get("/agent/v1/policy")
                .header("authorization", format!("Bearer {}", cred_worker.token))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(w_fetch.status(), StatusCode::NO_CONTENT);

    // Pilot fetches policy -> receives v2.0-bad
    let p_fetch = app(state.clone())
        .oneshot(
            Request::get("/agent/v1/policy")
                .header("authorization", format!("Bearer {}", cred_pilot.token))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(p_fetch.status(), StatusCode::OK);
    let pilot_bad_bundle = json_body(p_fetch).await;
    assert_eq!(pilot_bad_bundle["revision"], "v2.0-bad");

    // Pilot rejects v2.0-bad due to validation failure
    let p_rej = app(state.clone())
        .oneshot(
            Request::post("/agent/v1/policy/ack")
                .header("authorization", format!("Bearer {}", cred_pilot.token))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "deployment_sequence": pilot_bad_bundle["deployment_sequence"],
                        "revision": pilot_bad_bundle["revision"],
                        "policy_sha256": pilot_bad_bundle["policy_sha256"],
                        "status": "rejected",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(p_rej.status(), StatusCode::NO_CONTENT);

    // Verify rollout state is now rolled_back!
    let ro_state = app(state.clone())
        .oneshot(
            Request::get(format!(
                "/admin/v1/tenants/{}/groups/prod-grp/rollout",
                tenant.id
            ))
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ro_state.status(), StatusCode::OK);
    let ro_val = json_body(ro_state).await;
    assert_eq!(ro_val["phase"], "rolled_back");
    assert!(ro_val["failure_reason"]
        .as_str()
        .unwrap()
        .contains("rejected"));

    // Pilot fetches policy again -> receives rollback to v1.0!
    let p_rollback_fetch = app(state.clone())
        .oneshot(
            Request::get("/agent/v1/policy")
                .header("authorization", format!("Bearer {}", cred_pilot.token))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(p_rollback_fetch.status(), StatusCode::OK);
    let rollback_bundle = json_body(p_rollback_fetch).await;
    assert_eq!(rollback_bundle["revision"], "v1.0");
    assert!(
        rollback_bundle["deployment_sequence"].as_u64().unwrap()
            > pilot_bad_bundle["deployment_sequence"].as_u64().unwrap()
    );

    // Worker node STILL has never seen v2.0-bad
    let w_fetch2 = app(state.clone())
        .oneshot(
            Request::get("/agent/v1/policy")
                .header("authorization", format!("Bearer {}", cred_worker.token))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(w_fetch2.status(), StatusCode::NO_CONTENT);
}
