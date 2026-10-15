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

    // Verify rollout state is now rolling_back!
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
    assert_eq!(ro_val["phase"], "rolling_back");
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

    // Pilot acknowledges the rollback policy as applied!
    let p_rollback_ack = app(state.clone())
        .oneshot(
            Request::post("/agent/v1/policy/ack")
                .header("authorization", format!("Bearer {}", cred_pilot.token))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "deployment_sequence": rollback_bundle["deployment_sequence"],
                        "revision": rollback_bundle["revision"],
                        "policy_sha256": rollback_bundle["policy_sha256"],
                        "status": "applied",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(p_rollback_ack.status(), StatusCode::NO_CONTENT);

    // Rollout state is now confirmed rolled_back!
    let ro_confirmed = app(state.clone())
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
    assert_eq!(ro_confirmed.status(), StatusCode::OK);
    let ro_conf_val = json_body(ro_confirmed).await;
    assert_eq!(ro_conf_val["phase"], "rolled_back");

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

#[tokio::test]
async fn test_group_rollout_rejects_colliding_agent_revision() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Collision Test Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "grp-col", "Collision Group")
        .unwrap();
    store.enroll_managed_agent(&tenant.id, "pilot-col").unwrap();
    store
        .add_managed_group_member(&tenant.id, "grp-col", "pilot-col", true)
        .unwrap();

    // Create revision "v1.0" on pilot-col directly with content A
    store
        .create_managed_revision(&tenant.id, "pilot-col", "v1.0", "default: allow\n")
        .unwrap();

    // Create group revision "v1.0" with content B (differing digest)
    store
        .create_managed_group_revision(&tenant.id, "grp-col", "v1.0", "default: deny\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "grp-col", "v1.0")
        .unwrap();

    // Starting group rollout should fail with 400 Bad Request due to revision digest collision
    let start_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/grp-col/rollout",
                tenant.id
            ))
            .header("content-type", "application/json")
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::from(r#"{"revision":"v1.0"}"#))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_group_rollout_pause_and_resume() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Pause Resume Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "pause-grp", "Pause Group")
        .unwrap();
    let cred_pilot = store.enroll_managed_agent(&tenant.id, "pilot-pr").unwrap();
    let cred_worker = store.enroll_managed_agent(&tenant.id, "worker-pr").unwrap();

    store
        .add_managed_group_member(&tenant.id, "pause-grp", "pilot-pr", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "pause-grp", "worker-pr", false)
        .unwrap();

    store
        .create_managed_group_revision(&tenant.id, "pause-grp", "v1", "default: allow\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "pause-grp", "v1")
        .unwrap();

    // Start rollout
    let start_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/pause-grp/rollout",
                tenant.id
            ))
            .header("content-type", "application/json")
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::from(r#"{"revision":"v1"}"#))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_resp.status(), StatusCode::CREATED);
    assert_eq!(json_body(start_resp).await["phase"], "pilot");

    // Pause rollout
    let pause_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/pause-grp/rollout/pause",
                tenant.id
            ))
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pause_resp.status(), StatusCode::OK);
    assert_eq!(json_body(pause_resp).await["phase"], "paused");

    // Pilot fetches and acks policy
    let p_fetch = app(state.clone())
        .oneshot(
            Request::get("/agent/v1/policy")
                .header("authorization", format!("Bearer {}", cred_pilot.token))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let p_bundle = json_body(p_fetch).await;

    let p_ack = app(state.clone())
        .oneshot(
            Request::post("/agent/v1/policy/ack")
                .header("authorization", format!("Bearer {}", cred_pilot.token))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "deployment_sequence": p_bundle["deployment_sequence"],
                        "revision": p_bundle["revision"],
                        "policy_sha256": p_bundle["policy_sha256"],
                        "status": "applied",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(p_ack.status(), StatusCode::NO_CONTENT);

    // Rollout must STILL be paused (did not automatically promote to standard while paused)
    let ro_paused = app(state.clone())
        .oneshot(
            Request::get(format!(
                "/admin/v1/tenants/{}/groups/pause-grp/rollout",
                tenant.id
            ))
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json_body(ro_paused).await["phase"], "paused");

    // Worker fetches policy -> 204 No Content (still blocked because paused)
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

    // Resume rollout
    let resume_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/pause-grp/rollout/resume",
                tenant.id
            ))
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resume_resp.status(), StatusCode::OK);
    // Upon resume, since pilot is already applied, it advances to standard!
    assert_eq!(json_body(resume_resp).await["phase"], "standard");

    // Worker can now fetch policy!
    let w_fetch2 = app(state.clone())
        .oneshot(
            Request::get("/agent/v1/policy")
                .header("authorization", format!("Bearer {}", cred_worker.token))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(w_fetch2.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_group_rollout_rejects_paused_and_cross_group_conflict() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Exclusivity Test Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "grp-1", "Group 1")
        .unwrap();
    store
        .create_managed_group(&tenant.id, "grp-2", "Group 2")
        .unwrap();

    store
        .enroll_managed_agent(&tenant.id, "pilot-shared")
        .unwrap();
    store.enroll_managed_agent(&tenant.id, "worker-1").unwrap();
    store.enroll_managed_agent(&tenant.id, "worker-2").unwrap();

    store
        .add_managed_group_member(&tenant.id, "grp-1", "pilot-shared", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "grp-1", "worker-1", false)
        .unwrap();

    store
        .add_managed_group_member(&tenant.id, "grp-2", "pilot-shared", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "grp-2", "worker-2", false)
        .unwrap();

    store
        .create_managed_group_revision(&tenant.id, "grp-1", "rev-1", "default: allow\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "grp-1", "rev-1")
        .unwrap();

    store
        .create_managed_group_revision(&tenant.id, "grp-2", "rev-1", "default: allow\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "grp-2", "rev-1")
        .unwrap();

    // Start rollout on grp-1
    let start_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/grp-1/rollout",
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

    // Pause rollout on grp-1
    let pause_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/grp-1/rollout/pause",
                tenant.id
            ))
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pause_resp.status(), StatusCode::OK);

    // Starting another rollout on grp-1 while paused must fail (active rollout in paused phase)
    let start_paused_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/grp-1/rollout",
                tenant.id
            ))
            .header("content-type", "application/json")
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::from(r#"{"revision":"rev-1"}"#))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_paused_resp.status(), StatusCode::CONFLICT);

    // Starting rollout on grp-2 must fail because pilot-shared is enrolled in grp-1's active rollout!
    let start_grp2_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/grp-2/rollout",
                tenant.id
            ))
            .header("content-type", "application/json")
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::from(r#"{"revision":"rev-1"}"#))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_grp2_resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_group_rollout_fails_on_superseded_canary() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Superseded Test Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "sup-grp", "Superseded Group")
        .unwrap();
    let _cred_pilot = store.enroll_managed_agent(&tenant.id, "sup-pilot").unwrap();
    store
        .enroll_managed_agent(&tenant.id, "sup-worker")
        .unwrap();

    store
        .add_managed_group_member(&tenant.id, "sup-grp", "sup-pilot", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "sup-grp", "sup-worker", false)
        .unwrap();

    store
        .create_managed_group_revision(&tenant.id, "sup-grp", "rev-group-1", "default: allow\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "sup-grp", "rev-group-1")
        .unwrap();

    // Start rollout
    let start_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/sup-grp/rollout",
                tenant.id
            ))
            .header("content-type", "application/json")
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::from(r#"{"revision":"rev-group-1"}"#))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_resp.status(), StatusCode::CREATED);

    // Now an operator overrides sup-pilot individually with an out-of-band revision!
    store
        .create_managed_revision(
            &tenant.id,
            "sup-pilot",
            "rev-manual-override",
            "default: deny\n",
        )
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "sup-pilot", "rev-manual-override")
        .unwrap();
    let issuer = llm_firewall::tenant_store::ManagedIssuer::from_environment().unwrap();
    store
        .deploy_managed_revision(
            &tenant.id,
            "sup-pilot",
            "rev-manual-override",
            false,
            &issuer,
        )
        .unwrap();

    // Advancing rollout now MUST detect that canary deployment was superseded and fail the rollout!
    let adv_resp = app(state.clone())
        .oneshot(
            Request::post(format!(
                "/admin/v1/tenants/{}/groups/sup-grp/rollout/advance",
                tenant.id
            ))
            .header("x-llm-firewall-admin-token", OWNER_HEADER)
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(adv_resp.status(), StatusCode::OK);
    let adv_body = json_body(adv_resp).await;
    assert_eq!(adv_body["phase"], "failed");
    assert!(adv_body["failure_reason"]
        .as_str()
        .unwrap()
        .contains("superseded"));
}

#[tokio::test]
async fn test_group_rollout_fails_cleanly_when_issuer_unavailable() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Signer Test Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "signer-grp", "Signer Group")
        .unwrap();
    let _cred_pilot = store.enroll_managed_agent(&tenant.id, "pilot-s").unwrap();
    store.enroll_managed_agent(&tenant.id, "worker-s").unwrap();

    store
        .add_managed_group_member(&tenant.id, "signer-grp", "pilot-s", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "signer-grp", "worker-s", false)
        .unwrap();

    store
        .create_managed_group_revision(&tenant.id, "signer-grp", "rev-s", "default: allow\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "signer-grp", "rev-s")
        .unwrap();

    // Start with a custom key that does not exist in environment
    let custom_issuer = llm_firewall::tenant_store::ManagedIssuer::new(
        "unconfigured-custom-key".into(),
        TEST_SEED_HEX,
    )
    .unwrap();
    store
        .start_managed_group_rollout(&tenant.id, "signer-grp", "rev-s", &custom_issuer)
        .unwrap();

    // Pilot acknowledges policy
    let pilot_dep = store
        .list_managed_deployments(&tenant.id, "pilot-s")
        .unwrap();
    let ro = store
        .get_managed_group_rollout(&tenant.id, "signer-grp")
        .unwrap()
        .unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-s",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: pilot_dep[0].deployment_sequence,
                revision: "rev-s".into(),
                policy_sha256: ro.policy_sha256,
                status: "applied".into(),
            },
        )
        .unwrap();

    // Advancing to standard without passing an issuer must fail because rollout's issuer_key_id is unconfigured in env
    let err = store
        .advance_managed_group_rollout(&tenant.id, "signer-grp", None)
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("configured signing issuer is unavailable for standard wave deployment"));
}
