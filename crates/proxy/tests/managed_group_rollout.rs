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

#[tokio::test]
async fn test_group_mutations_require_owner_and_agent_credentials_cannot_authorize_them() {
    use llm_firewall::tenant_store::AdminRole;
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Group authorization").unwrap();
    store
        .create_managed_group(&tenant.id, "fleet", "Fleet")
        .unwrap();
    let root = format!("/admin/v1/tenants/{}/groups", tenant.id);
    for role in [AdminRole::Viewer, AdminRole::Operator] {
        let issued = store
            .create_admin(&format!("Group {role:?}"), role)
            .unwrap();
        let credential = format!("Bearer {}", issued.token);
        for (method, suffix) in [
            ("POST", ""),
            ("DELETE", "/fleet"),
            ("POST", "/fleet/members"),
            ("DELETE", "/fleet/members/pilot"),
            ("POST", "/fleet/revisions"),
            ("POST", "/fleet/revisions/candidate/approve"),
            ("POST", "/fleet/rollout"),
            ("POST", "/fleet/rollout/advance"),
            ("POST", "/fleet/rollout/rollback"),
            ("POST", "/fleet/rollout/pause"),
            ("POST", "/fleet/rollout/resume"),
        ] {
            let response = app(state.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(format!("{root}{suffix}"))
                        .header("content-type", "application/json")
                        .header("x-llm-firewall-admin-token", &credential)
                        .body(axum::body::Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{method} {suffix} for {role:?}"
            );
        }
        let response = app(state.clone())
            .oneshot(
                Request::get(format!("{root}/fleet"))
                    .header("x-llm-firewall-admin-token", &credential)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let agent = store.enroll_managed_agent(&tenant.id, "pilot").unwrap();
    let response = app(state)
        .oneshot(
            Request::post(root)
                .header("content-type", "application/json")
                .header(
                    "x-llm-firewall-admin-token",
                    format!("Bearer {}", agent.token),
                )
                .body(axum::body::Body::from(
                    r#"{"group_id":"forbidden","name":"Forbidden"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_group_deletion_preserves_paused_and_pending_rollback_plans() {
    use llm_firewall::tenant_store::{AppliedReport, ManagedIssuer, RolloutPhase};

    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Deletion guard").unwrap();
    let issuer = ManagedIssuer::from_environment().unwrap();
    store.enroll_managed_agent(&tenant.id, "pilot").unwrap();
    store
        .create_managed_group(&tenant.id, "group", "Group")
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "group", "pilot", true)
        .unwrap();
    store
        .create_managed_revision(&tenant.id, "pilot", "baseline", "default: allow\n")
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "pilot", "baseline")
        .unwrap();
    let baseline = store
        .deploy_managed_revision(&tenant.id, "pilot", "baseline", false, &issuer)
        .unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot",
            &AppliedReport {
                deployment_sequence: baseline.deployment_sequence,
                revision: baseline.revision,
                policy_sha256: baseline.policy_sha256,
                status: "applied".into(),
            },
        )
        .unwrap();
    store
        .create_managed_group_revision(&tenant.id, "group", "candidate", "default: deny\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "group", "candidate")
        .unwrap();
    let plan = store
        .start_managed_group_rollout(&tenant.id, "group", "candidate", &issuer)
        .unwrap();
    store
        .pause_managed_group_rollout(&tenant.id, "group")
        .unwrap();
    assert!(store.delete_managed_group(&tenant.id, "group").is_err());
    let paused = store
        .get_managed_group_rollout(&tenant.id, "group")
        .unwrap()
        .unwrap();
    assert_eq!(paused.rollout_id, plan.rollout_id);
    assert_eq!(paused.phase, RolloutPhase::Paused);
    let rollback = store
        .rollback_managed_group_rollout(&tenant.id, "group", &issuer)
        .unwrap()
        .unwrap();
    assert_eq!(rollback.phase, RolloutPhase::RollingBack);
    assert!(store.delete_managed_group(&tenant.id, "group").is_err());
    assert_eq!(
        store
            .get_managed_group_rollout(&tenant.id, "group")
            .unwrap()
            .unwrap()
            .rollout_id,
        plan.rollout_id
    );
}

#[tokio::test]
async fn test_frozen_rollout_ack_survives_live_membership_removal() {
    use llm_firewall::tenant_store::{AppliedReport, ManagedIssuer, RolloutPhase};

    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Frozen membership").unwrap();
    let issuer = ManagedIssuer::from_environment().unwrap();
    store.enroll_managed_agent(&tenant.id, "pilot").unwrap();
    store
        .create_managed_group(&tenant.id, "group", "Group")
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "group", "pilot", true)
        .unwrap();
    store
        .create_managed_group_revision(&tenant.id, "group", "candidate", "default: allow\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "group", "candidate")
        .unwrap();
    let plan = store
        .start_managed_group_rollout(&tenant.id, "group", "candidate", &issuer)
        .unwrap();
    store
        .remove_managed_group_member(&tenant.id, "group", "pilot")
        .unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot",
            &AppliedReport {
                deployment_sequence: plan.active_deployments["pilot"],
                revision: plan.revision,
                policy_sha256: plan.policy_sha256,
                status: "applied".into(),
            },
        )
        .unwrap();
    let completed = store
        .get_managed_group_rollout(&tenant.id, "group")
        .unwrap()
        .unwrap();
    assert_eq!(completed.phase, RolloutPhase::Completed);
}

#[tokio::test]
async fn test_completed_rollout_can_be_rolled_back_and_retry_is_idempotent() {
    use llm_firewall::tenant_store::{AppliedReport, ManagedIssuer, RolloutPhase};

    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Completed rollback").unwrap();
    let issuer = ManagedIssuer::from_environment().unwrap();
    store.enroll_managed_agent(&tenant.id, "pilot").unwrap();
    store
        .create_managed_group(&tenant.id, "group", "Group")
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "group", "pilot", true)
        .unwrap();
    store
        .create_managed_revision(&tenant.id, "pilot", "baseline", "default: allow\n")
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "pilot", "baseline")
        .unwrap();
    let baseline = store
        .deploy_managed_revision(&tenant.id, "pilot", "baseline", false, &issuer)
        .unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot",
            &AppliedReport {
                deployment_sequence: baseline.deployment_sequence,
                revision: baseline.revision,
                policy_sha256: baseline.policy_sha256,
                status: "applied".into(),
            },
        )
        .unwrap();
    store
        .create_managed_group_revision(&tenant.id, "group", "candidate", "default: deny\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "group", "candidate")
        .unwrap();
    let plan = store
        .start_managed_group_rollout(&tenant.id, "group", "candidate", &issuer)
        .unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot",
            &AppliedReport {
                deployment_sequence: plan.active_deployments["pilot"],
                revision: plan.revision,
                policy_sha256: plan.policy_sha256,
                status: "applied".into(),
            },
        )
        .unwrap();
    assert_eq!(
        store
            .get_managed_group_rollout(&tenant.id, "group")
            .unwrap()
            .unwrap()
            .phase,
        RolloutPhase::Completed
    );
    let rollback = store
        .rollback_managed_group_rollout(&tenant.id, "group", &issuer)
        .unwrap()
        .expect("completed plans remain rollback-capable");
    assert_eq!(rollback.phase, RolloutPhase::RollingBack);
    let deployment = &store.list_managed_deployments(&tenant.id, "pilot").unwrap()[0];
    assert!(deployment.deployment_sequence > plan.active_deployments["pilot"]);
    assert_eq!(deployment.revision, "baseline");
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot",
            &AppliedReport {
                deployment_sequence: deployment.deployment_sequence,
                revision: deployment.revision.clone(),
                policy_sha256: deployment.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();
    let retry = store
        .rollback_managed_group_rollout(&tenant.id, "group", &issuer)
        .unwrap()
        .expect("a rollback retry returns the confirmed plan");
    assert_eq!(retry.phase, RolloutPhase::RolledBack);
    assert_eq!(
        store
            .list_managed_deployments(&tenant.id, "pilot")
            .unwrap()
            .len(),
        3
    );
}

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

    // Retrying the same start returns the original plan without issuing a second wave.
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
    assert_eq!(conflict_resp.status(), StatusCode::CREATED);
    assert_eq!(
        json_body(conflict_resp).await["rollout_id"],
        rollout["rollout_id"]
    );

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

#[tokio::test]
async fn test_wave_retry_idempotent_no_duplicate_sequence_or_partial_rejection() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Wave Retry Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "wave-grp", "Wave Group")
        .unwrap();
    let _cred_pilot = store
        .enroll_managed_agent(&tenant.id, "wave-pilot")
        .unwrap();
    let _cred_w1 = store.enroll_managed_agent(&tenant.id, "wave-w1").unwrap();
    let _cred_w2 = store.enroll_managed_agent(&tenant.id, "wave-w2").unwrap();

    store
        .add_managed_group_member(&tenant.id, "wave-grp", "wave-pilot", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "wave-grp", "wave-w1", false)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "wave-grp", "wave-w2", false)
        .unwrap();

    store
        .create_managed_group_revision(&tenant.id, "wave-grp", "rev-v1", "default: allow\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "wave-grp", "rev-v1")
        .unwrap();

    let issuer = llm_firewall::tenant_store::ManagedIssuer::from_environment().unwrap();
    store
        .start_managed_group_rollout(&tenant.id, "wave-grp", "rev-v1", &issuer)
        .unwrap();

    // Pre-create unapproved revision on wave-w2 to test pre-validation
    store
        .create_managed_revision(&tenant.id, "wave-w2", "rev-v1", "default: allow\n")
        .unwrap();

    // Acknowledge pilot
    let pilot_dep = store
        .list_managed_deployments(&tenant.id, "wave-pilot")
        .unwrap();
    let ro = store
        .get_managed_group_rollout(&tenant.id, "wave-grp")
        .unwrap()
        .unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "wave-pilot",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: pilot_dep[0].deployment_sequence,
                revision: "rev-v1".into(),
                policy_sha256: ro.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Advancing rollout to standard wave must fail during pre-validation before any side effects!
    let preval_err = store
        .advance_managed_group_rollout(&tenant.id, "wave-grp", Some(&issuer))
        .unwrap_err();
    assert!(preval_err
        .to_string()
        .contains("candidate revision 'rev-v1' on standard agent 'wave-w2' is not approved"));

    // Verify wave-w1 had NO deployments issued (atomic wave pre-validation)
    let w1_deps_before = store
        .list_managed_deployments(&tenant.id, "wave-w1")
        .unwrap();
    assert!(w1_deps_before.is_empty());

    // Approve the revision on wave-w2
    store
        .approve_managed_revision(&tenant.id, "wave-w2", "rev-v1")
        .unwrap();

    // Advancing now succeeds and issues sequence 1 for each standard worker
    let adv1 = store
        .advance_managed_group_rollout(&tenant.id, "wave-grp", Some(&issuer))
        .unwrap()
        .unwrap();
    assert_eq!(
        adv1.phase,
        llm_firewall::tenant_store::RolloutPhase::Standard
    );
    let seq_w1 = *adv1.active_deployments.get("wave-w1").unwrap();
    let seq_w2 = *adv1.active_deployments.get("wave-w2").unwrap();

    // Advancing AGAIN before workers apply MUST be idempotent: reuse existing sequences, no duplicate deployments
    let adv2 = store
        .advance_managed_group_rollout(&tenant.id, "wave-grp", Some(&issuer))
        .unwrap()
        .unwrap();
    assert_eq!(
        adv2.phase,
        llm_firewall::tenant_store::RolloutPhase::Standard
    );
    assert_eq!(*adv2.active_deployments.get("wave-w1").unwrap(), seq_w1);
    assert_eq!(*adv2.active_deployments.get("wave-w2").unwrap(), seq_w2);

    let w1_deps = store
        .list_managed_deployments(&tenant.id, "wave-w1")
        .unwrap();
    let w2_deps = store
        .list_managed_deployments(&tenant.id, "wave-w2")
        .unwrap();
    assert_eq!(w1_deps.len(), 1);
    assert_eq!(w2_deps.len(), 1);
}

#[tokio::test]
async fn test_missing_baseline_pilot_failure_marks_rollout_failed_unresolved() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Missing Baseline Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "mb-grp", "Missing Baseline Group")
        .unwrap();
    store
        .enroll_managed_agent(&tenant.id, "pilot-with-base")
        .unwrap();
    store
        .enroll_managed_agent(&tenant.id, "pilot-no-base")
        .unwrap();

    store
        .add_managed_group_member(&tenant.id, "mb-grp", "pilot-with-base", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "mb-grp", "pilot-no-base", true)
        .unwrap();

    let issuer = llm_firewall::tenant_store::ManagedIssuer::from_environment().unwrap();

    // Deploy and acknowledge an earlier baseline for pilot-with-base ONLY
    store
        .create_managed_revision(
            &tenant.id,
            "pilot-with-base",
            "rev-base",
            "default: allow\n",
        )
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "pilot-with-base", "rev-base")
        .unwrap();
    let d0 = store
        .deploy_managed_revision(&tenant.id, "pilot-with-base", "rev-base", false, &issuer)
        .unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-with-base",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: d0.deployment_sequence,
                revision: "rev-base".into(),
                policy_sha256: d0.policy_sha256,
                status: "applied".into(),
            },
        )
        .unwrap();

    // Create candidate group revision and start rollout
    store
        .create_managed_group_revision(&tenant.id, "mb-grp", "rev-candidate", "default: deny\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "mb-grp", "rev-candidate")
        .unwrap();

    store
        .start_managed_group_rollout(&tenant.id, "mb-grp", "rev-candidate", &issuer)
        .unwrap();

    let dep_no_base = store
        .list_managed_deployments(&tenant.id, "pilot-no-base")
        .unwrap();
    let ro = store
        .get_managed_group_rollout(&tenant.id, "mb-grp")
        .unwrap()
        .unwrap();

    // pilot-no-base rejects candidate
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-no-base",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: dep_no_base[0].deployment_sequence,
                revision: "rev-candidate".into(),
                policy_sha256: ro.policy_sha256.clone(),
                status: "rejected".into(),
            },
        )
        .unwrap();

    // Advance rollout: triggers rollback
    let adv_rb = store
        .advance_managed_group_rollout(&tenant.id, "mb-grp", Some(&issuer))
        .unwrap()
        .unwrap();
    assert_eq!(
        adv_rb.phase,
        llm_firewall::tenant_store::RolloutPhase::RollingBack
    );

    // Verify pilot-with-base received rollback to rev-base, while pilot-no-base was NOT rolled back
    let rb_with_base = store
        .list_managed_deployments(&tenant.id, "pilot-with-base")
        .unwrap();
    assert_eq!(rb_with_base[0].revision, "rev-base");
    assert_eq!(adv_rb.active_deployments.len(), 1);
    assert!(adv_rb.active_deployments.contains_key("pilot-with-base"));

    // pilot-with-base applies rollback deployment
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-with-base",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: rb_with_base[0].deployment_sequence,
                revision: "rev-base".into(),
                policy_sha256: rb_with_base[0].policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Rollout MUST NOT claim rolled_back! It must transition to failed with unresolved reason.
    let adv_done = store
        .get_managed_group_rollout(&tenant.id, "mb-grp")
        .unwrap()
        .unwrap();
    assert_eq!(
        adv_done.phase,
        llm_firewall::tenant_store::RolloutPhase::Failed
    );
    assert!(adv_done
        .failure_reason
        .as_deref()
        .unwrap()
        .contains("rollback unresolved: agent 'pilot-no-base' has no restorable baseline and remains on candidate revision 'rev-candidate'"));
}

#[tokio::test]
async fn test_manual_rollback_with_missing_baseline_fails_closed() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Manual Rollback Test Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "mr-grp", "Manual Rollback Group")
        .unwrap();
    store.enroll_managed_agent(&tenant.id, "mr-pilot").unwrap();
    store
        .add_managed_group_member(&tenant.id, "mr-grp", "mr-pilot", true)
        .unwrap();

    store
        .create_managed_group_revision(&tenant.id, "mr-grp", "rev-1", "default: allow\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "mr-grp", "rev-1")
        .unwrap();

    let issuer = llm_firewall::tenant_store::ManagedIssuer::from_environment().unwrap();
    store
        .start_managed_group_rollout(&tenant.id, "mr-grp", "rev-1", &issuer)
        .unwrap();

    // mr-pilot had no prior baseline; manual rollback must fail closed
    let rb_err = store
        .rollback_managed_group_rollout(&tenant.id, "mr-grp", &issuer)
        .unwrap_err();
    assert!(rb_err
        .to_string()
        .contains("cannot rollback group rollout: no enrolled agents have a prior restorable applied baseline"));
}

#[tokio::test]
async fn test_pilot_start_unapproved_preflight_blocks_without_partial_issuance_and_resumes() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Pilot Preflight Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "pp-grp", "Pilot Preflight Group")
        .unwrap();
    store.enroll_managed_agent(&tenant.id, "pilot-1").unwrap();
    store.enroll_managed_agent(&tenant.id, "pilot-2").unwrap();
    store
        .add_managed_group_member(&tenant.id, "pp-grp", "pilot-1", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "pp-grp", "pilot-2", true)
        .unwrap();

    let yaml = "default: allow\n";
    store
        .create_managed_group_revision(&tenant.id, "pp-grp", "rev-c", yaml)
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "pp-grp", "rev-c")
        .unwrap();

    // Pre-create pilot-2 candidate revision with SAME digest, but leave it UNAPPROVED
    store
        .create_managed_revision(&tenant.id, "pilot-2", "rev-c", yaml)
        .unwrap();

    let issuer = llm_firewall::tenant_store::ManagedIssuer::from_environment().unwrap();
    let start_err = store
        .start_managed_group_rollout(&tenant.id, "pp-grp", "rev-c", &issuer)
        .unwrap_err();
    assert!(
        start_err.to_string().contains("is not approved"),
        "expected unapproved error: {}",
        start_err
    );

    // Verify pilot-1 received NO deployment (zero partial side effects)
    let p1_deps = store
        .list_managed_deployments(&tenant.id, "pilot-1")
        .unwrap();
    assert!(
        p1_deps.is_empty(),
        "pilot-1 must not receive orphan deployments on start failure"
    );

    // Now approve pilot-2's revision and retry start
    store
        .approve_managed_revision(&tenant.id, "pilot-2", "rev-c")
        .unwrap();

    let ro = store
        .start_managed_group_rollout(&tenant.id, "pp-grp", "rev-c", &issuer)
        .unwrap();
    assert_eq!(ro.phase, llm_firewall::tenant_store::RolloutPhase::Pilot);
    assert_eq!(ro.active_deployments.len(), 2);
    assert!(ro.active_deployments.contains_key("pilot-1"));
    assert!(ro.active_deployments.contains_key("pilot-2"));
}

#[tokio::test]
async fn test_pilot_rollback_with_unresolved_pilot_fails_instead_of_false_rolled_back() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store.create_tenant("Pilot Unresolved Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "pu-grp", "Pilot Unresolved Group")
        .unwrap();
    store
        .enroll_managed_agent(&tenant.id, "pilot-nobase")
        .unwrap();
    store
        .enroll_managed_agent(&tenant.id, "pilot-hasbase")
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "pu-grp", "pilot-nobase", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "pu-grp", "pilot-hasbase", true)
        .unwrap();

    let issuer = llm_firewall::tenant_store::ManagedIssuer::from_environment().unwrap();

    // pilot-hasbase has applied baseline
    store
        .create_managed_revision(&tenant.id, "pilot-hasbase", "rev-base", "default: allow\n")
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "pilot-hasbase", "rev-base")
        .unwrap();
    let base_dep = store
        .deploy_managed_revision(&tenant.id, "pilot-hasbase", "rev-base", false, &issuer)
        .unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-hasbase",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: base_dep.deployment_sequence,
                revision: "rev-base".into(),
                policy_sha256: base_dep.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Start group candidate
    store
        .create_managed_group_revision(&tenant.id, "pu-grp", "rev-cand", "default: deny\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "pu-grp", "rev-cand")
        .unwrap();

    let ro = store
        .start_managed_group_rollout(&tenant.id, "pu-grp", "rev-cand", &issuer)
        .unwrap();

    let dep_nobase = store
        .list_managed_deployments(&tenant.id, "pilot-nobase")
        .unwrap();
    let dep_hasbase = store
        .list_managed_deployments(&tenant.id, "pilot-hasbase")
        .unwrap();

    // pilot-nobase applies candidate
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-nobase",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: dep_nobase[0].deployment_sequence,
                revision: "rev-cand".into(),
                policy_sha256: ro.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // pilot-hasbase rejects candidate, triggering rollback
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-hasbase",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: dep_hasbase[0].deployment_sequence,
                revision: "rev-cand".into(),
                policy_sha256: ro.policy_sha256.clone(),
                status: "rejected".into(),
            },
        )
        .unwrap();

    // pilot-hasbase receives rollback deployment and applies it
    let rb_hasbase = store
        .list_managed_deployments(&tenant.id, "pilot-hasbase")
        .unwrap();
    assert_eq!(rb_hasbase[0].revision, "rev-base");
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-hasbase",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: rb_hasbase[0].deployment_sequence,
                revision: "rev-base".into(),
                policy_sha256: rb_hasbase[0].policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Rollout MUST fail with unresolved reason, NEVER declare RolledBack
    let final_ro = store
        .get_managed_group_rollout(&tenant.id, "pu-grp")
        .unwrap()
        .unwrap();
    assert_eq!(
        final_ro.phase,
        llm_firewall::tenant_store::RolloutPhase::Failed
    );
    assert!(final_ro
        .failure_reason
        .as_deref()
        .unwrap()
        .contains("rollback unresolved: agent 'pilot-nobase' has no restorable baseline and remains on candidate revision 'rev-cand'"));
}

#[tokio::test]
async fn test_manual_rollback_in_standard_wave_with_unresolved_worker_fails() {
    let state = test_state();
    let store = state.tenant_store.as_ref().unwrap();
    let tenant = store
        .create_tenant("Manual Rollback Standard Tenant")
        .unwrap();

    store
        .create_managed_group(&tenant.id, "mrs-grp", "Manual Rollback Standard Group")
        .unwrap();
    store.enroll_managed_agent(&tenant.id, "pilot-1").unwrap();
    store
        .enroll_managed_agent(&tenant.id, "worker-nobase")
        .unwrap();
    store
        .enroll_managed_agent(&tenant.id, "worker-hasbase")
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "mrs-grp", "pilot-1", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "mrs-grp", "worker-nobase", false)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "mrs-grp", "worker-hasbase", false)
        .unwrap();

    let issuer = llm_firewall::tenant_store::ManagedIssuer::from_environment().unwrap();

    // pilot-1 and worker-hasbase have applied baselines
    for (agent, rev) in [("pilot-1", "rev-pbase"), ("worker-hasbase", "rev-wbase")] {
        store
            .create_managed_revision(&tenant.id, agent, rev, "default: allow\n")
            .unwrap();
        store
            .approve_managed_revision(&tenant.id, agent, rev)
            .unwrap();
        let dep = store
            .deploy_managed_revision(&tenant.id, agent, rev, false, &issuer)
            .unwrap();
        store
            .acknowledge_managed_bundle(
                &tenant.id,
                agent,
                &llm_firewall::tenant_store::AppliedReport {
                    deployment_sequence: dep.deployment_sequence,
                    revision: rev.into(),
                    policy_sha256: dep.policy_sha256.clone(),
                    status: "applied".into(),
                },
            )
            .unwrap();
    }

    // Start group candidate
    store
        .create_managed_group_revision(&tenant.id, "mrs-grp", "rev-cand", "default: deny\n")
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "mrs-grp", "rev-cand")
        .unwrap();

    let ro = store
        .start_managed_group_rollout(&tenant.id, "mrs-grp", "rev-cand", &issuer)
        .unwrap();

    // pilot applies candidate, promoting standard wave
    let p_dep = store
        .list_managed_deployments(&tenant.id, "pilot-1")
        .unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-1",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: p_dep[0].deployment_sequence,
                revision: "rev-cand".into(),
                policy_sha256: ro.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Advance rollout: enters standard wave
    let ro_std = store
        .advance_managed_group_rollout(&tenant.id, "mrs-grp", Some(&issuer))
        .unwrap()
        .unwrap();
    assert_eq!(
        ro_std.phase,
        llm_firewall::tenant_store::RolloutPhase::Standard
    );

    // worker-nobase applies candidate while worker-hasbase is pending
    let w_nobase_dep = store
        .list_managed_deployments(&tenant.id, "worker-nobase")
        .unwrap();
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "worker-nobase",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: w_nobase_dep[0].deployment_sequence,
                revision: "rev-cand".into(),
                policy_sha256: ro.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Operator requests manual rollback
    let ro_rb = store
        .rollback_managed_group_rollout(&tenant.id, "mrs-grp", &issuer)
        .unwrap()
        .unwrap();
    assert_eq!(
        ro_rb.phase,
        llm_firewall::tenant_store::RolloutPhase::RollingBack
    );

    // pilot-1 and worker-hasbase receive rollback deployments
    let p_rb = store
        .list_managed_deployments(&tenant.id, "pilot-1")
        .unwrap();
    let w_rb = store
        .list_managed_deployments(&tenant.id, "worker-hasbase")
        .unwrap();
    assert_eq!(p_rb[0].revision, "rev-pbase");
    assert_eq!(w_rb[0].revision, "rev-wbase");

    // Both acknowledge rollback with applied
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pilot-1",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: p_rb[0].deployment_sequence,
                revision: "rev-pbase".into(),
                policy_sha256: p_rb[0].policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "worker-hasbase",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: w_rb[0].deployment_sequence,
                revision: "rev-wbase".into(),
                policy_sha256: w_rb[0].policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Advance rollout: MUST transition to Failed because worker-nobase has no baseline!
    let final_ro = store
        .get_managed_group_rollout(&tenant.id, "mrs-grp")
        .unwrap()
        .unwrap();
    assert_eq!(
        final_ro.phase,
        llm_firewall::tenant_store::RolloutPhase::Failed
    );
    assert!(final_ro
        .failure_reason
        .as_deref()
        .unwrap()
        .contains("rollback unresolved: agent 'worker-nobase' has no restorable baseline and remains on candidate revision 'rev-cand'"));
}

#[tokio::test]
async fn test_pilot_issuance_atomic_start_and_transient_failure_recovery() {
    std::env::set_var("SOUP_AGENT_POLICY_KEY_ID", TEST_KEY_ID);
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", TEST_SEED_HEX);

    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("store.db");
    let store = TenantStore::open(&db_path).unwrap();
    let tenant = store.create_tenant("Atomic Pilot Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "grp-transient", "Transient Group")
        .unwrap();
    store.enroll_managed_agent(&tenant.id, "pilot-a").unwrap();
    store.enroll_managed_agent(&tenant.id, "pilot-z").unwrap();
    store
        .add_managed_group_member(&tenant.id, "grp-transient", "pilot-a", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "grp-transient", "pilot-z", true)
        .unwrap();

    let yaml = "default: allow\n";
    store
        .create_managed_group_revision(&tenant.id, "grp-transient", "v1", yaml)
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "grp-transient", "v1")
        .unwrap();

    let issuer = llm_firewall::tenant_store::ManagedIssuer::from_environment().unwrap();

    // 1. Install trigger that aborts pilot-z insert
    {
        let db = rusqlite::Connection::open(&db_path).unwrap();
        db.execute_batch(
            "CREATE TRIGGER abort_pilot_z BEFORE INSERT ON managed_agent_deployments
             WHEN NEW.agent_id = 'pilot-z'
             BEGIN
                 SELECT RAISE(ABORT, 'transient failure on pilot-z');
             END;",
        )
        .unwrap();
    }

    // 2. Start fails cleanly due to transient trigger
    let err = store
        .start_managed_group_rollout(&tenant.id, "grp-transient", "v1", &issuer)
        .unwrap_err();
    assert!(err.to_string().contains("transient failure on pilot-z"));

    // Verify atomic failure: no partial rollout plan and no orphan pilot-a deployment
    assert!(store
        .get_managed_group_rollout(&tenant.id, "grp-transient")
        .unwrap()
        .is_none());
    let p_a_deps = store
        .list_managed_deployments(&tenant.id, "pilot-a")
        .unwrap();
    assert!(
        p_a_deps.is_empty(),
        "pilot-a deployment must roll back atomically"
    );

    // 3. Drop trigger and reopen store
    {
        let db = rusqlite::Connection::open(&db_path).unwrap();
        db.execute_batch("DROP TRIGGER abort_pilot_z;").unwrap();
    }
    drop(store);
    let store = TenantStore::open(&db_path).unwrap();

    // 4. Retry start: must succeed cleanly and issue both pilots
    let ro = store
        .start_managed_group_rollout(&tenant.id, "grp-transient", "v1", &issuer)
        .unwrap();
    assert_eq!(ro.phase, llm_firewall::tenant_store::RolloutPhase::Pilot);
    assert_eq!(ro.active_deployments.len(), 2);
    assert!(ro.active_deployments.contains_key("pilot-a"));
    assert!(ro.active_deployments.contains_key("pilot-z"));
}

#[tokio::test]
async fn test_partially_persisted_pilot_rollout_resumes_via_start_and_advance() {
    std::env::set_var("SOUP_AGENT_POLICY_KEY_ID", TEST_KEY_ID);
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", TEST_SEED_HEX);

    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("store.db");
    let store = TenantStore::open(&db_path).unwrap();
    let tenant = store.create_tenant("Partial Pilot Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "grp-part", "Partial Group")
        .unwrap();
    store.enroll_managed_agent(&tenant.id, "p-1").unwrap();
    store.enroll_managed_agent(&tenant.id, "p-2").unwrap();
    store
        .add_managed_group_member(&tenant.id, "grp-part", "p-1", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "grp-part", "p-2", true)
        .unwrap();

    let yaml = "default: allow\n";
    store
        .create_managed_group_revision(&tenant.id, "grp-part", "v1", yaml)
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "grp-part", "v1")
        .unwrap();

    let issuer = llm_firewall::tenant_store::ManagedIssuer::from_environment().unwrap();

    // Issue candidate revision and deployment to p-1 only
    store
        .create_managed_revision(&tenant.id, "p-1", "v1", yaml)
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "p-1", "v1")
        .unwrap();
    store
        .create_managed_revision(&tenant.id, "p-2", "v1", yaml)
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "p-2", "v1")
        .unwrap();

    let dep_p1 = store
        .deploy_managed_revision(&tenant.id, "p-1", "v1", false, &issuer)
        .unwrap();

    let digest = store
        .list_managed_group_revisions(&tenant.id, "grp-part")
        .unwrap()[0]
        .policy_sha256
        .clone();

    {
        let db = rusqlite::Connection::open(&db_path).unwrap();
        let mut active = std::collections::BTreeMap::new();
        active.insert("p-1", dep_p1.deployment_sequence);
        let mut inits = std::collections::BTreeMap::new();
        inits.insert("p-1", 0);
        inits.insert("p-2", 0);
        let prevs: std::collections::BTreeMap<&str, Option<&str>> =
            [("p-1", None), ("p-2", None)].into_iter().collect();

        db.execute(
            "INSERT INTO managed_group_rollouts
             (tenant_id, group_id, rollout_id, revision, policy_sha256, issuer_key_id, phase,
              pilot_agents_json, standard_agents_json, active_deployments_json, previous_revisions_json,
              failure_reason, created_at_unix, updated_at_unix, initial_sequences_json)
             VALUES (?1, ?2, 'ro_interrupted', 'v1', ?3, ?4, 'pilot', ?5, '[]', ?6, ?7, NULL, 1000, 1000, ?8)",
            rusqlite::params![
                tenant.id,
                "grp-part",
                digest,
                issuer.key_id(),
                serde_json::to_string(&vec!["p-1", "p-2"]).unwrap(),
                serde_json::to_string(&active).unwrap(),
                serde_json::to_string(&prevs).unwrap(),
                serde_json::to_string(&inits).unwrap(),
            ],
        )
        .unwrap();
    }

    // Reopen store from disk (restart recovery)
    drop(store);
    let store = TenantStore::open(&db_path).unwrap();

    // Part A: Retrying start resumes issuance of p-2
    let resumed = store
        .start_managed_group_rollout(&tenant.id, "grp-part", "v1", &issuer)
        .unwrap();
    assert_eq!(
        resumed.phase,
        llm_firewall::tenant_store::RolloutPhase::Pilot
    );
    assert_eq!(resumed.active_deployments.len(), 2);
    assert_eq!(
        resumed.active_deployments.get("p-1").copied(),
        Some(dep_p1.deployment_sequence)
    );
    assert!(resumed.active_deployments.contains_key("p-2"));

    // Now test Part B: advance with an unissued pilot in another group
    store
        .create_managed_group(&tenant.id, "grp-adv", "Advance Group")
        .unwrap();
    store.enroll_managed_agent(&tenant.id, "pa").unwrap();
    store.enroll_managed_agent(&tenant.id, "pb").unwrap();
    store
        .add_managed_group_member(&tenant.id, "grp-adv", "pa", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "grp-adv", "pb", true)
        .unwrap();
    store
        .create_managed_group_revision(&tenant.id, "grp-adv", "v1", yaml)
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "grp-adv", "v1")
        .unwrap();
    store
        .create_managed_revision(&tenant.id, "pa", "v1", yaml)
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "pa", "v1")
        .unwrap();
    store
        .create_managed_revision(&tenant.id, "pb", "v1", yaml)
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "pb", "v1")
        .unwrap();

    let dep_pa = store
        .deploy_managed_revision(&tenant.id, "pa", "v1", false, &issuer)
        .unwrap();

    {
        let db = rusqlite::Connection::open(&db_path).unwrap();
        let mut active = std::collections::BTreeMap::new();
        active.insert("pa", dep_pa.deployment_sequence);
        let mut inits = std::collections::BTreeMap::new();
        inits.insert("pa", 0);
        inits.insert("pb", 0);
        let prevs: std::collections::BTreeMap<&str, Option<&str>> =
            [("pa", None), ("pb", None)].into_iter().collect();

        db.execute(
            "INSERT INTO managed_group_rollouts
             (tenant_id, group_id, rollout_id, revision, policy_sha256, issuer_key_id, phase,
              pilot_agents_json, standard_agents_json, active_deployments_json, previous_revisions_json,
              failure_reason, created_at_unix, updated_at_unix, initial_sequences_json)
             VALUES (?1, ?2, 'ro_interrupted_adv', 'v1', ?3, ?4, 'pilot', ?5, '[]', ?6, ?7, NULL, 1000, 1000, ?8)",
            rusqlite::params![
                tenant.id,
                "grp-adv",
                digest,
                issuer.key_id(),
                serde_json::to_string(&vec!["pa", "pb"]).unwrap(),
                serde_json::to_string(&active).unwrap(),
                serde_json::to_string(&prevs).unwrap(),
                serde_json::to_string(&inits).unwrap(),
            ],
        )
        .unwrap();
    }

    // Acknowledge pa
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pa",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: dep_pa.deployment_sequence,
                revision: "v1".into(),
                policy_sha256: dep_pa.policy_sha256.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Call advance: advance should issue the missing pilot pb!
    let adv1 = store
        .advance_managed_group_rollout(&tenant.id, "grp-adv", Some(&issuer))
        .unwrap()
        .unwrap();
    println!(
        "adv1 phase: {:?}, active: {:?}",
        adv1.phase, adv1.active_deployments
    );
    assert_eq!(adv1.phase, llm_firewall::tenant_store::RolloutPhase::Pilot);
    assert_eq!(adv1.active_deployments.len(), 2);
    let pb_seq = *adv1.active_deployments.get("pb").unwrap();

    // Acknowledge pb
    store
        .acknowledge_managed_bundle(
            &tenant.id,
            "pb",
            &llm_firewall::tenant_store::AppliedReport {
                deployment_sequence: pb_seq,
                revision: "v1".into(),
                policy_sha256: digest.clone(),
                status: "applied".into(),
            },
        )
        .unwrap();

    // Both pa and pb are now applied. The acknowledgment automatically completed the rollout:
    let adv2 = store
        .get_managed_group_rollout(&tenant.id, "grp-adv")
        .unwrap()
        .unwrap();
    assert_eq!(
        adv2.phase,
        llm_firewall::tenant_store::RolloutPhase::Completed
    );
    assert_eq!(adv2.active_deployments.len(), 2);
}

#[tokio::test]
async fn test_pilot_recovery_refuses_superseded_slot_on_start_and_advance() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("store.db");
    let store = TenantStore::open(&db_path).unwrap();
    let tenant = store.create_tenant("Superseded Pilot Tenant").unwrap();

    store
        .create_managed_group(&tenant.id, "grp-sup", "Superseded Group")
        .unwrap();
    store.enroll_managed_agent(&tenant.id, "p-1").unwrap();
    store.enroll_managed_agent(&tenant.id, "p-2").unwrap();
    store
        .add_managed_group_member(&tenant.id, "grp-sup", "p-1", true)
        .unwrap();
    store
        .add_managed_group_member(&tenant.id, "grp-sup", "p-2", true)
        .unwrap();

    let yaml = "default: allow\n";
    store
        .create_managed_group_revision(&tenant.id, "grp-sup", "v1", yaml)
        .unwrap();
    store
        .approve_managed_group_revision(&tenant.id, "grp-sup", "v1")
        .unwrap();

    let issuer = llm_firewall::tenant_store::ManagedIssuer::from_environment().unwrap();

    store
        .create_managed_revision(&tenant.id, "p-1", "v1", yaml)
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "p-1", "v1")
        .unwrap();
    store
        .create_managed_revision(&tenant.id, "p-2", "v1", yaml)
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "p-2", "v1")
        .unwrap();

    let dep_p1 = store
        .deploy_managed_revision(&tenant.id, "p-1", "v1", false, &issuer)
        .unwrap();

    let digest = store
        .list_managed_group_revisions(&tenant.id, "grp-sup")
        .unwrap()[0]
        .policy_sha256
        .clone();

    // 1. Seed partial plan with p-1 issued (seq 1) and p-2 missing (initial sequence 0)
    {
        let db = rusqlite::Connection::open(&db_path).unwrap();
        let mut active = std::collections::BTreeMap::new();
        active.insert("p-1", dep_p1.deployment_sequence);
        let mut inits = std::collections::BTreeMap::new();
        inits.insert("p-1", 0);
        inits.insert("p-2", 0);
        let prevs: std::collections::BTreeMap<&str, Option<&str>> =
            [("p-1", None), ("p-2", None)].into_iter().collect();

        db.execute(
            "INSERT INTO managed_group_rollouts
             (tenant_id, group_id, rollout_id, revision, policy_sha256, issuer_key_id, phase,
              pilot_agents_json, standard_agents_json, active_deployments_json, previous_revisions_json,
              failure_reason, created_at_unix, updated_at_unix, initial_sequences_json)
             VALUES (?1, ?2, 'ro_sup_witness', 'v1', ?3, ?4, 'pilot', ?5, '[]', ?6, ?7, NULL, 1000, 1000, ?8)",
            rusqlite::params![
                tenant.id,
                "grp-sup",
                digest,
                issuer.key_id(),
                serde_json::to_string(&vec!["p-1", "p-2"]).unwrap(),
                serde_json::to_string(&active).unwrap(),
                serde_json::to_string(&prevs).unwrap(),
                serde_json::to_string(&inits).unwrap(),
            ],
        )
        .unwrap();
    }

    // Reopen store from disk
    drop(store);
    let store = TenantStore::open(&db_path).unwrap();

    // 2. Operator issues an explicit newer per-agent deployment for p-2 at sequence 1
    store
        .create_managed_revision(&tenant.id, "p-2", "operator-newer", "default: deny\n")
        .unwrap();
    store
        .approve_managed_revision(&tenant.id, "p-2", "operator-newer")
        .unwrap();
    let dep_newer = store
        .deploy_managed_revision(&tenant.id, "p-2", "operator-newer", false, &issuer)
        .unwrap();
    assert_eq!(dep_newer.deployment_sequence, 1);

    // 3. Retrying group start MUST refuse to supersede operator-newer
    let start_err = store
        .start_managed_group_rollout(&tenant.id, "grp-sup", "v1", &issuer)
        .unwrap_err();
    let err_msg = start_err.to_string();
    assert!(
        err_msg.contains("superseded") || err_msg.contains("conflict"),
        "expected supersession/conflict refusal, got: {}",
        err_msg
    );

    // Verify invariant: p-2 still only has sequence 1 (operator-newer), rollout inventory unchanged
    let p2_deps = store.list_managed_deployments(&tenant.id, "p-2").unwrap();
    assert_eq!(p2_deps.len(), 1);
    assert_eq!(p2_deps[0].revision, "operator-newer");
    let plan = store
        .get_managed_group_rollout(&tenant.id, "grp-sup")
        .unwrap()
        .unwrap();
    assert_eq!(plan.phase, llm_firewall::tenant_store::RolloutPhase::Pilot);
    assert_eq!(plan.active_deployments.len(), 1);
    assert_eq!(plan.active_deployments.get("p-1").copied(), Some(1));
    assert!(!plan.active_deployments.contains_key("p-2"));

    // 4. Calling advance MUST record supersession and fail the rollout without allocating sequence 2
    let adv = store
        .advance_managed_group_rollout(&tenant.id, "grp-sup", Some(&issuer))
        .unwrap()
        .unwrap();
    assert_eq!(adv.phase, llm_firewall::tenant_store::RolloutPhase::Failed);
    let reason = adv.failure_reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("superseded") || reason.contains("conflict"),
        "expected supersession failure reason, got: {}",
        reason
    );

    // Verify invariant: p-2 still only has sequence 1 (operator-newer); candidate v1 was not issued
    let p2_deps_after = store.list_managed_deployments(&tenant.id, "p-2").unwrap();
    assert_eq!(p2_deps_after.len(), 1);
    assert_eq!(p2_deps_after[0].revision, "operator-newer");
}
