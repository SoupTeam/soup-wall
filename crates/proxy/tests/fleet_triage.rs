// SPDX-License-Identifier: Apache-2.0
//! Cross-Agent triage projection: recorded problem flags, bounded counts,
//! keyset paging, authorization and tenant isolation (SQLite). The real
//! dual-store browser witness is scripts/console-fleet-triage-acceptance.py.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use llm_firewall::{
    app,
    handlers::AppState,
    tenant_store::{
        fleet_triage::{TriagePage, TriageQuery},
        AdminRole, AppliedReport, ManagedIssuer, TenantStore,
    },
    test_config,
};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
use std::{collections::BTreeMap, path::Path, sync::Arc};
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

fn issuer() -> ManagedIssuer {
    let seed = (0..32)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect::<String>();
    ManagedIssuer::new("fixture".into(), &seed).unwrap()
}

fn ack(
    db: &TenantStore,
    tenant: &str,
    agent: &str,
    d: &llm_firewall::tenant_store::ManagedDeployment,
    status: &str,
) {
    assert!(db
        .acknowledge_managed_bundle(
            tenant,
            agent,
            &AppliedReport {
                deployment_sequence: d.deployment_sequence,
                revision: d.revision.clone(),
                policy_sha256: d.policy_sha256.clone(),
                status: status.into(),
            },
        )
        .unwrap());
}

/// Mixed recorded outcomes through the store's own APIs; two rows are then
/// aged or removed directly to model old acknowledgements and lost history.
fn seed(path: &Path) -> (TenantStore, String, String) {
    let db = TenantStore::open(path.to_str().unwrap()).unwrap();
    let t = db.create_tenant("triage").unwrap().id;
    let other = db.create_tenant("triage-other").unwrap().id;
    let issuer = issuer();
    for agent in [
        "applied", "pending", "rejected", "mismatch", "revoked", "fresh", "gap", "old",
    ] {
        db.enroll_managed_agent(&t, agent).unwrap();
    }
    db.enroll_managed_agent(&other, "pending").unwrap();
    for agent in ["applied", "pending", "rejected", "mismatch", "gap", "old"] {
        db.create_managed_revision(&t, agent, "r1", "default: deny")
            .unwrap();
        db.approve_managed_revision(&t, agent, "r1").unwrap();
    }
    db.create_managed_revision(&t, "mismatch", "r2", "default: allow")
        .unwrap();
    db.approve_managed_revision(&t, "mismatch", "r2").unwrap();
    let d = db
        .deploy_managed_revision(&t, "applied", "r1", false, &issuer)
        .unwrap();
    ack(&db, &t, "applied", &d, "applied");
    db.deploy_managed_revision(&t, "pending", "r1", false, &issuer)
        .unwrap();
    let d = db
        .deploy_managed_revision(&t, "rejected", "r1", false, &issuer)
        .unwrap();
    ack(&db, &t, "rejected", &d, "rejected");
    let d = db
        .deploy_managed_revision(&t, "mismatch", "r1", false, &issuer)
        .unwrap();
    ack(&db, &t, "mismatch", &d, "applied");
    db.deploy_managed_revision(&t, "mismatch", "r2", false, &issuer)
        .unwrap();
    for _ in 0..2 {
        db.deploy_managed_revision(&t, "gap", "r1", false, &issuer)
            .unwrap();
    }
    let d = db
        .deploy_managed_revision(&t, "gap", "r1", false, &issuer)
        .unwrap();
    ack(&db, &t, "gap", &d, "applied");
    let d = db
        .deploy_managed_revision(&t, "old", "r1", false, &issuer)
        .unwrap();
    ack(&db, &t, "old", &d, "applied");
    db.revoke_managed_agent(&t, "revoked").unwrap();
    let raw = rusqlite::Connection::open(path).unwrap();
    raw.execute(
        "DELETE FROM managed_agent_deployments WHERE tenant_id=?1 AND agent_id='gap' AND deployment_sequence=1",
        [&t],
    )
    .unwrap();
    raw.execute(
        "UPDATE managed_agent_deployments SET applied_at_unix=applied_at_unix-90000 WHERE tenant_id=?1 AND agent_id='old'",
        [&t],
    )
    .unwrap();
    (db, t, other)
}

async fn page(db: &TenantStore, tenant: &str, q: TriageQuery) -> TriagePage {
    db.fleet_triage(tenant, q).await.unwrap().unwrap()
}
fn ids(p: &TriagePage) -> Vec<&str> {
    p.agents.iter().map(|a| a.agent_id.as_str()).collect()
}

#[tokio::test]
async fn triage_flags_counts_and_filters_recorded_problems() {
    let dir = tempfile::tempdir().unwrap();
    let (db, t, _) = seed(&dir.path().join("triage.sqlite"));
    let all = page(
        &db,
        &t,
        TriageQuery {
            problem: "all".into(),
            limit: 100,
            ..Default::default()
        },
    )
    .await;
    let problems = |id: &str| {
        all.agents
            .iter()
            .find(|a| a.agent_id == id)
            .unwrap()
            .problems
            .clone()
    };
    assert_eq!(problems("applied"), Vec::<String>::new());
    assert_eq!(problems("pending"), ["pending", "no_ack"]);
    assert_eq!(problems("rejected"), ["rejected", "no_ack"]);
    assert_eq!(problems("mismatch"), ["pending", "mismatch"]);
    assert_eq!(problems("revoked"), ["revoked", "no_history"]);
    assert_eq!(problems("fresh"), ["no_history"]);
    assert_eq!(problems("gap"), ["incomplete_history"]);
    assert_eq!(problems("old"), ["stale_ack"]);
    let c = &all.counts;
    assert_eq!((c.counted_agents, c.complete, c.matching), (8, true, 8));
    assert_eq!((c.attention, c.no_recorded_problem), (7, 1));
    assert_eq!((c.pending, c.rejected, c.mismatch, c.revoked), (2, 1, 1, 1));
    assert_eq!(
        (c.incomplete_history, c.no_ack, c.stale_ack, c.no_history),
        (1, 2, 1, 2)
    );
    assert!(all
        .agents
        .iter()
        .all(|a| a.current_liveness == "unknown" && a.runtime_coverage == "unknown"));
    for (filter, expected) in [
        (
            "attention",
            vec![
                "fresh", "gap", "mismatch", "old", "pending", "rejected", "revoked",
            ],
        ),
        ("no_recorded_problem", vec!["applied"]),
        ("pending", vec!["mismatch", "pending"]),
        ("no_history", vec!["fresh", "revoked"]),
        ("stale_ack", vec!["old"]),
    ] {
        let p = page(
            &db,
            &t,
            TriageQuery {
                problem: filter.into(),
                limit: 100,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(ids(&p), expected, "{filter}");
        assert_eq!(p.counts.matching as usize, expected.len());
        assert_eq!(
            p.counts.counted_agents, 8,
            "denominator stays the tenant count"
        );
    }
    // A wider age threshold no longer calls the 25-hour-old ACK old.
    let p = page(
        &db,
        &t,
        TriageQuery {
            problem: "stale_ack".into(),
            ack_age_seconds: 604_800,
            ..Default::default()
        },
    )
    .await;
    assert!(p.agents.is_empty());
    let p = page(
        &db,
        &t,
        TriageQuery {
            problem: "all".into(),
            prefix: "re".into(),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(ids(&p), ["rejected", "revoked"]);
    assert_eq!(p.counts.matching, 2);
}

#[tokio::test]
async fn triage_keyset_pages_by_id_and_by_acknowledgement_age() {
    let dir = tempfile::tempdir().unwrap();
    let (db, t, _) = seed(&dir.path().join("triage.sqlite"));
    for sort in ["agent_id", "ack_oldest"] {
        let mut q = TriageQuery {
            problem: "all".into(),
            sort: sort.into(),
            limit: 3,
            ..Default::default()
        };
        let mut seen = vec![];
        let mut ages = vec![];
        loop {
            let p = page(&db, &t, q.clone()).await;
            for a in &p.agents {
                seen.push(a.agent_id.clone());
                ages.push(
                    a.last_reported_applied
                        .as_ref()
                        .and_then(|d| d.reported_applied_at_unix)
                        .unwrap_or(-1),
                );
            }
            let Some(next) = p.next else { break };
            q.after = next.after;
            q.after_ack = next.after_ack;
        }
        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 8, "{sort}: no loss or duplicates");
        if sort == "agent_id" {
            assert_eq!(seen, unique);
        } else {
            assert!(ages.windows(2).all(|w| w[0] <= w[1]), "{ages:?}");
            assert_eq!(
                seen[..4],
                ["fresh", "pending", "rejected", "revoked"],
                "unacknowledged first"
            );
            assert_eq!(
                seen[4], "old",
                "oldest recorded acknowledgement after the unacknowledged"
            );
        }
    }
}

#[tokio::test]
async fn triage_http_authorization_scope_and_bounded_queries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("triage.sqlite");
    let (db, t, other) = seed(&path);
    let viewer = db.create_admin("triage-viewer", AdminRole::Viewer).unwrap();
    let operator = db
        .create_admin("triage-operator", AdminRole::Operator)
        .unwrap();
    let credential = db.enroll_managed_agent(&t, "credential-holder").unwrap();
    let state = state(db);
    let base = format!("/admin/v1/tenants/{t}/agent-triage");
    for token in [None, Some("invalid"), Some(credential.token.as_str())] {
        assert_eq!(
            get(app(state.clone()), &base, token).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    for token in [
        viewer.token.as_str(),
        operator.token.as_str(),
        "admin-test-token",
    ] {
        let (code, body) = get(
            app(state.clone()),
            &format!("{base}?problem=all&limit=100"),
            Some(token),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["contract_version"], "sw-agent-fleet-triage/1");
        assert!(body["agents"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["tenant_id"] == t.as_str()));
        let text = body.to_string();
        for forbidden in [
            "token_hash",
            "policy_yaml",
            "bundle_json",
            "signature_hex",
            "default: deny",
            credential.token.as_str(),
        ] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }
    // The other tenant's same Agent ID is never included.
    let (_, body) = get(
        app(state.clone()),
        &format!("/admin/v1/tenants/{other}/agent-triage?problem=all"),
        Some(&viewer.token),
    )
    .await;
    assert_eq!(body["counts"]["counted_agents"], 1);
    assert_eq!(
        body["agents"][0]["problems"],
        serde_json::json!(["no_history"])
    );
    assert_eq!(
        get(
            app(state.clone()),
            "/admin/v1/tenants/unknown/agent-triage",
            Some(&viewer.token)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    for suffix in [
        "?limit=0",
        "?limit=101",
        "?problem=healthy",
        "?sort=random",
        "?ack_age_seconds=60",
        "?after=../x",
        "?prefix=%3Cscript%3E",
        "?after_ack=5",
        "?sort=ack_oldest&after=a",
        "?sort=ack_oldest&after=a&after_ack=-2",
        "?extra=x",
    ] {
        assert_eq!(
            get(
                app(state.clone()),
                &format!("{base}{suffix}"),
                Some(&viewer.token)
            )
            .await
            .0,
            StatusCode::BAD_REQUEST,
            "{suffix}"
        );
    }
    let response = app(state.clone())
        .oneshot(
            Request::post(&base)
                .header(
                    "x-llm-firewall-admin-token",
                    format!("Bearer {}", viewer.token),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED | StatusCode::FORBIDDEN
    ));
}

#[tokio::test]
async fn triage_counts_are_bounded_and_marked_incomplete() {
    let db = TenantStore::open(":memory:").unwrap();
    let t = db.create_tenant("large").unwrap().id;
    let limit = llm_firewall::tenant_store::fleet_triage::SCAN_LIMIT;
    for n in 0..=limit {
        db.enroll_managed_agent(&t, &format!("agent-{n:05}"))
            .unwrap();
    }
    let p = page(
        &db,
        &t,
        TriageQuery {
            problem: "all".into(),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(p.counts.counted_agents, limit);
    assert!(!p.counts.complete);
    assert_eq!(p.agents.len(), 25);
    assert!(p.next.is_some());
    // The Agent after the count bound has the only applied acknowledgement.
    // Counts and pages share the first `limit` Agents by ID, so it is
    // neither counted nor listed, by prefix or by acknowledgement age.
    let outside = format!("agent-{limit:05}");
    let issuer = issuer();
    db.create_managed_revision(&t, &outside, "r1", "default: deny")
        .unwrap();
    db.approve_managed_revision(&t, &outside, "r1").unwrap();
    let d = db
        .deploy_managed_revision(&t, &outside, "r1", false, &issuer)
        .unwrap();
    ack(&db, &t, &outside, &d, "applied");
    for q in [
        TriageQuery {
            problem: "all".into(),
            prefix: outside.clone(),
            ..Default::default()
        },
        TriageQuery {
            problem: "no_recorded_problem".into(),
            sort: "ack_oldest".into(),
            ..Default::default()
        },
        TriageQuery {
            problem: "all".into(),
            sort: "ack_oldest".into(),
            prefix: "agent-1".into(),
            limit: 100,
            ..Default::default()
        },
    ] {
        let p = page(&db, &t, q.clone()).await;
        assert!(!p.counts.complete);
        assert!(
            p.agents.iter().all(|a| a.agent_id != outside),
            "{q:?} listed an Agent outside the counted universe"
        );
        assert!(p.agents.len() as i64 <= p.counts.matching, "{q:?}");
    }
    // Paging the whole bounded universe by age yields exactly the counted set.
    let mut q = TriageQuery {
        problem: "all".into(),
        sort: "ack_oldest".into(),
        limit: 100,
        ..Default::default()
    };
    let mut seen = 0i64;
    loop {
        let p = page(&db, &t, q.clone()).await;
        assert!(p.agents.iter().all(|a| a.agent_id != outside));
        seen += p.agents.len() as i64;
        let Some(next) = p.next else { break };
        q.after = next.after;
        q.after_ack = next.after_ack;
    }
    assert_eq!(seen, limit);
}

#[tokio::test]
async fn triage_empty_and_unknown_tenant() {
    let db = TenantStore::open(":memory:").unwrap();
    let t = db.create_tenant("empty").unwrap().id;
    let p = page(&db, &t, TriageQuery::default()).await;
    assert!(p.agents.is_empty() && p.next.is_none());
    assert_eq!((p.counts.counted_agents, p.counts.complete), (0, true));
    assert!(db
        .fleet_triage("unknown", TriageQuery::default())
        .await
        .unwrap()
        .is_none());
}
