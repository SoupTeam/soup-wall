// SPDX-License-Identifier: Apache-2.0
//! SOU-220: authoritative cohort preview and guarded start of a group rollout, over real HTTP.
//!
//! The same controls run on a SQLite file and, when `SOUP_COHORT_TEST_POSTGRES_URL` names a
//! disposable database, on PostgreSQL. Deployments, rollouts and confirmations are counted with
//! direct SQL; what an Agent actually receives is read through the Agent endpoint.
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use llm_firewall::handlers::AppState;
use llm_firewall::tenant_store::{
    AdminRole, AppliedReport, ManagedIssuer, StartGuard, TenantStore,
};
use llm_firewall::{app, test_config};
use serde_json::{json, Value};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};

const OWNER: &str = "Bearer admin-test-token";
/// Environment is process-global, so the backends must not interleave.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn set_signers() {
    std::env::set_var("SOUP_AGENT_POLICY_KEY_ID", "cohort-key");
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", "0c".repeat(32));
}

fn issuer() -> ManagedIssuer {
    ManagedIssuer::new("cohort-key".into(), &"0c".repeat(32)).unwrap()
}

async fn migrate_postgres(url: &str) -> anyhow::Result<()> {
    TenantStore::migrate_postgres_with_ca_and_tls(
        url,
        1000,
        Duration::from_secs(10),
        8,
        Duration::from_secs(10),
        None,
        false,
    )
    .await
}

struct Fixture {
    _dir: tempfile::TempDir,
    sqlite: std::path::PathBuf,
    postgres: Option<String>,
}

impl Fixture {
    async fn new(postgres: Option<String>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let sqlite = dir.path().join("console.sqlite");
        if let Some(url) = &postgres {
            migrate_postgres(url).await.unwrap();
        }
        Self {
            _dir: dir,
            sqlite,
            postgres,
        }
    }
    async fn store(&self) -> TenantStore {
        match &self.postgres {
            Some(url) => TenantStore::open_postgres_with_ca_and_tls(
                url,
                1000,
                Duration::from_secs(10),
                8,
                Duration::from_secs(10),
                None,
                false,
            )
            .await
            .unwrap(),
            None => TenantStore::open(&self.sqlite).unwrap(),
        }
    }
    async fn count(&self, sql: &str) -> i64 {
        if let Some(url) = &self.postgres {
            let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
                .await
                .unwrap();
            let task = tokio::spawn(async move { connection.await.unwrap() });
            let value: i64 = client.query_one(sql, &[]).await.unwrap().get(0);
            drop(client);
            task.await.unwrap();
            value
        } else {
            rusqlite::Connection::open(&self.sqlite)
                .unwrap()
                .query_row(sql, [], |r| r.get(0))
                .unwrap()
        }
    }
    async fn sql(&self, sqlite: &str, postgres: &str) {
        if let Some(url) = &self.postgres {
            let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
                .await
                .unwrap();
            let task = tokio::spawn(async move { connection.await.unwrap() });
            client.batch_execute(postgres).await.unwrap();
            drop(client);
            task.await.unwrap();
        } else {
            rusqlite::Connection::open(&self.sqlite)
                .unwrap()
                .execute_batch(sqlite)
                .unwrap();
        }
    }
    async fn deployments(&self, w: &World) -> i64 {
        self.count(&format!(
            "SELECT count(*) FROM managed_agent_deployments WHERE tenant_id='{}'",
            w.tenant
        ))
        .await
    }
    async fn rollouts(&self, w: &World) -> i64 {
        self.count(&format!(
            "SELECT count(*) FROM managed_group_rollouts WHERE tenant_id='{}'",
            w.tenant
        ))
        .await
    }
    async fn confirmations(&self, w: &World, consumed: bool) -> i64 {
        let null = if consumed { "NOT NULL" } else { "NULL" };
        self.count(&format!(
            "SELECT count(*) FROM managed_group_start_confirmations WHERE tenant_id='{}' AND consumed_at_unix IS {null}",
            w.tenant
        ))
        .await
    }
    /// Everything a preview must leave alone, as one comparable value.
    async fn scope_state(&self, w: &World) -> Vec<i64> {
        let t = &w.tenant;
        let mut state = vec![
            self.deployments(w).await,
            self.rollouts(w).await,
            self.count(&format!("SELECT count(*) FROM managed_agent_group_members WHERE tenant_id='{t}'")).await,
            self.count(&format!("SELECT count(*) FROM managed_agent_revisions WHERE tenant_id='{t}'")).await,
            self.count(&format!("SELECT count(*) FROM managed_group_revisions WHERE tenant_id='{t}'")).await,
            self.count(&format!("SELECT COALESCE(max(deployment_sequence),0) FROM managed_agent_deployments WHERE tenant_id='{t}'")).await,
        ];
        state.push(
            self.count(&format!("SELECT count(*) FROM managed_agent_deployments WHERE tenant_id='{t}' AND status<>'applied'"))
                .await,
        );
        state
    }
}

struct Server {
    base: String,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    async fn start(store: TenantStore) -> Self {
        let mut config = test_config("http://127.0.0.1:1".into());
        config.tenant_store.enabled = true;
        let state = Arc::new(AppState {
            firewall: Firewall::new(
                vec![Box::new(InjectionDetector::new())],
                PolicySet::from_yaml("default: allow").unwrap(),
            ),
            http: reqwest::Client::new(),
            openai_api_key: None,
            proxy_auth_token: None,
            tenant_store: Some(
                store
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
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app(state)).await.unwrap();
        });
        Self { base, task }
    }
    async fn kill(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

struct World {
    tenant: String,
    tokens: std::collections::BTreeMap<String, String>,
}

/// One pilot (`p1`), two workers (`w1`, `w2`) in group `fleet`; `w3` and `x1` are enrolled spares.
/// Every Agent has an applied baseline `base`, so no unacknowledged deployment blocks a start.
async fn world(store: &TenantStore, name: &str) -> World {
    let tenant = store
        .create_tenant_async(&format!("{name} {}", rand::random::<u64>()))
        .await
        .unwrap()
        .id;
    store
        .create_managed_group_async(&tenant, "fleet", "Fleet")
        .await
        .unwrap();
    let mut tokens = std::collections::BTreeMap::new();
    for (agent, member) in [
        ("p1", Some(true)),
        ("w1", Some(false)),
        ("w2", Some(false)),
        ("w3", None),
        ("x1", None),
    ] {
        let credential = store
            .enroll_managed_agent_async(&tenant, agent)
            .await
            .unwrap();
        tokens.insert(agent.to_string(), credential.token);
        if let Some(pilot) = member {
            store
                .add_managed_group_member_async(&tenant, "fleet", agent, pilot)
                .await
                .unwrap();
        }
        baseline(store, &tenant, agent).await;
    }
    store
        .create_managed_group_revision_async(&tenant, "fleet", "candidate", "default: deny\n")
        .await
        .unwrap();
    store
        .approve_managed_group_revision_async(&tenant, "fleet", "candidate")
        .await
        .unwrap();
    World { tenant, tokens }
}

async fn baseline(store: &TenantStore, tenant: &str, agent: &str) {
    store
        .create_managed_revision_async(tenant, agent, "base", "default: allow\n")
        .await
        .unwrap();
    store
        .approve_managed_revision_async(tenant, agent, "base")
        .await
        .unwrap();
    let dep = store
        .deploy_managed_revision_async(tenant, agent, "base", false, &issuer())
        .await
        .unwrap();
    ack(
        store,
        tenant,
        agent,
        dep.deployment_sequence,
        "base",
        &dep.policy_sha256,
    )
    .await;
}

async fn ack(
    store: &TenantStore,
    tenant: &str,
    agent: &str,
    sequence: u64,
    revision: &str,
    sha: &str,
) {
    assert!(store
        .acknowledge_managed_bundle_async(
            tenant,
            agent,
            &AppliedReport {
                deployment_sequence: sequence,
                revision: revision.into(),
                policy_sha256: sha.into(),
                status: "applied".into(),
            },
        )
        .await
        .unwrap());
}

async fn call(
    server: &Server,
    w: &World,
    path: &str,
    body: Value,
    header: &str,
) -> (StatusCode, Value) {
    let response = reqwest::Client::new()
        .post(format!(
            "{}/admin/v1/tenants/{}/groups/fleet/rollout{path}",
            server.base, w.tenant
        ))
        .header("x-llm-firewall-admin-token", header)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    (status, response.json().await.unwrap_or(Value::Null))
}

async fn preview(server: &Server, w: &World, header: &str) -> (StatusCode, Value) {
    call(
        server,
        w,
        "/preview",
        json!({"revision": "candidate"}),
        header,
    )
    .await
}

async fn start(
    server: &Server,
    w: &World,
    confirmation: Option<&str>,
    header: &str,
) -> (StatusCode, Value) {
    let mut body = json!({"revision": "candidate"});
    if let Some(id) = confirmation {
        body["confirmation_id"] = json!(id);
    }
    call(server, w, "", body, header).await
}

fn confirmation(preview: &Value) -> String {
    preview["confirmation"]["id"]
        .as_str()
        .expect("startable preview carries a confirmation")
        .to_string()
}

async fn fetch(server: &Server, w: &World, agent: &str) -> Option<Value> {
    let response = reqwest::Client::new()
        .get(format!("{}/agent/v1/policy", server.base))
        .bearer_auth(&w.tokens[agent])
        .send()
        .await
        .unwrap();
    if response.status().as_u16() == 204 {
        return None;
    }
    assert_eq!(response.status().as_u16(), 200);
    Some(response.json().await.unwrap())
}

fn unique(label: &str) -> String {
    format!("{label} {:016x}", rand::random::<u64>())
}

async fn controls(f: &Fixture) {
    let _guard = SERIAL.lock().await;
    set_signers();
    preview_is_authoritative_and_changes_nothing(f).await;
    guarded_start_freezes_the_previewed_cohort_and_replays(f).await;
    drift_returns_conflict_with_zero_deployments(f).await;
    confirmations_are_bound_and_cannot_be_forged_expired_or_reused(f).await;
    authorization_and_unavailable_store(f).await;
    concurrency_and_restart(f).await;
    signer_rotation_requires_a_fresh_preview(f).await;
    actual_issuer_is_checked_inside_guarded_start(f).await;
    legacy_start_is_unchanged(f).await;
}

async fn preview_is_authoritative_and_changes_nothing(f: &Fixture) {
    let store = f.store().await;
    let w = world(&store, "Preview").await;
    let server = Server::start(store.clone()).await;
    let before = f.scope_state(&w).await;
    let (status, p) = preview(&server, &w, OWNER).await;
    assert_eq!(status, StatusCode::OK, "{p}");
    assert_eq!(p["contract_version"], "sw-group-rollout-preview/1");
    assert_eq!(p["executed"], false);
    assert_eq!(p["pilots"], json!(["p1"]));
    assert_eq!(p["workers"], json!(["w1", "w2"]));
    assert_eq!(p["startable"], true);
    assert_eq!(p["blockers"], json!([]));
    let group_revision = store
        .list_managed_group_revisions_async(&w.tenant, "fleet")
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.revision == "candidate")
        .unwrap();
    assert_eq!(p["policy_sha256"], json!(group_revision.policy_sha256));
    assert_eq!(p["approved"], true);
    for agent in p["agents"].as_array().unwrap() {
        assert_eq!(agent["authorized"], true);
        assert_eq!(agent["baseline_revision"], "base");
        assert_eq!(agent["latest_sequence"], 1);
        assert_eq!(agent["latest_status"], "applied");
    }
    assert_eq!(p["agents"].as_array().unwrap().len(), 3);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expires = p["confirmation"]["expires_at_unix"].as_i64().unwrap();
    assert!(
        (now + 290..=now + 310).contains(&expires),
        "bounded five minute lifetime"
    );
    assert_eq!(p["confirmation"]["version"], 1);

    // Nothing but the confirmation record changed: no deployment, rollout, member or revision.
    assert_eq!(f.scope_state(&w).await, before);
    assert_eq!(f.confirmations(&w, false).await, 1);
    assert!(
        fetch(&server, &w, "p1").await.is_none(),
        "an Agent receives nothing from a preview"
    );

    // A second preview of the same scope has the same snapshot and replaces the first confirmation.
    let first = confirmation(&p);
    let (_, again) = preview(&server, &w, OWNER).await;
    assert_eq!(again["snapshot_sha256"], p["snapshot_sha256"]);
    assert_ne!(confirmation(&again), first);
    assert_eq!(
        f.confirmations(&w, false).await,
        1,
        "one outstanding confirmation per administrator and group"
    );
    let (status, refused) = start(&server, &w, Some(&first), OWNER).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refused["code"], "confirmation_invalid");
    assert_eq!(f.scope_state(&w).await, before);

    // An unapproved or unknown revision, and a blocked scope, offer no confirmation at all.
    let (status, unknown) = call(
        &server,
        &w,
        "/preview",
        json!({"revision": "missing"}),
        OWNER,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(unknown["startable"], false);
    assert!(unknown["confirmation"].is_null());
    assert_eq!(unknown["blockers"][0]["code"], "revision_not_approved");
    store
        .deploy_managed_revision_async(&w.tenant, "w1", "base", false, &issuer())
        .await
        .unwrap();
    let (_, blocked) = preview(&server, &w, OWNER).await;
    assert_eq!(blocked["startable"], false);
    assert!(blocked["confirmation"].is_null());
    assert!(blocked["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|b| b["code"] == "unacknowledged_deployment" && b["agent_id"] == "w1"));
    let (status, _) = start(
        &server,
        &w,
        Some("swc1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        OWNER,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(f.rollouts(&w).await, 0);
    server.kill().await;
}

async fn guarded_start_freezes_the_previewed_cohort_and_replays(f: &Fixture) {
    let store = f.store().await;
    let w = world(&store, "Guarded").await;
    let server = Server::start(store.clone()).await;
    let (_, p) = preview(&server, &w, OWNER).await;
    let id = confirmation(&p);
    let deployments_before = f.deployments(&w).await;

    let (status, started) = start(&server, &w, Some(&id), OWNER).await;
    assert_eq!(status, StatusCode::CREATED, "{started}");
    assert_eq!(started["confirmation"]["replayed"], false);
    assert_eq!(started["pilot_agents"], p["pilots"]);
    assert_eq!(started["standard_agents"], p["workers"]);
    assert_eq!(started["policy_sha256"], p["policy_sha256"]);
    assert_eq!(started["previous_revisions"]["p1"], "base");
    // Only the pilot wave is issued, and the pilot actually receives the previewed digest.
    assert_eq!(f.deployments(&w).await, deployments_before + 1);
    assert_eq!(f.rollouts(&w).await, 1);
    let bundle = fetch(&server, &w, "p1")
        .await
        .expect("pilot receives its deployment");
    assert_eq!(bundle["policy_sha256"], p["policy_sha256"]);
    assert!(fetch(&server, &w, "w1").await.is_none());
    assert_eq!(f.confirmations(&w, true).await, 1);
    assert_eq!(f.confirmations(&w, false).await, 0);

    // The response was lost: the retry reconciles to the same rollout and issues nothing.
    let rollout_id = started["rollout_id"].clone();
    for _ in 0..3 {
        let (status, again) = start(&server, &w, Some(&id), OWNER).await;
        assert_eq!(status, StatusCode::CREATED, "{again}");
        assert_eq!(again["confirmation"]["replayed"], true);
        assert_eq!(again["rollout_id"], rollout_id);
    }
    assert_eq!(f.deployments(&w).await, deployments_before + 1);
    assert_eq!(f.rollouts(&w).await, 1);

    server.kill().await;
}

#[derive(Clone, Copy, Debug)]
enum Drift {
    MemberAdded,
    MemberRemoved,
    PilotChanged,
    AgentRevoked,
    BaselineChanged,
    SequenceAdvanced,
    OtherRolloutClaimsAgent,
    SameGroupRolloutStarted,
}

async fn drift_returns_conflict_with_zero_deployments(f: &Fixture) {
    for drift in [
        Drift::MemberAdded,
        Drift::MemberRemoved,
        Drift::PilotChanged,
        Drift::AgentRevoked,
        Drift::BaselineChanged,
        Drift::SequenceAdvanced,
        Drift::OtherRolloutClaimsAgent,
        Drift::SameGroupRolloutStarted,
    ] {
        let store = f.store().await;
        let w = world(&store, "Drift").await;
        let server = Server::start(store.clone()).await;
        let (_, p) = preview(&server, &w, OWNER).await;
        let id = confirmation(&p);
        match drift {
            Drift::MemberAdded => {
                store
                    .add_managed_group_member_async(&w.tenant, "fleet", "w3", false)
                    .await
                    .unwrap();
            }
            Drift::MemberRemoved => {
                store
                    .remove_managed_group_member_async(&w.tenant, "fleet", "w2")
                    .await
                    .unwrap();
            }
            Drift::PilotChanged => {
                store
                    .add_managed_group_member_async(&w.tenant, "fleet", "w1", true)
                    .await
                    .unwrap();
            }
            Drift::AgentRevoked => {
                store
                    .revoke_managed_agent_async(&w.tenant, "w2")
                    .await
                    .unwrap();
            }
            Drift::BaselineChanged => {
                store
                    .create_managed_revision_async(&w.tenant, "w1", "next", "default: deny\n")
                    .await
                    .unwrap();
                store
                    .approve_managed_revision_async(&w.tenant, "w1", "next")
                    .await
                    .unwrap();
                let dep = store
                    .deploy_managed_revision_async(&w.tenant, "w1", "next", false, &issuer())
                    .await
                    .unwrap();
                ack(
                    &store,
                    &w.tenant,
                    "w1",
                    dep.deployment_sequence,
                    "next",
                    &dep.policy_sha256,
                )
                .await;
            }
            Drift::SequenceAdvanced => {
                store
                    .deploy_managed_revision_async(&w.tenant, "w2", "base", false, &issuer())
                    .await
                    .unwrap();
            }
            Drift::OtherRolloutClaimsAgent => {
                store
                    .create_managed_group_async(&w.tenant, "other", "Other")
                    .await
                    .unwrap();
                store
                    .add_managed_group_member_async(&w.tenant, "other", "w1", true)
                    .await
                    .unwrap();
                store
                    .create_managed_group_revision_async(&w.tenant, "other", "r", "default: deny\n")
                    .await
                    .unwrap();
                store
                    .approve_managed_group_revision_async(&w.tenant, "other", "r")
                    .await
                    .unwrap();
                store
                    .start_managed_group_rollout_async(&w.tenant, "other", "r", &issuer())
                    .await
                    .unwrap();
            }
            Drift::SameGroupRolloutStarted => {
                store
                    .start_managed_group_rollout_async(&w.tenant, "fleet", "candidate", &issuer())
                    .await
                    .unwrap();
            }
        }
        let deployments = f.deployments(&w).await;
        let rollouts = f.rollouts(&w).await;
        let sequence = f.scope_state(&w).await;
        let (status, refused) = start(&server, &w, Some(&id), OWNER).await;
        assert_eq!(status, StatusCode::CONFLICT, "{drift:?}: {refused}");
        assert_eq!(
            refused["code"], "confirmation_stale",
            "{drift:?}: {refused}"
        );
        assert_eq!(
            f.deployments(&w).await,
            deployments,
            "{drift:?} issued a policy"
        );
        assert_eq!(
            f.rollouts(&w).await,
            rollouts,
            "{drift:?} created a rollout"
        );
        assert_eq!(f.scope_state(&w).await, sequence, "{drift:?} changed state");
        assert_eq!(
            f.confirmations(&w, true).await,
            0,
            "{drift:?} consumed the confirmation"
        );

        // The Console's remedy: ask the server again and review. A clean scope then starts exactly
        // what the new preview says.
        if matches!(
            drift,
            Drift::AgentRevoked
                | Drift::OtherRolloutClaimsAgent
                | Drift::SameGroupRolloutStarted
                | Drift::SequenceAdvanced
        ) {
            let (_, fresh) = preview(&server, &w, OWNER).await;
            assert_eq!(fresh["startable"], false, "{drift:?} must remain blocked");
            assert!(fresh["confirmation"].is_null());
        } else {
            let (_, fresh) = preview(&server, &w, OWNER).await;
            assert_eq!(fresh["startable"], true, "{drift:?}: {fresh}");
            assert_ne!(fresh["snapshot_sha256"], p["snapshot_sha256"]);
            let fresh_id = confirmation(&fresh);
            let (status, started) = start(&server, &w, Some(&fresh_id), OWNER).await;
            assert_eq!(status, StatusCode::CREATED, "{drift:?}: {started}");
            assert_eq!(started["pilot_agents"], fresh["pilots"]);
            assert_eq!(started["standard_agents"], fresh["workers"]);
            assert_eq!(
                f.deployments(&w).await,
                deployments + fresh["pilots"].as_array().unwrap().len() as i64
            );
        }
        server.kill().await;
    }
}

async fn confirmations_are_bound_and_cannot_be_forged_expired_or_reused(f: &Fixture) {
    let store = f.store().await;
    let w = world(&store, "Binding").await;
    let foreign = world(&store, "Foreign").await;
    let second = store
        .create_admin_async(&unique("Second owner"), AdminRole::Owner)
        .await
        .unwrap();
    let second_header = format!("Bearer {}", second.token);
    let server = Server::start(store.clone()).await;
    let (_, p) = preview(&server, &w, OWNER).await;
    let id = confirmation(&p);
    let state = f.scope_state(&w).await;

    // Another administrator, another tenant, another revision or signer, malformed and forged ids.
    let mut forged_tail = id.clone();
    forged_tail.pop();
    forged_tail.push(if id.ends_with('A') { 'B' } else { 'A' });
    for (label, target, token, header) in [
        (
            "other administrator",
            &w,
            id.as_str(),
            second_header.as_str(),
        ),
        ("other tenant", &foreign, id.as_str(), OWNER),
        ("forged tail", &w, forged_tail.as_str(), OWNER),
        ("not an identity", &w, "swc1_short", OWNER),
        (
            "random identity",
            &w,
            "swc1_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            OWNER,
        ),
    ] {
        let (status, body) = start(&server, target, Some(token), header).await;
        assert_eq!(status, StatusCode::CONFLICT, "{label}");
        assert_eq!(body["code"], "confirmation_invalid", "{label}");
    }
    let (status, body) = call(
        &server,
        &w,
        "",
        json!({"revision": "candidate", "confirmation_id": id, "issuer_key_id": "cohort-key"}),
        OWNER,
    )
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::CONFLICT, json!("confirmation_invalid")),
        "different requested signer"
    );
    let (status, body) = call(
        &server,
        &w,
        "",
        json!({"revision": "base", "confirmation_id": id}),
        OWNER,
    )
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::CONFLICT, json!("confirmation_invalid")),
        "different revision"
    );
    assert_eq!(f.scope_state(&w).await, state);
    assert_eq!(f.scope_state(&foreign).await[1], 0);
    assert_eq!(
        f.confirmations(&w, true).await,
        0,
        "no failed attempt consumes the confirmation"
    );

    // Expiry is enforced from the stored record, not from anything the client sends.
    f.sql(
        &format!(
            "UPDATE managed_group_start_confirmations SET expires_at_unix=1 WHERE tenant_id='{}'",
            w.tenant
        ),
        &format!(
            "UPDATE managed_group_start_confirmations SET expires_at_unix=1 WHERE tenant_id='{}'",
            w.tenant
        ),
    )
    .await;
    let (status, body) = start(&server, &w, Some(&id), OWNER).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::CONFLICT, json!("confirmation_expired"))
    );
    assert_eq!(f.scope_state(&w).await, state);

    // A used confirmation cannot start a second rollout, even after the first completed.
    let (_, fresh) = preview(&server, &w, OWNER).await;
    let used = confirmation(&fresh);
    let (status, first) = start(&server, &w, Some(&used), OWNER).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let rollout_id = first["rollout_id"].as_str().unwrap().to_string();
    let plan = store
        .get_managed_group_rollout_async(&w.tenant, "fleet")
        .await
        .unwrap()
        .unwrap();
    for pilot in &plan.pilot_agents {
        let dep = store
            .list_managed_deployments_async(&w.tenant, pilot)
            .await
            .unwrap()
            .remove(0);
        ack(
            &store,
            &w.tenant,
            pilot,
            dep.deployment_sequence,
            &dep.revision,
            &dep.policy_sha256,
        )
        .await;
    }
    store
        .advance_managed_group_rollout_async(&w.tenant, "fleet", Some(&issuer()))
        .await
        .unwrap();
    let plan = store
        .get_managed_group_rollout_async(&w.tenant, "fleet")
        .await
        .unwrap()
        .unwrap();
    for worker in &plan.standard_agents {
        let dep = store
            .list_managed_deployments_async(&w.tenant, worker)
            .await
            .unwrap()
            .remove(0);
        ack(
            &store,
            &w.tenant,
            worker,
            dep.deployment_sequence,
            &dep.revision,
            &dep.policy_sha256,
        )
        .await;
    }
    store
        .advance_managed_group_rollout_async(&w.tenant, "fleet", Some(&issuer()))
        .await
        .unwrap();
    let completed = store
        .get_managed_group_rollout_async(&w.tenant, "fleet")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.phase.as_str(), "completed");
    store
        .create_managed_group_revision_async(&w.tenant, "fleet", "second", "default: allow\n")
        .await
        .unwrap();
    store
        .approve_managed_group_revision_async(&w.tenant, "fleet", "second")
        .await
        .unwrap();
    let rollouts = f.rollouts(&w).await;
    let deployments = f.deployments(&w).await;
    let (status, body) = call(
        &server,
        &w,
        "",
        json!({"revision": "second", "confirmation_id": used}),
        OWNER,
    )
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::CONFLICT, json!("confirmation_invalid")),
        "reuse for another revision"
    );
    // For its own revision it can only ever reconcile to the rollout it started; nothing new is issued.
    let (status, body) = start(&server, &w, Some(&used), OWNER).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["rollout_id"], json!(rollout_id));
    assert_eq!(body["confirmation"]["replayed"], true);
    assert_eq!(f.rollouts(&w).await, rollouts);
    assert_eq!(f.deployments(&w).await, deployments);
    // Once a different rollout has replaced it, the old confirmation reconciles to nothing.
    store
        .start_managed_group_rollout_async(&w.tenant, "fleet", "second", &issuer())
        .await
        .unwrap();
    let rollouts = f.rollouts(&w).await;
    let deployments = f.deployments(&w).await;
    let (status, body) = start(&server, &w, Some(&used), OWNER).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::CONFLICT, json!("confirmation_invalid")),
        "reuse after replacement"
    );
    assert_eq!(f.rollouts(&w).await, rollouts);
    assert_eq!(f.deployments(&w).await, deployments);
    server.kill().await;
}

async fn authorization_and_unavailable_store(f: &Fixture) {
    let store = f.store().await;
    let w = world(&store, "Authorization").await;
    let owner = store
        .create_admin_async(&unique("Revocable owner"), AdminRole::Owner)
        .await
        .unwrap();
    let operator = store
        .create_admin_async(&unique("Operator"), AdminRole::Operator)
        .await
        .unwrap();
    let viewer = store
        .create_admin_async(&unique("Viewer"), AdminRole::Viewer)
        .await
        .unwrap();
    let owner_header = format!("Bearer {}", owner.token);
    let server = Server::start(store.clone()).await;
    let before = f.scope_state(&w).await;

    for (label, header, expected) in [
        (
            "viewer",
            format!("Bearer {}", viewer.token),
            StatusCode::FORBIDDEN,
        ),
        (
            "operator",
            format!("Bearer {}", operator.token),
            StatusCode::FORBIDDEN,
        ),
        (
            "unknown",
            "Bearer nope".to_string(),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let (status, body) = preview(&server, &w, &header).await;
        assert_eq!(status, expected, "{label}: {body}");
        assert!(body.get("confirmation").is_none(), "{label}");
        let (status, _) = start(
            &server,
            &w,
            Some("swc1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &header,
        )
        .await;
        assert_eq!(status, expected, "{label} start");
    }
    assert_eq!(f.confirmations(&w, false).await, 0);

    // A revoked Owner: refused by the middleware, and again by the store inside its transaction.
    let (_, p) = preview(&server, &w, &owner_header).await;
    let id = confirmation(&p);
    store.revoke_admin_async(&owner.admin.id).await.unwrap();
    let (status, _) = start(&server, &w, Some(&id), &owner_header).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for result in [
        store
            .start_managed_group_rollout_guarded_async(
                &w.tenant,
                "fleet",
                "candidate",
                Some(&issuer()),
                &StartGuard {
                    confirmation_id: &id,
                    admin_id: &owner.admin.id,
                    requested_issuer_key: None,
                },
            )
            .await
            .map(|_| ()),
        store
            .preview_managed_group_start_async(
                &w.tenant,
                "fleet",
                "candidate",
                &owner.admin.id,
                None,
            )
            .await
            .map(|_| ()),
    ] {
        assert!(result.is_err(), "revoked administrator reached the store");
    }
    assert_eq!(f.scope_state(&w).await, before);

    // A tenant that is no longer active, and a group that does not exist.
    let inactive = world(&store, "Inactive").await;
    let (_, p) = preview(&server, &inactive, OWNER).await;
    let id = confirmation(&p);
    store
        .set_tenant_active_async(&inactive.tenant, false)
        .await
        .unwrap();
    let (status, _) = preview(&server, &inactive, OWNER).await;
    assert!(status.is_client_error(), "{status}");
    let (status, _) = start(&server, &inactive, Some(&id), OWNER).await;
    assert!(status.is_client_error(), "{status}");
    assert_eq!(f.rollouts(&inactive).await, 0);
    let response = reqwest::Client::new()
        .post(format!(
            "{}/admin/v1/tenants/{}/groups/nope/rollout/preview",
            server.base, w.tenant
        ))
        .header("x-llm-firewall-admin-token", OWNER)
        .json(&json!({"revision": "candidate"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);

    // The store cannot record the confirmation: the preview fails and records nothing new.
    let outstanding = f.confirmations(&w, false).await;
    f.sql(
        "CREATE TRIGGER fail_confirmation BEFORE INSERT ON managed_group_start_confirmations BEGIN SELECT RAISE(ABORT,'injected persistence failure'); END;",
        "CREATE OR REPLACE FUNCTION fail_confirmation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected persistence failure'; END $$; CREATE TRIGGER fail_confirmation BEFORE INSERT ON managed_group_start_confirmations FOR EACH ROW EXECUTE FUNCTION fail_confirmation();",
    )
    .await;
    let (status, _) = preview(&server, &w, OWNER).await;
    assert!(status.is_client_error() || status.is_server_error());
    f.sql(
        "DROP TRIGGER fail_confirmation;",
        "DROP TRIGGER fail_confirmation ON managed_group_start_confirmations;",
    )
    .await;
    assert_eq!(f.confirmations(&w, false).await, outstanding);

    // The store cannot record the consumption: the whole start rolls back and stays resumable.
    let (_, p) = preview(&server, &w, OWNER).await;
    let id = confirmation(&p);
    f.sql(
        "CREATE TRIGGER fail_consume BEFORE UPDATE ON managed_group_start_confirmations BEGIN SELECT RAISE(ABORT,'injected persistence failure'); END;",
        "CREATE OR REPLACE FUNCTION fail_consume() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected persistence failure'; END $$; CREATE TRIGGER fail_consume BEFORE UPDATE ON managed_group_start_confirmations FOR EACH ROW EXECUTE FUNCTION fail_consume();",
    )
    .await;
    let (status, _) = start(&server, &w, Some(&id), OWNER).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        f.scope_state(&w).await,
        before,
        "no policy, rollout or revision survived the failed start"
    );
    assert!(fetch(&server, &w, "p1").await.is_none());
    f.sql(
        "DROP TRIGGER fail_consume;",
        "DROP TRIGGER fail_consume ON managed_group_start_confirmations;",
    )
    .await;
    let (status, started) = start(&server, &w, Some(&id), OWNER).await;
    assert_eq!(status, StatusCode::CREATED, "{started}");
    assert_eq!(f.rollouts(&w).await, 1);
    server.kill().await;
}

async fn concurrency_and_restart(f: &Fixture) {
    let store = f.store().await;
    let w = Arc::new(world(&store, "Concurrency").await);
    let second = store
        .create_admin_async(&unique("Competing owner"), AdminRole::Owner)
        .await
        .unwrap();
    let second_header = format!("Bearer {}", second.token);
    let server = Arc::new(Server::start(store.clone()).await);

    // One confirmation, many simultaneous starts: one issuance, the rest reconcile to it.
    let (_, p) = preview(&server, &w, OWNER).await;
    let id = confirmation(&p);
    let before = f.deployments(&w).await;
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let (server, w, id) = (server.clone(), w.clone(), id.clone());
        set.spawn(async move { start(&server, &w, Some(&id), OWNER).await });
    }
    let (mut fresh, mut replayed) = (0, 0);
    while let Some(result) = set.join_next().await {
        let (status, body) = result.unwrap();
        assert_eq!(status, StatusCode::CREATED, "{body}");
        if body["confirmation"]["replayed"] == true {
            replayed += 1
        } else {
            fresh += 1
        }
    }
    assert_eq!((fresh, replayed), (1, 11));
    assert_eq!(
        f.deployments(&w).await,
        before + 1,
        "exactly the pilot wave, once"
    );
    assert_eq!(f.rollouts(&w).await, 1);

    // Two administrators race for the same group: exactly one rollout is created.
    let racing = Arc::new(world(&store, "Race").await);
    let (_, a) = preview(&server, &racing, OWNER).await;
    let (_, b) = preview(&server, &racing, &second_header).await;
    let (ia, ib) = (confirmation(&a), confirmation(&b));
    let before = f.deployments(&racing).await;
    let (ra, rb) = tokio::join!(
        start(&server, &racing, Some(&ia), OWNER),
        start(&server, &racing, Some(&ib), &second_header)
    );
    let created = [ra.0, rb.0]
        .iter()
        .filter(|s| **s == StatusCode::CREATED)
        .count();
    let conflicts = [ra.0, rb.0]
        .iter()
        .filter(|s| **s == StatusCode::CONFLICT)
        .count();
    assert_eq!((created, conflicts), (1, 1), "{:?} {:?}", ra, rb);
    assert_eq!(f.rollouts(&racing).await, 1);
    assert_eq!(f.deployments(&racing).await, before + 1);

    // Restart: a confirmation survives a crash before the start, and its outcome survives after it.
    let restarted_world = world(&store, "Restart").await;
    let (_, p) = preview(&server, &restarted_world, OWNER).await;
    let id = confirmation(&p);
    Arc::try_unwrap(server).ok().unwrap().kill().await;
    let server = Server::start(f.store().await).await;
    let (status, started) = start(&server, &restarted_world, Some(&id), OWNER).await;
    assert_eq!(status, StatusCode::CREATED, "{started}");
    let count = f.deployments(&restarted_world).await;
    server.kill().await;
    let server = Server::start(f.store().await).await;
    let (status, again) = start(&server, &restarted_world, Some(&id), OWNER).await;
    assert_eq!(status, StatusCode::CREATED, "{again}");
    assert_eq!(again["confirmation"]["replayed"], true);
    assert_eq!(again["rollout_id"], started["rollout_id"]);
    assert_eq!(f.deployments(&restarted_world).await, count);
    server.kill().await;
}

/// Exercise the original review reproduction over TCP and a reopened persistent store.
/// Include same-ID key material rotation and explicitly selected non-default issuers.
async fn signer_rotation_requires_a_fresh_preview(f: &Fixture) {
    for (label, requested, next_id, next_seed) in [
        ("default-id", None, "new-unpreviewed-key", "0d"),
        ("default-material", None, "cohort-key", "0d"),
        ("explicit-default", Some("cohort-key"), "cohort-key", "0d"),
        ("named-material", Some("named-key"), "cohort-key", "0c"),
    ] {
        set_signers();
        std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX_NAMED_KEY", "0e".repeat(32));
        let store = f.store().await;
        let w = world(&store, label).await;
        let server = Server::start(store).await;
        let body = json!({"revision": "candidate", "issuer_key_id": requested});
        let (status, original) = call(&server, &w, "/preview", body.clone(), OWNER).await;
        assert_eq!(status, StatusCode::OK, "{original}");
        let selected_id = requested.unwrap_or("cohort-key");
        assert_eq!(original["resolved_signer"]["issuer_key_id"], selected_id);
        let original_issuer = ManagedIssuer::new(
            selected_id.into(),
            &if requested == Some("named-key") {
                "0e"
            } else {
                "0c"
            }
            .repeat(32),
        )
        .unwrap();
        let expected_sha = {
            use sha2::{Digest, Sha256};
            // Decode only the public key. Secret material must never enter the preview.
            let public = original_issuer.public_key_hex();
            let bytes: Vec<u8> = (0..public.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&public[i..i + 2], 16).unwrap())
                .collect();
            format!("{:x}", Sha256::digest(bytes))
        };
        assert_eq!(
            original["resolved_signer"]["public_key_sha256"],
            expected_sha
        );
        let id = confirmation(&original);
        let before = f.scope_state(&w).await;
        server.kill().await;
        std::env::set_var("SOUP_AGENT_POLICY_KEY_ID", next_id);
        std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", next_seed.repeat(32));
        if requested == Some("named-key") {
            std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX_NAMED_KEY", "0f".repeat(32));
        }
        let server = Server::start(f.store().await).await;
        let guarded =
            json!({"revision": "candidate", "issuer_key_id": requested, "confirmation_id": id});
        let (status, rejected) = call(&server, &w, "", guarded.clone(), OWNER).await;
        assert_eq!(status, StatusCode::CONFLICT, "{label}: {rejected}");
        assert_eq!(rejected["code"], "confirmation_stale", "{rejected}");
        assert_eq!(
            f.scope_state(&w).await,
            before,
            "no issuance/revision/sequence/rollout drift"
        );
        assert_eq!(f.confirmations(&w, true).await, 0);
        assert_eq!(f.confirmations(&w, false).await, 1);
        // A fresh preview authorizes the newly selected public identity; it
        // must not silently fall back to the previous/default signer.
        let fresh_world = world(&f.store().await, "Fresh signer preview").await;
        let (status, fresh) = call(&server, &fresh_world, "/preview", body.clone(), OWNER).await;
        assert_eq!(status, StatusCode::OK, "{fresh}");
        assert_ne!(fresh["resolved_signer"], original["resolved_signer"]);
        let (status, fresh_started) = call(&server, &fresh_world, "",
            json!({"revision": "candidate", "issuer_key_id": requested, "confirmation_id": confirmation(&fresh)}), OWNER).await;
        assert_eq!(status, StatusCode::CREATED, "{fresh_started}");
        let fresh_envelope = fetch(&server, &fresh_world, "p1").await.unwrap();
        assert_eq!(
            fresh_envelope["issuer_key_id"],
            fresh["resolved_signer"]["issuer_key_id"]
        );
        assert_eq!(f.rollouts(&fresh_world).await, 1);
        // Staleness does not consume the confirmation: restoring the exact old
        // signer still allows it, without issuing a new preview.
        set_signers();
        std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX_NAMED_KEY", "0e".repeat(32));
        let (status, started) = call(&server, &w, "", guarded.clone(), OWNER).await;
        assert_eq!(status, StatusCode::CREATED, "{label}: {started}");
        let envelope = fetch(&server, &w, "p1").await.unwrap();
        assert_eq!(envelope["issuer_key_id"], selected_id, "{envelope}");
        assert_eq!(f.deployments(&w).await, before[0] + 1);
        let issued = f.deployments(&w).await;
        server.kill().await;
        // A consumed confirmation is reconciliation, not issuance: no signer
        // is necessary, even after expiry or a restart/rotation.
        std::env::remove_var("SOUP_AGENT_POLICY_SEED_HEX");
        std::env::remove_var("SOUP_AGENT_POLICY_SEED_HEX_NAMED_KEY");
        let server = Server::start(f.store().await).await;
        let (status, replayed) = call(&server, &w, "", guarded, OWNER).await;
        assert_eq!(status, StatusCode::CREATED, "{replayed}");
        assert_eq!(replayed["confirmation"]["replayed"], true);
        assert_eq!(replayed["rollout_id"], started["rollout_id"]);
        assert_eq!(f.deployments(&w).await, issued);
        server.kill().await;
    }
    set_signers();
}

/// The caller may have captured an issuer before acquiring the store lease.
/// Guard the actual issuer reference, never an unrelated re-read of environment.
async fn actual_issuer_is_checked_inside_guarded_start(f: &Fixture) {
    set_signers();
    let store = f.store().await;
    let w = world(&store, "Actual issuer").await;
    let p = store
        .preview_managed_group_start_async(&w.tenant, "fleet", "candidate", "bootstrap_owner", None)
        .await
        .unwrap();
    let id = p.confirmation.unwrap().id;
    let before = f.scope_state(&w).await;
    let guard = StartGuard {
        confirmation_id: &id,
        admin_id: "bootstrap_owner",
        requested_issuer_key: None,
    };
    for actual in [
        ManagedIssuer::new("cohort-key".into(), &"0d".repeat(32)).unwrap(),
        ManagedIssuer::new("other-key".into(), &"0c".repeat(32)).unwrap(),
    ] {
        let error = store
            .start_managed_group_rollout_guarded_async(
                &w.tenant,
                "fleet",
                "candidate",
                Some(&actual),
                &guard,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<llm_firewall::tenant_store::ConfirmationRefused>()
                .unwrap()
                .code(),
            "confirmation_stale"
        );
        assert_eq!(f.scope_state(&w).await, before);
    }
    assert!(store
        .start_managed_group_rollout_guarded_async(
            &w.tenant,
            "fleet",
            "candidate",
            Some(&issuer()),
            &guard
        )
        .await
        .is_ok());
}

async fn legacy_start_is_unchanged(f: &Fixture) {
    let store = f.store().await;
    let w = world(&store, "Legacy").await;
    let server = Server::start(store).await;
    let before = f.deployments(&w).await;
    let (status, started) = start(&server, &w, None, OWNER).await;
    assert_eq!(status, StatusCode::CREATED, "{started}");
    assert!(
        started.get("confirmation").is_none(),
        "an unguarded start carries no confirmation"
    );
    assert_eq!(f.deployments(&w).await, before + 1);
    // The unguarded call is idempotent exactly as before.
    let (status, again) = start(&server, &w, None, OWNER).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(again["rollout_id"], started["rollout_id"]);
    assert_eq!(f.deployments(&w).await, before + 1);
    server.kill().await;
}

/// The integrated history is 28 -> deployment keys 29 -> confirmations 30.
/// An experimental database that reused 29 for confirmations is not that history.
async fn postgres_migration_history(f: &Fixture) {
    let url = f.postgres.as_ref().unwrap();
    f.sql(
        "SELECT 1",
        "DROP TABLE managed_group_start_confirmations;
        DROP TABLE managed_agent_deployment_keys;
        DELETE FROM llm_firewall_schema_migrations WHERE version IN (29,30);",
    )
    .await;
    migrate_postgres(url).await.unwrap();
    assert_eq!(
        f.count("SELECT count(*) FROM llm_firewall_schema_migrations WHERE version IN (29,30)")
            .await,
        2
    );
    assert_eq!(f.count("SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ('managed_agent_deployment_keys','managed_group_start_confirmations')").await, 2);

    // Accepted version29 data must survive upgrading to the confirmation schema.
    let store = f.store().await;
    let w = world(&store, "Migration history").await;
    drop(store);
    f.sql("SELECT 1", &format!(
        "INSERT INTO managed_agent_deployment_keys
            (tenant_id,agent_id,idempotency_key,admin_id,intent_digest,deployment_sequence,created_at_unix)
         SELECT tenant_id,agent_id,'integration-migration-retained','bootstrap_owner',
            decode(repeat('ab',32),'hex'),deployment_sequence,issued_at_unix
         FROM managed_agent_deployments WHERE tenant_id='{}' AND agent_id='p1';
         DROP TABLE managed_group_start_confirmations;
         DELETE FROM llm_firewall_schema_migrations WHERE version=30;", w.tenant))
        .await;
    migrate_postgres(url).await.unwrap();
    assert_eq!(f.count(&format!("SELECT count(*) FROM managed_agent_deployment_keys WHERE tenant_id='{}' AND idempotency_key='integration-migration-retained'", w.tenant)).await, 1);
    assert_eq!(
        f.count("SELECT count(*) FROM llm_firewall_schema_migrations WHERE version IN (29,30)")
            .await,
        2
    );

    // Preserve the incompatible ledger on refusal. A later explicit correction
    // is required, rather than recording30 while silently missing version29 data.
    f.sql(
        "SELECT 1",
        "DROP TABLE managed_agent_deployment_keys;
        DELETE FROM llm_firewall_schema_migrations WHERE version=30;",
    )
    .await;
    let error = migrate_postgres(url).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("migration 29 deployment-key table is missing"),
        "{error:#}"
    );
    assert_eq!(
        f.count("SELECT count(*) FROM llm_firewall_schema_migrations WHERE version=29")
            .await,
        1
    );
    assert_eq!(
        f.count("SELECT count(*) FROM llm_firewall_schema_migrations WHERE version=30")
            .await,
        0
    );
    assert_eq!(f.count("SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename='managed_agent_deployment_keys'").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename='managed_group_start_confirmations'").await, 1);

    // Restore only this disposable test database before the HTTP controls.
    f.sql(
        "SELECT 1",
        "DROP TABLE managed_group_start_confirmations;
        DELETE FROM llm_firewall_schema_migrations WHERE version=29;",
    )
    .await;
    migrate_postgres(url).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_cohort_confirmation_over_http() {
    controls(&Fixture::new(None).await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable SOUP_COHORT_TEST_POSTGRES_URL database"]
async fn postgres_cohort_confirmation_over_http() {
    let fixture = Fixture::new(Some(
        std::env::var("SOUP_COHORT_TEST_POSTGRES_URL").expect("disposable database URL"),
    ))
    .await;
    postgres_migration_history(&fixture).await;
    controls(&fixture).await;
}
