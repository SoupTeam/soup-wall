// SPDX-License-Identifier: Apache-2.0
//! SOU-219: retry-safe individual managed deployment issuance over real HTTP.
//!
//! The same controls run on a SQLite file and, when `SOUP_DEPLOY_TEST_POSTGRES_URL` names a
//! disposable database, on PostgreSQL. Issued rows, keys and observed Agent deliveries are counted
//! with direct database queries and the Agent fetch endpoint, not with the API under test.
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use llm_firewall::handlers::AppState;
use llm_firewall::tenant_store::{AdminRole, TenantStore};
use llm_firewall::{app, test_config};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
use tokio::io::AsyncWriteExt;

const OWNER: &str = "Bearer admin-test-token";
const KEY_ID: &str = "idempotency-key-a";
const OTHER_KEY_ID: &str = "idempotency-key-b";
/// Environment is process-global, so the backends must not interleave.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn set_signers() {
    std::env::set_var("SOUP_AGENT_POLICY_KEY_ID", KEY_ID);
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", "0a".repeat(32));
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
            .unwrap();
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
    /// Independent integer query: SQLite and PostgreSQL spellings are supplied by the caller.
    async fn count(&self, sqlite: &str, postgres: &str) -> i64 {
        if let Some(url) = &self.postgres {
            let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
                .await
                .unwrap();
            let task = tokio::spawn(async move { connection.await.unwrap() });
            let value: i64 = client.query_one(postgres, &[]).await.unwrap().get(0);
            drop(client);
            task.await.unwrap();
            value
        } else {
            rusqlite::Connection::open(&self.sqlite)
                .unwrap()
                .query_row(sqlite, [], |r| r.get(0))
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
    async fn deployments(&self, tenant: &str) -> i64 {
        let q =
            format!("SELECT count(*) FROM managed_agent_deployments WHERE tenant_id='{tenant}'");
        self.count(&q, &q).await
    }
    async fn keys(&self, tenant: &str) -> i64 {
        let q = format!(
            "SELECT count(*) FROM managed_agent_deployment_keys WHERE tenant_id='{tenant}'"
        );
        self.count(&q, &q).await
    }
    async fn max_sequence(&self, tenant: &str) -> i64 {
        let q = format!(
            "SELECT COALESCE(max(deployment_sequence),0) FROM managed_agent_deployments WHERE tenant_id='{tenant}'"
        );
        self.count(&q, &q).await
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
    /// Simulates a Console crash: in-flight work is abandoned without any shutdown step.
    async fn kill(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

struct Audience {
    tenant: String,
    agent: String,
    token: String,
}

async fn audience(store: &TenantStore, name: &str) -> Audience {
    let tenant = store
        .create_tenant_async(&format!("{name} {}", rand::random::<u64>()))
        .await
        .unwrap();
    let credential = store
        .enroll_managed_agent_async(&tenant.id, "agent-a")
        .await
        .unwrap();
    for (revision, yaml) in [("r1", "default: allow\n"), ("r2", "default: deny\n")] {
        store
            .create_managed_revision_async(&tenant.id, "agent-a", revision, yaml)
            .await
            .unwrap();
        store
            .approve_managed_revision_async(&tenant.id, "agent-a", revision)
            .await
            .unwrap();
    }
    Audience {
        tenant: tenant.id,
        agent: "agent-a".into(),
        token: credential.token,
    }
}

async fn post(
    server: &Server,
    a: &Audience,
    revision: &str,
    key: Option<&str>,
    body: Value,
    authorization: &str,
) -> (StatusCode, Value) {
    let mut request = reqwest::Client::new()
        .post(format!(
            "{}/admin/v1/tenants/{}/agents/{}/revisions/{revision}/deploy",
            server.base, a.tenant, a.agent
        ))
        .header("x-llm-firewall-admin-token", authorization)
        .json(&body);
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    let response = request.send().await.unwrap();
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    (status, response.json().await.unwrap_or(Value::Null))
}

/// What the Agent actually receives. `None` is HTTP 204 (nothing pending).
async fn fetch(server: &Server, a: &Audience) -> Option<(Value, String)> {
    let response = reqwest::Client::new()
        .get(format!("{}/agent/v1/policy", server.base))
        .bearer_auth(&a.token)
        .send()
        .await
        .unwrap();
    if response.status().as_u16() == 204 {
        return None;
    }
    assert_eq!(response.status().as_u16(), 200);
    let bytes = response.bytes().await.unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Some((serde_json::from_slice(&bytes).unwrap(), digest))
}

async fn acknowledge(server: &Server, a: &Audience, bundle: &Value) {
    let response = reqwest::Client::new()
        .post(format!("{}/agent/v1/policy/ack", server.base))
        .bearer_auth(&a.token)
        .json(&json!({
            "deployment_sequence": bundle["deployment_sequence"],
            "revision": bundle["revision"],
            "policy_sha256": bundle["policy_sha256"],
            "status": "applied",
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "ack {}", response.status());
}

fn idem(body: &Value) -> &Value {
    &body["idempotency"]
}

fn unique(label: &str) -> String {
    format!("{label} {:016x}", rand::random::<u64>())
}

fn key(label: &str) -> String {
    format!("{label}-{:016x}", rand::random::<u64>())
}

async fn controls(f: &Fixture) {
    let _guard = SERIAL.lock().await;
    set_signers();
    cold_revision_gets_are_read_only_and_backend_equivalent(f).await;
    revision_readback_and_authoring_authorization(f).await;
    guarded_console_issuance_conflicts_without_side_effects(f).await;
    lost_response_returns_original_and_delivers_once(f).await;
    parallel_callers_share_one_issuance(f).await;
    conflicting_reuse_is_refused_without_issuance(f).await;
    invalid_keys_and_keyless_compatibility(f).await;
    restart_and_failure_boundaries(f).await;
    authorization_is_rechecked_before_a_stored_result(f).await;
    historical_retry_cannot_reactivate_or_renew(f).await;
}

async fn lost_response_returns_original_and_delivers_once(f: &Fixture) {
    let store = f.store().await;
    let a = audience(&store, "Lost response").await;
    let server = Server::start(store).await;
    let k = key("lost-response");

    // The first response is lost: send the request on a raw socket and never read the answer.
    let body = "{}";
    let mut stream = tokio::net::TcpStream::connect(server.base.trim_start_matches("http://"))
        .await
        .unwrap();
    let raw = format!(
        "POST /admin/v1/tenants/{}/agents/{}/revisions/r1/deploy HTTP/1.1\r\nhost: x\r\nx-llm-firewall-admin-token: {OWNER}\r\nidempotency-key: {k}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        a.tenant,
        a.agent,
        body.len()
    );
    stream.write_all(raw.as_bytes()).await.unwrap();
    // The socket stays open until the commit is visible, then closes without reading the answer.
    for _ in 0..100 {
        if f.deployments(&a.tenant).await == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(stream);
    assert_eq!(
        f.deployments(&a.tenant).await,
        1,
        "server committed the lost request"
    );

    let (status, retry) = post(&server, &a, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(idem(&retry)["replayed"], true);
    assert_eq!(retry["deployment_sequence"], 1);
    let first_envelope = idem(&retry)["envelope_sha256"].clone();
    let first_expiry = idem(&retry)["expires_at_unix"].clone();
    let issued_at = retry["issued_at_unix"].clone();

    // More retries, a second later: nothing renews and nothing is numbered again.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    for _ in 0..3 {
        let (status, again) = post(&server, &a, "r1", Some(&k), json!({}), OWNER).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(again["deployment_sequence"], 1);
        assert_eq!(again["issued_at_unix"], issued_at);
        assert_eq!(idem(&again)["envelope_sha256"], first_envelope);
        assert_eq!(idem(&again)["expires_at_unix"], first_expiry);
        assert_eq!(idem(&again)["replayed"], true);
    }
    assert_eq!(f.deployments(&a.tenant).await, 1);
    assert_eq!(f.keys(&a.tenant).await, 1);
    assert_eq!(f.max_sequence(&a.tenant).await, 1);

    // The Agent observes exactly one signed envelope, byte-identical to the one the API reported.
    let (bundle, digest) = fetch(&server, &a).await.expect("one pending deployment");
    assert_eq!(bundle["deployment_sequence"], 1);
    assert_eq!(json!(digest), first_envelope);
    assert_eq!(bundle["expires_at_unix"], first_expiry);
    acknowledge(&server, &a, &bundle).await;
    assert!(
        fetch(&server, &a).await.is_none(),
        "no second delivery after acknowledgement"
    );
    server.kill().await;
}

async fn parallel_callers_share_one_issuance(f: &Fixture) {
    let store = f.store().await;
    let a = Arc::new(audience(&store, "Parallel").await);
    let server = Arc::new(Server::start(store).await);
    let k = key("parallel");
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let (server, a, k) = (server.clone(), a.clone(), k.clone());
        set.spawn(async move { post(&server, &a, "r1", Some(&k), json!({}), OWNER).await });
    }
    let mut fresh = 0;
    let mut envelopes = std::collections::BTreeSet::new();
    while let Some(result) = set.join_next().await {
        let (status, body) = result.unwrap();
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["deployment_sequence"], 1);
        if idem(&body)["replayed"] == false {
            fresh += 1;
        }
        envelopes.insert(idem(&body)["envelope_sha256"].to_string());
    }
    assert_eq!(fresh, 1, "exactly one caller issued");
    assert_eq!(envelopes.len(), 1);
    assert_eq!(f.deployments(&a.tenant).await, 1);
    assert_eq!(f.keys(&a.tenant).await, 1);

    // Distinct keys in parallel still produce gap-free distinct sequences.
    let mut set = tokio::task::JoinSet::new();
    for n in 0..8 {
        let (server, a) = (server.clone(), a.clone());
        let k = key(&format!("distinct{n}"));
        let revision = if n % 2 == 0 { "r2" } else { "r1" };
        set.spawn(async move { post(&server, &a, revision, Some(&k), json!({}), OWNER).await });
    }
    let mut sequences = Vec::new();
    while let Some(result) = set.join_next().await {
        let (status, body) = result.unwrap();
        assert_eq!(status, StatusCode::CREATED, "{body}");
        sequences.push(body["deployment_sequence"].as_u64().unwrap());
    }
    sequences.sort_unstable();
    assert_eq!(sequences, (2..=9).collect::<Vec<_>>());
    assert_eq!(f.deployments(&a.tenant).await, 9);
    assert_eq!(f.keys(&a.tenant).await, 9);
    Arc::try_unwrap(server).ok().unwrap().kill().await;
}

async fn conflicting_reuse_is_refused_without_issuance(f: &Fixture) {
    let store = f.store().await;
    let a = audience(&store, "Conflict").await;
    let b = audience(&store, "Foreign tenant").await;
    let second = store
        .create_admin_async(&unique("Second owner"), AdminRole::Owner)
        .await
        .unwrap();
    let second_header = format!("Bearer {}", second.token);
    let server = Server::start(store).await;
    let k = key("conflict");
    let (status, original) = post(&server, &a, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(idem(&original)["replayed"], false);
    assert_eq!(original["action"], "activate");

    for (label, revision, body, header) in [
        ("different revision", "r2", json!({}), OWNER),
        ("rollback semantics", "r1", json!({"rollback": true}), OWNER),
        (
            "different requested signer",
            "r1",
            json!({"issuer_key_id": KEY_ID}),
            OWNER,
        ),
        (
            "foreign administrator",
            "r1",
            json!({}),
            second_header.as_str(),
        ),
    ] {
        let (status, refused) = post(&server, &a, revision, Some(&k), body, header).await;
        assert_eq!(status, StatusCode::CONFLICT, "{label}: {refused}");
        assert!(
            refused.get("deployment_sequence").is_none(),
            "{label} leaked an issuance"
        );
    }
    assert_eq!(f.deployments(&a.tenant).await, 1);
    assert_eq!(f.keys(&a.tenant).await, 1);

    // The same text in another tenant is a different key: it neither replays nor leaks tenant A.
    let (status, foreign) = post(&server, &b, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(idem(&foreign)["replayed"], false);
    assert_eq!(foreign["tenant_id"], json!(b.tenant));
    assert_ne!(
        idem(&foreign)["envelope_sha256"],
        idem(&original)["envelope_sha256"]
    );
    assert_eq!(f.deployments(&a.tenant).await, 1);
    assert_eq!(f.deployments(&b.tenant).await, 1);

    // The original is still what the owner's exact retry returns.
    let (status, replay) = post(&server, &a, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(replay["deployment_sequence"], 1);
    assert_eq!(idem(&replay)["replayed"], true);
    server.kill().await;
}

async fn invalid_keys_and_keyless_compatibility(f: &Fixture) {
    let store = f.store().await;
    let a = audience(&store, "Key shape").await;
    let server = Server::start(store).await;
    for bad in [
        "short",
        &"k".repeat(129),
        "has space in it",
        "semi;colon-key",
        "uni\u{e9}code-key",
    ] {
        let response = reqwest::Client::new()
            .post(format!(
                "{}/admin/v1/tenants/{}/agents/{}/revisions/r1/deploy",
                server.base, a.tenant, a.agent
            ))
            .header("x-llm-firewall-admin-token", OWNER)
            .header("idempotency-key", bad.as_bytes())
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 400, "{bad:?}");
    }
    // Two key headers are ambiguous and refused.
    let response = reqwest::Client::new()
        .post(format!(
            "{}/admin/v1/tenants/{}/agents/{}/revisions/r1/deploy",
            server.base, a.tenant, a.agent
        ))
        .header("x-llm-firewall-admin-token", OWNER)
        .header("idempotency-key", "aaaaaaaa-one")
        .header("idempotency-key", "bbbbbbbb-two")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(f.deployments(&a.tenant).await, 0);
    assert_eq!(f.keys(&a.tenant).await, 0);

    // Boundary lengths are accepted.
    for good in ["12345678", &"z".repeat(128)] {
        let (status, _) = post(&server, &a, "r1", Some(good), json!({}), OWNER).await;
        assert_eq!(status, StatusCode::CREATED, "{good:?}");
    }
    // Keyless behavior is unchanged: each POST is a new sequence, with no `idempotency` object.
    let before = f.deployments(&a.tenant).await;
    for _ in 0..2 {
        let (status, body) = post(&server, &a, "r1", None, json!({}), OWNER).await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(body.get("idempotency").is_none());
    }
    assert_eq!(f.deployments(&a.tenant).await, before + 2);
    assert_eq!(f.keys(&a.tenant).await, 2, "keyless requests store no key");
    server.kill().await;
}

async fn restart_and_failure_boundaries(f: &Fixture) {
    let store = f.store().await;
    let a = audience(&store, "Restart").await;
    let server = Server::start(store).await;

    // Failure before commit: the key row cannot be written, so nothing at all commits.
    f.sql(
        "CREATE TRIGGER fail_key BEFORE INSERT ON managed_agent_deployment_keys BEGIN SELECT RAISE(ABORT,'injected persistence failure'); END;",
        "CREATE OR REPLACE FUNCTION fail_key() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected persistence failure'; END $$; CREATE TRIGGER fail_key BEFORE INSERT ON managed_agent_deployment_keys FOR EACH ROW EXECUTE FUNCTION fail_key();",
    )
    .await;
    let k = key("restart");
    let (status, _) = post(&server, &a, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        f.deployments(&a.tenant).await,
        0,
        "issuance rolled back with the key"
    );
    assert_eq!(f.keys(&a.tenant).await, 0);
    assert!(
        fetch(&server, &a).await.is_none(),
        "no half-issued policy is deliverable"
    );
    f.sql(
        "DROP TRIGGER fail_key;",
        "DROP TRIGGER fail_key ON managed_agent_deployment_keys; DROP FUNCTION public.fail_key();",
    )
    .await;

    // The same key then recovers, with the first sequence (no gap from the failed attempt).
    let (status, issued) = post(&server, &a, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(issued["deployment_sequence"], 1);
    assert_eq!(idem(&issued)["replayed"], false);

    // Crash after commit: kill the Console, reopen storage, retry.
    server.kill().await;
    let restarted = Server::start(f.store().await).await;
    let (status, replay) = post(&restarted, &a, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(replay["deployment_sequence"], 1);
    assert_eq!(idem(&replay)["replayed"], true);
    assert_eq!(
        idem(&replay)["envelope_sha256"],
        idem(&issued)["envelope_sha256"]
    );
    assert_eq!(f.deployments(&a.tenant).await, 1);
    assert_eq!(f.keys(&a.tenant).await, 1);

    // A retry needs no signer: it still succeeds when the Console lost its issuer configuration,
    // while a new issuance with that same missing signer is refused and numbers nothing.
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", "");
    let (status, replay) = post(&restarted, &a, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CREATED, "{replay}");
    assert_eq!(idem(&replay)["replayed"], true);
    let (status, _) = post(
        &restarted,
        &a,
        "r2",
        Some(&key("needs-signer")),
        json!({}),
        OWNER,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(f.deployments(&a.tenant).await, 1);
    set_signers();

    // A retry naming another signer is a different intent even though the bytes of the key match.
    let (status, _) = post(
        &restarted,
        &a,
        "r1",
        Some(&k),
        json!({"issuer_key_id": OTHER_KEY_ID}),
        OWNER,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    restarted.kill().await;
}

async fn authorization_is_rechecked_before_a_stored_result(f: &Fixture) {
    let store = f.store().await;
    let a = audience(&store, "Authorization").await;
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
    let k = key("authorization");
    let (status, _) = post(&server, &a, "r1", Some(&k), json!({}), &owner_header).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(f.deployments(&a.tenant).await, 1);

    // No credential, a lower role, and an unknown credential obtain nothing with the stored key.
    for (header, expected) in [
        ("Bearer nope", StatusCode::UNAUTHORIZED),
        (&format!("Bearer {}", viewer.token), StatusCode::FORBIDDEN),
        (&format!("Bearer {}", operator.token), StatusCode::FORBIDDEN),
    ] {
        let (status, body) = post(&server, &a, "r1", Some(&k), json!({}), header).await;
        assert_eq!(status, expected, "{body}");
        assert!(body.get("deployment_sequence").is_none());
    }

    // A revoked administrator cannot replay their own earlier result.
    store.revoke_admin_async(&owner.admin.id).await.unwrap();
    let (status, body) = post(&server, &a, "r1", Some(&k), json!({}), &owner_header).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.get("deployment_sequence").is_none());

    // The middleware is not the only guard: an administrator revoked between authentication and the
    // issuing transaction is refused by the store itself, for a replay and for a new key alike.
    for stored_key in [k.as_str(), key("after-revocation").as_str()] {
        let refused = store
            .deploy_managed_revision_keyed_async(
                &a.tenant,
                &a.agent,
                "r1",
                false,
                None,
                &llm_firewall::tenant_store::DeploymentIdempotency {
                    key: stored_key,
                    admin_id: &owner.admin.id,
                    requested_issuer_key: None,
                    expected_sequence: None,
                },
            )
            .await;
        let error = refused.expect_err("revoked administrator must not obtain a result");
        assert!(error
            .downcast_ref::<llm_firewall::tenant_store::IdempotencyConflict>()
            .is_none());
    }
    assert_eq!(f.deployments(&a.tenant).await, 1);

    // Tenant deactivation and Agent revocation stop replay as they stop a new issuance.
    let tenant_b = audience(&store, "Deactivated").await;
    let (status, _) = post(&server, &tenant_b, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CREATED);
    store
        .set_tenant_active_async(&tenant_b.tenant, false)
        .await
        .unwrap();
    let (status, body) = post(&server, &tenant_b, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.get("deployment_sequence").is_none());
    assert_eq!(f.deployments(&tenant_b.tenant).await, 1);

    let revoked = audience(&store, "Revoked Agent").await;
    let (status, _) = post(&server, &revoked, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CREATED);
    store
        .revoke_managed_agent_async(&revoked.tenant, &revoked.agent)
        .await
        .unwrap();
    let (status, body) = post(&server, &revoked, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.get("deployment_sequence").is_none());
    assert_eq!(f.deployments(&revoked.tenant).await, 1);

    // The bootstrap owner is a different principal, so the revoked owner's key is not theirs.
    let (status, body) = post(&server, &a, "r1", Some(&k), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(f.deployments(&a.tenant).await, 1);
    server.kill().await;
}

async fn historical_retry_cannot_reactivate_or_renew(f: &Fixture) {
    let store = f.store().await;
    let a = audience(&store, "Historical").await;
    let server = Server::start(store.clone()).await;
    let k1 = key("history-one");
    let (_, one) = post(&server, &a, "r1", Some(&k1), json!({}), OWNER).await;
    let (bundle, _) = fetch(&server, &a).await.unwrap();
    acknowledge(&server, &a, &bundle).await;
    let (_, two) = post(
        &server,
        &a,
        "r2",
        Some(&key("history-two")),
        json!({}),
        OWNER,
    )
    .await;
    assert_eq!(one["deployment_sequence"], 1);
    assert_eq!(two["deployment_sequence"], 2);

    // Replaying the older key neither redelivers sequence 1 nor changes what is pending.
    let (status, replay) = post(&server, &a, "r1", Some(&k1), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(replay["deployment_sequence"], 1);
    assert_eq!(
        replay["status"], "applied",
        "reports the current, not a reset, state"
    );
    let (pending, _) = fetch(&server, &a)
        .await
        .expect("sequence 2 is still the pending one");
    assert_eq!(pending["deployment_sequence"], 2);
    assert_eq!(f.max_sequence(&a.tenant).await, 2);
    assert_eq!(f.deployments(&a.tenant).await, 2);

    // An old, expired issuance is returned unchanged: replay never renews its expiry.
    f.sql(
        &format!("UPDATE managed_agent_deployments SET bundle_json=json_set(bundle_json,'$.expires_at_unix',1) WHERE tenant_id='{}' AND deployment_sequence=1", a.tenant),
        &format!("UPDATE managed_agent_deployments SET bundle_json=jsonb_set(bundle_json::jsonb,'{{expires_at_unix}}','1')::text WHERE tenant_id='{}' AND deployment_sequence=1", a.tenant),
    )
    .await;
    let (status, expired) = post(&server, &a, "r1", Some(&k1), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(idem(&expired)["expires_at_unix"], 1);
    assert_eq!(expired["deployment_sequence"], 1);
    assert_eq!(f.deployments(&a.tenant).await, 2);
    server.kill().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_deployment_idempotency_over_http() {
    controls(&Fixture::new(None).await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable SOUP_DEPLOY_TEST_POSTGRES_URL database"]
async fn postgres_deployment_idempotency_over_http() {
    controls(
        &Fixture::new(Some(
            std::env::var("SOUP_DEPLOY_TEST_POSTGRES_URL").expect("disposable database URL"),
        ))
        .await,
    )
    .await;
}

/// Stored keys survive a schema that predates the table: opening an older SQLite file adds it.
#[tokio::test]
async fn sqlite_older_database_gains_the_key_table_on_first_use() {
    let _guard = SERIAL.lock().await;
    set_signers();
    let f = Fixture::new(None).await;
    let store = f.store().await;
    let a = audience(&store, "Older database").await;
    f.sql(
        "DROP TABLE IF EXISTS managed_agent_deployment_keys;",
        "SELECT 1",
    )
    .await;
    let server = Server::start(f.store().await).await;
    let (status, body) = post(&server, &a, "r1", Some(&key("older")), json!({}), OWNER).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(f.keys(&a.tenant).await, 1);
    server.kill().await;
}

async fn revision_readback_and_authoring_authorization(f: &Fixture) {
    let store = f.store().await;
    let a = audience(&store, "Revision readback").await;
    let b = audience(&store, "Other audience").await;
    let viewer = store
        .create_admin_async(&unique("Revision viewer"), AdminRole::Viewer)
        .await
        .unwrap();
    let owner = store
        .create_admin_async(&unique("Revision owner"), AdminRole::Owner)
        .await
        .unwrap();
    let server = Server::start(store.clone()).await;
    let client = reqwest::Client::new();
    let path = format!(
        "{}/admin/v1/tenants/{}/agents/{}/revisions",
        server.base, a.tenant, a.agent
    );
    let view = format!("Bearer {}", viewer.token);
    let response = client
        .get(format!("{path}?limit=1"))
        .header("x-llm-firewall-admin-token", &view)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let rows: Value = response.json().await.unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["revision"], "r1");
    assert!(rows[0].get("policy_yaml").is_none());
    let rows: Value = client
        .get(format!("{path}?limit=1&after=r1"))
        .header("x-llm-firewall-admin-token", &view)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rows[0]["revision"], "r2");
    let row: Value = client
        .get(format!("{path}/r2"))
        .header("x-llm-firewall-admin-token", &view)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(row["tenant_id"], a.tenant);
    assert_eq!(row["agent_id"], a.agent);
    assert_eq!(row["policy_yaml"], "default: deny\n");
    assert_eq!(
        row["policy_sha256"],
        format!("{:x}", Sha256::digest(b"default: deny\n"))
    );
    assert_eq!(
        client
            .get(format!("{path}?limit=101"))
            .header("x-llm-firewall-admin-token", &view)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        400
    );
    assert_eq!(
        client
            .get(format!("{path}/missing"))
            .header("x-llm-firewall-admin-token", &view)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    assert_eq!(
        client
            .get(format!("{path}/r2"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
    assert_eq!(
        client
            .post(&path)
            .header("x-llm-firewall-admin-token", &view)
            .json(&json!({"revision":"no","policy_yaml":"default: allow\n"}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    // Readback is GET-only: no deployment or key allocation, no cross-audience YAML.
    assert_eq!(f.deployments(&a.tenant).await, 0);
    assert!(store
        .read_managed_revision_async(&b.tenant, "absent", "r1")
        .await
        .unwrap()
        .is_none());
    let doc = store
        .create_managed_revision_authorized_async(
            &a.tenant,
            &a.agent,
            "new",
            "default: deny\n",
            &owner.admin.id,
        )
        .await
        .unwrap();
    assert!(!doc.approved);
    assert!(store
        .create_managed_revision_authorized_async(
            &a.tenant,
            &a.agent,
            "new",
            "default: allow\n",
            &owner.admin.id
        )
        .await
        .is_err());
    let id = owner.admin.id;
    let q = format!("UPDATE control_plane_admins SET role='viewer' WHERE id='{id}'");
    f.sql(&q, &q).await;
    assert!(store
        .approve_managed_revision_authorized_async(&a.tenant, &a.agent, "new", &id)
        .await
        .is_err());
    assert!(store
        .create_managed_revision_authorized_async(
            &a.tenant,
            &a.agent,
            "after-demotion",
            "default: deny\n",
            &id
        )
        .await
        .is_err());
    assert!(
        !store
            .read_managed_revision_async(&a.tenant, &a.agent, "new")
            .await
            .unwrap()
            .unwrap()
            .identity
            .approved
    );
    store
        .revoke_managed_agent_async(&a.tenant, &a.agent)
        .await
        .unwrap();
    assert!(store
        .create_managed_revision_authorized_async(
            &a.tenant,
            &a.agent,
            "after-revocation",
            "default: deny\n",
            "bootstrap_owner"
        )
        .await
        .is_err());
    assert!(store
        .approve_managed_revision_authorized_async(&a.tenant, &a.agent, "new", "bootstrap_owner")
        .await
        .is_err());
}

async fn guarded_console_issuance_conflicts_without_side_effects(f: &Fixture) {
    let store = f.store().await;
    let a = audience(&store, "Guarded Console").await;
    let server = Server::start(store.clone()).await;
    let first = key("guard-first");
    let next = key("guard-next");
    let (status, original) = post(
        &server,
        &a,
        "r1",
        Some(&first),
        json!({"expected_sequence":0}),
        OWNER,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = post(
        &server,
        &a,
        "r2",
        Some(&next),
        json!({"expected_sequence":0}),
        OWNER,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(f.deployments(&a.tenant).await, 1);
    assert_eq!(f.keys(&a.tenant).await, 1);
    let (status, replay) = post(
        &server,
        &a,
        "r1",
        Some(&first),
        json!({"expected_sequence":0}),
        OWNER,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        replay["deployment_sequence"],
        original["deployment_sequence"]
    );
    assert_eq!(
        idem(&replay)["envelope_sha256"],
        idem(&original)["envelope_sha256"]
    );
    assert_eq!(
        post(
            &server,
            &a,
            "r1",
            Some(&first),
            json!({"expected_sequence":1}),
            OWNER
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (bundle, _) = fetch(&server, &a).await.unwrap();
    acknowledge(&server, &a, &bundle).await;
    store
        .create_managed_group_async(&a.tenant, "guard-group", "Guard")
        .await
        .unwrap();
    store
        .enroll_managed_agent_async(&a.tenant, "pilot")
        .await
        .unwrap();
    store
        .add_managed_group_member_async(&a.tenant, "guard-group", "pilot", true)
        .await
        .unwrap();
    store
        .add_managed_group_member_async(&a.tenant, "guard-group", &a.agent, false)
        .await
        .unwrap();
    store
        .create_managed_group_revision_async(
            &a.tenant,
            "guard-group",
            "group-candidate",
            "default: deny\n",
        )
        .await
        .unwrap();
    store
        .approve_managed_group_revision_async(&a.tenant, "guard-group", "group-candidate")
        .await
        .unwrap();
    let issuer = llm_firewall::tenant_store::ManagedIssuer::from_environment_for_key(None).unwrap();
    store
        .start_managed_group_rollout_async(&a.tenant, "guard-group", "group-candidate", &issuer)
        .await
        .unwrap();
    // This Agent is a frozen worker, not yet issued by the group. Sequence CAS
    // alone would miss the conflict; live membership is not the ownership source.
    store
        .remove_managed_group_member_async(&a.tenant, "guard-group", &a.agent)
        .await
        .unwrap();
    let (status, _) = post(
        &server,
        &a,
        "r2",
        Some(&next),
        json!({"expected_sequence":1}),
        OWNER,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        store
            .list_managed_deployments_async(&a.tenant, &a.agent)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(f.keys(&a.tenant).await, 1);
    // A prior confirmed issuance can still be reconciled during a group rollout.
    assert_eq!(
        post(
            &server,
            &a,
            "r1",
            Some(&first),
            json!({"expected_sequence":0}),
            OWNER
        )
        .await
        .0,
        StatusCode::CREATED
    );
}

async fn cold_revision_gets_are_read_only_and_backend_equivalent(f: &Fixture) {
    let store = f.store().await;
    let tenant = store
        .create_tenant_async(&unique("Cold revision GET"))
        .await
        .unwrap();
    let sqlite =
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='managed_agent_revisions'";
    let postgres="SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename='managed_agent_revisions'";
    let before = f.count(sqlite, postgres).await;
    let server = Server::start(store).await;
    let url = format!(
        "{}/admin/v1/tenants/{}/agents/never-enrolled/revisions",
        server.base, tenant.id
    );
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("x-llm-firewall-admin-token", OWNER)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.json::<Value>().await.unwrap(), json!([]));
    let response = client
        .get(format!("{url}/absent"))
        .header("x-llm-firewall-admin-token", OWNER)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
    assert_eq!(
        f.count(sqlite, postgres).await,
        before,
        "GET allocated managed schema"
    );
}
