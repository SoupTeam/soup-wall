// SPDX-License-Identifier: Apache-2.0
//! SOU-241: versioned rejection reasons on the authenticated acknowledgement.
//!
//! Real HTTP against a SQLite file and, when `SOUP_DEPLOY_TEST_POSTGRES_URL`
//! names a disposable database, PostgreSQL. Stored rows are read with direct
//! database queries, not only through the API under test.
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use llm_firewall::handlers::AppState;
use llm_firewall::tenant_store::fleet::FleetQuery;
use llm_firewall::tenant_store::TenantStore;
use llm_firewall::{app, test_config};
use serde_json::{json, Value};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};

const OWNER: &str = "Bearer admin-test-token";
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    /// `(reason_version, reason_code, received_at_unix)` rows for one Agent,
    /// read directly from the store.
    async fn rejections(&self, tenant: &str) -> Vec<(i64, Option<i64>, Option<String>, i64)> {
        let q = format!(
            "SELECT deployment_sequence,reason_version,reason_code,received_at_unix FROM managed_agent_rejections WHERE tenant_id='{tenant}' ORDER BY deployment_sequence"
        );
        if let Some(url) = &self.postgres {
            let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
                .await
                .unwrap();
            let task = tokio::spawn(async move { connection.await.unwrap() });
            let rows = client.query(&q, &[]).await.unwrap();
            drop(client);
            task.await.unwrap();
            rows.iter()
                .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
                .collect()
        } else {
            let db = rusqlite::Connection::open(&self.sqlite).unwrap();
            let mut stmt = db.prepare(&q).unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        }
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

async fn deploy(server: &Server, a: &Audience, revision: &str) -> Value {
    let response = reqwest::Client::new()
        .post(format!(
            "{}/admin/v1/tenants/{}/agents/{}/revisions/{revision}/deploy",
            server.base, a.tenant, a.agent
        ))
        .header("x-llm-firewall-admin-token", OWNER)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "deploy {}",
        response.status()
    );
    let fetched = reqwest::Client::new()
        .get(format!("{}/agent/v1/policy", server.base))
        .bearer_auth(&a.token)
        .send()
        .await
        .unwrap();
    assert_eq!(fetched.status().as_u16(), 200);
    fetched.json().await.unwrap()
}

async fn ack(server: &Server, token: &str, body: Value) -> u16 {
    reqwest::Client::new()
        .post(format!("{}/agent/v1/policy/ack", server.base))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

fn body(bundle: &Value, status: &str, rejection: Option<Value>) -> Value {
    let mut v = json!({
        "deployment_sequence": bundle["deployment_sequence"],
        "revision": bundle["revision"],
        "policy_sha256": bundle["policy_sha256"],
        "status": status,
    });
    if let Some(r) = rejection {
        v["rejection"] = r;
    }
    v
}

fn reason(code: &str) -> Option<Value> {
    Some(json!({"version": 1, "code": code}))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn controls(f: &Fixture) {
    let _guard = SERIAL.lock().await;
    std::env::set_var("SOUP_AGENT_POLICY_KEY_ID", "rejection-key-a");
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", "0b".repeat(32));
    let store = f.store().await;
    let a = audience(&store, "Rejections").await;
    let foreign = audience(&store, "Foreign").await;
    let server = Server::start(store).await;

    let first = deploy(&server, &a, "r1").await;
    // Invalid reasons are refused before any state change: a well-formed
    // reason outside the allowlist with 400, a malformed shape by the
    // existing strict JSON extractor with 422.
    for (bad, expected) in [
        (json!({"version": 2, "code": "bundle_expired"}), 400),
        (
            json!({"version": 1, "code": "Bundle expired: at 12:00"}),
            400,
        ),
        (json!({"version": 1, "code": "not_a_code"}), 400),
        (json!({"version": 1, "code": "x".repeat(4096)}), 400),
        (
            json!({"version": 1, "code": "bundle_expired", "detail": "x"}),
            422,
        ),
        (json!({"version": 1}), 422),
        (json!("bundle_expired"), 422),
    ] {
        assert_eq!(
            ack(
                &server,
                &a.token,
                body(&first, "rejected", Some(bad.clone()))
            )
            .await,
            expected,
            "{bad}"
        );
    }
    assert_eq!(
        ack(
            &server,
            &a.token,
            body(&first, "applied", reason("bundle_expired"))
        )
        .await,
        400,
        "applied ACK never carries a reason"
    );
    let mut unknown = body(&first, "rejected", None);
    unknown["detail"] = json!("free text");
    assert_eq!(ack(&server, &a.token, unknown).await, 422);
    // Foreign tenant credential and an unknown bearer keep the existing auth contract.
    assert_eq!(
        ack(
            &server,
            &foreign.token,
            body(&first, "rejected", reason("bundle_expired"))
        )
        .await,
        409
    );
    assert_eq!(
        ack(
            &server,
            "not-a-token",
            body(&first, "rejected", reason("bundle_expired"))
        )
        .await,
        401
    );
    assert!(f.rejections(&a.tenant).await.is_empty());

    // First authenticated rejection is stored with Console receipt time.
    let before = now();
    assert_eq!(
        ack(
            &server,
            &a.token,
            body(&first, "rejected", reason("bundle_expired"))
        )
        .await,
        204
    );
    let rows = f.rejections(&a.tenant).await;
    assert_eq!(rows.len(), 1);
    let seq: i64 = first["deployment_sequence"].as_i64().unwrap();
    assert_eq!(
        (rows[0].0, rows[0].1, rows[0].2.as_deref()),
        (seq, Some(1), Some("bundle_expired"))
    );
    assert!(rows[0].3 >= before && rows[0].3 <= now());
    // Same retry is idempotent; a conflicting reason or status is refused and
    // the first rejection is kept.
    assert_eq!(
        ack(
            &server,
            &a.token,
            body(&first, "rejected", reason("bundle_expired"))
        )
        .await,
        204
    );
    assert_eq!(
        ack(
            &server,
            &a.token,
            body(&first, "rejected", reason("policy_invalid"))
        )
        .await,
        409
    );
    assert_eq!(
        ack(&server, &a.token, body(&first, "rejected", None)).await,
        409
    );
    assert_eq!(
        ack(&server, &a.token, body(&first, "applied", None)).await,
        409
    );
    assert_eq!(f.rejections(&a.tenant).await, rows);

    // Corrected redeploy: a newer candidate applies; the rejection stays on
    // its own exact candidate and the fleet detail exposes both.
    let second = deploy(&server, &a, "r2").await;
    assert_eq!(
        ack(&server, &a.token, body(&second, "applied", None)).await,
        204
    );
    let store = f.store().await;
    let detail = store
        .fleet_detail(&a.tenant, &a.agent, FleetQuery::default())
        .await
        .unwrap()
        .unwrap();
    let records = serde_json::to_value(&detail.deployments).unwrap();
    let seq_text = seq.to_string();
    let rejected = records
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["sequence"] == seq_text.as_str())
        .unwrap();
    assert_eq!(rejected["recorded_state"], "rejected");
    assert_eq!(rejected["rejection_code"], "bundle_expired");
    assert_eq!(rejected["rejection_reason_version"], 1);
    assert_eq!(rejected["rejected_at_unix"], rows[0].3);
    let applied = records
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["revision"] == "r2")
        .unwrap();
    assert_eq!(applied["recorded_state"], "applied");
    assert!(applied.get("rejection_code").is_none());
    // The policy panel's deployment list carries the same fields.
    let listed: Value = reqwest::Client::new()
        .get(format!(
            "{}/admin/v1/tenants/{}/agents/{}/deployments",
            server.base, a.tenant, a.agent
        ))
        .header("x-llm-firewall-admin-token", OWNER)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["deployment_sequence"] == seq)
        .unwrap();
    assert_eq!(row["status"], "rejected");
    assert_eq!(row["rejection_code"], "bundle_expired");
    assert_eq!(row["rejected_at_unix"], rows[0].3);
    let row = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["revision"] == "r2")
        .unwrap();
    assert!(row.get("rejection_code").is_none() && row.get("rejected_at_unix").is_none());

    // An older Agent without a reason is still recorded, with no code.
    let third = deploy(&server, &a, "r1").await;
    assert_eq!(
        ack(&server, &a.token, body(&third, "rejected", None)).await,
        204
    );
    assert_eq!(
        ack(&server, &a.token, body(&third, "rejected", None)).await,
        204
    );
    assert_eq!(
        ack(
            &server,
            &a.token,
            body(&third, "rejected", reason("policy_invalid"))
        )
        .await,
        409
    );
    let rows = f.rejections(&a.tenant).await;
    assert_eq!(rows.len(), 2);
    assert_eq!((rows[1].1, rows[1].2.clone()), (None, None));

    // Restart keeps the stored reason; a revoked credential is refused.
    server.kill().await;
    let store = f.store().await;
    store
        .revoke_managed_agent_async(&a.tenant, &a.agent)
        .await
        .unwrap();
    let server = Server::start(store).await;
    assert_eq!(
        ack(
            &server,
            &a.token,
            body(&first, "rejected", reason("bundle_expired"))
        )
        .await,
        401
    );
    assert_eq!(f.rejections(&a.tenant).await, rows);
    server.kill().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_rejection_reasons_over_http() {
    controls(&Fixture::new(None).await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable SOUP_DEPLOY_TEST_POSTGRES_URL database"]
async fn postgres_rejection_reasons_over_http() {
    controls(
        &Fixture::new(Some(
            std::env::var("SOUP_DEPLOY_TEST_POSTGRES_URL").expect("disposable database URL"),
        ))
        .await,
    )
    .await;
}
