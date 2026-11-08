// SPDX-License-Identifier: Apache-2.0
//! SOU-242: owner-confirmed stale-restore recovery over HTTP.
//!
//! The restored state is emulated by deleting the newest deployment row from
//! the owned database after the Agent applied it (the real backup/restore
//! witness with agentfw is scripts/console-stale-restore-acceptance.py). The
//! Agent side is its real authenticated HTTP contract: fetch, applied
//! acknowledgement and heartbeat with its own credential. SQLite always runs;
//! PostgreSQL runs with a disposable `SOUP_DEPLOY_TEST_POSTGRES_URL`.
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use llm_firewall::{
    app, handlers::AppState, tenant_store::AdminRole, tenant_store::TenantStore, test_config,
};
use serde_json::{json, Value};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const OWNER: &str = "admin-test-token";
const INSTANCE: &str = "0123456789abcdef0123456789abcdef";

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
        admin_token: Some(OWNER.into()),
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

struct Http(Arc<AppState>);
impl Http {
    async fn call(
        &self,
        method: &str,
        path: &str,
        admin: Option<&str>,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut r = Request::builder().method(method).uri(path);
        if let Some(t) = admin {
            r = r.header("x-llm-firewall-admin-token", format!("Bearer {t}"));
        }
        if let Some(t) = bearer {
            r = r.header("authorization", format!("Bearer {t}"));
        }
        let body = match body {
            Some(b) => {
                r = r.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let response = app(self.0.clone())
            .oneshot(r.body(body).unwrap())
            .await
            .unwrap();
        let code = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 1 << 22).await.unwrap();
        (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }
    async fn admin(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        self.call(method, path, Some(token), None, body).await
    }
}

struct Db {
    sqlite: Option<std::path::PathBuf>,
    postgres: Option<String>,
}
impl Db {
    async fn exec(&self, sql: &str) {
        if let Some(url) = &self.postgres {
            let (client, conn) = tokio_postgres::connect(url, tokio_postgres::NoTls)
                .await
                .unwrap();
            let task = tokio::spawn(async move { conn.await.unwrap() });
            client.batch_execute(sql).await.unwrap();
            drop(client);
            task.await.unwrap();
        } else {
            let db = rusqlite::Connection::open(self.sqlite.as_ref().unwrap()).unwrap();
            db.busy_timeout(Duration::from_secs(10)).unwrap();
            db.execute_batch(sql).unwrap();
        }
    }
    async fn count(&self, sql: &str) -> i64 {
        if let Some(url) = &self.postgres {
            let (client, conn) = tokio_postgres::connect(url, tokio_postgres::NoTls)
                .await
                .unwrap();
            let task = tokio::spawn(async move { conn.await.unwrap() });
            let v: i64 = client.query_one(sql, &[]).await.unwrap().get(0);
            drop(client);
            task.await.unwrap();
            v
        } else {
            let db = rusqlite::Connection::open(self.sqlite.as_ref().unwrap()).unwrap();
            db.query_row(sql, [], |r| r.get(0)).unwrap()
        }
    }
}

async fn open(postgres: Option<String>) -> (TenantStore, Db, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("console.sqlite");
    let store = match &postgres {
        Some(url) => {
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
            TenantStore::open_postgres_with_ca_and_tls(
                url,
                1000,
                Duration::from_secs(10),
                8,
                Duration::from_secs(10),
                None,
                false,
            )
            .await
            .unwrap()
        }
        None => TenantStore::open(&path).unwrap(),
    };
    (
        store,
        Db {
            sqlite: postgres.is_none().then_some(path),
            postgres,
        },
        dir,
    )
}

async fn scenario(postgres: Option<String>) {
    let _guard = SERIAL.lock().await;
    std::env::set_var("SOUP_AGENT_POLICY_KEY_ID", "recovery-key-a");
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", "0c".repeat(32));
    let (store, db, _dir) = open(postgres).await;
    let tenant = store
        .create_tenant_async(&format!("Recovery {}", rand::random::<u64>()))
        .await
        .unwrap()
        .id;
    let other = store
        .create_tenant_async(&format!("Foreign {}", rand::random::<u64>()))
        .await
        .unwrap()
        .id;
    let token = store
        .enroll_managed_agent_async(&tenant, "edge")
        .await
        .unwrap()
        .token;
    let foreign = store
        .enroll_managed_agent_async(&other, "edge")
        .await
        .unwrap()
        .token;
    store
        .enroll_managed_agent_async(&tenant, "edge-2")
        .await
        .unwrap();
    for (rev, yaml) in [("r1", "default: allow\n"), ("r2", "default: deny\n")] {
        store
            .create_managed_revision_async(&tenant, "edge", rev, yaml)
            .await
            .unwrap();
        store
            .approve_managed_revision_async(&tenant, "edge", rev)
            .await
            .unwrap();
    }
    let operator = store
        .create_admin_async("recovery-operator", AdminRole::Operator)
        .await
        .unwrap()
        .token;
    let viewer = store
        .create_admin_async("recovery-viewer", AdminRole::Viewer)
        .await
        .unwrap()
        .token;
    let h = Http(state(store));
    let base = format!("/admin/v1/tenants/{tenant}/agents/edge");

    // Agent applies #1 and then #2 through its real contract.
    let mut bundles = Vec::new();
    for rev in ["r1", "r2"] {
        assert_eq!(
            h.admin(
                "POST",
                &format!("{base}/revisions/{rev}/deploy"),
                OWNER,
                Some(json!({}))
            )
            .await
            .0,
            201
        );
        let (code, bundle) = h
            .call("GET", "/agent/v1/policy", None, Some(&token), None)
            .await;
        assert_eq!(code, 200);
        let ack = json!({"deployment_sequence": bundle["deployment_sequence"], "revision": bundle["revision"],
                         "policy_sha256": bundle["policy_sha256"], "status": "applied"});
        assert_eq!(
            h.call(
                "POST",
                "/agent/v1/policy/ack",
                None,
                Some(&token),
                Some(ack)
            )
            .await
            .0,
            204
        );
        bundles.push(bundle);
    }
    let (old, evidence) = (bundles[0].clone(), bundles[1].clone());
    // The restored database predates #2 (owned fixture edit, see module doc).
    db.exec(&format!("DELETE FROM managed_agent_deployments WHERE tenant_id='{tenant}' AND agent_id='edge' AND deployment_sequence=2")).await;

    let preview = |body: Value| {
        let (h, base) = (&h, base.clone());
        async move {
            h.admin(
                "POST",
                &format!("{base}/stale-recovery/preview"),
                OWNER,
                Some(body),
            )
            .await
        }
    };
    // Without an authenticated observation, recovery stays closed.
    let (code, body) = preview(json!({"evidence": evidence})).await;
    assert_eq!(
        (code, body["refusal"].as_str()),
        (409, Some("observation_unavailable"))
    );

    // The Agent reports its own active policy with its credential.
    let (code, reg) = h.call("POST", "/agent/v1/heartbeat/registrations", None, Some(&token),
        Some(json!({"contract_version": "sw-agent-heartbeat/1", "tenant_id": tenant, "agent_id": "edge",
                    "credential_generation": 1, "instance_id": INSTANCE}))).await;
    assert_eq!(code, 201, "{reg}");
    let beat = |seq: i64, observed: &Value| {
        json!({"contract_version": "sw-agent-heartbeat/1", "tenant_id": tenant,
        "agent_id": "edge", "credential_generation": 1, "instance_id": INSTANCE, "registration_id": reg["registration_id"],
        "sequence": seq, "observed_policy": {"deployment_sequence": observed["deployment_sequence"],
        "revision": observed["revision"], "policy_sha256": observed["policy_sha256"]}})
    };
    // A report naming another policy does not match the evidence.
    assert_eq!(
        h.call(
            "POST",
            "/agent/v1/heartbeats",
            None,
            Some(&token),
            Some(beat(1, &old))
        )
        .await
        .0,
        204
    );
    let (code, body) = preview(json!({"evidence": evidence})).await;
    assert_eq!(
        (code, body["refusal"].as_str()),
        (409, Some("observation_mismatch"))
    );
    tokio::time::sleep(Duration::from_secs(5)).await; // heartbeat minimum interval
    assert_eq!(
        h.call(
            "POST",
            "/agent/v1/heartbeats",
            None,
            Some(&token),
            Some(beat(2, &evidence))
        )
        .await
        .0,
        204
    );

    // Role, audience, tamper and replay refusals.
    assert_eq!(
        h.admin(
            "POST",
            &format!("{base}/stale-recovery/preview"),
            &operator,
            Some(json!({"evidence": evidence}))
        )
        .await
        .0,
        403
    );
    assert_eq!(
        h.admin(
            "POST",
            &format!("{base}/stale-recovery/preview"),
            &viewer,
            Some(json!({"evidence": evidence}))
        )
        .await
        .0,
        403
    );
    assert_eq!(
        h.call(
            "POST",
            &format!("{base}/stale-recovery/preview"),
            None,
            Some(&token),
            Some(json!({"evidence": evidence}))
        )
        .await
        .0,
        401
    );
    let (code, body) = h
        .admin(
            "POST",
            &format!("/admin/v1/tenants/{tenant}/agents/edge-2/stale-recovery/preview"),
            OWNER,
            Some(json!({"evidence": evidence})),
        )
        .await;
    assert_eq!(
        (code, body["refusal"].as_str()),
        (409, Some("evidence_wrong_audience"))
    );
    let mut tampered = evidence.clone();
    tampered["policy_yaml"] = json!("default: allow\n");
    assert_eq!(
        preview(json!({"evidence": tampered})).await.1["refusal"],
        "evidence_digest_mismatch"
    );
    let mut forged = evidence.clone();
    forged["signature_hex"] = json!("00".repeat(64));
    assert_eq!(
        preview(json!({"evidence": forged})).await.1["refusal"],
        "evidence_signature_invalid"
    );
    assert_eq!(
        preview(json!({"evidence": old})).await.1["refusal"],
        "evidence_not_ahead"
    );
    let mut extra = evidence.clone();
    extra["note"] = json!("x");
    assert_eq!(preview(json!({"evidence": extra})).await.0, 400);
    assert_eq!(
        preview(json!({"evidence": evidence, "force": true}))
            .await
            .0,
        400
    );

    // A valid preview grants nothing and writes nothing.
    let (code, p) = preview(json!({"evidence": evidence})).await;
    assert_eq!(code, 200, "{p}");
    assert_eq!(
        (p["restored_sequence"].as_i64(), p["next_sequence"].as_i64()),
        (Some(1), Some(3))
    );
    assert!(p["unrecoverable_interval"].is_null());
    assert_eq!(
        db.count(&format!(
            "SELECT COUNT(*) FROM managed_agent_recovery_fences WHERE tenant_id='{tenant}'"
        ))
        .await,
        0
    );
    let (code, s) = h
        .admin("GET", &format!("{base}/stale-recovery"), &viewer, None)
        .await;
    assert_eq!((code, s["state"].as_str()), (200, Some("none")));

    let confirm = |binding: &Value, phrase: &Value| {
        let (h, base, evidence) = (&h, base.clone(), evidence.clone());
        let body = json!({"evidence": evidence, "state_binding": binding, "confirmation": phrase});
        async move {
            h.admin(
                "POST",
                &format!("{base}/stale-recovery/confirm"),
                OWNER,
                Some(body),
            )
            .await
        }
    };
    assert_eq!(
        confirm(&p["state_binding"], &json!("recover edge")).await.1["refusal"],
        "confirmation_mismatch"
    );
    assert_eq!(
        confirm(&json!("a".repeat(64)), &p["confirmation"]).await.1["refusal"],
        "state_changed"
    );
    assert_eq!(h.admin("POST", &format!("{base}/stale-recovery/confirm"), &operator,
        Some(json!({"evidence": evidence, "state_binding": p["state_binding"], "confirmation": p["confirmation"]}))).await.0, 403);
    // A concurrent policy mutation after the preview keeps recovery closed.
    assert_eq!(
        h.admin(
            "POST",
            &format!("{base}/revisions"),
            OWNER,
            Some(json!({"revision": "r3", "policy_yaml": "default: deny\n"}))
        )
        .await
        .0,
        201
    );
    assert_eq!(
        confirm(&p["state_binding"], &p["confirmation"]).await.1["refusal"],
        "state_changed"
    );
    let (code, p) = preview(json!({"evidence": evidence})).await;
    assert_eq!(code, 200);

    // Concurrent confirmations: exactly one fence.
    let (a, b) = tokio::join!(
        confirm(&p["state_binding"], &p["confirmation"]),
        confirm(&p["state_binding"], &p["confirmation"])
    );
    let mut codes = [a.0, b.0];
    codes.sort();
    assert!(
        codes == [200, 201] || codes == [201, 409],
        "{codes:?} {a:?} {b:?}"
    );
    let fenced = if a.0 == 201 { a.1 } else { b.1 };
    assert_eq!(
        (
            fenced["fence"]["fence_sequence"].as_i64(),
            fenced["fence"]["state"].as_str()
        ),
        (Some(2), Some("fenced"))
    );
    assert_eq!(fenced["fence"]["confirmed_by"], "bootstrap_owner");
    // Idempotent retry; new evidence for the same sequence cannot reopen it.
    let (code, again) = confirm(&p["state_binding"], &p["confirmation"]).await;
    assert_eq!((code, again["replayed"].as_bool()), (200, Some(true)));
    assert_eq!(
        preview(json!({"evidence": evidence})).await.1["refusal"],
        "evidence_not_ahead"
    );
    assert_eq!(
        db.count(&format!(
            "SELECT COUNT(*) FROM managed_agent_recovery_fences WHERE tenant_id='{tenant}'"
        ))
        .await,
        1
    );

    // The fence is persisted before signing: the normal deploy path issues #3.
    let (code, d) = h
        .admin(
            "POST",
            &format!("{base}/revisions/r1/deploy"),
            OWNER,
            Some(json!({})),
        )
        .await;
    assert_eq!(
        (code, d["deployment_sequence"].as_i64()),
        (201, Some(3)),
        "{d}"
    );
    let (_, s) = h
        .admin("GET", &format!("{base}/stale-recovery"), &viewer, None)
        .await;
    assert_eq!(s["state"], "fenced", "a delivered row is not completion");
    let (code, bundle) = h
        .call("GET", "/agent/v1/policy", None, Some(&token), None)
        .await;
    assert_eq!(
        (code, bundle["deployment_sequence"].as_i64()),
        (200, Some(3))
    );
    // Equal or lower conflicting sequences stay refused at the Console too.
    let stale = json!({"deployment_sequence": 2, "revision": "r2", "policy_sha256": evidence["policy_sha256"], "status": "applied"});
    assert_eq!(
        h.call(
            "POST",
            "/agent/v1/policy/ack",
            None,
            Some(&token),
            Some(stale)
        )
        .await
        .0,
        409
    );
    // A foreign credential cannot complete it.
    let ack = json!({"deployment_sequence": 3, "revision": "r1", "policy_sha256": bundle["policy_sha256"], "status": "applied"});
    assert_eq!(
        h.call(
            "POST",
            "/agent/v1/policy/ack",
            None,
            Some(&foreign),
            Some(ack.clone())
        )
        .await
        .0,
        409
    );
    let (_, s) = h
        .admin("GET", &format!("{base}/stale-recovery"), &viewer, None)
        .await;
    assert_eq!(s["state"], "fenced");
    // Only the authenticated applied acknowledgement completes recovery.
    assert_eq!(
        h.call(
            "POST",
            "/agent/v1/policy/ack",
            None,
            Some(&token),
            Some(ack)
        )
        .await
        .0,
        204
    );
    let (_, s) = h
        .admin("GET", &format!("{base}/stale-recovery"), &viewer, None)
        .await;
    assert_eq!(
        (
            s["state"].as_str(),
            s["fences"][0]["completion"]["deployment_sequence"].as_i64()
        ),
        (Some("complete"), Some(3))
    );
    assert_eq!(s["restored_sequence"].as_i64(), Some(3));

    // Changed issuer key material: evidence no longer verifies.
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", "0d".repeat(32));
    db.exec(&format!("DELETE FROM managed_agent_deployments WHERE tenant_id='{tenant}' AND agent_id='edge' AND deployment_sequence=3")).await;
    let mut later = bundle.clone();
    later["deployment_sequence"] = json!(9);
    assert_eq!(
        preview(json!({"evidence": later})).await.1["refusal"],
        "evidence_signature_invalid"
    );
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", "0c".repeat(32));
    // Revoked credential keeps recovery closed.
    assert_eq!(
        h.admin("POST", &format!("{base}/revoke"), OWNER, Some(json!({})))
            .await
            .0,
        204
    );
    assert_eq!(
        preview(json!({"evidence": evidence})).await.1["refusal"],
        "revoked"
    );
    let (code, _) = h
        .admin(
            "GET",
            &format!("/admin/v1/tenants/{tenant}/agents/missing/stale-recovery"),
            &viewer,
            None,
        )
        .await;
    assert_eq!(code, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_stale_restore_recovery() {
    scenario(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable SOUP_DEPLOY_TEST_POSTGRES_URL database"]
async fn postgres_stale_restore_recovery() {
    scenario(Some(
        std::env::var("SOUP_DEPLOY_TEST_POSTGRES_URL").expect("disposable database URL"),
    ))
    .await;
}

/// Sends a confirm request whose body is held until `between` ran, after the
/// admin middleware already authenticated the headers.
async fn held_confirm<F: std::future::Future<Output = ()>>(
    base: &str,
    path: &str,
    token: &str,
    body: &Value,
    between: F,
) -> (u16, Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body = body.to_string();
    let mut stream = tokio::net::TcpStream::connect(base).await.unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nhost: {base}\r\nx-llm-firewall-admin-token: Bearer {token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    between.await;
    stream.write_all(body.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw);
    let code = text[9..12].parse().unwrap();
    let json = text
        .split("\r\n\r\n")
        .nth(1)
        .and_then(|b| serde_json::from_str(b.trim()).ok())
        .unwrap_or(Value::Null);
    (code, json)
}

/// P1 regression: an Owner authenticated by the middleware but revoked or
/// demoted before the fence transaction cannot create a fence.
async fn owner_revalidated(postgres: Option<String>) {
    let _guard = SERIAL.lock().await;
    std::env::set_var("SOUP_AGENT_POLICY_KEY_ID", "recovery-key-a");
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", "0c".repeat(32));
    let (store, db, _dir) = open(postgres).await;
    let tenant = store
        .create_tenant_async(&format!("Owner check {}", rand::random::<u64>()))
        .await
        .unwrap()
        .id;
    store
        .enroll_managed_agent_async(&tenant, "edge")
        .await
        .unwrap();
    store
        .create_managed_revision_async(&tenant, "edge", "r1", "default: allow\n")
        .await
        .unwrap();
    store
        .approve_managed_revision_async(&tenant, "edge", "r1")
        .await
        .unwrap();
    let revoked = store
        .create_admin_async("held-owner-revoked", AdminRole::Owner)
        .await
        .unwrap();
    let demoted = store
        .create_admin_async("held-owner-demoted", AdminRole::Owner)
        .await
        .unwrap();
    let control = store
        .create_admin_async("held-owner-control", AdminRole::Owner)
        .await
        .unwrap();
    let state = state(store.clone());
    let h = Http(state.clone());
    let base = format!("/admin/v1/tenants/{tenant}/agents/edge");
    assert_eq!(
        h.admin(
            "POST",
            &format!("{base}/revisions/r1/deploy"),
            OWNER,
            Some(json!({}))
        )
        .await
        .0,
        201
    );
    let (_, list) = h
        .admin("GET", &format!("{base}/deployments"), OWNER, None)
        .await;
    let seq = list[0]["deployment_sequence"].as_i64().unwrap();
    let bundle_json: String = if let Some(url) = &db.postgres {
        let (client, conn) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .unwrap();
        let task = tokio::spawn(async move { conn.await.unwrap() });
        let v = client
            .query_one(
                "SELECT bundle_json FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id='edge' AND deployment_sequence=$2",
                &[&tenant, &seq],
            )
            .await
            .unwrap()
            .get(0);
        drop(client);
        task.await.unwrap();
        v
    } else {
        let c = rusqlite::Connection::open(db.sqlite.as_ref().unwrap()).unwrap();
        c.query_row(
            "SELECT bundle_json FROM managed_agent_deployments WHERE tenant_id=?1 AND agent_id='edge' AND deployment_sequence=?2",
            rusqlite::params![tenant, seq],
            |r| r.get(0),
        )
        .unwrap()
    };
    let mut evidence: Value = serde_json::from_str(&bundle_json).unwrap();
    evidence["deployment_sequence"] = json!(seq + 1);
    let body = json!({"evidence": evidence, "state_binding": "a".repeat(64), "confirmation": "recover edge"});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    let path = format!("{base}/stale-recovery/confirm");

    // Control: the same held request from a live Owner reaches the rules.
    let (code, reply) = held_confirm(&addr, &path, &control.token, &body, async {}).await;
    assert_eq!(
        (code, reply["refusal"].as_str()),
        (409, Some("evidence_signature_invalid")),
        "{reply}"
    );
    // Revoked while the body was held.
    let (code, reply) = held_confirm(&addr, &path, &revoked.token, &body, async {
        assert!(store.revoke_admin_async(&revoked.admin.id).await.unwrap());
    })
    .await;
    assert_eq!(
        (code, reply["refusal"].as_str()),
        (403, Some("owner_not_active")),
        "{reply}"
    );
    // Demoted to Operator while the body was held.
    let (code, reply) = held_confirm(&addr, &path, &demoted.token, &body, async {
        db.exec(&format!(
            "UPDATE control_plane_admins SET role='operator' WHERE id='{}'",
            demoted.admin.id
        ))
        .await;
    })
    .await;
    assert_eq!(
        (code, reply["refusal"].as_str()),
        (403, Some("owner_not_active")),
        "{reply}"
    );
    assert_eq!(
        db.count(&format!(
            "SELECT COUNT(*) FROM managed_agent_recovery_fences WHERE tenant_id='{tenant}'"
        ))
        .await,
        0
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_confirm_revalidates_owner() {
    owner_revalidated(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable SOUP_DEPLOY_TEST_POSTGRES_URL database"]
async fn postgres_confirm_revalidates_owner() {
    owner_revalidated(Some(
        std::env::var("SOUP_DEPLOY_TEST_POSTGRES_URL").expect("disposable database URL"),
    ))
    .await;
}
