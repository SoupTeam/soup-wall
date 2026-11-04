// SPDX-License-Identifier: Apache-2.0
//! Restart/concurrency/fault controls shared by SQLite and a disposable PostgreSQL database.
use llm_firewall::tenant_store::{
    AppliedReport, ManagedGroupRollout, ManagedIssuer, RolloutPhase, TenantStore,
};
use std::time::Duration;

struct Fixture {
    _dir: tempfile::TempDir,
    sqlite: std::path::PathBuf,
    postgres: Option<String>,
    store: TenantStore,
}
impl Fixture {
    async fn new(postgres: Option<String>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let sqlite = dir.path().join("console.sqlite");
        let store = if let Some(url) = &postgres {
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
            Self::pg_store(url).await
        } else {
            TenantStore::open(&sqlite).unwrap()
        };
        Self {
            _dir: dir,
            sqlite,
            postgres,
            store,
        }
    }
    async fn pg_store(url: &str) -> TenantStore {
        TenantStore::open_postgres_with_ca_and_tls(
            url,
            1000,
            Duration::from_secs(10),
            1,
            Duration::from_secs(10),
            None,
            false,
        )
        .await
        .unwrap()
    }
    async fn reopen(&self) -> TenantStore {
        match &self.postgres {
            Some(url) => Self::pg_store(url).await,
            None => TenantStore::open(&self.sqlite).unwrap(),
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
}
fn issuer() -> ManagedIssuer {
    ManagedIssuer::new("atomic-test".into(), &"09".repeat(32)).unwrap()
}
async fn setup(store: &TenantStore) -> String {
    let tenant = store
        .create_tenant_async(&format!(
            "Atomic rollout controls {}",
            rand::random::<u64>()
        ))
        .await
        .unwrap();
    store
        .create_managed_group_async(&tenant.id, "group", "Group")
        .await
        .unwrap();
    for (agent, pilot) in [("p1", true), ("p2", true), ("w1", false), ("w2", false)] {
        store
            .enroll_managed_agent_async(&tenant.id, agent)
            .await
            .unwrap();
        store
            .add_managed_group_member_async(&tenant.id, "group", agent, pilot)
            .await
            .unwrap();
        store
            .create_managed_revision_async(&tenant.id, agent, "base", "default: allow\n")
            .await
            .unwrap();
        store
            .approve_managed_revision_async(&tenant.id, agent, "base")
            .await
            .unwrap();
        let dep = store
            .deploy_managed_revision_async(&tenant.id, agent, "base", false, &issuer())
            .await
            .unwrap();
        store
            .acknowledge_managed_bundle_async(
                &tenant.id,
                agent,
                &AppliedReport {
                    deployment_sequence: dep.deployment_sequence,
                    revision: dep.revision,
                    policy_sha256: dep.policy_sha256,
                    status: "applied".into(),
                },
            )
            .await
            .unwrap();
    }
    store
        .create_managed_group_revision_async(&tenant.id, "group", "candidate", "default: deny\n")
        .await
        .unwrap();
    store
        .approve_managed_group_revision_async(&tenant.id, "group", "candidate")
        .await
        .unwrap();
    tenant.id
}
async fn ack(store: &TenantStore, tenant: &str, agent: &str, plan: &ManagedGroupRollout) {
    let dep = store
        .list_managed_deployments_async(tenant, agent)
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.deployment_sequence == plan.active_deployments[agent])
        .unwrap();
    assert!(store
        .acknowledge_managed_bundle_async(
            tenant,
            agent,
            &AppliedReport {
                deployment_sequence: dep.deployment_sequence,
                revision: dep.revision,
                policy_sha256: dep.policy_sha256,
                status: "applied".into()
            }
        )
        .await
        .unwrap());
}

async fn expire(f: &Fixture, tenant: &str) {
    let condition = format!("UPDATE managed_agent_deployments SET issued_at_unix=issued_at_unix-301 WHERE tenant_id='{tenant}' AND revision='candidate'");
    f.sql(&condition, &condition).await;
}
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
async fn controls(postgres: Option<String>) {
    let _guard = SERIAL.lock().await;
    std::env::set_var("SOUP_AGENT_POLICY_KEY_ID", "atomic-test");
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", "09".repeat(32));
    let f = Fixture::new(postgres).await;
    let tenant = setup(&f.store).await;
    let plan = f
        .store
        .start_managed_group_rollout_async(&tenant, "group", "candidate", &issuer())
        .await
        .unwrap();
    expire(&f, &tenant).await;
    // A new Console process discovers persisted work without an ACK or POST.
    let a = f.reopen().await;
    let b = f.reopen().await;
    let own_cursor = llm_firewall::rollout_reconciliation::RolloutCursor {
        tenant_id: tenant.clone(),
        group_id: String::new(),
        rollout_id: String::new(),
    };
    let ids = a
        .discover_active_rollouts_async(Some(&own_cursor), 1)
        .await
        .unwrap();
    let id = ids
        .iter()
        .find(|id| id.tenant_id == tenant)
        .unwrap()
        .clone();
    assert_eq!(id.rollout_id, plan.rollout_id);
    // Missing signer must roll back the ENTIRE attempted transition.
    std::env::remove_var("SOUP_AGENT_POLICY_SEED_HEX");
    assert!(a.reconcile_saved_rollout_async(&id).await.is_err());
    assert_eq!(
        a.get_managed_group_rollout_async(&tenant, "group")
            .await
            .unwrap()
            .unwrap()
            .phase,
        RolloutPhase::Pilot
    );
    assert_eq!(
        a.list_managed_deployments_async(&tenant, "p1")
            .await
            .unwrap()
            .len(),
        2
    );
    a.reconcile_rollout_page(None, 100).await.unwrap();
    assert_eq!(
        a.reconciliation_status(&tenant, "group")["last_observation"]["blocked"],
        true
    );
    assert!(a.reconciliation_status("other-tenant", "group")["last_observation"].is_null());
    std::env::set_var("SOUP_AGENT_POLICY_SEED_HEX", "09".repeat(32));
    // Two replicas plus a manual Owner transition share one durable boundary.
    let manual_issuer = issuer();
    let (ra, rb, manual) = tokio::join!(
        a.reconcile_saved_rollout_async(&id),
        b.reconcile_saved_rollout_async(&id),
        f.store
            .advance_managed_group_rollout_async(&tenant, "group", Some(&manual_issuer))
    );
    ra.unwrap();
    rb.unwrap();
    manual.unwrap();
    let rollback = a
        .get_managed_group_rollout_async(&tenant, "group")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rollback.phase, RolloutPhase::RollingBack);
    assert_eq!(rollback.rollout_id, plan.rollout_id);
    assert_eq!(rollback.active_deployments["p1"], 3);
    for agent in ["p1", "p2"] {
        assert_eq!(
            a.list_managed_deployments_async(&tenant, agent)
                .await
                .unwrap()
                .len(),
            3
        );
    }
    a.reconcile_saved_rollout_async(&id).await.unwrap();
    assert_eq!(
        a.get_managed_group_rollout_async(&tenant, "group")
            .await
            .unwrap()
            .unwrap()
            .phase,
        RolloutPhase::RollingBack
    );
    for agent in ["p1", "p2"] {
        ack(&a, &tenant, agent, &rollback).await;
        ack(&a, &tenant, agent, &rollback).await;
    }
    assert_eq!(
        a.get_managed_group_rollout_async(&tenant, "group")
            .await
            .unwrap()
            .unwrap()
            .phase,
        RolloutPhase::RolledBack
    );
    // A discovery identity cannot accidentally advance a replacement plan.
    let fresh = a
        .start_managed_group_rollout_async(&tenant, "group", "candidate", &issuer())
        .await
        .unwrap();
    assert_ne!(fresh.rollout_id, id.rollout_id);
    assert!(a
        .reconcile_saved_rollout_async(&id)
        .await
        .unwrap()
        .is_none());
    // Paused gates stay paused even after downtime, with unchanged sequences.
    a.pause_managed_group_rollout_async(&tenant, "group")
        .await
        .unwrap();
    expire(&f, &tenant).await;
    let paused = a
        .get_managed_group_rollout_async(&tenant, "group")
        .await
        .unwrap()
        .unwrap();
    assert!(!a
        .discover_active_rollouts_async(None, 100)
        .await
        .unwrap()
        .iter()
        .any(|i| i.tenant_id == tenant));
    let paused_id = llm_firewall::rollout_reconciliation::RolloutCursor {
        rollout_id: fresh.rollout_id.clone(),
        ..id.clone()
    };
    assert!(a
        .reconcile_saved_rollout_async(&paused_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        a.get_managed_group_rollout_async(&tenant, "group")
            .await
            .unwrap()
            .unwrap()
            .active_deployments,
        paused.active_deployments
    );
    // Distinct tenant; timely exact applied ACKs progress with no manual call.
    let timely = setup(&a).await;
    let good = a
        .start_managed_group_rollout_async(&timely, "group", "candidate", &issuer())
        .await
        .unwrap();
    for agent in ["p1", "p2"] {
        ack(&a, &timely, agent, &good).await;
    }
    let standard = a
        .get_managed_group_rollout_async(&timely, "group")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(standard.phase, RolloutPhase::Standard);
    for agent in ["w1", "w2"] {
        ack(&a, &timely, agent, &standard).await;
    }
    assert_eq!(
        a.get_managed_group_rollout_async(&timely, "group")
            .await
            .unwrap()
            .unwrap()
            .phase,
        RolloutPhase::Completed
    );
    // Revoked Agent cannot be revived or treated as applied by the worker.
    let revoked = setup(&a).await;
    let r = a
        .start_managed_group_rollout_async(&revoked, "group", "candidate", &issuer())
        .await
        .unwrap();
    a.revoke_managed_agent_async(&revoked, "p1").await.unwrap();
    let rid = llm_firewall::rollout_reconciliation::RolloutCursor {
        tenant_id: revoked.clone(),
        group_id: "group".into(),
        rollout_id: r.rollout_id,
    };
    a.reconcile_saved_rollout_async(&rid).await.unwrap();
    assert_eq!(
        a.get_managed_group_rollout_async(&revoked, "group")
            .await
            .unwrap()
            .unwrap()
            .phase,
        RolloutPhase::Failed
    );
    assert_eq!(
        a.list_managed_deployments_async(&revoked, "p1")
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(a.discover_active_rollouts_async(None, 0).await.is_err());
    assert!(a.discover_active_rollouts_async(None, 101).await.is_err());
    // Fair pages pass a permanently blocked first plan rather than LIMIT starvation.
    let first = setup(&a).await;
    let second = setup(&a).await;
    a.start_managed_group_rollout_async(&first, "group", "candidate", &issuer())
        .await
        .unwrap();
    a.start_managed_group_rollout_async(&second, "group", "candidate", &issuer())
        .await
        .unwrap();
    let mut cursor = None;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let page = a
            .discover_active_rollouts_async(cursor.as_ref(), 1)
            .await
            .unwrap();
        if page.is_empty() {
            break;
        }
        assert_eq!(page.len(), 1);
        seen.insert(page[0].tenant_id.clone());
        cursor = page.last().cloned();
    }
    assert!(seen.contains(&first) && seen.contains(&second));
    assert!(a
        .reconcile_rollout_page(cursor.as_ref(), 1)
        .await
        .unwrap()
        .is_none());
    // A finite scan ceiling forces a wrap even when later keys remain active.
    let all = a.discover_active_rollouts_async(None, 100).await.unwrap();
    let boundary = &all[0];
    let bounded = a
        .discover_active_rollouts_window_async(None, Some(boundary), 100)
        .await
        .unwrap();
    assert_eq!(bounded, vec![boundary.clone()]);
    assert!(a
        .discover_active_rollouts_window_async(Some(boundary), Some(boundary), 1)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        a.active_rollout_ceiling_async().await.unwrap(),
        all.last().cloned()
    );
    // Two actual scheduling loops, then graceful stop between transactions.
    expire(&f, &first).await;
    expire(&f, &second).await;
    let worker_a = f.reopen().await;
    let worker_b = f.reopen().await;
    let (stop_a, rx_a) = tokio::sync::watch::channel(false);
    let (stop_b, rx_b) = tokio::sync::watch::channel(false);
    let ca = llm_firewall::rollout_reconciliation::ReconciliationConfig {
        enabled: true,
        interval_seconds: 1,
        batch_size: 100,
    };
    let cb = ca.clone();
    let aa = worker_a.clone();
    let bb = worker_b.clone();
    let loop_a = tokio::spawn(async move { aa.run_rollout_reconciliation(ca, rx_a).await });
    let loop_b = tokio::spawn(async move { bb.run_rollout_reconciliation(cb, rx_b).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if worker_a
                .get_managed_group_rollout_async(&first, "group")
                .await
                .unwrap()
                .unwrap()
                .phase
                == RolloutPhase::RollingBack
                && worker_b
                    .get_managed_group_rollout_async(&second, "group")
                    .await
                    .unwrap()
                    .unwrap()
                    .phase
                    == RolloutPhase::RollingBack
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    stop_a.send(true).unwrap();
    stop_b.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop_a.await.unwrap().unwrap();
        loop_b.await.unwrap().unwrap();
    })
    .await
    .unwrap();
    for tenant in [&first, &second] {
        assert_eq!(
            worker_a
                .list_managed_deployments_async(tenant, "p1")
                .await
                .unwrap()
                .len(),
            3
        );
    }
    assert_eq!(
        worker_a.reconciliation_status(&first, "group")["worker"]["running"],
        false
    );
    // Shutdown before startup performs no scan or issuance.
    let (stop, rx) = tokio::sync::watch::channel(true);
    a.run_rollout_reconciliation(
        llm_firewall::rollout_reconciliation::ReconciliationConfig {
            enabled: true,
            interval_seconds: 1,
            batch_size: 1,
        },
        rx,
    )
    .await
    .unwrap();
    drop(stop);
    assert_eq!(
        a.reconciliation_status(&first, "group")["worker"]["running"],
        false
    );
    std::env::remove_var("SOUP_AGENT_POLICY_KEY_ID");
    std::env::remove_var("SOUP_AGENT_POLICY_SEED_HEX");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_reconciliation_controls() {
    controls(None).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an owned disposable PostgreSQL database"]
async fn postgres_reconciliation_controls() {
    controls(Some(
        std::env::var("SOUP_RECONCILIATION_TEST_POSTGRES_URL")
            .expect("disposable database required"),
    ))
    .await;
}
#[test]
fn reconciliation_configuration_is_explicit_and_bounded() {
    use llm_firewall::rollout_reconciliation::ReconciliationConfig;
    let mut c = ReconciliationConfig::default();
    assert!(!c.enabled);
    c.validate().unwrap();
    c.batch_size = 101;
    assert!(c.validate().is_err());
    c.batch_size = 1;
    c.interval_seconds = 0;
    assert!(c.validate().is_err());
}

/// An unfinished authenticated request distinguishes default SIGTERM from a
/// newly installed graceful-drain handler. Disabled reconciliation must retain
/// the pre-existing signal lifecycle, even while HTTP input is still pending.
#[cfg(unix)]
#[test]
fn disabled_worker_preserves_console_sigterm_lifecycle() {
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(console_sigterm_with_pending_body(false).signal(), Some(15));
}

#[cfg(unix)]
#[test]
fn enabled_worker_joins_without_waiting_for_incomplete_http_body() {
    assert!(console_sigterm_with_pending_body(true).success());
}

#[cfg(unix)]
fn console_sigterm_with_pending_body(enabled: bool) -> std::process::ExitStatus {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::{Command, Stdio};
    use std::time::Instant;
    struct Guard(std::process::Child);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    std::fs::write(
        dir.path().join("firewall.yaml"),
        format!(
            "bind: '{address}'\ntenant_store:\n  enabled: true\n  database_path: console.sqlite\nrollout_reconciliation:\n  enabled: {enabled}\n"
        ),
    )
    .unwrap();
    let mut child = Guard(
        Command::new(env!("CARGO_BIN_EXE_llm-firewall"))
            .current_dir(dir.path())
            .env_clear()
            .env("LLM_FW_ADMIN_TOKEN", "disposable-signal-test-token")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(mut connection) = TcpStream::connect_timeout(&address, Duration::from_millis(100))
        {
            connection
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            connection
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut bytes = [0; 64];
            if let Ok(n) = connection.read(&mut bytes) {
                if std::str::from_utf8(&bytes[..n])
                    .unwrap_or("")
                    .contains("200")
                {
                    break;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "disposable Console did not become healthy"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let mut pending = TcpStream::connect(address).unwrap();
    pending
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    pending.write_all(b"POST /admin/v1/tenants HTTP/1.1\r\nHost: localhost\r\nx-llm-firewall-admin-token: Bearer disposable-signal-test-token\r\nContent-Type: application/json\r\nContent-Length: 1000\r\nExpect: 100-continue\r\n\r\n").unwrap();
    // The interim response proves the authenticated route is polling its body.
    // Keep that body incomplete while the worker receives the shutdown signal.
    let mut interim = Vec::new();
    while !interim.ends_with(b"\r\n\r\n") {
        let mut byte = [0; 1];
        pending.read_exact(&mut byte).unwrap();
        interim.push(byte[0]);
        assert!(interim.len() <= 128);
    }
    assert!(interim.starts_with(b"HTTP/1.1 100 Continue\r\n"));
    pending.write_all(b"{").unwrap();
    assert!(Command::new("/bin/kill")
        .args(["-TERM", &child.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "Console shutdown waited for an incomplete HTTP body (reconciliation enabled: {enabled})"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(pending);
    status
}
