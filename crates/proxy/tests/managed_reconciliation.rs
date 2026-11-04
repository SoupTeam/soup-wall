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
async fn controls(postgres: Option<String>) {
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
