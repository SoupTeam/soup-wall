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
async fn race(
    a: TenantStore,
    b: TenantStore,
    tenant: &str,
    start: bool,
) -> Vec<ManagedGroupRollout> {
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let runtime = tokio::runtime::Handle::current();
    let tasks = [a, b]
        .into_iter()
        .map(|store| {
            let barrier = barrier.clone();
            let runtime = runtime.clone();
            let tenant = tenant.to_owned();
            tokio::task::spawn_blocking(move || {
                barrier.wait();
                runtime.block_on(async {
                    let signer = issuer();
                    if start {
                        store
                            .start_managed_group_rollout_async(
                                &tenant,
                                "group",
                                "candidate",
                                &signer,
                            )
                            .await
                            .unwrap()
                    } else {
                        store
                            .advance_managed_group_rollout_async(&tenant, "group", Some(&signer))
                            .await
                            .unwrap()
                            .unwrap()
                    }
                })
            })
        })
        .collect::<Vec<_>>();
    let mut plans = Vec::new();
    for task in tasks {
        plans.push(task.await.unwrap());
    }
    plans
}

async fn controls(f: Fixture) {
    let signing_issuer = issuer();
    let tenant = setup(&f.store).await;
    // Force the second pilot insert to fail AFTER the first one: the whole start must disappear.
    f.sql("CREATE TRIGGER fail_wave BEFORE INSERT ON managed_agent_deployments WHEN NEW.agent_id='p2' AND NEW.revision='candidate' BEGIN SELECT RAISE(ABORT,'injected issuance failure'); END;",
    "CREATE FUNCTION fail_wave() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.agent_id='p2' AND NEW.revision='candidate' THEN RAISE EXCEPTION 'injected issuance failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_wave BEFORE INSERT ON managed_agent_deployments FOR EACH ROW EXECUTE FUNCTION fail_wave();").await;
    assert!(f
        .store
        .start_managed_group_rollout_async(&tenant, "group", "candidate", &signing_issuer)
        .await
        .is_err());
    let restarted = f.reopen().await;
    assert!(restarted
        .get_managed_group_rollout_async(&tenant, "group")
        .await
        .unwrap()
        .is_none());
    for agent in ["p1", "p2"] {
        assert_eq!(
            restarted
                .list_managed_deployments_async(&tenant, agent)
                .await
                .unwrap()
                .len(),
            1
        );
    }
    f.sql(
        "DROP TRIGGER fail_wave;",
        "DROP TRIGGER fail_wave ON managed_agent_deployments; DROP FUNCTION fail_wave();",
    )
    .await;
    // Two independent store handles race the same start: both return one durable identity.
    let other = f.reopen().await;
    let plans = race(restarted.clone(), other.clone(), &tenant, true).await;
    let a = &plans[0];
    let b = &plans[1];
    assert_eq!(a.agents["p1"].status, "pending");
    assert_eq!(a.agents["w1"].status, "not_issued");
    assert_eq!(a.rollout_id, b.rollout_id);
    assert_eq!(a.active_deployments, b.active_deployments);
    for agent in ["p1", "p2"] {
        assert_eq!(
            other
                .list_managed_deployments_async(&tenant, agent)
                .await
                .unwrap()
                .len(),
            2
        );
    }
    // Fail the second standard insert and verify the first deployment and phase roll back together.
    f.sql("CREATE TRIGGER fail_wave BEFORE INSERT ON managed_agent_deployments WHEN NEW.agent_id='w2' AND NEW.revision='candidate' BEGIN SELECT RAISE(ABORT,'injected wave failure'); END;",
    "CREATE FUNCTION fail_wave() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.agent_id='w2' AND NEW.revision='candidate' THEN RAISE EXCEPTION 'injected wave failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_wave BEFORE INSERT ON managed_agent_deployments FOR EACH ROW EXECUTE FUNCTION fail_wave();").await;
    ack(&restarted, &tenant, "p1", a).await;
    ack(&restarted, &tenant, "p2", a).await;
    assert!(other
        .advance_managed_group_rollout_async(&tenant, "group", Some(&signing_issuer))
        .await
        .is_err());
    let after = f.reopen().await;
    assert_eq!(
        after
            .get_managed_group_rollout_async(&tenant, "group")
            .await
            .unwrap()
            .unwrap()
            .phase,
        RolloutPhase::Pilot
    );
    assert_eq!(
        after
            .list_managed_deployments_async(&tenant, "w1")
            .await
            .unwrap()
            .len(),
        1
    );
    f.sql(
        "DROP TRIGGER fail_wave;",
        "DROP TRIGGER fail_wave ON managed_agent_deployments; DROP FUNCTION fail_wave();",
    )
    .await;
    let plans = race(after.clone(), other.clone(), &tenant, false).await;
    let a = &plans[0];
    let b = &plans[1];
    assert_eq!(a.active_deployments, b.active_deployments);
    assert_eq!(a.phase, RolloutPhase::Standard);
    assert_eq!(a.agents["p1"].status, "applied");
    assert!(a.agents["p1"].last_matching_acknowledgement.is_some());
    assert_eq!(a.agents["w1"].status, "pending");
    for agent in ["w1", "w2"] {
        assert_eq!(
            after
                .list_managed_deployments_async(&tenant, agent)
                .await
                .unwrap()
                .len(),
            2
        );
    }
    // Retry pause/resume and rollback across a new store handle, then confirm via real store ACKs.
    after
        .pause_managed_group_rollout_async(&tenant, "group")
        .await
        .unwrap();
    assert!(other
        .delete_managed_group_async(&tenant, "group")
        .await
        .is_err());
    let resumed = other
        .resume_managed_group_rollout_async(&tenant, "group", &signing_issuer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resumed.phase, RolloutPhase::Standard);
    // An interrupted rollback cannot expose only the first baseline deployment.
    f.sql("CREATE TRIGGER fail_wave BEFORE INSERT ON managed_agent_deployments WHEN NEW.agent_id='p2' AND NEW.action='rollback' BEGIN SELECT RAISE(ABORT,'injected rollback failure'); END;",
    "CREATE FUNCTION fail_wave() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.agent_id='p2' AND NEW.action='rollback' THEN RAISE EXCEPTION 'injected rollback failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_wave BEFORE INSERT ON managed_agent_deployments FOR EACH ROW EXECUTE FUNCTION fail_wave();").await;
    assert!(after
        .rollback_managed_group_rollout_async(&tenant, "group", &signing_issuer)
        .await
        .is_err());
    for agent in ["p1", "p2", "w1", "w2"] {
        assert_eq!(
            other
                .list_managed_deployments_async(&tenant, agent)
                .await
                .unwrap()
                .len(),
            2
        );
    }
    assert_eq!(
        other
            .get_managed_group_rollout_async(&tenant, "group")
            .await
            .unwrap()
            .unwrap()
            .phase,
        RolloutPhase::Standard
    );
    f.sql(
        "DROP TRIGGER fail_wave;",
        "DROP TRIGGER fail_wave ON managed_agent_deployments; DROP FUNCTION fail_wave();",
    )
    .await;
    let rb = after
        .rollback_managed_group_rollout_async(&tenant, "group", &signing_issuer)
        .await
        .unwrap()
        .unwrap();
    let retry = other
        .rollback_managed_group_rollout_async(&tenant, "group", &signing_issuer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rb.active_deployments, retry.active_deployments);
    assert!(other
        .delete_managed_group_async(&tenant, "group")
        .await
        .is_err());
    for agent in ["p1", "p2", "w1", "w2"] {
        ack(&after, &tenant, agent, &rb).await;
    }
    assert_eq!(
        other
            .get_managed_group_rollout_async(&tenant, "group")
            .await
            .unwrap()
            .unwrap()
            .phase,
        RolloutPhase::RolledBack
    );
    // A new plan freezes the workers too: an intervening individual deployment must block promotion.
    after
        .create_managed_group_revision_async(&tenant, "group", "next", "default: deny\n")
        .await
        .unwrap();
    after
        .approve_managed_group_revision_async(&tenant, "group", "next")
        .await
        .unwrap();
    let next = after
        .start_managed_group_rollout_async(&tenant, "group", "next", &signing_issuer)
        .await
        .unwrap();
    after
        .deploy_managed_revision_async(&tenant, "w1", "base", false, &signing_issuer)
        .await
        .unwrap();
    ack(&after, &tenant, "p1", &next).await;
    ack(&after, &tenant, "p2", &next).await;
    let conflict = other
        .get_managed_group_rollout_async(&tenant, "group")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(conflict.phase, RolloutPhase::Failed);
    assert!(conflict.failure_reason.unwrap().contains("w1"));
    // Competing plans share Agents: transaction ownership admits only one group.
    let tenant = setup(&f.store).await;
    f.store
        .create_managed_group_async(&tenant, "other", "Other")
        .await
        .unwrap();
    for agent in ["p1", "p2", "w1", "w2"] {
        f.store
            .add_managed_group_member_async(&tenant, "other", agent, agent.starts_with('p'))
            .await
            .unwrap();
    }
    f.store
        .create_managed_group_revision_async(&tenant, "other", "candidate", "default: deny\n")
        .await
        .unwrap();
    f.store
        .approve_managed_group_revision_async(&tenant, "other", "candidate")
        .await
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let runtime = tokio::runtime::Handle::current();
    let mut tasks = Vec::new();
    for group in ["group", "other"] {
        let store = f.reopen().await;
        let barrier = barrier.clone();
        let runtime = runtime.clone();
        let tenant = tenant.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            barrier.wait();
            runtime.block_on(async {
                store
                    .start_managed_group_rollout_async(&tenant, group, "candidate", &issuer())
                    .await
            })
        }));
    }
    let mut accepted = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(
        accepted, 1,
        "overlapping plans must never both own the same Agents"
    );
    for agent in ["p1", "p2"] {
        assert_eq!(
            f.store
                .list_managed_deployments_async(&tenant, agent)
                .await
                .unwrap()
                .len(),
            2
        );
    }
    // A deterministic expired ACK deadline closes the canary gate, then a rejected
    // rollback ACK produces Failed rather than waiting indefinitely or claiming success.
    let tenant = setup(&f.store).await;
    let overdue_candidate = f
        .store
        .start_managed_group_rollout_async(&tenant, "group", "candidate", &signing_issuer)
        .await
        .unwrap();
    f.sql(
        "UPDATE managed_agent_deployments SET issued_at_unix=0 WHERE status='issued';",
        "UPDATE managed_agent_deployments SET issued_at_unix=0 WHERE status='issued';",
    )
    .await;
    ack(&f.store, &tenant, "p1", &overdue_candidate).await;
    let view = f
        .store
        .get_managed_group_rollout_async(&tenant, "group")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        view.agents["p1"].status, "overdue",
        "a late ACK must not reopen an expired canary gate"
    );
    let rb = f
        .store
        .advance_managed_group_rollout_async(&tenant, "group", Some(&signing_issuer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rb.phase, RolloutPhase::RollingBack);
    assert!(rb.failure_reason.as_deref().unwrap().contains("timed out"));
    for agent in ["w1", "w2"] {
        assert_eq!(
            f.store
                .list_managed_deployments_async(&tenant, agent)
                .await
                .unwrap()
                .len(),
            1
        );
    }
    let dep = f
        .store
        .list_managed_deployments_async(&tenant, "p1")
        .await
        .unwrap()
        .remove(0);
    f.store
        .acknowledge_managed_bundle_async(
            &tenant,
            "p1",
            &AppliedReport {
                deployment_sequence: dep.deployment_sequence,
                revision: dep.revision,
                policy_sha256: dep.policy_sha256,
                status: "rejected".into(),
            },
        )
        .await
        .unwrap();
    let failed = f
        .store
        .get_managed_group_rollout_async(&tenant, "group")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failed.phase, RolloutPhase::Failed);
    assert!(failed
        .failure_reason
        .unwrap()
        .contains("rollback unresolved"));
    // Late baseline ACKs are truthful Agent state, but cannot confirm a rollback
    // after its deadline. They must leave the group explicitly Failed.
    let tenant = setup(&f.store).await;
    f.store
        .start_managed_group_rollout_async(&tenant, "group", "candidate", &signing_issuer)
        .await
        .unwrap();
    let rb = f
        .store
        .rollback_managed_group_rollout_async(&tenant, "group", &signing_issuer)
        .await
        .unwrap()
        .unwrap();
    f.sql("UPDATE managed_agent_deployments SET issued_at_unix=0 WHERE action='rollback' AND status='issued';", "UPDATE managed_agent_deployments SET issued_at_unix=0 WHERE action='rollback' AND status='issued';").await;
    ack(&f.store, &tenant, "p1", &rb).await;
    let late = f
        .store
        .get_managed_group_rollout_async(&tenant, "group")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(late.phase, RolloutPhase::Failed);
    assert_eq!(late.agents["p1"].status, "overdue");
    assert!(late.failure_reason.unwrap().contains("rollback unresolved"));

    // One pilot may already run the candidate before joining this plan.
    // Its frozen baseline is that same immutable revision; restoration still
    // needs a new signed sequence and must not abort the rest of the rollback.
    let tenant = setup(&f.store).await;
    f.store
        .create_managed_revision_async(&tenant, "p1", "candidate", "default: deny\n")
        .await
        .unwrap();
    f.store
        .approve_managed_revision_async(&tenant, "p1", "candidate")
        .await
        .unwrap();
    let preexisting = f
        .store
        .deploy_managed_revision_async(&tenant, "p1", "candidate", false, &signing_issuer)
        .await
        .unwrap();
    f.store
        .acknowledge_managed_bundle_async(
            &tenant,
            "p1",
            &AppliedReport {
                deployment_sequence: preexisting.deployment_sequence,
                revision: preexisting.revision,
                policy_sha256: preexisting.policy_sha256,
                status: "applied".into(),
            },
        )
        .await
        .unwrap();
    let plan = f
        .store
        .start_managed_group_rollout_async(&tenant, "group", "candidate", &signing_issuer)
        .await
        .unwrap();
    let restored = f
        .store
        .rollback_managed_group_rollout_async(&tenant, "group", &signing_issuer)
        .await
        .unwrap()
        .unwrap();
    assert!(restored.active_deployments["p1"] > plan.active_deployments["p1"]);
    for agent in ["p1", "p2"] {
        ack(&f.store, &tenant, agent, &restored).await;
    }
    assert_eq!(
        f.store
            .get_managed_group_rollout_async(&tenant, "group")
            .await
            .unwrap()
            .unwrap()
            .phase,
        RolloutPhase::RolledBack
    );

    // Upgrade a populated legacy group schema: preserve identities and rows;
    // an old in-flight plan lacking sequence snapshots must never auto-promote.
    let tenant = setup(&f.store).await;
    let legacy = f
        .store
        .start_managed_group_rollout_async(&tenant, "group", "candidate", &signing_issuer)
        .await
        .unwrap();
    let original_columns="tenant_id,group_id,rollout_id,revision,policy_sha256,issuer_key_id,phase,pilot_agents_json,standard_agents_json,active_deployments_json,previous_revisions_json,failure_reason,created_at_unix,updated_at_unix";
    let source = include_str!("../src/tenant_store/managed_postgres.rs");
    let native = source
        .split("CREATE TABLE IF NOT EXISTS managed_group_rollouts (")
        .nth(1)
        .unwrap()
        .split(");\"")
        .next()
        .unwrap();
    let legacy_columns = native
        .lines()
        .filter(|line| !line.contains("initial_sequences_json") && !line.contains("plan_sequence"))
        .collect::<Vec<_>>()
        .join("\n");
    let postgres_legacy=format!("CREATE TEMP TABLE legacy_rows AS SELECT {original_columns} FROM managed_group_rollouts; DROP TABLE managed_group_rollouts; CREATE TABLE managed_group_rollouts ({legacy_columns}); INSERT INTO managed_group_rollouts ({original_columns}) SELECT {original_columns} FROM legacy_rows; DROP TABLE legacy_rows; DELETE FROM llm_firewall_schema_migrations WHERE version=27;");
    f.sql(
        "ALTER TABLE managed_group_rollouts DROP COLUMN initial_sequences_json;",
        &postgres_legacy,
    )
    .await;

    if let Some(url) = &f.postgres {
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
    let upgraded = f.reopen().await;
    let restored = upgraded
        .get_managed_group_rollout_async(&tenant, "group")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored.rollout_id, legacy.rollout_id);
    assert_eq!(restored.active_deployments, legacy.active_deployments);
    let refused = upgraded
        .advance_managed_group_rollout_async(&tenant, "group", Some(&signing_issuer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(refused.phase, RolloutPhase::Failed);
    assert!(refused.failure_reason.unwrap().contains("legacy"));
    for agent in ["w1", "w2"] {
        assert_eq!(
            upgraded
                .list_managed_deployments_async(&tenant, agent)
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_atomic_restart_and_concurrency() {
    controls(Fixture::new(None).await).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable SOUP_GROUP_TEST_POSTGRES_URL database"]
async fn postgres_atomic_restart_and_concurrency() {
    controls(
        Fixture::new(Some(
            std::env::var("SOUP_GROUP_TEST_POSTGRES_URL").expect("disposable database URL"),
        ))
        .await,
    )
    .await;
}
