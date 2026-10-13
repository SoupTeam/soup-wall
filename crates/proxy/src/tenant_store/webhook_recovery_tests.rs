// SPDX-License-Identifier: Apache-2.0

//! Failure injection into the production outbox. HTTP receiver witnesses are
//! covered separately; this module does not pretend stored status proves receipt.

use super::*;

struct TestDb {
    store: TenantStore,
    postgres: Option<tokio_postgres::Client>,
    postgres_url: Option<String>,
    path: std::path::PathBuf,
    _directory: tempfile::TempDir,
}

impl TestDb {
    fn sqlite() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbox.sqlite");
        Self {
            store: TenantStore::open(&path).unwrap(),
            postgres: None,
            postgres_url: None,
            path,
            _directory: directory,
        }
    }

    async fn seed(&self) -> WebhookDelivery {
        let store = self
            .store
            .clone()
            .with_webhook_signing_key_base64url(&base64url(&[7; 32]))
            .unwrap();
        let tenant = store
            .create_tenant_async(&random_id("webhook_test"))
            .await
            .unwrap();
        store
            .create_webhook_destination_async(
                &tenant.id,
                "https://receiver.example.test/events",
                &[],
            )
            .await
            .unwrap();
        let version = store
            .create_policy_version_async(&tenant.id, "author", TenantPolicyDocument::new(None))
            .await
            .unwrap();
        store
            .approve_policy_version_async(&tenant.id, &version.id, "reviewer")
            .await
            .unwrap();
        store
            .deploy_policy_version_async(
                &tenant.id,
                &version.id,
                "reviewer",
                PolicyDeploymentAction::Activate,
            )
            .await
            .unwrap();
        let rows = store
            .list_webhook_deliveries_async(&tenant.id, 100)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        rows[0].clone()
    }

    async fn claim(&self) -> Option<PendingWebhookDelivery> {
        claim(&self.store).await
    }

    async fn finish(&self, delivery: &WebhookDelivery, result: WebhookAttemptResult) -> bool {
        match &self.store.postgres {
            Some(postgres) => postgres
                .finish_webhook_delivery(delivery, result)
                .await
                .unwrap(),
            None => self
                .store
                .finish_webhook_delivery(delivery, result)
                .unwrap(),
        }
    }

    async fn row(&self, delivery: &WebhookDelivery) -> WebhookDelivery {
        self.store
            .list_webhook_deliveries_async(&delivery.tenant_id, 100)
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.id == delivery.id)
            .unwrap()
    }

    // Move scheduling time only; claim ownership, retry counts, and status
    // transitions always run through the production implementation.
    async fn make_due(&self, id: &str) {
        let now = now_unix() - 1;
        match &self.postgres {
            Some(client) => {
                client.execute("UPDATE tenant_webhook_deliveries SET next_attempt_at_unix = $2, locked_until_unix = CASE WHEN status = 'in_flight' THEN $2 ELSE locked_until_unix END WHERE id = $1", &[&id, &now]).await.unwrap();
            }
            None => {
                self.store.connection().unwrap().execute("UPDATE tenant_webhook_deliveries SET next_attempt_at_unix = ?2, locked_until_unix = CASE WHEN status = 'in_flight' THEN ?2 ELSE locked_until_unix END WHERE id = ?1", params![id, now]).unwrap();
            }
        }
    }

    async fn deactivate(&self, delivery: &WebhookDelivery) {
        assert!(self
            .store
            .deactivate_webhook_destination_async(&delivery.tenant_id, &delivery.destination_id)
            .await
            .unwrap());
    }

    async fn reopen(&self) -> TenantStore {
        match &self.postgres_url {
            Some(url) => TenantStore::open_postgres_for_test(url, 1000)
                .await
                .unwrap(),
            None => TenantStore::open(&self.path).unwrap(),
        }
    }
}

async fn claim(store: &TenantStore) -> Option<PendingWebhookDelivery> {
    match &store.postgres {
        Some(postgres) => postgres.claim_webhook_delivery().await.unwrap(),
        None => store.claim_webhook_delivery().unwrap(),
    }
}

fn success() -> WebhookAttemptResult {
    WebhookAttemptResult {
        http_status: Some(204),
        error: None,
    }
}
fn failure() -> WebhookAttemptResult {
    WebhookAttemptResult {
        http_status: Some(503),
        error: Some("webhook endpoint returned HTTP 503".into()),
    }
}

async fn stale_completion_races(db: &TestDb) {
    let delivery = db.seed().await;
    let old = db.claim().await.unwrap();
    db.make_due(&delivery.id).await;
    let new = db.claim().await.unwrap();
    assert_eq!(new.delivery.attempt_count, 2);
    assert_eq!(old.delivery.id, new.delivery.id);
    assert_eq!(old.event, new.event);
    assert!(db.finish(&new.delivery, success()).await);
    let delivered = db.row(&delivery).await;
    assert_eq!(delivered.status, WebhookDeliveryStatus::Delivered);
    assert!(!db.finish(&old.delivery, failure()).await);
    assert!(!db.finish(&old.delivery, success()).await);
    assert!(
        !db.finish(&new.delivery, failure()).await,
        "completion replay is fenced"
    );
    assert_eq!(
        db.row(&delivery).await,
        delivered,
        "stale failure must not reset a delivered event"
    );

    let delivery = db.seed().await;
    let old = db.claim().await.unwrap();
    db.make_due(&delivery.id).await;
    let new = db.claim().await.unwrap();
    assert!(db.finish(&new.delivery, failure()).await);
    let pending = db.row(&delivery).await;
    assert_eq!(pending.status, WebhookDeliveryStatus::Pending);
    assert!(!db.finish(&old.delivery, success()).await);
    assert_eq!(
        db.row(&delivery).await,
        pending,
        "stale success cannot hide a newer failure"
    );
    db.deactivate(&delivery).await;
}

async fn lease_and_attempt_are_independent_fences(db: &TestDb) {
    let delivery = db.seed().await;
    let current = db.claim().await.unwrap();
    let mut wrong_attempt = current.delivery.clone();
    wrong_attempt.attempt_count += 1;
    assert!(!db.finish(&wrong_attempt, success()).await);
    let mut wrong_lease = current.delivery.clone();
    wrong_lease.locked_until_unix = Some(current.delivery.locked_until_unix.unwrap() + 1);
    assert!(!db.finish(&wrong_lease, success()).await);
    let mut expired = current.delivery.clone();
    db.make_due(&delivery.id).await;
    expired.locked_until_unix = db.row(&delivery).await.locked_until_unix;
    assert!(
        !db.finish(&expired, success()).await,
        "matching but expired lease cannot finish"
    );
    let replacement = db.claim().await.unwrap();
    assert_eq!(replacement.delivery.attempt_count, 2);
    assert!(db.finish(&replacement.delivery, success()).await);
}

async fn retry_budget_and_error_bounds(db: &TestDb) {
    let delivery = db.seed().await;
    for attempt in 1..=WEBHOOK_MAX_ATTEMPTS {
        let current = db.claim().await.unwrap();
        assert_eq!(current.delivery.attempt_count, attempt);
        let started = now_unix();
        assert!(
            db.finish(
                &current.delivery,
                WebhookAttemptResult {
                    http_status: Some(503),
                    error: Some("🧱".repeat(200))
                }
            )
            .await
        );
        let row = db.row(&delivery).await;
        assert_eq!(row.last_http_status, Some(503));
        assert_eq!(row.last_error.as_ref().unwrap().len(), 512);
        assert!(row.locked_until_unix.is_none());
        assert!(row.delivered_at_unix.is_none());
        if attempt < WEBHOOK_MAX_ATTEMPTS {
            assert_eq!(row.status, WebhookDeliveryStatus::Pending);
            assert!(row.next_attempt_at_unix >= started + 5 * (1_i64 << attempt));
            assert!(
                db.claim().await.is_none(),
                "backoff must prevent immediate retry"
            );
            db.make_due(&delivery.id).await;
        } else {
            assert_eq!(row.status, WebhookDeliveryStatus::Dead);
            assert!(db.claim().await.is_none());
        }
    }
}

async fn expired_claims_exhaust_budget(db: &TestDb) {
    let delivery = db.seed().await;
    let mut last = None;
    for attempt in 1..=WEBHOOK_MAX_ATTEMPTS {
        let current = db.claim().await.unwrap();
        assert_eq!(current.delivery.attempt_count, attempt);
        assert!(
            db.claim().await.is_none(),
            "live lease excludes competing claim"
        );
        db.make_due(&delivery.id).await;
        last = Some(current);
    }
    assert!(
        db.claim().await.is_none(),
        "crashes must not bypass maximum attempts"
    );
    let row = db.row(&delivery).await;
    assert_eq!(row.status, WebhookDeliveryStatus::Dead);
    assert_eq!(row.attempt_count, WEBHOOK_MAX_ATTEMPTS);
    assert_eq!(
        row.last_error.as_deref(),
        Some("lease_expired_after_max_attempts")
    );
    assert!(row.last_http_status.is_none());
    assert!(row.locked_until_unix.is_none());
    assert!(!db.finish(&last.unwrap().delivery, success()).await);
}

async fn destination_deactivation(db: &TestDb) {
    let queued = db.seed().await;
    db.deactivate(&queued).await;
    assert!(db.claim().await.is_none());
    let row = db.row(&queued).await;
    assert_eq!(row.status, WebhookDeliveryStatus::Dead);
    assert_eq!(row.attempt_count, 0);
    assert_eq!(row.last_error.as_deref(), Some("destination_inactive"));

    let delivery = db.seed().await;
    let in_flight = db.claim().await.unwrap();
    db.deactivate(&delivery).await;
    assert!(db.claim().await.is_none());
    assert_eq!(
        db.row(&delivery).await.status,
        WebhookDeliveryStatus::InFlight
    );
    assert!(
        db.finish(&in_flight.delivery, success()).await,
        "deactivation cannot erase a completed external effect"
    );
    assert_eq!(
        db.row(&delivery).await.status,
        WebhookDeliveryStatus::Delivered
    );

    let delivery = db.seed().await;
    let in_flight = db.claim().await.unwrap();
    db.deactivate(&delivery).await;
    assert!(db.finish(&in_flight.delivery, failure()).await);
    assert_eq!(db.row(&delivery).await.status, WebhookDeliveryStatus::Dead);
    assert!(
        db.claim().await.is_none(),
        "deactivated destination must not be retried"
    );

    let delivery = db.seed().await;
    let _abandoned = db.claim().await.unwrap();
    db.deactivate(&delivery).await;
    db.make_due(&delivery.id).await;
    assert!(db.claim().await.is_none());
    assert_eq!(db.row(&delivery).await.status, WebhookDeliveryStatus::Dead);
}

async fn populated_reopen_preserves_ownership(db: &TestDb) {
    let delivered = db.seed().await;
    let current = db.claim().await.unwrap();
    assert!(db.finish(&current.delivery, success()).await);
    let pending = db.seed().await;
    let in_flight = db.claim().await.unwrap();
    let snapshot = db.row(&pending).await;
    let delivered_snapshot = db.row(&delivered).await;
    let reopened = db.reopen().await;
    assert_eq!(
        reopened
            .list_webhook_deliveries_async(&pending.tenant_id, 100)
            .await
            .unwrap(),
        vec![snapshot]
    );
    assert_eq!(
        reopened
            .list_webhook_deliveries_async(&delivered.tenant_id, 100)
            .await
            .unwrap(),
        vec![delivered_snapshot]
    );
    assert!(
        claim(&reopened).await.is_none(),
        "startup migrations must not reset live claims"
    );
    db.make_due(&pending.id).await;
    let recovered = claim(&reopened).await.unwrap();
    assert_eq!(recovered.delivery.event_id, in_flight.delivery.event_id);
    assert_eq!(recovered.delivery.id, in_flight.delivery.id);
    assert_eq!(recovered.delivery.attempt_count, 2);
    assert!(db.finish(&recovered.delivery, success()).await);
    assert!(!db.finish(&in_flight.delivery, failure()).await);
}

#[tokio::test]
async fn sqlite_stale_worker_cannot_rewrite_newer_delivery() {
    stale_completion_races(&TestDb::sqlite()).await;
}
#[tokio::test]
async fn sqlite_lease_and_attempt_fences() {
    lease_and_attempt_are_independent_fences(&TestDb::sqlite()).await;
}
#[tokio::test]
async fn sqlite_retry_backoff_dead_letter_and_bounded_errors() {
    retry_budget_and_error_bounds(&TestDb::sqlite()).await;
}
#[tokio::test]
async fn sqlite_crashed_workers_exhaust_retry_budget() {
    expired_claims_exhaust_budget(&TestDb::sqlite()).await;
}
#[tokio::test]
async fn sqlite_deactivation_preserves_real_in_flight_results() {
    destination_deactivation(&TestDb::sqlite()).await;
}

#[tokio::test]
async fn sqlite_populated_startup_migrations_preserve_claims() {
    let db = TestDb::sqlite();
    let schema = db
        .store
        .connection()
        .unwrap()
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name = 'tenant_webhook_deliveries'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    populated_reopen_preserves_ownership(&db).await;
    assert_eq!(
        db.store
            .connection()
            .unwrap()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'tenant_webhook_deliveries'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        schema
    );
}

#[tokio::test]
async fn sqlite_independent_connections_claim_once() {
    let db = TestDb::sqlite();
    let delivery = db.seed().await;
    let first = TenantStore::open(&db.path).unwrap();
    let second = TenantStore::open(&db.path).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let threads = [first, second]
        .into_iter()
        .map(|store| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .claim_webhook_delivery()
                    .unwrap()
                    .map(|claim| claim.delivery.id)
            })
        })
        .collect::<Vec<_>>();
    let ids = threads
        .into_iter()
        .filter_map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec![delivery.id.clone()]);
    assert_eq!(db.row(&delivery).await.attempt_count, 1);
}

#[tokio::test]
#[ignore = "requires LLM_FW_TEST_POSTGRES_URL pointing at a dedicated disposable database; do not share with other test suites"]
async fn postgres_webhook_recovery_and_fenced_completion() {
    let url = std::env::var("LLM_FW_TEST_POSTGRES_URL")
        .expect("dedicated disposable PostgreSQL URL is required");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let store = TenantStore::open_postgres_for_test(&url, 1000)
        .await
        .unwrap();
    let existing: i64 = client.query_one("SELECT count(*) FROM tenant_webhook_deliveries WHERE status IN ('pending', 'in_flight')", &[]).await.unwrap().get(0);
    assert_eq!(existing, 0, "use a dedicated disposable database without pending deliveries; this test never deletes existing data");
    let directory = tempfile::tempdir().unwrap();
    let db = TestDb {
        store,
        postgres: Some(client),
        postgres_url: Some(url),
        path: directory.path().join("unused"),
        _directory: directory,
    };
    stale_completion_races(&db).await;
    println!("postgres stale_failure_after_new_success and stale_success_after_new_failure: pass");
    lease_and_attempt_are_independent_fences(&db).await;
    retry_budget_and_error_bounds(&db).await;
    expired_claims_exhaust_budget(&db).await;
    destination_deactivation(&db).await;
    println!("postgres lease/attempt fences, retry/dead-letter, crash budget, deactivation: pass");
    let migrations_before = db
        .postgres
        .as_ref()
        .unwrap()
        .query(
            "SELECT version, applied_at_unix FROM llm_firewall_schema_migrations ORDER BY version",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get::<_, i64>(0), row.get::<_, i64>(1)))
        .collect::<Vec<_>>();
    populated_reopen_preserves_ownership(&db).await;
    let migrations_after = db
        .postgres
        .as_ref()
        .unwrap()
        .query(
            "SELECT version, applied_at_unix FROM llm_firewall_schema_migrations ORDER BY version",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get::<_, i64>(0), row.get::<_, i64>(1)))
        .collect::<Vec<_>>();
    assert_eq!(migrations_before, migrations_after);
    let delivery = db.seed().await;
    let independent = db.reopen().await;
    let (first, second) = tokio::join!(claim(&db.store), claim(&independent));
    let claims = [first, second].into_iter().flatten().collect::<Vec<_>>();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].delivery.id, delivery.id);
    assert_eq!(db.row(&delivery).await.attempt_count, 1);
    assert!(db.finish(&claims[0].delivery, success()).await);
    println!("postgres populated migration/reopen and independent concurrent claims: pass");
}
