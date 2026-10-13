// SPDX-License-Identifier: Apache-2.0

//! Disposable SOU-33 receiver evidence. Only this cfg(test) module permits an
//! HTTP loopback transport; production validation, DNS pinning and TLS remain
//! in `deliver_webhook`. Run the ignored parent test, not the child helper.

use std::{
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{bail, Context};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path as RoutePath, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    base64url, hex_lower, now_unix, send_webhook_request, PolicyDeploymentAction,
    TenantModelPolicy, TenantPolicyDocument, TenantStore, WebhookDelivery, WebhookDeliveryStatus,
    WebhookSigningKey,
};

const WORKER_TEST: &str = "tenant_store::webhook_delivery_tests::webhook_receiver_demo_worker";
const FIXTURE_KEY: [u8; 32] = [42; 32];

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ReceiverReceipt {
    scenario: String,
    delivery_id: String,
    event_id: String,
    body_sha256: String,
    signature_valid: bool,
    status: u16,
    duplicate: bool,
    effect_applied: bool,
}

struct ReceiverEvidence {
    secret: String,
    receipt_file: File,
    receipts: Vec<ReceiverReceipt>,
    // The delivery header is not signed. Only authenticated body fields form
    // the deduplication key; a changed header cannot repeat an applied effect.
    applied: HashMap<(String, String), String>,
    first_authenticated_request: Option<(Vec<u8>, String)>,
}

type SharedReceiver = Arc<Mutex<ReceiverEvidence>>;

fn decode_signature(value: &str) -> Option<Vec<u8>> {
    let value = value.strip_prefix("sha256=")?;
    if value.len() != 64 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)? as u8;
            let low = (pair[1] as char).to_digit(16)? as u8;
            Some((high << 4) | low)
        })
        .collect()
}

async fn receive(
    State(shared): State<SharedReceiver>,
    RoutePath(scenario): RoutePath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let mut state = shared.lock().expect("receiver state poisoned");
    let signature = headers
        .get("x-llm-firewall-signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let mut mac = Hmac::<Sha256>::new_from_slice(state.secret.as_bytes()).unwrap();
    mac.update(&body);
    let signature_valid =
        decode_signature(signature).is_some_and(|signature| mac.verify_slice(&signature).is_ok());
    let payload: serde_json::Value = if signature_valid {
        serde_json::from_slice(&body).unwrap_or_default()
    } else {
        serde_json::Value::Null
    };
    let event_id = payload["event_id"].as_str().unwrap_or_default().to_owned();
    let tenant_id = payload["tenant_id"].as_str().unwrap_or_default().to_owned();
    let delivery_id = headers
        .get("x-llm-firewall-delivery")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let digest = hex_lower(&Sha256::digest(&body));
    let key = (tenant_id, event_id.clone());
    let transient_failure = scenario == "retry"
        && !state
            .receipts
            .iter()
            .any(|receipt| receipt.scenario == "retry");
    let status = if !signature_valid || key.0.is_empty() || key.1.is_empty() {
        StatusCode::UNAUTHORIZED
    } else if transient_failure {
        StatusCode::SERVICE_UNAVAILABLE
    } else if state
        .applied
        .get(&key)
        .is_some_and(|existing| *existing != digest)
    {
        // A signed but conflicting event identity is not an idempotent retry.
        StatusCode::CONFLICT
    } else {
        StatusCode::OK
    };
    let duplicate = status.is_success() && state.applied.contains_key(&key);
    let effect_applied = status.is_success() && !duplicate;
    if effect_applied {
        state.applied.insert(key, digest.clone());
    }
    if signature_valid && state.first_authenticated_request.is_none() {
        state.first_authenticated_request = Some((body.to_vec(), signature.to_owned()));
    }
    let receipt = ReceiverReceipt {
        scenario,
        delivery_id,
        event_id,
        body_sha256: digest,
        signature_valid,
        status: status.as_u16(),
        duplicate,
        effect_applied,
    };
    // Receipt persistence is independent of the sender's database and happens
    // before its HTTP response. No body, signature, secret or URL is recorded.
    serde_json::to_writer(&mut state.receipt_file, &receipt).unwrap();
    state.receipt_file.write_all(b"\n").unwrap();
    state.receipt_file.sync_all().unwrap();
    state.receipts.push(receipt);
    status
}

struct SenderChild(Option<Child>, PathBuf);

impl SenderChild {
    fn start(directory: &Path, database: &Path, target: &str, pause: bool) -> anyhow::Result<Self> {
        let output = File::create(directory.join("sender.log"))?;
        let completed = directory.join("sender.completed");
        if completed.exists() {
            std::fs::remove_file(&completed)?;
        }
        let child =
            Command::new(directory.join(format!("sender-fixture{}", std::env::consts::EXE_SUFFIX)))
                .args(["--ignored", "--exact", WORKER_TEST, "--nocapture"])
                .env("SOUP_WALL_WEBHOOK_DEMO_DATABASE", database)
                .env("SOUP_WALL_WEBHOOK_DEMO_TARGET", target)
                .env("SOUP_WALL_WEBHOOK_DEMO_COMPLETED", &completed)
                .env(
                    "SOUP_WALL_WEBHOOK_DEMO_MARKER",
                    directory.join("response.observed"),
                )
                .env(
                    "SOUP_WALL_WEBHOOK_DEMO_PAUSE",
                    if pause { "1" } else { "0" },
                )
                .stdout(Stdio::from(output.try_clone()?))
                .stderr(Stdio::from(output))
                .spawn()
                .context("could not start disposable sender")?;
        Ok(Self(Some(child), completed))
    }

    async fn expect_success(&mut self) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let child = self.0.as_mut().expect("sender already reaped");
            if let Some(status) = child.try_wait()? {
                self.0.take();
                if !status.success() {
                    bail!("disposable sender exited unsuccessfully: {status}");
                }
                if !self.1.is_file() {
                    bail!("sender exited without its completion witness (possibly zero matched tests)");
                }
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("disposable sender did not exit within 15 seconds");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn interrupt(&mut self) -> anyhow::Result<()> {
        let child = self.0.as_mut().expect("sender already reaped");
        child
            .kill()
            .context("could not interrupt disposable sender")?;
        let status = child.wait()?;
        self.0.take();
        assert!(
            !status.success(),
            "interrupted sender unexpectedly succeeded"
        );
        Ok(())
    }
}

impl Drop for SenderChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct ReceiverTask(tokio::task::JoinHandle<()>);

impl Drop for ReceiverTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn open_fixture(path: &Path) -> anyhow::Result<TenantStore> {
    TenantStore::open(path)?.with_webhook_signing_key_base64url(&base64url(&FIXTURE_KEY))
}

fn enqueue_case(
    store: &TenantStore,
    tenant_id: &str,
    case: &str,
) -> anyhow::Result<WebhookDelivery> {
    let previous = store
        .list_webhook_deliveries(tenant_id, 100)?
        .into_iter()
        .map(|delivery| delivery.id)
        .collect::<HashSet<_>>();
    let version = store.create_policy_version(
        tenant_id,
        "fixture-author",
        TenantPolicyDocument::new(Some(TenantModelPolicy {
            allowed_models: vec![format!("fixture-{case}")],
        })),
    )?;
    store.approve_policy_version(tenant_id, &version.id, "fixture-owner")?;
    store.deploy_policy_version(
        tenant_id,
        &version.id,
        "fixture-owner",
        PolicyDeploymentAction::Activate,
    )?;
    let mut added = store
        .list_webhook_deliveries(tenant_id, 100)?
        .into_iter()
        .filter(|delivery| !previous.contains(&delivery.id));
    let delivery = added.next().context("fixture deployment did not enqueue")?;
    assert!(
        added.next().is_none(),
        "fixture unexpectedly enqueued multiple deliveries"
    );
    Ok(delivery)
}

fn read_delivery(
    store: &TenantStore,
    original: &WebhookDelivery,
) -> anyhow::Result<WebhookDelivery> {
    store
        .list_webhook_deliveries(&original.tenant_id, 100)?
        .into_iter()
        .find(|delivery| delivery.id == original.id)
        .context("fixture delivery disappeared")
}

async fn wait_until_due(timestamp: i64) {
    let remaining = (timestamp - now_unix() + 1).max(0) as u64;
    assert!(
        remaining <= 35,
        "fixture attempted an unexpectedly long wait"
    );
    tokio::time::sleep(Duration::from_secs(remaining)).await;
}

#[tokio::test]
#[ignore = "child-process fixture; run webhook_receiver_recovery_demo instead"]
async fn webhook_receiver_demo_worker() -> anyhow::Result<()> {
    let Some(database) = std::env::var_os("SOUP_WALL_WEBHOOK_DEMO_DATABASE") else {
        return Ok(());
    };
    let target = std::env::var("SOUP_WALL_WEBHOOK_DEMO_TARGET")?;
    let target = reqwest::Url::parse(&target)?;
    // This is test-only defense in depth. There is no production HTTP/private
    // destination option or configuration flag introduced by this fixture.
    assert_eq!(target.scheme(), "http");
    assert_eq!(target.host_str(), Some("127.0.0.1"));
    let store = open_fixture(Path::new(&database))?;
    let pending = store
        .claim_webhook_delivery()?
        .context("no claimable fixture delivery")?;
    let key = WebhookSigningKey::from_base64url(&base64url(&FIXTURE_KEY))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let result = send_webhook_request(&client, target, &key, &pending).await;
    if std::env::var("SOUP_WALL_WEBHOOK_DEMO_PAUSE").as_deref() == Ok("1") {
        assert_eq!(result.http_status, Some(200));
        assert!(result.error.is_none());
        let marker = std::env::var_os("SOUP_WALL_WEBHOOK_DEMO_MARKER")
            .context("missing child response marker")?;
        let mut marker = File::create(marker)?;
        marker.write_all(b"HTTP success observed; completion not written\n")?;
        marker.sync_all()?;
        std::future::pending::<()>().await;
    }
    assert!(store.finish_webhook_delivery(&pending.delivery, result)?);
    let completed = std::env::var_os("SOUP_WALL_WEBHOOK_DEMO_COMPLETED")
        .context("missing child completion witness")?;
    let mut completed = File::create(completed)?;
    completed.write_all(b"completion committed\n")?;
    completed.sync_all()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disposable receiver, child interruption and real retry/lease delays (~45 seconds)"]
async fn webhook_receiver_recovery_demo() -> anyhow::Result<()> {
    let started = Instant::now();
    let directory = tempfile::tempdir()?;
    // Another checkout may rebuild a shared Cargo target during the real
    // lease wait. Pin the running test binary before creating any children.
    std::fs::copy(
        std::env::current_exe()?,
        directory
            .path()
            .join(format!("sender-fixture{}", std::env::consts::EXE_SUFFIX)),
    )?;
    let database = directory.path().join("sender.sqlite3");
    let receipts_path = directory.path().join("receiver-receipts.jsonl");
    let store = open_fixture(&database)?;
    let tenant = store.create_tenant("Disposable webhook receiver evidence")?;
    let issued = store
        .create_webhook_destination_async(&tenant.id, "https://receiver.example.test/events", &[])
        .await?;
    let receiver = Arc::new(Mutex::new(ReceiverEvidence {
        secret: issued.secret,
        receipt_file: OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&receipts_path)?,
        receipts: Vec::new(),
        applied: HashMap::new(),
        first_authenticated_request: None,
    }));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let router = Router::new()
        .route("/:scenario", post(receive))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(receiver.clone());
    let _receiver_task = ReceiverTask(tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("receiver failed");
    }));
    let target = |scenario: &str| format!("http://{address}/{scenario}");

    let useful = enqueue_case(&store, &tenant.id, "useful")?;
    SenderChild::start(directory.path(), &database, &target("useful"), false)?
        .expect_success()
        .await?;
    let useful_done = read_delivery(&store, &useful)?;
    assert_eq!(useful_done.status, WebhookDeliveryStatus::Delivered);
    assert_eq!(useful_done.attempt_count, 1);
    assert_eq!(receiver.lock().unwrap().applied.len(), 1);

    // Authentication is checked by the receiver independently of sender
    // status. An unsigned delivery header is not a safe idempotency key.
    let (body, signature) = receiver
        .lock()
        .unwrap()
        .first_authenticated_request
        .clone()
        .unwrap();
    let probe_client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut tampered: serde_json::Value = serde_json::from_slice(&body)?;
    tampered["event_type"] = "forged.event".into();
    let rejected = probe_client
        .post(target("tampered"))
        .header("x-llm-firewall-signature", &signature)
        .header("x-llm-firewall-delivery", &useful.id)
        .body(serde_json::to_vec(&tampered)?)
        .send()
        .await?;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    let header_replay = probe_client
        .post(target("header-replay"))
        .header("x-llm-firewall-signature", &signature)
        .header("x-llm-firewall-delivery", "altered-unsigned-delivery")
        .body(body)
        .send()
        .await?;
    assert_eq!(header_replay.status(), StatusCode::OK);
    assert_eq!(receiver.lock().unwrap().applied.len(), 1);

    let retry = enqueue_case(&store, &tenant.id, "retry")?;
    SenderChild::start(directory.path(), &database, &target("retry"), false)?
        .expect_success()
        .await?;
    let retry_pending = read_delivery(&store, &retry)?;
    assert_eq!(retry_pending.status, WebhookDeliveryStatus::Pending);
    assert_eq!(retry_pending.last_http_status, Some(503));
    assert_eq!(retry_pending.attempt_count, 1);
    assert_eq!(receiver.lock().unwrap().applied.len(), 1);
    assert!(
        store.claim_webhook_delivery()?.is_none(),
        "retry bypassed backoff"
    );
    wait_until_due(retry_pending.next_attempt_at_unix).await;
    SenderChild::start(directory.path(), &database, &target("retry"), false)?
        .expect_success()
        .await?;
    let retry_done = read_delivery(&store, &retry)?;
    assert_eq!(retry_done.status, WebhookDeliveryStatus::Delivered);
    assert_eq!(retry_done.attempt_count, 2);

    let interrupted = enqueue_case(&store, &tenant.id, "interrupted")?;
    let mut child = SenderChild::start(directory.path(), &database, &target("interrupted"), true)?;
    let marker = directory.path().join("response.observed");
    let marker_deadline = Instant::now() + Duration::from_secs(15);
    while !marker.exists() {
        assert!(
            Instant::now() < marker_deadline,
            "child never observed HTTP success"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let before_kill = read_delivery(&store, &interrupted)?;
    assert_eq!(before_kill.status, WebhookDeliveryStatus::InFlight);
    assert_eq!(before_kill.attempt_count, 1);
    assert_eq!(
        receiver.lock().unwrap().applied.len(),
        3,
        "HTTP side effect must be witnessed before sender interruption"
    );
    child.interrupt()?;
    drop(store);
    let restarted = open_fixture(&database)?;
    let after_restart = read_delivery(&restarted, &interrupted)?;
    assert_eq!(after_restart.status, WebhookDeliveryStatus::InFlight);
    assert!(
        restarted.claim_webhook_delivery()?.is_none(),
        "live lease was stolen"
    );
    wait_until_due(
        after_restart
            .locked_until_unix
            .context("missing claim lease")?,
    )
    .await;
    SenderChild::start(directory.path(), &database, &target("interrupted"), false)?
        .expect_success()
        .await?;
    let interrupted_done = read_delivery(&restarted, &interrupted)?;
    assert_eq!(interrupted_done.status, WebhookDeliveryStatus::Delivered);
    assert_eq!(interrupted_done.attempt_count, 2);
    assert!(restarted.claim_webhook_delivery()?.is_none());

    let receipts = BufReader::new(File::open(&receipts_path)?)
        .lines()
        .map(|line| -> anyhow::Result<ReceiverReceipt> { Ok(serde_json::from_str(&line?)?) })
        .collect::<anyhow::Result<Vec<_>>>()?;
    assert_eq!(receipts.len(), 7);
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.effect_applied)
            .count(),
        3
    );
    assert_eq!(
        receipts.iter().filter(|receipt| receipt.duplicate).count(),
        2
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| !receipt.signature_valid)
            .count(),
        1
    );
    for (scenario, delivery, expected_count) in [
        ("useful", &useful, 1),
        ("retry", &retry, 2),
        ("interrupted", &interrupted, 2),
    ] {
        let rows = receipts
            .iter()
            .filter(|receipt| receipt.scenario == scenario)
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), expected_count);
        assert!(rows.iter().all(|receipt| receipt.delivery_id == delivery.id
            && receipt.event_id == delivery.event_id
            && receipt.signature_valid));
        assert!(rows
            .windows(2)
            .all(|pair| pair[0].body_sha256 == pair[1].body_sha256));
    }
    let summary = serde_json::json!({
        "schema_version": 1,
        "scenario": "webhook_receiver_recovery_demo",
        "result": "pass",
        "store": "sqlite",
        "transport": "cfg(test)-only loopback HTTP; shared production request/signature helper",
        "production_egress_validation_bypassed_only_in_test_module": true,
        "public_https_deployment_acceptance": false,
        "retry_clock": "real",
        "lease_clock": "real",
        "receiver_receipt_storage": "durable JSONL",
        "receiver_dedup_storage": "in-memory fixture; receiver remains running",
        "receiver_restart_acceptance": false,
        "process_interrupted_after_receiver_success_before_store_completion": true,
        "receiver_receipts": receipts.len(),
        "authenticated_receipts": 6,
        "receiver_effects": 3,
        "duplicates_without_repeated_effect": 2,
        "tampered_body_rejections": 1,
        "unsigned_delivery_header_replay_deduplicated": true,
        "deduplication_key": ["authenticated tenant_id", "authenticated event_id"],
        "stable_delivery_event_ids_and_payloads_across_retries": true,
        "delivered_rows": 3,
        "attempt_counts": { "useful": 1, "http_retry": 2, "interrupted": 2 },
        "elapsed_ms": started.elapsed().as_millis(),
        "receipts": receipts,
    });
    let encoded = serde_json::to_string_pretty(&summary)?;
    if let Some(path) = std::env::var_os("SOUP_WALL_WEBHOOK_EVIDENCE") {
        let mut file = File::create(PathBuf::from(path))?;
        file.write_all(encoded.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    println!("{encoded}");
    Ok(())
}
