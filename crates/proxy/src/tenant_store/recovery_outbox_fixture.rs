// SPDX-License-Identifier: Apache-2.0
//! Opt-in recovery fixture; local transport is confined to this test binary.
//! Claim, signing, HTTP encoding and fenced completion are production functions.
//! This does not exercise the production public-HTTPS destination resolver.

use super::*;
use anyhow::ensure;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureConfig {
    schema_version: u8,
    sqlite_path: Option<PathBuf>,
    postgres_url: Option<String>,
    signing_key: String,
    receiver_url: String,
    delivery_id: String,
    result_path: PathBuf,
}

fn private_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let file = fs::symlink_metadata(path)?;
    let parent = fs::symlink_metadata(path.parent().context("missing private parent")?)?;
    ensure!(file.is_file() && file.nlink() == 1 && file.mode() & 0o777 == 0o600);
    ensure!(parent.is_dir() && parent.mode() & 0o777 == 0o700);
    ensure!(file.uid() == parent.uid());
    ensure!(
        file.uid()
            == tempfile::tempfile_in(path.parent().context("missing private parent")?)?
                .metadata()?
                .uid()
    );
    ensure!(path.is_absolute() && path.canonicalize()? == path);
    ensure!(file.len() <= 32 * 1024);
    Ok(())
}

/// Explicitly run by console-recovery-webhook-fixture.py, never by an operator
/// against a default database. Normal cargo test records the intentional opt-in.
#[cfg(unix)]
#[tokio::test]
#[ignore = "requires an explicitly owned restored database and private fixture config"]
async fn restored_outbox_claim_send_and_fenced_finish() -> anyhow::Result<()> {
    let path = PathBuf::from(std::env::var("SOUP_RECOVERY_OUTBOX_CONFIG")?);
    private_file(&path)?;
    let cfg: FixtureConfig = serde_json::from_slice(&fs::read(&path)?)?;
    ensure!(cfg.schema_version == 1 && cfg.delivery_id.starts_with("webhook_delivery_"));
    ensure!(cfg.sqlite_path.is_some() != cfg.postgres_url.is_some());
    let url = Url::parse(&cfg.receiver_url)?;
    ensure!(url.scheme() == "http" && url.host_str() == Some("127.0.0.1"));
    ensure!(url.port().is_some() && url.path() == "/events" && url.query().is_none());
    ensure!(url.username().is_empty() && url.password().is_none() && url.fragment().is_none());
    let store = if let Some(database) = cfg.sqlite_path {
        ensure!(database.is_absolute() && database.canonicalize()? == database);
        let metadata = fs::symlink_metadata(&database)?;
        use std::os::unix::fs::MetadataExt;
        ensure!(metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o777 == 0o600);
        ensure!(database.parent() == path.parent().and_then(Path::parent));
        ensure!(database.file_name().and_then(|n| n.to_str()) == Some("recovered.sqlite"));
        TenantStore::open(database)?
    } else {
        let database = cfg.postgres_url.context("missing fixture target")?;
        let parsed = Url::parse(&database)?;
        ensure!(matches!(parsed.scheme(), "postgres" | "postgresql"));
        ensure!(matches!(parsed.host_str(), Some("127.0.0.1" | "::1")));
        ensure!(parsed.path().starts_with("/sou49_recovered_"));
        TenantStore::open_postgres_with_ca_and_tls(
            &database,
            1000,
            Duration::from_secs(5),
            2,
            Duration::from_secs(5),
            None,
            false,
        )
        .await?
    };
    let pending = match &store.postgres {
        Some(pg) => pg.claim_webhook_delivery().await?,
        None => store.claim_webhook_delivery()?,
    }
    .context("expected restored due outbox delivery")?;
    ensure!(pending.delivery.id == cfg.delivery_id);
    let key = WebhookSigningKey::from_base64url(&cfg.signing_key)?;
    let client = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let result = send_webhook_request(&client, url, &key, &pending).await;
    let http_status = result.http_status;
    let success = result.error.is_none();
    let completed = match &store.postgres {
        Some(pg) => {
            pg.finish_webhook_delivery(&pending.delivery, result)
                .await?
        }
        None => store.finish_webhook_delivery(&pending.delivery, result)?,
    };
    ensure!(
        completed,
        "live attempt must retain its completion ownership"
    );
    let recorded = store
        .list_webhook_deliveries_async(&pending.delivery.tenant_id, 500)
        .await?
        .into_iter()
        .find(|row| row.id == cfg.delivery_id)
        .context("missing recorded outbox state")?;
    ensure!(recorded.attempt_count == pending.delivery.attempt_count);
    ensure!(recorded.event_id == pending.event.id && recorded.locked_until_unix.is_none());
    ensure!(
        recorded.status
            == if success {
                WebhookDeliveryStatus::Delivered
            } else {
                WebhookDeliveryStatus::Pending
            }
    );
    let value = serde_json::json!({"schema_version":1,"status":"passed",
        "attempt_count":recorded.attempt_count,"http_status":http_status,
        "delivered":success,"completion_owned":completed,
        "next_attempt_at_unix":recorded.next_attempt_at_unix});
    ensure!(cfg.result_path.parent() == path.parent());
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(cfg.result_path)?;
    file.write_all(&serde_json::to_vec(&value)?)?;
    file.sync_all()?;
    Ok(())
}
