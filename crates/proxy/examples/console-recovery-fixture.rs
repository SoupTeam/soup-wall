// SPDX-License-Identifier: Apache-2.0

//! Local-only Console recovery fixture. Credentials are written exclusively to
//! owner-only artifacts. This helper does not contact providers, an IdP or a
//! webhook receiver. Initial tenant state uses the native TenantStore API;
//! explicit synthetic retry/lease metadata models a stopped dispatcher.
//! PostgreSQL must already have the current schema. SQLite initialization is
//! allowed only for a new disposable seed; probes preflight currency before the
//! existing constructor and reject any schema or row changes during that open.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use llm_firewall::tenant_store::{
    PolicyDeploymentAction, TenantLimits, TenantModelPolicy, TenantPolicyDocument, TenantRateLimit,
    TenantSpendLimit, TenantStore, WebhookDeliveryStatus, WorkspacePermission, WorkspaceRole,
};
use rand::Rng;
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_postgres::{Client, NoTls};

const DATABASE_ENV: &str = "LLM_FW_CONSOLE_RECOVERY_FIXTURE_DATABASE_URL";
const SQLITE_ENV: &str = "LLM_FW_CONSOLE_RECOVERY_FIXTURE_SQLITE_PATH";
const DESTINATION: &str = "https://hooks.example.test/console-recovery";
const MAX_PRIVATE_FILE: u64 = 64 * 1024;
const MANIFEST_FILE: &str = "fixture-manifest.json";
const MARKER_FILE: &str = "fixture-seed-start.json";
const SYNTHETIC_RETRY_ERROR: &str = "synthetic stopped-dispatcher HTTP 503 fixture";

// Never derive Debug: this private contract contains one-time credentials.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u16,
    run_id: String,
    source_fingerprint: String,
    webhook_signing_key: String,
    tenant_id: String,
    control_tenant_id: String,
    workspace_id: String,
    control_workspace_id: String,
    owner_principal_id: String,
    control_owner_principal_id: String,
    active_account_id: String,
    active_account_token: String,
    revoked_account_id: String,
    revoked_account_token: String,
    control_active_account_id: String,
    control_active_account_token: String,
    destination_id: String,
    destination_secret: String,
    webhook_url: String,
    policy_version_id: String,
    second_policy_version_id: String,
    control_policy_version_id: String,
    event_id: String,
    second_event_id: String,
    control_event_id: String,
    delivery_id: String,
    in_flight_delivery_id: String,
    retry_due_at_unix: i64,
    lease_until_unix: i64,
    retry_state_origin: String,
    limits: TenantLimits,
    model_policy: TenantModelPolicy,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema_version: u16,
    run_id: String,
    source_fingerprint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Seed,
    Probe,
}
impl FromStr for Phase {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "seed" => Ok(Self::Seed),
            "probe" => Ok(Self::Probe),
            _ => bail!("unsupported fixture mode"),
        }
    }
}

// Deliberately fixed output: no arbitrary DB values, names, endpoints, IDs or
// credential material crosses this public boundary, including on errors.
#[derive(Serialize)]
struct PublicAggregate {
    schema_version: u16,
    mode: Phase,
    status: &'static str,
    tenants: u8,
    service_accounts: u8,
    webhook_destinations: u8,
    baseline_security_events: u8,
    pending_retry_preserved: bool,
    in_flight_ownership_preserved: bool,
    retry_state_synthetic: bool,
    retained_tokens_authenticated: bool,
    revoked_token_rejected: bool,
    tenant_isolation_verified: bool,
    target_schema_migrated: bool,
    model_requests_sent: u8,
    webhook_requests_sent: u8,
}
impl PublicAggregate {
    const fn for_phase(mode: Phase) -> Self {
        Self {
            schema_version: 1,
            mode,
            status: "passed",
            tenants: 2,
            service_accounts: 3,
            webhook_destinations: 1,
            baseline_security_events: 3,
            pending_retry_preserved: true,
            in_flight_ownership_preserved: true,
            retry_state_synthetic: true,
            retained_tokens_authenticated: true,
            revoked_token_rejected: true,
            tenant_isolation_verified: true,
            target_schema_migrated: false,
            model_requests_sent: 0,
            webhook_requests_sent: 0,
        }
    }
}

// Do not derive Debug: a PostgreSQL URL can contain a password.
enum Database {
    Sqlite(PathBuf),
    Postgres(String),
}

fn refuse() -> ! {
    eprintln!("Console recovery fixture refused; private artifacts are retained");
    std::process::exit(1);
}
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [mode, directory] = args.as_slice() else {
        refuse();
    };
    let phase = Phase::from_str(mode).unwrap_or_else(|_| refuse());
    if run(phase, Path::new(directory)).await.is_err() {
        refuse();
    }
    let public =
        serde_json::to_string(&PublicAggregate::for_phase(phase)).unwrap_or_else(|_| refuse());
    println!("{public}");
}

async fn run(phase: Phase, directory: &Path) -> Result<()> {
    let directory = private_run_directory(directory)?;
    let db = database_from_environment(&directory, phase)?;
    let fingerprint = db.fingerprint().await?;
    let store = db.open_current(phase).await?;
    if phase == Phase::Seed {
        let run_id = random_text(16);
        write_private_new(
            &directory.join(MARKER_FILE),
            &Marker {
                schema_version: 1,
                run_id: run_id.clone(),
                source_fingerprint: fingerprint.clone(),
            },
        )?;
        ensure!(
            !directory.join(MANIFEST_FILE).exists(),
            "manifest already exists"
        );
        db.require_empty().await?;
        let key = random_text(32);
        let store = store.with_webhook_signing_key_base64url(&key)?;
        let manifest = seed_fixture(&store, &run_id, &fingerprint, &key).await?;
        db.seed_retry_state(&manifest).await?;
        probe_fixture(&store, &manifest).await?;
        write_private_new(&directory.join(MANIFEST_FILE), &manifest)?;
        return Ok(());
    }
    let manifest: Manifest = read_private(&directory.join(MANIFEST_FILE))?;
    let marker: Marker = read_private(&directory.join(MARKER_FILE))?;
    ensure!(
        manifest.schema_version == 1
            && marker.schema_version == 1
            && manifest.run_id == marker.run_id
            && manifest.source_fingerprint == marker.source_fingerprint,
        "fixture run binding differs"
    );
    ensure!(
        manifest.limits == fixture_limits()
            && manifest.model_policy == fixture_model_policy()
            && manifest.webhook_url == DESTINATION
            && manifest.retry_state_origin == "synthetic-stopped-dispatcher",
        "fixture contract differs"
    );
    probe_fixture(&store, &manifest).await
}

fn database_from_environment(directory: &Path, phase: Phase) -> Result<Database> {
    let pg = std::env::var(DATABASE_ENV).ok();
    let sqlite = std::env::var(SQLITE_ENV).ok();
    match (pg, sqlite) {
        (Some(url), None) => {
            validate_local_url(&url)?;
            Ok(Database::Postgres(url))
        }
        (None, Some(path)) => Ok(Database::Sqlite(validate_sqlite_path(
            directory,
            Path::new(&path),
            phase == Phase::Seed,
        )?)),
        _ => bail!("exactly one explicit fixture database is required"),
    }
}

fn validate_sqlite_path(directory: &Path, path: &Path, seed: bool) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "SQLite path must be absolute");
    let parent = path
        .parent()
        .context("SQLite parent absent")?
        .canonicalize()?;
    ensure!(
        parent.starts_with(directory),
        "SQLite path is outside the private run"
    );
    for ancestor in path
        .parent()
        .context("SQLite parent absent")?
        .ancestors()
        .take_while(|ancestor| ancestor.starts_with(directory))
    {
        ensure!(
            !fs::symlink_metadata(ancestor)?.file_type().is_symlink(),
            "SQLite parent is linked"
        );
    }
    let name = path.file_name().context("SQLite file name absent")?;
    let canonical = parent.join(name);
    ensure!(canonical == path, "SQLite path is not canonical");
    ensure!(
        path.extension().and_then(|value| value.to_str()) == Some("sqlite"),
        "SQLite fixture extension differs"
    );
    if !path.exists() && seed {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)?.sync_all()?;
    }
    private_permissions(path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.nlink() == 1 && metadata.uid() == fs::metadata(&parent)?.uid(),
            "SQLite fixture is aliased or has a different owner"
        );
    }
    Ok(canonical)
}

impl Database {
    async fn fingerprint(&self) -> Result<String> {
        match self {
            Self::Sqlite(path) => Ok(format!("sqlite:{}", path.display())),
            Self::Postgres(url) => database_fingerprint(url).await,
        }
    }
    async fn open_current(&self, phase: Phase) -> Result<TenantStore> {
        match self {
            Self::Postgres(url) => {
                let url = if phase == Phase::Probe {
                    readonly_url(url)?
                } else {
                    url.clone()
                };
                TenantStore::open_postgres_with_ca_and_tls(
                    &url,
                    1000,
                    Duration::from_secs(5),
                    2,
                    Duration::from_secs(5),
                    None,
                    false,
                )
                .await
            }
            Self::Sqlite(path) => {
                if phase == Phase::Seed && fs::metadata(path)?.len() == 0 {
                    // Explicit initialization of a fresh disposable source only.
                    return TenantStore::open(path);
                }
                validate_current_sqlite(path)?;
                let before = sqlite_snapshot(path)?;
                let store = TenantStore::open(path)?;
                ensure!(
                    sqlite_snapshot(path)? == before,
                    "SQLite constructor changed the already-current target"
                );
                Ok(store)
            }
        }
    }
    async fn require_empty(&self) -> Result<()> {
        match self {
            Self::Postgres(url) => require_empty_postgres(url).await,
            Self::Sqlite(path) => {
                let db = sqlite_read_only(path)?;
                let mut statement = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?;
                let tables = statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                for table in tables {
                    let condition = if table == "organizations" {
                        " WHERE id <> 'org_bootstrap'"
                    } else {
                        ""
                    };
                    let count: i64 = db.query_row(
                        &format!("SELECT COUNT(*) FROM {}{}", quote(&table), condition),
                        [],
                        |row| row.get(0),
                    )?;
                    ensure!(count == 0, "fixture source is already populated");
                }
                Ok(())
            }
        }
    }
    async fn seed_retry_state(&self, m: &Manifest) -> Result<()> {
        // These are explicit synthetic recovery fixtures, not a claim that an
        // HTTP attempt was performed. Production SSRF checks remain unchanged.
        match self {
            Self::Sqlite(path) => {
                let mut db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
                let tx = db.transaction()?;
                ensure!(tx.execute("UPDATE tenant_webhook_deliveries SET status='pending', attempt_count=1, next_attempt_at_unix=?1, last_http_status=503, last_error=?2 WHERE id=?3 AND tenant_id=?4 AND status='pending' AND attempt_count=0", params![m.retry_due_at_unix, SYNTHETIC_RETRY_ERROR, m.delivery_id, m.tenant_id])? == 1, "pending fixture row differs");
                ensure!(tx.execute("UPDATE tenant_webhook_deliveries SET status='in_flight', attempt_count=2, next_attempt_at_unix=?1, locked_until_unix=?2 WHERE id=?3 AND tenant_id=?4 AND status='pending' AND attempt_count=0", params![m.retry_due_at_unix, m.lease_until_unix, m.in_flight_delivery_id, m.tenant_id])? == 1, "in-flight fixture row differs");
                tx.commit()?;
            }
            Self::Postgres(url) => {
                let mut config = tokio_postgres::Config::from_str(url)?;
                config.connect_timeout(Duration::from_secs(5));
                config.options("-c statement_timeout=5000");
                let (mut client, connection) = config.connect(NoTls).await?;
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                let tx = client.transaction().await?;
                ensure!(tx.execute("UPDATE tenant_webhook_deliveries SET status='pending', attempt_count=1, next_attempt_at_unix=$1, last_http_status=503, last_error=$2 WHERE id=$3 AND tenant_id=$4 AND status='pending' AND attempt_count=0", &[&m.retry_due_at_unix, &SYNTHETIC_RETRY_ERROR, &m.delivery_id, &m.tenant_id]).await? == 1, "pending fixture row differs");
                ensure!(tx.execute("UPDATE tenant_webhook_deliveries SET status='in_flight', attempt_count=2, next_attempt_at_unix=$1, locked_until_unix=$2 WHERE id=$3 AND tenant_id=$4 AND status='pending' AND attempt_count=0", &[&m.retry_due_at_unix, &m.lease_until_unix, &m.in_flight_delivery_id, &m.tenant_id]).await? == 1, "in-flight fixture row differs");
                tx.commit().await?;
            }
        }
        Ok(())
    }
}

fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
fn sqlite_read_only(path: &Path) -> Result<Connection> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(Duration::from_secs(5))?;
    Ok(db)
}
fn sqlite_value(value: rusqlite::types::ValueRef<'_>) -> Value {
    match value {
        rusqlite::types::ValueRef::Null => Value::Null,
        rusqlite::types::ValueRef::Integer(value) => json!(["integer", value]),
        rusqlite::types::ValueRef::Real(value) => json!(["real", value.to_bits()]),
        rusqlite::types::ValueRef::Text(value) => json!(["text", URL_SAFE_NO_PAD.encode(value)]),
        rusqlite::types::ValueRef::Blob(value) => json!(["blob", URL_SAFE_NO_PAD.encode(value)]),
    }
}
fn sqlite_query(db: &Connection, sql: &str) -> Result<Vec<Value>> {
    let mut statement = db.prepare(sql)?;
    let count = statement.column_count();
    let values = statement
        .query_map([], |row| {
            (0..count)
                .map(|index| row.get_ref(index).map(sqlite_value))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map(Value::Array)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(values)
}
fn sqlite_snapshot(path: &Path) -> Result<Value> {
    let db = sqlite_read_only(path)?;
    let schema = sqlite_query(
        &db,
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name",
    )?;
    let cookie: i64 = db.query_row("PRAGMA schema_version", [], |row| row.get(0))?;
    let mut tables = BTreeMap::new();
    let mut statement =
        db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for name in names {
        let mut rows = sqlite_query(&db, &format!("SELECT * FROM {}", quote(&name)))?;
        rows.sort_by_key(|row| row.to_string());
        tables.insert(name, rows);
    }
    Ok(json!({"schema_cookie": cookie, "schema": schema, "tables": tables}))
}
fn validate_current_sqlite(path: &Path) -> Result<()> {
    // Build a disposable empty schema as a reference, never migrate the
    // target. Compare every native tenant table/index and all column layouts.
    let directory = tempfile::tempdir()?;
    let reference_path = directory.path().join("reference.sqlite");
    drop(TenantStore::open(&reference_path)?);
    let reference = sqlite_read_only(&reference_path)?;
    let db = sqlite_read_only(path)?;
    let mut statement = reference.prepare("SELECT type,name FROM sqlite_master WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type,name")?;
    let objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (kind, name) in objects {
        let exists: i64 = db.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type=?1 AND name=?2",
            params![kind, name],
            |row| row.get(0),
        )?;
        ensure!(exists == 1, "SQLite native schema object is absent");
        if kind == "table" {
            let sql = format!("PRAGMA table_info({})", quote(&name));
            ensure!(
                sqlite_query(&db, &sql)? == sqlite_query(&reference, &sql)?,
                "SQLite native column layout differs"
            );
            let sql = format!("PRAGMA foreign_key_list({})", quote(&name));
            ensure!(
                sqlite_query(&db, &sql)? == sqlite_query(&reference, &sql)?,
                "SQLite native foreign keys differ"
            );
        }
    }
    let bootstrap: i64 = db.query_row(
        "SELECT COUNT(*) FROM organizations WHERE id='org_bootstrap'",
        [],
        |row| row.get(0),
    )?;
    let missing: i64 = db.query_row("SELECT COUNT(*) FROM tenants t WHERE NOT EXISTS (SELECT 1 FROM workspaces w WHERE w.tenant_id=t.id)", [], |row| row.get(0))?;
    ensure!(
        bootstrap == 1 && missing == 0,
        "SQLite bootstrap/backfill is incomplete"
    );
    Ok(())
}

fn validate_local_url(value: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(value).context("invalid fixture database URL")?;
    ensure!(
        matches!(parsed.scheme(), "postgres" | "postgresql"),
        "fixture requires PostgreSQL"
    );
    let host = parsed.host_str().context("fixture host is absent")?;
    let address: IpAddr = host
        .trim_matches(['[', ']'])
        .parse()
        .context("fixture requires a numeric loopback host")?;
    ensure!(address.is_loopback(), "fixture host is not loopback");
    ensure!(
        !parsed.username().is_empty() && parsed.path().len() > 1 && parsed.fragment().is_none(),
        "fixture database identity is absent"
    );
    let config = tokio_postgres::Config::from_str(value)?;
    let name = config
        .get_dbname()
        .context("fixture database name is absent")?;
    ensure!(
        name.starts_with("sou49_")
            && name.len() > 6
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
        "fixture database requires a disposable SOU-49 name"
    );
    let query: Vec<_> = parsed.query_pairs().collect();
    ensure!(
        query.len() == 1 && query[0].0 == "sslmode" && query[0].1 == "disable",
        "local fixture requires only sslmode=disable"
    );
    Ok(())
}

fn readonly_url(value: &str) -> Result<String> {
    validate_local_url(value)?;
    let mut parsed = reqwest::Url::parse(value)?;
    // PostgreSQL URI options use percent decoding, not form decoding: a '+'
    // remains literal instead of becoming a space between '-c' and the setting.
    parsed.set_query(Some(
        "sslmode=disable&options=-c%20default_transaction_read_only%3Don",
    ));
    Ok(parsed.into())
}

async fn database_client(url: &str) -> Result<Client> {
    let mut config = tokio_postgres::Config::from_str(url)?;
    config.connect_timeout(Duration::from_secs(5));
    config.options("-c default_transaction_read_only=on -c statement_timeout=5000");
    let (client, connection) = config.connect(NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

async fn database_fingerprint(url: &str) -> Result<String> {
    let row = database_client(url)
        .await?
        .query_one(
            "SELECT current_database() || '|' || COALESCE(host(inet_server_addr()), 'local') || '|' || COALESCE(inet_server_port()::text, 'local')",
            &[],
        )
        .await?;
    Ok(row.get(0))
}

async fn require_empty_postgres(url: &str) -> Result<()> {
    let client = database_client(url).await?;
    let tables = client
        .query(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
            &[],
        )
        .await?;
    for row in tables {
        let table: String = row.get(0);
        if table == "llm_firewall_schema_migrations" || table == "organizations" {
            continue;
        }
        let quoted = format!("\"{}\"", table.replace('"', "\"\""));
        let count: i64 = client
            .query_one(&format!("SELECT COUNT(*) FROM public.{quoted}"), &[])
            .await?
            .get(0);
        ensure!(count == 0, "fixture source is already populated");
    }
    // Migrations create the bootstrap organization. Extra organizations are
    // operator state even when they have no tenants and must not be seeded.
    let extra: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM organizations WHERE id <> 'org_bootstrap'",
            &[],
        )
        .await?
        .get(0);
    ensure!(extra == 0, "fixture source contains operator organizations");
    Ok(())
}

fn fixture_limits() -> TenantLimits {
    TenantLimits {
        rate_limit: Some(TenantRateLimit {
            requests_per_window: 7,
            window_seconds: 60,
        }),
        spend_limit: Some(TenantSpendLimit {
            window_seconds: 86_400,
            max_usd_micros: 1_000_000,
            reserve_usd_micros_per_request: 50_000,
        }),
    }
}

fn fixture_model_policy() -> TenantModelPolicy {
    TenantModelPolicy {
        allowed_models: vec!["restore-fixture-allowed".into()],
    }
}

async fn activate(store: &TenantStore, tenant: &str, policy: TenantModelPolicy) -> Result<String> {
    let version = store
        .create_policy_version_async(
            tenant,
            "restore-fixture-operator",
            TenantPolicyDocument::new(Some(policy)),
        )
        .await?;
    store
        .approve_policy_version_async(tenant, &version.id, "restore-fixture-owner")
        .await?;
    store
        .deploy_policy_version_async(
            tenant,
            &version.id,
            "restore-fixture-owner",
            PolicyDeploymentAction::Activate,
        )
        .await?;
    Ok(version.id)
}

async fn seed_fixture(
    store: &TenantStore,
    run: &str,
    fingerprint: &str,
    key: &str,
) -> Result<Manifest> {
    ensure!(
        store.list_tenants_async().await?.is_empty(),
        "fixture source already has tenants"
    );
    let tenant = store
        .create_tenant_async(&format!("Console recovery {run}"))
        .await?;
    let control = store
        .create_tenant_async("Console recovery control")
        .await?;
    let workspace = store
        .workspace_for_tenant_async(&tenant.id)
        .await?
        .context("fixture workspace absent")?;
    let control_workspace = store
        .workspace_for_tenant_async(&control.id)
        .await?
        .context("control workspace absent")?;
    let owner = store
        .create_workspace_principal_async("Console recovery owner")
        .await?;
    let control_owner = store
        .create_workspace_principal_async("Console recovery control owner")
        .await?;
    store
        .set_workspace_membership_async(&workspace.id, &owner.id, WorkspaceRole::Owner)
        .await?;
    store
        .set_workspace_membership_async(
            &control_workspace.id,
            &control_owner.id,
            WorkspaceRole::Owner,
        )
        .await?;
    store
        .set_workspace_limits_async(&workspace.id, &owner.id, fixture_limits())
        .await?;
    let expires = now_unix()? + 86_400;
    let active = store
        .create_workspace_service_account_async(
            &workspace.id,
            &owner.id,
            "retained-machine",
            expires,
        )
        .await?;
    let revoked = store
        .create_workspace_service_account_async(
            &workspace.id,
            &owner.id,
            "revoked-machine",
            expires,
        )
        .await?;
    let control_active = store
        .create_workspace_service_account_async(
            &control_workspace.id,
            &control_owner.id,
            "control-machine",
            expires,
        )
        .await?;
    ensure!(
        store
            .revoke_workspace_service_account_async(&workspace.id, &revoked.account.id, &owner.id)
            .await?,
        "fixture revocation failed"
    );
    let destination = store
        .create_workspace_webhook_destination_async(
            &workspace.id,
            &owner.id,
            DESTINATION,
            &["policy.deployed".into()],
        )
        .await?;
    let policy_version_id = activate(store, &tenant.id, fixture_model_policy()).await?;
    let second_policy_version_id = activate(store, &tenant.id, fixture_model_policy()).await?;
    let control_policy_version_id = activate(store, &control.id, control_model_policy()).await?;
    let events = store.list_security_events_async(&tenant.id, 0, 10).await?;
    let control_events = store.list_security_events_async(&control.id, 0, 10).await?;
    let deliveries = store.list_webhook_deliveries_async(&tenant.id, 10).await?;
    ensure!(
        events.len() == 2 && control_events.len() == 1 && deliveries.len() == 2,
        "fixture event count differs"
    );
    let pending = deliveries
        .iter()
        .find(|d| d.event_id == events[0].id)
        .context("first delivery absent")?;
    let in_flight = deliveries
        .iter()
        .find(|d| d.event_id == events[1].id)
        .context("second delivery absent")?;
    let due = now_unix()? + 1800;
    Ok(Manifest {
        schema_version: 1,
        run_id: run.into(),
        source_fingerprint: fingerprint.into(),
        webhook_signing_key: key.into(),
        tenant_id: tenant.id,
        control_tenant_id: control.id,
        workspace_id: workspace.id,
        control_workspace_id: control_workspace.id,
        owner_principal_id: owner.id,
        control_owner_principal_id: control_owner.id,
        active_account_id: active.account.id,
        active_account_token: active.token,
        revoked_account_id: revoked.account.id,
        revoked_account_token: revoked.token,
        control_active_account_id: control_active.account.id,
        control_active_account_token: control_active.token,
        destination_id: destination.destination.id,
        destination_secret: destination.secret,
        webhook_url: DESTINATION.into(),
        policy_version_id,
        second_policy_version_id,
        control_policy_version_id,
        event_id: events[0].id.clone(),
        second_event_id: events[1].id.clone(),
        control_event_id: control_events[0].id.clone(),
        delivery_id: pending.id.clone(),
        in_flight_delivery_id: in_flight.id.clone(),
        retry_due_at_unix: due,
        lease_until_unix: due,
        retry_state_origin: "synthetic-stopped-dispatcher".into(),
        limits: fixture_limits(),
        model_policy: fixture_model_policy(),
    })
}

fn control_model_policy() -> TenantModelPolicy {
    TenantModelPolicy {
        allowed_models: vec!["console-recovery-control".into()],
    }
}

async fn probe_fixture(store: &TenantStore, m: &Manifest) -> Result<()> {
    let tenants = store.list_tenants_async().await?;
    ensure!(
        tenants.len() == 2
            && tenants
                .iter()
                .all(|t| t.active && (t.id == m.tenant_id || t.id == m.control_tenant_id)),
        "fixture tenants differ"
    );
    for (tenant, workspace, principal) in [
        (&m.tenant_id, &m.workspace_id, &m.owner_principal_id),
        (
            &m.control_tenant_id,
            &m.control_workspace_id,
            &m.control_owner_principal_id,
        ),
    ] {
        let actual = store
            .workspace_for_tenant_async(tenant)
            .await?
            .context("fixture workspace absent")?;
        ensure!(
            actual.id == *workspace && actual.active,
            "fixture workspace differs"
        );
        let members = store.list_workspace_members_async(workspace).await?;
        ensure!(
            members.len() == 1
                && members[0].principal_id == *principal
                && members[0].active
                && members[0].role == WorkspaceRole::Owner,
            "fixture membership differs"
        );
        ensure!(
            store
                .workspace_permits_async(principal, workspace, WorkspacePermission::ApprovePolicies)
                .await?,
            "owner lost permission"
        );
    }
    ensure!(
        !store
            .workspace_permits_async(
                &m.owner_principal_id,
                &m.control_workspace_id,
                WorkspacePermission::ApprovePolicies
            )
            .await?
            && !store
                .workspace_permits_async(
                    &m.control_owner_principal_id,
                    &m.workspace_id,
                    WorkspacePermission::ApprovePolicies
                )
                .await?,
        "cross-tenant principal gained permission"
    );
    let accounts = store
        .list_workspace_service_accounts_async(&m.workspace_id, &m.owner_principal_id)
        .await?;
    let active = accounts
        .iter()
        .find(|a| a.id == m.active_account_id)
        .context("retained account absent")?;
    let revoked = accounts
        .iter()
        .find(|a| a.id == m.revoked_account_id)
        .context("revoked account absent")?;
    ensure!(
        accounts.len() == 2
            && active.active
            && active.revoked_at_unix.is_none()
            && active.expires_at_unix > now_unix()?
            && !revoked.active
            && revoked.revoked_at_unix.is_some(),
        "fixture account state differs"
    );
    let control_accounts = store
        .list_workspace_service_accounts_async(
            &m.control_workspace_id,
            &m.control_owner_principal_id,
        )
        .await?;
    ensure!(
        control_accounts.len() == 1
            && control_accounts[0].id == m.control_active_account_id
            && control_accounts[0].active,
        "control credential differs"
    );
    let access = store
        .authenticate_access_async(Some(&format!("Bearer {}", m.active_account_token)))
        .await?
        .context("retained token rejected")?;
    ensure!(
        access.identity.tenant_id == m.tenant_id
            && access.limits == m.limits
            && access.model_policy.as_ref() == Some(&m.model_policy),
        "retained token policy differs"
    );
    let control_access = store
        .authenticate_access_async(Some(&format!("Bearer {}", m.control_active_account_token)))
        .await?
        .context("control token rejected")?;
    ensure!(
        control_access.identity.tenant_id == m.control_tenant_id
            && control_access.model_policy.as_ref() == Some(&control_model_policy()),
        "control token policy differs"
    );
    for token in [&m.revoked_account_token, "invalid-console-recovery-token"] {
        ensure!(
            store
                .authenticate_access_async(Some(&format!("Bearer {token}")))
                .await?
                .is_none(),
            "invalid or revoked token authenticates"
        );
    }
    let destinations = store.list_webhook_destinations_async(&m.tenant_id).await?;
    ensure!(
        destinations.len() == 1
            && destinations[0].id == m.destination_id
            && destinations[0].active
            && destinations[0].url == DESTINATION
            && destinations[0].event_types == ["policy.deployed"],
        "fixture destination differs"
    );
    ensure!(
        store
            .list_webhook_destinations_async(&m.control_tenant_id)
            .await?
            .is_empty()
            && store
                .list_webhook_deliveries_async(&m.control_tenant_id, 10)
                .await?
                .is_empty(),
        "control tenant inherited outbox state"
    );
    let deliveries = store
        .list_webhook_deliveries_async(&m.tenant_id, 100)
        .await?;
    let pending = deliveries
        .iter()
        .find(|d| d.id == m.delivery_id)
        .context("retry delivery absent")?;
    let in_flight = deliveries
        .iter()
        .find(|d| d.id == m.in_flight_delivery_id)
        .context("owned delivery absent")?;
    ensure!(
        pending.event_id == m.event_id
            && pending.destination_id == m.destination_id
            && pending.status == WebhookDeliveryStatus::Pending
            && pending.attempt_count == 1
            && pending.next_attempt_at_unix == m.retry_due_at_unix
            && pending.locked_until_unix.is_none()
            && pending.delivered_at_unix.is_none()
            && pending.last_http_status == Some(503)
            && pending.last_error.as_deref() == Some(SYNTHETIC_RETRY_ERROR),
        "pending retry metadata differs"
    );
    ensure!(
        in_flight.event_id == m.second_event_id
            && in_flight.destination_id == m.destination_id
            && in_flight.status == WebhookDeliveryStatus::InFlight
            && in_flight.attempt_count == 2
            && in_flight.next_attempt_at_unix == m.retry_due_at_unix
            && in_flight.locked_until_unix == Some(m.lease_until_unix)
            && in_flight.delivered_at_unix.is_none()
            && in_flight.last_http_status.is_none()
            && in_flight.last_error.is_none(),
        "in-flight ownership differs"
    );
    for (tenant, pairs) in [
        (
            &m.tenant_id,
            vec![
                (&m.event_id, &m.policy_version_id, 1),
                (&m.second_event_id, &m.second_policy_version_id, 2),
            ],
        ),
        (
            &m.control_tenant_id,
            vec![(&m.control_event_id, &m.control_policy_version_id, 1)],
        ),
    ] {
        let events = store.list_security_events_async(tenant, 0, 100).await?;
        let versions = store.list_policy_versions_async(tenant, 100).await?;
        for (event_id, version_id, sequence) in pairs {
            let event = events
                .iter()
                .find(|e| e.id == *event_id)
                .context("baseline event absent")?;
            ensure!(
                event.sequence == sequence
                    && event.event_type == "policy.deployed"
                    && event.payload["version_id"] == *version_id,
                "baseline event differs"
            );
            let version = versions
                .iter()
                .find(|v| v.id == *version_id)
                .context("approved policy absent")?;
            ensure!(
                version.approved_by.as_deref() == Some("restore-fixture-owner"),
                "baseline approval differs"
            );
        }
    }
    Ok(())
}

fn now_unix() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

fn random_text(length: usize) -> String {
    let mut bytes = vec![0; length];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn private_run_directory(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "private run directory must be absolute");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .context("workspace root absent")?
        .canonicalize()?;
    let target = root.join("target");
    let resolved = path.canonicalize()?;
    ensure!(
        resolved.starts_with(&target) && resolved != target,
        "private run directory is outside ignored target"
    );
    for ancestor in path.ancestors().take_while(|p| *p != root) {
        ensure!(
            !fs::symlink_metadata(ancestor)?.file_type().is_symlink(),
            "private run path is linked"
        );
    }
    private_permissions(&resolved, true)?;
    Ok(resolved)
}

#[cfg(unix)]
fn private_permissions(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink()
            && (if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            }),
        "private artifact has wrong type"
    );
    ensure!(
        metadata.permissions().mode() & 0o777 == if directory { 0o700 } else { 0o600 },
        "private artifact permissions differ"
    );
    Ok(())
}

#[cfg(not(unix))]
fn private_permissions(_path: &Path, _directory: bool) -> Result<()> {
    bail!("private restore artifacts require Unix owner-only permissions");
}

fn write_private_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("private artifact parent absent")?;
    private_permissions(parent, true)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    private_permissions(path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            file.metadata()?.uid() == fs::metadata(parent)?.uid(),
            "private artifact owner differs"
        );
    }
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    Ok(())
}

fn read_private<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    private_permissions(path, false)?;
    ensure!(
        fs::metadata(path)?.len() <= MAX_PRIVATE_FILE,
        "private artifact is oversized"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            fs::metadata(path)?.uid()
                == fs::metadata(path.parent().context("private artifact parent absent")?)?.uid(),
            "private artifact owner differs"
        );
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyed_store(path: &Path) -> TenantStore {
        TenantStore::open(path)
            .unwrap()
            .with_webhook_signing_key_base64url(&URL_SAFE_NO_PAD.encode([7_u8; 32]))
            .unwrap()
    }
    async fn populated(path: &Path) -> (TenantStore, Manifest) {
        let store = keyed_store(path);
        let m = seed_fixture(
            &store,
            "offline-console-run",
            "source-private-identity",
            &URL_SAFE_NO_PAD.encode([7_u8; 32]),
        )
        .await
        .unwrap();
        Database::Sqlite(path.to_owned())
            .seed_retry_state(&m)
            .await
            .unwrap();
        (store, m)
    }

    #[tokio::test]
    async fn seed_and_probe_preserve_native_credentials_isolation_and_retry_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.sqlite");
        let (store, m) = populated(&path).await;
        let before = sqlite_snapshot(&path).unwrap();
        for _ in 0..2 {
            probe_fixture(&store, &m).await.unwrap();
        }
        assert_eq!(sqlite_snapshot(&path).unwrap(), before);
        let audit = store
            .list_workspace_admin_audit_async(&m.workspace_id, 100)
            .await
            .unwrap();
        for action in [
            "service_account.create",
            "service_account.revoke",
            "webhook_destination.create",
        ] {
            assert!(audit.iter().any(|event| event.action == action));
        }
    }

    #[tokio::test]
    async fn restored_sqlite_copy_probes_without_schema_or_row_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.sqlite");
        let restored = directory.path().join("restored.sqlite");
        let (store, m) = populated(&source).await;
        drop(store);
        fs::copy(&source, &restored).unwrap();
        let before = sqlite_snapshot(&restored).unwrap();
        let restored_store = Database::Sqlite(restored.clone())
            .open_current(Phase::Probe)
            .await
            .unwrap();
        probe_fixture(&restored_store, &m).await.unwrap();
        assert_eq!(sqlite_snapshot(&restored).unwrap(), before);
        assert_eq!(sqlite_snapshot(&source).unwrap(), before);
    }

    #[tokio::test]
    async fn probe_refuses_old_schema_before_the_constructor_can_migrate_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("old.sqlite");
        let store = TenantStore::open(&path).unwrap();
        drop(store);
        let db = Connection::open(&path).unwrap();
        db.execute_batch("DROP INDEX tenant_webhook_deliveries_due;")
            .unwrap();
        drop(db);
        let before = sqlite_snapshot(&path).unwrap();
        assert!(Database::Sqlite(path.clone())
            .open_current(Phase::Probe)
            .await
            .is_err());
        assert_eq!(sqlite_snapshot(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn probe_refuses_missing_bootstrap_before_open_would_backfill_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("old.sqlite");
        drop(TenantStore::open(&path).unwrap());
        let db = Connection::open(&path).unwrap();
        db.execute("DELETE FROM organizations WHERE id='org_bootstrap'", [])
            .unwrap();
        drop(db);
        let before = sqlite_snapshot(&path).unwrap();
        assert!(Database::Sqlite(path.clone())
            .open_current(Phase::Probe)
            .await
            .is_err());
        assert_eq!(sqlite_snapshot(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn reseeding_or_retry_metadata_replay_cannot_overwrite_existing_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.sqlite");
        let (store, m) = populated(&path).await;
        let before = sqlite_snapshot(&path).unwrap();
        assert!(seed_fixture(
            &store,
            "second",
            &m.source_fingerprint,
            &m.webhook_signing_key
        )
        .await
        .is_err());
        assert!(Database::Sqlite(path.clone())
            .seed_retry_state(&m)
            .await
            .is_err());
        assert!(Database::Sqlite(path.clone())
            .require_empty()
            .await
            .is_err());
        assert_eq!(sqlite_snapshot(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn a_changed_retry_owner_or_revocation_is_detected_instead_of_reported_as_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.sqlite");
        let (store, m) = populated(&path).await;
        let db = Connection::open(&path).unwrap();
        db.execute(
            "UPDATE tenant_webhook_deliveries SET attempt_count=3 WHERE id=?1",
            [&m.in_flight_delivery_id],
        )
        .unwrap();
        assert!(probe_fixture(&store, &m).await.is_err());
        db.execute(
            "UPDATE tenant_webhook_deliveries SET attempt_count=2 WHERE id=?1",
            [&m.in_flight_delivery_id],
        )
        .unwrap();
        db.execute(
            "UPDATE workspace_service_accounts SET active=1, revoked_at_unix=NULL WHERE id=?1",
            [&m.revoked_account_id],
        )
        .unwrap();
        assert!(probe_fixture(&store, &m).await.is_err());
    }

    #[tokio::test]
    async fn fixed_public_contract_never_exposes_private_manifest_values() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.sqlite");
        let (_store, m) = populated(&path).await;
        for phase in [Phase::Seed, Phase::Probe] {
            let public = serde_json::to_value(PublicAggregate::for_phase(phase)).unwrap();
            assert_eq!(
                public,
                json!({"schema_version":1,"mode":phase,"status":"passed",
                "tenants":2,"service_accounts":3,"webhook_destinations":1,"baseline_security_events":3,
                "pending_retry_preserved":true,"in_flight_ownership_preserved":true,
                "retry_state_synthetic":true,"retained_tokens_authenticated":true,
                "revoked_token_rejected":true,"tenant_isolation_verified":true,
                "target_schema_migrated":false,"model_requests_sent":0,"webhook_requests_sent":0})
            );
            let encoded = public.to_string();
            for private in [
                &m.run_id,
                &m.source_fingerprint,
                &m.webhook_signing_key,
                &m.active_account_token,
                &m.revoked_account_token,
                &m.control_active_account_token,
                &m.destination_secret,
                &m.tenant_id,
                &m.control_tenant_id,
                &m.workspace_id,
                &m.control_workspace_id,
                &m.owner_principal_id,
                &m.control_owner_principal_id,
                &m.active_account_id,
                &m.revoked_account_id,
                &m.control_active_account_id,
                &m.destination_id,
                &m.policy_version_id,
                &m.second_policy_version_id,
                &m.control_policy_version_id,
                &m.event_id,
                &m.second_event_id,
                &m.control_event_id,
                &m.delivery_id,
                &m.in_flight_delivery_id,
                &m.webhook_url,
            ] {
                assert!(!encoded.contains(private));
            }
        }
    }

    #[test]
    fn postgres_urls_require_explicit_numeric_loopback_and_no_connection_option_override() {
        for valid in [
            "postgresql://fixture:private@127.0.0.1/sou49_source?sslmode=disable",
            "postgresql://fixture:private@[::1]:5433/sou49_source?sslmode=disable",
        ] {
            validate_local_url(valid).unwrap();
            let original = tokio_postgres::Config::from_str(valid).unwrap();
            let readonly = tokio_postgres::Config::from_str(&readonly_url(valid).unwrap()).unwrap();
            assert_eq!(original.get_hosts(), readonly.get_hosts());
            assert_eq!(original.get_dbname(), readonly.get_dbname());
            assert_eq!(original.get_user(), readonly.get_user());
            assert_eq!(original.get_password(), readonly.get_password());
            assert_eq!(
                readonly.get_options(),
                Some("-c default_transaction_read_only=on")
            );
        }
        for invalid in ["postgresql://fixture:private@localhost/sou49_source?sslmode=disable",
            "postgresql://fixture:private@203.0.113.1/sou49_source?sslmode=disable",
            "postgresql://fixture:private@127.0.0.1/production?sslmode=disable",
            "postgresql://fixture:private@127.0.0.1/sou49_source?sslmode=require",
            "postgresql://fixture:private@127.0.0.1/sou49_source?sslmode=disable&options=-c%20search_path=other"] {
            assert!(validate_local_url(invalid).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_path_and_private_artifacts_refuse_links_public_files_and_replay() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let directory = directory.path().canonicalize().unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let source = directory.join("source.sqlite");
        validate_sqlite_path(&directory, &source, true).unwrap();
        assert!(
            validate_sqlite_path(&directory, &directory.join("../escape.sqlite"), true).is_err()
        );
        let link = directory.join("linked.sqlite");
        symlink(&source, &link).unwrap();
        assert!(validate_sqlite_path(&directory, &link, false).is_err());
        let hard_link = directory.join("hard-linked.sqlite");
        fs::hard_link(&source, &hard_link).unwrap();
        assert!(validate_sqlite_path(&directory, &hard_link, false).is_err());
        assert!(validate_sqlite_path(&directory, &source, false).is_err());
        fs::remove_file(&hard_link).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_sqlite_path(&directory, &source, false).is_err());
        let marker = directory.join(MARKER_FILE);
        let value = Marker {
            schema_version: 1,
            run_id: "private-run".into(),
            source_fingerprint: "private-source".into(),
        };
        write_private_new(&marker, &value).unwrap();
        assert!(write_private_new(&marker, &value).is_err());
        let read: Marker = read_private(&marker).unwrap();
        assert_eq!(read.run_id, value.run_id);
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private::<Marker>(&marker).is_err());
    }

    #[test]
    fn invalid_mode_errors_do_not_echo_untrusted_input() {
        for invalid in ["", "exercise-restored", "private-token\nseed", "SEED"] {
            assert_eq!(
                Phase::from_str(invalid).unwrap_err().to_string(),
                "unsupported fixture mode"
            );
        }
    }
}
