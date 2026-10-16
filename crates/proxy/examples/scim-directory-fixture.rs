// SPDX-License-Identifier: Apache-2.0
//! Owned loopback SCIM interoperability fixture. Credentials travel over private pipes only.
use anyhow::{bail, Context};
use llm_firewall::{app, handlers::AppState, tenant_store::TenantStore, test_config};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
use std::future::IntoFuture;
use std::{
    io::{BufRead, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [database] = args.as_slice() else {
        bail!("requires a new disposable database path or postgres");
    };
    if database != "postgres" && Path::new(database).exists() {
        bail!("refusing existing SQLite store");
    }
    let store = open_store(database).await?;
    anyhow::ensure!(
        store.list_organizations_async().await?.is_empty(),
        "requires empty fixture store"
    );
    let expiry = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64 + 1800;
    let mut issued = Vec::new();
    for label in ["SCIM fixture A", "SCIM fixture B"] {
        let org = store.create_organization_async(label).await?;
        issued.push(
            store
                .issue_scim_token_async(&org.id, "fixture", expiry)
                .await?,
        );
    }
    let mut config = test_config("http://127.0.0.1:1".into());
    config.tenant_store.enabled = true;
    let state = Arc::new(AppState {
        firewall: Firewall::new(
            vec![Box::new(InjectionDetector::new())],
            PolicySet::from_yaml("default: allow")?,
        ),
        http: reqwest::Client::new(),
        openai_api_key: None,
        proxy_auth_token: None,
        tenant_store: Some(store),
        admin_token: None,
        oidc_state_cipher: None,
        saml: None,
        rate_limiter: Mutex::new(llm_firewall::rate_limit::RateLimiter::new(
            Default::default(),
        )),
        spend_ledger: Mutex::new(llm_firewall::spend_limit::SpendLedger::new(
            Default::default(),
        )),
        redis_limits: None,
        agent: Mutex::new(soup_wall_agent::AgentFirewall::with_default_policy()),
        moderation: llm_firewall::moderation::ModerationGate::new(Default::default()),
        config,
    });

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(axum::serve(listener, app(state.clone())).into_future());
    println!(
        "{}",
        serde_json::json!({"base_url": format!("http://{address}/scim/v2/"),
        "token": issued[0].token, "other_token": issued[1].token})
    );
    std::io::stdout().flush()?;
    let store = state
        .tenant_store
        .as_ref()
        .context("fixture store absent")?;
    // Fixed commands only; no caller-provided token IDs or arbitrary SQL.
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().take(4) {
            if tx.blocking_send(line.unwrap_or_default()).is_err() {
                break;
            }
        }
    });
    while let Some(command) = rx.recv().await {
        match command.as_str() {
            "revoke" => {
                anyhow::ensure!(
                    store
                        .revoke_scim_token_async(&issued[0].credential.id)
                        .await?,
                    "revocation failed"
                );
                println!("revoked");
                std::io::stdout().flush()?;
            }
            "stop" => break,
            _ => bail!("unknown fixture command"),
        }
    }
    server.abort();
    let _ = server.await;
    Ok(())
}

async fn open_store(database: &str) -> anyhow::Result<TenantStore> {
    if database == "postgres" {
        let url = std::env::var("SOUP_OIDC_FIXTURE_DATABASE_URL")?;
        let expected = std::env::var("SOUP_OIDC_FIXTURE_DATABASE_NAME")?;
        validate_postgres_fixture(&url, &expected)?;
        let ca = std::env::var("LLM_FW_POSTGRES_CA_CERT_FILE")?;
        TenantStore::open_postgres_with_ca(
            &url,
            1000,
            std::time::Duration::from_secs(5),
            2,
            std::time::Duration::from_secs(5),
            Some(&ca),
        )
        .await
    } else {
        TenantStore::open(database)
    }
}

fn validate_postgres_fixture(value: &str, expected: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(value)?;
    let query: Vec<_> = url.query_pairs().collect();
    if !expected.starts_with("soup_oidc_")
        || expected.len() != 42
        || !expected[10..].bytes().all(|b| b.is_ascii_hexdigit())
        || url.scheme() != "postgresql"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none()
        || url.path() != format!("/{expected}")
        || url.username() != "oidc_fixture"
        || url.password().is_none()
        || url.fragment().is_some()
        || query.len() != 1
        || query[0].0 != "sslmode"
        || query[0].1 != "require"
    {
        bail!("requires the explicit loopback TLS disposable PostgreSQL fixture");
    }
    Ok(())
}
