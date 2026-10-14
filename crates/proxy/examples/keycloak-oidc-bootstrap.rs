// SPDX-License-Identifier: Apache-2.0

//! Seed only a new disposable SQLite or PostgreSQL store for the real-provider OIDC drill.
use anyhow::{bail, Context};
use llm_firewall::tenant_store::{TenantStore, WorkspaceRole};
use std::{io::Read, path::Path, time::Duration};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if let [mode, database] = args.as_slice() {
        if mode == "--probe-token" {
            if database != "postgres" && !Path::new(database).is_file() {
                bail!("probe requires an existing fixture");
            }
            let store = open_store(database).await?;
            let mut token = String::new();
            std::io::stdin().take(4097).read_to_string(&mut token)?;
            if token.len() > 4096 {
                bail!("oversized fixture token");
            }
            let authorized = store
                .authenticate_access_async(Some(&format!("Bearer {}", token.trim())))
                .await?
                .is_some();
            println!("{}", serde_json::json!({"authenticated": authorized}));
            return Ok(());
        }
    }
    let [database, issuer, client, redirect, owner, analyst] = args.as_slice() else {
        bail!("usage: keycloak-oidc-bootstrap NEW_DATABASE ISSUER CLIENT REDIRECT OWNER_SUB ANALYST_SUB");
    };
    println!(
        "{}",
        bootstrap(database, issuer, client, redirect, owner, analyst).await?
    );
    Ok(())
}

async fn bootstrap(
    database: &str,
    issuer: &str,
    client: &str,
    redirect: &str,
    owner: &str,
    analyst: &str,
) -> anyhow::Result<serde_json::Value> {
    if (database != "postgres" && Path::new(database).exists()) || owner == analyst {
        bail!("requires a new database and distinct synthetic subjects");
    }
    let store = open_store(database).await?;
    if !store.list_tenants_async().await?.is_empty() {
        bail!("fixture database already populated");
    }
    let organization = store
        .create_organization_async("Disposable OIDC acceptance")
        .await?;
    let tenant = store
        .create_tenant_in_organization_async(&organization.id, "Acceptance workspace")
        .await?;
    let workspace = store
        .workspace_for_tenant_async(&tenant.id)
        .await?
        .context("workspace absent")?;
    store
        .set_organization_oidc_connection_async(&organization.id, issuer, client, redirect, true)
        .await?;
    let mut principals = Vec::new();
    for (subject, role) in [
        (owner, WorkspaceRole::Owner),
        (analyst, WorkspaceRole::Analyst),
    ] {
        let principal = store
            .create_workspace_principal_async("Synthetic OIDC member")
            .await?;
        store
            .link_workspace_external_identity_async(&principal.id, issuer, subject)
            .await?;
        store
            .set_workspace_membership_async(&workspace.id, &principal.id, role)
            .await?;
        principals.push(principal.id);
    }
    let other_org = store
        .create_organization_async("Unrelated acceptance organization")
        .await?;
    let other_tenant = store
        .create_tenant_in_organization_async(&other_org.id, "Unrelated workspace")
        .await?;
    let other_workspace = store
        .workspace_for_tenant_async(&other_tenant.id)
        .await?
        .context("workspace absent")?;
    store
        .set_organization_oidc_connection_async(&other_org.id, issuer, client, redirect, true)
        .await?;
    Ok(
        serde_json::json!({"organization_id": organization.id, "workspace_id": workspace.id,
        "owner_principal_id": principals[0], "analyst_principal_id": principals[1],
        "other_organization_id": other_org.id, "other_workspace_id": other_workspace.id}),
    )
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
            Duration::from_secs(5),
            2,
            Duration::from_secs(5),
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn postgres_fixture_rejects_external_unbound_and_unverified_targets() {
        let name = "soup_oidc_0123456789abcdef0123456789abcdef";
        let valid =
            format!("postgresql://oidc_fixture:synthetic@127.0.0.1:5432/{name}?sslmode=require");
        assert!(validate_postgres_fixture(&valid, name).is_ok());
        for bad in [
            valid.replace("127.0.0.1", "192.0.2.1"),
            valid.replace("require", "disable"),
            valid.replace(name, "existing"),
            format!("{valid}&options=anything"),
            valid.replace("oidc_fixture:", "operator:"),
        ] {
            assert!(validate_postgres_fixture(&bad, name).is_err());
        }
    }
    #[tokio::test]
    async fn fixture_has_local_roles_and_no_cross_workspace_membership() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("fixture.sqlite");
        let path = database.to_str().unwrap();
        let issuer = "https://id.example.test/realms/disposable";
        let scope = bootstrap(
            path,
            issuer,
            "console",
            "https://console.example.test/auth/oidc/callback",
            "owner",
            "analyst",
        )
        .await
        .unwrap();
        let store = TenantStore::open(path).unwrap();
        let members = store
            .list_workspace_members(scope["workspace_id"].as_str().unwrap())
            .unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.iter().any(|m| m.role == WorkspaceRole::Owner));
        assert!(members.iter().any(|m| m.role == WorkspaceRole::Analyst));
        assert!(store
            .list_workspace_members(scope["other_workspace_id"].as_str().unwrap())
            .unwrap()
            .is_empty());
        assert!(bootstrap(
            path,
            issuer,
            "console",
            "https://console.example.test/auth/oidc/callback",
            "owner",
            "analyst"
        )
        .await
        .is_err());
        assert_eq!(
            store
                .list_workspace_members(scope["workspace_id"].as_str().unwrap())
                .unwrap()
                .len(),
            2
        );
    }
}
