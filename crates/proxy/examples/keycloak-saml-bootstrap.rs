// SPDX-License-Identifier: Apache-2.0

//! Pre-provision two synthetic SAML identities in a new, disposable SQLite store.
//! This example never reads an assertion or grants access from an IdP role claim.

use std::{io::Read, path::Path};

use anyhow::{bail, Context};
use llm_firewall::tenant_store::{TenantStore, WorkspaceRole};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if let [mode, database] = arguments.as_slice() {
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
    if let [mode, database, issuer, owner, analyst] = arguments.as_slice() {
        if mode == "--lifecycle" {
            println!("{}", lifecycle(database, issuer, owner, analyst).await?);
            return Ok(());
        }
    }
    let [database, issuer, subject, alias] = arguments.as_slice() else {
        bail!(
            "usage: keycloak-saml-bootstrap NEW_DATABASE ISSUER SYNTHETIC_SUBJECT SYNTHETIC_ALIAS"
        );
    };
    println!("{}", bootstrap(database, issuer, subject, alias)?);
    Ok(())
}

fn bootstrap(
    database: &str,
    issuer: &str,
    subject: &str,
    alias: &str,
) -> anyhow::Result<serde_json::Value> {
    if subject == alias {
        bail!("the negative signature check needs a distinct pre-provisioned alias");
    }
    if Path::new(database).exists() {
        bail!("refusing to change an existing database");
    }
    let store = TenantStore::open(database)?;
    let organization = store.create_organization("Disposable Keycloak acceptance")?;
    let tenant = store.create_tenant_in_organization(&organization.id, "Disposable workspace")?;
    let workspace = store
        .workspace_for_tenant(&tenant.id)?
        .context("new tenant has no workspace")?;
    let principal = store.create_workspace_principal("Synthetic Keycloak user")?;
    store.link_workspace_external_identity(&principal.id, issuer, subject)?;
    store.set_workspace_membership(&workspace.id, &principal.id, WorkspaceRole::Owner)?;
    // One issuer has one subject per principal. Use another authorized principal
    // so the negative mutation cannot be rejected merely as an unknown identity.
    let alias_principal = store.create_workspace_principal("Synthetic negative-check user")?;
    store.link_workspace_external_identity(&alias_principal.id, issuer, alias)?;
    store.set_workspace_membership(&workspace.id, &alias_principal.id, WorkspaceRole::Owner)?;
    // The SAML connection is imported by the driver after bootstrap. Verify
    // stored identities/memberships here; the OIDC authorization helper needs
    // a separate configured OIDC connection and cannot validate this SAML seed.
    let members = store.list_workspace_members(&workspace.id)?;
    for (name_id, principal_id) in [(subject, &principal.id), (alias, &alias_principal.id)] {
        let linked = store
            .workspace_principal_for_external_identity(issuer, name_id)?
            .context("pre-provisioned synthetic identity is not linked")?;
        let membership = members
            .iter()
            .find(|member| member.principal_id == linked.id)
            .context("pre-provisioned synthetic identity has no workspace membership")?;
        if linked.id != *principal_id
            || !linked.active
            || !membership.active
            || membership.role != WorkspaceRole::Owner
        {
            bail!("pre-provisioned synthetic identity lacks the owner role");
        }
    }
    Ok(serde_json::json!({
        "organization_id": organization.id,
        "workspace_id": workspace.id,
    }))
}

async fn lifecycle(
    database: &str,
    issuer: &str,
    owner: &str,
    analyst: &str,
) -> anyhow::Result<serde_json::Value> {
    if owner == analyst || (database != "postgres" && Path::new(database).exists()) {
        bail!("requires a fresh disposable database and distinct subjects");
    }
    let store = open_store(database).await?;
    if !store.list_tenants_async().await?.is_empty() {
        bail!("fixture already populated");
    }
    let organization = store
        .create_organization_async("Disposable SAML acceptance")
        .await?;
    let tenant = store
        .create_tenant_in_organization_async(&organization.id, "SAML workspace")
        .await?;
    let workspace = store
        .workspace_for_tenant_async(&tenant.id)
        .await?
        .context("workspace absent")?;
    let other = store
        .create_tenant_in_organization_async(&organization.id, "No membership workspace")
        .await?;
    let other_workspace = store
        .workspace_for_tenant_async(&other.id)
        .await?
        .context("workspace absent")?;
    let mut principals = Vec::new();
    for (subject, role) in [
        (owner, WorkspaceRole::Owner),
        (analyst, WorkspaceRole::Analyst),
    ] {
        let principal = store
            .create_workspace_principal_async("Synthetic SAML user")
            .await?;
        store
            .link_workspace_external_identity_async(&principal.id, issuer, subject)
            .await?;
        store
            .set_workspace_membership_async(&workspace.id, &principal.id, role)
            .await?;
        principals.push(principal.id);
    }
    Ok(
        serde_json::json!({"organization_id": organization.id, "workspace_id": workspace.id,
        "other_workspace_id": other_workspace.id,
        "owner_principal_id": principals[0], "analyst_principal_id": principals[1]}),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_preprovisions_two_active_owners_before_idp_import() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("fixture.sqlite");
        let issuer = "https://127.0.0.1:20443/realms/fixture";
        let scope = bootstrap(
            database.to_str().unwrap(),
            issuer,
            "user@example.test",
            "alias@example.test",
        )
        .expect("SAML bootstrap must not require a configured OIDC connection");
        let store = TenantStore::open(database.to_str().unwrap()).unwrap();
        let members = store
            .list_workspace_members(scope["workspace_id"].as_str().unwrap())
            .unwrap();
        assert_eq!(members.len(), 2);
        assert_ne!(members[0].principal_id, members[1].principal_id);
        for subject in ["user@example.test", "alias@example.test"] {
            let principal = store
                .workspace_principal_for_external_identity(issuer, subject)
                .unwrap()
                .unwrap();
            let member = members
                .iter()
                .find(|member| member.principal_id == principal.id)
                .unwrap();
            assert!(principal.active && member.active);
            assert_eq!(member.role, WorkspaceRole::Owner);
        }
    }

    #[test]
    fn bootstrap_refuses_existing_file_without_modifying_it() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("existing.sqlite");
        std::fs::write(&database, b"existing operator data").unwrap();
        assert!(bootstrap(
            database.to_str().unwrap(),
            "https://idp.example/realm",
            "user",
            "alias"
        )
        .is_err());
        assert_eq!(std::fs::read(&database).unwrap(), b"existing operator data");
    }
}
