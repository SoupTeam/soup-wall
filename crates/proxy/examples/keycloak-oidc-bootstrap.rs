// SPDX-License-Identifier: Apache-2.0

//! Seed only a new disposable SQLite store for the real-provider OIDC drill.
use anyhow::{bail, Context};
use llm_firewall::tenant_store::{TenantStore, WorkspaceRole};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [database, issuer, client, redirect, owner, analyst] = args.as_slice() else {
        bail!("usage: keycloak-oidc-bootstrap NEW_DATABASE ISSUER CLIENT REDIRECT OWNER_SUB ANALYST_SUB");
    };
    println!(
        "{}",
        bootstrap(database, issuer, client, redirect, owner, analyst)?
    );
    Ok(())
}

fn bootstrap(
    database: &str,
    issuer: &str,
    client: &str,
    redirect: &str,
    owner: &str,
    analyst: &str,
) -> anyhow::Result<serde_json::Value> {
    if Path::new(database).exists() || owner == analyst {
        bail!("requires a new database and distinct synthetic subjects");
    }
    let store = TenantStore::open(database)?;
    let organization = store.create_organization("Disposable OIDC acceptance")?;
    let tenant = store.create_tenant_in_organization(&organization.id, "Acceptance workspace")?;
    let workspace = store
        .workspace_for_tenant(&tenant.id)?
        .context("workspace absent")?;
    store.set_organization_oidc_connection(&organization.id, issuer, client, redirect, true)?;
    let mut principals = Vec::new();
    for (subject, role) in [
        (owner, WorkspaceRole::Owner),
        (analyst, WorkspaceRole::Analyst),
    ] {
        let principal = store.create_workspace_principal("Synthetic OIDC member")?;
        store.link_workspace_external_identity(&principal.id, issuer, subject)?;
        store.set_workspace_membership(&workspace.id, &principal.id, role)?;
        principals.push(principal.id);
    }
    let other_org = store.create_organization("Unrelated acceptance organization")?;
    let other_tenant = store.create_tenant_in_organization(&other_org.id, "Unrelated workspace")?;
    let other_workspace = store
        .workspace_for_tenant(&other_tenant.id)?
        .context("workspace absent")?;
    store.set_organization_oidc_connection(&other_org.id, issuer, client, redirect, true)?;
    Ok(
        serde_json::json!({"organization_id": organization.id, "workspace_id": workspace.id,
        "owner_principal_id": principals[0], "analyst_principal_id": principals[1],
        "other_organization_id": other_org.id, "other_workspace_id": other_workspace.id}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_has_local_roles_and_no_cross_workspace_membership() {
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
