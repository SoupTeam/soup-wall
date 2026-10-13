// SPDX-License-Identifier: Apache-2.0
//! SQLite-only, tenant-scoped managed Agent enrollment (SOU-30).
//!
//! Agent credentials are random, returned once, and hashed with domain
//! separation. They are never admin, tenant proxy, or workspace credentials.
//! A revoked Agent is rejected at lookup time even if it knows its old token.

use anyhow::{ensure, Context, Result};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{now_unix, random_base64url, TenantStore};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EnrolledAgent {
    pub tenant_id: String,
    pub agent_id: String,
    pub created_at_unix: i64,
    pub revoked_at_unix: Option<i64>,
}

/// Token is sent to the operator at enrollment ONLY. It must not be persisted
/// in a console log, audit event or ordinary agent inventory response.
#[derive(Serialize)]
pub struct IssuedAgentCredential {
    #[serde(flatten)]
    pub agent: EnrolledAgent,
    pub token: String,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn credential_hash(token: &str) -> Option<Vec<u8>> {
    if token.len() != 52
        || !token.starts_with("sw_agent_")
        || !token
            .bytes()
            .skip(9)
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update(b"soup-wall-managed-agent-credential-v1\0");
    digest.update(token.as_bytes());
    Some(digest.finalize().to_vec())
}

fn ensure_schema(connection: &rusqlite::Connection) -> Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS managed_agent_enrollments (
             tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
             agent_id TEXT NOT NULL,
             token_hash BLOB NOT NULL UNIQUE,
             created_at_unix INTEGER NOT NULL,
             revoked_at_unix INTEGER,
             PRIMARY KEY (tenant_id, agent_id)
         );
         CREATE INDEX IF NOT EXISTS managed_agents_active_tokens
             ON managed_agent_enrollments(token_hash)
             WHERE revoked_at_unix IS NULL;",
        )
        .context("failed to prepare SQLite managed-agent enrollment schema")
}

impl TenantStore {
    /// Called by an authorized *admin* route, never directly by an Agent.
    /// A second enrollment for the same tenant/Agent is rejected; after
    /// revocation, reprovision a distinct Agent identity in this bounded slice.
    pub fn enroll_managed_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<IssuedAgentCredential> {
        ensure!(
            valid_id(tenant_id) && valid_id(agent_id),
            "invalid tenant/Agent identity"
        );
        let mut conn = self.connection()?;
        ensure_schema(&conn)?;
        let tx = conn
            .transaction()
            .context("could not start Agent enrollment transaction")?;
        let active: Option<i64> = tx
            .query_row(
                "SELECT active FROM tenants WHERE id = ?1",
                [tenant_id],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(active == Some(1), "tenant not found or inactive");
        let token = format!("sw_agent_{}", random_base64url(32));
        let hash = credential_hash(&token).context("invalid generated Agent credential")?;
        let created_at_unix = now_unix();
        tx.execute(
            "INSERT INTO managed_agent_enrollments
                 (tenant_id, agent_id, token_hash, created_at_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![tenant_id, agent_id, hash, created_at_unix],
        )
        .context("Agent enrollment already exists or could not be saved")?;
        tx.commit()?;
        Ok(IssuedAgentCredential {
            agent: EnrolledAgent {
                tenant_id: tenant_id.to_owned(),
                agent_id: agent_id.to_owned(),
                created_at_unix,
                revoked_at_unix: None,
            },
            token,
        })
    }

    /// Strictly Bearer Agent credential; tenant/admin tokens never work here.
    /// A disabled tenant and any revoked enrollment are refused.
    pub fn authenticate_managed_agent(
        &self,
        authorization: Option<&str>,
    ) -> Result<Option<EnrolledAgent>> {
        let Some(token) = authorization.and_then(|s| s.strip_prefix("Bearer ")) else {
            return Ok(None);
        };
        let Some(hash) = credential_hash(token) else {
            return Ok(None);
        };
        let conn = self.connection()?;
        ensure_schema(&conn)?;
        conn.query_row(
            "SELECT a.tenant_id, a.agent_id, a.created_at_unix, a.revoked_at_unix
             FROM managed_agent_enrollments a
             JOIN tenants t ON t.id = a.tenant_id
             WHERE a.token_hash = ?1 AND a.revoked_at_unix IS NULL AND t.active = 1",
            [hash],
            |r| {
                Ok(EnrolledAgent {
                    tenant_id: r.get(0)?,
                    agent_id: r.get(1)?,
                    created_at_unix: r.get(2)?,
                    revoked_at_unix: r.get(3)?,
                })
            },
        )
        .optional()
        .context("managed Agent authentication failed")
    }

    /// Revoking enrollment invalidates credential and fetch/ack authorization.
    pub fn revoke_managed_agent(&self, tenant_id: &str, agent_id: &str) -> Result<bool> {
        ensure!(
            valid_id(tenant_id) && valid_id(agent_id),
            "invalid tenant/Agent identity"
        );
        let conn = self.connection()?;
        ensure_schema(&conn)?;
        let changed = conn.execute(
            "UPDATE managed_agent_enrollments SET revoked_at_unix = ?3
             WHERE tenant_id = ?1 AND agent_id = ?2 AND revoked_at_unix IS NULL",
            params![tenant_id, agent_id, now_unix()],
        )?;
        Ok(changed == 1)
    }

    /// Bounded tenant-scoped inventory with no credential hashes or secrets.
    pub fn list_managed_agents(&self, tenant_id: &str) -> Result<Vec<EnrolledAgent>> {
        ensure!(valid_id(tenant_id), "invalid tenant identity");
        let conn = self.connection()?;
        ensure_schema(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT tenant_id, agent_id, created_at_unix, revoked_at_unix
             FROM managed_agent_enrollments WHERE tenant_id = ?1
             ORDER BY agent_id ASC LIMIT 256",
        )?;
        let rows = stmt.query_map([tenant_id], |r| {
            Ok(EnrolledAgent {
                tenant_id: r.get(0)?,
                agent_id: r.get(1)?,
                created_at_unix: r.get(2)?,
                revoked_at_unix: r.get(3)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list managed Agents")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_authenticate_revoke_and_isolate_tenants() {
        let store = TenantStore::open(":memory:").unwrap();
        let one = store.create_tenant("agent-enrollment-one").unwrap();
        let two = store.create_tenant("agent-enrollment-two").unwrap();
        let issued = store.enroll_managed_agent(&one.id, "agent-a").unwrap();
        assert!(issued.token.starts_with("sw_agent_"));
        assert!(store.enroll_managed_agent(&one.id, "agent-a").is_err());
        assert!(store
            .enroll_managed_agent("tenant_not_real", "agent-a")
            .is_err());
        assert!(store
            .authenticate_managed_agent(Some("Bearer llmfw_tenant_token"))
            .unwrap()
            .is_none());
        assert!(store
            .authenticate_managed_agent(Some(&format!("Bearer {}", issued.token)))
            .unwrap()
            .is_some());
        let list = store.list_managed_agents(&one.id).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].agent_id, "agent-a");
        assert!(store.list_managed_agents(&two.id).unwrap().is_empty());
        assert!(store.revoke_managed_agent(&one.id, "agent-a").unwrap());
        assert!(!store.revoke_managed_agent(&one.id, "agent-a").unwrap());
        assert!(store
            .authenticate_managed_agent(Some(&format!("Bearer {}", issued.token)))
            .unwrap()
            .is_none());
        assert!(store.list_managed_agents(&one.id).unwrap()[0]
            .revoked_at_unix
            .is_some());
    }

    #[test]
    fn validate_agent_identity_rejects_paths_and_empty_ids() {
        assert!(!valid_id(""));
        assert!(!valid_id("../../x"));
        assert!(!valid_id("white space"));
        assert!(!valid_id(&"a".repeat(129)));
        assert!(valid_id("agent.alpha-01"));
    }
}
