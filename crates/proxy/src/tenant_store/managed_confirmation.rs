// SPDX-License-Identifier: Apache-2.0
//! SOU-220: authoritative cohort preview and guarded start for a group rollout.
//!
//! A preview reads the server-authorized scope (effective cohort, approved digest, baselines and
//! sequences) and, only when nothing blocks the start, records one bounded, expiring confirmation.
//! A preview issues no deployment and grants no authority: authorization stays with the existing
//! Owner role, tenant and Agent checks. The guarded start re-derives the same facts under the
//! storage transaction (SQLite) or tenant lease (PostgreSQL) that issues the first wave, and refuses
//! with zero deployments if anything differs. The pure rules live here once; each backend only gathers
//! the facts, so SQLite and PostgreSQL cannot drift apart.
use super::operator_audit::{AuditFact, AuditOperation};
use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::managed_policy::{
    eligible, eligible_group, exact_id, group_schema, ManagedGroupRollout, ManagedIssuer,
};
use super::{now_unix, random_base64url, AdminRole, TenantStore};

pub const PREVIEW_CONTRACT: &str = "sw-group-rollout-preview/1";
pub const CONFIRMATION_VERSION: u16 = 1;
pub const CONFIRMATION_TTL_SECS: i64 = 300;
/// A preview describes at most this many Agents; larger groups cannot be confirmed through it.
pub const MAX_PREVIEW_AGENTS: usize = 500;
const ID_PREFIX: &str = "swc1_";
const ID_DOMAIN: &[u8] = b"soup-wall-group-start-confirmation-id-v1\0";
const INTENT_DOMAIN: &[u8] = b"soup-wall-group-start-confirmation-intent-v1\0";
const SNAPSHOT_DOMAIN: &[u8] = b"soup-wall-group-start-snapshot-v1\0";
/// Identity the bootstrap admin token authenticates as; it has no stored row to recheck.
const BOOTSTRAP_ADMIN: &str = "bootstrap_owner";
const ACTIVE_PHASES: [&str; 4] = ["pilot", "standard", "paused", "rolling_back"];

pub fn valid_confirmation_id(id: &str) -> bool {
    id.len() == ID_PREFIX.len() + 43
        && id.starts_with(ID_PREFIX)
        && id[ID_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Clone, Debug, Serialize)]
pub struct CohortAgent {
    pub agent_id: String,
    pub wave: &'static str,
    /// Enrolled, not revoked, tenant active: the same test the issuance applies.
    pub authorized: bool,
    pub baseline_revision: Option<String>,
    pub latest_sequence: u64,
    pub latest_revision: Option<String>,
    pub latest_status: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CohortBlocker {
    pub code: &'static str,
    pub agent_id: Option<String>,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct LatestRollout {
    pub rollout_id: String,
    pub phase: String,
    pub revision: String,
    pub policy_sha256: String,
}

/// Actual public signing identity, independent of the requested default/alias.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedSigner {
    pub issuer_key_id: String,
    /// SHA-256 of the raw Ed25519 public-key bytes; never a seed fingerprint.
    pub public_key_sha256: String,
}

pub(super) fn signer_identity(issuer: &ManagedIssuer) -> ResolvedSigner {
    ResolvedSigner {
        issuer_key_id: issuer.key_id().to_owned(),
        public_key_sha256: issuer.public_key_sha256(),
    }
}

/// The server's view of what a start would do right now. Contains no secret and no authority.
#[derive(Clone, Debug, Serialize)]
pub struct CohortPreview {
    pub contract_version: &'static str,
    pub executed: bool,
    pub tenant_id: String,
    pub group_id: String,
    pub revision: String,
    pub policy_sha256: Option<String>,
    pub approved: bool,
    /// Exactly as requested; `None` means the Console default signer.
    pub issuer_key_id: Option<String>,
    pub signer_available: bool,
    pub resolved_signer: Option<ResolvedSigner>,
    pub pilots: Vec<String>,
    pub workers: Vec<String>,
    pub agents: Vec<CohortAgent>,
    pub latest_rollout: Option<LatestRollout>,
    pub blockers: Vec<CohortBlocker>,
    pub startable: bool,
    /// Digest of every fact above; a start is allowed only while it still matches.
    pub snapshot_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct StartConfirmation {
    pub version: u16,
    pub id: String,
    pub expires_at_unix: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct GroupStartPreview {
    #[serde(flatten)]
    pub preview: CohortPreview,
    /// Present only when `startable`.
    pub confirmation: Option<StartConfirmation>,
}

#[derive(Clone, Copy, Debug)]
pub struct StartGuard<'a> {
    pub confirmation_id: &'a str,
    pub admin_id: &'a str,
    pub requested_issuer_key: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct GuardedStart {
    pub rollout: ManagedGroupRollout,
    /// The confirmation had already started this exact rollout; nothing was issued now.
    pub replayed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationFailure {
    /// Scope, authorization, revision, baseline or sequence changed since the preview.
    Stale,
    Expired,
    /// Unknown, forged, foreign, for another intent, or already used for a different outcome.
    Invalid,
}

#[derive(Debug)]
pub struct ConfirmationRefused(pub ConfirmationFailure);
impl ConfirmationRefused {
    pub fn code(&self) -> &'static str {
        match self.0 {
            ConfirmationFailure::Stale => "confirmation_stale",
            ConfirmationFailure::Expired => "confirmation_expired",
            ConfirmationFailure::Invalid => "confirmation_invalid",
        }
    }
}
impl std::fmt::Display for ConfirmationRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            ConfirmationFailure::Stale => "the cohort changed since it was previewed",
            ConfirmationFailure::Expired => "the confirmation expired",
            ConfirmationFailure::Invalid => "the confirmation is not valid for this request",
        })
    }
}
impl std::error::Error for ConfirmationRefused {}

/// Facts about one Agent, gathered by a backend from a consistent read.
#[derive(Clone, Debug, Default)]
pub struct AgentFacts {
    pub authorized: bool,
    pub latest: Option<(u64, String, String)>,
    pub baseline: Option<String>,
    pub revision_conflict: bool,
    pub revision_unapproved: bool,
}

#[derive(Clone, Debug, Default)]
pub struct CohortFacts {
    pub revision: Option<(String, bool)>,
    pub latest_rollout: Option<LatestRollout>,
    pub members: Vec<(String, bool)>,
    /// Active rollouts of other groups of the tenant, with their frozen Agents.
    pub other_active: Vec<(String, String, String, Vec<String>)>,
    pub agents: BTreeMap<String, AgentFacts>,
}

fn sha(parts: &[&[u8]]) -> Vec<u8> {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u32).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().to_vec()
}

fn confirmation_hash(id: &str) -> Vec<u8> {
    sha(&[ID_DOMAIN, id.as_bytes()])
}

pub(super) fn intent_digest(
    tenant: &str,
    group: &str,
    admin_id: &str,
    revision: &str,
    requested_issuer: Option<&str>,
) -> Vec<u8> {
    sha(&[
        INTENT_DOMAIN,
        &CONFIRMATION_VERSION.to_be_bytes(),
        tenant.as_bytes(),
        group.as_bytes(),
        admin_id.as_bytes(),
        revision.as_bytes(),
        requested_issuer.unwrap_or("").as_bytes(),
    ])
}

fn hex(bytes: &[u8]) -> String {
    super::managed_policy::hex(bytes)
}

/// Pure rules: turns gathered facts into the preview, blockers and snapshot digest.
pub(super) fn assemble(
    facts: &CohortFacts,
    tenant: &str,
    group: &str,
    revision: &str,
    requested_issuer: Option<&str>,
    resolved_signer: Option<ResolvedSigner>,
) -> CohortPreview {
    let signer_available = resolved_signer.is_some();
    let mut blockers = Vec::new();
    let mut block = |code: &'static str, agent: Option<&str>, detail: String| {
        blockers.push(CohortBlocker {
            code,
            agent_id: agent.map(str::to_owned),
            detail,
        })
    };
    let (policy_sha256, approved) = match &facts.revision {
        Some((sha, approved)) => (Some(sha.clone()), *approved),
        None => (None, false),
    };
    if !approved {
        block(
            "revision_not_approved",
            None,
            format!("group revision '{revision}' is not approved or does not exist"),
        );
    }
    let mut pilots: Vec<String> = facts
        .members
        .iter()
        .filter(|(_, pilot)| *pilot)
        .map(|(a, _)| a.clone())
        .collect();
    let mut workers: Vec<String> = facts
        .members
        .iter()
        .filter(|(_, pilot)| !*pilot)
        .map(|(a, _)| a.clone())
        .collect();
    pilots.sort();
    workers.sort();
    if facts.members.is_empty() {
        block("empty_group", None, "the group has no members".into());
    } else if pilots.is_empty() {
        block(
            "no_pilots",
            None,
            "a staged rollout needs at least one pilot".into(),
        );
    }
    if facts.members.len() > MAX_PREVIEW_AGENTS {
        block(
            "cohort_too_large",
            None,
            format!("a preview describes at most {MAX_PREVIEW_AGENTS} Agents"),
        );
    }
    if let Some(latest) = &facts.latest_rollout {
        if ACTIVE_PHASES.contains(&latest.phase.as_str()) {
            block(
                "active_rollout",
                None,
                format!(
                    "rollout {} is {}; read it instead of starting another",
                    latest.rollout_id, latest.phase
                ),
            );
        } else if latest.phase == "completed"
            && latest.revision == revision
            && Some(&latest.policy_sha256) == policy_sha256.as_ref()
        {
            block(
                "already_rolled_out",
                None,
                format!(
                    "rollout {} already completed this revision",
                    latest.rollout_id
                ),
            );
        }
    }
    let member_ids: std::collections::BTreeSet<&str> =
        facts.members.iter().map(|(a, _)| a.as_str()).collect();
    for (other_group, rollout_id, phase, agents) in &facts.other_active {
        for agent in agents.iter().filter(|a| member_ids.contains(a.as_str())) {
            block(
                "agent_in_active_rollout",
                Some(agent),
                format!("rollout {rollout_id} of group '{other_group}' is {phase}"),
            );
        }
    }
    let mut agents = Vec::new();
    for (wave, ids) in [("pilot", &pilots), ("worker", &workers)] {
        for id in ids {
            let f = facts.agents.get(id).cloned().unwrap_or_default();
            if !f.authorized {
                block(
                    "agent_not_authorized",
                    Some(id),
                    "not enrolled, revoked or tenant inactive".into(),
                );
            }
            if let Some((sequence, _, status)) = &f.latest {
                if status == "issued" || status == "delivered" {
                    block(
                        "unacknowledged_deployment",
                        Some(id),
                        format!("sequence {sequence} is {status} and not acknowledged"),
                    );
                }
            }
            if f.revision_conflict {
                block(
                    "revision_collision",
                    Some(id),
                    format!("revision '{revision}' exists with a different digest"),
                );
            }
            if f.revision_unapproved {
                block(
                    "agent_revision_not_approved",
                    Some(id),
                    format!("revision '{revision}' exists but is not approved"),
                );
            }
            agents.push(CohortAgent {
                agent_id: id.clone(),
                wave,
                authorized: f.authorized,
                baseline_revision: f.baseline.clone(),
                latest_sequence: f.latest.as_ref().map(|l| l.0).unwrap_or(0),
                latest_revision: f.latest.as_ref().map(|l| l.1.clone()),
                latest_status: f.latest.as_ref().map(|l| l.2.clone()),
            });
        }
    }
    if !signer_available {
        block(
            "signer_unavailable",
            None,
            "the Console cannot sign with the requested issuer key".into(),
        );
    }
    let mut preview = CohortPreview {
        contract_version: PREVIEW_CONTRACT,
        executed: false,
        tenant_id: tenant.into(),
        group_id: group.into(),
        revision: revision.into(),
        policy_sha256,
        approved,
        issuer_key_id: requested_issuer.map(str::to_owned),
        signer_available,
        resolved_signer,
        pilots,
        workers,
        agents,
        latest_rollout: facts.latest_rollout.clone(),
        startable: blockers.is_empty(),
        blockers,
        snapshot_sha256: String::new(),
    };
    let canonical = serde_json::to_vec(&preview).unwrap_or_default();
    preview.snapshot_sha256 = hex(&sha(&[SNAPSHOT_DOMAIN, &canonical]));
    preview
}

pub(super) fn resolved_signer(requested: Option<&str>) -> Option<ResolvedSigner> {
    ManagedIssuer::from_environment_for_key(requested)
        .ok()
        .as_ref()
        .map(signer_identity)
}

pub(super) fn new_confirmation_id() -> String {
    format!("{ID_PREFIX}{}", random_base64url(32))
}

pub(super) fn id_hash(id: &str) -> Vec<u8> {
    confirmation_hash(id)
}

pub(super) const SQLITE_CONFIRMATION_SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS managed_group_start_confirmations (
    tenant_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    confirmation_hash BLOB NOT NULL CHECK(length(confirmation_hash)=32),
    admin_id TEXT NOT NULL,
    intent_digest BLOB NOT NULL CHECK(length(intent_digest)=32),
    snapshot_sha256 TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL,
    consumed_at_unix INTEGER,
    rollout_id TEXT,
    PRIMARY KEY(tenant_id,group_id,confirmation_hash),
    FOREIGN KEY(tenant_id,group_id) REFERENCES managed_agent_groups(tenant_id,group_id) ON DELETE CASCADE
);";

/// The row for a confirmation, as stored.
pub(super) struct StoredConfirmation {
    pub admin_id: String,
    pub intent: Vec<u8>,
    pub snapshot_sha256: String,
    pub expires_at_unix: i64,
    pub consumed: bool,
    pub rollout_id: Option<String>,
}

/// Decides what a guarded start may do with a stored confirmation, before any fact is re-read.
pub(super) enum Disposition {
    Proceed,
    Replay(String),
}

pub(super) fn classify(
    stored: Option<StoredConfirmation>,
    admin_id: &str,
    intent: &[u8],
    now: i64,
) -> std::result::Result<(Disposition, Option<String>), ConfirmationRefused> {
    let Some(stored) = stored else {
        return Err(ConfirmationRefused(ConfirmationFailure::Invalid));
    };
    if stored.admin_id != admin_id || stored.intent != intent {
        return Err(ConfirmationRefused(ConfirmationFailure::Invalid));
    }
    if stored.consumed {
        return match stored.rollout_id {
            Some(rollout) => Ok((Disposition::Replay(rollout), None)),
            None => Err(ConfirmationRefused(ConfirmationFailure::Invalid)),
        };
    }
    if now >= stored.expires_at_unix {
        return Err(ConfirmationRefused(ConfirmationFailure::Expired));
    }
    Ok((Disposition::Proceed, Some(stored.snapshot_sha256)))
}

pub(super) fn ensure_preview_input(
    tenant: &str,
    group: &str,
    revision: &str,
    admin_id: &str,
) -> Result<()> {
    ensure!(
        exact_id(tenant) && exact_id(group) && exact_id(revision) && exact_id(admin_id),
        "invalid identifier"
    );
    Ok(())
}

impl TenantStore {
    /// Read-only with respect to deployments, membership, revisions and rollout state. The only row
    /// it writes is the bounded, expiring confirmation (one outstanding per administrator and group).
    pub fn preview_managed_group_start(
        &self,
        tenant: &str,
        group: &str,
        revision: &str,
        admin_id: &str,
        requested_issuer: Option<&str>,
    ) -> Result<GroupStartPreview> {
        ensure_preview_input(tenant, group, revision, admin_id)?;
        let mut db = self.connection()?;
        group_schema(&db)?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        eligible_group(&tx, tenant, group)?;
        current_admin_may_mutate(&tx, admin_id)?;
        let facts = gather(&tx, tenant, group, revision)?;
        let preview = assemble(
            &facts,
            tenant,
            group,
            revision,
            requested_issuer,
            resolved_signer(requested_issuer),
        );
        let confirmation = if preview.startable {
            let now = now_unix();
            // One outstanding confirmation per administrator and group; old rows are pruned.
            tx.execute(
                "DELETE FROM managed_group_start_confirmations
                 WHERE tenant_id=?1 AND group_id=?2 AND admin_id=?3 AND consumed_at_unix IS NULL",
                params![tenant, group, admin_id],
            )?;
            tx.execute(
                "DELETE FROM managed_group_start_confirmations
                 WHERE tenant_id=?1 AND group_id=?2 AND consumed_at_unix IS NULL AND expires_at_unix < ?3",
                params![tenant, group, now - 86_400],
            )?;
            let id = new_confirmation_id();
            let expires = now + CONFIRMATION_TTL_SECS;
            tx.execute(
                "INSERT INTO managed_group_start_confirmations
                 (tenant_id,group_id,confirmation_hash,admin_id,intent_digest,snapshot_sha256,created_at_unix,expires_at_unix)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    tenant,
                    group,
                    id_hash(&id),
                    admin_id,
                    intent_digest(tenant, group, admin_id, revision, requested_issuer),
                    preview.snapshot_sha256,
                    now,
                    expires
                ],
            )?;
            Some(StartConfirmation {
                version: CONFIRMATION_VERSION,
                id,
                expires_at_unix: expires,
            })
        } else {
            None
        };
        tx.commit()?;
        Ok(GroupStartPreview {
            preview,
            confirmation,
        })
    }

    /// Revalidates the confirmation inside the issuing transaction and starts only on an exact match.
    /// Every refusal leaves zero new deployments and does not consume the confirmation.
    pub fn start_managed_group_rollout_guarded(
        &self,
        tenant: &str,
        group: &str,
        revision: &str,
        issuer: Option<&ManagedIssuer>,
        guard: &StartGuard<'_>,
    ) -> Result<GuardedStart> {
        ensure_preview_input(tenant, group, revision, guard.admin_id)?;
        ensure!(
            valid_confirmation_id(guard.confirmation_id),
            ConfirmationRefused(ConfirmationFailure::Invalid)
        );
        let mut db = self.connection()?;
        group_schema(&db)?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        eligible_group(&tx, tenant, group)?;
        current_admin_may_mutate(&tx, guard.admin_id)?;
        let hash = id_hash(guard.confirmation_id);
        let stored: Option<StoredConfirmation> = tx
            .query_row(
                "SELECT admin_id,intent_digest,snapshot_sha256,expires_at_unix,consumed_at_unix IS NOT NULL,rollout_id
                 FROM managed_group_start_confirmations
                 WHERE tenant_id=?1 AND group_id=?2 AND confirmation_hash=?3",
                params![tenant, group, hash],
                |r| {
                    Ok(StoredConfirmation {
                        admin_id: r.get(0)?,
                        intent: r.get(1)?,
                        snapshot_sha256: r.get(2)?,
                        expires_at_unix: r.get(3)?,
                        consumed: r.get(4)?,
                        rollout_id: r.get(5)?,
                    })
                },
            )
            .optional()?;
        let intent = intent_digest(
            tenant,
            group,
            guard.admin_id,
            revision,
            guard.requested_issuer_key,
        );
        let (disposition, expected) = classify(stored, guard.admin_id, &intent, now_unix())?;
        if let Disposition::Replay(rollout_id) = disposition {
            let current = self
                .get_managed_group_rollout_conn(&tx, tenant, group)?
                .filter(|r| r.rollout_id == rollout_id)
                .ok_or(ConfirmationRefused(ConfirmationFailure::Invalid))?;
            tx.commit()?;
            return Ok(GuardedStart {
                rollout: current,
                replayed: true,
            });
        }
        let facts = gather(&tx, tenant, group, revision)?;
        let now_preview = assemble(
            &facts,
            tenant,
            group,
            revision,
            guard.requested_issuer_key,
            issuer.map(signer_identity),
        );
        ensure!(
            now_preview.startable && Some(&now_preview.snapshot_sha256) == expected.as_ref(),
            ConfirmationRefused(ConfirmationFailure::Stale)
        );
        let issuer = issuer.context("Agent policy issuer unavailable")?;
        self.start_managed_group_rollout_conn(&tx, tenant, group, revision, issuer)?;
        let rollout = self
            .get_managed_group_rollout_conn(&tx, tenant, group)?
            .context("rollout disappeared during transaction")?;
        let consumed = tx.execute(
            "UPDATE managed_group_start_confirmations SET consumed_at_unix=?4, rollout_id=?5
             WHERE tenant_id=?1 AND group_id=?2 AND confirmation_hash=?3 AND consumed_at_unix IS NULL",
            params![tenant, group, hash, now_unix(), rollout.rollout_id],
        )?;
        ensure!(
            consumed == 1,
            ConfirmationRefused(ConfirmationFailure::Invalid)
        );
        self.audit_committed(
            &tx,
            tenant,
            AuditFact::rollout(AuditOperation::RolloutStart, &rollout),
        )?;
        tx.commit()?;
        Ok(GuardedStart {
            rollout,
            replayed: false,
        })
    }
}

/// Reads every fact `assemble` needs from one SQLite connection (one transaction).
fn gather(
    db: &rusqlite::Connection,
    tenant: &str,
    group: &str,
    revision: &str,
) -> Result<CohortFacts> {
    let mut facts = CohortFacts {
        revision: db
            .query_row(
                "SELECT policy_sha256, approved_at_unix IS NOT NULL FROM managed_group_revisions
                 WHERE tenant_id=?1 AND group_id=?2 AND revision=?3",
                params![tenant, group, revision],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?,
        latest_rollout: db
            .query_row(
                "SELECT rollout_id,phase,revision,policy_sha256 FROM managed_group_rollouts
                 WHERE tenant_id=?1 AND group_id=?2 ORDER BY rowid DESC LIMIT 1",
                params![tenant, group],
                |r| {
                    Ok(LatestRollout {
                        rollout_id: r.get(0)?,
                        phase: r.get(1)?,
                        revision: r.get(2)?,
                        policy_sha256: r.get(3)?,
                    })
                },
            )
            .optional()?,
        ..Default::default()
    };
    let mut stmt = db.prepare(
        "SELECT agent_id, is_pilot FROM managed_agent_group_members
         WHERE tenant_id=?1 AND group_id=?2 ORDER BY agent_id LIMIT ?3",
    )?;
    facts.members = stmt
        .query_map(params![tenant, group, MAX_PREVIEW_AGENTS as i64 + 1], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? == 1))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut stmt = db.prepare(
        "SELECT group_id,rollout_id,phase,pilot_agents_json,standard_agents_json FROM managed_group_rollouts
         WHERE tenant_id=?1 AND group_id<>?2 AND phase IN ('pilot','standard','paused','rolling_back')",
    )?;
    let others = stmt
        .query_map(params![tenant, group], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (other_group, rollout, phase, pilots, standards) in others {
        let mut agents: Vec<String> = serde_json::from_str(&pilots).unwrap_or_default();
        agents.extend(serde_json::from_str::<Vec<String>>(&standards).unwrap_or_default());
        facts
            .other_active
            .push((other_group, rollout, phase, agents));
    }
    let wanted = facts.revision.as_ref().map(|(sha, _)| sha.clone());
    for (agent, _) in facts.members.iter().take(MAX_PREVIEW_AGENTS) {
        let authorized = eligible(db, tenant, agent).is_ok();
        let latest = db
            .query_row(
                "SELECT deployment_sequence,revision,status FROM managed_agent_deployments
                 WHERE tenant_id=?1 AND agent_id=?2 ORDER BY deployment_sequence DESC LIMIT 1",
                params![tenant, agent],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let baseline = db
            .query_row(
                "SELECT revision FROM managed_agent_deployments
                 WHERE tenant_id=?1 AND agent_id=?2 AND status='applied' ORDER BY deployment_sequence DESC LIMIT 1",
                params![tenant, agent],
                |r| r.get(0),
            )
            .optional()?;
        let existing: Option<(String, Option<i64>)> = db
            .query_row(
                "SELECT policy_sha256, approved_at_unix FROM managed_agent_revisions
                 WHERE tenant_id=?1 AND agent_id=?2 AND revision=?3",
                params![tenant, agent, revision],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (revision_conflict, revision_unapproved) = match (&existing, &wanted) {
            (Some((sha, _)), Some(wanted)) if sha != wanted => (true, false),
            (Some((_, approved)), _) => (false, approved.is_none()),
            _ => (false, false),
        };
        facts.agents.insert(
            agent.clone(),
            AgentFacts {
                authorized,
                latest,
                baseline,
                revision_conflict,
                revision_unapproved,
            },
        );
    }
    Ok(facts)
}

/// Mirrors the request-time Owner requirement inside the issuing transaction.
fn current_admin_may_mutate(db: &rusqlite::Connection, admin_id: &str) -> Result<()> {
    if admin_id == BOOTSTRAP_ADMIN {
        return Ok(());
    }
    let role: Option<String> = db
        .query_row(
            "SELECT role FROM control_plane_admins WHERE id=?1 AND active=1",
            params![admin_id],
            |r| r.get(0),
        )
        .optional()?;
    let role = role.context("administrator is no longer active")?;
    ensure!(
        AdminRole::from_storage(&role)?.permits(AdminRole::Owner),
        "administrator role does not permit rollout changes"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(members: &[(&str, bool)]) -> CohortFacts {
        let mut facts = CohortFacts {
            revision: Some(("a".repeat(64), true)),
            members: members.iter().map(|(a, p)| (a.to_string(), *p)).collect(),
            ..Default::default()
        };
        for (agent, _) in members {
            facts.agents.insert(
                agent.to_string(),
                AgentFacts {
                    authorized: true,
                    latest: Some((1, "base".into(), "applied".into())),
                    baseline: Some("base".into()),
                    ..Default::default()
                },
            );
        }
        facts
    }

    fn test_signer() -> Option<ResolvedSigner> {
        Some(ResolvedSigner {
            issuer_key_id: "test-key".into(),
            public_key_sha256: "ab".repeat(32),
        })
    }

    #[test]
    fn snapshot_ignores_member_order_but_not_any_fact() {
        let a = assemble(
            &facts(&[("p", true), ("w1", false), ("w2", false)]),
            "t",
            "g",
            "r",
            None,
            test_signer(),
        );
        let b = assemble(
            &facts(&[("w2", false), ("p", true), ("w1", false)]),
            "t",
            "g",
            "r",
            None,
            test_signer(),
        );
        assert!(a.startable);
        assert_eq!(a.snapshot_sha256, b.snapshot_sha256);
        let mut changed = facts(&[("p", true), ("w1", false), ("w2", false)]);
        changed.agents.get_mut("w1").unwrap().baseline = Some("other".into());
        assert_ne!(
            assemble(&changed, "t", "g", "r", None, test_signer()).snapshot_sha256,
            a.snapshot_sha256
        );
        let mut sequence = facts(&[("p", true), ("w1", false), ("w2", false)]);
        sequence.agents.get_mut("w2").unwrap().latest = Some((2, "base".into(), "applied".into()));
        assert_ne!(
            assemble(&sequence, "t", "g", "r", None, test_signer()).snapshot_sha256,
            a.snapshot_sha256
        );
        assert_ne!(
            assemble(
                &facts(&[("p", true), ("w1", false), ("w2", false)]),
                "t",
                "g",
                "r",
                Some("k"),
                test_signer()
            )
            .snapshot_sha256,
            a.snapshot_sha256,
            "the requested signer is part of the scope"
        );
        assert_ne!(
            assemble(
                &facts(&[("p", true), ("w1", true), ("w2", false)]),
                "t",
                "g",
                "r",
                None,
                test_signer()
            )
            .snapshot_sha256,
            a.snapshot_sha256
        );
    }

    #[test]
    fn snapshot_binds_resolved_key_id_and_public_key_material() {
        let facts = facts(&[("p", true)]);
        let old = test_signer().unwrap();
        let baseline = assemble(&facts, "t", "g", "r", None, Some(old.clone()));
        for changed in [
            ResolvedSigner {
                issuer_key_id: "rotated".into(),
                ..old.clone()
            },
            ResolvedSigner {
                public_key_sha256: "cd".repeat(32),
                ..old.clone()
            },
        ] {
            let new = assemble(&facts, "t", "g", "r", None, Some(changed.clone()));
            assert_eq!(new.issuer_key_id, baseline.issuer_key_id);
            assert_eq!(new.signer_available, baseline.signer_available);
            assert_ne!(new.snapshot_sha256, baseline.snapshot_sha256);
            assert_eq!(new.resolved_signer, Some(changed));
        }
        assert!(!assemble(&facts, "t", "g", "r", None, None).startable);
    }

    #[test]
    fn every_blocker_withholds_the_start() {
        let base = facts(&[("p", true), ("w", false)]);
        let codes = |facts: &CohortFacts, signer: bool| -> Vec<&'static str> {
            let preview = assemble(
                facts,
                "t",
                "g",
                "r",
                None,
                signer.then(test_signer).flatten(),
            );
            assert_eq!(preview.startable, preview.blockers.is_empty());
            preview.blockers.iter().map(|b| b.code).collect()
        };
        assert!(codes(&base, true).is_empty());
        assert_eq!(codes(&base, false), ["signer_unavailable"]);
        let mut f = base.clone();
        f.revision = None;
        assert_eq!(codes(&f, true), ["revision_not_approved"]);
        let mut f = base.clone();
        f.members = vec![("w".into(), false)];
        assert_eq!(codes(&f, true), ["no_pilots"]);
        let mut f = base.clone();
        f.members.clear();
        assert_eq!(codes(&f, true), ["empty_group"]);
        let mut f = base.clone();
        f.agents.get_mut("w").unwrap().authorized = false;
        assert_eq!(codes(&f, true), ["agent_not_authorized"]);
        let mut f = base.clone();
        f.agents.get_mut("p").unwrap().latest = Some((3, "r".into(), "delivered".into()));
        assert_eq!(codes(&f, true), ["unacknowledged_deployment"]);
        let mut f = base.clone();
        f.agents.get_mut("p").unwrap().revision_conflict = true;
        f.agents.get_mut("w").unwrap().revision_unapproved = true;
        assert_eq!(
            codes(&f, true),
            ["revision_collision", "agent_revision_not_approved"]
        );
        let mut f = base.clone();
        f.other_active = vec![(
            "other".into(),
            "ro_1".into(),
            "pilot".into(),
            vec!["w".into(), "zzz".into()],
        )];
        assert_eq!(codes(&f, true), ["agent_in_active_rollout"]);
        let mut f = base.clone();
        f.latest_rollout = Some(LatestRollout {
            rollout_id: "ro".into(),
            phase: "paused".into(),
            revision: "r".into(),
            policy_sha256: "a".repeat(64),
        });
        assert_eq!(codes(&f, true), ["active_rollout"]);
        f.latest_rollout.as_mut().unwrap().phase = "completed".into();
        assert_eq!(codes(&f, true), ["already_rolled_out"]);
        f.latest_rollout.as_mut().unwrap().revision = "older".into();
        assert!(
            codes(&f, true).is_empty(),
            "a completed rollout of another revision does not block"
        );
    }

    #[test]
    fn the_preview_is_bounded() {
        let members: Vec<(String, bool)> = (0..=MAX_PREVIEW_AGENTS)
            .map(|n| (format!("a{n:04}"), n == 0))
            .collect();
        let refs: Vec<(&str, bool)> = members.iter().map(|(a, p)| (a.as_str(), *p)).collect();
        let preview = assemble(&facts(&refs), "t", "g", "r", None, test_signer());
        assert!(!preview.startable);
        assert!(preview
            .blockers
            .iter()
            .any(|b| b.code == "cohort_too_large"));
    }

    #[test]
    fn identities_have_one_shape_and_are_domain_separated() {
        let id = new_confirmation_id();
        assert!(valid_confirmation_id(&id));
        assert!(!valid_confirmation_id(&id[..id.len() - 1]));
        assert!(!valid_confirmation_id(&id.replace("swc1_", "swc2_")));
        assert!(!valid_confirmation_id(&format!("{}!", &id[..id.len() - 1])));
        assert_ne!(id_hash(&id), Sha256::digest(id.as_bytes()).to_vec());
        let one = intent_digest("t", "g", "a", "r", None);
        assert_ne!(one, intent_digest("t", "g", "b", "r", None));
        assert_ne!(one, intent_digest("t", "h", "a", "r", None));
        assert_ne!(one, intent_digest("u", "g", "a", "r", None));
        assert_ne!(one, intent_digest("t", "g", "a", "s", None));
        assert_ne!(one, intent_digest("t", "g", "a", "r", Some("k")));
        // Field boundaries are length-prefixed: shifting a byte between fields changes the digest.
        assert_ne!(
            intent_digest("ab", "c", "a", "r", None),
            intent_digest("a", "bc", "a", "r", None)
        );
    }
}
