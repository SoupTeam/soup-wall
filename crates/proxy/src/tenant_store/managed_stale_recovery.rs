// SPDX-License-Identifier: Apache-2.0
//! SOU-242: owner-confirmed recovery of a stale restored Console for one
//! unchanged enrolled Agent (`sw-console-stale-restore-recovery/1`).
//!
//! After a restore, a running Agent may already apply a deployment newer than
//! the restored database. That Agent keeps its durable active policy and
//! refuses lower or equal sequences, so the restored Console cannot reach it.
//! This procedure lets an Owner present the Agent's retained signed bundle
//! (its `managed-policy-active.json`) as evidence. The Console accepts it only
//! when all of these hold at once:
//!
//! - the enrollment exists, is not revoked and has the credential generation
//!   the Agent itself reports in a fresh authenticated heartbeat;
//! - the evidence is signed by this Console's current issuer key, and the
//!   newest restored deployment verifies with that same key (no issuer change);
//! - tenant, Agent, sequence, revision and digest are exact, and the sequence
//!   is above everything the restored database has issued or fenced;
//! - the Agent's fresh self-report names exactly that sequence, revision and
//!   digest.
//!
//! A preview grants nothing. The confirmation must repeat the exact phrase
//! and the state binding of the preview; both are re-derived inside the same
//! write transaction, so any deployment, revision, enrollment, issuer or fence
//! change in between refuses it. A confirmed fence is persisted before any new
//! signing: the next issuance for that Agent uses a sequence above the fence,
//! through the normal deployment path. The deployments between the restored
//! sequence and the fence are recorded as an unrecoverable history interval.
//! Recovery is complete only when a deployment above the fence, issued after
//! the confirmation, has an authenticated `applied` acknowledgement.
//!
//! The pure rules live here once; each backend only gathers the facts.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::agent_heartbeat::{self, Row as HeartbeatRow};
use super::managed_policy::{hex, ManagedIssuer, SignedManagedBundle};

pub const CONTRACT: &str = "sw-console-stale-restore-recovery/1";
/// PostgreSQL migration that adds `managed_agent_recovery_fences`.
pub const SCHEMA_VERSION: i64 = 33;
/// The evidence is one bundle: at most the 64 KiB policy plus bounded fields.
pub const MAX_BODY_BYTES: usize = 160 * 1024;
const BINDING_DOMAIN: &[u8] = b"soup-wall-stale-restore-recovery-binding-v1\0";

pub const RESTRICTIONS: [&str; 5] = [
    "Only this tenant, enrollment credential generation and current issuer key are covered.",
    "Deployments between the restored sequence and the fence are unrecoverable history: they are not reconstructed.",
    "The Agent keeps its active policy and counters; nothing is reset, rewound or acknowledged for it.",
    "Recovery completes only after a new signed deployment above the fence is applied and acknowledged by the Agent.",
    "A changed issuer, rotated or revoked credential, or other trust-epoch change needs a separate reviewed procedure.",
];

/// Body of a preview: the retained signed bundle exactly as the Agent stores it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewRequest {
    pub evidence: SignedManagedBundle,
}

/// Body of a confirmation: the same evidence plus what the preview returned.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmRequest {
    pub evidence: SignedManagedBundle,
    pub state_binding: String,
    pub confirmation: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    NotEnrolled,
    Revoked,
    EvidenceMalformed,
    EvidenceWrongAudience,
    EvidenceDigestMismatch,
    IssuerChanged,
    EvidenceSignatureInvalid,
    NoRestoredDeployment,
    EvidenceNotAhead,
    ObservationUnavailable,
    ObservationNotFresh,
    CredentialChanged,
    ObservationMismatch,
    StateChanged,
    ConfirmationMismatch,
    OwnerNotActive,
}
impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::NotEnrolled => "not_enrolled",
            Self::Revoked => "revoked",
            Self::EvidenceMalformed => "evidence_malformed",
            Self::EvidenceWrongAudience => "evidence_wrong_audience",
            Self::EvidenceDigestMismatch => "evidence_digest_mismatch",
            Self::IssuerChanged => "issuer_changed",
            Self::EvidenceSignatureInvalid => "evidence_signature_invalid",
            Self::NoRestoredDeployment => "no_restored_deployment",
            Self::EvidenceNotAhead => "evidence_not_ahead",
            Self::ObservationUnavailable => "observation_unavailable",
            Self::ObservationNotFresh => "observation_not_fresh",
            Self::CredentialChanged => "credential_changed",
            Self::ObservationMismatch => "observation_mismatch",
            Self::StateChanged => "state_changed",
            Self::ConfirmationMismatch => "confirmation_mismatch",
            Self::OwnerNotActive => "owner_not_active",
        }
    }
    pub fn http_status(self) -> u16 {
        match self {
            Self::NotEnrolled => 404,
            Self::OwnerNotActive => 403,
            Self::EvidenceMalformed | Self::ConfirmationMismatch => 400,
            _ => 409,
        }
    }
    pub fn message(self) -> &'static str {
        match self {
            Self::NotEnrolled => "Agent is not enrolled in this tenant.",
            Self::Revoked => "Agent credential is revoked; recovery stays closed.",
            Self::EvidenceMalformed => "Evidence is not a bounded signed Agent policy bundle.",
            Self::EvidenceWrongAudience => "Evidence names a different tenant or Agent.",
            Self::EvidenceDigestMismatch => "Evidence policy does not match its signed digest.",
            Self::IssuerChanged => "Evidence or the restored deployments are not signed by this Console's current issuer key.",
            Self::EvidenceSignatureInvalid => "Evidence signature does not verify with the current issuer key.",
            Self::NoRestoredDeployment => "The restored database has no deployment for this Agent to bind.",
            Self::EvidenceNotAhead => "Evidence is not newer than the restored or already fenced sequence.",
            Self::ObservationUnavailable => "No authenticated Agent heartbeat is available; enable it and wait for a report.",
            Self::ObservationNotFresh => "The Agent's last authenticated report is not fresh.",
            Self::CredentialChanged => "The Agent's report uses a different credential generation.",
            Self::ObservationMismatch => "The Agent's fresh report does not name the evidence sequence, revision and digest.",
            Self::StateChanged => "The restored state changed after the preview; preview again.",
            Self::ConfirmationMismatch => "The confirmation does not repeat the exact preview phrase and binding.",
            Self::OwnerNotActive => "The confirming administrator is no longer an active Owner.",
        }
    }
}

/// Facts a backend gathers inside one transaction.
#[derive(Clone, Debug)]
pub(super) struct Facts {
    pub enrolled: bool,
    pub revoked: bool,
    pub generation: i64,
    /// SHA-256 of the stored credential hash (never the credential).
    pub credential_digest: String,
    pub latest: Option<LatestDeployment>,
    /// Highest restored deployment the Agent did not reject (0 when none):
    /// a later row this Agent rejected is a refused conflict, not history.
    pub restored_floor: i64,
    pub fence_high: i64,
    /// Digest over the Agent's revision rows (revision, digest, approval).
    pub revisions_digest: String,
    pub heartbeat_available: bool,
    pub heartbeat: Option<HeartbeatRow>,
    pub now: i64,
}
#[derive(Clone, Debug)]
pub(super) struct LatestDeployment {
    pub sequence: i64,
    pub revision: String,
    pub policy_sha256: String,
    pub status: String,
    pub bundle_json: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EvidenceView {
    pub deployment_sequence: i64,
    pub revision: String,
    pub policy_sha256: String,
    pub issuer_key_id: String,
    pub issued_at_unix: i64,
    pub bundle_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Interval {
    pub from_sequence: i64,
    pub to_sequence: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Preview {
    pub contract_version: String,
    pub tenant_id: String,
    pub agent_id: String,
    /// Highest restored sequence the Agent did not reject, or an earlier fence.
    pub restored_sequence: i64,
    /// Newest restored deployment row and its recorded state.
    pub latest_restored_sequence: i64,
    pub restored_status: String,
    pub evidence: EvidenceView,
    pub observed_at_unix: i64,
    pub observation_age_seconds: i64,
    pub credential_generation: i64,
    pub issuer_public_key_sha256: String,
    /// Deployments whose history the restored database does not hold.
    pub unrecoverable_interval: Option<Interval>,
    pub next_sequence: i64,
    pub state_binding: String,
    pub confirmation: String,
    pub restrictions: Vec<String>,
}

pub(super) struct Verified {
    pub preview: Preview,
    pub restored_high: i64,
}

fn sha(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}
fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
fn field(buffer: &mut Vec<u8>, value: &str) {
    buffer.extend_from_slice(&(value.len() as u64).to_be_bytes());
    buffer.extend_from_slice(value.as_bytes());
}

/// The exact phrase an Owner types to confirm.
pub fn confirmation_phrase(agent: &str, from: i64, to: i64, binding: &str) -> String {
    format!("recover {agent} from {from} to {to} {}", &binding[..12])
}

pub(super) fn evaluate(
    tenant: &str,
    agent: &str,
    facts: &Facts,
    evidence: &SignedManagedBundle,
    issuer: &ManagedIssuer,
) -> Result<Verified, Refusal> {
    if !facts.enrolled {
        return Err(Refusal::NotEnrolled);
    }
    if facts.revoked {
        return Err(Refusal::Revoked);
    }
    if evidence.schema_version != 1
        || evidence.revision.is_empty()
        || evidence.revision.len() > 128
        || evidence.issuer_key_id.is_empty()
        || evidence.issuer_key_id.len() > 128
        || evidence.policy_yaml.is_empty()
        || evidence.policy_yaml.len() > super::managed_policy::MAX_YAML
        || !is_hex64(&evidence.policy_sha256)
        || evidence.signature_hex.len() != 128
        || evidence.deployment_sequence == 0
        || evidence.deployment_sequence > (1_u64 << 53)
    {
        return Err(Refusal::EvidenceMalformed);
    }
    if evidence.tenant_id != tenant || evidence.agent_id != agent {
        return Err(Refusal::EvidenceWrongAudience);
    }
    if sha(evidence.policy_yaml.as_bytes()) != evidence.policy_sha256 {
        return Err(Refusal::EvidenceDigestMismatch);
    }
    if evidence.issuer_key_id != issuer.key_id() {
        return Err(Refusal::IssuerChanged);
    }
    if !issuer.verifies(evidence) {
        return Err(Refusal::EvidenceSignatureInvalid);
    }
    let latest = facts.latest.as_ref().ok_or(Refusal::NoRestoredDeployment)?;
    let restored: SignedManagedBundle =
        serde_json::from_str(&latest.bundle_json).map_err(|_| Refusal::IssuerChanged)?;
    if restored.issuer_key_id != issuer.key_id() || !issuer.verifies(&restored) {
        return Err(Refusal::IssuerChanged);
    }
    // Everything the restored Console issued that the Agent did not refuse,
    // and every earlier fence, must be below the evidence. Restored rows at
    // or above it are allowed only when this Agent rejected them.
    let restored_high = facts.restored_floor.max(facts.fence_high);
    let evidence_sequence = evidence.deployment_sequence as i64;
    if evidence_sequence <= restored_high {
        return Err(Refusal::EvidenceNotAhead);
    }
    if !facts.heartbeat_available {
        return Err(Refusal::ObservationUnavailable);
    }
    let report = facts
        .heartbeat
        .as_ref()
        .ok_or(Refusal::ObservationUnavailable)?;
    if report.generation != facts.generation {
        return Err(Refusal::CredentialChanged);
    }
    let received = report.received_at.ok_or(Refusal::ObservationUnavailable)?;
    let age = facts.now.saturating_sub(received).max(0);
    if age > agent_heartbeat::EXPIRES_AFTER_SECONDS {
        return Err(Refusal::ObservationNotFresh);
    }
    let observed = report.policy.as_ref().ok_or(Refusal::ObservationMismatch)?;
    if observed.deployment_sequence != evidence_sequence
        || observed.revision != evidence.revision
        || observed.policy_sha256 != evidence.policy_sha256
    {
        return Err(Refusal::ObservationMismatch);
    }
    let bundle_sha256 = sha(&serde_json::to_vec(evidence).map_err(|_| Refusal::EvidenceMalformed)?);
    let issuer_pk = issuer.public_key_sha256();
    let mut b = BINDING_DOMAIN.to_vec();
    for v in [
        tenant,
        agent,
        &facts.generation.to_string(),
        &facts.credential_digest,
        &latest.sequence.to_string(),
        &latest.revision,
        &latest.policy_sha256,
        &latest.status,
        &sha(latest.bundle_json.as_bytes()),
        &facts.fence_high.to_string(),
        &facts.restored_floor.to_string(),
        &facts.revisions_digest,
        issuer.key_id(),
        &issuer_pk,
        &bundle_sha256,
    ] {
        field(&mut b, v);
    }
    let binding = sha(&b);
    let interval = (evidence_sequence > restored_high + 1).then(|| Interval {
        from_sequence: restored_high + 1,
        to_sequence: evidence_sequence - 1,
    });
    Ok(Verified {
        restored_high,
        preview: Preview {
            contract_version: CONTRACT.into(),
            tenant_id: tenant.into(),
            agent_id: agent.into(),
            restored_sequence: restored_high,
            latest_restored_sequence: latest.sequence,
            restored_status: latest.status.clone(),
            evidence: EvidenceView {
                deployment_sequence: evidence_sequence,
                revision: evidence.revision.clone(),
                policy_sha256: evidence.policy_sha256.clone(),
                issuer_key_id: evidence.issuer_key_id.clone(),
                issued_at_unix: evidence.issued_at_unix,
                bundle_sha256,
            },
            observed_at_unix: received,
            observation_age_seconds: age,
            credential_generation: facts.generation,
            issuer_public_key_sha256: issuer_pk,
            unrecoverable_interval: interval,
            next_sequence: evidence_sequence.max(latest.sequence) + 1,
            confirmation: confirmation_phrase(agent, restored_high, evidence_sequence, &binding),
            state_binding: binding,
            restrictions: RESTRICTIONS.iter().map(|s| (*s).into()).collect(),
        },
    })
}

/// A confirmation must repeat the preview exactly against re-derived facts.
pub(super) fn check_confirmation(
    verified: &Verified,
    binding: &str,
    phrase: &str,
) -> Result<(), Refusal> {
    if !is_hex64(binding) {
        return Err(Refusal::ConfirmationMismatch);
    }
    if verified.preview.state_binding != binding {
        return Err(Refusal::StateChanged);
    }
    if verified.preview.confirmation != phrase {
        return Err(Refusal::ConfirmationMismatch);
    }
    Ok(())
}

/// A persisted fence and its derived state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Fence {
    pub fence_sequence: i64,
    pub restored_sequence: i64,
    pub evidence_revision: String,
    pub evidence_policy_sha256: String,
    pub evidence_bundle_sha256: String,
    pub issuer_key_id: String,
    pub credential_generation: i64,
    pub unrecoverable_interval: Option<Interval>,
    pub observed_at_unix: i64,
    pub confirmed_by: String,
    pub confirmed_at_unix: i64,
    /// `fenced` until a deployment above the fence is applied, then `complete`.
    pub state: String,
    pub completion: Option<Completion>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Completion {
    pub deployment_sequence: i64,
    pub revision: String,
    pub policy_sha256: String,
    pub applied_at_unix: Option<i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Confirmed {
    pub contract_version: String,
    /// True when this exact evidence was already confirmed (idempotent retry).
    pub replayed: bool,
    pub fence: Fence,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Status {
    pub contract_version: String,
    pub tenant_id: String,
    pub agent_id: String,
    /// `none`, `fenced` (waiting for a new applied deployment) or `complete`.
    pub state: String,
    pub restored_sequence: i64,
    pub fences: Vec<Fence>,
    pub restrictions: Vec<String>,
}

pub(super) fn status(tenant: &str, agent: &str, restored: i64, fences: Vec<Fence>) -> Status {
    let state = fences
        .first()
        .map(|f| f.state.clone())
        .unwrap_or_else(|| "none".into());
    Status {
        contract_version: CONTRACT.into(),
        tenant_id: tenant.into(),
        agent_id: agent.into(),
        state,
        restored_sequence: restored,
        fences,
        restrictions: RESTRICTIONS.iter().map(|s| (*s).into()).collect(),
    }
}

/// Columns of a fence row, in `fence_from_parts` order.
pub(super) const FENCE_COLUMNS: &str = "fence_sequence,restored_sequence,evidence_revision,evidence_policy_sha256,evidence_bundle_sha256,issuer_key_id,credential_generation,unrecoverable_from,unrecoverable_to,observed_at_unix,confirmed_by,confirmed_at_unix";
/// The first applied deployment above a fence, issued after its confirmation.
pub(super) const COMPLETION_SQL: &str = "SELECT deployment_sequence,revision,policy_sha256,applied_at_unix FROM managed_agent_deployments WHERE tenant_id=?1 AND agent_id=?2 AND deployment_sequence>?3 AND issued_at_unix>=?4 AND status='applied' ORDER BY deployment_sequence LIMIT 1";

#[allow(clippy::too_many_arguments)]
pub(super) fn fence_from_parts(
    fence_sequence: i64,
    restored_sequence: i64,
    evidence_revision: String,
    evidence_policy_sha256: String,
    evidence_bundle_sha256: String,
    issuer_key_id: String,
    credential_generation: i64,
    interval: (Option<i64>, Option<i64>),
    observed_at_unix: i64,
    confirmed_by: String,
    confirmed_at_unix: i64,
    completion: Option<Completion>,
) -> Fence {
    Fence {
        fence_sequence,
        restored_sequence,
        evidence_revision,
        evidence_policy_sha256,
        evidence_bundle_sha256,
        issuer_key_id,
        credential_generation,
        unrecoverable_interval: match interval {
            (Some(from_sequence), Some(to_sequence)) => Some(Interval {
                from_sequence,
                to_sequence,
            }),
            _ => None,
        },
        observed_at_unix,
        confirmed_by,
        confirmed_at_unix,
        state: if completion.is_some() {
            "complete".into()
        } else {
            "fenced".into()
        },
        completion,
    }
}

pub(super) const SQLITE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS managed_agent_recovery_fences (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    fence_sequence INTEGER NOT NULL CHECK(fence_sequence > 0),
    restored_sequence INTEGER NOT NULL CHECK(restored_sequence >= 0 AND restored_sequence < fence_sequence),
    evidence_revision TEXT NOT NULL CHECK(length(evidence_revision) BETWEEN 1 AND 128),
    evidence_policy_sha256 TEXT NOT NULL CHECK(length(evidence_policy_sha256) = 64),
    evidence_bundle_sha256 TEXT NOT NULL CHECK(length(evidence_bundle_sha256) = 64),
    issuer_key_id TEXT NOT NULL CHECK(length(issuer_key_id) BETWEEN 1 AND 128),
    issuer_public_key_sha256 TEXT NOT NULL CHECK(length(issuer_public_key_sha256) = 64),
    credential_generation INTEGER NOT NULL CHECK(credential_generation > 0),
    state_binding TEXT NOT NULL CHECK(length(state_binding) = 64),
    unrecoverable_from INTEGER,
    unrecoverable_to INTEGER,
    observed_at_unix INTEGER NOT NULL,
    confirmed_by TEXT NOT NULL CHECK(length(confirmed_by) BETWEEN 1 AND 128),
    confirmed_at_unix INTEGER NOT NULL,
    PRIMARY KEY(tenant_id,agent_id,fence_sequence),
    UNIQUE(tenant_id,agent_id,evidence_bundle_sha256),
    CHECK((unrecoverable_from IS NULL) = (unrecoverable_to IS NULL)),
    CHECK(unrecoverable_from IS NULL OR (unrecoverable_from = restored_sequence + 1 AND unrecoverable_to = fence_sequence - 1 AND unrecoverable_from <= unrecoverable_to)),
    FOREIGN KEY(tenant_id,agent_id) REFERENCES managed_agent_enrollments(tenant_id,agent_id)
);";

pub(super) const POSTGRES_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS managed_agent_recovery_fences (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    fence_sequence BIGINT NOT NULL CHECK(fence_sequence > 0),
    restored_sequence BIGINT NOT NULL CHECK(restored_sequence >= 0 AND restored_sequence < fence_sequence),
    evidence_revision TEXT NOT NULL CHECK(length(evidence_revision) BETWEEN 1 AND 128),
    evidence_policy_sha256 TEXT NOT NULL CHECK(length(evidence_policy_sha256) = 64),
    evidence_bundle_sha256 TEXT NOT NULL CHECK(length(evidence_bundle_sha256) = 64),
    issuer_key_id TEXT NOT NULL CHECK(length(issuer_key_id) BETWEEN 1 AND 128),
    issuer_public_key_sha256 TEXT NOT NULL CHECK(length(issuer_public_key_sha256) = 64),
    credential_generation BIGINT NOT NULL CHECK(credential_generation > 0),
    state_binding TEXT NOT NULL CHECK(length(state_binding) = 64),
    unrecoverable_from BIGINT,
    unrecoverable_to BIGINT,
    observed_at_unix BIGINT NOT NULL,
    confirmed_by TEXT NOT NULL CHECK(length(confirmed_by) BETWEEN 1 AND 128),
    confirmed_at_unix BIGINT NOT NULL,
    PRIMARY KEY(tenant_id,agent_id,fence_sequence),
    UNIQUE(tenant_id,agent_id,evidence_bundle_sha256),
    CHECK((unrecoverable_from IS NULL) = (unrecoverable_to IS NULL)),
    CHECK(unrecoverable_from IS NULL OR (unrecoverable_from = restored_sequence + 1 AND unrecoverable_to = fence_sequence - 1 AND unrecoverable_from <= unrecoverable_to)),
    FOREIGN KEY(tenant_id,agent_id) REFERENCES managed_agent_enrollments(tenant_id,agent_id)
);";

/// Highest fenced sequence for one Agent, or 0 (both dialects; `?1`/`?2` or `$1`/`$2`).
pub(super) const SQLITE_FENCE_HIGH: &str = "SELECT COALESCE(MAX(fence_sequence),0) FROM managed_agent_recovery_fences WHERE tenant_id=?1 AND agent_id=?2";
pub(super) const SQLITE_RESTORED_FLOOR: &str = "SELECT COALESCE(MAX(deployment_sequence),0) FROM managed_agent_deployments WHERE tenant_id=?1 AND agent_id=?2 AND status<>'rejected'";
pub(super) const POSTGRES_RESTORED_FLOOR: &str = "SELECT COALESCE(MAX(deployment_sequence),0) FROM managed_agent_deployments WHERE tenant_id=$1 AND agent_id=$2 AND status<>'rejected'";
pub(super) const POSTGRES_FENCE_HIGH: &str = "SELECT COALESCE(MAX(fence_sequence),0) FROM managed_agent_recovery_fences WHERE tenant_id=$1 AND agent_id=$2";

/// Digest over revision rows, gathered as (revision, digest, approved_at).
pub(super) fn revisions_digest(rows: &[(String, String, Option<i64>)]) -> String {
    let mut b = Vec::new();
    for (revision, digest, approved) in rows {
        field(&mut b, revision);
        field(&mut b, digest);
        field(&mut b, &approved.map(|v| v.to_string()).unwrap_or_default());
    }
    sha(&b)
}
pub(super) fn credential_digest(token_hash: &[u8]) -> String {
    sha(token_hash)
}

/// The bootstrap Owner is the configured admin token itself, not a stored
/// row: its authority is the live process configuration that just
/// authenticated it. Every stored administrator is re-read inside the fence
/// transaction, so revocation or demotion after authentication refuses.
pub(super) const BOOTSTRAP_OWNER: &str = "bootstrap_owner";
pub(super) fn owner_role_active(role: Option<&str>) -> bool {
    role.and_then(|r| super::AdminRole::from_storage(r).ok())
        .is_some_and(|r| r.permits(super::AdminRole::Owner))
}

fn sqlite_owner_active(db: &rusqlite::Connection, admin_id: &str) -> Result<bool> {
    use rusqlite::{params, OptionalExtension};
    if admin_id == BOOTSTRAP_OWNER {
        return Ok(true);
    }
    let role: Option<String> = db
        .query_row(
            "SELECT role FROM control_plane_admins WHERE id=?1 AND active=1",
            params![admin_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(owner_role_active(role.as_deref()))
}

/// Outcome of a store call: a decision, or a typed refusal.
pub type Decision<T> = std::result::Result<T, Refusal>;

fn sqlite_facts(db: &rusqlite::Connection, tenant: &str, agent: &str) -> Result<Facts> {
    use rusqlite::{params, OptionalExtension};
    super::managed_policy::schema(db)?;
    db.execute_batch(agent_heartbeat::SQLITE_TABLE)?;
    let enrollment: Option<(Option<i64>, i64, Vec<u8>)> = db
        .query_row(
            "SELECT revoked_at_unix,credential_generation,token_hash FROM managed_agent_enrollments WHERE tenant_id=?1 AND agent_id=?2",
            params![tenant, agent],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let latest = db
        .query_row(
            "SELECT deployment_sequence,revision,policy_sha256,status,bundle_json FROM managed_agent_deployments WHERE tenant_id=?1 AND agent_id=?2 ORDER BY deployment_sequence DESC LIMIT 1",
            params![tenant, agent],
            |r| {
                Ok(LatestDeployment {
                    sequence: r.get(0)?,
                    revision: r.get(1)?,
                    policy_sha256: r.get(2)?,
                    status: r.get(3)?,
                    bundle_json: r.get(4)?,
                })
            },
        )
        .optional()?;
    let fence_high: i64 = db.query_row(SQLITE_FENCE_HIGH, params![tenant, agent], |r| r.get(0))?;
    let restored_floor: i64 =
        db.query_row(SQLITE_RESTORED_FLOOR, params![tenant, agent], |r| r.get(0))?;
    let mut stmt = db.prepare(
        "SELECT revision,policy_sha256,approved_at_unix FROM managed_agent_revisions WHERE tenant_id=?1 AND agent_id=?2 ORDER BY revision",
    )?;
    let revisions = stmt
        .query_map(params![tenant, agent], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let heartbeat = db
        .query_row(
            &format!(
                "SELECT {} FROM temp.agent_heartbeats WHERE tenant_id=?1 AND agent_id=?2",
                agent_heartbeat::ROW_COLUMNS
            ),
            params![tenant, agent],
            agent_heartbeat::sqlite_row,
        )
        .optional()?;
    let (enrolled, revoked, generation, credential) = match enrollment {
        Some((revoked, generation, hash)) => (
            true,
            revoked.is_some(),
            generation,
            credential_digest(&hash),
        ),
        None => (false, false, 0, String::new()),
    };
    Ok(Facts {
        enrolled,
        revoked,
        generation,
        credential_digest: credential,
        latest,
        restored_floor,
        fence_high,
        revisions_digest: revisions_digest(&revisions),
        heartbeat_available: true,
        heartbeat,
        now: super::now_unix(),
    })
}

fn sqlite_fences(db: &rusqlite::Connection, tenant: &str, agent: &str) -> Result<Vec<Fence>> {
    use rusqlite::{params, OptionalExtension};
    let mut stmt = db.prepare(&format!(
        "SELECT {FENCE_COLUMNS} FROM managed_agent_recovery_fences WHERE tenant_id=?1 AND agent_id=?2 ORDER BY fence_sequence DESC LIMIT 20"
    ))?;
    let rows = stmt
        .query_map(params![tenant, agent], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
                (r.get::<_, Option<i64>>(7)?, r.get::<_, Option<i64>>(8)?),
                r.get::<_, i64>(9)?,
                r.get::<_, String>(10)?,
                r.get::<_, i64>(11)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut out = Vec::new();
    for (seq, restored, revision, digest, bundle, key, generation, interval, observed, by, at) in
        rows
    {
        let completion = db
            .query_row(COMPLETION_SQL, params![tenant, agent, seq, at], |r| {
                Ok(Completion {
                    deployment_sequence: r.get(0)?,
                    revision: r.get(1)?,
                    policy_sha256: r.get(2)?,
                    applied_at_unix: r.get(3)?,
                })
            })
            .optional()?;
        out.push(fence_from_parts(
            seq, restored, revision, digest, bundle, key, generation, interval, observed, by, at,
            completion,
        ));
    }
    Ok(out)
}

impl super::TenantStore {
    /// Preview a stale-restore recovery; grants nothing and writes nothing.
    pub async fn stale_recovery_preview(
        &self,
        tenant: &str,
        agent: &str,
        evidence: SignedManagedBundle,
        issuer: ManagedIssuer,
    ) -> Result<Decision<Preview>> {
        anyhow::ensure!(
            agent_heartbeat::valid_ids(tenant, agent),
            "invalid identity"
        );
        if let Some(pg) = &self.postgres {
            return pg
                .stale_recovery_preview(tenant, agent, &evidence, &issuer)
                .await;
        }
        let (store, tenant, agent) = (self.clone(), tenant.to_owned(), agent.to_owned());
        tokio::task::spawn_blocking(move || {
            let db = store.connection()?;
            let facts = sqlite_facts(&db, &tenant, &agent)?;
            Ok(evaluate(&tenant, &agent, &facts, &evidence, &issuer).map(|v| v.preview))
        })
        .await?
    }

    /// Confirm a preview: re-derive everything under the write lock, then
    /// persist the fence before any new signing. Idempotent for the same
    /// evidence once fenced.
    pub async fn stale_recovery_confirm(
        &self,
        tenant: &str,
        agent: &str,
        request: ConfirmRequest,
        issuer: ManagedIssuer,
        admin_id: &str,
    ) -> Result<Decision<Confirmed>> {
        anyhow::ensure!(
            agent_heartbeat::valid_ids(tenant, agent),
            "invalid identity"
        );
        anyhow::ensure!(
            !admin_id.is_empty() && admin_id.len() <= 128,
            "invalid admin identity"
        );
        if let Some(pg) = &self.postgres {
            return pg
                .stale_recovery_confirm(tenant, agent, &request, &issuer, admin_id)
                .await;
        }
        let (store, tenant, agent, admin) = (
            self.clone(),
            tenant.to_owned(),
            agent.to_owned(),
            admin_id.to_owned(),
        );
        tokio::task::spawn_blocking(move || {
            use rusqlite::params;
            let mut db = store.connection()?;
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            // Under the write lock: a revoke or demotion cannot interleave.
            if !sqlite_owner_active(&tx, &admin)? {
                return Ok(Err(Refusal::OwnerNotActive));
            }
            if let Some(existing) = replayed(&tx, &tenant, &agent, &request)? {
                return Ok(Ok(existing));
            }
            let facts = sqlite_facts(&tx, &tenant, &agent)?;
            let verified = match evaluate(&tenant, &agent, &facts, &request.evidence, &issuer) {
                Ok(v) => v,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if let Err(refusal) =
                check_confirmation(&verified, &request.state_binding, &request.confirmation)
            {
                return Ok(Err(refusal));
            }
            let p = &verified.preview;
            let now = super::now_unix();
            let interval = p.unrecoverable_interval.as_ref();
            tx.execute(
                "INSERT INTO managed_agent_recovery_fences (tenant_id,agent_id,fence_sequence,restored_sequence,evidence_revision,evidence_policy_sha256,evidence_bundle_sha256,issuer_key_id,issuer_public_key_sha256,credential_generation,state_binding,unrecoverable_from,unrecoverable_to,observed_at_unix,confirmed_by,confirmed_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                params![
                    tenant,
                    agent,
                    p.evidence.deployment_sequence,
                    verified.restored_high,
                    p.evidence.revision,
                    p.evidence.policy_sha256,
                    p.evidence.bundle_sha256,
                    p.evidence.issuer_key_id,
                    p.issuer_public_key_sha256,
                    p.credential_generation,
                    p.state_binding,
                    interval.map(|i| i.from_sequence),
                    interval.map(|i| i.to_sequence),
                    p.observed_at_unix,
                    admin,
                    now
                ],
            )?;
            let fence = sqlite_fences(&tx, &tenant, &agent)?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("fence not persisted"))?;
            tx.commit()?;
            Ok(Ok(Confirmed {
                contract_version: CONTRACT.into(),
                replayed: false,
                fence,
            }))
        })
        .await?
    }

    /// Current recovery state for one Agent (`None` when not enrolled).
    pub async fn stale_recovery_status(&self, tenant: &str, agent: &str) -> Result<Option<Status>> {
        anyhow::ensure!(
            agent_heartbeat::valid_ids(tenant, agent),
            "invalid identity"
        );
        if let Some(pg) = &self.postgres {
            return pg.stale_recovery_status(tenant, agent).await;
        }
        let (store, tenant, agent) = (self.clone(), tenant.to_owned(), agent.to_owned());
        tokio::task::spawn_blocking(move || {
            use rusqlite::{params, OptionalExtension};
            let db = store.connection()?;
            super::managed_policy::schema(&db)?;
            let enrolled = db
                .query_row(
                    "SELECT 1 FROM managed_agent_enrollments WHERE tenant_id=?1 AND agent_id=?2",
                    params![tenant, agent],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !enrolled {
                return Ok(None);
            }
            let restored: i64 = db.query_row(
                "SELECT COALESCE(MAX(deployment_sequence),0) FROM managed_agent_deployments WHERE tenant_id=?1 AND agent_id=?2",
                params![tenant, agent],
                |r| r.get(0),
            )?;
            let fences = sqlite_fences(&db, &tenant, &agent)?;
            Ok(Some(status(&tenant, &agent, restored, fences)))
        })
        .await?
    }
}

/// The same evidence already fenced: return it unchanged (idempotent retry).
fn replayed(
    db: &rusqlite::Connection,
    tenant: &str,
    agent: &str,
    request: &ConfirmRequest,
) -> Result<Option<Confirmed>> {
    use rusqlite::{params, OptionalExtension};
    super::managed_policy::schema(db)?;
    let Ok(bytes) = serde_json::to_vec(&request.evidence) else {
        return Ok(None);
    };
    let digest = sha(&bytes);
    let found: Option<(i64, String)> = db
        .query_row(
            "SELECT fence_sequence,state_binding FROM managed_agent_recovery_fences WHERE tenant_id=?1 AND agent_id=?2 AND evidence_bundle_sha256=?3",
            params![tenant, agent, digest],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((seq, binding)) = found else {
        return Ok(None);
    };
    if binding != request.state_binding {
        return Ok(None);
    }
    let fence = sqlite_fences(db, tenant, agent)?
        .into_iter()
        .find(|f| f.fence_sequence == seq);
    Ok(fence.map(|fence| Confirmed {
        contract_version: CONTRACT.into(),
        replayed: true,
        fence,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::agent_heartbeat::ObservedPolicy;
    use super::*;

    fn issuer() -> ManagedIssuer {
        ManagedIssuer::new("recovery-key".into(), &"0a".repeat(32)).unwrap()
    }
    fn bundle(issuer: &ManagedIssuer, seq: u64, yaml: &str) -> SignedManagedBundle {
        let mut b = SignedManagedBundle {
            schema_version: 1,
            tenant_id: "t1".into(),
            agent_id: "a1".into(),
            revision: format!("r{seq}"),
            deployment_sequence: seq,
            issued_at_unix: 1000,
            expires_at_unix: 4600,
            issuer_key_id: issuer.key_id().into(),
            policy_yaml: yaml.into(),
            policy_sha256: sha(yaml.as_bytes()),
            signature_hex: String::new(),
        };
        issuer.sign(&mut b).unwrap();
        b
    }
    fn facts(issuer: &ManagedIssuer, observed: &SignedManagedBundle) -> Facts {
        let restored = bundle(issuer, 2, "default: allow\n");
        Facts {
            enrolled: true,
            revoked: false,
            generation: 1,
            credential_digest: "c".repeat(64),
            latest: Some(LatestDeployment {
                sequence: 2,
                revision: "r2".into(),
                policy_sha256: restored.policy_sha256.clone(),
                status: "applied".into(),
                bundle_json: serde_json::to_string(&restored).unwrap(),
            }),
            restored_floor: 2,
            fence_high: 0,
            revisions_digest: "d".repeat(64),
            heartbeat_available: true,
            heartbeat: Some(HeartbeatRow {
                generation: 1,
                instance_id: "1".repeat(32),
                registration_id: "2".repeat(32),
                last_sequence: 4,
                registered_at: 9000,
                received_at: Some(9990),
                policy: Some(ObservedPolicy {
                    deployment_sequence: observed.deployment_sequence as i64,
                    revision: observed.revision.clone(),
                    policy_sha256: observed.policy_sha256.clone(),
                }),
            }),
            now: 10_000,
        }
    }

    #[test]
    fn only_exact_fresh_current_evidence_opens_a_fence() {
        let i = issuer();
        let ev = bundle(&i, 4, "default: deny\n");
        let f = facts(&i, &ev);
        let ok = evaluate("t1", "a1", &f, &ev, &i).unwrap();
        let p = &ok.preview;
        assert_eq!((p.restored_sequence, p.next_sequence), (2, 5));
        assert_eq!(
            p.unrecoverable_interval,
            Some(Interval {
                from_sequence: 3,
                to_sequence: 3
            })
        );
        assert!(p.confirmation.starts_with("recover a1 from 2 to 4 "));
        assert!(check_confirmation(&ok, &p.state_binding, &p.confirmation).is_ok());
        assert_eq!(
            check_confirmation(&ok, &"0".repeat(64), &p.confirmation),
            Err(Refusal::StateChanged)
        );
        assert_eq!(
            check_confirmation(&ok, &p.state_binding, "recover"),
            Err(Refusal::ConfirmationMismatch)
        );
        // Adjacent: no unrecoverable interval.
        let next = bundle(&i, 3, "default: deny\n");
        assert_eq!(
            evaluate("t1", "a1", &facts(&i, &next), &next, &i)
                .unwrap()
                .preview
                .unrecoverable_interval,
            None
        );

        let refuse = |f: &Facts, e: &SignedManagedBundle, i: &ManagedIssuer| {
            evaluate("t1", "a1", f, e, i).err()
        };
        let mut tampered = ev.clone();
        tampered.policy_yaml = "default: allow\n".into();
        tampered.policy_sha256 = sha(tampered.policy_yaml.as_bytes());
        assert_eq!(
            refuse(&facts(&i, &tampered), &tampered, &i),
            Some(Refusal::EvidenceSignatureInvalid)
        );
        let mut digest = ev.clone();
        digest.policy_yaml = "default: allow\n".into();
        assert_eq!(
            refuse(&f, &digest, &i),
            Some(Refusal::EvidenceDigestMismatch)
        );
        let mut foreign = ev.clone();
        foreign.tenant_id = "t2".into();
        assert_eq!(
            refuse(&f, &foreign, &i),
            Some(Refusal::EvidenceWrongAudience)
        );
        let other = ManagedIssuer::new("recovery-key".into(), &"0b".repeat(32)).unwrap();
        assert_eq!(
            refuse(&f, &ev, &other),
            Some(Refusal::EvidenceSignatureInvalid)
        );
        let renamed = ManagedIssuer::new("other-key".into(), &"0a".repeat(32)).unwrap();
        assert_eq!(refuse(&f, &ev, &renamed), Some(Refusal::IssuerChanged));
        // Restored deployments from another key: issuer changed even if evidence verifies.
        let mut g = f.clone();
        let old = bundle(&other, 2, "default: allow\n");
        g.latest.as_mut().unwrap().bundle_json = serde_json::to_string(&old).unwrap();
        assert_eq!(refuse(&g, &ev, &i), Some(Refusal::IssuerChanged));
        // Replayed or old evidence is not ahead; an existing fence raises the floor.
        let replay = bundle(&i, 2, "default: allow\n");
        assert_eq!(
            refuse(&facts(&i, &replay), &replay, &i),
            Some(Refusal::EvidenceNotAhead)
        );
        let mut fenced = f.clone();
        fenced.fence_high = 4;
        assert_eq!(refuse(&fenced, &ev, &i), Some(Refusal::EvidenceNotAhead));
        // A restored row the Agent rejected at the evidence sequence is a refused
        // conflict: the evidence still opens, and issuance goes above both.
        let mut conflict = f.clone();
        conflict.restored_floor = 2;
        conflict.latest.as_mut().unwrap().sequence = 4;
        conflict.latest.as_mut().unwrap().status = "rejected".into();
        let c = evaluate("t1", "a1", &conflict, &ev, &i).unwrap().preview;
        assert_eq!(
            (
                c.restored_sequence,
                c.latest_restored_sequence,
                c.next_sequence
            ),
            (2, 4, 5)
        );
        let mut no = f.clone();
        no.latest = None;
        assert_eq!(refuse(&no, &ev, &i), Some(Refusal::NoRestoredDeployment));
        let mut revoked = f.clone();
        revoked.revoked = true;
        assert_eq!(refuse(&revoked, &ev, &i), Some(Refusal::Revoked));
        let mut absent = f.clone();
        absent.enrolled = false;
        assert_eq!(refuse(&absent, &ev, &i), Some(Refusal::NotEnrolled));
        // Observation: missing, stale, other generation, other policy.
        let mut h = f.clone();
        h.heartbeat = None;
        assert_eq!(refuse(&h, &ev, &i), Some(Refusal::ObservationUnavailable));
        let mut h = f.clone();
        h.heartbeat_available = false;
        assert_eq!(refuse(&h, &ev, &i), Some(Refusal::ObservationUnavailable));
        let mut h = f.clone();
        h.now = 9990 + agent_heartbeat::EXPIRES_AFTER_SECONDS + 1;
        assert_eq!(refuse(&h, &ev, &i), Some(Refusal::ObservationNotFresh));
        let mut h = f.clone();
        h.generation = 2;
        assert_eq!(refuse(&h, &ev, &i), Some(Refusal::CredentialChanged));
        let other_obs = bundle(&i, 5, "default: deny\n");
        assert_eq!(
            refuse(&facts(&i, &other_obs), &ev, &i),
            Some(Refusal::ObservationMismatch)
        );
        // Any change to the gathered state changes the binding.
        let base = ok.preview.state_binding.clone();
        for change in [
            |f: &mut Facts| f.revisions_digest = "e".repeat(64),
            |f: &mut Facts| f.credential_digest = "f".repeat(64),
            |f: &mut Facts| f.latest.as_mut().unwrap().status = "rejected".into(),
        ] {
            let mut c = f.clone();
            change(&mut c);
            assert_ne!(
                evaluate("t1", "a1", &c, &ev, &i)
                    .unwrap()
                    .preview
                    .state_binding,
                base
            );
        }
        // A heartbeat tick that names the same policy keeps the binding.
        let mut tick = f.clone();
        tick.heartbeat.as_mut().unwrap().last_sequence = 9;
        assert_eq!(
            evaluate("t1", "a1", &tick, &ev, &i)
                .unwrap()
                .preview
                .state_binding,
            base
        );
    }

    #[test]
    fn refusal_codes_are_distinct_and_bounded() {
        use Refusal::*;
        let all = [
            NotEnrolled,
            Revoked,
            EvidenceMalformed,
            EvidenceWrongAudience,
            EvidenceDigestMismatch,
            IssuerChanged,
            EvidenceSignatureInvalid,
            NoRestoredDeployment,
            EvidenceNotAhead,
            ObservationUnavailable,
            ObservationNotFresh,
            CredentialChanged,
            ObservationMismatch,
            StateChanged,
            ConfirmationMismatch,
            OwnerNotActive,
        ];
        let codes: std::collections::BTreeSet<_> = all.iter().map(|r| r.code()).collect();
        assert_eq!(codes.len(), all.len());
        assert!(all
            .iter()
            .all(|r| [400, 403, 404, 409].contains(&r.http_status())));
    }
}
