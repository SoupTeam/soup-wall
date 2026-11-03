// SPDX-License-Identifier: Apache-2.0
//! Opt-in managed Agent heartbeat (`sw-agent-heartbeat/1`).
//!
//! An enrolled Agent authenticates with its existing credential, registers
//! one process instance under its current server-issued credential
//! generation and then reports strictly increasing sequences. Freshness uses
//! only the server's receipt time and a fixed expiry; a client clock, a
//! replayed request or a restarted process cannot revive it. A heartbeat is a
//! self-report, never runtime attestation, proof of enforcement or an
//! execution grant.
//!
//! Storage is one bounded row per Agent outside the recoverable control-plane
//! schema: a connection-scoped table on SQLite (gone on restart) and the
//! separate `agent_observations` schema on PostgreSQL (created by `migrate`).
//! A restore therefore never brings back an old observation as fresh.
use super::{agent_enrollment::valid_id, now_unix, EnrolledAgent, TenantStore};
use anyhow::Result;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

pub const CONTRACT: &str = "sw-agent-heartbeat/1";
pub const STATUS_CONTRACT: &str = "sw-agent-heartbeat-status/1";
/// Server-side freshness window measured from the server's receipt time.
pub const EXPIRES_AFTER_SECONDS: i64 = 90;
/// What the Console recommends; Agents may send less often, never faster
/// than `MIN_INTERVAL_SECONDS`.
pub const INTERVAL_SECONDS: i64 = 30;
pub const MIN_INTERVAL_SECONDS: i64 = 5;
pub const MAX_BODY_BYTES: usize = 2048;

pub fn valid_ids(tenant: &str, agent: &str) -> bool {
    valid_id(tenant) && valid_id(agent)
}
fn hex32(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
fn random_id() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub contract_version: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub credential_generation: i64,
    /// Random per Agent process start, chosen by the Agent.
    pub instance_id: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ObservedPolicy {
    pub deployment_sequence: i64,
    pub revision: String,
    pub policy_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub contract_version: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub credential_generation: i64,
    pub instance_id: String,
    /// Server-issued at registration; replaces any earlier registration.
    pub registration_id: String,
    pub sequence: i64,
    /// The Agent's own report of its loaded managed policy, if any.
    pub observed_policy: Option<ObservedPolicy>,
}
impl Registration {
    pub fn valid(&self) -> bool {
        self.contract_version == CONTRACT
            && valid_id(&self.tenant_id)
            && valid_id(&self.agent_id)
            && self.credential_generation > 0
            && hex32(&self.instance_id)
    }
}
impl Heartbeat {
    pub fn valid(&self) -> bool {
        self.contract_version == CONTRACT
            && valid_id(&self.tenant_id)
            && valid_id(&self.agent_id)
            && self.credential_generation > 0
            && hex32(&self.instance_id)
            && hex32(&self.registration_id)
            && (1..=(1_i64 << 53)).contains(&self.sequence)
            && self.observed_policy.as_ref().is_none_or(|p| {
                p.deployment_sequence > 0
                    && valid_id(&p.revision)
                    && p.policy_sha256.len() == 64
                    && p.policy_sha256
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Registered {
    pub contract_version: String,
    pub registration_id: String,
    pub credential_generation: i64,
    pub interval_seconds: i64,
    pub min_interval_seconds: i64,
    pub expires_after_seconds: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Body names a different tenant or Agent than the credential.
    WrongAgent,
    /// Body names a credential generation other than the current one.
    EpochMismatch,
    /// No registration for this Agent (or the Console lost it on restart).
    NotRegistered,
    /// A newer registration, another instance or another generation owns it.
    RegistrationSuperseded,
    /// Sequence not greater than the last accepted one.
    SequenceReplay,
    /// Faster than the minimum interval since the last accepted heartbeat.
    TooFrequent,
}
impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Refusal::WrongAgent => "wrong_agent",
            Refusal::EpochMismatch => "epoch_mismatch",
            Refusal::NotRegistered => "not_registered",
            Refusal::RegistrationSuperseded => "registration_superseded",
            Refusal::SequenceReplay => "sequence_replay",
            Refusal::TooFrequent => "too_frequent",
        }
    }
}
#[derive(Debug, PartialEq)]
pub enum Outcome<T> {
    Unauthorized,
    Unavailable,
    Refused(Refusal),
    Accepted(T),
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct Row {
    pub generation: i64,
    pub instance_id: String,
    pub registration_id: String,
    pub last_sequence: i64,
    pub registered_at: i64,
    pub received_at: Option<i64>,
    pub policy: Option<ObservedPolicy>,
}

fn same_agent(identity: &EnrolledAgent, tenant: &str, agent: &str) -> bool {
    identity.tenant_id == tenant && identity.agent_id == agent
}
pub(super) fn check_registration(
    identity: &EnrolledAgent,
    r: &Registration,
) -> Result<(), Refusal> {
    if !same_agent(identity, &r.tenant_id, &r.agent_id) {
        return Err(Refusal::WrongAgent);
    }
    if identity.credential_generation != r.credential_generation {
        return Err(Refusal::EpochMismatch);
    }
    Ok(())
}
pub(super) fn check_heartbeat(
    identity: &EnrolledAgent,
    row: Option<&Row>,
    h: &Heartbeat,
    now: i64,
) -> Result<(), Refusal> {
    if !same_agent(identity, &h.tenant_id, &h.agent_id) {
        return Err(Refusal::WrongAgent);
    }
    if identity.credential_generation != h.credential_generation {
        return Err(Refusal::EpochMismatch);
    }
    let Some(row) = row else {
        return Err(Refusal::NotRegistered);
    };
    if row.registration_id != h.registration_id
        || row.instance_id != h.instance_id
        || row.generation != identity.credential_generation
    {
        return Err(Refusal::RegistrationSuperseded);
    }
    if h.sequence <= row.last_sequence {
        return Err(Refusal::SequenceReplay);
    }
    if row
        .received_at
        .is_some_and(|at| now < at.saturating_add(MIN_INTERVAL_SECONDS))
    {
        return Err(Refusal::TooFrequent);
    }
    Ok(())
}
pub(super) fn registered(registration_id: String, generation: i64) -> Registered {
    Registered {
        contract_version: CONTRACT.into(),
        registration_id,
        credential_generation: generation,
        interval_seconds: INTERVAL_SECONDS,
        min_interval_seconds: MIN_INTERVAL_SECONDS,
        expires_after_seconds: EXPIRES_AFTER_SECONDS,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ReportedState {
    pub credential_generation: i64,
    pub registered_at_unix: i64,
    pub sequence: i64,
    pub last_received_at_unix: Option<i64>,
    pub observed_policy: Option<ObservedPolicy>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatStatus {
    pub contract_version: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub observed_at_unix: i64,
    /// `fresh`, `stale`, `registered_no_report`, `credential_changed`,
    /// `revoked`, `unsupported` or `unavailable`.
    pub status: String,
    pub expires_after_seconds: i64,
    pub age_seconds: Option<i64>,
    pub current_credential_generation: i64,
    pub reported: Option<ReportedState>,
    pub note: String,
}
pub(super) fn status(
    tenant: &str,
    agent: &str,
    revoked: bool,
    generation: i64,
    row: Option<Row>,
    available: bool,
    now: i64,
) -> HeartbeatStatus {
    let (status, age) = if !available {
        ("unavailable", None)
    } else if revoked {
        ("revoked", None)
    } else {
        match &row {
            None => ("unsupported", None),
            Some(r) if r.generation != generation => ("credential_changed", None),
            Some(Row {
                received_at: None, ..
            }) => ("registered_no_report", None),
            Some(Row {
                received_at: Some(at),
                ..
            }) => {
                let age = now.saturating_sub(*at).max(0);
                (
                    if age <= EXPIRES_AFTER_SECONDS {
                        "fresh"
                    } else {
                        "stale"
                    },
                    Some(age),
                )
            }
        }
    };
    let age = age.or_else(|| {
        row.as_ref()
            .and_then(|r| r.received_at)
            .map(|at| now.saturating_sub(at).max(0))
    });
    HeartbeatStatus {
        contract_version: STATUS_CONTRACT.into(),
        tenant_id: tenant.into(),
        agent_id: agent.into(),
        observed_at_unix: now,
        status: status.into(),
        expires_after_seconds: EXPIRES_AFTER_SECONDS,
        age_seconds: age,
        current_credential_generation: generation,
        reported: if available {
            row.map(|r| ReportedState {
                credential_generation: r.generation,
                registered_at_unix: r.registered_at,
                sequence: r.last_sequence,
                last_received_at_unix: r.received_at,
                observed_policy: r.policy,
            })
        } else {
            None
        },
        note: "An authenticated self-report by the Agent process, timed by this Console. \
               It is not runtime attestation, proof of enforcement or a health check."
            .into(),
    }
}

const SQLITE_TABLE: &str = "CREATE TEMP TABLE IF NOT EXISTS agent_heartbeats (
    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
    credential_generation INTEGER NOT NULL, instance_id TEXT NOT NULL,
    registration_id TEXT NOT NULL, last_sequence INTEGER NOT NULL,
    registered_at_unix INTEGER NOT NULL, received_at_unix INTEGER,
    policy_sequence INTEGER, policy_revision TEXT, policy_sha256 TEXT,
    PRIMARY KEY(tenant_id, agent_id))";
const ROW_COLUMNS: &str = "credential_generation,instance_id,registration_id,last_sequence,registered_at_unix,received_at_unix,policy_sequence,policy_revision,policy_sha256";

fn sqlite_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let seq: Option<i64> = r.get(6)?;
    Ok(Row {
        generation: r.get(0)?,
        instance_id: r.get(1)?,
        registration_id: r.get(2)?,
        last_sequence: r.get(3)?,
        registered_at: r.get(4)?,
        received_at: r.get(5)?,
        policy: match seq {
            Some(deployment_sequence) => Some(ObservedPolicy {
                deployment_sequence,
                revision: r.get(7)?,
                policy_sha256: r.get(8)?,
            }),
            None => None,
        },
    })
}
fn sqlite_identity(
    tx: &rusqlite::Transaction<'_>,
    authorization: Option<&str>,
) -> Result<Option<EnrolledAgent>> {
    let Some(hash) = authorization
        .and_then(|s| s.strip_prefix("Bearer "))
        .and_then(super::agent_enrollment::credential_hash)
    else {
        return Ok(None);
    };
    if tx
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='managed_agent_enrollments'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_none()
    {
        return Ok(None);
    }
    Ok(tx
        .query_row(
            "SELECT a.tenant_id,a.agent_id,a.created_at_unix,a.revoked_at_unix,a.credential_generation
             FROM managed_agent_enrollments a JOIN tenants t ON t.id=a.tenant_id
             WHERE a.token_hash=?1 AND a.revoked_at_unix IS NULL AND t.active=1",
            [hash],
            |r| {
                Ok(EnrolledAgent {
                    tenant_id: r.get(0)?,
                    agent_id: r.get(1)?,
                    created_at_unix: r.get(2)?,
                    revoked_at_unix: r.get(3)?,
                    credential_generation: r.get(4)?,
                })
            },
        )
        .optional()?)
}

impl TenantStore {
    pub async fn register_agent_heartbeat(
        &self,
        authorization: Option<String>,
        request: Registration,
    ) -> Result<Outcome<Registered>> {
        if let Some(pg) = &self.postgres {
            return pg
                .register_agent_heartbeat(authorization.as_deref(), &request)
                .await;
        }
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = store.connection()?;
            db.execute_batch(SQLITE_TABLE)?;
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let Some(identity) = sqlite_identity(&tx, authorization.as_deref())? else {
                return Ok(Outcome::Unauthorized);
            };
            if let Err(refusal) = check_registration(&identity, &request) {
                return Ok(Outcome::Refused(refusal));
            }
            let id = random_id();
            tx.execute(
                "INSERT INTO temp.agent_heartbeats(tenant_id,agent_id,credential_generation,instance_id,registration_id,last_sequence,registered_at_unix)
                 VALUES(?1,?2,?3,?4,?5,0,?6)
                 ON CONFLICT(tenant_id,agent_id) DO UPDATE SET credential_generation=excluded.credential_generation,
                   instance_id=excluded.instance_id,registration_id=excluded.registration_id,last_sequence=0,
                   registered_at_unix=excluded.registered_at_unix,received_at_unix=NULL,policy_sequence=NULL,
                   policy_revision=NULL,policy_sha256=NULL",
                params![identity.tenant_id, identity.agent_id, identity.credential_generation, request.instance_id, id, now_unix()],
            )?;
            tx.commit()?;
            Ok(Outcome::Accepted(registered(id, identity.credential_generation)))
        })
        .await?
    }

    pub async fn record_agent_heartbeat(
        &self,
        authorization: Option<String>,
        request: Heartbeat,
    ) -> Result<Outcome<()>> {
        if let Some(pg) = &self.postgres {
            return pg
                .record_agent_heartbeat(authorization.as_deref(), &request)
                .await;
        }
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = store.connection()?;
            db.execute_batch(SQLITE_TABLE)?;
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let Some(identity) = sqlite_identity(&tx, authorization.as_deref())? else {
                return Ok(Outcome::Unauthorized);
            };
            let row = tx
                .query_row(
                    &format!("SELECT {ROW_COLUMNS} FROM temp.agent_heartbeats WHERE tenant_id=?1 AND agent_id=?2"),
                    params![identity.tenant_id, identity.agent_id],
                    sqlite_row,
                )
                .optional()?;
            let now = now_unix();
            if let Err(refusal) = check_heartbeat(&identity, row.as_ref(), &request, now) {
                return Ok(Outcome::Refused(refusal));
            }
            let p = request.observed_policy.as_ref();
            tx.execute(
                "UPDATE temp.agent_heartbeats SET last_sequence=?3,received_at_unix=?4,policy_sequence=?5,policy_revision=?6,policy_sha256=?7
                 WHERE tenant_id=?1 AND agent_id=?2 AND registration_id=?8",
                params![identity.tenant_id, identity.agent_id, request.sequence, now,
                        p.map(|p| p.deployment_sequence), p.map(|p| p.revision.clone()), p.map(|p| p.policy_sha256.clone()),
                        request.registration_id],
            )?;
            tx.commit()?;
            Ok(Outcome::Accepted(()))
        })
        .await?
    }

    /// Admin read of one Agent's heartbeat status. `None` when the tenant or
    /// enrollment does not exist.
    pub async fn agent_heartbeat_status(
        &self,
        tenant: &str,
        agent: &str,
    ) -> Result<Option<HeartbeatStatus>> {
        anyhow::ensure!(valid_id(tenant) && valid_id(agent), "invalid identity");
        if let Some(pg) = &self.postgres {
            return pg.agent_heartbeat_status(tenant, agent).await;
        }
        let store = self.clone();
        let (tenant, agent) = (tenant.to_owned(), agent.to_owned());
        tokio::task::spawn_blocking(move || {
            let mut db = store.connection()?;
            db.execute_batch(SQLITE_TABLE)?;
            let tx = db.transaction()?;
            if tx
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='managed_agent_enrollments'",
                    [],
                    |_| Ok(()),
                )
                .optional()?
                .is_none()
            {
                return Ok(None);
            }
            let Some((revoked, generation)) = tx
                .query_row(
                    "SELECT revoked_at_unix,credential_generation FROM managed_agent_enrollments WHERE tenant_id=?1 AND agent_id=?2",
                    params![tenant, agent],
                    |r| Ok((r.get::<_, Option<i64>>(0)?.is_some(), r.get::<_, i64>(1)?)),
                )
                .optional()?
            else {
                return Ok(None);
            };
            let row = tx
                .query_row(
                    &format!("SELECT {ROW_COLUMNS} FROM temp.agent_heartbeats WHERE tenant_id=?1 AND agent_id=?2"),
                    params![tenant, agent],
                    sqlite_row,
                )
                .optional()?;
            Ok(Some(status(&tenant, &agent, revoked, generation, row, true, now_unix())))
        })
        .await?
    }
}

/// PostgreSQL DDL run by `migrate` only; deliberately outside the `public`
/// schema covered by the versioned Console recovery inventory.
pub(super) const POSTGRES_SCHEMA: &str = "CREATE SCHEMA IF NOT EXISTS agent_observations;
 CREATE TABLE IF NOT EXISTS agent_observations.heartbeats (
    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
    credential_generation BIGINT NOT NULL CHECK(credential_generation>0),
    instance_id TEXT NOT NULL CHECK(length(instance_id)=32),
    registration_id TEXT NOT NULL CHECK(length(registration_id)=32),
    last_sequence BIGINT NOT NULL CHECK(last_sequence>=0),
    registered_at_unix BIGINT NOT NULL, received_at_unix BIGINT,
    policy_sequence BIGINT, policy_revision TEXT, policy_sha256 TEXT,
    PRIMARY KEY(tenant_id, agent_id),
    FOREIGN KEY(tenant_id, agent_id) REFERENCES public.managed_agent_enrollments(tenant_id, agent_id) ON DELETE CASCADE);";
pub(super) const POSTGRES_ROW_COLUMNS: &str = ROW_COLUMNS;
pub(super) fn new_registration_id() -> String {
    random_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(generation: i64) -> EnrolledAgent {
        EnrolledAgent {
            tenant_id: "t".into(),
            agent_id: "a".into(),
            created_at_unix: 0,
            revoked_at_unix: None,
            credential_generation: generation,
        }
    }
    fn row(received: Option<i64>) -> Row {
        Row {
            generation: 1,
            instance_id: "1".repeat(32),
            registration_id: "2".repeat(32),
            last_sequence: 4,
            registered_at: 100,
            received_at: received,
            policy: None,
        }
    }
    fn beat(sequence: i64) -> Heartbeat {
        Heartbeat {
            contract_version: CONTRACT.into(),
            tenant_id: "t".into(),
            agent_id: "a".into(),
            credential_generation: 1,
            instance_id: "1".repeat(32),
            registration_id: "2".repeat(32),
            sequence,
            observed_policy: None,
        }
    }

    #[test]
    fn freshness_uses_only_server_receipt_time_and_fixed_expiry() {
        let at = |now| status("t", "a", false, 1, Some(row(Some(1_000))), true, now).status;
        assert_eq!(at(1_000), "fresh");
        assert_eq!(at(1_000 + EXPIRES_AFTER_SECONDS), "fresh");
        assert_eq!(at(1_000 + EXPIRES_AFTER_SECONDS + 1), "stale");
        // A receipt time in the future (clock moved back) is age 0, not negative.
        assert_eq!(
            status("t", "a", false, 1, Some(row(Some(2_000))), true, 1_000).age_seconds,
            Some(0)
        );
        assert_eq!(
            status("t", "a", false, 1, None, true, 1).status,
            "unsupported"
        );
        assert_eq!(
            status("t", "a", false, 1, Some(row(None)), true, 1).status,
            "registered_no_report"
        );
        assert_eq!(
            status("t", "a", false, 2, Some(row(Some(1))), true, 1).status,
            "credential_changed"
        );
        assert_eq!(
            status("t", "a", true, 1, Some(row(Some(1))), true, 1).status,
            "revoked"
        );
        let unavailable = status("t", "a", false, 1, Some(row(Some(1))), false, 1);
        assert_eq!(unavailable.status, "unavailable");
        assert!(unavailable.reported.is_none());
    }

    #[test]
    fn heartbeat_decisions_refuse_replay_supersession_epoch_and_identity() {
        let r = row(Some(1_000));
        let now = 1_000 + MIN_INTERVAL_SECONDS;
        assert_eq!(
            check_heartbeat(&identity(1), Some(&r), &beat(5), now),
            Ok(())
        );
        assert_eq!(
            check_heartbeat(&identity(1), Some(&r), &beat(4), now),
            Err(Refusal::SequenceReplay)
        );
        assert_eq!(
            check_heartbeat(&identity(1), Some(&r), &beat(3), now),
            Err(Refusal::SequenceReplay)
        );
        assert_eq!(
            check_heartbeat(&identity(1), Some(&r), &beat(5), now - 1),
            Err(Refusal::TooFrequent)
        );
        assert_eq!(
            check_heartbeat(&identity(2), Some(&r), &beat(5), now),
            Err(Refusal::EpochMismatch)
        );
        assert_eq!(
            check_heartbeat(&identity(1), None, &beat(5), now),
            Err(Refusal::NotRegistered)
        );
        let mut other = beat(5);
        other.registration_id = "3".repeat(32);
        assert_eq!(
            check_heartbeat(&identity(1), Some(&r), &other, now),
            Err(Refusal::RegistrationSuperseded)
        );
        let mut other = beat(5);
        other.instance_id = "4".repeat(32);
        assert_eq!(
            check_heartbeat(&identity(1), Some(&r), &other, now),
            Err(Refusal::RegistrationSuperseded)
        );
        let mut other = beat(5);
        other.agent_id = "b".into();
        assert_eq!(
            check_heartbeat(&identity(1), Some(&r), &other, now),
            Err(Refusal::WrongAgent)
        );
        // A registration under an older generation is superseded even if the
        // request itself names the current generation.
        let mut old = r.clone();
        old.generation = 1;
        let mut current = beat(5);
        current.credential_generation = 2;
        assert_eq!(
            check_heartbeat(&identity(2), Some(&old), &current, now),
            Err(Refusal::RegistrationSuperseded)
        );
    }

    #[test]
    fn contract_shapes_are_strict() {
        assert!(beat(1).valid());
        assert!(!beat(0).valid());
        assert!(!beat((1_i64 << 53) + 1).valid());
        let mut b = beat(1);
        b.instance_id = "ABCDEF".repeat(5) + "AB";
        assert!(!b.valid());
        let mut b = beat(1);
        b.observed_policy = Some(ObservedPolicy {
            deployment_sequence: 1,
            revision: "r1".into(),
            policy_sha256: "A".repeat(64),
        });
        assert!(!b.valid());
        assert!(serde_json::from_str::<Heartbeat>(
            &serde_json::to_string(&beat(1))
                .unwrap()
                .replace("}", ",\"prompt\":\"x\"}")
        )
        .is_err());
    }
}
