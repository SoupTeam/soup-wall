// SPDX-License-Identifier: Apache-2.0
//! SOU-241: finite reasons for an Agent's rejection of a policy candidate.
//!
//! The existing authenticated acknowledgement may carry an optional
//! `rejection` object `{version: 1, code}` whose code comes from this fixed
//! allowlist (derived by the Agent at the actual failure boundary). The
//! Console stores the first authenticated rejection of the exact candidate
//! (tenant, Agent, sequence, revision, digest) with its own receipt time in
//! `managed_agent_rejections`. An acknowledgement without a reason (an older
//! Agent) is still recorded, with no code. Nothing free-form is accepted.
use serde::{Deserialize, Serialize};

pub const REASON_VERSION: i64 = 1;
/// PostgreSQL migration that adds `managed_agent_rejections`.
pub const SCHEMA_VERSION: i64 = 32;

/// `(code, category)`; categories group the failure boundary.
pub const CODES: [(&str, &str); 15] = [
    ("issuer_key_unknown", "trust"),
    ("issuer_key_revoked", "trust"),
    ("keyring_unavailable", "trust"),
    ("signature_invalid", "signature"),
    ("digest_mismatch", "signature"),
    ("audience_mismatch", "signature"),
    ("schema_unsupported", "signature"),
    ("bundle_malformed", "signature"),
    ("bundle_expired", "expiry"),
    ("issued_in_future", "expiry"),
    ("lifetime_invalid", "expiry"),
    ("policy_invalid", "policy"),
    ("policy_too_large", "policy"),
    ("sequence_stale", "activation"),
    ("activation_failed", "activation"),
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RejectionReport {
    pub version: i64,
    pub code: String,
}
impl RejectionReport {
    pub fn valid(&self) -> bool {
        self.version == REASON_VERSION && CODES.iter().any(|(code, _)| *code == self.code)
    }
}

/// Stored with each deployment record in fleet reads; `code` is `None` when
/// the Agent did not report one (an Agent that predates reason codes).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RecordedRejection {
    pub reason_version: Option<i64>,
    pub code: Option<String>,
    pub received_at_unix: i64,
}

pub(super) const SQLITE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS managed_agent_rejections (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    deployment_sequence INTEGER NOT NULL,
    revision TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    reason_version INTEGER CHECK(reason_version IS NULL OR reason_version = 1),
    reason_code TEXT CHECK(reason_code IS NULL OR length(reason_code) BETWEEN 1 AND 48),
    received_at_unix INTEGER NOT NULL,
    PRIMARY KEY(tenant_id,agent_id,deployment_sequence),
    CHECK((reason_version IS NULL) = (reason_code IS NULL)),
    FOREIGN KEY(tenant_id,agent_id,deployment_sequence)
      REFERENCES managed_agent_deployments(tenant_id,agent_id,deployment_sequence)
);";

pub(super) const POSTGRES_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS managed_agent_rejections (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    deployment_sequence BIGINT NOT NULL,
    revision TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    reason_version BIGINT CHECK(reason_version IS NULL OR reason_version = 1),
    reason_code TEXT CHECK(reason_code IS NULL OR length(reason_code) BETWEEN 1 AND 48),
    received_at_unix BIGINT NOT NULL,
    PRIMARY KEY(tenant_id,agent_id,deployment_sequence),
    CHECK((reason_version IS NULL) = (reason_code IS NULL)),
    FOREIGN KEY(tenant_id,agent_id,deployment_sequence)
      REFERENCES managed_agent_deployments(tenant_id,agent_id,deployment_sequence)
);";

/// Validates the optional reason against the acknowledgement status.
pub(super) fn check(status: &str, reason: Option<&RejectionReport>) -> anyhow::Result<()> {
    anyhow::ensure!(
        reason.is_none() || (status == "rejected" && reason.is_some_and(RejectionReport::valid)),
        "invalid rejection reason"
    );
    Ok(())
}
pub(super) fn parts(reason: Option<&RejectionReport>) -> (Option<i64>, Option<String>) {
    match reason {
        Some(r) => (Some(r.version), Some(r.code.clone())),
        None => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_are_a_finite_versioned_allowlist() {
        let ok = RejectionReport {
            version: 1,
            code: "bundle_expired".into(),
        };
        assert!(ok.valid());
        assert!(check("rejected", Some(&ok)).is_ok());
        assert!(check("rejected", None).is_ok());
        assert!(check("applied", None).is_ok());
        assert!(check("applied", Some(&ok)).is_err());
        for bad in [
            RejectionReport {
                version: 2,
                code: "bundle_expired".into(),
            },
            RejectionReport {
                version: 1,
                code: "Bundle expired".into(),
            },
            RejectionReport {
                version: 1,
                code: "x".repeat(49),
            },
            RejectionReport {
                version: 1,
                code: String::new(),
            },
        ] {
            assert!(check("rejected", Some(&bad)).is_err(), "{bad:?}");
        }
        assert!(serde_json::from_str::<RejectionReport>(
            r#"{"version":1,"code":"bundle_expired","detail":"x"}"#
        )
        .is_err());
        let mut seen = std::collections::BTreeSet::new();
        for (code, category) in CODES {
            assert!(code.len() <= 48 && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
            assert!(["trust", "signature", "expiry", "policy", "activation"].contains(&category));
            assert!(seen.insert(code), "duplicate {code}");
        }
    }

    /// The browser text table covers exactly the server allowlist.
    #[test]
    fn browser_reason_table_matches_the_allowlist() {
        let js = include_str!("../agent_rejection_reasons.js");
        let listed = js.matches(": T(\"").count();
        assert_eq!(listed, CODES.len());
        for (code, category) in CODES {
            assert!(
                js.contains(&format!("    {code}: T(\"{category}\", ")),
                "{code}"
            );
        }
    }
}
