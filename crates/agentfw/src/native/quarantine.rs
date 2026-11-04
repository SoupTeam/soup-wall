// SPDX-License-Identifier: Apache-2.0
//! Private, bounded custody of refused original responses. No redemption API.
use super::*;

const MAX_RECORDS: usize = 32;
const MAX_BYTES: usize = 8 * 1024 * 1024;

struct Record {
    epoch: String,
    expires: Instant,
    // Serialized sensitive source/provenance stays inside the daemon. It is
    // never returned in a response, audit, status endpoint or error message.
    bytes: Vec<u8>,
    terminal: bool,
}

#[derive(Default)]
pub(super) struct Quarantine {
    records: BTreeMap<String, Record>,
}

impl Quarantine {
    /// Requires the private consumed result, not a copied execution receipt.
    /// The caller holds admission and firewall locks through capture and audit.
    pub(super) fn hold(
        &mut self,
        consumed: execution::Consumed,
        session: &Session,
        call: &Call,
        request: &Request,
        firewall: &soup_wall_agent::AgentFirewall,
        events: &[AgentEvent],
        outcome: &Outcome,
        now: Instant,
    ) -> Result<String, &'static str> {
        self.records.retain(|_, record| record.expires > now);
        if self.records.len() >= MAX_RECORDS {
            return Err("analysis_quarantine_capacity");
        }
        if session.terminal || call.expires <= now {
            return Err("analysis_quarantine_expired");
        }
        let grant = session
            .authority_digest
            .as_deref()
            .ok_or("analysis_quarantine_source_grant_missing")?;
        let host = session
            .host_session
            .as_deref()
            .ok_or("analysis_quarantine_host_missing")?;
        let content = request
            .content
            .as_deref()
            .ok_or("analysis_quarantine_content_missing")?;
        let source = consumed.metadata();
        if source.original_result_sha256 != hash(content.as_bytes())
            || source.original_result_bytes != content.len()
        {
            return Err("analysis_quarantine_content_mismatch");
        }
        let provenance = firewall.provenance_snapshot_for(&[&session.epoch, host]);
        if provenance.legacy_unknown_history
            || provenance.sessions.iter().any(|entry| entry.incomplete)
            || !provenance
                .sessions
                .iter()
                .any(|entry| entry.session == session.epoch)
            || !provenance
                .sessions
                .iter()
                .any(|entry| entry.session == host)
            || outcome.provenance_incomplete
        {
            return Err("analysis_quarantine_provenance_incomplete");
        }
        let policy = serde_json::to_value(firewall.policy_for_diagnostics())
            .map_err(|_| "analysis_quarantine_policy")?;
        let retained = json!({
            "contract": "sw-analysis-quarantine/1",
            "source": source,
            "content": content,
            "source_grant_digest": grant,
            "source_authority_expires_at_ms": session.authority_expires_at_ms,
            "session_epoch": session.epoch,
            "parent_epoch": session.parent_epoch,
            "host": host,
            "invocation_binding": call.binding_sha256,
            "policy_sha256": canonical_digest(&policy),
            "managed_policy": firewall.active_managed_policy(),
            "provenance": provenance,
            "events": events,
            "inspection": {
                "verdict": verdict_label(resolved(outcome)),
                "rule": outcome.rule, "findings": outcome.findings,
                "taint": outcome.taint, "risk_score": outcome.risk_score,
                "provenance_incomplete": outcome.provenance_incomplete
            }
        });
        let used: usize = self.records.values().map(|record| record.bytes.len()).sum();
        let bytes = encode_bounded(&retained, MAX_BYTES.saturating_sub(used))?;
        let id = crate::token::generate();
        if self.records.contains_key(&id) {
            return Err("analysis_quarantine_identity_collision");
        }
        self.records.insert(
            id.clone(),
            Record {
                epoch: session.epoch.clone(),
                expires: call.expires,
                bytes,
                terminal: false,
            },
        );
        Ok(id)
    }

    /// Retirement invalidates the lifecycle without erasing retained source.
    /// The original call deadline bounds both payload and terminal tombstone.
    pub(super) fn retire(&mut self, epoch: &str) {
        for record in self
            .records
            .values_mut()
            .filter(|record| record.epoch == epoch)
        {
            if !record.terminal {
                record.terminal = true;
            }
        }
    }

    #[cfg(test)]
    pub(super) fn retained(&self, id: &str) -> Option<(Value, bool)> {
        self.records.get(id).map(|record| {
            (
                serde_json::from_slice(&record.bytes).unwrap(),
                record.terminal,
            )
        })
    }
}

fn encode_bounded(value: &Value, limit: usize) -> Result<Vec<u8>, &'static str> {
    struct Writer {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other("quarantine capacity"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| "analysis_quarantine_capacity")?;
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_byte_limit_counts_json_escaping_and_exact_boundary() {
        let value = json!({"text": "\u{0000}\n\\\"Русский текст"});
        let expected = serde_json::to_vec(&value).unwrap();
        assert_eq!(encode_bounded(&value, expected.len()).unwrap(), expected);
        assert_eq!(
            encode_bounded(&value, expected.len() - 1),
            Err("analysis_quarantine_capacity")
        );
        assert_eq!(
            encode_bounded(&value, 0),
            Err("analysis_quarantine_capacity")
        );
    }
}
