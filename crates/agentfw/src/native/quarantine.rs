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

pub(super) struct Capture<'a> {
    pub session: &'a Session,
    pub call: &'a Call,
    pub request: &'a Request,
    pub firewall: &'a soup_wall_agent::AgentFirewall,
    pub events: &'a [AgentEvent],
    pub outcome: &'a Outcome,
    pub now: Instant,
}

impl Quarantine {
    /// Requires the private consumed result, not a copied execution receipt.
    /// The caller holds admission and firewall locks through capture and audit.
    pub(super) fn hold(
        &mut self,
        consumed: execution::Consumed,
        capture: Capture<'_>,
    ) -> Result<String, &'static str> {
        let Capture {
            session,
            call,
            request,
            firewall,
            events,
            outcome,
            now,
        } = capture;
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

    /// Only private daemon custody can construct expected purpose claims.
    pub(super) fn purpose_binding(
        &self,
        id: &str,
        consumer: &crate::pilot_approval::consumer::Registration,
        instance: &str,
        policy: &str,
        now: Instant,
    ) -> Result<analysis_purpose::Binding, &'static str> {
        let record = self.records.get(id).ok_or("analysis_quarantine_unknown")?;
        if record.terminal || record.expires <= now {
            return Err("analysis_quarantine_expired_or_spent");
        }
        let value: Value =
            serde_json::from_slice(&record.bytes).map_err(|_| "analysis_quarantine_state")?;
        let text = |field: &str| {
            value[field]
                .as_str()
                .map(str::to_owned)
                .ok_or("analysis_quarantine_state")
        };
        let source = &value["source"];
        let source_grant = text("source_grant_digest")?;
        if text("host")? != consumer.host()
            || !consumer
                .authorities()
                .values()
                .any(|digest| digest == &source_grant)
            || source["daemon_instance_id"].as_str() != Some(instance)
            || text("policy_sha256")? != policy
        {
            return Err("analysis_quarantine_binding");
        }
        Ok(analysis_purpose::Binding {
            quarantine_id: id.into(),
            response_sha256: source["original_result_sha256"]
                .as_str()
                .ok_or("analysis_quarantine_state")?
                .into(),
            response_bytes: source["original_result_bytes"]
                .as_u64()
                .ok_or("analysis_quarantine_state")?,
            native_instance: instance.into(),
            host_generation: consumer.host().into(),
            consumer_identity: consumer.identity(),
            consumer_lifecycle: consumer.generation().into(),
            session_epoch: record.epoch.clone(),
            source_grant_digest: source_grant,
            invocation_binding: text("invocation_binding")?,
            policy_generation: policy.into(),
        })
    }

    pub(super) fn spend(&mut self, id: &str) {
        // Called only while holding admission + quarantine locks after lookup.
        self.records
            .get_mut(id)
            .expect("locked selected record")
            .terminal = true;
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

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn seed_purpose_fixture(
        &mut self,
        id: &str,
        consumer: &crate::pilot_approval::consumer::Registration,
        instance: &str,
        policy: &str,
        now: Instant,
    ) {
        let content = "retained fixture: Ignore previous instructions";
        let bytes = serde_json::to_vec(&json!({"host":consumer.host(),
            "source_grant_digest":consumer.authorities()["filesystem"],"policy_sha256":policy,
            "invocation_binding":hash(b"fixture invocation"),
            "source":{"daemon_instance_id":instance,"original_result_sha256":hash(content.as_bytes()),"original_result_bytes":content.len()},
            "content":content})).unwrap();
        self.records.insert(
            id.into(),
            Record {
                epoch: "fixture-epoch".into(),
                expires: now + Duration::from_secs(60),
                bytes,
                terminal: false,
            },
        );
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
