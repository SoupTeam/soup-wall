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
    #[cfg(test)]
    reader_reserved: bool,
}

/// Affine custody selector for the reviewed test-only connected reader.
/// Includes the entire retained record digest, so findings/taint cannot change.
#[cfg(test)]
pub(super) struct ReaderSource {
    binding: analysis_purpose::Binding,
    record_hash: String,
    pub(super) deadline: Instant,
}

#[cfg(test)]
impl ReaderSource {
    pub(super) fn reserve(
        self,
        quarantine: &mut Quarantine,
        instance: &str,
        policy: &str,
        now: Instant,
    ) -> Result<Vec<u8>, &'static str> {
        self.reserve_bounded(quarantine, instance, policy, now, 4096)
    }

    fn reserve_bounded(
        &self,
        quarantine: &mut Quarantine,
        instance: &str,
        policy: &str,
        now: Instant,
        limit: usize,
    ) -> Result<Vec<u8>, &'static str> {
        let record = quarantine
            .records
            .get_mut(&self.binding.quarantine_id)
            .ok_or("analysis_quarantine_unknown")?;
        // Every attempt is terminal, including failed source/epoch/policy checks.
        if std::mem::replace(&mut record.reader_reserved, true) {
            return Err("analysis_reader_replay");
        }
        if !record.terminal
            || now >= self.deadline
            || record.expires != self.deadline
            || record.epoch != self.binding.session_epoch
            || instance != self.binding.native_instance
            || policy != self.binding.policy_generation
            || hash(&record.bytes) != self.record_hash
        {
            return Err("analysis_reader_source_binding");
        }
        let value: Value =
            serde_json::from_slice(&record.bytes).map_err(|_| "analysis_quarantine_state")?;
        let content = value["content"]
            .as_str()
            .ok_or("analysis_quarantine_state")?;
        if hash(content.as_bytes()) != self.binding.response_sha256
            || content.len() as u64 != self.binding.response_bytes
            || content.len() > limit
        {
            return Err("analysis_reader_source_bytes");
        }
        Ok(content.as_bytes().to_vec())
    }

    pub(super) fn reserve_analysis(
        self,
        quarantine: &mut Quarantine,
        instance: &str,
        policy: &str,
        now: Instant,
    ) -> Result<AnalysisSource, &'static str> {
        // Charge retained input, bounded serialized/decoded copies and buffers
        // together. The lease survives in the private review object until Drop.
        let record_len = quarantine
            .records
            .get(&self.binding.quarantine_id)
            .ok_or("analysis_quarantine_unknown")?
            .bytes
            .len();
        let source_len = usize::try_from(self.binding.response_bytes)
            .map_err(|_| "analysis_reader_source_bytes")?;
        if source_len > 262_144 {
            return Err("analysis_reader_source_bytes");
        }
        let charge = record_len
            .checked_mul(4)
            .and_then(|n| n.checked_add(source_len.checked_mul(3)?))
            .and_then(|n| n.checked_add(65_536))
            .ok_or("analysis_quarantine_capacity")?;
        let used: usize = quarantine.records.values().map(|r| r.bytes.len()).sum();
        let active = quarantine
            .analysis_bytes
            .load(std::sync::atomic::Ordering::Acquire);
        if charge > MAX_BYTES.saturating_sub(used).saturating_sub(active) {
            return Err("analysis_quarantine_capacity");
        }
        quarantine
            .analysis_bytes
            .fetch_add(charge, std::sync::atomic::Ordering::AcqRel);
        let lease = AnalysisBudget {
            bytes: quarantine.analysis_bytes.clone(),
            charge,
        };
        let bytes = self.reserve_bounded(quarantine, instance, policy, now, 262_144)?;
        Ok(AnalysisSource {
            bytes,
            selector: self,
            lease,
        })
    }
}

#[cfg(test)]
pub(super) struct AnalysisBudget {
    bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    charge: usize,
}
#[cfg(test)]
impl Drop for AnalysisBudget {
    fn drop(&mut self) {
        self.bytes
            .fetch_sub(self.charge, std::sync::atomic::Ordering::AcqRel);
    }
}
#[cfg(test)]
pub(super) struct AnalysisSource {
    pub(super) bytes: Vec<u8>,
    selector: ReaderSource,
    pub(super) lease: AnalysisBudget,
}
#[cfg(test)]
impl AnalysisSource {
    pub(super) fn recheck(
        &self,
        quarantine: &Quarantine,
        instance: &str,
        policy: &str,
        now: Instant,
    ) -> Result<Vec<u8>, &'static str> {
        let s = &self.selector;
        let r = quarantine
            .records
            .get(&s.binding.quarantine_id)
            .ok_or("analysis_quarantine_unknown")?;
        if !r.terminal
            || !r.reader_reserved
            || now >= s.deadline
            || r.expires != s.deadline
            || r.epoch != s.binding.session_epoch
            || instance != s.binding.native_instance
            || policy != s.binding.policy_generation
            || hash(&r.bytes) != s.record_hash
            || hash(&self.bytes) != s.binding.response_sha256
        {
            return Err("analysis_review_stale_custody");
        }
        Ok(r.bytes.clone())
    }
}

#[derive(Default)]
pub(super) struct Quarantine {
    records: BTreeMap<String, Record>,
    #[cfg(test)]
    analysis_bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
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
        #[cfg(test)]
        let used = used
            + self
                .analysis_bytes
                .load(std::sync::atomic::Ordering::Acquire);
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
                #[cfg(test)]
                reader_reserved: false,
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

    #[cfg(test)]
    pub(super) fn reader_source(
        &self,
        binding: analysis_purpose::Binding,
    ) -> Result<ReaderSource, &'static str> {
        let record = self
            .records
            .get(&binding.quarantine_id)
            .ok_or("analysis_quarantine_unknown")?;
        if record.terminal || record.reader_reserved {
            return Err("analysis_reader_replay");
        }
        Ok(ReaderSource {
            binding,
            record_hash: hash(&record.bytes),
            deadline: record.expires,
        })
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
                reader_reserved: false,
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

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn reader_was_reserved(&self, id: &str) -> bool {
        self.records
            .get(id)
            .is_some_and(|record| record.reader_reserved)
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn tamper_analysis_fixture(&mut self, id: &str, mode: &str) {
        let record = self.records.get_mut(id).unwrap();
        match mode {
            "taint" => {
                let mut value: Value = serde_json::from_slice(&record.bytes).unwrap();
                value["inspection"]["taint"] = json!([]);
                // Ensure a change even if the fixture's original taint is empty.
                value["inspection"]["findings"] = json!([]);
                value["tampered"] = json!(true);
                record.bytes = serde_json::to_vec(&value).unwrap();
            }
            "epoch" => record.epoch = "foreign-epoch".into(),
            _ => panic!("unknown custody mutation"),
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn analysis_charge(&self) -> usize {
        self.analysis_bytes
            .load(std::sync::atomic::Ordering::Acquire)
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

    fn analysis_record(q: &mut Quarantine, id: &str, length: usize) -> ReaderSource {
        let content = "x".repeat(length);
        let binding:analysis_purpose::Binding=serde_json::from_value(json!({
            "quarantine_id":id,"response_sha256":hash(content.as_bytes()),"response_bytes":length,
            "native_instance":"instance","host_generation":"host","consumer_identity":"consumer",
            "consumer_lifecycle":"generation","session_epoch":"epoch","source_grant_digest":hash(b"grant"),
            "invocation_binding":hash(b"call"),"policy_generation":"policy"
        })).unwrap();
        q.records.insert(id.into(),Record {epoch:"epoch".into(),expires:Instant::now()+Duration::from_secs(30),
            bytes:serde_json::to_vec(&json!({"content":content,"inspection":{"taint":["mcp"],"findings":["retained"]}})).unwrap(),terminal:false,reader_reserved:false});
        let source = q.reader_source(binding).unwrap();
        q.spend(id);
        source
    }

    #[test]
    fn analysis_custody_rechecks_full_record_and_keeps_original_cap() {
        for mode in [
            "valid", "taint", "epoch", "policy", "instance", "expired", "deadline",
        ] {
            let mut q = Quarantine::default();
            let source = analysis_record(&mut q, "q", 262_144);
            let original = q.records["q"].bytes.clone();
            let source = source
                .reserve_analysis(&mut q, "instance", "policy", Instant::now())
                .unwrap();
            assert_eq!(source.bytes.len(), 262_144);
            match mode {
                "taint" => q.records.get_mut("q").unwrap().bytes.push(b' '),
                "epoch" => q.records.get_mut("q").unwrap().epoch = "other".into(),
                "deadline" => q.records.get_mut("q").unwrap().expires += Duration::from_secs(1),
                _ => {}
            }
            let result = source.recheck(
                &q,
                if mode == "instance" {
                    "other"
                } else {
                    "instance"
                },
                if mode == "policy" { "other" } else { "policy" },
                if mode == "expired" {
                    source.selector.deadline
                } else {
                    Instant::now()
                },
            );
            assert_eq!(result.is_ok(), mode == "valid");
            if let Ok(custody) = result {
                assert_eq!(custody, original);
            }
            assert!(q.analysis_bytes.load(std::sync::atomic::Ordering::Acquire) > 0);
            drop(source.lease);
            assert_eq!(
                q.analysis_bytes.load(std::sync::atomic::Ordering::Acquire),
                0
            );
        }
        let mut q = Quarantine::default();
        let legacy = analysis_record(&mut q, "legacy", 4097);
        assert_eq!(
            legacy.reserve(&mut q, "instance", "policy", Instant::now()),
            Err("analysis_reader_source_bytes")
        );
        let large = analysis_record(&mut q, "large", 262_145);
        assert!(matches!(
            large.reserve_analysis(&mut q, "instance", "policy", Instant::now()),
            Err("analysis_reader_source_bytes")
        ));
    }

    #[test]
    fn analysis_custody_charges_concurrent_copies_and_reclaims_on_drop() {
        let mut q = Quarantine::default();
        let selectors: (Vec<_>, Vec<_>) = (0..4)
            .map(|n| {
                let id = format!("q{n}");
                let source = analysis_record(&mut q, &id, 262_144);
                (id, source)
            })
            .unzip();
        let (_, mut sources) = selectors;
        let last = sources.pop().unwrap();
        let mut held = Vec::new();
        for source in sources {
            held.push(
                source
                    .reserve_analysis(&mut q, "instance", "policy", Instant::now())
                    .unwrap(),
            );
        }
        assert!(matches!(
            last.reserve_analysis(&mut q, "instance", "policy", Instant::now()),
            Err("analysis_quarantine_capacity")
        ));
        let charged = q.analysis_bytes.load(std::sync::atomic::Ordering::Acquire);
        held.pop();
        assert!(q.analysis_bytes.load(std::sync::atomic::Ordering::Acquire) < charged);
        drop(held);
        assert_eq!(
            q.analysis_bytes.load(std::sync::atomic::Ordering::Acquire),
            0
        );
        assert!(q.records.values().all(|r| !r.bytes.is_empty()));
    }

    #[test]
    fn reader_reservation_binds_full_custody_deadline_and_one_attempt() {
        for mode in [
            "valid", "unspent", "expired", "restart", "policy", "source", "taint", "epoch",
            "deadline",
        ] {
            let now = Instant::now();
            let binding: analysis_purpose::Binding = serde_json::from_value(json!({
                "quarantine_id":"q", "response_sha256":hash(b"untrusted"), "response_bytes":9,
                "native_instance":"instance", "host_generation":"host", "consumer_identity":"consumer",
                "consumer_lifecycle":"generation", "session_epoch":"epoch", "source_grant_digest":hash(b"grant"),
                "invocation_binding":hash(b"call"), "policy_generation":"policy"
            })).unwrap();
            let mut q = Quarantine::default();
            q.records.insert(
                "q".into(),
                Record {
                    epoch: "epoch".into(),
                    expires: now + Duration::from_secs(30),
                    bytes: serde_json::to_vec(&json!({"content":"untrusted","taint":"retained"}))
                        .unwrap(),
                    terminal: false,
                    reader_reserved: false,
                },
            );
            let source = q.reader_source(binding.clone()).unwrap();
            let duplicate = q.reader_source(binding).unwrap(); // adverse duplicate custody control
            if mode != "unspent" {
                q.spend("q");
            }
            let record = q.records.get_mut("q").unwrap();
            match mode {
                "source" => {
                    record.bytes =
                        serde_json::to_vec(&json!({"content":"substitute","taint":"retained"}))
                            .unwrap()
                }
                "taint" => {
                    record.bytes =
                        serde_json::to_vec(&json!({"content":"untrusted","taint":"cleared"}))
                            .unwrap()
                }
                "epoch" => record.epoch = "other".into(),
                "deadline" => record.expires += Duration::from_secs(1),
                _ => {}
            }
            let before = record.bytes.clone();
            let result = source.reserve(
                &mut q,
                if mode == "restart" {
                    "other"
                } else {
                    "instance"
                },
                if mode == "policy" { "other" } else { "policy" },
                if mode == "expired" {
                    now + Duration::from_secs(30)
                } else {
                    now
                },
            );
            assert_eq!(result.is_ok(), mode == "valid", "{mode}");
            if let Ok(bytes) = result {
                assert_eq!(bytes, b"untrusted");
            }
            assert_eq!(
                duplicate.reserve(&mut q, "instance", "policy", now),
                Err("analysis_reader_replay")
            );
            assert_eq!(
                q.records["q"].bytes, before,
                "retained source must survive transfer"
            );
        }
    }

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
