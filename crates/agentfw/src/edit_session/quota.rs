// SPDX-License-Identifier: Apache-2.0
//! Run-local ceilings, never execution authority. An admitted reservation is
//! monotone: a failed/withheld/cancelled operation cannot refill an active run.
use anyhow::{ensure, Result};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;

pub const CONTRACT: &str = "sw-installed-edit-mutation-quota/1";
const MAX_MUTATIONS: u64 = 64;
const MAX_BYTES: u64 = MAX_MUTATIONS * crate::mcp::replace_file::MAX_BYTES as u64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub contract_version: String,
    pub max_mutations: u64,
    pub max_write_bytes: u64,
}
impl Limits {
    #[cfg(any(test, target_os = "linux"))]
    pub fn new(max_mutations: u64, max_write_bytes: u64) -> Result<Self> {
        let value = Self {
            contract_version: CONTRACT.into(),
            max_mutations,
            max_write_bytes,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.contract_version == CONTRACT
                && self.max_mutations <= MAX_MUTATIONS
                && self.max_write_bytes <= MAX_BYTES,
            "edit_quota_limits_invalid"
        );
        Ok(())
    }
}
/// A missing legacy field is supported; explicit null is not a budget.
pub(super) fn present<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Limits>, D::Error> {
    Limits::deserialize(d).map(Some)
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub limits: Limits,
    pub admitted_mutation_attempts: u64,
    pub charged_write_bytes: u64,
    pub known_committed_mutations: u64,
    pub known_committed_write_bytes: u64,
    pub known_not_committed_mutations: u64,
    pub indeterminate_publications: u64,
    pub pending_prepublication_attempts: u64,
    pub remaining_mutations: u64,
    pub remaining_write_bytes: u64,
}

#[derive(Debug)]
pub(crate) struct Refusal {
    pub code: &'static str,
    pub usage: Option<Box<Snapshot>>,
}
impl Refusal {
    pub fn response(&self, id: &Value) -> Vec<u8> {
        let detail = json!({"error_code":self.code,"mutation_quota":self.usage,
            "next_action":"inspect_output_then_explicit_prepare_and_new_run_with_fresh_ask",
            "automatic_retry":false,"active_run_reset_available":false});
        let mut raw = json!({"jsonrpc":"2.0","id":id,"result":{"isError":true,
            "content":[{"type":"text","text":detail.to_string()}]}})
        .to_string()
        .into_bytes();
        raw.push(b'\n');
        raw
    }
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for Refusal {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserved,
    Publishing,
    Committed,
    NotCommitted,
    Indeterminate,
}
struct Entry {
    bytes: u64,
    phase: Phase,
}

pub(crate) struct Ledger {
    limits: Limits,
    registry_sha256: String,
    host: String,
    entries: Mutex<BTreeMap<String, Entry>>,
}
impl Ledger {
    #[cfg(any(test, target_os = "linux"))]
    pub fn new(limits: Limits, registry_sha256: String, host: String) -> Result<Arc<Self>> {
        limits.validate()?;
        ensure!(
            crate::native::is_digest(&registry_sha256) && crate::native::identifier(&host),
            "edit_quota_scope_invalid"
        );
        Ok(Arc::new(Self {
            limits,
            registry_sha256,
            host,
            entries: Mutex::new(BTreeMap::new()),
        }))
    }
    fn usage(&self, entries: &BTreeMap<String, Entry>) -> Snapshot {
        let charged = entries.values().map(|e| e.bytes).sum::<u64>();
        let committed = entries.values().filter(|e| e.phase == Phase::Committed);
        Snapshot {
            limits: self.limits.clone(),
            admitted_mutation_attempts: entries.len() as u64,
            charged_write_bytes: charged,
            known_committed_mutations: committed.clone().count() as u64,
            known_committed_write_bytes: committed.map(|e| e.bytes).sum(),
            known_not_committed_mutations: entries
                .values()
                .filter(|e| e.phase == Phase::NotCommitted)
                .count() as u64,
            indeterminate_publications: entries
                .values()
                .filter(|e| matches!(e.phase, Phase::Publishing | Phase::Indeterminate))
                .count() as u64,
            pending_prepublication_attempts: entries
                .values()
                .filter(|e| e.phase == Phase::Reserved)
                .count() as u64,
            remaining_mutations: self.limits.max_mutations - entries.len() as u64,
            remaining_write_bytes: self.limits.max_write_bytes - charged,
        }
    }
    #[cfg(any(test, target_os = "linux"))]
    pub fn snapshot(&self) -> std::result::Result<Snapshot, Refusal> {
        self.entries
            .lock()
            .map(|e| self.usage(&e))
            .map_err(|_| Refusal {
                code: "edit_quota_state_unavailable",
                usage: None,
            })
    }
    pub fn reserve(
        self: &Arc<Self>,
        registry: &str,
        host: Option<&str>,
        call: &str,
        binding: &str,
        bytes: u64,
    ) -> std::result::Result<Ticket, Refusal> {
        let mut entries = self.entries.lock().map_err(|_| Refusal {
            code: "edit_quota_state_unavailable",
            usage: None,
        })?;
        let before = self.usage(&entries);
        let reject = |code| Refusal {
            code,
            usage: Some(Box::new(before.clone())),
        };
        if !bool::from(registry.as_bytes().ct_eq(self.registry_sha256.as_bytes()))
            || host != Some(self.host.as_str())
            || !crate::native::identifier(call)
            || !crate::native::is_digest(binding)
        {
            return Err(reject("edit_quota_scope_mismatch"));
        }
        // The native call is single-use even if a replay changes its binding.
        let key = crate::mcp::replace_file::content_sha256(
            format!("agentfw/edit-quota-call/v1\0{call}").as_bytes(),
        );
        if entries.contains_key(&key) {
            return Err(reject("edit_quota_request_replayed"));
        }
        if before.remaining_mutations == 0 {
            return Err(reject("edit_quota_mutation_limit"));
        }
        if bytes > before.remaining_write_bytes {
            return Err(reject("edit_quota_write_byte_limit"));
        }
        // Full byte and operation charges are permanent even on known failure.
        // This also bounds detached staging workers without speculative refunds.
        entries.insert(
            key.clone(),
            Entry {
                bytes,
                phase: Phase::Reserved,
            },
        );
        self.emit("reserved", &self.usage(&entries));
        Ok(Ticket {
            ledger: self.clone(),
            key,
            settled: false,
        })
    }
    fn emit(&self, event: &str, usage: &Snapshot) {
        eprintln!(
            "{}",
            json!({"event":"edit_mutation_quota","transition":event,
            "registry_sha256":self.registry_sha256,"usage":usage})
        );
    }
}

/// Affine bookkeeping for the existing broker. This value cannot execute or
/// authorize anything; publication still needs all original native gates.
#[must_use]
pub(crate) struct Ticket {
    ledger: Arc<Ledger>,
    key: String,
    settled: bool,
}
impl Ticket {
    pub fn begin_publication(&mut self) -> std::result::Result<(), Refusal> {
        let mut entries = self.ledger.entries.lock().map_err(|_| Refusal {
            code: "edit_quota_state_unavailable",
            usage: None,
        })?;
        let entry = entries.get_mut(&self.key).expect("reserved quota entry");
        if entry.phase != Phase::Reserved {
            return Err(Refusal {
                code: "edit_quota_reservation_spent",
                usage: Some(Box::new(self.ledger.usage(&entries))),
            });
        }
        entry.phase = Phase::Publishing;
        self.ledger.emit(
            "publication_indeterminate_until_completion",
            &self.ledger.usage(&entries),
        );
        Ok(())
    }
    pub fn complete(mut self, committed: bool) -> std::result::Result<(), Refusal> {
        self.settle(Some(committed))?;
        self.settled = true;
        Ok(())
    }
    fn settle(&self, committed: Option<bool>) -> std::result::Result<(), Refusal> {
        let mut entries = self.ledger.entries.lock().map_err(|_| Refusal {
            code: "edit_quota_state_unavailable",
            usage: None,
        })?;
        let entry = entries.get_mut(&self.key).expect("reserved quota entry");
        entry.phase = match (entry.phase, committed) {
            (Phase::Publishing, Some(true)) => Phase::Committed,
            (Phase::Reserved | Phase::Publishing, Some(false)) => Phase::NotCommitted,
            (Phase::Reserved, None) => Phase::NotCommitted,
            (Phase::Publishing, None) => Phase::Indeterminate,
            _ => {
                return Err(Refusal {
                    code: "edit_quota_reservation_spent",
                    usage: Some(Box::new(self.ledger.usage(&entries))),
                })
            }
        };
        self.ledger.emit("settled", &self.ledger.usage(&entries));
        Ok(())
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self.settle(None);
        }
    }
}

#[cfg(test)]
mod tests;
