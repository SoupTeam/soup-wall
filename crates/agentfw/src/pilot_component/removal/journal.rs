// SPDX-License-Identifier: Apache-2.0
//! Append-only exact-object outcomes. An unlink without its durable completion
//! record stays uncertain; missing names never silently become completed work.
use super::{
    canonical, decode, digest, ensure, inventory, processes, same, sha, Budget, Context, Dir,
    Entry, Identity, Plan, Result, Retained, FORMAT, MAX_ENTRIES,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    format: String,
    plan: String,
    directory: Identity,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format: String,
    plan: String,
    index: usize,
    attempt: usize,
    entry_sha256: String,
    phase: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    format: String,
    plan: String,
    success_ack_sha256: String,
}
#[derive(Serialize)]
struct Outcome {
    name: String,
    status: &'static str,
    reason: &'static str,
}
pub(super) struct Journal {
    dir: Dir,
    plan: Plan,
    hash: String,
    success_ack: Option<String>,
}
fn record_name(index: usize, attempt: usize, phase: &str) -> String {
    format!("{index:04}-{attempt}-{phase}.json")
}
fn location(plan: &Plan, e: &Entry) -> Result<(PathBuf, String)> {
    let root = plan.selected.home.join("pilot-front-door");
    if e.name.is_empty() {
        return Ok((plan.selected.home.clone(), "pilot-front-door".into()));
    }
    let path = root.join(&e.name);
    ensure!(
        e.name.len() <= 512
            && !e.name.starts_with('/')
            && e.name
                .split('/')
                .all(|n| !n.is_empty() && n != "." && n != ".."),
        "removal_plan_path_invalid"
    );
    Ok((
        path.parent().context("removal_plan_path_invalid")?.into(),
        path.file_name()
            .and_then(|n| n.to_str())
            .context("removal_plan_path_invalid")?
            .into(),
    ))
}
impl Journal {
    pub fn create(plan: &Plan, hash: &str, b: &mut Budget) -> Result<Self> {
        let raw = canonical(plan)?;
        ensure!(raw.len() <= 144 * 1024, "removal_record_cap");
        crate::private_export::publish(&plan.selected.journal, &[("plan.json", &raw)], || {
            ensure!(
                inventory::preview(&plan.selected, b)? == *plan,
                "removal_stale_confirmation"
            );
            ensure!(
                processes::blockers(plan, b)?.is_empty(),
                "removal_active_or_uncertain"
            );
            Ok(())
        })?;
        let dir = Dir::open(&plan.selected.journal)?;
        dir.write_new(
            "binding.json",
            &canonical(&Binding {
                format: FORMAT.into(),
                plan: hash.into(),
                directory: dir.id.clone(),
            })?,
        )?;
        Self::open(
            &Retained {
                journal: plan.selected.journal.clone(),
                expect_plan: hash.into(),
                success_ack: None,
            },
            b,
        )
    }
    pub fn open(r: &Retained, b: &mut Budget) -> Result<Self> {
        let dir = Dir::open(&r.journal)?;
        let (raw, _) = dir.read("plan.json", 512 * 1024, b)?;
        let plan: Plan = decode(&raw)?;
        ensure!(
            raw == canonical(&plan)?
                && same(&digest(&plan)?, &r.expect_plan)
                && plan.format == FORMAT
                && plan.scope == "verified_front_door_component_only"
                && plan.selected.journal == r.journal
                && !plan.entries.is_empty()
                && plan.entries.len() <= MAX_ENTRIES
                && plan
                    .entries
                    .last()
                    .is_some_and(|e| e.name.is_empty() && e.identity == plan.root),
            "removal_plan_mismatch"
        );
        let parent = Dir::open(r.journal.parent().context("removal_journal_parent")?)?;
        ensure!(
            parent.id.object(&plan.journal_parent),
            "removal_journal_parent_changed"
        );
        let binding: Binding = dir.json("binding.json", 16384, b)?;
        ensure!(
            binding.format == FORMAT
                && same(&binding.plan, &r.expect_plan)
                && binding.directory.object(&dir.id),
            "removal_journal_changed"
        );
        let allowed: BTreeSet<_> = [
            "plan.json".to_string(),
            "binding.json".into(),
            "complete.json".into(),
        ]
        .into_iter()
        .chain((0..plan.entries.len()).flat_map(|i| {
            (0..3).flat_map(move |attempt| {
                ["intent", "done", "failed"].map(move |phase| record_name(i, attempt, phase))
            })
        }))
        .collect();
        ensure!(
            dir.names()?.iter().all(|n| allowed.contains(n)),
            "removal_unknown_journal_entry"
        );
        let journal = Self {
            dir,
            plan,
            hash: r.expect_plan.clone(),
            success_ack: r.success_ack.clone(),
        };
        journal.validate_progress(b)?;
        Ok(journal)
    }
    fn check_record(&self, index: usize, phase: &str, b: &mut Budget) -> Result<bool> {
        let attempt = self.attempt(index)?;
        self.check_at(index, attempt, phase, b)
    }
    fn check_at(&self, index: usize, attempt: usize, phase: &str, b: &mut Budget) -> Result<bool> {
        let name = record_name(index, attempt, phase);
        if self.dir.optional(&name)?.is_none() {
            return Ok(false);
        }
        let value: Record = self.dir.json(&name, 16384, b)?;
        ensure!(
            value.format == FORMAT
                && same(&value.plan, &self.hash)
                && value.index == index
                && value.attempt == attempt
                && value.phase == phase
                && same(
                    &value.entry_sha256,
                    &sha(&canonical(&self.plan.entries[index])?)
                ),
            "removal_progress_invalid"
        );
        Ok(true)
    }
    fn validate_progress(&self, b: &mut Budget) -> Result<()> {
        for index in 0..self.plan.entries.len() {
            let mut previous_failed = false;
            for attempt in 0..3 {
                let intent = self.check_at(index, attempt, "intent", b)?;
                let done = self.check_at(index, attempt, "done", b)?;
                let failed = self.check_at(index, attempt, "failed", b)?;
                ensure!(
                    (intent || (!done && !failed)) && (!intent || attempt == 0 || previous_failed),
                    "removal_progress_invalid"
                );
                previous_failed = intent && failed && !done;
            }
        }
        Ok(())
    }
    fn write_record(&self, index: usize, phase: &str) -> Result<()> {
        self.write_at(index, self.attempt(index)?, phase)
    }
    fn attempt(&self, index: usize) -> Result<usize> {
        for attempt in (0..3).rev() {
            if self
                .dir
                .optional(&record_name(index, attempt, "intent"))?
                .is_some()
            {
                return Ok(attempt);
            }
        }
        Ok(0)
    }
    fn write_at(&self, index: usize, attempt: usize, phase: &str) -> Result<()> {
        ensure!(attempt < 3, "removal_retry_limit");
        self.dir.write_new(
            &record_name(index, attempt, phase),
            &canonical(&Record {
                format: FORMAT.into(),
                plan: self.hash.clone(),
                index,
                attempt,
                entry_sha256: sha(&canonical(&self.plan.entries[index])?),
                phase: phase.into(),
            })?,
        )
    }
    fn inspect(&self, b: &mut Budget) -> Result<Vec<Outcome>> {
        self.dir.recheck()?;
        ensure!(
            Dir::open(&self.plan.selected.home)?
                .id
                .object(&self.plan.home),
            "removal_home_changed"
        );
        let mut rows = vec![];
        for (index, e) in self.plan.entries.iter().enumerate() {
            b.tick(0)?;
            let (parent, leaf) = location(&self.plan, e)?;
            let intent = self.check_record(index, "intent", b)?;
            let done = self.check_record(index, "done", b)?;
            let failed = self.check_record(index, "failed", b)?;
            ensure!(!done || intent, "removal_progress_invalid");
            let named = match Dir::open(&parent) {
                Ok(p) => p.optional(&leaf)?,
                Err(error) => {
                    // A parent removed by this plan must have its own durable
                    // completion. A link/foreign/substituted parent is not absence.
                    if std::fs::symlink_metadata(&parent).is_ok() {
                        return Err(error);
                    }
                    let relative = parent
                        .strip_prefix(self.plan.selected.home.join("pilot-front-door"))
                        .ok()
                        .and_then(|p| p.to_str())
                        .unwrap_or("");
                    let parent_index = self
                        .plan
                        .entries
                        .iter()
                        .position(|e| e.name == relative)
                        .context("removal_parent_unavailable")?;
                    ensure!(
                        self.check_record(parent_index, "done", b)?,
                        "removal_parent_unavailable"
                    );
                    None
                }
            };
            let (status, reason) = match named {
                None if done && !failed => ("removed", "durable_exact_object_completion"),
                None if intent => ("uncertain", "missing_object_without_certain_completion"),
                None => ("uncertain", "object_disappeared_before_intent"),
                Some(now)
                    if done
                        || (if e.identity.directory() {
                            !now.object(&e.identity)
                        } else {
                            now != e.identity
                        }) =>
                {
                    ("retained", "substituted_or_reappeared_object")
                }
                Some(_) if failed => ("failed", "previous_attempt_failed_original_still_present"),
                Some(_) => ("retained", "original_object_present"),
            };
            rows.push(Outcome {
                name: e.name.clone(),
                status,
                reason,
            });
        }
        Ok(rows)
    }
    fn verify_remaining(&self, rows: &[Outcome], b: &mut Budget) -> Result<()> {
        inventory::retained_recheck(&self.plan, b)?;
        for (e, row) in self.plan.entries.iter().zip(rows) {
            ensure!(
                row.reason != "substituted_or_reappeared_object" && row.status != "uncertain",
                "removal_uncertain_or_substituted_object"
            );
            if row.status == "removed" {
                continue;
            }
            let (parent, leaf) = location(&self.plan, e)?;
            let d = Dir::open(&parent)?;
            if e.identity.directory() {
                let child = Dir::open(&parent.join(&leaf))?;
                ensure!(child.id.object(&e.identity), "removal_object_substituted");
                let expected: BTreeSet<_> = self
                    .plan
                    .entries
                    .iter()
                    .zip(rows)
                    .filter(|(_, r)| r.status != "removed")
                    .filter_map(|(entry, _)| location(&self.plan, entry).ok())
                    .filter(|(p, _)| p == &parent.join(&leaf))
                    .map(|(_, n)| n)
                    .collect();
                ensure!(
                    child.names()?.into_iter().collect::<BTreeSet<_>>() == expected,
                    "removal_unexpected_entry"
                );
            } else {
                let (raw, id) = d.read(&leaf, 1024 * 1024, b)?;
                ensure!(
                    id == e.identity && e.sha256.as_ref().is_some_and(|h| same(&sha(&raw), h)),
                    "removal_object_substituted"
                );
            }
        }
        inventory::no_mounts(&self.plan.selected.home.join("pilot-front-door"))?;
        Ok(())
    }
    fn acknowledged(&self, b: &mut Budget) -> Result<bool> {
        if self.dir.optional("complete.json")?.is_none() {
            return Ok(false);
        }
        let c: Completion = self.dir.json("complete.json", 16384, b)?;
        ensure!(
            c.format == FORMAT
                && same(&c.plan, &self.hash)
                && crate::native::is_digest(&c.success_ack_sha256),
            "removal_completion_invalid"
        );
        Ok(self.success_ack.as_ref().is_some_and(|ack| {
            ack.len() == 43 && same(&sha(ack.as_bytes()), &c.success_ack_sha256)
        }))
    }
    fn result(&self, rows: Vec<Outcome>, acknowledged: bool, ack: Option<&str>) -> Value {
        let status = if rows.iter().all(|r| r.status == "removed") && acknowledged {
            "removed"
        } else if rows.iter().any(|r| r.status == "uncertain")
            || rows.iter().all(|r| r.status == "removed")
        {
            "uncertain"
        } else if rows.iter().any(|r| r.status == "failed") {
            "failed"
        } else {
            "retained"
        };
        json!({"format":FORMAT,"status":status,"plan_sha256":self.hash,"scope":self.plan.scope,"objects":rows,
            "success_ack":ack,
            "user_data_retained":true,"agent_entrypoint_retained":true,"processes_stopped":0,"providers_executed":0,
            "recovery":"built_in_agent_pilot_removal_status_or_explicit_resume"})
    }
    pub fn status(&self, b: &mut Budget) -> Result<Value> {
        let _lock = self.dir.lock()?;
        Ok(self.result(self.inspect(b)?, self.acknowledged(b)?, None))
    }
    pub fn apply(&self, b: &mut Budget) -> Result<Value> {
        let _lock = self.dir.lock()?;
        let rows = self.inspect(b)?;
        if rows.iter().all(|r| r.status == "removed") {
            return Ok(self.result(rows, self.acknowledged(b)?, None));
        }
        let installation = Dir::open(&self.plan.selected.home.join("pilot-front-door"))?;
        ensure!(
            installation.id.object(&self.plan.root),
            "removal_object_substituted"
        );
        let _installation_lock = installation.lock()?;
        self.verify_remaining(&rows, b)?;
        ensure!(
            processes::blockers(&self.plan, b)?.is_empty(),
            "removal_active_or_uncertain"
        );
        for (index, (e, row)) in self.plan.entries.iter().zip(&rows).enumerate() {
            if row.status == "removed" {
                continue;
            }
            let (parent, leaf) = location(&self.plan, e)?;
            // The durable intent precedes every unlink. Reusing that intent on
            // resume requires the original full file identity, not its name.
            if row.status == "failed" {
                // Only a still-present exact original can enter another bounded
                // attempt; uncertain/substituted objects fail complete preflight.
                self.write_at(index, self.attempt(index)? + 1, "intent")?;
            }
            if !self.check_record(index, "intent", b)? {
                self.write_record(index, "intent")?;
            }
            let operation = (|| -> Result<()> {
                self.dir.recheck()?;
                inventory::retained_recheck(&self.plan, b)?;
                Dir::open(&parent)?.remove(&leaf, &e.identity, e.sha256.as_deref(), b)?;
                self.write_record(index, "done")
            })();
            if operation.is_err() {
                let _ = self.write_record(index, "failed");
                return Ok(self.result(self.inspect(b)?, false, None));
            }
        }
        let rows = self.inspect(b)?;
        ensure!(
            rows.iter().all(|r| r.status == "removed"),
            "removal_completion_unverified"
        );
        let ack = crate::token::generate();
        self.dir.write_new(
            "complete.json",
            &canonical(&Completion {
                format: FORMAT.into(),
                plan: self.hash.clone(),
                success_ack_sha256: sha(ack.as_bytes()),
            })?,
        )?;
        self.dir.recheck()?;
        Ok(self.result(rows, true, Some(&ack)))
    }
}

#[cfg(test)]
mod tests;
