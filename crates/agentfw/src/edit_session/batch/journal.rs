// SPDX-License-Identifier: Apache-2.0
//! Exact per-member proof custody. A visible receipt alone is not a returned,
//! durable completion. Recovery never invents a withheld acknowledgement.
use super::*;
use crate::mcp::replace_file::Identity;
use std::{collections::BTreeMap, fs::Metadata, io::Write};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Op {
    Apply,
    Revert,
}
impl Op {
    fn name(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Revert => "revert",
        }
    }
}
fn name(op: Op, i: usize, phase: &str) -> String {
    format!("{}-{i:02}-{phase}.json", op.name())
}
fn blob(i: usize) -> String {
    format!("images-{i:02}.bin")
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
    format: String,
    plan: String,
    directory: RootIdentity,
    blobs: Vec<Identity>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Intent {
    format: String,
    plan: String,
    journal: RootIdentity,
    index: usize,
    operation: Op,
    before: Baseline,
    staged: Identity,
    after_sha256: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Done {
    format: String,
    plan: String,
    journal: RootIdentity,
    index: usize,
    operation: Op,
    intent_sha256: String,
    after: Baseline,
    file_synced: bool,
    directory_synced: bool,
    ack_sha256: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Failure {
    format: String,
    plan: String,
    index: usize,
    operation: Op,
    status: String,
}
#[derive(Default, Clone)]
struct Progress {
    intent: Option<Intent>,
    done: Option<Done>,
    failed: bool,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(super) struct Row {
    pub index: usize,
    pub target: String,
    pub status: &'static str,
    pub reason: &'static str,
    current: Option<Baseline>,
}
#[derive(Clone)]
struct Proof {
    index: usize,
    op: Op,
    receipt: String,
    ack: String,
}
fn proof(raw: &str, count: usize) -> Result<Proof> {
    let parts: Vec<_> = raw.split(':').collect();
    ensure!(parts.len() == 4, "edit_batch_proof_invalid");
    let index: usize = parts[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("edit_batch_proof_invalid"))?;
    let op = match parts[1] {
        "apply" => Op::Apply,
        "revert" => Op::Revert,
        _ => anyhow::bail!("edit_batch_proof_invalid"),
    };
    ensure!(
        index < count
            && crate::native::is_digest(parts[2])
            && parts[3].len() == 43
            && parts[3]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "edit_batch_proof_invalid"
    );
    Ok(Proof {
        index,
        op,
        receipt: parts[2].into(),
        ack: parts[3].into(),
    })
}
pub(super) struct Journal {
    pub dir: Dir,
    pub plan: Plan,
    pub id: RootIdentity,
    pub hash: String,
    read: Directory,
    before: Vec<Vec<u8>>,
    after: Vec<Vec<u8>>,
    files: BTreeMap<String, Metadata>,
    applied: Vec<Progress>,
    reverted: Vec<Progress>,
    proofs: Vec<Proof>,
}
impl Journal {
    pub fn retain(p: &mut Proposal, b: &mut Budget) -> Result<Self> {
        let plan = profile::canonical(&p.plan)?;
        ensure!(plan.len() <= 48 * 1024, "edit_batch_plan_cap");
        let mut files = vec![("plan.json".to_string(), plan)];
        for i in 0..p.plan.members.len() {
            files.push((
                blob(i),
                [p.before[i].as_slice(), p.after[i].as_slice()].concat(),
            ));
        }
        let refs: Vec<_> = files
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect();
        crate::private_export::publish(&p.plan.selected.journal, &refs, || {
            source_check(&p.plan, &mut p.source, b)?;
            for m in &p.plan.members {
                let (id, now, _) = snapshot(&p.plan.selected.root, &m.target, b)?;
                ensure!(
                    id == p.plan.root && now == m.before,
                    "edit_batch_target_changed"
                );
            }
            Ok(())
        })?;
        let (read, id) = directory(&p.plan.selected.journal)?;
        let mut blobs = vec![];
        for i in 0..p.plan.members.len() {
            let (_, m) = read
                .read_output(&blob(i), 2 * CAP, b)
                .map_err(anyhow::Error::msg)?
                .context("edit_batch_blob_missing")?;
            blobs.push(single::identity(&m));
        }
        let hash = confirmation(&p.plan)?;
        let binding = Binding {
            format: FORMAT.into(),
            plan: hash.clone(),
            directory: id,
            blobs,
        };
        Dir::open(&p.plan.selected.journal)?
            .write_new("identity.json", &profile::canonical(&binding)?)?;
        Self::open(
            &Retained {
                journal: p.plan.selected.journal.clone(),
                expect_plan: hash,
                proof: vec![],
            },
            b,
        )
    }
    pub fn open(r: &Retained, b: &mut Budget) -> Result<Self> {
        let (read, id) = directory(&r.journal)?;
        let dir = Dir::open(&r.journal)?;
        ensure!(
            dir.identity()? == (id.device, id.inode),
            "edit_batch_journal_changed"
        );
        let mut files = BTreeMap::new();
        let mut load = |name: &str, cap: u64| -> Result<Vec<u8>> {
            let (raw, meta) = read
                .read_output(name, cap, b)
                .map_err(anyhow::Error::msg)?
                .context("edit_batch_journal_incomplete")?;
            files.insert(name.into(), meta);
            Ok(raw)
        };
        let raw = load("plan.json", 48 * 1024)?;
        let plan: Plan = decode(&raw)?;
        validate(&plan)?;
        ensure!(
            raw == profile::canonical(&plan)?
                && same(&confirmation(&plan)?, &r.expect_plan)
                && plan.selected.journal == r.journal,
            "edit_batch_plan_changed"
        );
        let (_, parent) = directory(r.journal.parent().context("edit_batch_journal_parent")?)?;
        ensure!(
            parent == plan.journal_parent,
            "edit_batch_journal_parent_changed"
        );
        let binding: Binding = decode(&load("identity.json", 16384)?)?;
        ensure!(
            binding.format == FORMAT
                && same(&binding.plan, &r.expect_plan)
                && binding.directory == id
                && binding.blobs.len() == plan.members.len(),
            "edit_batch_journal_changed"
        );
        let (mut before, mut after) = (vec![], vec![]);
        for (i, m) in plan.members.iter().enumerate() {
            let n = blob(i);
            let bytes = load(&n, 2 * CAP)?;
            let split = m.before.identity.size as usize;
            ensure!(
                bytes.len() == split + m.after_bytes,
                "edit_batch_blob_changed"
            );
            let (old, new) = bytes.split_at(split);
            ensure!(
                same(&audit::sha(old), &m.before.sha256)
                    && same(&audit::sha(new), &m.after_sha256)
                    && std::str::from_utf8(old).is_ok()
                    && std::str::from_utf8(new).is_ok(),
                "edit_batch_blob_changed"
            );
            before.push(old.to_vec());
            after.push(new.to_vec());
        }
        drop(load);
        for (i, expected) in binding.blobs.iter().enumerate() {
            ensure!(
                files
                    .get(&blob(i))
                    .is_some_and(|m| single::identity(m) == *expected),
                "edit_batch_blob_changed"
            );
        }
        let count = plan.members.len();
        let mut j = Self {
            dir,
            plan,
            id,
            hash: r.expect_plan.clone(),
            read,
            before,
            after,
            files,
            applied: vec![Progress::default(); count],
            reverted: vec![Progress::default(); count],
            proofs: vec![],
        };
        let mut seen = BTreeSet::new();
        ensure!(r.proof.len() <= 2 * count, "edit_batch_proof_invalid");
        for raw in &r.proof {
            let p = proof(raw, count)?;
            ensure!(
                seen.insert((p.index, p.op.name())),
                "edit_batch_proof_duplicate"
            );
            j.proofs.push(p);
        }
        for op in [Op::Apply, Op::Revert] {
            for i in 0..count {
                let intent = j.optional::<Intent>(&name(op, i, "intent"), b)?;
                let done = j.optional::<Done>(&name(op, i, "done"), b)?;
                let failure = j.optional::<Failure>(&name(op, i, "failed"), b)?;
                if let Some(f) = &failure {
                    ensure!(
                        f.format == FORMAT
                            && same(&f.plan, &j.hash)
                            && f.index == i
                            && f.operation == op
                            && f.status == "uncertain",
                        "edit_batch_progress_invalid"
                    );
                }
                let pg = Progress {
                    intent,
                    done,
                    failed: failure.is_some(),
                };
                j.check_progress(i, op, &pg)?;
                if op == Op::Apply {
                    j.applied[i] = pg
                } else {
                    j.reverted[i] = pg
                }
            }
        }
        j.recheck(b)?;
        Ok(j)
    }
    fn optional<T: serde::de::DeserializeOwned>(
        &mut self,
        n: &str,
        b: &mut Budget,
    ) -> Result<Option<T>> {
        let value = self
            .read
            .read_output(n, 16384, b)
            .map_err(anyhow::Error::msg)?;
        value
            .map(|(raw, m)| {
                self.files.insert(n.into(), m);
                decode(&raw)
            })
            .transpose()
    }
    fn check_progress(&self, i: usize, op: Op, p: &Progress) -> Result<()> {
        if p.intent.is_none() && p.done.is_none() && !p.failed {
            return Ok(());
        }
        let m = &self.plan.members[i];
        let prior = &self.applied[i];
        let before = if op == Op::Apply {
            &m.before
        } else {
            &prior
                .done
                .as_ref()
                .context("edit_batch_revert_without_apply")?
                .after
        };
        if let Some(intent) = &p.intent {
            ensure!(
                intent.format == FORMAT
                    && same(&intent.plan, &self.hash)
                    && intent.journal == self.id
                    && intent.index == i
                    && intent.operation == op
                    && &intent.before == before
                    && same(
                        &intent.after_sha256,
                        if op == Op::Apply {
                            &m.after_sha256
                        } else {
                            &m.before.sha256
                        }
                    ),
                "edit_batch_progress_invalid"
            );
        }
        if let Some(done) = &p.done {
            let intent = p
                .intent
                .as_ref()
                .context("edit_batch_receipt_without_intent")?;
            ensure!(
                done.format == FORMAT
                    && same(&done.plan, &self.hash)
                    && done.journal == self.id
                    && done.index == i
                    && done.operation == op
                    && same(
                        &done.intent_sha256,
                        &digest(b"agentfw/edit-batch-intent/v1\0", intent)?
                    )
                    && done.file_synced
                    && done.directory_synced
                    && crate::native::is_digest(&done.ack_sha256)
                    && same(&done.after.sha256, &intent.after_sha256)
                    && done.after.identity.device == intent.staged.device
                    && done.after.identity.inode == intent.staged.inode
                    && done.after.identity.size == intent.staged.size
                    && done.after.identity.uid == before.identity.uid
                    && done.after.identity.gid == before.identity.gid
                    && done.after.identity.mode == before.identity.mode,
                "edit_batch_progress_invalid"
            );
        }
        Ok(())
    }
    pub fn recheck(&self, _b: &mut Budget) -> Result<()> {
        self.read
            .check_path(&self.plan.selected.journal)
            .map_err(anyhow::Error::msg)?;
        for (n, m) in &self.files {
            self.read.check_file(n, m).map_err(anyhow::Error::msg)?;
        }
        let mut names = BTreeSet::new();
        let mut entries = self.read.entries().map_err(anyhow::Error::msg)?;
        while let Some(n) = entries.next().map_err(anyhow::Error::msg)? {
            ensure!(names.len() < 80, "edit_batch_journal_cap");
            let n =
                String::from_utf8(n).map_err(|_| anyhow::anyhow!("edit_batch_journal_unknown"))?;
            names.insert(n);
        }
        ensure!(
            names == self.files.keys().cloned().collect(),
            "edit_batch_journal_unknown"
        );
        Ok(())
    }
    pub fn progress_hash(&self) -> Result<String> {
        let rows: Vec<_> = self
            .files
            .iter()
            .map(|(n, m)| json!({"name":n,"identity":single::identity(m)}))
            .collect();
        digest(b"agentfw/edit-batch-progress/v1\0", &rows)
    }
    fn write<T: Serialize>(&mut self, n: &str, value: &T, b: &mut Budget) -> Result<()> {
        self.recheck(b)?;
        self.dir.write_new(n, &profile::canonical(value)?)?;
        let (_, m) = self
            .read
            .read_output(n, 16384, b)
            .map_err(anyhow::Error::msg)?
            .context("edit_batch_progress_missing")?;
        self.files.insert(n.into(), m);
        Ok(())
    }
    fn proven(&self, i: usize, op: Op, p: &Progress) -> Result<bool> {
        if p.failed {
            return Ok(false);
        }
        let Some(done) = &p.done else {
            return Ok(false);
        };
        let hash = digest(b"agentfw/edit-batch-receipt/v1\0", done)?;
        Ok(self.proofs.iter().any(|x| {
            x.index == i
                && x.op == op
                && same(&x.receipt, &hash)
                && same(&audit::sha(x.ack.as_bytes()), &done.ack_sha256)
        }))
    }
    pub fn inspect(&self, b: &mut Budget) -> Result<Vec<Row>> {
        self.recheck(b)?;
        let mut rows = vec![];
        for (i, m) in self.plan.members.iter().enumerate() {
            let observed = snapshot(&self.plan.selected.root, &m.target, b).ok();
            let current = observed
                .filter(|(id, _, _)| id == &self.plan.root)
                .map(|(_, now, _)| now);
            let a = &self.applied[i];
            let r = &self.reverted[i];
            let (status, reason) = if r.intent.is_some() || r.done.is_some() || r.failed {
                if self.proven(i, Op::Revert, r)?
                    && r.done
                        .as_ref()
                        .is_some_and(|d| current.as_ref() == Some(&d.after))
                {
                    ("reverted", "returned_exact_revert_completion")
                } else {
                    ("uncertain", "revert_or_current_identity_unproven")
                }
            } else if a.intent.is_some() || a.done.is_some() || a.failed {
                if self.proven(i, Op::Apply, a)?
                    && a.done
                        .as_ref()
                        .is_some_and(|d| current.as_ref() == Some(&d.after))
                {
                    ("applied", "returned_exact_apply_completion")
                } else if a.failed && a.intent.is_none() && current.as_ref() == Some(&m.before) {
                    ("failed", "prepublication_failed_original_unchanged")
                } else {
                    ("uncertain", "publication_or_current_identity_unproven")
                }
            } else if current.as_ref() == Some(&m.before) {
                ("untouched", "exact_original_without_publication_intent")
            } else {
                ("uncertain", "original_missing_or_changed")
            };
            rows.push(Row {
                index: i,
                target: m.target.clone(),
                status,
                reason,
                current,
            });
        }
        Ok(rows)
    }
    pub fn response(&self, b: &mut Budget) -> Result<Value> {
        let rows = self.inspect(b)?;
        let status = if rows.iter().all(|r| r.status == "applied") {
            "applied"
        } else if rows.iter().all(|r| r.status == "reverted") {
            "reverted"
        } else if rows.iter().any(|r| r.status == "uncertain") {
            "partial_or_uncertain"
        } else if rows.iter().any(|r| r.status == "failed") {
            "partial_or_failed"
        } else {
            "partial"
        };
        Ok(
            json!({"format":FORMAT,"status":status,"plan_sha256":self.hash,"files":rows,"proofs":self.proofs.iter().map(|p|format!("{}:{}:{}:{}",p.index,p.op.name(),p.receipt,p.ack)).collect::<Vec<_>>(),"global_atomicity":false,"automatic_rollback":false,"authority":false,"operator_provider_requests":0}),
        )
    }
    fn publish(
        &mut self,
        i: usize,
        op: Op,
        b: &mut Budget,
        gate: impl FnOnce(&Self, &mut Budget) -> Result<()>,
    ) -> Result<()> {
        let m = &self.plan.members[i];
        let before = if op == Op::Apply {
            m.before.clone()
        } else {
            self.applied[i]
                .done
                .as_ref()
                .context("edit_batch_apply_unproven")?
                .after
                .clone()
        };
        let content = if op == Op::Apply {
            &self.after[i]
        } else {
            &self.before[i]
        };
        let stage = replace_file::Prepared::prepare(
            &self.plan.selected.root,
            &self.plan.selected.root.join(&m.target),
            &self.plan.root,
            &before.identity,
            &before.sha256,
            std::str::from_utf8(content)?,
        )?
        .stage()?;
        let intent = Intent {
            format: FORMAT.into(),
            plan: self.hash.clone(),
            journal: self.id.clone(),
            index: i,
            operation: op,
            before,
            staged: stage.staged_identity()?,
            after_sha256: audit::sha(content),
        };
        let len = content.len();
        self.write(&name(op, i, "intent"), &intent, b)?;
        if op == Op::Apply {
            self.applied[i].intent = Some(intent.clone())
        } else {
            self.reverted[i].intent = Some(intent.clone())
        }
        self.recheck(b)?;
        gate(self, b)?;
        let commit = stage.publish_before(Instant::now() + Duration::from_secs(10))?;
        ensure!(
            commit.committed
                && commit.file_synced
                && commit.directory_synced
                && commit.bytes_written == len,
            "edit_batch_commit_unconfirmed"
        );
        let (id, after, bytes) =
            snapshot(&self.plan.selected.root, &self.plan.members[i].target, b)?;
        ensure!(
            id == self.plan.root
                && after.identity.device == intent.staged.device
                && after.identity.inode == intent.staged.inode
                && same(&audit::sha(&bytes), &intent.after_sha256),
            "edit_batch_commit_changed"
        );
        let ack = crate::token::generate();
        let done = Done {
            format: FORMAT.into(),
            plan: self.hash.clone(),
            journal: self.id.clone(),
            index: i,
            operation: op,
            intent_sha256: digest(b"agentfw/edit-batch-intent/v1\0", &intent)?,
            after,
            file_synced: true,
            directory_synced: true,
            ack_sha256: audit::sha(ack.as_bytes()),
        };
        self.write(&name(op, i, "done"), &done, b)?;
        let proof = Proof {
            index: i,
            op,
            receipt: digest(b"agentfw/edit-batch-receipt/v1\0", &done)?,
            ack,
        };
        if op == Op::Apply {
            self.applied[i].done = Some(done)
        } else {
            self.reverted[i].done = Some(done)
        }
        self.proofs.push(proof.clone());
        self.recheck(b)?;
        // Stream custody only AFTER all completion syncs. A kill or stdout error
        // before this delivery cannot be repaired from the on-disk hash.
        println!(
            "{}",
            json!({"format":FORMAT,"status":"member_completed","index":i,"operation":op,"proof":format!("{}:{}:{}:{}",i,op.name(),proof.receipt,proof.ack)})
        );
        std::io::stdout().flush()?;
        Ok(())
    }
    fn failed(&mut self, i: usize, op: Op, b: &mut Budget) {
        let f = Failure {
            format: FORMAT.into(),
            plan: self.hash.clone(),
            index: i,
            operation: op,
            status: "uncertain".into(),
        };
        // If a prior write was only partially visible, retain it and refuse future
        // mutation rather than overwriting any evidence.
        let _ = self.write(&name(op, i, "failed"), &f, b);
        if op == Op::Apply {
            self.applied[i].failed = true
        } else {
            self.reverted[i].failed = true
        }
    }
    fn guard_targets(&self, rows: &[Row], b: &mut Budget) -> Result<()> {
        for (m, r) in self.plan.members.iter().zip(rows) {
            let now = snapshot(&self.plan.selected.root, &m.target, b)
                .ok()
                .filter(|(id, _, _)| id == &self.plan.root)
                .map(|(_, v, _)| v);
            ensure!(r.current == now, "edit_batch_target_changed");
        }
        Ok(())
    }
    fn completed_row(&self, i: usize, op: Op) -> Result<Row> {
        let p = if op == Op::Apply {
            &self.applied[i]
        } else {
            &self.reverted[i]
        };
        let done = p.done.as_ref().context("edit_batch_commit_unconfirmed")?;
        Ok(Row {
            index: i,
            target: self.plan.members[i].target.clone(),
            status: if op == Op::Apply {
                "applied"
            } else {
                "reverted"
            },
            reason: if op == Op::Apply {
                "returned_exact_apply_completion"
            } else {
                "returned_exact_revert_completion"
            },
            current: Some(done.after.clone()),
        })
    }
    pub fn apply(&mut self, source: &mut SelectedOutput, b: &mut Budget) -> Result<Value> {
        let mut rows = self.inspect(b)?;
        ensure!(
            rows.iter().all(|r| r.status == "untouched"),
            "edit_batch_apply_no_retry"
        );
        // Full private pre/postimage set was synchronized by retain before this loop.
        for i in 0..self.plan.members.len() {
            let result = (|| {
                self.guard_targets(&rows, b)?;
                self.publish(i, Op::Apply, b, |j, b| {
                    source_check(&j.plan, source, b)?;
                    j.guard_targets(&rows, b)
                })
            })();
            if result.is_err() {
                self.failed(i, Op::Apply, b);
                return self.response(b);
            }
            rows[i] = self.completed_row(i, Op::Apply)?;
        }
        self.response(b)
    }
    pub fn restore(
        &mut self,
        source: &mut SelectedOutput,
        eligible: &[usize],
        b: &mut Budget,
    ) -> Result<Value> {
        let mut rows = self.inspect(b)?;
        for &i in eligible {
            let result = (|| {
                self.guard_targets(&rows, b)?;
                ensure!(rows[i].status == "applied", "edit_batch_apply_unproven");
                self.publish(i, Op::Revert, b, |j, b| {
                    source_check(&j.plan, source, b)?;
                    j.guard_targets(&rows, b)
                })
            })();
            if result.is_err() {
                self.failed(i, Op::Revert, b);
                return self.response(b);
            }
            rows[i] = self.completed_row(i, Op::Revert)?;
        }
        self.response(b)
    }
}
#[cfg(test)]
mod tests;
