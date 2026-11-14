// SPDX-License-Identifier: Apache-2.0
//! Bounded append-only private publication records. An incomplete attempt is
//! never resumed, and current bytes alone cannot establish a successful call.
use super::{
    audit, confirmation, decode, digest, directory, identity, profile, recheck_source,
    recheck_target, same, snapshot, Baseline, Budget, Directory, Plan, Proposal, RootIdentity,
    SelectedOutput, CAP, FORMAT,
};
use crate::{
    edit_session::control_io::Dir,
    mcp::replace_file::{self, Identity},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct JournalIdentity {
    format: String,
    pub(super) plan: String,
    pub(super) directory: RootIdentity,
    preimage: Identity,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Operation {
    Apply,
    Revert,
}
impl Operation {
    fn intent(self) -> &'static str {
        match self {
            Self::Apply => "apply-intent.json",
            Self::Revert => "revert-intent.json",
        }
    }
    fn receipt(self) -> &'static str {
        match self {
            Self::Apply => "applied.json",
            Self::Revert => "reverted.json",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    format: String,
    operation: Operation,
    pub(super) plan: String,
    journal: RootIdentity,
    before: Baseline,
    staged: Identity,
    after_sha256: String,
    previous_receipt: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    format: String,
    operation: Operation,
    pub(super) plan: String,
    journal: RootIdentity,
    intent_sha256: String,
    pub(super) after: Baseline,
    file_synced: bool,
    directory_synced: bool,
    success_ack_sha256: String,
}
pub(super) struct Published {
    pub(super) receipt: Receipt,
    pub(super) success_ack: String,
}
pub(super) fn receipt_digest(r: &Receipt) -> Result<String> {
    digest(b"agentfw/edit-application-receipt/v1\0", r)
}
pub(super) struct Journal {
    path: PathBuf,
    pub(super) dir: Dir,
    read: Directory,
    pub(super) plan: Plan,
    pub(super) identity: JournalIdentity,
    pub(super) before: Vec<u8>,
}
impl Journal {
    pub(super) fn open(path: &Path, expected: &str, budget: &mut Budget) -> Result<Self> {
        let (read, id) = directory(path)?;
        let dir = Dir::open(path)?;
        ensure!(
            dir.identity()? == (id.device, id.inode),
            "edit_apply_journal_changed"
        );
        let plan_raw = read
            .read_output("plan.json", 16384, budget)
            .map_err(anyhow::Error::msg)?
            .context("edit_apply_journal_incomplete")?
            .0;
        let plan: Plan = decode(&plan_raw)?;
        ensure!(
            profile::canonical(&plan)? == plan_raw
                && same(&confirmation(&plan)?, expected)
                && plan.selected.journal == path
                && plan.operator_uid == unsafe { libc::geteuid() }
                && plan.format == FORMAT
                && plan.writer_exclusion == replace_file::EXCLUSION,
            "edit_apply_journal_plan_mismatch"
        );
        let (before, meta) = read
            .read_output("preimage.bin", CAP, budget)
            .map_err(anyhow::Error::msg)?
            .context("edit_apply_backup_missing")?;
        ensure!(
            before.len() as u64 == plan.before.identity.size
                && same(&audit::sha(&before), &plan.before.sha256),
            "edit_apply_backup_changed"
        );
        let record = read
            .read_output("identity.json", 16384, budget)
            .map_err(anyhow::Error::msg)?
            .context("edit_apply_journal_incomplete")?
            .0;
        let identity: JournalIdentity = decode(&record)?;
        ensure!(
            identity.format == FORMAT
                && same(&identity.plan, expected)
                && identity.directory == id
                && identity.preimage == self::identity(&meta),
            "edit_apply_journal_identity_changed"
        );
        Ok(Self {
            path: path.into(),
            dir,
            read,
            plan,
            identity,
            before,
        })
    }
    fn optional<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
        budget: &mut Budget,
    ) -> Result<Option<T>> {
        self.read
            .read_output(name, 16384, budget)
            .map_err(anyhow::Error::msg)?
            .map(|(raw, _)| decode(&raw))
            .transpose()
    }
    pub(super) fn recheck(&self, budget: &mut Budget) -> Result<()> {
        let current = Self::open(&self.path, &self.identity.plan, budget)?;
        ensure!(
            current.identity == self.identity
                && current.plan == self.plan
                && current.before == self.before,
            "edit_apply_journal_changed"
        );
        Ok(())
    }
    fn receipt(
        &self,
        op: Operation,
        previous: Option<&Receipt>,
        budget: &mut Budget,
    ) -> Result<Option<Receipt>> {
        let intent: Option<Intent> = self.optional(op.intent(), budget)?;
        let receipt: Option<Receipt> = self.optional(op.receipt(), budget)?;
        let Some(receipt) = receipt else {
            return Ok(None);
        };
        let intent = intent.context("edit_apply_receipt_without_intent")?;
        let before = previous.map_or(&self.plan.before, |r| &r.after);
        let after_digest = match op {
            Operation::Apply => &self.plan.after_sha256,
            Operation::Revert => &self.plan.before.sha256,
        };
        let after_bytes = match op {
            Operation::Apply => self.plan.after_bytes as u64,
            Operation::Revert => self.plan.before.identity.size,
        };
        let previous_hash = previous.map(receipt_digest).transpose()?;
        ensure!(
            intent.format == FORMAT
                && receipt.format == FORMAT
                && intent.operation == op
                && receipt.operation == op
                && intent.before == *before
                && intent.previous_receipt == previous_hash
                && same(&intent.plan, &self.identity.plan)
                && same(&receipt.plan, &self.identity.plan)
                && intent.journal == self.identity.directory
                && receipt.journal == self.identity.directory
                && same(&intent.after_sha256, after_digest)
                && same(&receipt.after.sha256, after_digest)
                && receipt.after.identity.device == intent.staged.device
                && receipt.after.identity.inode == intent.staged.inode
                && receipt.after.identity.size == after_bytes
                && intent.staged.size == after_bytes
                && receipt.after.identity.mode == before.identity.mode
                && receipt.after.identity.uid == before.identity.uid
                && receipt.after.identity.gid == before.identity.gid
                && receipt.file_synced
                && receipt.directory_synced
                && crate::native::is_digest(&receipt.success_ack_sha256)
                && same(
                    &receipt.intent_sha256,
                    &digest(b"agentfw/edit-application-intent/v1\0", &intent)?
                ),
            "edit_apply_receipt_invalid"
        );
        Ok(Some(receipt))
    }
    pub(super) fn acknowledged(
        &self,
        expected: Option<&str>,
        success_ack: Option<&str>,
        budget: &mut Budget,
    ) -> Result<(Operation, Receipt)> {
        let error: Option<Failure> = self.optional("indeterminate.json", budget)?;
        ensure!(error.is_none(), "edit_apply_interrupted_or_uncertain");
        let applied = self
            .receipt(Operation::Apply, None, budget)?
            .context("edit_apply_no_complete_receipt")?;
        let intent: Option<Intent> = self.optional(Operation::Revert.intent(), budget)?;
        let (op, receipt) = if intent.is_some() {
            (
                Operation::Revert,
                self.receipt(Operation::Revert, Some(&applied), budget)?
                    .context("edit_apply_revert_interrupted")?,
            )
        } else {
            ensure!(
                self.optional::<Receipt>(Operation::Revert.receipt(), budget)?
                    .is_none(),
                "edit_apply_receipt_without_intent"
            );
            (Operation::Apply, applied)
        };
        let recorded_digest = receipt_digest(&receipt)?;
        ensure!(
            expected.is_some_and(|e| same(e, &recorded_digest)),
            "edit_apply_successful_command_receipt_required"
        );
        ensure!(
            success_ack.is_some_and(|ack| ack.len() == 43
                && same(&audit::sha(ack.as_bytes()), &receipt.success_ack_sha256)),
            "edit_apply_successful_command_ack_required"
        );
        recheck_target(&self.plan, &receipt.after, budget)?;
        Ok((op, receipt))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Failure {
    format: String,
    operation: Operation,
    pub(super) plan: String,
    status: String,
}

pub(super) fn retain(proposal: &Proposal, budget: &mut Budget) -> Result<Journal> {
    let plan = &proposal.plan;
    let bytes = profile::canonical(plan)?;
    ensure!(bytes.len() <= 16384, "edit_apply_plan_cap");
    crate::private_export::publish(
        &plan.selected.journal,
        &[("plan.json", &bytes), ("preimage.bin", &proposal.before)],
        || {
            recheck_source(plan, &proposal.source, budget)?;
            recheck_target(plan, &plan.before, budget)
        },
    )?;
    let (read, id) = directory(&plan.selected.journal)?;
    let (_, meta) = read
        .read_output("preimage.bin", CAP, budget)
        .map_err(anyhow::Error::msg)?
        .context("edit_apply_backup_missing")?;
    let dir = Dir::open(&plan.selected.journal)?;
    let identity = JournalIdentity {
        format: FORMAT.into(),
        plan: confirmation(plan)?,
        directory: id,
        preimage: self::identity(&meta),
    };
    dir.write_new("identity.json", &profile::canonical(&identity)?)?;
    let result = Journal::open(&plan.selected.journal, &identity.plan, budget)?;
    ensure!(
        result.plan == *plan && result.before == proposal.before,
        "edit_apply_journal_changed"
    );
    Ok(result)
}
pub(super) fn publish(
    journal: &Journal,
    source: &SelectedOutput,
    operation: Operation,
    before: &Baseline,
    content: &str,
    previous: Option<&Receipt>,
    budget: &mut Budget,
) -> Result<Published> {
    let plan = &journal.plan;
    let result = (|| {
        let deadline = Instant::now() + Duration::from_secs(10);
        journal.recheck(budget)?;
        recheck_source(plan, source, budget)?;
        recheck_target(plan, before, budget)?;
        let staged = replace_file::Prepared::prepare(
            &plan.selected.root,
            &plan.selected.root.join(&plan.selected.target),
            &plan.root_identity,
            &before.identity,
            &before.sha256,
            content,
        )?
        .stage()?;
        let staged_identity = staged.staged_identity()?;
        let intent = Intent {
            format: FORMAT.into(),
            operation,
            plan: journal.identity.plan.clone(),
            journal: journal.identity.directory.clone(),
            before: before.clone(),
            staged: staged_identity.clone(),
            after_sha256: audit::sha(content.as_bytes()),
            previous_receipt: previous.map(receipt_digest).transpose()?,
        };
        journal
            .dir
            .write_new(operation.intent(), &profile::canonical(&intent)?)?;
        journal.recheck(budget)?;
        recheck_source(plan, source, budget)?;
        recheck_target(plan, before, budget)?;
        let commit = staged.publish_before(deadline)?;
        ensure!(
            commit.committed
                && commit.file_synced
                && commit.directory_synced
                && commit.bytes_written == content.len(),
            "edit_apply_commit_unconfirmed"
        );
        let (root, after, bytes) = snapshot(&plan.selected.root, &plan.selected.target, budget)?;
        ensure!(
            root == plan.root_identity
                && after.identity.device == staged_identity.device
                && after.identity.inode == staged_identity.inode
                && bytes == content.as_bytes(),
            "edit_apply_published_target_changed"
        );
        // Only the hash is retained. An interrupted command cannot manufacture
        // a success acknowledgement by reading an already-visible receipt.
        let success_ack = crate::token::generate();
        let receipt = Receipt {
            format: FORMAT.into(),
            operation,
            plan: journal.identity.plan.clone(),
            journal: journal.identity.directory.clone(),
            intent_sha256: digest(b"agentfw/edit-application-intent/v1\0", &intent)?,
            after,
            file_synced: true,
            directory_synced: true,
            success_ack_sha256: audit::sha(success_ack.as_bytes()),
        };
        journal
            .dir
            .write_new(operation.receipt(), &profile::canonical(&receipt)?)?;
        journal.recheck(budget)?;
        recheck_source(plan, source, budget)?;
        recheck_target(plan, &receipt.after, budget)?;
        Ok(Published {
            receipt,
            success_ack,
        })
    })();
    if result.is_err() {
        // A retained intent is single-use, even when no final receipt could be
        // made durable. Preserve evidence and never infer success or retry.
        let failure = Failure {
            format: FORMAT.into(),
            operation,
            plan: journal.identity.plan.clone(),
            status: "indeterminate".into(),
        };
        if let Ok(bytes) = profile::canonical(&failure) {
            let _ = journal.dir.write_new("indeterminate.json", &bytes);
        }
    }
    result
}

#[cfg(test)]
mod tests;
