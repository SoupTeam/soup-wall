// SPDX-License-Identifier: Apache-2.0
//! A separately consented, single-file local publication. Retained observations
//! and Ask decisions never grant destination authority. Arbitrary same-UID
//! concurrent writers remain outside the accepted sole-writer boundary.
use super::{
    diagnostic::{
        audit,
        io::{Budget, Directory},
    },
    launch,
    profile::{self, Baseline},
    review::{OutputBinding, SelectedOutput},
};
use crate::mcp::replace_file::{self, Identity, RootIdentity};
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;

const FORMAT: &str = "sw-installed-edit-application/1";
const CAP: u64 = replace_file::MAX_BYTES as u64;

mod journal;
use journal::{publish, receipt_digest, retain, Journal, JournalIdentity, Operation, Receipt};

#[derive(Args, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Selection {
    #[arg(long)]
    run: PathBuf,
    /// Original immutable prepared plan, not a model-generated review report.
    #[arg(long)]
    plan: PathBuf,
    #[arg(long)]
    sha256: String,
    /// Exactly one declared mutation output from the completed run.
    #[arg(long)]
    output: String,
    /// Explicit existing, owner-private and quiesced project directory.
    #[arg(long)]
    root: PathBuf,
    /// Existing direct-child regular file; no missing-leaf fallback.
    #[arg(long)]
    target: String,
    /// New private application directory outside source and destination roots.
    #[arg(long)]
    journal: PathBuf,
}

#[derive(Args, Debug)]
pub(super) struct Retained {
    #[arg(long)]
    journal: PathBuf,
    /// Confirmation digest retained from the original apply preview.
    #[arg(long)]
    expect_plan: String,
    /// Receipt returned by a successful operation, not inferred from current bytes.
    #[arg(long)]
    receipt: Option<String>,
    /// Private acknowledgement returned only by a fully successful command.
    #[arg(long)]
    success_ack: Option<String>,
}

#[derive(Subcommand, Debug)]
pub(super) enum Action {
    /// Read-only exact source/target/backup-location preview; no private backup yet.
    Preview(Selection),
    /// Apply only the previewed single-file change with fresh operator consent.
    Commit {
        #[command(flatten)]
        selected: Selection,
        #[arg(long)]
        confirm: String,
        /// The operator has excluded other writers, including same-UID writers.
        #[arg(long)]
        private_sole_writer: bool,
        /// Retain the bounded private preimage in the selected journal.
        #[arg(long)]
        consent_private_backup: bool,
    },
    /// Bounded read-only recovery; never resume, retry, infer a commit or clean up.
    #[command(alias = "recover")]
    Status(Retained),
    /// Read-only proposal to restore the preimage of this exact acknowledged apply.
    RevertPreview(Retained),
    /// Restore only an unchanged recorded postimage, with separate fresh consent.
    Revert {
        #[command(flatten)]
        selected: Retained,
        #[arg(long)]
        confirm: String,
        #[arg(long)]
        private_sole_writer: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Plan {
    format: String,
    selected: Selection,
    source: OutputBinding,
    source_plan_identity: RootIdentity,
    root_identity: RootIdentity,
    before: Baseline,
    after_sha256: String,
    after_bytes: usize,
    journal_parent_identity: RootIdentity,
    writer_exclusion: String,
    operator_uid: u32,
}

fn digest(domain: &[u8], value: &impl Serialize) -> Result<String> {
    let mut bytes = domain.to_vec();
    bytes.extend(profile::canonical(value)?);
    Ok(replace_file::content_sha256(&bytes))
}
fn confirmation(plan: &Plan) -> Result<String> {
    digest(b"agentfw/edit-application/v1\0", plan)
}
fn same(actual: &str, expected: &str) -> bool {
    crate::native::is_digest(actual)
        && crate::native::is_digest(expected)
        && bool::from(actual.as_bytes().ct_eq(expected.as_bytes()))
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(audit::strict(bytes).map_err(anyhow::Error::msg)?)
        .map_err(|_| anyhow::anyhow!("edit_apply_record_schema"))
}
fn root_id(m: &fs::Metadata) -> RootIdentity {
    RootIdentity {
        device: m.dev(),
        inode: m.ino(),
    }
}
fn identity(m: &fs::Metadata) -> Identity {
    Identity {
        device: m.dev(),
        inode: m.ino(),
        size: m.len(),
        mtime_seconds: m.mtime(),
        mtime_nanoseconds: m.mtime_nsec(),
        ctime_seconds: m.ctime(),
        ctime_nanoseconds: m.ctime_nsec(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
    }
}
fn directory(path: &Path) -> Result<(Directory, RootIdentity)> {
    let d = Directory::open(path).map_err(anyhow::Error::msg)?;
    let m = d.metadata().map_err(anyhow::Error::msg)?;
    ensure!(
        m.gid() == unsafe { libc::getegid() } && m.mode() & 0o7777 == 0o700,
        "edit_apply_directory_metadata"
    );
    Ok((d, root_id(&m)))
}
fn snapshot(
    root: &Path,
    name: &str,
    budget: &mut Budget,
) -> Result<(RootIdentity, Baseline, Vec<u8>)> {
    let (d, id) = directory(root)?;
    let (bytes, meta) = d
        .read_output(name, CAP, budget)
        .map_err(anyhow::Error::msg)?
        .context("edit_apply_target_missing")?;
    ensure!(
        std::str::from_utf8(&bytes).is_ok(),
        "edit_apply_target_text_required"
    );
    Ok((
        id,
        Baseline {
            identity: identity(&meta),
            sha256: audit::sha(&bytes),
        },
        bytes,
    ))
}
fn overlap(a: &Path, b: &Path) -> Result<()> {
    ensure!(
        !a.starts_with(b) && !b.starts_with(a),
        "edit_apply_protected_overlap"
    );
    // Canonical lexical names are already checked by descriptor traversal.
    // Also refuse inode aliases (e.g. an existing bind alias), in either direction.
    for (leaf, ancestors) in [(a, b), (b, a)] {
        if let Ok(m) = fs::symlink_metadata(leaf) {
            let id = root_id(&m);
            for p in ancestors.ancestors() {
                if let Ok(other) = fs::symlink_metadata(p) {
                    ensure!(root_id(&other) != id, "edit_apply_protected_inode_alias");
                }
            }
        }
    }
    Ok(())
}
fn target_leaf(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with(".soup-replace-")
        && !name.contains(['/', '\\'])
        && !name.chars().any(char::is_control)
        && matches!(
            Path::new(name).components().next(),
            Some(std::path::Component::Normal(_))
        )
}
fn protect(selected: &Selection, source: &SelectedOutput) -> Result<RootIdentity> {
    ensure!(
        target_leaf(&selected.target) && profile::leaf(&selected.output),
        "edit_apply_direct_child"
    );
    let parent = selected
        .journal
        .parent()
        .context("edit_apply_journal_parent")?;
    let leaf = selected
        .journal
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| profile::leaf(n))
        .context("edit_apply_journal_name")?;
    ensure!(
        parent.join(leaf).as_os_str() == selected.journal.as_os_str(),
        "edit_apply_journal_alias"
    );
    let (_, parent_id) = directory(parent)?;
    let p = source.profile();
    let mut roots = vec![
        selected.run.as_path(),
        selected.plan.as_path(),
        p.root.as_path(),
        p.component.home.as_path(),
    ];
    for file in [
        &p.agent.path,
        &p.claude.path,
        &p.component.python.path,
        &p.component.classifier.path,
    ] {
        roots.push(file.parent().context("edit_apply_runtime_parent")?);
    }
    for protected in roots {
        overlap(&selected.root, protected)?;
        overlap(&selected.journal, protected)?;
        // A nonexistent journal cannot yet have its own inode. Its parent must
        // nevertheless not be an alias into a protected directory.
        let m = fs::symlink_metadata(protected)?;
        ensure!(
            parent_id != root_id(&m),
            "edit_apply_journal_protected_parent"
        );
    }
    overlap(&selected.journal, &selected.root)?;
    Ok(parent_id)
}
fn original_plan(
    selected: &Selection,
    source: &SelectedOutput,
    budget: &mut Budget,
) -> Result<RootIdentity> {
    let (d, id) = directory(&selected.plan)?;
    let raw = d
        .immutable("profile.json", 128 * 1024, budget)
        .map_err(anyhow::Error::msg)?;
    let hash = d
        .immutable("profile.sha256", 64, budget)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        raw == profile::canonical(source.profile())?
            && hash == selected.sha256.as_bytes()
            && same(&audit::sha(&raw), &selected.sha256),
        "edit_apply_original_plan_changed"
    );
    Ok(id)
}
struct Proposal {
    plan: Plan,
    source: SelectedOutput,
    before: Vec<u8>,
}
fn propose(selected: &Selection, budget: &mut Budget) -> Result<Proposal> {
    let source = SelectedOutput::open(&selected.run, &selected.sha256, &selected.output, budget)?;
    launch::verify_anchors(source.profile())?;
    let parent = protect(selected, &source)?;
    let source_plan_identity = original_plan(selected, &source, budget)?;
    ensure!(
        fs::symlink_metadata(&selected.journal)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "edit_apply_journal_exists_no_retry"
    );
    let (root_identity, before, bytes) = snapshot(&selected.root, &selected.target, budget)?;
    let preview = replace_file::preview(
        &selected.root,
        &selected.root.join(&selected.target),
        source.content()?,
    )?;
    ensure!(
        preview.root == root_identity
            && preview.old_identity == before.identity
            && same(&preview.old_sha256, &before.sha256),
        "edit_apply_target_changed"
    );
    let binding = source.binding()?;
    let plan = Plan {
        format: FORMAT.into(),
        selected: selected.clone(),
        source: binding,
        source_plan_identity,
        root_identity,
        before,
        after_sha256: preview.new_sha256,
        after_bytes: preview.new_bytes,
        journal_parent_identity: parent,
        writer_exclusion: replace_file::EXCLUSION.into(),
        operator_uid: unsafe { libc::geteuid() },
    };
    let proposal = Proposal {
        plan,
        source,
        before: bytes,
    };
    recheck_source(&proposal.plan, &proposal.source, budget)?;
    recheck_target(&proposal.plan, &proposal.plan.before, budget)?;
    Ok(proposal)
}
fn recheck_source(plan: &Plan, source: &SelectedOutput, budget: &mut Budget) -> Result<()> {
    ensure!(
        plan.format == FORMAT
            && plan.operator_uid == unsafe { libc::geteuid() }
            && plan.writer_exclusion == replace_file::EXCLUSION,
        "edit_apply_plan_contract"
    );
    let selected = &plan.selected;
    launch::verify_anchors(source.profile())?;
    source.recheck(budget)?;
    ensure!(
        source.binding()? == plan.source
            && original_plan(selected, source, budget)? == plan.source_plan_identity
            && protect(selected, source)? == plan.journal_parent_identity,
        "edit_apply_source_changed"
    );
    Ok(())
}
fn recheck_target(plan: &Plan, expected: &Baseline, budget: &mut Budget) -> Result<()> {
    let (root, before, _) = snapshot(&plan.selected.root, &plan.selected.target, budget)?;
    ensure!(
        root == plan.root_identity
            && before.identity == expected.identity
            && same(&before.sha256, &expected.sha256),
        "edit_apply_target_changed"
    );
    Ok(())
}

#[derive(Serialize)]
struct RevertPlan<'a> {
    format: &'static str,
    plan: &'a Plan,
    journal: &'a JournalIdentity,
    applied: &'a Receipt,
}
fn revert_confirmation(j: &Journal, applied: &Receipt) -> Result<String> {
    digest(
        b"agentfw/edit-application-revert/v1\0",
        &RevertPlan {
            format: FORMAT,
            plan: &j.plan,
            journal: &j.identity,
            applied,
        },
    )
}
fn observed_source(j: &Journal, budget: &mut Budget) -> Result<SelectedOutput> {
    let s = &j.plan.selected;
    let source = SelectedOutput::open(&s.run, &s.sha256, &s.output, budget)?;
    recheck_source(&j.plan, &source, budget)?;
    Ok(source)
}
fn response(
    status: &str,
    confirmation: &str,
    receipt: Option<&Receipt>,
    ack: Option<&str>,
) -> Result<Value> {
    Ok(
        json!({"format":FORMAT,"status":status,"plan_sha256":confirmation,
        "receipt_sha256":receipt.map(receipt_digest).transpose()?,
        "success_ack":ack,
        "local_operator_publication":receipt.is_some(),"mcp_authority":false,"tool_execution":false}),
    )
}
fn execute(action: Action) -> Result<Value> {
    ensure!(
        cfg!(target_arch = "x86_64"),
        "edit_apply_requires_native_linux_x86_64"
    );
    let mut budget = Budget::new();
    match action {
        Action::Preview(selected) => {
            let p = propose(&selected, &mut budget)?;
            Ok(
                json!({"format":FORMAT,"status":"preview","confirmation_sha256":confirmation(&p.plan)?,
                "plan":p.plan,"executed":false,"authority":false,"private_backup_retained":false,
                "requires":["fresh_exact_confirmation","private_sole_writer","private_backup_consent"]}),
            )
        }
        Action::Commit {
            selected,
            confirm,
            private_sole_writer,
            consent_private_backup,
        } => {
            ensure!(
                private_sole_writer && consent_private_backup,
                "edit_apply_explicit_operator_consent_required"
            );
            let p = propose(&selected, &mut budget)?;
            let expected = confirmation(&p.plan)?;
            ensure!(same(&confirm, &expected), "edit_apply_stale_confirmation");
            let journal = retain(&p, &mut budget)?;
            let _lock = journal.dir.lock()?;
            let published = publish(
                &journal,
                &p.source,
                Operation::Apply,
                &p.plan.before,
                p.source.content()?,
                None,
                &mut budget,
            )?;
            response(
                "applied",
                &expected,
                Some(&published.receipt),
                Some(&published.success_ack),
            )
        }
        Action::Status(args) => {
            let j = Journal::open(&args.journal, &args.expect_plan, &mut budget)?;
            let _lock = j.dir.lock()?;
            let _source = observed_source(&j, &mut budget)?;
            let state = j.acknowledged(
                args.receipt.as_deref(),
                args.success_ack.as_deref(),
                &mut budget,
            );
            j.recheck(&mut budget)?;
            match state {
                Ok((op, receipt)) => response(
                    if op == Operation::Apply {
                        "applied"
                    } else {
                        "reverted"
                    },
                    &args.expect_plan,
                    Some(&receipt),
                    args.success_ack.as_deref(),
                ),
                Err(_) => response("indeterminate", &args.expect_plan, None, None),
            }
        }
        Action::RevertPreview(args) => {
            let j = Journal::open(&args.journal, &args.expect_plan, &mut budget)?;
            let _lock = j.dir.lock()?;
            let _source = observed_source(&j, &mut budget)?;
            let (op, receipt) = j.acknowledged(
                args.receipt.as_deref(),
                args.success_ack.as_deref(),
                &mut budget,
            )?;
            ensure!(op == Operation::Apply, "edit_apply_already_reverted");
            replace_file::Prepared::prepare(
                &j.plan.selected.root,
                &j.plan.selected.root.join(&j.plan.selected.target),
                &j.plan.root_identity,
                &receipt.after.identity,
                &receipt.after.sha256,
                std::str::from_utf8(&j.before).context("edit_apply_backup_text_required")?,
            )?
            .preview()?;
            j.recheck(&mut budget)?;
            Ok(
                json!({"format":FORMAT,"status":"revert_preview","confirmation_sha256":revert_confirmation(&j,&receipt)?,
                "plan_sha256":args.expect_plan,"executed":false,"authority":false,
                "restore_sha256":j.plan.before.sha256,"restore_bytes":j.before.len()}),
            )
        }
        Action::Revert {
            selected: args,
            confirm,
            private_sole_writer,
        } => {
            ensure!(
                private_sole_writer,
                "edit_apply_explicit_operator_consent_required"
            );
            let j = Journal::open(&args.journal, &args.expect_plan, &mut budget)?;
            let _lock = j.dir.lock()?;
            let source = observed_source(&j, &mut budget)?;
            let (op, applied) = j.acknowledged(
                args.receipt.as_deref(),
                args.success_ack.as_deref(),
                &mut budget,
            )?;
            ensure!(
                op == Operation::Apply && same(&confirm, &revert_confirmation(&j, &applied)?),
                "edit_apply_stale_revert_confirmation"
            );
            let published = publish(
                &j,
                &source,
                Operation::Revert,
                &applied.after,
                std::str::from_utf8(&j.before).context("edit_apply_backup_text_required")?,
                Some(&applied),
                &mut budget,
            )?;
            response(
                "reverted",
                &args.expect_plan,
                Some(&published.receipt),
                Some(&published.success_ack),
            )
        }
    }
}
pub(super) fn command(action: Action) -> Result<()> {
    let value = execute(action).map_err(|e| {
        let code = e
            .downcast_ref::<replace_file::Error>()
            .map(|e| e.code.to_string())
            .or_else(|| {
                e.chain().map(ToString::to_string).find(|s| {
                    s.len() <= 96
                        && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                        && ["edit_", "selected_", "current_", "retained_", "terminal_"]
                            .iter()
                            .any(|p| s.starts_with(p))
                })
            })
            .unwrap_or_else(|| "unsafe_or_unavailable_selected_state".into());
        anyhow::anyhow!("edit_apply_refused: {code}")
    })?;
    let bytes = serde_json::to_string(&value)?;
    ensure!(bytes.len() <= 32 * 1024, "edit_apply_response_cap");
    println!("{bytes}");
    Ok(())
}
