// SPDX-License-Identifier: Apache-2.0
//! Finite local operator batches. Per-file publication is atomic under the
//! accepted sole-writer boundary; the batch is deliberately NOT globally atomic.
use super::{
    application as single,
    control_io::Dir,
    diagnostic::{
        audit,
        io::{Budget, Directory},
    },
    launch,
    profile::{self, Baseline},
    review::{OutputBinding, SelectedOutput},
};
use crate::mcp::replace_file::{self, RootIdentity};
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use single::{decode, digest, directory, same, snapshot, CAP};
use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};
mod journal;
use journal::{Journal, Row};
const FORMAT: &str = "sw-installed-edit-batch/1";
const MAX_TOTAL: usize = 8 * 4096;

#[derive(Args, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Selection {
    #[arg(long)]
    run: PathBuf,
    /// Original immutable prepared plan.
    #[arg(long)]
    plan: PathBuf,
    #[arg(long)]
    sha256: String,
    /// Ordered exact OUTPUT=TARGET mapping; repeat two to eight times.
    #[arg(long = "map", required = true)]
    mapping: Vec<String>,
    #[arg(long)]
    root: PathBuf,
    /// New private journal outside source, destination, runtime and run roots.
    #[arg(long)]
    journal: PathBuf,
}
#[derive(Args, Debug)]
pub(super) struct Retained {
    #[arg(long)]
    journal: PathBuf,
    #[arg(long)]
    expect_plan: String,
    /// Returned INDEX:apply|revert:RECEIPT_SHA256:PRIVATE_ACK, repeated as needed.
    #[arg(long = "proof", allow_hyphen_values = true)]
    proof: Vec<String>,
}
#[derive(Subcommand, Debug)]
pub(super) enum Action {
    /// Read-only complete ordered mapping and exact identities. No subprocess or write.
    Preview(Selection),
    Apply {
        #[command(flatten)]
        selected: Selection,
        #[arg(long)]
        confirm: String,
        #[arg(long)]
        private_sole_writer: bool,
        #[arg(long)]
        consent_private_backup: bool,
    },
    /// Observe each durable effect; never retry or infer completion from bytes.
    Status(Retained),
    /// Read-only proposal to restore only proven unchanged members of a partial batch.
    RecoverPreview(Retained),
    /// Explicitly restore eligible members only; never continue forward application.
    Recover {
        #[command(flatten)]
        selected: Retained,
        #[arg(long)]
        confirm: String,
        #[arg(long)]
        private_sole_writer: bool,
    },
    /// Read-only proposal to restore an entirely applied, unchanged set.
    RevertPreview(Retained),
    Revert {
        #[command(flatten)]
        selected: Retained,
        #[arg(long)]
        confirm: String,
        #[arg(long)]
        private_sole_writer: bool,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Member {
    output: String,
    target: String,
    source: OutputBinding,
    before: Baseline,
    after_sha256: String,
    after_bytes: usize,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Plan {
    format: String,
    selected: Selection,
    root: RootIdentity,
    source_plan: RootIdentity,
    journal_parent: RootIdentity,
    uid: u32,
    writer_exclusion: String,
    members: Vec<Member>,
}
struct Proposal {
    plan: Plan,
    source: SelectedOutput,
    before: Vec<Vec<u8>>,
    after: Vec<Vec<u8>>,
}
fn confirmation(p: &Plan) -> Result<String> {
    digest(b"agentfw/edit-batch/v1\0", p)
}
fn mappings(s: &Selection) -> Result<Vec<(String, String)>> {
    ensure!(
        (2..=profile::MAX_TARGETS).contains(&s.mapping.len()),
        "edit_batch_count"
    );
    let (mut outputs, mut targets) = (BTreeSet::new(), BTreeSet::new());
    s.mapping
        .iter()
        .map(|m| {
            let (o, t) = m.split_once('=').context("edit_batch_mapping")?;
            ensure!(
                profile::leaf(o)
                    && single::target_leaf(t)
                    && outputs.insert(o)
                    && targets.insert(t),
                "edit_batch_duplicate_or_invalid_mapping"
            );
            Ok((o.into(), t.into()))
        })
        .collect()
}
fn selection(s: &Selection, output: &str, target: &str) -> single::Selection {
    single::Selection {
        run: s.run.clone(),
        plan: s.plan.clone(),
        sha256: s.sha256.clone(),
        output: output.into(),
        root: s.root.clone(),
        target: target.into(),
        journal: s.journal.clone(),
    }
}
fn validate(p: &Plan) -> Result<()> {
    let map = mappings(&p.selected)?;
    ensure!(
        p.format == FORMAT
            && p.uid == unsafe { libc::geteuid() }
            && p.writer_exclusion == replace_file::EXCLUSION
            && map.len() == p.members.len(),
        "edit_batch_plan_contract"
    );
    let mut ids = BTreeSet::new();
    let mut sources = BTreeSet::new();
    let (mut old, mut new) = (0usize, 0usize);
    for ((o, t), m) in map.iter().zip(&p.members) {
        ensure!(
            &m.output == o
                && &m.target == t
                && m.source.output == m.output
                && m.source.output_bytes == m.after_bytes
                && same(&m.source.output_sha256, &m.after_sha256)
                && m.source.run == p.selected.run
                && same(&m.source.profile_sha256, &p.selected.sha256)
                && crate::native::is_digest(&m.before.sha256)
                && m.before.identity.size <= CAP
                && m.after_bytes <= CAP as usize
                && ids.insert((m.before.identity.device, m.before.identity.inode))
                && sources.insert(m.source.output_identity.object_identity()),
            "edit_batch_plan_contract"
        );
        old += m.before.identity.size as usize;
        new += m.after_bytes;
    }
    ensure!(
        old <= MAX_TOTAL && new <= MAX_TOTAL && ids.is_disjoint(&sources),
        "edit_batch_aggregate_or_alias"
    );
    Ok(())
}
fn source_check(p: &Plan, source: &mut SelectedOutput, b: &mut Budget) -> Result<()> {
    validate(p)?;
    launch::verify_anchors(source.profile())?;
    source.recheck(b)?;
    let first = &p.members[0];
    let selected = selection(&p.selected, &first.output, &first.target);
    ensure!(
        single::original_plan(&selected, source, b)? == p.source_plan
            && single::protect(&selected, source)? == p.journal_parent,
        "edit_batch_source_changed"
    );
    for m in &p.members {
        source.select_name(&m.output)?;
        ensure!(
            source.binding()? == m.source
                && same(&audit::sha(source.content()?.as_bytes()), &m.after_sha256),
            "edit_batch_source_changed"
        );
    }
    Ok(())
}
fn open_source(p: &Plan, b: &mut Budget) -> Result<SelectedOutput> {
    let mut source =
        SelectedOutput::open(&p.selected.run, &p.selected.sha256, &p.members[0].output, b)?;
    source_check(p, &mut source, b)?;
    Ok(source)
}
fn propose(s: &Selection, b: &mut Budget) -> Result<Proposal> {
    let map = mappings(s)?;
    let mut source = SelectedOutput::open(&s.run, &s.sha256, &map[0].0, b)?;
    launch::verify_anchors(source.profile())?;
    let first = selection(s, &map[0].0, &map[0].1);
    let journal_parent = single::protect(&first, &source)?;
    let source_plan = single::original_plan(&first, &source, b)?;
    ensure!(
        fs::symlink_metadata(&s.journal).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "edit_batch_journal_exists_no_retry"
    );
    let mut members = vec![];
    let mut before = vec![];
    let mut after = vec![];
    let root = replace_file::inspect_workspace(&s.root)?;
    for (output, target) in map {
        source.select_name(&output)?;
        let bytes = source.content()?.as_bytes().to_vec();
        let (id, baseline, old) = snapshot(&s.root, &target, b)?;
        ensure!(id == root, "edit_batch_target_changed");
        let preview = replace_file::Prepared::prepare(
            &s.root,
            &s.root.join(&target),
            &root,
            &baseline.identity,
            &baseline.sha256,
            std::str::from_utf8(&bytes)?,
        )?
        .preview()?;
        members.push(Member {
            output,
            target,
            source: source.binding()?,
            before: baseline,
            after_sha256: preview.new_sha256,
            after_bytes: preview.new_bytes,
        });
        before.push(old);
        after.push(bytes);
    }
    let p = Plan {
        format: FORMAT.into(),
        selected: s.clone(),
        root,
        source_plan,
        journal_parent,
        uid: unsafe { libc::geteuid() },
        writer_exclusion: replace_file::EXCLUSION.into(),
        members,
    };
    source_check(&p, &mut source, b)?;
    for m in &p.members {
        let (id, now, _) = snapshot(&s.root, &m.target, b)?;
        ensure!(id == p.root && now == m.before, "edit_batch_target_changed");
    }
    Ok(Proposal {
        plan: p,
        source,
        before,
        after,
    })
}
fn fresh_restore(
    j: &Journal,
    b: &mut Budget,
    partial: bool,
) -> Result<(String, Vec<Row>, Vec<usize>)> {
    let rows = j.inspect(b)?;
    let eligible: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.status == "applied")
        .map(|(i, _)| i)
        .collect();
    ensure!(
        !eligible.is_empty() && (partial || eligible.len() == rows.len()),
        "edit_batch_no_safe_complete_restore"
    );
    let proof = j.progress_hash()?;
    let hash = digest(
        b"agentfw/edit-batch-restore/v1\0",
        &json!({"format":FORMAT,"plan":j.hash,"journal":j.id,"partial":partial,"rows":rows,"eligible":eligible,"progress":proof}),
    )?;
    Ok((hash, rows, eligible))
}
fn restore_preview(j: &Journal, b: &mut Budget, partial: bool) -> Result<Value> {
    let _source = open_source(&j.plan, b)?;
    let (hash, rows, eligible) = fresh_restore(j, b, partial)?;
    j.recheck(b)?;
    Ok(
        json!({"format":FORMAT,"status":if partial{"recover_preview"}else{"revert_preview"},"confirmation_sha256":hash,"plan_sha256":j.hash,"files":rows,"restore_indices":eligible,"executed":false,"authority":false,"automatic_rollback":false}),
    )
}
fn execute(action: Action) -> Result<Value> {
    ensure!(
        cfg!(target_arch = "x86_64") && unsafe { libc::geteuid() } != 0,
        "edit_batch_native_linux_user_required"
    );
    let partial = matches!(&action, Action::RecoverPreview(_) | Action::Recover { .. });
    let mut b = Budget::new();
    match action {
        Action::Preview(s) => {
            let p = propose(&s, &mut b)?;
            Ok(
                json!({"format":FORMAT,"status":"preview","confirmation_sha256":confirmation(&p.plan)?,"plan":p.plan,"executed":false,"private_backup_retained":false,"authority":false}),
            )
        }
        Action::Apply {
            selected,
            confirm,
            private_sole_writer,
            consent_private_backup,
        } => {
            ensure!(
                private_sole_writer && consent_private_backup,
                "edit_batch_explicit_consent_required"
            );
            let mut p = propose(&selected, &mut b)?;
            ensure!(
                same(&confirm, &confirmation(&p.plan)?),
                "edit_batch_stale_confirmation"
            );
            let mut j = Journal::retain(&mut p, &mut b)?;
            let lock_dir = Dir::open(&j.plan.selected.journal)?;
            let _lock = lock_dir.lock()?;
            j.apply(&mut p.source, &mut b)
        }
        Action::Status(r) => {
            let j = Journal::open(&r, &mut b)?;
            let lock_dir = Dir::open(&j.plan.selected.journal)?;
            let _lock = lock_dir.lock()?;
            j.response(&mut b)
        }
        Action::RecoverPreview(r) | Action::RevertPreview(r) => {
            let j = Journal::open(&r, &mut b)?;
            let lock_dir = Dir::open(&j.plan.selected.journal)?;
            let _lock = lock_dir.lock()?;
            restore_preview(&j, &mut b, partial)
        }
        Action::Recover {
            selected,
            confirm,
            private_sole_writer,
        }
        | Action::Revert {
            selected,
            confirm,
            private_sole_writer,
        } => {
            ensure!(private_sole_writer, "edit_batch_explicit_consent_required");
            let mut j = Journal::open(&selected, &mut b)?;
            let lock_dir = Dir::open(&j.plan.selected.journal)?;
            let _lock = lock_dir.lock()?;
            let mut source = open_source(&j.plan, &mut b)?;
            let (expected, _, eligible) = fresh_restore(&j, &mut b, partial)?;
            ensure!(
                same(&confirm, &expected),
                "edit_batch_stale_restore_confirmation"
            );
            j.restore(&mut source, &eligible, &mut b)
        }
    }
}
pub(super) fn command(action: Action) -> Result<()> {
    let result = execute(action);
    match result {
        Ok(value) => {
            let raw = serde_json::to_string(&value)?;
            ensure!(raw.len() <= 128 * 1024, "edit_batch_response_cap");
            println!("{raw}");
            Ok(())
        }
        Err(error) => {
            let code = error
                .downcast_ref::<replace_file::Error>()
                .map(|e| e.code.to_string())
                .or_else(|| {
                    error.chain().map(ToString::to_string).find(|s| {
                        s.len() <= 96
                            && s.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
                            && ["edit_", "selected_", "diagnostic_", "replace_", "export_"]
                                .iter()
                                .any(|p| s.starts_with(p))
                    })
                })
                .unwrap_or_else(|| "edit_batch_unsafe_or_unavailable".into());
            println!(
                "{}",
                json!({"format":FORMAT,"status":"refused","reason":code,"project_effects":"not_inferred_inspect_retained_journal","authority":false})
            );
            anyhow::bail!("edit_batch_refused")
        }
    }
}
