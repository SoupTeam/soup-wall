// SPDX-License-Identifier: Apache-2.0
//! Bounded descriptive inventory. Selection binds local identities, never authority.
use super::{
    diagnostic::{
        audit,
        io::{same_directory, stable, Budget, Directory, Result as Observation},
        linux,
    },
    profile, record, Action,
};
use anyhow::{ensure, Result};
use clap::{Args as ClapArgs, Parser};
use serde::Serialize;
use std::{
    ffi::OsString,
    fs::Metadata,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const FORMAT: &str = "sw-installed-edit-inventory/1";
const MAX_ENTRIES: usize = 32;

#[derive(ClapArgs, Debug)]
pub(super) struct Args {
    /// Explicit installed Agent home; verify its selected helper without executing it.
    #[arg(long)]
    home: PathBuf,
    /// Existing owner-private directory directly containing retained edit runs.
    #[arg(long)]
    state: PathBuf,
    /// Select only this exact UUID from a preceding inventory; never a path or prefix.
    #[arg(long)]
    run_id: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(ClapArgs, Debug)]
pub(super) struct WithRun {
    #[arg(long)]
    home: PathBuf,
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    run_id: String,
    /// Current inventory identity digest; not a grant or cleanup/export confirmation.
    #[arg(long)]
    selection_sha256: String,
    /// Explicit existing status/review/stop command and options, after --; omit --run.
    #[arg(last = true, required = true)]
    action: Vec<OsString>,
}

#[derive(Parser)]
struct ExactCommand {
    #[command(subcommand)]
    action: Action,
}

#[derive(Serialize)]
struct Row {
    run_id: Option<String>,
    entry_sha256: String,
    status: &'static str,
    reason: &'static str,
    recorded_host_outcome: &'static str,
    owner_observation: &'static str,
    profile_sha256: Option<String>,
    source_commit: Option<String>,
    source_tree: Option<String>,
    component_sha256: Option<String>,
    declared_targets: Option<usize>,
    selection_sha256: Option<String>,
}
impl Row {
    fn unknown(name: &[u8], reason: &'static str) -> Self {
        Self {
            run_id: id(name).map(str::to_owned),
            entry_sha256: audit::sha(name),
            status: "unknown",
            reason,
            recorded_host_outcome: "unknown",
            owner_observation: "unknown",
            profile_sha256: None,
            source_commit: None,
            source_tree: None,
            component_sha256: None,
            declared_targets: None,
            selection_sha256: None,
        }
    }
}

#[derive(Serialize)]
struct Report {
    format: &'static str,
    status: &'static str,
    reason: &'static str,
    executed: bool,
    authority: bool,
    provenance: &'static str,
    approval_history: &'static str,
    limits: serde_json::Value,
    verified_component: Option<String>,
    rows: Vec<Row>,
}
impl Report {
    fn new() -> Self {
        Self {
            format: FORMAT,
            status: "complete",
            reason: "ok",
            executed: false,
            authority: false,
            provenance: "retained_local_records_not_execution_or_inactivity_proof",
            approval_history: "not_inspected_use_exact_status_for_ask_history",
            limits: serde_json::json!({"entries":MAX_ENTRIES,"file_reads":512,
                "bytes":2097152,"depth":1,"seconds":10}),
            verified_component: None,
            rows: vec![],
        }
    }
}

fn id(name: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(name).ok()?.strip_prefix("edit-")?;
    (text.len() == 36
        && text.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        }))
    .then_some(text)
}
fn name(run_id: &str) -> Observation<String> {
    let name = format!("edit-{run_id}");
    if id(name.as_bytes()) != Some(run_id) {
        return Err("inventory_exact_id_required");
    }
    Ok(name)
}
fn object(m: &Metadata) -> [u64; 5] {
    [
        m.dev(),
        m.ino(),
        u64::from(m.uid()),
        u64::from(m.gid()),
        u64::from(m.mode()),
    ]
}

struct Pinned {
    root: Directory,
    selected: linux::Selection,
    generation: Metadata,
    files: Vec<(&'static str, Option<Metadata>)>,
    row: Row,
}
impl Pinned {
    fn inspect(state: &Path, name: &str, budget: &mut Budget) -> Observation<Self> {
        let run_id = id(name.as_bytes()).ok_or("inventory_exact_id_required")?;
        let root = Directory::open(state)?;
        let child = root.child_dir(name)?;
        let generation = child.metadata()?;
        let run_path = state.join(name);
        let selected = linux::select(&run_path, budget)?;
        if !same_directory(&generation, &selected.directory.metadata()?) {
            return Err("inventory_run_changed");
        }
        let mut files = vec![];
        let mut identities = vec![];
        let mut outcome = "terminal_not_recorded";
        for (leaf, cap, expected) in [
            ("run.json", 16384, Some(selected.run_bytes.as_slice())),
            (
                "diagnostic-context.json",
                16384,
                Some(selected.context_bytes.as_slice()),
            ),
            (
                "profile.json",
                131072,
                Some(selected.profile_bytes.as_slice()),
            ),
            (
                "profile.sha256",
                64,
                Some(selected.context.profile_sha256.as_bytes()),
            ),
            ("terminal.json", 32768, None),
        ] {
            let observed = selected.directory.read_observed(leaf, cap, budget, false)?;
            if let Some((bytes, meta)) = observed {
                if expected.is_some_and(|old| old != bytes.as_slice()) {
                    return Err("inventory_record_changed");
                }
                if leaf == "terminal.json" {
                    outcome = linux::terminal(
                        &bytes,
                        &selected.context,
                        selected.profile.mutation_quota.as_ref(),
                    )?;
                }
                identities.push(serde_json::json!([
                    leaf,
                    object(&meta),
                    meta.len(),
                    meta.mtime(),
                    meta.mtime_nsec(),
                    meta.ctime(),
                    meta.ctime_nsec(),
                    audit::sha(&bytes)
                ]));
                files.push((leaf, Some(meta)));
            } else if expected.is_some() {
                return Err("inventory_record_changed");
            } else {
                identities.push(serde_json::json!([leaf, null]));
                files.push((leaf, None));
            }
        }
        let boot = record::process_identity(std::process::id())
            .map_err(|_| "inventory_kernel_identity_unavailable")?;
        let owner = if selected.context.owner.boot_id != boot.boot_id {
            "recorded_old_boot"
        } else if record::process_identity(selected.context.owner.pid)
            .is_ok_and(|current| current == selected.context.owner)
        {
            "identity_matches_liveness_not_established"
        } else {
            "unavailable_or_changed_not_completion"
        };
        let digest = profile::digest(&serde_json::json!({"format":FORMAT,
            "state_sha256":audit::sha(state.as_os_str().as_encoded_bytes()),
            "root":object(&root.metadata()?),"run_id":run_id,
            "run":object(&generation),"files":identities}))
        .map_err(|_| "inventory_identity_invalid")?;
        let row = Row {
            run_id: Some(run_id.into()),
            entry_sha256: audit::sha(name.as_bytes()),
            status: "recorded",
            reason: "local_record_only",
            recorded_host_outcome: outcome,
            owner_observation: owner,
            profile_sha256: Some(selected.context.profile_sha256.clone()),
            source_commit: Some(selected.profile.component.source_commit.clone()),
            source_tree: Some(selected.profile.component.source_tree.clone()),
            component_sha256: Some(selected.profile.component.id.clone()),
            declared_targets: Some(selected.profile.targets.len()),
            selection_sha256: Some(digest),
        };
        let pinned = Self {
            root,
            selected,
            generation,
            files,
            row,
        };
        pinned.recheck(state, budget)?;
        Ok(pinned)
    }
    fn recheck(&self, state: &Path, budget: &mut Budget) -> Observation<()> {
        budget.tick(0)?;
        self.root.check_path(state)?;
        self.selected
            .directory
            .check_path(&self.selected.context.run)?;
        if !stable(&self.generation, &self.selected.directory.metadata()?) {
            return Err("inventory_run_changed");
        }
        for (name, before) in &self.files {
            if let Some(before) = before {
                self.selected.directory.check_file(name, before)?;
            } else if self.selected.directory.read(name, 0, budget)?.is_some() {
                return Err("inventory_record_changed");
            }
        }
        Ok(())
    }
}

fn inventory(state: &Path, exact: Option<&str>, report: &mut Report) -> Observation<()> {
    let mut budget = Budget::new();
    let root = Directory::open(state)?;
    let generation = root.metadata()?;
    if let Some(run_id) = exact {
        let selected = Pinned::inspect(state, &name(run_id)?, &mut budget)?;
        report.rows.push(selected.row);
    } else {
        let mut entries = root.entries()?;
        while let Some(raw) = entries.next()? {
            if let Err(reason) = budget.tick(0) {
                report.status = "incomplete";
                report.reason = reason;
                break;
            }
            if report.rows.len() == MAX_ENTRIES {
                report.status = "incomplete";
                report.reason = "inventory_entry_limit";
                break;
            }
            let row = match id(&raw) {
                Some(_) => {
                    match Pinned::inspect(state, std::str::from_utf8(&raw).unwrap(), &mut budget) {
                        Ok(pinned) => pinned.row,
                        Err(reason) => Row::unknown(&raw, reason),
                    }
                }
                None => Row::unknown(&raw, "inventory_unrecognized_entry"),
            };
            if row.status == "unknown" && report.status == "complete" {
                report.status = "incomplete";
                report.reason = "inventory_unknown_records";
            }
            let exhausted = row.reason == "diagnostic_read_budget";
            report.rows.push(row);
            if exhausted {
                report.status = "incomplete";
                report.reason = "diagnostic_read_budget";
                break;
            }
        }
    }
    root.check_path(state)?;
    if !stable(&generation, &root.metadata()?) {
        report.status = "incomplete";
        report.reason = "inventory_root_changed_during_observation";
    }
    report
        .rows
        .sort_by(|a, b| a.entry_sha256.cmp(&b.entry_sha256));
    Ok(())
}

fn component(home: &Path) -> Result<String> {
    crate::pilot_component::Store::new(home)
        .current()
        .map(|c| c.id)
        .map_err(|_| anyhow::anyhow!("inventory_verified_component_required"))
}
pub(super) fn command(args: Args) -> Result<()> {
    let mut report = Report::new();
    report.verified_component = Some(component(&args.home)?);
    if let Err(reason) = inventory(&args.state, args.run_id.as_deref(), &mut report) {
        report.status = "unknown";
        report.reason = reason;
        report.rows.clear();
    }
    let bytes = serde_json::to_string_pretty(&report)?;
    ensure!(bytes.len() <= 64 * 1024, "inventory_report_limit");
    if args.json {
        println!("{bytes}");
    } else {
        println!(
            "Edit-run inventory: {} ({}). Local records are not inactivity or execution proof.",
            report.status, report.reason
        );
        for row in &report.rows {
            println!(
                "{}: {} / {} / {}; selection {}",
                row.run_id.as_deref().unwrap_or("unrecognized entry"),
                row.recorded_host_outcome,
                row.owner_observation,
                row.reason,
                row.selection_sha256.as_deref().unwrap_or("unavailable")
            );
            println!(
                "  Profile {} source {} helper {} targets {}",
                row.profile_sha256.as_deref().unwrap_or("unknown"),
                row.source_commit.as_deref().unwrap_or("unknown"),
                row.component_sha256.as_deref().unwrap_or("unknown"),
                row.declared_targets
                    .map_or_else(|| "unknown".into(), |n| n.to_string())
            );
        }
    }
    ensure!(report.status == "complete", "edit_inventory_incomplete");
    Ok(())
}

pub(super) fn with_run(args: WithRun) -> Result<()> {
    component(&args.home)?;
    let mut budget = Budget::new();
    let pinned = Pinned::inspect(
        &args.state,
        &name(&args.run_id).map_err(anyhow::Error::msg)?,
        &mut budget,
    )
    .map_err(anyhow::Error::msg)?;
    ensure!(
        crate::native::is_digest(&args.selection_sha256)
            && pinned.row.selection_sha256.as_deref() == Some(args.selection_sha256.as_str()),
        "inventory_selection_changed"
    );
    let command = args.action.first().and_then(|s| s.to_str());
    ensure!(
        matches!(command, Some("status" | "review" | "stop"))
            && !args
                .action
                .iter()
                .any(|s| s == "--run" || s.to_str().is_some_and(|v| v.starts_with("--run="))),
        "inventory_existing_action_required"
    );
    let mut words = vec![
        OsString::from("edit-session"),
        args.action[0].clone(),
        OsString::from("--run"),
        pinned.selected.context.run.clone().into_os_string(),
    ];
    words.extend_from_slice(&args.action[1..]);
    let action = ExactCommand::try_parse_from(words)
        .map_err(|_| anyhow::anyhow!("inventory_action_arguments_invalid"))?
        .action;
    pinned
        .recheck(&args.state, &mut budget)
        .map_err(anyhow::Error::msg)?;
    // Held descriptors survive the handoff. The existing command also performs
    // its own exact-run validation and requires its original independent consent.
    super::launch::command(action)
}

#[cfg(test)]
mod tests;
