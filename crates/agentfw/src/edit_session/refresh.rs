// SPDX-License-Identifier: Apache-2.0
//! Explicit re-observation of the same declared scope, never recovery or replay.
//! No grants, pending decisions, receipts or run state are read or modified.
use super::{
    launch,
    profile::{self, Baseline, Profile},
};
use crate::mcp::replace_file;
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::os::unix::fs::MetadataExt;
use std::{
    fs,
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;

const FORMAT: &str = "sw-installed-edit-refresh/1";

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Observation {
    name: String,
    /// None proves absence only for an unchanged create declaration.
    current: Option<Baseline>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Proposal {
    format: &'static str,
    source_plan: PathBuf,
    source_plan_sha256: String,
    destination: PathBuf,
    before: Profile,
    after: Profile,
    observed_targets: Vec<Observation>,
    profile_sha256: String,
    scope_unchanged: bool,
    prior_operation_outcome: &'static str,
    requires_fresh_run_and_exact_ask: bool,
}

fn immutable(plan: &Path, expected: &str) -> Result<Profile> {
    let p = launch::read_plan(plan, expected)?;
    for name in ["profile.json", "profile.sha256"] {
        let m = fs::symlink_metadata(plan.join(name))?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.gid() == unsafe { libc::getegid() }
                && m.mode() & 0o7777 == 0o400,
            "edit_refresh_immutable_plan_required"
        );
    }
    let mut entries = fs::read_dir(plan)?;
    let mut names = Vec::new();
    for _ in 0..3 {
        if let Some(entry) = entries.next() {
            names.push(entry?.file_name());
        }
    }
    names.sort();
    ensure!(
        names == ["profile.json", "profile.sha256"],
        "edit_refresh_plan_inventory"
    );
    ensure!(
        !plan.starts_with(&p.root) && !p.root.starts_with(plan),
        "edit_state_overlaps_output"
    );
    Ok(p)
}

fn destination(out: &Path, old: &Path, p: &Profile) -> Result<()> {
    let parent = out.parent().context("edit_plan_parent")?;
    launch::private_dir(parent)?;
    let name = out
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| profile::leaf(s))
        .context("edit_plan_name")?;
    ensure!(
        out.is_absolute()
            && parent.join(name) == out
            && !out.starts_with(&p.root)
            && !p.root.starts_with(out)
            && !out.starts_with(old)
            && !old.starts_with(out),
        "edit_refresh_destination_invalid"
    );
    ensure!(
        fs::symlink_metadata(out).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "edit_plan_already_exists_or_publication_failed"
    );
    Ok(())
}

fn observe(p: &Profile) -> Result<(Profile, Vec<Observation>)> {
    ensure!(
        replace_file::inspect_workspace(&p.root)? == p.root_identity,
        "edit_root_changed"
    );
    let mut next = p.clone();
    let mut observations = Vec::with_capacity(p.targets.len());
    for t in &mut next.targets {
        let current = if t.create {
            // Never infer a new operation from existence, even if bytes match.
            ensure!(
                fs::symlink_metadata(p.root.join(&t.name))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "edit_refresh_create_exists_use_explicit_prepare_for_replace"
            );
            None
        } else {
            let current = replace_file::preview(&p.root, &p.root.join(&t.name), "")?;
            Some(Baseline {
                identity: current.old_identity,
                sha256: current.old_sha256,
            })
        };
        if t.replacement.is_some() {
            t.replacement = current.clone();
        }
        observations.push(Observation {
            name: t.name.clone(),
            current,
        });
    }
    Ok((next, observations))
}

fn proposal(plan: &Path, expected: &str, out: &Path) -> Result<Proposal> {
    let old = immutable(plan, expected)?;
    launch::verify_anchors(&old)?;
    destination(out, plan, &old)?;
    let (mut next, observed_targets) = observe(&old)?;
    // This changes the exact plan digest even when current bytes still match.
    // It says nothing about whether any previous operation actually executed.
    next.refreshed_from_sha256 = Some(expected.into());
    launch::verify(&next)?;
    let digest = profile::digest(&next)?;
    ensure!(digest != expected, "edit_refresh_digest_unchanged");
    Ok(Proposal {
        format: FORMAT,
        source_plan: plan.into(),
        source_plan_sha256: expected.into(),
        destination: out.into(),
        before: old,
        after: next,
        observed_targets,
        profile_sha256: digest,
        scope_unchanged: true,
        prior_operation_outcome: "unknown-not-inferred-from-current-bytes",
        requires_fresh_run_and_exact_ask: true,
    })
}

fn confirmation(proposal: &Proposal) -> Result<String> {
    let mut raw = b"agentfw/edit-plan-refresh/v1\0".to_vec();
    raw.extend(profile::canonical(proposal)?);
    Ok(replace_file::content_sha256(&raw))
}

pub(super) fn command(
    plan: &Path,
    expected: &str,
    out: &Path,
    apply: bool,
    confirm: Option<&str>,
) -> Result<Value> {
    ensure!(
        apply == confirm.is_some(),
        "edit_refresh_explicit_confirmation_required"
    );
    let old = immutable(plan, expected)?;
    launch::verify_anchors(&old)?;
    // Reuse the executor's independent directory flock. Every accepted create
    // or replacement writer conflicts with it; no lock file is created.
    let root = crate::sandbox::PinnedWorkspace::open(&old.root)?;
    let _lock = replace_file::writer_lock(&root.duplicate_root_descriptor()?)?;
    let proposed = proposal(plan, expected, out)?;
    let binding = confirmation(&proposed)?;
    if apply {
        ensure!(
            confirm.is_some_and(|s| crate::native::is_digest(s)
                && bool::from(s.as_bytes().ct_eq(binding.as_bytes()))),
            "edit_refresh_confirmation_changed"
        );
        launch::publish_checked(out, &proposed.after, || {
            ensure!(
                proposal(plan, expected, out)? == proposed,
                "edit_refresh_inputs_changed"
            );
            Ok(())
        })?;
    }
    Ok(json!({"format":FORMAT,"executed":apply,"authority":false,
        "status":if apply {"prepared-not-active"} else {"preview"},
        "confirmation_sha256":binding,"profile_sha256":proposed.profile_sha256,"proposal":proposed}))
}

#[cfg(test)]
mod tests;
