// SPDX-License-Identifier: Apache-2.0
//! Exact retained result observation. No execution, authority or writer proof.
use super::{
    control,
    diagnostic::{
        audit,
        io::{Budget, Directory},
        linux::{self, Selection},
    },
    profile::{self, Profile},
    record::{self, ProcessIdentity},
};
use anyhow::{ensure, Context as _, Result};
use clap::Args as ClapArgs;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::Metadata,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const FORMAT: &str = "sw-installed-edit-review/1";
const CAP: u64 = 4096;

pub(super) mod export_set;

#[derive(ClapArgs, Debug)]
pub(super) struct Args {
    #[arg(long)]
    run: PathBuf,
    /// Expected digest from the operator's immutable prepared plan.
    #[arg(long)]
    sha256: String,
    /// Exact declared mutation outputs to display as escaped untrusted text.
    #[arg(long)]
    show: Vec<String>,
    /// Explicit NAME=/absolute/baseline file. Verifies recorded pre-edit content identity.
    #[arg(long)]
    baseline: Vec<String>,
    /// This operation may display or save the selected private file contents.
    #[arg(long)]
    consent_private_content: bool,
    /// New owner-private bundle directory, separate from sanitized support export.
    #[arg(long, requires_all = ["include", "expect_observation", "consent_private_content"])]
    export: Option<PathBuf>,
    /// Individually consented output names; never implicitly include all outputs.
    #[arg(long, requires = "export")]
    include: Vec<String>,
    /// Exact observation_sha256 from a preceding read-only review.
    #[arg(long, requires = "export")]
    expect_observation: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct FileIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl From<&Metadata> for FileIdentity {
    fn from(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}
#[derive(Serialize)]
struct Output {
    name: String,
    observation: &'static str,
    kind: &'static str,
    bytes: Option<usize>,
    sha256: Option<String>,
    identity: Option<FileIdentity>,
    text: bool,
    baseline: &'static str,
    #[serde(skip)]
    content: Option<Vec<u8>>,
}
#[derive(Serialize)]
struct Observation {
    format: &'static str,
    run_sha256: String,
    profile_sha256: String,
    binding_sha256: String,
    terminal: &'static str,
    outputs: Vec<Output>,
    attribution: &'static str,
    authority: bool,
    executed: bool,
}
struct Reviewed {
    selection: Selection,
    root: Directory,
    observation: Observation,
    terminal: Vec<u8>,
    receipt: Vec<u8>,
    host: Vec<u8>,
}

/// Reuse the accepted completed-run checks without treating a review as a grant.
/// The held output-directory lock remains alive until this selection is dropped.
pub(super) struct SelectedOutput {
    args: Args,
    reviewed: Reviewed,
    index: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct OutputBinding {
    pub run: PathBuf,
    pub run_identity: (u64, u64),
    pub run_sha256: String,
    pub profile_sha256: String,
    pub component: profile::Component,
    pub observation_sha256: String,
    pub binding_sha256: String,
    pub output: String,
    pub output_identity: FileIdentity,
    pub output_sha256: String,
    pub output_bytes: usize,
}

impl SelectedOutput {
    pub fn open(run: &Path, expected: &str, name: &str, budget: &mut Budget) -> Result<Self> {
        let args = Args {
            run: run.into(),
            sha256: expected.into(),
            show: vec![],
            baseline: vec![],
            consent_private_content: false,
            export: None,
            include: vec![],
            expect_observation: None,
        };
        let reviewed = observe(&args, budget)?;
        let index = reviewed
            .observation
            .outputs
            .iter()
            .position(|o| o.name == name)
            .context("edit_apply_output_not_declared")?;
        let selected = Self {
            args,
            reviewed,
            index,
        };
        selected.content()?;
        Ok(selected)
    }

    pub fn profile(&self) -> &Profile {
        &self.reviewed.selection.profile
    }

    pub fn content(&self) -> Result<&str> {
        let output = &self.reviewed.observation.outputs[self.index];
        ensure!(output.text, "edit_apply_text_output_required");
        std::str::from_utf8(
            output
                .content
                .as_deref()
                .context("edit_apply_output_missing")?,
        )
        .context("edit_apply_text_output_required")
    }

    pub fn binding(&self) -> Result<OutputBinding> {
        let observation = &self.reviewed.observation;
        let output = &observation.outputs[self.index];
        let meta = self
            .reviewed
            .selection
            .directory
            .metadata()
            .map_err(anyhow::Error::msg)?;
        Ok(OutputBinding {
            run: self.args.run.clone(),
            run_identity: (meta.dev(), meta.ino()),
            run_sha256: observation.run_sha256.clone(),
            profile_sha256: observation.profile_sha256.clone(),
            component: self.profile().component.clone(),
            observation_sha256: profile::digest(observation)?,
            binding_sha256: observation.binding_sha256.clone(),
            output: output.name.clone(),
            output_identity: output
                .identity
                .clone()
                .context("edit_apply_output_missing")?,
            output_sha256: output.sha256.clone().context("edit_apply_output_missing")?,
            output_bytes: output.bytes.context("edit_apply_output_missing")?,
        })
    }

    pub fn recheck(&self, budget: &mut Budget) -> Result<()> {
        recheck(&self.args, &self.reviewed, budget)
    }
}
fn needed(dir: &Directory, name: &str, cap: u64, budget: &mut Budget) -> Result<Vec<u8>> {
    dir.read(name, cap, budget)
        .map_err(anyhow::Error::msg)?
        .context("edit_review_record_missing")
}
fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    serde_json::from_value(audit::strict(raw).map_err(anyhow::Error::msg)?)
        .map_err(|_| anyhow::anyhow!("edit_review_schema_invalid"))
}
fn inactive(identity: &ProcessIdentity) -> Result<()> {
    identity.validate()?;
    ensure!(
        identity.uid == unsafe { libc::geteuid() },
        "edit_review_foreign_process"
    );
    let current = record::process_identity(std::process::id())?;
    ensure!(
        identity.boot_id == current.boot_id,
        "edit_review_stale_boot"
    );
    match record::process_identity(identity.pid) {
        Ok(value) => ensure!(&value != identity, "edit_review_process_still_present"),
        Err(_) => ensure!(
            std::fs::symlink_metadata(format!("/proc/{}", identity.pid))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "edit_review_process_indeterminate"
        ),
    }
    Ok(())
}
fn root(p: &Profile) -> Result<Directory> {
    let dir = Directory::open(&p.root).map_err(anyhow::Error::msg)?;
    let meta = dir.metadata().map_err(anyhow::Error::msg)?;
    ensure!(
        meta.dev() == p.root_identity.device
            && meta.ino() == p.root_identity.inode
            && meta.gid() == unsafe { libc::getegid() }
            && meta.mode() & 0o7777 == 0o700,
        "edit_review_output_root_changed"
    );
    Ok(dir)
}
fn text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|s| {
        !s.chars()
            .any(|c| c == '\0' || (c.is_control() && !matches!(c, '\n' | '\r' | '\t' | '\u{1b}')))
    })
}
fn observe(args: &Args, budget: &mut Budget) -> Result<Reviewed> {
    ensure!(
        cfg!(target_arch = "x86_64"),
        "edit_review_requires_native_linux_x86_64"
    );
    let selection = linux::select(&args.run, budget).map_err(anyhow::Error::msg)?;
    let Selection {
        directory,
        context,
        profile,
        ..
    } = &selection;
    ensure!(
        crate::native::is_digest(&args.sha256) && args.sha256 == context.profile_sha256,
        "edit_review_expected_profile_mismatch"
    );
    ensure!(
        directory
            .immutable("profile.json", 128 * 1024, budget)
            .map_err(anyhow::Error::msg)?
            == selection.profile_bytes
            && directory
                .immutable("profile.sha256", 64, budget)
                .map_err(anyhow::Error::msg)?
                == args.sha256.as_bytes(),
        "edit_review_immutable_profile_changed"
    );
    let terminal = needed(directory, "terminal.json", 32 * 1024, budget)?;
    ensure!(
        linux::terminal(&terminal, context, profile.mutation_quota.as_ref())
            .map_err(anyhow::Error::msg)?
            == "recorded_host_completed",
        "edit_review_run_incomplete"
    );
    inactive(&context.owner)?;
    let host = needed(directory, "host-process.json", 4096, budget)?;
    let host_identity: ProcessIdentity = decode(&host)?;
    inactive(&host_identity)?;
    let meta = directory.metadata().map_err(anyhow::Error::msg)?;
    let receipt =
        control::retained_completion(&args.run, context, (meta.dev(), meta.ino()), budget)?;
    let root = root(profile)?;
    root.observation_lock().map_err(anyhow::Error::msg)?;
    let mut outputs = vec![];
    for target in profile
        .targets
        .iter()
        .filter(|t| t.create || t.replacement.is_some())
    {
        let observed = root
            .read_output(&target.name, CAP, budget)
            .map_err(anyhow::Error::msg)?;
        let (content, identity) = match observed {
            Some((bytes, meta)) => (Some(bytes), Some(FileIdentity::from(&meta))),
            None => (None, None),
        };
        outputs.push(Output {
            name: target.name.clone(),
            observation: if content.is_some() {
                "present"
            } else {
                "absent"
            },
            kind: if content.is_some() {
                "regular"
            } else {
                "missing"
            },
            bytes: content.as_ref().map(Vec::len),
            sha256: content.as_deref().map(audit::sha),
            identity,
            text: content.as_deref().is_some_and(text),
            baseline: if target.replacement.is_some() {
                "baseline_unavailable"
            } else {
                "not_applicable_create"
            },
            content,
        });
    }
    let binding_sha256 = profile::digest(&(
        audit::sha(&selection.run_bytes),
        audit::sha(&selection.context_bytes),
        audit::sha(&terminal),
        audit::sha(&receipt),
        audit::sha(&host),
        (meta.dev(), meta.ino()),
    ))?;
    let observation = Observation {
        format: FORMAT,
        run_sha256: audit::sha(&selection.run_bytes),
        profile_sha256: args.sha256.clone(),
        binding_sha256,
        terminal: "recorded_host_completed_and_cleanup_confirmed",
        outputs,
        attribution: "current_bytes_not_writer_commit_delivery_or_model_consumption_proof",
        authority: false,
        executed: false,
    };
    Ok(Reviewed {
        selection,
        root,
        observation,
        terminal,
        receipt,
        host,
    })
}
fn recheck(args: &Args, review: &Reviewed, budget: &mut Budget) -> Result<()> {
    let selected = linux::select(&args.run, budget).map_err(anyhow::Error::msg)?;
    let old = &review.selection;
    ensure!(
        selected.run_bytes == old.run_bytes
            && selected.context_bytes == old.context_bytes
            && selected.profile_bytes == old.profile_bytes,
        "edit_review_binding_changed"
    );
    ensure!(
        selected
            .directory
            .immutable("profile.json", 128 * 1024, budget)
            .map_err(anyhow::Error::msg)?
            == old.profile_bytes
            && selected
                .directory
                .immutable("profile.sha256", 64, budget)
                .map_err(anyhow::Error::msg)?
                == args.sha256.as_bytes(),
        "edit_review_immutable_profile_changed"
    );
    let meta = selected.directory.metadata().map_err(anyhow::Error::msg)?;
    let old_meta = old.directory.metadata().map_err(anyhow::Error::msg)?;
    ensure!(
        meta.dev() == old_meta.dev() && meta.ino() == old_meta.ino(),
        "edit_review_run_changed"
    );
    ensure!(
        needed(&selected.directory, "terminal.json", 32 * 1024, budget)? == review.terminal
            && needed(&selected.directory, "host-process.json", 4096, budget)? == review.host
            && control::retained_completion(
                &args.run,
                &selected.context,
                (meta.dev(), meta.ino()),
                budget
            )? == review.receipt,
        "edit_review_terminal_changed"
    );
    inactive(&selected.context.owner)?;
    inactive(&decode::<ProcessIdentity>(&review.host)?)?;
    let current_root = root(&selected.profile)?;
    let current_meta = current_root.metadata().map_err(anyhow::Error::msg)?;
    let held_meta = review.root.metadata().map_err(anyhow::Error::msg)?;
    ensure!(
        current_meta.dev() == held_meta.dev() && current_meta.ino() == held_meta.ino(),
        "edit_review_output_root_changed"
    );
    for output in &review.observation.outputs {
        let current = review
            .root
            .read_output(&output.name, CAP, budget)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            match (current, &output.content, &output.identity) {
                (None, None, None) => true,
                (Some((bytes, meta)), Some(old_bytes), Some(identity)) =>
                    bytes == *old_bytes && &FileIdentity::from(&meta) == identity,
                _ => false,
            },
            "edit_review_output_changed"
        );
    }
    Ok(())
}
fn selected<'a>(names: &'a [String], outputs: &[Output]) -> Result<BTreeSet<&'a str>> {
    ensure!(
        names.len() <= profile::MAX_TARGETS,
        "edit_review_selection_cap"
    );
    let mut result = BTreeSet::new();
    for name in names {
        ensure!(
            outputs.iter().any(|o| &o.name == name) && result.insert(name.as_str()),
            "edit_review_target_not_declared_or_duplicate"
        );
    }
    Ok(result)
}
// Rust's ASCII escape format quotes every non-ASCII codepoint as well as ESC,
// line breaks, bidi controls and C1 terminals. Content cannot become terminal UI.
fn escaped(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes).context("edit_review_text_required")?;
    let rendered = text
        .chars()
        .flat_map(char::escape_default)
        .collect::<String>();
    ensure!(
        rendered.len() <= 10 * CAP as usize,
        "edit_review_render_cap"
    );
    Ok(rendered)
}
fn baseline(spec: &str, review: &Reviewed, budget: &mut Budget) -> Result<(String, Vec<u8>)> {
    let (name, path) = spec
        .split_once('=')
        .context("edit_review_baseline_selection")?;
    let target = review
        .selection
        .profile
        .targets
        .iter()
        .find(|t| t.name == name)
        .and_then(|t| t.replacement.as_ref())
        .context("edit_review_baseline_not_replacement")?;
    let path = Path::new(path);
    let leaf = path
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|n| profile::leaf(n))
        .context("edit_review_baseline_leaf")?;
    let parent = Directory::open(path.parent().context("edit_review_baseline_parent")?)
        .map_err(anyhow::Error::msg)?;
    let (bytes, _) = parent
        .read_output(leaf, CAP, budget)
        .map_err(anyhow::Error::msg)?
        .context("edit_review_baseline_unavailable")?;
    // A separately retained copy can verify the plan's content identity, never
    // the old inode's provenance or the source/writer of these bytes.
    ensure!(
        bytes.len() as u64 == target.identity.size && audit::sha(&bytes) == target.sha256,
        "edit_review_baseline_content_identity_mismatch"
    );
    ensure!(text(&bytes), "edit_review_baseline_text_required");
    Ok((name.to_owned(), bytes))
}
pub(super) fn command(args: Args) -> Result<()> {
    let result = run(&args);
    // Never echo an untrusted path, payload or underlying OS/parser error.
    result.map_err(|e| {
        anyhow::anyhow!(
            "edit_review_refused: {}",
            e.chain()
                .last()
                .map(ToString::to_string)
                .filter(|s| s.starts_with("edit_")
                    || s.starts_with("selected_")
                    || s.starts_with("current_")
                    || s.starts_with("terminal_")
                    || s.starts_with("retained_"))
                .unwrap_or_else(|| "unsafe_or_unavailable_selected_state".into())
        )
    })
}
fn run(args: &Args) -> Result<()> {
    ensure!(
        args.baseline.len() <= profile::MAX_TARGETS,
        "edit_review_baseline_cap"
    );
    ensure!(
        args.consent_private_content
            || (args.show.is_empty() && args.baseline.is_empty() && args.export.is_none()),
        "edit_review_private_content_consent_required"
    );
    let mut budget = Budget::new();
    let review = observe(args, &mut budget)?;
    let show = selected(&args.show, &review.observation.outputs)?;
    let include = selected(&args.include, &review.observation.outputs)?;
    let digest = profile::digest(&review.observation)?;
    let mut displays = vec![];
    for name in show {
        let output = review
            .observation
            .outputs
            .iter()
            .find(|o| o.name == name)
            .unwrap();
        ensure!(output.text, "edit_review_selected_text_unavailable");
        displays.push(serde_json::json!({"name": name, "encoding":"rust_ascii_escaped_untrusted_text", "text": escaped(output.content.as_ref().unwrap())?}));
    }
    let mut comparisons = vec![];
    let mut baselines = BTreeSet::new();
    for spec in &args.baseline {
        let (name, before) = baseline(spec, &review, &mut budget)?;
        ensure!(
            baselines.insert(name.clone()),
            "edit_review_duplicate_baseline"
        );
        let output = review
            .observation
            .outputs
            .iter()
            .find(|o| o.name == name)
            .unwrap();
        ensure!(output.text, "edit_review_selected_text_unavailable");
        let current = output.content.as_ref().unwrap();
        comparisons.push(serde_json::json!({"name":name, "verification":"recorded_pre_edit_content_sha256_and_size_not_inode_provenance",
            "baseline":"verified_explicit_copy", "equal": before == *current,
            "before_escaped":escaped(&before)?, "current_escaped":escaped(current)?}));
    }
    recheck(args, &review, &mut budget)?;
    let response = serde_json::json!({"format":FORMAT, "status":"reviewed", "observation_sha256":digest,
        "observation":&review.observation, "display":displays, "comparison":comparisons,
        "exported":args.export.is_some(), "private_content":args.consent_private_content});
    let bytes = serde_json::to_string(&response)?;
    ensure!(bytes.len() <= 128 * 1024, "edit_review_response_cap");
    if let Some(out) = &args.export {
        ensure!(
            args.expect_observation.as_deref() == Some(digest.as_str()) && !include.is_empty(),
            "edit_review_observation_mismatch_or_empty_export"
        );
        for protected in [
            &args.run,
            &review.selection.profile.root,
            &review.selection.profile.component.home,
        ] {
            ensure!(
                !out.starts_with(protected) && !protected.starts_with(out),
                "edit_review_export_overlap"
            );
        }
        let mut files = vec![];
        let mut manifest_files = vec![];
        for name in include {
            ensure!(name != "manifest.json", "edit_review_reserved_export_name");
            let output = review
                .observation
                .outputs
                .iter()
                .find(|o| o.name == name)
                .unwrap();
            let bytes = output
                .content
                .as_ref()
                .context("edit_review_export_output_missing")?;
            files.push((name, bytes.as_slice()));
            manifest_files.push(
                serde_json::json!({"name":name, "bytes":bytes.len(), "sha256":audit::sha(bytes)}),
            );
        }
        let manifest = serde_json::to_vec(
            &serde_json::json!({"format":"sw-installed-edit-private-review-bundle/1",
            "privacy":"operator_selected_private_file_contents_not_sanitized_support",
            "observation_sha256":digest, "observation":&review.observation, "files":manifest_files,
            "application":"none", "authority":false}),
        )?;
        ensure!(manifest.len() <= 32 * 1024, "edit_review_manifest_cap");
        files.push(("manifest.json", &manifest));
        crate::private_export::publish(out, &files, || recheck(args, &review, &mut budget))?;
    }
    println!("{bytes}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rendering_escapes_terminal_unicode_and_binary_is_not_text() {
        assert_eq!(escaped(b"hello\n\x1b[31m").unwrap(), "hello\\n\\u{1b}[31m");
        assert_eq!(escaped("\u{202e}".as_bytes()).unwrap(), "\\u{202e}");
        assert!(!text(b"\xff"));
        assert!(!text(b"a\0b"));
        assert!(text(b"hello\n"));
    }
    #[test]
    fn exact_selection_refuses_traversal_duplicates_and_read_only_sources() {
        assert!(selected(&["../secret".into()], &[]).is_err());
        assert!(selected(&["source.txt".into()], &[]).is_err());
        assert!(selected(&[], &[]).unwrap().is_empty());
    }
}
