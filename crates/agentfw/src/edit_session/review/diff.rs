// SPDX-License-Identifier: Apache-2.0
//! Consented, bounded observation only. No process, writer or export is invoked.
use super::{
    audit, baseline_target, observe, profile, recheck, selected, verify_baseline, Args, Budget,
    Directory, FileIdentity, Reviewed, CAP,
};
use anyhow::{ensure, Context as _, Result};
use std::collections::BTreeMap;
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

mod unified;
const DIFF_FORMAT: &str = "sw-installed-edit-diff/1";

struct Baseline {
    path: PathBuf,
    leaf: String,
    parent: Directory,
    parent_identity: (u64, u64, u32, u32, u32),
    identity: FileIdentity,
    bytes: Vec<u8>,
}
fn directory_identity(dir: &Directory) -> Result<(u64, u64, u32, u32, u32)> {
    let m = dir.metadata().map_err(anyhow::Error::msg)?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
impl Baseline {
    fn select(
        name: &str,
        path: &str,
        args: &Args,
        review: &Reviewed,
        budget: &mut Budget,
    ) -> Result<Self> {
        baseline_target(name, review)?;
        let path = Path::new(path);
        let raw = path.as_os_str().as_encoded_bytes();
        ensure!(
            path.is_absolute()
                && raw.len() <= 4096
                && raw.len() > 1
                && raw[1..]
                    .split(|b| *b == b'/')
                    .all(|n| !n.is_empty() && n != b"." && n != b".."),
            "edit_diff_baseline_canonical_path_required"
        );
        for protected in [
            &args.run,
            &review.selection.profile.root,
            &review.selection.profile.component.home,
        ] {
            ensure!(
                !path.starts_with(protected) && !protected.starts_with(path),
                "edit_diff_baseline_scope_overlap"
            );
        }
        // Only the explicitly supplied leaf is selected. Unicode/spaces are
        // permitted here; output declarations retain their existing grammar.
        let leaf = path
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| s.len() <= 255)
            .context("edit_diff_baseline_leaf_invalid")?
            .to_owned();
        let parent = Directory::open(path.parent().context("edit_diff_baseline_parent_missing")?)
            .map_err(anyhow::Error::msg)?;
        let parent_identity = directory_identity(&parent)?;
        let (bytes, meta) = parent
            .read_output(&leaf, CAP, budget)
            .map_err(anyhow::Error::msg)?
            .context("edit_diff_baseline_unavailable")?;
        verify_baseline(name, &bytes, review)?;
        Ok(Self {
            path: path.to_owned(),
            leaf,
            parent,
            parent_identity,
            identity: FileIdentity::from(&meta),
            bytes,
        })
    }
    fn recheck(&self, budget: &mut Budget) -> Result<()> {
        let fresh = Directory::open(self.path.parent().unwrap()).map_err(anyhow::Error::msg)?;
        ensure!(
            directory_identity(&fresh)? == self.parent_identity
                && directory_identity(&self.parent)? == self.parent_identity,
            "edit_diff_baseline_parent_changed"
        );
        let (bytes, meta) = self
            .parent
            .read_output(&self.leaf, CAP, budget)
            .map_err(anyhow::Error::msg)?
            .context("edit_diff_baseline_disappeared")?;
        ensure!(
            bytes == self.bytes && FileIdentity::from(&meta) == self.identity,
            "edit_diff_baseline_changed"
        );
        let fresh = Directory::open(self.path.parent().unwrap()).map_err(anyhow::Error::msg)?;
        ensure!(
            directory_identity(&fresh)? == self.parent_identity,
            "edit_diff_baseline_parent_changed"
        );
        Ok(())
    }
    fn binding(&self) -> serde_json::Value {
        serde_json::json!({"path_sha256":audit::sha(self.path.as_os_str().as_encoded_bytes()),
            "parent_identity":self.parent_identity,"identity":self.identity,"sha256":audit::sha(&self.bytes)})
    }
}

pub(super) fn reason(error: &anyhow::Error) -> String {
    error
        .chain()
        .filter_map(|e| {
            let code = e.to_string();
            (code.len() <= 128
                && code
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                && [
                    "edit_",
                    "selected_",
                    "current_",
                    "terminal_",
                    "retained_",
                    "diagnostic_",
                ]
                .iter()
                .any(|p| code.starts_with(p)))
            .then_some(code)
        })
        .next()
        .unwrap_or_else(|| "edit_diff_selected_input_unavailable".into())
}

pub(super) fn run(args: &Args) -> Result<()> {
    ensure!(
        args.consent_private_content,
        "edit_diff_private_content_consent_required"
    );
    ensure!(
        !args.diff.is_empty()
            && args.diff.len() <= profile::MAX_TARGETS
            && args.diff_baseline.len() <= profile::MAX_TARGETS,
        "edit_diff_selection_cap"
    );
    ensure!(
        args.diff_baseline.is_empty() || args.consent_baseline_content,
        "edit_diff_baseline_consent_required"
    );
    // Also enforce read-only separation for callers constructing Args directly.
    ensure!(
        args.export.is_none()
            && args.include.is_empty()
            && args.expect_observation.is_none()
            && args.show.is_empty()
            && args.baseline.is_empty(),
        "edit_diff_read_only_mode_required"
    );
    let mut budget = Budget::new();
    let review = observe(args, &mut budget)?;
    let names = selected(&args.diff, &review.observation.outputs)?;
    let mut baselines = BTreeMap::new();
    for spec in &args.diff_baseline {
        let (name, path) = spec
            .split_once('=')
            .context("edit_diff_baseline_selection_invalid")?;
        ensure!(
            names.contains(name) && !baselines.contains_key(name),
            "edit_diff_baseline_not_selected_or_duplicate"
        );
        baselines.insert(
            name.to_owned(),
            Baseline::select(name, path, args, &review, &mut budget)?,
        );
    }
    let mut limits = unified::Limits::default();
    let mut summaries = vec![];
    let mut displays = vec![];
    let mut bindings = vec![];
    for name in names {
        budget.tick(0).map_err(anyhow::Error::msg)?;
        let output = review
            .observation
            .outputs
            .iter()
            .find(|o| o.name == name)
            .unwrap();
        let current = output
            .content
            .as_deref()
            .context("edit_diff_output_missing")?;
        let baseline = baselines.get(name);
        let rendered = unified::render(
            name,
            baseline.map(|b| b.leaf.as_str()),
            baseline.map(|b| b.bytes.as_slice()),
            current,
            &mut limits,
            &mut budget,
        )?;
        summaries.push(serde_json::json!({"name_sha256":audit::sha(name.as_bytes()),
            "baseline":if baseline.is_some(){"verified_explicit_pre_edit_content_not_writer_proof"}else{"new_file_view_no_baseline_selected"},
            "baseline_sha256":baseline.map(|b|audit::sha(&b.bytes)),"output_sha256":output.sha256,
            "old_bytes":baseline.map(|b|b.bytes.len()),"new_bytes":current.len(),
            "old_lines":rendered.old_lines,"new_lines":rendered.new_lines,
            "added_lines":rendered.added,"removed_lines":rendered.removed,
            "equal":baseline.is_some_and(|b|b.bytes == current),"complete":true}));
        bindings.push(serde_json::json!({"name_sha256":audit::sha(name.as_bytes()),"baseline":baseline.map(Baseline::binding)}));
        displays.push(serde_json::json!({"name_escaped":unified::escape(name),
            "encoding":"unified_diff_of_rust_ascii_escaped_untrusted_lines_not_apply_instructions",
            "text":rendered.text}));
    }
    recheck(args, &review, &mut budget)?;
    for baseline in baselines.values() {
        baseline.recheck(&mut budget)?;
    }
    // Last-file rechecks happen after every baseline observation as well.
    recheck(args, &review, &mut budget)?;
    let observation_sha256 = profile::digest(&review.observation)?;
    let comparison_sha256 = profile::digest(&(
        DIFF_FORMAT,
        &observation_sha256,
        &bindings,
        &summaries,
        &displays,
    ))?;
    let response = serde_json::json!({"format":DIFF_FORMAT,"status":"reviewed","complete":true,
        "observation_sha256":observation_sha256,"observation":review.observation,
        "comparison_sha256":comparison_sha256,"summary":summaries,"baseline_bindings":bindings,"display":displays,
        "limits":unified::bounds(),"private_content":true,"executed":false,"authority":false,"exported":false});
    let raw = serde_json::to_string(&response)?;
    ensure!(raw.len() <= 128 * 1024, "edit_diff_response_cap");
    println!("{raw}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};
    #[derive(Parser)]
    struct Grammar {
        #[command(flatten)]
        args: Args,
    }
    #[test]
    fn diff_is_explicitly_selected_and_cannot_export() {
        Grammar::command().debug_assert();
        let words = [
            "review",
            "--run",
            "/private/run",
            "--sha256",
            &"a".repeat(64),
            "--diff",
            "a.txt",
        ];
        assert!(Grammar::try_parse_from(words.iter().copied()).is_ok());
        assert!(
            Grammar::try_parse_from(words.iter().copied().chain(["--export", "/private/new"]))
                .is_err()
        );
        assert!(Grammar::try_parse_from([
            "review",
            "--run",
            "/private/run",
            "--sha256",
            &"a".repeat(64),
            "--diff-baseline",
            "a.txt=/private/old"
        ])
        .is_err());
    }
    #[test]
    fn errors_never_echo_path_or_content() {
        assert_eq!(
            reason(&anyhow::anyhow!("/private/secret\n\u{1b}")),
            "edit_diff_selected_input_unavailable"
        );
        assert_eq!(
            reason(&anyhow::anyhow!("edit_diff_work_cap")),
            "edit_diff_work_cap"
        );
    }
}
