// SPDX-License-Identifier: Apache-2.0
//! SOU-204 CLI acceptance on committed fixtures: exit codes, refusals that
//! write nothing, reproducible output and no writes outside the new output
//! directory (isolated HOME/USERPROFILE, empty working directory, unchanged
//! inputs). These are filesystem observations of one process run; they do not
//! by themselves prove the absence of network traffic.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use sha2::{Digest, Sha256};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schema_upgrade")
}

fn tree(path: &Path) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let rel = entry
                .path()
                .strip_prefix(path)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if entry.metadata().unwrap().is_dir() {
                rows.push((rel, Vec::new()));
                stack.push(entry.path());
            } else {
                rows.push((rel, std::fs::read(entry.path()).unwrap()));
            }
        }
    }
    rows.sort();
    rows
}

fn digest_files(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|p| format!("{:x}", Sha256::digest(std::fs::read(p).unwrap())))
        .collect()
}

struct Env {
    home: tempfile::TempDir,
    cwd: tempfile::TempDir,
    out_root: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            cwd: tempfile::tempdir().unwrap(),
            out_root: tempfile::tempdir().unwrap(),
        }
    }

    fn run(&self, out: &str, args: &[&Path], flags: &[&str]) -> (Output, PathBuf) {
        let out = self.out_root.path().join(out);
        let mut command = Command::new(env!("CARGO_BIN_EXE_agentfw"));
        command.arg("mcp-schema-upgrade");
        for (flag, path) in flags.iter().zip(args) {
            command.arg(flag).arg(path);
        }
        let output = command
            .arg("--out")
            .arg(&out)
            .env_clear()
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .current_dir(self.cwd.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (output, out)
    }

    fn assert_untouched(&self) {
        assert!(tree(self.home.path()).is_empty(), "HOME was written");
        assert!(
            tree(self.cwd.path()).is_empty(),
            "working directory was written"
        );
    }
}

fn profile(name: &str, file: &str) -> PathBuf {
    root().join("profiles/mcp").join(name).join(file)
}

fn baseline(fixture: &Value) -> (PathBuf, PathBuf, PathBuf) {
    let git = fixture["baseline"]
        .as_str()
        .unwrap()
        .contains("git-readonly-v1");
    let name = if git {
        "git-readonly-v1"
    } else {
        "filesystem-readonly-v1"
    };
    (
        profile(name, "upstream-tools-list.json"),
        profile(name, "upstream-identity.json"),
        fixtures().join(format!("{name}.registry.json")),
    )
}

#[test]
fn every_committed_fixture_meets_its_manifest_expectation_without_side_effects() {
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(fixtures().join("MANIFEST.json")).unwrap()).unwrap();
    let env = Env::new();
    let protected: Vec<PathBuf> = [
        "filesystem-readonly-v1/upstream-tools-list.json",
        "filesystem-readonly-v1/upstream-identity.json",
        "git-readonly-v1/upstream-tools-list.json",
        "git-readonly-v1/upstream-identity.json",
    ]
    .iter()
    .map(|p| root().join("profiles/mcp").join(p))
    .collect();
    let before_digests = digest_files(&protected);
    let fixture_tree = tree(&fixtures());
    let mut ran = 0;
    for fixture in manifest["fixtures"].as_array().unwrap() {
        let kind = fixture["kind"].as_str().unwrap();
        if kind != "mutated_upgrade_snapshot" && kind != "invalid_input" {
            continue;
        }
        let name = fixture["fixture"].as_str().unwrap();
        let after = fixtures().join(name);
        let (before, identity, registry) = baseline(fixture);
        let (output, out) = env.run(
            name,
            &[&before, &after, &identity, &registry],
            &["--before", "--after", "--before-identity", "--registry"],
        );
        let expect = &fixture["expect"];
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            expect["exit"].as_i64().map(|c| c as i32),
            "{name}: {stderr}"
        );
        if kind == "invalid_input" {
            let code = expect["refusal"].as_str().unwrap();
            assert!(stderr.contains(code), "{name}: {stderr}");
            assert!(!out.exists(), "{name}: refusal must write nothing");
        } else {
            let report: Value =
                serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
            assert_eq!(
                report["summary"]["classification"], expect["classification"],
                "{name}"
            );
            for k in expect["kinds"].as_array().into_iter().flatten() {
                assert!(
                    report["findings"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|f| &f["kind"] == k),
                    "{name}: missing {k}"
                );
            }
            assert_eq!(report["acceptance"]["analyzer_accepts"], false);
            let files: Vec<String> = tree(&out).into_iter().map(|(n, _)| n).collect();
            assert_eq!(
                files,
                [
                    "REVIEW_GUIDE.md",
                    "findings.csv",
                    "report.json",
                    "report.txt",
                    "review-pack.json"
                ]
            );
        }
        ran += 1;
    }
    assert_eq!(ran, 19);
    env.assert_untouched();
    assert_eq!(digest_files(&protected), before_digests, "inputs changed");
    assert_eq!(tree(&fixtures()), fixture_tree, "fixtures changed");
}

#[test]
fn destination_controls_are_reproducible_and_existing_output_is_refused() {
    let env = Env::new();
    let args = [
        profile("filesystem-readonly-v1", "upstream-tools-list.json"),
        fixtures().join("fs-destination-controls.json"),
        fixtures().join("fs-control-current.registry.json"),
        fixtures().join("fs-control-proposed.registry.json"),
    ];
    let refs: Vec<&Path> = args.iter().map(PathBuf::as_path).collect();
    let flags = ["--before", "--after", "--registry", "--proposed-registry"];
    let (first, a) = env.run("a", &refs, &flags);
    let (second, b) = env.run("b", &refs, &flags);
    assert_eq!(first.status.code(), Some(5));
    assert_eq!(second.status.code(), Some(5));
    assert_eq!(tree(&a), tree(&b), "identical inputs must reproduce output");
    let report: Value =
        serde_json::from_slice(&std::fs::read(a.join("report.json")).unwrap()).unwrap();
    let kinds: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["kind"].as_str().unwrap())
        .collect();
    for k in [
        "declared_selector_target_changed",
        "declared_action_changed",
        "declared_destination_changed",
        "declaration_binding_stale",
    ] {
        assert!(kinds.contains(&k), "{k}");
    }

    let before = tree(&a);
    let (again, _) = env.run("a", &refs, &flags);
    assert_eq!(again.status.code(), Some(4));
    assert_eq!(tree(&a), before, "existing output must not change");

    // --registry and --declarations are mutually exclusive (clap usage error).
    let (both, out) = env.run(
        "c",
        &[&args[0], &args[1], &args[2], &args[2]],
        &["--before", "--after", "--registry", "--declarations"],
    );
    assert_eq!(both.status.code(), Some(2));
    assert!(!out.exists());
    env.assert_untouched();
}

#[test]
fn unreadable_input_is_a_technical_failure_without_output() {
    let env = Env::new();
    let missing = env.cwd.path().join("missing.json");
    let present = profile("git-readonly-v1", "upstream-tools-list.json");
    let (output, out) = env.run("x", &[&present, &missing], &["--before", "--after"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(!out.exists());
    let (output, out) = env.run("y", &[&present, env.cwd.path()], &["--before", "--after"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "directory is not a regular file"
    );
    assert!(!out.exists());
    env.assert_untouched();
}

#[test]
fn current_declarations_are_required_unless_snapshot_only_is_explicit() {
    let env = Env::new();
    let before = profile("git-readonly-v1", "upstream-tools-list.json");
    let after = fixtures().join("git-semantic.json");
    let (refused, out) = env.run("missing", &[&before, &after], &["--before", "--after"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("missing_declarations"));
    assert!(!out.exists());

    let mut command = Command::new(env!("CARGO_BIN_EXE_agentfw"));
    let out = env.out_root.path().join("snapshot-only");
    let output = command
        .args(["mcp-schema-upgrade", "--snapshot-only", "--before"])
        .arg(&before)
        .arg("--after")
        .arg(&after)
        .arg("--out")
        .arg(&out)
        .env_clear()
        .env("HOME", env.home.path())
        .env("USERPROFILE", env.home.path())
        .current_dir(env.cwd.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));
    let report: Value =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
    assert_eq!(
        report["summary"]["semantic_review"],
        "unavailable_snapshot_only"
    );
    let text = std::fs::read_to_string(out.join("report.txt")).unwrap();
    assert!(text.contains("Semantic review is UNAVAILABLE"));
    env.assert_untouched();
}

#[test]
fn declaration_only_drift_exits_review_required_with_consistent_outputs() {
    let env = Env::new();
    let snapshot = profile("filesystem-readonly-v1", "upstream-tools-list.json");
    let current = fixtures().join("filesystem-readonly-v1.registry.json");
    let mut proposed: Value = serde_json::from_slice(&std::fs::read(&current).unwrap()).unwrap();
    for t in proposed["tools"].as_array_mut().unwrap() {
        if t["name"] == "read_text_file" {
            t["action_class"] = Value::from("network");
        }
    }
    let proposed_path = env.out_root.path().join("proposed.json");
    std::fs::write(&proposed_path, serde_json::to_vec(&proposed).unwrap()).unwrap();
    let flags = ["--before", "--after", "--registry", "--proposed-registry"];
    let (output, out) = env.run(
        "drift",
        &[&snapshot, &snapshot, &current, &proposed_path],
        &flags,
    );
    assert_eq!(output.status.code(), Some(5));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("review_required (exit 5)"), "{stdout}");
    let report: Value =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["summary"]["byte_identical"], true);
    assert_eq!(report["summary"]["outcome"], "review_required");
    assert_eq!(report["summary"]["exit_code"], 5);
    let text = std::fs::read_to_string(out.join("report.txt")).unwrap();
    assert!(text.contains("Snapshots byte-identical: true; declaration findings: 1"));
    let guide = std::fs::read_to_string(out.join("REVIEW_GUIDE.md")).unwrap();
    assert!(guide.contains("Outcome `review_required`"));

    // Control: identical snapshots and a proposal equal to the current registry.
    let (control, out) = env.run("same", &[&snapshot, &snapshot, &current, &current], &flags);
    assert_eq!(control.status.code(), Some(0));
    let report: Value =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["summary"]["outcome"], "no_drift");
    env.assert_untouched();
}
