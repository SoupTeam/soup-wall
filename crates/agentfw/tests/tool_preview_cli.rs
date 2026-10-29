// SPDX-License-Identifier: Apache-2.0
//! SOU-174: `agentfw tool-preview` through the real binary and a really installed package.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use agentfw::classifier_runtime::package::{self as pkg, Store, Which};
use serde_json::Value;

const CANARY: &str = "CANARY-SECRET-5d2e91";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn installed_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let store = Store::new(&home.path().join(".agentfw"));
    let archive = pkg::build(Which::Frozen, &root()).unwrap();
    store
        .install(&archive, Path::new("/usr/bin/python3"))
        .unwrap();
    home
}

fn tree(path: &Path) -> Vec<(String, u64, Vec<u8>)> {
    let mut rows = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            let rel = entry
                .path()
                .strip_prefix(path)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if meta.is_dir() {
                rows.push((rel, 0, Vec::new()));
                stack.push(entry.path());
            } else {
                rows.push((rel, meta.len(), std::fs::read(entry.path()).unwrap()));
            }
        }
    }
    rows.sort();
    rows
}

fn preview(home: &Path, frame: &str, extra: &[&str]) -> (Output, Value) {
    let cwd = tempfile::tempdir().unwrap();
    let file = cwd.path().join("frame.json");
    std::fs::write(&file, frame).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .args(["tool-preview", "--json", "--frame"])
        .arg(&file)
        .args(extra)
        .env_clear()
        .env("HOME", home)
        .current_dir(cwd.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    (output, report)
}

#[test]
fn benign_read_is_classified_by_the_installed_package_and_changes_nothing() {
    let home = installed_home();
    let before = tree(home.path());
    let (output, report) = preview(
        home.path(),
        r#"{"tool":"read_text_file","arguments":{"path":"/workspace/notes.txt"}}"#,
        &["--profile", "filesystem"],
    );
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert_eq!(report["outcome"], "classified");
    assert_eq!(
        report["classification"]["labels"],
        serde_json::json!(["read"])
    );
    assert_eq!(report["policy_verdict"], Value::Null);
    assert_eq!(report["non_authoritative"], true);
    let package = Store::new(&home.path().join(".agentfw")).current().unwrap();
    assert_eq!(report["identity"]["package_id"], package.id);
    assert_eq!(
        report["identity"]["classifier_sha256"],
        package.classifier_sha256
    );
    assert_eq!(
        tree(home.path()),
        before,
        "preview changed the install home"
    );
}

#[test]
fn refusals_start_no_worker_and_need_no_package() {
    let home = tempfile::tempdir().unwrap();
    for frame in [
        "",
        "{",
        r#"{"tool":"a","tool":"b","arguments":{}}"#,
        r#"{"tool":"a","arguments":{}} {"tool":"b","arguments":{}}"#,
    ] {
        let (output, report) = preview(home.path(), frame, &["--profile", "filesystem"]);
        assert_eq!(output.status.code(), Some(2), "{frame}");
        assert_eq!(report["outcome"], "refused");
    }
    assert!(
        std::fs::read_dir(home.path()).unwrap().next().is_none(),
        "preview created files in an empty home"
    );
}

#[test]
fn a_missing_package_is_a_technical_error_not_unknown() {
    let home = tempfile::tempdir().unwrap();
    let (output, report) = preview(
        home.path(),
        r#"{"tool":"read_text_file","arguments":{"path":"a.txt"}}"#,
        &["--profile", "filesystem"],
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(report["outcome"], "technical_error");
    assert_eq!(report["technical_error"]["code"], "package_not_installed");
    assert!(report.get("classification").is_none());
    assert!(std::fs::read_dir(home.path()).unwrap().next().is_none());
}

#[test]
fn an_altered_package_is_never_used() {
    use std::os::unix::fs::PermissionsExt;
    let home = installed_home();
    let store = Store::new(&home.path().join(".agentfw"));
    let id = store.verify().unwrap()["package"]
        .as_str()
        .unwrap()
        .to_owned();
    let file = store
        .root()
        .join("packages")
        .join(id)
        .join("rule_baseline.py");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut bytes = std::fs::read(&file).unwrap();
    bytes.extend_from_slice(b"# altered\n");
    std::fs::write(&file, bytes).unwrap();
    let before = tree(home.path());
    let (output, report) = preview(
        home.path(),
        r#"{"tool":"read_text_file","arguments":{"path":"a.txt"}}"#,
        &["--profile", "filesystem"],
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(report["outcome"], "technical_error");
    assert!(report.get("classification").is_none());
    assert_eq!(tree(home.path()), before);
}

#[test]
fn canaries_never_reach_text_json_or_export() {
    use std::os::unix::fs::PermissionsExt;
    let home = installed_home();
    let out = tempfile::tempdir().unwrap();
    std::fs::set_permissions(out.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let export = out.path().join("report.json");
    let frame = format!(
        r#"{{"tool":"tool_{CANARY}","description":"note {CANARY}","arguments":{{"path":"/workspace/{CANARY}.txt","content":"key={CANARY}","k_{CANARY}":"v"}}}}"#
    );
    let (output, _) = preview(
        home.path(),
        &frame,
        &[
            "--profile",
            "filesystem",
            "--export",
            export.to_str().unwrap(),
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    let exported = std::fs::read_to_string(&export).unwrap();
    for blob in [
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        exported,
    ] {
        assert!(!blob.contains(CANARY));
    }
    assert_eq!(
        std::fs::metadata(&export).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // A second export to the same name is refused and does not replace the file.
    let (second, _) = preview(
        home.path(),
        &frame,
        &[
            "--profile",
            "filesystem",
            "--export",
            export.to_str().unwrap(),
        ],
    );
    assert_eq!(second.status.code(), Some(4));
}
