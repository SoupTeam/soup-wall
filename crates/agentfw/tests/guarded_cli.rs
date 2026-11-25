// SPDX-License-Identifier: Apache-2.0
//! The guarded file subcommands, driven through the real binary.
//!
//! These pin how the CLI finds its policy: the shipped default when the home
//! has no `config.yaml`, the configured policy file when one is named, and a
//! hard failure (never a silent fallback to the default policy) when the
//! configuration or the policy it names cannot be loaded.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Output};

struct Fixture {
    home: tempfile::TempDir,
    workspace: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            workspace: tempfile::tempdir().unwrap(),
        }
    }

    fn configure(&self, config_yaml: &str) {
        let dir = self.home.path().join(".agentfw");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.yaml"), config_yaml).unwrap();
    }

    fn run(&self, subcommand: &str, arguments: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agentfw"));
        command
            .arg(subcommand)
            .arg("--workspace")
            .arg(self.workspace.path())
            .args(arguments)
            .env_clear()
            .env("HOME", self.home.path());
        if let Some(path) = std::env::var_os("PATH") {
            command.env("PATH", path);
        }
        command.output().unwrap()
    }

    fn file(&self, name: &str) -> std::path::PathBuf {
        self.workspace.path().join(name)
    }
}

fn result(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn refused(output: &Output, expected: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(expected), "stderr: {stderr}");
}

fn deny_policy() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/offline-replay/deny-policy.yaml")
        .display()
        .to_string()
}

#[test]
fn default_policy_applies_write_rename_and_delete_inside_the_workspace() {
    let fixture = Fixture::new();

    let written = result(&fixture.run(
        "guarded-write",
        &["--path", "note.txt", "--content", "hello"],
    ));
    assert_eq!(written["decision"]["verdict"], "allow");
    assert_eq!(written["bytes_written"], 5);
    assert_eq!(std::fs::read(fixture.file("note.txt")).unwrap(), b"hello");

    let renamed = result(&fixture.run(
        "guarded-rename",
        &["--from", "note.txt", "--to", "moved.txt"],
    ));
    assert_eq!(renamed["decision"]["verdict"], "allow");
    assert_eq!(renamed["renamed"], true);
    assert!(!fixture.file("note.txt").exists());
    assert_eq!(std::fs::read(fixture.file("moved.txt")).unwrap(), b"hello");

    let deleted = result(&fixture.run("guarded-delete", &["--path", "moved.txt"]));
    assert_eq!(deleted["decision"]["verdict"], "allow");
    assert_eq!(deleted["deleted"], true);
    assert!(!fixture.file("moved.txt").exists());
}

#[test]
fn a_path_outside_the_workspace_is_refused_without_writing() {
    let fixture = Fixture::new();
    let output = fixture.run(
        "guarded-write",
        &["--path", "../escape.txt", "--content", "x"],
    );
    refused(&output, "path traversal is not allowed");
    assert!(!fixture
        .workspace
        .path()
        .parent()
        .unwrap()
        .join("escape.txt")
        .exists());
}

#[test]
fn a_configured_deny_policy_refuses_every_guarded_file_operation() {
    let fixture = Fixture::new();
    std::fs::write(fixture.file("kept.txt"), b"kept").unwrap();
    fixture.configure(&format!("policy: {}\n", deny_policy()));

    refused(
        &fixture.run("guarded-write", &["--path", "new.txt", "--content", "x"]),
        "verdict=deny",
    );
    refused(
        &fixture.run(
            "guarded-rename",
            &["--from", "kept.txt", "--to", "gone.txt"],
        ),
        "verdict=deny",
    );
    refused(
        &fixture.run("guarded-delete", &["--path", "kept.txt"]),
        "verdict=deny",
    );

    assert!(!fixture.file("new.txt").exists());
    assert!(!fixture.file("gone.txt").exists());
    assert_eq!(std::fs::read(fixture.file("kept.txt")).unwrap(), b"kept");
}

#[test]
fn an_invalid_configuration_fails_instead_of_using_the_default_policy() {
    let fixture = Fixture::new();
    fixture.configure("enforce: [\n");
    let output = fixture.run("guarded-write", &["--path", "note.txt", "--content", "x"]);
    refused(&output, "enforce");
    assert!(!fixture.file("note.txt").exists());
}

#[test]
fn a_missing_policy_file_fails_instead_of_using_the_default_policy() {
    let fixture = Fixture::new();
    let missing = fixture.home.path().join("missing-policy.yaml");
    fixture.configure(&format!("policy: {}\n", missing.display()));
    let output = fixture.run("guarded-write", &["--path", "note.txt", "--content", "x"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!fixture.file("note.txt").exists());
}
