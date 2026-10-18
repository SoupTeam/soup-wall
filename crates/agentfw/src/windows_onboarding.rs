// SPDX-License-Identifier: Apache-2.0

use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::mcp::connection::{windows as connection, Options};

const FILE_LIMIT: usize = 1024 * 1024;
const EXECUTABLE_LIMIT: usize = 512 * 1024 * 1024;

#[derive(Args, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    #[arg(long)]
    pub agent: PathBuf,
    #[arg(long)]
    pub agent_sha256: String,
    #[arg(long)]
    pub python: PathBuf,
    #[arg(long)]
    pub python_sha256: String,
    #[arg(long)]
    pub classifier: PathBuf,
    #[arg(long)]
    pub classifier_sha256: String,
    #[arg(long)]
    pub registry: PathBuf,
    #[arg(long)]
    pub registry_sha256: String,
    #[arg(long)]
    pub policy: PathBuf,
    #[arg(long)]
    pub policy_sha256: String,
    #[arg(long)]
    pub host_config: PathBuf,
    #[arg(long)]
    pub server: String,
    #[arg(long)]
    pub home: PathBuf,
    #[arg(long)]
    pub state_directory: PathBuf,
    #[arg(long)]
    pub report: PathBuf,
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: u16,
}

#[derive(Subcommand)]
pub enum Command {
    Preview(Selection),
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Preview {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub confirmation: String,
    pub identities: Value,
    pub proposed_changes: Vec<&'static str>,
    pub host_reload: &'static str,
    pub synthetic_protection: &'static str,
    pub unsupported_scopes: Vec<&'static str>,
    pub elapsed_ms: u128,
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn fresh(path: &Path) -> Result<()> {
    let _pin = connection::parent(path)?;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => anyhow::bail!("a fresh owned destination is required"),
    }
}

fn asset(path: &Path, expected: &str, executable: bool) -> Result<(Vec<u8>, connection::Identity)> {
    ensure!(
        crate::native::is_digest(expected),
        "invalid expected SHA-256"
    );
    ensure!(
        path.is_absolute(),
        "an explicit absolute asset path is required"
    );
    if executable {
        ensure!(
            path.extension()
                .is_some_and(|value| value.eq_ignore_ascii_case("exe")),
            "a native executable is required"
        );
    }
    let selected = connection::read_file(
        path,
        if executable {
            EXECUTABLE_LIMIT
        } else {
            FILE_LIMIT
        },
    )?;
    ensure!(
        sha(&selected.0) == expected,
        "selected asset digest mismatch"
    );
    Ok(selected)
}

fn confirmation(selection: &Selection, identities: &Value) -> Result<String> {
    Ok(sha(&serde_json::to_vec(&json!({
        "schema_version": "sw-windows-onboarding-preview/1",
        "selection": selection,
        "identities": identities,
    }))?))
}

pub async fn preview(selection: &Selection) -> Result<Preview> {
    crate::self_test::windows_safety::standard_user()?;
    preview_selected(selection).await
}

async fn preview_selected(selection: &Selection) -> Result<Preview> {
    let started = Instant::now();
    ensure!(
        selection
            .home
            .file_name()
            .is_some_and(|value| value == ".agentfw"),
        "select a fresh .agentfw home under a private owned directory"
    );
    fresh(&selection.home)?;
    fresh(&selection.report)?;
    ensure!(
        !selection.state_directory.starts_with(&selection.home)
            && !selection.report.starts_with(&selection.home),
        "state and report must remain outside the new Agent home"
    );
    let _state_pin = connection::parent(&selection.state_directory.join("onboarding.json"))?;
    fresh(&selection.state_directory.join("onboarding.json"))?;
    ensure!(
        selection.port != 0,
        "select an explicit nonzero loopback port"
    );
    let listener = TcpListener::bind(("127.0.0.1", selection.port))
        .context("selected loopback port is occupied or unavailable")?;
    let assets = [
        (&selection.agent, &selection.agent_sha256, true),
        (&selection.python, &selection.python_sha256, true),
        (&selection.classifier, &selection.classifier_sha256, false),
        (&selection.registry, &selection.registry_sha256, false),
        (&selection.policy, &selection.policy_sha256, false),
    ];
    let snapshots = assets
        .iter()
        .map(|(path, digest, executable)| asset(path, digest, *executable))
        .collect::<Result<Vec<_>>>()?;
    let _registry = crate::native::NativeState::from_bytes(
        &snapshots[3].0,
        &selection.registry_sha256,
        crate::token::generate(),
    )
    .context("invalid reviewed native registry")?;
    let policy = soup_wall_agent::AgentPolicySet::from_yaml(
        std::str::from_utf8(&snapshots[4].0).context("policy must be UTF-8")?,
    )
    .context("invalid reviewed Agent policy")?;
    let host_before = connection::read_file(&selection.host_config, FILE_LIMIT)?;
    let options = Options {
        path: selection.host_config.clone(),
        server: selection.server.clone(),
        home: selection.home.clone(),
        agent: selection.agent.clone(),
        probe_tool: None,
        probe_args: None,
        runtime: None,
    };
    let connection_report = connection::run("preview", &options).await?;
    ensure!(
        connection_report.status == "preview",
        "connection preview is unavailable"
    );
    let connection_report = serde_json::to_value(connection_report)?;
    ensure!(
        connection::read_file(&selection.host_config, FILE_LIMIT)? == host_before,
        "host configuration changed during preview"
    );
    for ((path, digest, executable), before) in assets.iter().zip(&snapshots) {
        ensure!(
            asset(path, digest, *executable)? == *before,
            "asset changed during preview"
        );
    }
    fresh(&selection.home)?;
    fresh(&selection.report)?;
    let identities = json!({
        "agent_sha256": selection.agent_sha256,
        "python_sha256": selection.python_sha256,
        "classifier_sha256": selection.classifier_sha256,
        "registry_sha256": selection.registry_sha256,
        "policy_source_sha256": selection.policy_sha256,
        "policy_runtime_sha256": sha(&serde_json::to_vec(&policy)?),
        "host_config_sha256": sha(&host_before.0),
        "host_file_identity": host_before.1,
        "selected_entry_sha256": connection_report["selected_sha256"],
    });
    drop(listener);
    Ok(Preview {
        schema_version: "sw-windows-onboarding-preview/1",
        status: "preview",
        confirmation: confirmation(selection, &identities)?,
        identities,
        proposed_changes: vec![
            "Create a private Agent home and recovery journal",
            "Install the selected Agent and reviewed native configuration",
            "Start and verify the owned daemon",
            "Wrap only the selected existing MCP entry",
            "Run the installed Windows self-test and retain a fresh report",
        ],
        host_reload: "pending_explicit_host_reload",
        synthetic_protection: "not_witnessed",
        unsupported_scopes: vec![
            "live_model_effectiveness",
            "arbitrary_server_sandbox",
            "other_operating_systems",
        ],
        elapsed_ms: started.elapsed().as_millis(),
    })
}

pub fn run(command: Command) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match command {
        Command::Preview(selection) => {
            let result = runtime.block_on(preview(&selection))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_test::{fixture, windows_safety as safety};
    use std::io::Write;
    use std::process::{Command as ProcessCommand, Stdio};

    struct Fixture {
        root: tempfile::TempDir,
        selection: Selection,
    }

    fn write(path: &Path, bytes: &[u8]) {
        let mut file = safety::new_file(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = std::env::temp_dir().canonicalize().unwrap();
            let temporary = temporary.to_str().unwrap();
            let root =
                tempfile::tempdir_in(temporary.strip_prefix(r"\\?\").unwrap_or(temporary)).unwrap();
            std::fs::remove_dir(root.path()).unwrap();
            safety::new_directory(root.path()).unwrap();
            let path = |name| root.path().join(name);
            let agent = path("agentfw.exe");
            let python = path("python.exe");
            let classifier = path("rule_baseline.py");
            let registry = path("registry.json");
            let policy = path("policy.yaml");
            let host_config = path("host.json");
            let state_directory = path("state");
            safety::new_directory(&state_directory).unwrap();
            let agent_bytes = b"controlled preview fixture; never executed";
            let python_bytes = b"controlled Python preview fixture; never executed";
            let classifier_bytes = b"raise RuntimeError('preview must not execute this source')";
            let registry_bytes = fixture::registry();
            for (path, bytes) in [
                (&agent, agent_bytes.as_slice()),
                (&python, python_bytes.as_slice()),
                (&classifier, classifier_bytes.as_slice()),
                (&registry, registry_bytes.as_slice()),
                (&policy, fixture::SHIPPED_POLICY.as_bytes()),
            ] {
                write(path, bytes);
            }
            let config = json!({"mcpServers": {
                "notes": {"command": agent, "args": ["original-server"]},
                "other": {"command": "untouched", "env": {"TOKEN": "operator-sentinel"}}
            }, "settings": {"theme": "operator-sentinel"}});
            write(&host_config, &serde_json::to_vec(&config).unwrap());
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let selection = Selection {
                agent,
                agent_sha256: sha(agent_bytes),
                python,
                python_sha256: sha(python_bytes),
                classifier,
                classifier_sha256: sha(classifier_bytes),
                registry,
                registry_sha256: sha(&registry_bytes),
                policy,
                policy_sha256: sha(fixture::SHIPPED_POLICY.as_bytes()),
                host_config,
                server: "notes".into(),
                home: path(".agentfw"),
                state_directory,
                report: path("report.json"),
                port,
            };
            Self { root, selection }
        }

        fn names(&self) -> Vec<String> {
            let mut names = std::fs::read_dir(self.root.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            names.sort();
            names
        }
    }

    #[tokio::test]
    async fn preview_is_read_only_and_does_not_execute_selected_programs() {
        let fixture = Fixture::new();
        let names = fixture.names();
        let host = std::fs::read(&fixture.selection.host_config).unwrap();
        let result = preview_selected(&fixture.selection).await.unwrap();
        assert_eq!(result.status, "preview");
        assert_eq!(result.synthetic_protection, "not_witnessed");
        assert_eq!(result.host_reload, "pending_explicit_host_reload");
        assert_eq!(result.confirmation.len(), 64);
        assert_eq!(fixture.names(), names);
        assert_eq!(std::fs::read(&fixture.selection.host_config).unwrap(), host);
        assert!(!fixture.selection.home.exists());
        assert!(!fixture.selection.report.exists());
        assert_eq!(
            std::fs::read_dir(&fixture.selection.state_directory)
                .unwrap()
                .count(),
            0
        );
        let printed = serde_json::to_string(&result).unwrap();
        assert!(!printed.contains("operator-sentinel"));
        assert!(!printed.contains(&fixture.root.path().display().to_string()));
    }

    #[tokio::test]
    async fn confirmation_changes_with_host_edits_and_exact_destinations() {
        let fixture = Fixture::new();
        let original = preview_selected(&fixture.selection).await.unwrap();
        let repeated = preview_selected(&fixture.selection).await.unwrap();
        assert_eq!(original.confirmation, repeated.confirmation);
        let mut changed = fixture.selection.clone();
        changed.report = fixture.root.path().join("different-report.json");
        assert_ne!(
            original.confirmation,
            preview_selected(&changed).await.unwrap().confirmation
        );
        let mut value: Value =
            serde_json::from_slice(&std::fs::read(&changed.host_config).unwrap()).unwrap();
        value["settings"]["theme"] = json!("operator edit");
        std::fs::write(&changed.host_config, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_ne!(
            repeated.confirmation,
            preview_selected(&fixture.selection)
                .await
                .unwrap()
                .confirmation
        );
    }

    #[tokio::test]
    async fn every_asset_requires_the_expected_digest() {
        let fixture = Fixture::new();
        for index in 0..5 {
            let mut selection = fixture.selection.clone();
            let digest = match index {
                0 => &mut selection.agent_sha256,
                1 => &mut selection.python_sha256,
                2 => &mut selection.classifier_sha256,
                3 => &mut selection.registry_sha256,
                _ => &mut selection.policy_sha256,
            };
            *digest = "0".repeat(64);
            assert!(preview_selected(&selection).await.is_err());
            assert!(!selection.home.exists());
        }
    }

    #[tokio::test]
    async fn existing_home_report_and_journal_are_preserved() {
        for target in 0..3 {
            let fixture = Fixture::new();
            let path = match target {
                0 => fixture.selection.home.clone(),
                1 => fixture.selection.report.clone(),
                _ => fixture.selection.state_directory.join("onboarding.json"),
            };
            write(&path, b"operator-sentinel");
            assert!(preview_selected(&fixture.selection).await.is_err());
            assert_eq!(std::fs::read(path).unwrap(), b"operator-sentinel");
        }
    }

    #[tokio::test]
    async fn occupied_foreign_port_receives_no_preview_traffic() {
        let mut fixture = Fixture::new();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        fixture.selection.port = listener.local_addr().unwrap().port();
        assert!(preview_selected(&fixture.selection).await.is_err());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(!fixture.selection.home.exists());
    }

    #[tokio::test]
    async fn invalid_registry_and_policy_fail_even_with_matching_hashes() {
        let mut fixture = Fixture::new();
        std::fs::write(&fixture.selection.registry, b"{}").unwrap();
        fixture.selection.registry_sha256 = sha(b"{}");
        assert!(preview_selected(&fixture.selection).await.is_err());
        let bytes = fixture::registry();
        std::fs::write(&fixture.selection.registry, &bytes).unwrap();
        fixture.selection.registry_sha256 = sha(&bytes);
        std::fs::write(&fixture.selection.policy, b"invalid: [").unwrap();
        fixture.selection.policy_sha256 = sha(b"invalid: [");
        assert!(preview_selected(&fixture.selection).await.is_err());
    }

    #[tokio::test]
    async fn unknown_server_and_duplicate_host_fields_are_refused() {
        let mut fixture = Fixture::new();
        fixture.selection.server = "missing".into();
        assert!(preview_selected(&fixture.selection).await.is_err());
        fixture.selection.server = "notes".into();
        std::fs::write(
            &fixture.selection.host_config,
            br#"{"mcpServers":{},"mcpServers":{}}"#,
        )
        .unwrap();
        assert!(preview_selected(&fixture.selection).await.is_err());
    }

    #[tokio::test]
    async fn hardlinked_host_configuration_is_refused_without_changes() {
        let fixture = Fixture::new();
        let alias = fixture.root.path().join("host-alias.json");
        std::fs::hard_link(&fixture.selection.host_config, &alias).unwrap();
        let before = std::fs::read(&alias).unwrap();
        assert!(preview_selected(&fixture.selection).await.is_err());
        assert_eq!(std::fs::read(&alias).unwrap(), before);
    }

    #[tokio::test]
    async fn real_ntfs_junction_and_broad_acl_are_refused() {
        let mut fixture = Fixture::new();
        let original = fixture.selection.state_directory.clone();
        let junction = fixture.root.path().join("state-alias");
        assert!(ProcessCommand::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&original)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        fixture.selection.state_directory = junction.clone();
        assert!(preview_selected(&fixture.selection).await.is_err());
        std::fs::remove_dir(&junction).unwrap();
        fixture.selection.state_directory = original.clone();
        assert!(ProcessCommand::new("icacls")
            .arg(&original)
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        assert!(preview_selected(&fixture.selection).await.is_err());
        assert!(original.exists());
        assert!(!fixture.selection.home.exists());
    }
}
