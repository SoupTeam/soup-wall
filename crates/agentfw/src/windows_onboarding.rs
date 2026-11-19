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

mod transaction;

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
    pub workspace: PathBuf,
    #[arg(long)]
    pub report: PathBuf,
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: u16,
}

#[derive(Subcommand)]
pub enum Command {
    Preview(Selection),
    Apply {
        #[command(flatten)]
        selection: Selection,
        #[arg(long)]
        confirm: String,
        #[arg(long, hide = true, value_parser = ["prepared", "configured", "installed", "daemon_started", "publishing", "connected"])]
        pause_after: Option<String>,
    },
    Inspect(transaction::StateArgs),
    Verify(transaction::StateArgs),
    Recover(transaction::StateArgs),
    Remove(transaction::StateArgs),
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
    let _workspace_pin = crate::windows_read::CreateParent::prepare_workspace(
        &selection.workspace,
        &selection.workspace,
    )?;
    ensure!(
        Some(selection.state_directory.as_path()) != selection.host_config.parent(),
        "use a separate state directory for onboarding"
    );
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
    let registry = crate::native::NativeState::from_bytes(
        &snapshots[3].0,
        &selection.registry_sha256,
        crate::token::generate(),
    )
    .context("invalid reviewed native registry")?;
    for resource in registry
        .registry
        .tools
        .iter()
        .filter_map(|tool| tool.resource_policy.as_ref())
    {
        ensure!(
            resource.is_windows_handles()
                && resource.workspace == selection.workspace
                && resource.classifier_sha256 == selection.classifier_sha256,
            "registry resources do not match the selected Windows runtime"
        );
    }
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
        server_profile: None,
        classifier_script: None,
        classifier_python: None,
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
        "runner_sha256": crate::lifecycle::sha256_file(&std::env::current_exe()?)?,
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
        Command::Apply {
            selection,
            confirm,
            pause_after,
        } => {
            let result = runtime.block_on(transaction::apply(
                selection,
                &confirm,
                pause_after.as_deref(),
            ))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Inspect(args) => {
            let result = runtime.block_on(transaction::inspect(&args.state_directory))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Verify(args) => {
            let result = runtime.block_on(transaction::verify(&args.state_directory))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Recover(args) => {
            let result = runtime.block_on(transaction::recover(&args.state_directory))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Remove(args) => {
            let result = runtime.block_on(transaction::remove(&args.state_directory))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
