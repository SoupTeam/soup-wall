// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Trusted per-run Claude Code pilot launcher for two pinned MCP servers (SOU-99).
//!
//! Provides a bounded, isolated execution environment outside the source workspace,
//! automatically minting distinct signed child authority grants bound to the authenticated
//! live daemon instance, strictly configuring the host boundary to prevent unmediated tool bypass,
//! constructing runnable collectors from verified installed assets, and supervising the host
//! lifetime with declared timeouts, signal handlers, and owned process-group cleanup.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::native::child_authority;
use crate::Config;

pub const DEFAULT_TIMEOUT_SECONDS: u64 = 180;
pub const FILESYSTEM_SERVER_ID: &str = "filesystem";
pub const GIT_SERVER_ID: &str = "git";

pub const FILESYSTEM_ALLOWED_TOOLS: &[&str] = &[
    "read_text_file",
    "list_directory",
    "directory_tree",
    "search_files",
    "get_file_info",
    "list_allowed_directories",
];

pub const GIT_ALLOWED_TOOLS: &[&str] = &[
    "git_status",
    "git_diff",
    "git_diff_untracked",
    "git_diff_staged",
    "git_log",
    "git_show",
];

/// Inspect selected roots using the same validators as the original profiles.
/// No Git process, daemon, authority, workspace writes or configuration loading.
#[derive(Args, Debug)]
pub struct PilotWorkspacesArgs {
    #[arg(long)]
    pub workspace: PathBuf,
    #[arg(long)]
    pub git_workspace: PathBuf,
    /// Explicit compatibility grammar; does not load or authorize a runtime profile.
    #[arg(long, value_enum, default_value = "v1")]
    pub git_profile_kind: crate::pilot_workspaces::GitProfileKind,
}

pub fn inspect_workspaces(args: PilotWorkspacesArgs) -> Result<()> {
    let report = crate::pilot_workspaces::inspect(
        &args.workspace,
        &args.git_workspace,
        args.git_profile_kind,
    );
    println!("{}", serde_json::to_string(&report)?);
    ensure!(report.is_supported(), "workspace compatibility not established; see reason codes");
    Ok(())
}

/// Helper to generate random hex identifier without external uuid crate.
fn random_hex_128() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// Helper to generate a random UUID-like string.
pub fn random_uuid_v4() -> String {
    let r1 = rand::random::<u64>();
    let r2 = rand::random::<u64>();
    // set version 4 and variant bits
    let r1 = (r1 & 0xFFFFFFFFFFFF0FFF) | 0x0000000000004000;
    let r2 = (r2 & 0x3FFFFFFFFFFFFFFF) | 0x8000000000000000;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (r1 >> 32) as u32,
        ((r1 >> 16) & 0xFFFF) as u16,
        (r1 & 0xFFFF) as u16,
        (r2 >> 48) as u16,
        (r2 & 0xFFFFFFFFFFFF)
    )
}

/// CLI options for the `pilot-launch` subcommand.
#[derive(Args, Debug, Clone)]
pub struct PilotLaunchArgs {
    /// Path to Claude Code executable.
    #[arg(long)]
    pub claude: PathBuf,

    /// Target workspace directory exposed to the pilot.
    #[arg(long)]
    pub workspace: PathBuf,

    /// Separate Git root pinned by the installed Git profile; defaults to --workspace.
    #[arg(long)]
    pub git_workspace: Option<PathBuf>,

    /// Explicit installed daemon home directory containing native-token and config;
    /// defaults to ~/.agentfw or AGENTFW_HOME.
    #[arg(long)]
    pub home: Option<PathBuf>,

    /// Path to filesystem profile JSON or directory containing upstream metadata.
    #[arg(long)]
    pub fs_profile: PathBuf,

    /// Path to Git profile JSON or directory containing upstream metadata.
    #[arg(long)]
    pub git_profile: PathBuf,

    /// Optional path to verified rule-classifier package or script.
    #[arg(long)]
    pub classifier: Option<PathBuf>,

    /// Anonymous sealed provider-input descriptor supplied by the prepared entry.
    #[arg(long, hide = true)]
    pub provider_env_fd: Option<i32>,
    /// Explicit operator-owned Linux resource budget; absent means unbudgeted.
    #[arg(long)]
    pub linux_budget: Option<PathBuf>,

    /// Expected canonical budget identity from an explicit preflight.
    #[arg(long, requires = "linux_budget")]
    pub linux_budget_sha256: Option<String>,

    /// Optional path to pilot policy YAML.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Optional explicit host session ID; generated if not provided.
    #[arg(long, visible_alias = "session-id")]
    pub host_session: Option<String>,

    /// Optional path to agentfw executable for running MCP collectors; defaults to current_exe.
    #[arg(long)]
    pub agent_bin: Option<PathBuf>,

    /// Dry run: validate inputs, construct per-run configuration plan, and output JSON without launching host.
    #[arg(long)]
    pub dry_run: bool,

    /// Maximum seconds allowed for the host conversation before cancellation.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS)]
    pub timeout_seconds: u64,

    /// Opt in to bounded operator Ask continuation for original Linux read-only profiles.
    #[arg(long, default_value_t = 0)]
    pub ask_wait_seconds: u64,

    /// Output versioned machine-readable JSON summary instead of operator logs.
    #[arg(long)]
    pub json: bool,

    /// Optional prompt passed to Claude Code via -p; defaults to "Run the owned pilot sequence.".
    #[arg(long, short = 'p')]
    pub prompt: Option<String>,

    /// Model identifier passed to Claude Code; defaults to "claude-sonnet-4-20250514".
    #[arg(long, default_value = "claude-sonnet-4-20250514")]
    pub model: String,

    /// Mock daemon token for testing/dry-run when daemon is not running.
    #[arg(long, hide = true)]
    pub mock_daemon_token: Option<String>,

    /// Mock daemon instance ID for offline unit testing.
    #[arg(long, hide = true)]
    pub mock_instance_id: Option<String>,

    /// Allow unverified command-based JSON profile fixtures for acceptance testing.
    #[arg(long, hide = true)]
    pub allow_command_fixtures: bool,
}

/// Validated configuration ready for execution.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    pub claude_path: PathBuf,
    pub workspace_path: PathBuf,
    pub home_path: PathBuf,
    pub git_workspace_path: PathBuf,
    pub fs_profile_path: PathBuf,
    pub git_profile_path: PathBuf,
    pub classifier_path: Option<PathBuf>,
    pub linux_budget: Option<PathBuf>,
    pub linux_budget_sha256: Option<String>,
    pub policy_path: Option<PathBuf>,
    pub host_session: String,
    pub agent_bin_path: PathBuf,
    pub timeout: Duration,
    pub ask_wait_seconds: u64,
    pub dry_run: bool,
    pub mock_daemon_token: Option<String>,
    pub mock_instance_id: Option<String>,
    pub allow_command_fixtures: bool,
    pub fs_tools: Vec<String>,
    pub git_tools: Vec<String>,
    pub fs_runtime_cmd: Vec<String>,
    pub git_runtime_cmd: Vec<String>,
    pub prompt: String,
    pub model: String,
}

/// JSON report produced by dry-run or full execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotLaunchReport {
    pub contract_version: String,
    pub status: String,
    pub host_session: String,
    pub claude_path: String,
    pub workspace_path: String,
    pub private_config_dir: String,
    pub allowed_tools: Vec<String>,
    pub servers: BTreeMap<String, ServerLaunchPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub checks_passed: Vec<String>,
    #[serde(default)]
    pub resource_budget: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerLaunchPlan {
    pub server_id: String,
    pub command: String,
    pub args: Vec<String>,
    pub granted_tools: Vec<String>,
    pub token_redacted: bool,
}

impl PilotLaunchArgs {
    /// Validate all supplied arguments and resolve normalized paths.
    pub fn validate(&self) -> Result<ValidatedConfig> {
        // 1. Claude Code binary
        ensure!(
            self.claude.exists(),
            "selected Claude Code executable does not exist: {:?}",
            self.claude
        );
        let claude_path = self.claude.canonicalize().context("canonicalize claude")?;
        ensure!(
            claude_path.is_file(),
            "selected Claude Code is not a file: {:?}",
            claude_path
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&claude_path)?;
            let mode = meta.permissions().mode();
            ensure!(
                mode & 0o111 != 0,
                "selected Claude Code is not executable (mode: {:o}): {:?}",
                mode,
                claude_path
            );
        }

        // 2. Workspace
        ensure!(
            self.workspace.exists(),
            "selected workspace directory does not exist: {:?}",
            self.workspace
        );
        let workspace_path = self
            .workspace
            .canonicalize()
            .context("canonicalize workspace")?;
        ensure!(
            workspace_path.is_dir(),
            "selected workspace is not a directory: {:?}",
            workspace_path
        );

        // 3. Profiles
        ensure!(
            self.fs_profile.exists(),
            "filesystem profile does not exist: {:?}",
            self.fs_profile
        );
        let fs_profile_path = self
            .fs_profile
            .canonicalize()
            .context("canonicalize fs_profile")?;

        ensure!(
            self.git_profile.exists(),
            "Git profile does not exist: {:?}",
            self.git_profile
        );
        let git_profile_path = self
            .git_profile
            .canonicalize()
            .context("canonicalize git_profile")?;

        // 4. Daemon home
        let home_path = match &self.home {
            Some(h) => {
                if h.exists() {
                    h.canonicalize().context("canonicalize home")?
                } else {
                    h.clone()
                }
            }
            None => match std::env::var_os("AGENTFW_HOME") {
                Some(h) => PathBuf::from(h),
                None => Config::home_path()?,
            },
        };

        let git_workspace_path = self
            .git_workspace
            .as_ref()
            .unwrap_or(&workspace_path)
            .canonicalize()
            .context("canonicalize Git workspace")?;
        ensure!(
            git_workspace_path.is_dir(),
            "selected Git workspace is not a directory"
        );

        // 5. Optional classifier and policy
        let classifier_path = match &self.classifier {
            Some(p) => {
                ensure!(
                    p.exists(),
                    "selected classifier package/script does not exist: {:?}",
                    p
                );
                Some(p.canonicalize().context("canonicalize classifier")?)
            }
            None => None,
        };

        let policy_path = match &self.policy {
            Some(p) => {
                ensure!(p.exists(), "selected policy file does not exist: {:?}", p);
                Some(p.canonicalize().context("canonicalize policy")?)
            }
            None => None,
        };

        // 6. Agent binary
        let agent_bin_path = match &self.agent_bin {
            Some(p) => {
                ensure!(p.exists(), "agent binary does not exist: {:?}", p);
                p.canonicalize().context("canonicalize agent_bin")?
            }
            None => std::env::current_exe().context("get current exe")?,
        };

        // 7. Host session ID
        let host_session = match &self.host_session {
            Some(s) => {
                ensure!(
                    !s.trim().is_empty() && s.len() <= 128,
                    "invalid host session id"
                );
                s.clone()
            }
            None => random_uuid_v4(),
        };

        // Extract or default allowed tools
        let fs_tools = extract_tools_from_profile(&fs_profile_path, FILESYSTEM_ALLOWED_TOOLS)?;
        let git_tools = extract_tools_from_profile(&git_profile_path, GIT_ALLOWED_TOOLS)?;

        // Ensure no tool collisions
        let mut tool_set = HashSet::new();
        for t in &fs_tools {
            ensure!(
                tool_set.insert(t.clone()),
                "duplicate tool declaration: {}",
                t
            );
        }
        for t in &git_tools {
            ensure!(
                tool_set.insert(t.clone()),
                "colliding tool between servers: {}",
                t
            );
        }

        // Resolve runnable runtime commands from verified profiles
        let is_mock = self.mock_daemon_token.is_some() || self.allow_command_fixtures;
        let (fs_runtime_cmd, resolved_fs_profile) = resolve_server_runtime(
            FILESYSTEM_SERVER_ID,
            &fs_profile_path,
            &workspace_path,
            is_mock,
        )?;
        let (git_runtime_cmd, resolved_git_profile) = resolve_server_runtime(
            GIT_SERVER_ID,
            &git_profile_path,
            &git_workspace_path,
            is_mock,
        )?;

        let prompt = self
            .prompt
            .clone()
            .unwrap_or_else(|| "Run the owned pilot sequence.".to_string());
        let model = self.model.clone();

        crate::pilot_host::validate(
            &claude_path,
            self.allow_command_fixtures || self.mock_daemon_token.is_some(),
        )?;

        let budget_identity = if let Some(path) = &self.linux_budget {
            ensure!(
                path.is_absolute() && path.canonicalize()? == *path,
                "pilot_budget_selection_invalid"
            );
            let identity = crate::mcp::linux_budget::Config::load_file(path)?.identity();
            ensure!(
                self.linux_budget_sha256
                    .as_ref()
                    .is_none_or(|expected| expected == &identity),
                "pilot_budget_selection_changed"
            );
            Some(identity)
        } else {
            ensure!(
                self.linux_budget_sha256.is_none(),
                "pilot_budget_selection_missing"
            );
            None
        };

        Ok(ValidatedConfig {
            claude_path,
            workspace_path,
            git_workspace_path,
            home_path,
            fs_profile_path: resolved_fs_profile,
            git_profile_path: resolved_git_profile,
            classifier_path,
            linux_budget: self.linux_budget.clone(),
            linux_budget_sha256: budget_identity,
            policy_path,
            host_session,
            agent_bin_path,
            timeout: Duration::from_secs(self.timeout_seconds),
            ask_wait_seconds: self.ask_wait_seconds,
            dry_run: self.dry_run,
            mock_daemon_token: self.mock_daemon_token.clone(),
            mock_instance_id: self.mock_instance_id.clone(),
            allow_command_fixtures: self.allow_command_fixtures,
            fs_tools,
            git_tools,
            fs_runtime_cmd,
            git_runtime_cmd,
            prompt,
            model,
        })
    }
}

/// Extract tool names from profile directory, JSON file, or adjacent registry.
fn extract_tools_from_profile(profile_path: &Path, fallback: &[&str]) -> Result<Vec<String>> {
    let candidate_files = if profile_path.is_dir() {
        vec![
            profile_path.join("registry.json"),
            profile_path.join("upstream-tools-list.json"),
            profile_path.join("profile.json"),
        ]
    } else {
        let parent = profile_path.parent();
        let mut list = vec![profile_path.to_path_buf()];
        if let Some(p) = parent {
            list.push(p.join("registry.json"));
            list.push(p.join("upstream-tools-list.json"));
        }
        list
    };

    for path in candidate_files {
        if path.is_file() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(arr) = val.get("tools").and_then(|t| t.as_array()) {
                        let mut list = Vec::new();
                        for item in arr {
                            if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                                list.push(name.to_string());
                            }
                        }
                        if !list.is_empty() {
                            return Ok(list);
                        }
                    }
                }
            }
        }
    }

    Ok(fallback.iter().map(|&s| s.to_string()).collect())
}

/// Resolve runnable server runtime executable and arguments from profile metadata.
pub fn resolve_server_runtime(
    server_id: &str,
    profile_path: &Path,
    workspace: &Path,
    is_mock: bool,
) -> Result<(Vec<String>, PathBuf)> {
    let profile_file = if profile_path.is_dir() {
        profile_path.join("profile.json")
    } else {
        profile_path.to_path_buf()
    };

    if !is_mock {
        ensure!(
            profile_file.is_file(),
            "installed MCP server profile not found at {:?}",
            profile_file
        );
        let bytes = fs::read(&profile_file)
            .with_context(|| format!("read profile at {:?}", profile_file))?;
        let profile = crate::mcp::server_profile::ProfileConfig::read(&bytes).map_err(|e| {
            anyhow::anyhow!(
                "invalid MCP server profile at {:?}: real pilot requires validated ProfileConfig: {}",
                profile_file,
                e
            )
        })?;

        let (cmd, args) = match server_id {
            FILESYSTEM_SERVER_ID => {
                let entry = profile
                    .package_root
                    .join(crate::mcp::server_profile::SERVER_ENTRYPOINT);
                let args = vec![entry.display().to_string(), "/workspace".to_string()];
                (profile.runtime_path.display().to_string(), args)
            }
            GIT_SERVER_ID => {
                let args = vec![
                    "-I".to_string(),
                    "-B".to_string(),
                    "-m".to_string(),
                    "mcp_server_git".to_string(),
                    "--repository".to_string(),
                    "/workspace".to_string(),
                ];
                (profile.runtime_path.display().to_string(), args)
            }
            other => bail!("unsupported server_id {:?} for ProfileConfig", other),
        };

        let canonical_ws = workspace
            .canonicalize()
            .with_context(|| format!("canonicalize workspace {:?}", workspace))?;
        profile
            .validate_command(&cmd, &args, &canonical_ws)
            .context("profile validate_command contract check failed")?;

        let mut full_cmd = vec![cmd];
        full_cmd.extend(args);
        return Ok((full_cmd, profile_file));
    }

    // Explicit test/mock path (is_mock == true)
    if profile_file.is_file() {
        let bytes = fs::read(&profile_file)
            .with_context(|| format!("read profile at {:?}", profile_file))?;

        // 1. Try reading as validated ProfileConfig
        if let Ok(profile) = crate::mcp::server_profile::ProfileConfig::read(&bytes) {
            let (cmd, args) = match server_id {
                FILESYSTEM_SERVER_ID => {
                    let entry = profile
                        .package_root
                        .join(crate::mcp::server_profile::SERVER_ENTRYPOINT);
                    let args = vec![entry.display().to_string(), "/workspace".to_string()];
                    (profile.runtime_path.display().to_string(), args)
                }
                GIT_SERVER_ID => {
                    let args = vec![
                        "-I".to_string(),
                        "-B".to_string(),
                        "-m".to_string(),
                        "mcp_server_git".to_string(),
                        "--repository".to_string(),
                        "/workspace".to_string(),
                    ];
                    (profile.runtime_path.display().to_string(), args)
                }
                other => bail!("unsupported server_id {:?} for ProfileConfig", other),
            };

            let canonical_ws = workspace
                .canonicalize()
                .with_context(|| format!("canonicalize workspace {:?}", workspace))?;
            profile
                .validate_command(&cmd, &args, &canonical_ws)
                .context("profile validate_command contract check failed")?;

            let mut full_cmd = vec![cmd];
            full_cmd.extend(args);
            return Ok((full_cmd, profile_file));
        }

        // 2. Parse as JSON to support command-based profile fixtures or runtimePath configs in test/mock mode
        let val: serde_json::Value = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "profile at {:?} is neither valid ProfileConfig nor valid JSON",
                profile_file
            )
        })?;

        // If it declared an installed MCP format, reject the invalid profile
        if let Some(format) = val.get("format").and_then(|f| f.as_str()) {
            if format.starts_with("sw-mcp/") {
                bail!(
                    "invalid MCP server profile at {:?}: failed ProfileConfig validation",
                    profile_file
                );
            }
        }

        if let Some(runtime_path) = val.get("runtimePath").and_then(|v| v.as_str()) {
            if server_id == FILESYSTEM_SERVER_ID {
                let package_root = val
                    .get("packageRoot")
                    .and_then(|v| v.as_str())
                    .unwrap_or(".");
                let entry = Path::new(package_root)
                    .join("node_modules/@modelcontextprotocol/server-filesystem/dist/index.js");
                return Ok((
                    vec![
                        runtime_path.to_string(),
                        entry.display().to_string(),
                        "/workspace".to_string(),
                    ],
                    profile_file,
                ));
            } else if server_id == GIT_SERVER_ID {
                return Ok((
                    vec![
                        runtime_path.to_string(),
                        "-I".to_string(),
                        "-B".to_string(),
                        "-m".to_string(),
                        "mcp_server_git".to_string(),
                        "--repository".to_string(),
                        "/workspace".to_string(),
                    ],
                    profile_file,
                ));
            }
        } else if let Some(cmd) = val.get("command").and_then(|v| v.as_str()) {
            let mut full = vec![cmd.to_string()];
            if let Some(args) = val.get("args").and_then(|a| a.as_array()) {
                for arg in args {
                    if let Some(s) = arg.as_str() {
                        full.push(s.to_string());
                    }
                }
            }
            return Ok((full, profile_file));
        }

        bail!(
            "invalid MCP server profile at {:?}: expected installed profile, runtimePath, or command",
            profile_file
        );
    }

    // Default fallback for minimal unit tests when no profile file exists in mock mode
    Ok((
        vec!["echo".to_string(), server_id.to_string()],
        profile_file,
    ))
}

/// RAII Guard that securely removes the private per-run directory upon exit or failure.
pub struct PrivateDirGuard {
    pub path: PathBuf,
    disarmed: bool,
}

impl PrivateDirGuard {
    pub fn new(workspace: &Path) -> Result<Self> {
        Self::for_workspaces(&[workspace])
    }

    fn for_workspaces(workspaces: &[&Path]) -> Result<Self> {
        let parent = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        Self::in_parent(workspaces, &parent)
    }

    fn in_parent(workspaces: &[&Path], parent: &Path) -> Result<Self> {
        let parent = parent
            .canonicalize()
            .context("canonicalize private state parent")?;
        let private_path = parent.join(format!("soup-wall-pilot-{}", random_hex_128()));
        for workspace in workspaces {
            ensure!(
                !private_path.starts_with(workspace.canonicalize()?),
                "private per-run configuration directory must be outside the workspace"
            );
        }
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        builder.create(&private_path)?;
        Ok(Self {
            path: private_path,
            disarmed: false,
        })
    }

    pub fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for PrivateDirGuard {
    fn drop(&mut self) {
        if !self.disarmed && self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Query the live daemon's authenticated `/native/v1/instance` endpoint to obtain its current `instance_id`.
pub fn fetch_daemon_instance(config: &ValidatedConfig, daemon_token: &str) -> Result<String> {
    if let Some(ref mock_inst) = config.mock_instance_id {
        return Ok(mock_inst.clone());
    }
    if config.mock_daemon_token.is_some() {
        return Ok("mock-daemon-instance-id".to_string());
    }

    let cfg_path = config.home_path.join("config.yaml");
    let daemon_cfg = if cfg_path.exists() {
        let text = fs::read_to_string(&cfg_path)?;
        Config::from_yaml(&text)?
    } else {
        Config::default()
    };

    let url = format!("http://{}/native/v1/instance", daemon_cfg.socket_address());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create runtime for instance discovery")?;

    let token = daemon_token.trim().to_string();
    let instance_id = rt.block_on(async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()?;
        let res = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .context("connect to daemon /native/v1/instance")?;
        ensure!(
            res.status().is_success(),
            "daemon /native/v1/instance returned status {}",
            res.status()
        );
        let val: serde_json::Value = res
            .json()
            .await
            .context("parse /native/v1/instance JSON response")?;
        let id = val["instance_id"].as_str().ok_or_else(|| {
            anyhow::anyhow!("missing instance_id in /native/v1/instance response")
        })?;
        ensure!(
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "invalid instance_id returned from daemon: {:?}",
            id
        );
        Ok::<String, anyhow::Error>(id.to_string())
    })?;

    Ok(instance_id)
}

/// Probe daemon liveness during host execution.
async fn probe_daemon_liveness(home_path: &Path, daemon_token: &str) -> Result<String> {
    let cfg_path = home_path.join("config.yaml");
    let daemon_cfg = if cfg_path.exists() {
        let text = fs::read_to_string(&cfg_path)?;
        Config::from_yaml(&text)?
    } else {
        Config::default()
    };

    let url = format!("http://{}/native/v1/instance", daemon_cfg.socket_address());
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()?;
    let res = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", daemon_token.trim()))
        .send()
        .await
        .context("probe daemon /native/v1/instance")?;
    ensure!(
        res.status().is_success(),
        "daemon /native/v1/instance probe failed with status {}",
        res.status()
    );
    let val: serde_json::Value = res.json().await?;
    let id = val["instance_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing instance_id in probe response"))?;
    Ok(id.to_string())
}

/// Verify that the operator selected --policy matches the daemon's active, enforcing policy.
pub fn verify_daemon_policy(config: &ValidatedConfig, _daemon_token: &str) -> Result<()> {
    let policy_path = match &config.policy_path {
        Some(p) => p,
        None => return Ok(()),
    };

    let policy_bytes = fs::read(policy_path)
        .with_context(|| format!("read selected policy file at {:?}", policy_path))?;
    let policy_str =
        std::str::from_utf8(&policy_bytes).context("selected policy file is not valid UTF-8")?;
    let selected_policy_set = soup_wall_agent::AgentPolicySet::from_yaml(policy_str)
        .context("selected policy file does not parse as valid AgentPolicySet")?;
    let selected_policy_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&selected_policy_set).context("serialize policy set")?)
    );

    let cfg_path = config.home_path.join("config.yaml");
    if cfg_path.exists() {
        let cfg_text = fs::read_to_string(&cfg_path)
            .with_context(|| format!("read daemon config at {:?}", cfg_path))?;
        let daemon_cfg = Config::from_yaml(&cfg_text)
            .with_context(|| format!("parse daemon config at {:?}", cfg_path))?;

        ensure!(
            daemon_cfg.enforce,
            "daemon at {:?} is running in shadow mode (enforce: false); --policy requires an enforcing daemon",
            cfg_path
        );

        let daemon_policy_path = daemon_cfg.policy.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "launcher specified --policy {:?}, but daemon config at {:?} has no policy configured",
                policy_path,
                cfg_path
            )
        })?;

        let daemon_policy_abs = if daemon_policy_path.is_absolute() {
            daemon_policy_path.clone()
        } else {
            config.home_path.join(daemon_policy_path)
        };

        if let Ok(canonical_daemon_policy) = daemon_policy_abs.canonicalize() {
            ensure!(
                &canonical_daemon_policy == policy_path,
                "policy mismatch: launcher selected {:?} but daemon is configured with {:?}",
                policy_path,
                canonical_daemon_policy
            );
        }

        let daemon_policy_bytes = fs::read(&daemon_policy_abs)
            .with_context(|| format!("read daemon policy at {:?}", daemon_policy_abs))?;
        let daemon_policy_str = std::str::from_utf8(&daemon_policy_bytes)
            .context("daemon policy file is not valid UTF-8")?;
        let daemon_policy_set = soup_wall_agent::AgentPolicySet::from_yaml(daemon_policy_str)
            .context("daemon policy does not parse as valid AgentPolicySet")?;
        let daemon_policy_sha256 = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&daemon_policy_set).context("serialize daemon policy set")?
            )
        );

        ensure!(
            selected_policy_sha256 == daemon_policy_sha256,
            "policy digest mismatch: selected policy SHA-256 {} differs from daemon policy SHA-256 {}",
            selected_policy_sha256,
            daemon_policy_sha256
        );

        // If daemon is live (not mock), query /diagnostics/v1/protection
        if config.mock_daemon_token.is_none() {
            let token_path = config.home_path.join("token");
            ensure!(
                token_path.exists(),
                "daemon status token does not exist at {:?}; ensure daemon is initialized",
                token_path
            );
            let status_token = fs::read_to_string(&token_path)
                .context("read daemon status token")?
                .trim()
                .to_string();

            let url = format!(
                "http://{}/diagnostics/v1/protection",
                daemon_cfg.socket_address()
            );
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("create runtime for diagnostics verification")?;

            let nonce = crate::token::generate();
            let (mode, active_policy_sha256) = rt.block_on(async {
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_secs(5))
                    .build()?;
                let res = client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", status_token))
                    .header(crate::protection_status::NONCE_HEADER, &nonce)
                    .send()
                    .await
                    .context("connect to daemon /diagnostics/v1/protection")?;
                ensure!(
                    res.status().is_success(),
                    "daemon /diagnostics/v1/protection returned status {}",
                    res.status()
                );
                let snapshot: crate::protection_status::Snapshot = res
                    .json()
                    .await
                    .context("parse /diagnostics/v1/protection JSON snapshot")?;
                Ok::<(crate::protection_status::Mode, String), anyhow::Error>((
                    snapshot.mode,
                    snapshot.policy.sha256,
                ))
            })?;

            ensure!(
                mode == crate::protection_status::Mode::Enforcing,
                "daemon active mode is not enforcing: {:?}",
                mode
            );

            ensure!(
                active_policy_sha256 == selected_policy_sha256,
                "policy mismatch with live daemon: daemon enforces SHA-256 {} but selected policy has SHA-256 {}",
                active_policy_sha256,
                selected_policy_sha256
            );
        }
    } else if config.mock_daemon_token.is_none() {
        bail!(
            "launcher specified --policy {:?}, but daemon config does not exist at {:?}",
            policy_path,
            cfg_path
        );
    }

    Ok(())
}

// Keep the owned leader unreaped until its process group has been stopped.
// try_wait() would release its PID before the delayed group KILL, permitting reuse.
#[cfg(unix)]
fn owned_host_exited(child: &mut std::process::Child) -> std::io::Result<bool> {
    let mut information = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut information,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(information.si_signo != 0)
}

#[cfg(not(unix))]
fn owned_host_exited(child: &mut std::process::Child) -> std::io::Result<bool> {
    child.try_wait().map(|status| status.is_some())
}

#[cfg(target_os = "macos")]
fn mac_group_has_running_processes(output: &str, group: u32) -> Result<bool> {
    let mut observed = false;
    for row in output.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = row.split_ascii_whitespace();
        let id: u32 = fields
            .next()
            .context("missing group observation")?
            .parse()?;
        let state = fields.next().context("missing group state")?;
        ensure!(fields.next().is_none(), "invalid group observation");
        observed = true;
        if id == group && !state.starts_with('Z') {
            return Ok(true);
        }
    }
    ensure!(observed, "empty process group observation");
    Ok(false)
}

#[cfg(target_os = "macos")]
async fn mac_group_is_zombie_only(group: u32) -> Result<bool> {
    use tokio::io::AsyncReadExt;
    // Read-only observation of the pinned, unreaped leader's existing group.
    // No observed PID is ever selected for a signal. Fixed system ps reports
    // only group/state, never command arguments or user identifiers.
    let mut command = tokio::process::Command::new("/bin/ps");
    command
        .args(["-axo", "pgid=,stat="])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn().context("observe owned group")?;
    let stdout = child.stdout.take().context("group observation pipe")?;
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut bytes = Vec::new();
        stdout
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= 4 * 1024 * 1024,
            "group observation byte limit"
        );
        ensure!(child.wait().await?.success(), "group observation failed");
        Ok::<_, anyhow::Error>(!mac_group_has_running_processes(
            std::str::from_utf8(&bytes)?,
            group,
        )?)
    })
    .await
    .context("group observation deadline")?
}

#[cfg(unix)]
async fn signal_owned_group(pgid: u32, kind: i32) -> Result<()> {
    if unsafe { libc::kill(-(pgid as i32), kind) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        if error.raw_os_error() == Some(libc::EPERM) && mac_group_is_zombie_only(pgid).await? {
            // Seatbelt refuses a signal to an unreaped zombie. That process
            // cannot execute; a live/unknown member still fails closed.
            return Ok(());
        }
        anyhow::bail!("owned host process group termination unconfirmed: {error}");
    }
    Ok(())
}

#[cfg(unix)]
#[allow(dead_code)]
async fn terminate_process_group(pgid: u32, grace: Duration) -> Result<()> {
    let term = signal_owned_group(pgid, libc::SIGTERM).await;
    tokio::time::sleep(grace).await;
    let kill = signal_owned_group(pgid, libc::SIGKILL).await;
    term?;
    kill?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(dead_code)]
async fn terminate_process_group(_pgid: u32, _grace: Duration) -> Result<()> {
    Ok(())
}

/// Observation only: never discover a PID to signal. The unreaped leader
/// reserves this exact group identity throughout the kill/reap boundary.
#[cfg(target_os = "linux")]
fn host_group_has_children(group: u32) -> Result<bool> {
    let mut count = 0usize;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == group {
            continue;
        }
        count += 1;
        ensure!(
            count <= 32768,
            "owned host cleanup process observation limit"
        );
        let stat = match fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("owned host cleanup observation unavailable"),
        };
        let (_, fields) = stat
            .rsplit_once(')')
            .context("owned host cleanup process identity invalid")?;
        let observed_group: u32 = fields
            .split_whitespace()
            .nth(2)
            .context("owned host cleanup process identity incomplete")?
            .parse()?;
        if observed_group == group {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn reap_owned_host(child: &mut std::process::Child) -> Result<std::process::ExitStatus> {
    #[cfg(target_os = "linux")]
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if owned_host_exited(child)? && !host_group_has_children(child.id())? {
                break;
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "pilot stop incomplete: owned host group still has unreaped processes"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    child.wait().context("reap owned host after group cleanup")
}

/// Mint HMAC-signed scoped child authority grants bound to the live daemon instance.
pub fn mint_grants(
    config: &ValidatedConfig,
    now_ms: u64,
    instance_id: &str,
) -> Result<BTreeMap<String, child_authority::ChildAuthorityGrant>> {
    let daemon_token = if let Some(ref mock) = config.mock_daemon_token {
        mock.clone()
    } else {
        let token_path = config.home_path.join("native-token");
        ensure!(
            token_path.exists(),
            "daemon native-token does not exist at {:?}; ensure agentfw daemon is initialized",
            token_path
        );
        fs::read_to_string(&token_path)
            .context("read native-token")?
            .trim()
            .to_string()
    };

    let key = child_authority::derive_key(&daemon_token);
    let ttl_ms = config.timeout.as_millis() as u64 + 60_000; // Extra minute for grace

    let mut grants = BTreeMap::new();

    // 1. Filesystem grant: nonce is bound to live daemon instance_id
    let fs_nonce = format!("{instance_id}.{}", random_uuid_v4());
    let fs_grant = child_authority::mint_scoped(
        &key,
        &config.host_session,
        FILESYSTEM_SERVER_ID,
        &config.fs_tools,
        now_ms,
        ttl_ms,
        fs_nonce,
        Some(format!("claude-{}", FILESYSTEM_SERVER_ID)),
        None,
        None,
    );
    grants.insert(FILESYSTEM_SERVER_ID.to_string(), fs_grant);

    // 2. Git grant: nonce is bound to live daemon instance_id
    let git_nonce = format!("{instance_id}.{}", random_uuid_v4());
    let git_grant = child_authority::mint_scoped(
        &key,
        &config.host_session,
        GIT_SERVER_ID,
        &config.git_tools,
        now_ms,
        ttl_ms,
        git_nonce,
        Some(format!("claude-{}", GIT_SERVER_ID)),
        None,
        None,
    );
    grants.insert(GIT_SERVER_ID.to_string(), git_grant);

    Ok(grants)
}

/// Construct per-process MCP JSON configuration referencing both servers.
pub fn write_per_process_mcp_config(
    private_dir: &Path,
    config: &ValidatedConfig,
    grants: &BTreeMap<String, child_authority::ChildAuthorityGrant>,
    budget: Option<&crate::pilot_budget::RunBudget>,
) -> Result<(PathBuf, BTreeMap<String, ServerLaunchPlan>)> {
    let mut server_plans = BTreeMap::new();
    let mut mcp_servers = serde_json::Map::new();

    for (server_id, grant) in grants {
        let encoded_grant = child_authority::encode_token(grant);
        let (runtime_cmd, profile_file) = if server_id == FILESYSTEM_SERVER_ID {
            (
                config.fs_runtime_cmd.clone(),
                config.fs_profile_path.clone(),
            )
        } else {
            (
                config.git_runtime_cmd.clone(),
                config.git_profile_path.clone(),
            )
        };

        let mut collector_args = vec![
            "mcp".to_string(),
            "--id".to_string(),
            server_id.clone(),
            "--native-admission".to_string(),
            "--host-session".to_string(),
            config.host_session.clone(),
            "--child-authority".to_string(),
            encoded_grant.clone(),
            "--home".to_string(),
            config.home_path.display().to_string(),
        ];
        if config.ask_wait_seconds > 0 {
            collector_args.extend([
                "--native-approval-wait-seconds".into(),
                config.ask_wait_seconds.to_string(),
            ]);
        }
        if config.linux_budget.is_some() {
            collector_args.extend([
                "--pilot-budget-binding".into(),
                budget
                    .map(|b| b.binding_path.clone())
                    .unwrap_or_else(|| {
                        private_dir.join("budget-binding-required-at-execution.json")
                    })
                    .display()
                    .to_string(),
            ]);
        }
        if let Some(identity) = &config.linux_budget_sha256 {
            collector_args.extend(["--pilot-budget-sha256".into(), identity.clone()]);
        }
        collector_args.push("--".into());
        collector_args.extend(runtime_cmd.clone());

        let mut s_obj = serde_json::Map::new();
        s_obj.insert(
            "type".to_string(),
            serde_json::Value::String("stdio".to_string()),
        );
        s_obj.insert(
            "command".to_string(),
            serde_json::Value::String(config.agent_bin_path.display().to_string()),
        );
        s_obj.insert(
            "args".to_string(),
            serde_json::Value::Array(
                collector_args
                    .iter()
                    .map(|a| serde_json::Value::String(a.clone()))
                    .collect(),
            ),
        );

        let mut env_obj = serde_json::Map::new();
        env_obj.insert(
            "AGENTFW_WORKSPACE".to_string(),
            serde_json::Value::String(
                if server_id == GIT_SERVER_ID {
                    &config.git_workspace_path
                } else {
                    &config.workspace_path
                }
                .display()
                .to_string(),
            ),
        );
        if !config.allow_command_fixtures && config.mock_daemon_token.is_none() {
            ensure!(
                profile_file.is_file(),
                "installed MCP server profile not found at {:?}",
                profile_file
            );
            let bytes = fs::read(&profile_file)
                .with_context(|| format!("read profile at {:?}", profile_file))?;
            crate::mcp::server_profile::ProfileConfig::read(&bytes).map_err(|e| {
                anyhow::anyhow!(
                    "installed profile at {:?} failed ProfileConfig validation: {}",
                    profile_file,
                    e
                )
            })?;
            env_obj.insert(
                "AGENTFW_MCP_SERVER_PROFILE".to_string(),
                serde_json::Value::String(profile_file.display().to_string()),
            );
        } else if let Ok(bytes) = fs::read(&profile_file) {
            if crate::mcp::server_profile::ProfileConfig::read(&bytes).is_ok() {
                env_obj.insert(
                    "AGENTFW_MCP_SERVER_PROFILE".to_string(),
                    serde_json::Value::String(profile_file.display().to_string()),
                );
            } else if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(format) = val.get("format").and_then(|f| f.as_str()) {
                    if format.starts_with("sw-mcp/") {
                        bail!(
                            "invalid MCP server profile at {:?}: failed ProfileConfig validation",
                            profile_file
                        );
                    }
                }
            }
        }
        if let Some(ref policy) = config.policy_path {
            env_obj.insert(
                "AGENTFW_POLICY".to_string(),
                serde_json::Value::String(policy.display().to_string()),
            );
        }
        env_obj.insert(
            "AGENTFW_HOST_SESSION".to_string(),
            serde_json::Value::String(config.host_session.clone()),
        );
        env_obj.insert(
            "AGENTFW_CHILD_AUTHORITY".to_string(),
            serde_json::Value::String(encoded_grant),
        );
        env_obj.insert(
            "AGENTFW_NATIVE_LIVENESS".to_string(),
            serde_json::Value::String("true".to_string()),
        );
        env_obj.insert(
            "AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS".to_string(),
            serde_json::Value::String("4".to_string()),
        );
        env_obj.insert(
            "AGENTFW_HOME".to_string(),
            serde_json::Value::String(config.home_path.display().to_string()),
        );

        if let Some(parent) = config.home_path.parent() {
            env_obj.insert(
                "HOME".to_string(),
                serde_json::Value::String(parent.display().to_string()),
            );
        } else {
            env_obj.insert(
                "HOME".to_string(),
                serde_json::Value::String(config.home_path.display().to_string()),
            );
        }

        if let Some(ref classifier) = config.classifier_path {
            env_obj.insert(
                "AGENTFW_CLASSIFIER".to_string(),
                serde_json::Value::String("rule-baseline".to_string()),
            );
            env_obj.insert(
                "AGENTFW_RULE_BASELINE".to_string(),
                serde_json::Value::String(classifier.display().to_string()),
            );
        }

        // The interpreter is part of the validated installed Git profile.
        // An ambient project environment must not replace executable classifier authority.
        if let Some(python) = config.git_runtime_cmd.first() {
            env_obj.insert(
                "AGENTFW_CLASSIFIER_PYTHON".to_string(),
                serde_json::Value::String(python.clone()),
            );
        }

        if let Some(source) = &config.linux_budget {
            let selected = budget.map(|b| b.config_path()).unwrap_or(source);
            let binding = budget
                .map(|b| b.binding_path.clone())
                .unwrap_or_else(|| private_dir.join("budget-binding-required-at-execution.json"));
            env_obj.insert(
                crate::mcp::linux_budget::ENVIRONMENT.into(),
                serde_json::json!(selected),
            );
            env_obj.insert(
                crate::pilot_budget::BINDING_ENV.into(),
                serde_json::json!(binding),
            );
        }

        env_obj.insert("PATH".into(), serde_json::json!("/usr/bin:/bin"));
        env_obj.insert("LANG".into(), serde_json::json!("C.UTF-8"));
        env_obj.insert("TMPDIR".into(), serde_json::json!(private_dir));
        let mut isolated_args = vec![serde_json::json!("-i"), serde_json::json!("--")];
        for (key, value) in &env_obj {
            isolated_args.push(serde_json::json!(format!(
                "{}={}",
                key,
                value
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("collector_environment_invalid"))?
            )));
        }
        isolated_args.push(serde_json::json!(config.agent_bin_path));
        isolated_args.extend(collector_args.iter().map(|value| serde_json::json!(value)));
        s_obj.insert("command".into(), serde_json::json!("/usr/bin/env"));
        s_obj.insert("args".into(), serde_json::Value::Array(isolated_args));
        let cleared_provider = crate::pilot_host::PROVIDER_ENV
            .iter()
            .map(|key| ((*key).to_string(), serde_json::json!("")))
            .collect();
        s_obj.insert(
            "env".to_string(),
            serde_json::Value::Object(cleared_provider),
        );
        mcp_servers.insert(server_id.clone(), serde_json::Value::Object(s_obj));

        // Sanitized plan for reporting (tokens redacted)
        let mut report_args = vec![
            "mcp".to_string(),
            "--id".to_string(),
            server_id.clone(),
            "--native-admission".to_string(),
            "--host-session".to_string(),
            config.host_session.clone(),
            "--child-authority".to_string(),
            "[REDACTED]".to_string(),
            "--home".to_string(),
            config.home_path.display().to_string(),
            "--".to_string(),
        ];
        report_args.extend(runtime_cmd);

        server_plans.insert(
            server_id.clone(),
            ServerLaunchPlan {
                server_id: server_id.clone(),
                command: config.agent_bin_path.display().to_string(),
                args: report_args,
                granted_tools: grant.granted_tools.clone(),
                token_redacted: true,
            },
        );
    }

    let mut root_obj = serde_json::Map::new();
    root_obj.insert(
        "mcpServers".to_string(),
        serde_json::Value::Object(mcp_servers),
    );

    let config_path = private_dir.join("mcp.json");
    fs::write(&config_path, serde_json::to_string_pretty(&root_obj)?)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
    }

    Ok((config_path, server_plans))
}

/// Execute the pilot launcher command with strict isolation and bounded supervision.
pub fn run(args: PilotLaunchArgs) -> Result<()> {
    // Consume supplied authority before validation/configuration can allocate
    // another descriptor with the same number as a malformed input.
    let provider = crate::pilot_host::provider_inputs(args.provider_env_fd)?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let config = args.validate()?;
    if !config.dry_run {
        // Only the intended host receives the explicitly selected provider inputs.
        ensure!(
            config.allow_command_fixtures
                || config.mock_daemon_token.is_some()
                || provider
                    .iter()
                    .any(|(key, value)| (key == "ANTHROPIC_API_KEY"
                        || key == "ANTHROPIC_AUTH_TOKEN")
                        && !value.is_empty()),
            "provider_unavailable"
        );
    }

    if config.ask_wait_seconds > 0 {
        crate::pilot_approval::preflight(&config)?;
    }
    let guard =
        PrivateDirGuard::for_workspaces(&[&config.workspace_path, &config.git_workspace_path])?;

    let budget = if !config.dry_run {
        if let Some(source) = &config.linux_budget {
            ensure!(
                !config.home_path.starts_with(&config.workspace_path)
                    && !config.home_path.starts_with(&config.git_workspace_path),
                "pilot_budget_private_state_required"
            );
            Some(crate::pilot_budget::RunBudget::for_run(
                source,
                &config.home_path,
                &config.host_session,
                config
                    .linux_budget_sha256
                    .as_deref()
                    .expect("validated budget identity"),
            )?)
        } else {
            None
        }
    } else {
        None
    };

    // Discover live daemon instance or mock for testing
    let daemon_token = if let Some(ref mock) = config.mock_daemon_token {
        mock.clone()
    } else {
        let token_path = config.home_path.join("native-token");
        ensure!(
            token_path.exists(),
            "daemon native-token does not exist at {:?}; ensure agentfw daemon is initialized",
            token_path
        );
        fs::read_to_string(&token_path)
            .context("read native-token")?
            .trim()
            .to_string()
    };

    let instance_id = fetch_daemon_instance(&config, &daemon_token)
        .context("authenticate and validate live daemon instance")?;

    verify_daemon_policy(&config, &daemon_token)
        .context("verify daemon active policy against selected policy")?;

    let grants = mint_grants(&config, now_ms, &instance_id)?;
    let pilot_run = if !config.dry_run
        && cfg!(target_os = "linux")
        && !config.allow_command_fixtures
        && config.mock_daemon_token.is_none()
        && config.mock_instance_id.is_none()
        && config.classifier_path.is_some()
        && config.policy_path.is_some()
        && crate::pilot_approval::liveness_configured(&config.home_path)?
    {
        Some(crate::pilot_approval::RunGuard::create(
            &config,
            &instance_id,
            &grants,
        )?)
    } else {
        None
    };
    let (mcp_config_path, server_plans) =
        write_per_process_mcp_config(&guard.path, &config, &grants, budget.as_ref())?;

    let mut allowed_tools = Vec::new();
    for t in &config.fs_tools {
        allowed_tools.push(t.clone());
        allowed_tools.push(format!("mcp__{FILESYSTEM_SERVER_ID}__{t}"));
    }
    for t in &config.git_tools {
        allowed_tools.push(t.clone());
        allowed_tools.push(format!("mcp__{GIT_SERVER_ID}__{t}"));
    }
    allowed_tools.sort();
    allowed_tools.dedup();

    let checks_passed = vec![
        "claude-executable-verified".into(),
        "workspace-verified".into(),
        "profiles-validated-without-collision".into(),
        "live-daemon-instance-bound".into(),
        "runnable-mcp-collectors-constructed".into(),
        "private-config-dir-created-mode-0700".into(),
        "scoped-child-authority-grants-minted".into(),
        "tokens-confined-to-private-config".into(),
        "strict-mcp-boundary-enforced".into(),
    ];

    if config.dry_run {
        let report = PilotLaunchReport {
            contract_version: "sw-pilot-launcher/1".into(),
            status: "preview_ready".into(),
            host_session: config.host_session.clone(),
            claude_path: config.claude_path.display().to_string(),
            workspace_path: config.workspace_path.display().to_string(),
            private_config_dir: guard.path.display().to_string(),
            allowed_tools,
            servers: server_plans,
            exit_code: Some(0),
            checks_passed,
            resource_budget: if config.linux_budget.is_some() {
                serde_json::json!({"status":"selected-not-active","requested":true})
            } else {
                serde_json::json!({"status":"unbudgeted","requested":false})
            },
            error: None,
        };

        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            eprintln!("Claude Code pilot launch preview validated successfully.");
            eprintln!("Daemon instance: {}", instance_id);
            eprintln!("Private dir:     {}", guard.path.display());
            eprintln!("MCP Config:      {}", mcp_config_path.display());
            eprintln!(
                "Allowed tools ({}): {:?}",
                report.allowed_tools.len(),
                report.allowed_tools
            );
        }
        return Ok(());
    }

    // Full execution mode
    let mut cmd = Command::new(&config.claude_path);
    cmd.arg("--restricted")
        .arg("-p")
        .arg(&config.prompt)
        .arg("--strict-mcp-config")
        .arg("--mcp-config")
        .arg(&mcp_config_path)
        .arg("--session-id")
        .arg(&config.host_session)
        .arg("--tools")
        .arg("")
        .arg("--allowedTools")
        .arg(allowed_tools.join(","))
        .arg("--no-session-persistence")
        .arg("--output-format")
        .arg("stream-json")
        .arg("--verbose")
        .arg("--permission-mode")
        .arg("dontAsk")
        .arg("--model")
        .arg(&config.model)
        .current_dir(&config.workspace_path);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
        if args.json {
            use std::os::fd::FromRawFd;
            unsafe {
                cmd.stdout(std::process::Stdio::from_raw_fd(libc::dup(
                    libc::STDERR_FILENO,
                )));
            }
        }
    }

    crate::pilot_host::isolate(&mut cmd, &guard.path, provider)?;
    // Explicit command fixtures may use ordinary system utilities. The pinned
    // production client has no executable search path; its MCP commands and
    // selected collector/runtime paths are already absolute.
    if args.allow_command_fixtures || args.mock_daemon_token.is_some() {
        cmd.env("PATH", "/usr/bin:/bin");
    }
    #[cfg(target_os = "linux")]
    let child_environment = if !args.allow_command_fixtures && args.mock_daemon_token.is_none() {
        Some(crate::pilot_host::ChildEnvironmentGuard::install(
            &mut cmd,
            &guard.path,
        )?)
    } else {
        None
    };
    cmd.env("CLAUDE_CONFIG_DIR", guard.path.join(".claude"))
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        .env("CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL", "1")
        .env("DISABLE_UPDATES", "1")
        .env("DISABLE_AUTOUPDATER", "1")
        .env("DISABLE_BUG_REPORTING", "1")
        .env("DISABLE_GROWTHBOOK", "1")
        .env("ENABLE_CLAUDEAI_MCP_SERVERS", "false")
        .env("CLAUDE_CODE_DISABLE_CLAUDE_MDS", "1")
        .env("CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1")
        .env("CLAUDE_CODE_DISABLE_BACKGROUND_TASKS", "1")
        .env("CLAUDE_CODE_DISABLE_BUNDLED_SKILLS", "1")
        .env("CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS", "1")
        .env("CLAUDE_CODE_MAX_RETRIES", "0");

    if let Some(run) = &pilot_run {
        if config.ask_wait_seconds > 0 {
            eprintln!("Pilot Ask configured; run: {}", run.id());
            eprintln!(
                "Second terminal (same daemon home): agentfw pilot-approval --run {} list",
                run.id()
            );
        }
        eprintln!("Pilot owned run: {}; stop from another terminal: agentfw pilot-approval --home {} --run {} stop",
            run.id(), config.home_path.display(), run.id());
    }
    // Install interception before creating the separate host process group.
    // A TERM during runtime/signal initialization must never strand a live host.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create supervisor runtime")?;

    #[cfg(unix)]
    let (mut sigterm, mut sigint) = {
        let _entered = rt.enter();
        (
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
        )
    };
    if let Some(budget) = &budget {
        budget.verify_root()?;
    }
    let timeout = config.timeout;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut child = cmd.spawn().context("failed to spawn Claude Code host")?;
    let child_pid = child.id();
    drop(cmd);
    #[cfg(target_os = "linux")]
    let child_environment_ready = child_environment
        .map(|guard| guard.confirm_until(deadline.into_std()))
        .transpose();

    let home_path = config.home_path.clone();
    let is_mock = config.mock_daemon_token.is_some();
    let initial_instance = instance_id.clone();
    let current_token = daemon_token.clone();

    let mut host_stopped = false;
    let mut intercepted_term = false;
    let mut cleanup_waiter = pilot_run.as_ref().map(|run| run.cleanup_waiter());
    let exit_status = rt.block_on(async {
        #[cfg(target_os = "linux")]
        if child_environment_ready.is_err() {
            let host_deadline_expired = tokio::time::Instant::now() >= deadline;
            let group = terminate_process_group(child_pid, Duration::from_millis(200)).await;
            host_stopped = reap_owned_host(&mut child).await.is_ok() && group.is_ok();
            if let Some(waiter) = cleanup_waiter.take() {
                let _ = tokio::task::spawn_blocking(waiter).await;
            }
            if host_deadline_expired {
                bail!("pilot host execution exceeded declared timeout of {}s", timeout.as_secs());
            }
            bail!("provider_child_environment_unavailable");
        }
        let mut interval = tokio::time::interval(Duration::from_millis(1000));
        interval.tick().await;

        loop {
            if tokio::time::Instant::now() >= deadline {
                let group = terminate_process_group(child_pid, Duration::from_millis(200)).await;
                #[cfg(not(unix))]
                {
                    let _ = child.kill();
                }
                host_stopped = reap_owned_host(&mut child).await.is_ok() && group.is_ok();
                bail!("pilot host execution exceeded declared timeout of {}s", timeout.as_secs());
            }
            // Check if child has exited
            match owned_host_exited(&mut child) {
                Ok(true) => {
                    // Every host exit must let enrolled owners acknowledge
                    // namespace cleanup before group TERM/KILL. Keep the leader
                    // unreaped so its process-group identity cannot be reused.
                    let owner_confirmation = if let Some(waiter) = cleanup_waiter.take() {
                        tokio::task::spawn_blocking(waiter)
                            .await
                            .context("selected-owner cleanup worker failed")
                            .and_then(|result| result)
                    } else {
                        Ok(())
                    };
                    // A missing/failed acknowledgement never skips physical
                    // cleanup, but cannot turn the terminal result into success.
                    let group = terminate_process_group(child_pid, Duration::from_millis(50)).await;
                    let result = reap_owned_host(&mut child).await;
                    host_stopped = result.is_ok() && group.is_ok();
                    group?;
                    owner_confirmation?;
                    return result;
                }
                Ok(false) => {}
                Err(error) => {
                    // Ownership could not be established; never signal a potentially reused PID.
                    return Err(anyhow::anyhow!("cannot establish owned host exit state: {}", error));
                }
            }

            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    let group = terminate_process_group(child_pid, Duration::from_millis(200)).await;
                    #[cfg(not(unix))]
                    {
                        let _ = child.kill();
                    }
                    host_stopped = reap_owned_host(&mut child).await.is_ok() && group.is_ok();
                    bail!("pilot host execution exceeded declared timeout of {}s", timeout.as_secs());
                }
                _ = async {
                    #[cfg(unix)]
                    sigint.recv().await;
                    #[cfg(not(unix))]
                    let _ = tokio::signal::ctrl_c().await;
                } => {
                    let group = terminate_process_group(child_pid, Duration::from_millis(200)).await;
                    #[cfg(not(unix))]
                    {
                        let _ = child.kill();
                    }
                    host_stopped = reap_owned_host(&mut child).await.is_ok() && group.is_ok();
                    bail!("pilot host interrupted by SIGINT");
                }
                _ = async {
                    #[cfg(unix)]
                    sigterm.recv().await;
                    #[cfg(not(unix))]
                    futures_util::future::pending::<()>().await;
                } => {
                    intercepted_term = true;
                    if let Some(waiter) = cleanup_waiter.take() {
                        // A native revoke wakes the enrolled collectors first.
                        // Give their existing owners time to acknowledge the
                        // whole namespace before host-group termination.
                        // finish() independently checks the actual observations.
                        let _ = tokio::task::spawn_blocking(waiter).await;
                    }
                    let group = terminate_process_group(child_pid, Duration::from_millis(200)).await;
                    #[cfg(not(unix))]
                    {
                        let _ = child.kill();
                    }
                    host_stopped = reap_owned_host(&mut child).await.is_ok() && group.is_ok();
                    bail!("pilot host terminated by SIGTERM");
                }
                _ = interval.tick() => {
                    if !is_mock && home_path.join("config.yaml").exists() {
                        match probe_daemon_liveness(&home_path, &current_token).await {
                            Ok(live_id) if live_id == initial_instance => {}
                            _ => {
                                let group = terminate_process_group(child_pid, Duration::from_millis(200)).await;
                                #[cfg(not(unix))]
                                {
                                    let _ = child.kill();
                                }
                                host_stopped = reap_owned_host(&mut child).await.is_ok() && group.is_ok();
                                bail!("daemon instance lost or restarted during pilot session");
                            }
                        }
                    }
                }
            }
        }
    });
    // Cancellation, timeout, daemon loss and a crashing host cannot become a
    // successful stop merely because a concurrent caller published intent.
    let stop_can_complete = intercepted_term
        || exit_status
            .as_ref()
            .is_ok_and(std::process::ExitStatus::success);
    let cleanup = pilot_run
        .as_ref()
        .map(|run| run.finish(host_stopped && stop_can_complete))
        .transpose();
    let authenticated_stop = cleanup? == Some(true);
    let resource_budget = if let Some(budget) = &budget {
        budget.verify_root()?;
        budget.summary()?
    } else {
        serde_json::json!({"status":"unbudgeted","requested":false})
    };
    let budget_refused = resource_budget
        .get("failed_children")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
        > 0
        || resource_budget
            .get("unresolved_children")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            > 0;
    let host_exit = terminal_exit_code(exit_status, intercepted_term, authenticated_stop)?;
    let exit_code = if budget_refused { 1 } else { host_exit };
    if !args.json {
        if authenticated_stop {
            eprintln!("Pilot owned run stopped; already dispatched effects were not rolled back");
        } else {
            eprintln!("Pilot session completed with exit code: {}", exit_code);
        }
    } else {
        let report = PilotLaunchReport {
            contract_version: "sw-pilot-launcher/1".into(),
            status: if authenticated_stop {
                "stopped".into()
            } else if exit_code == 0 {
                "completed".into()
            } else {
                "failed".into()
            },
            host_session: config.host_session.clone(),
            claude_path: config.claude_path.display().to_string(),
            workspace_path: config.workspace_path.display().to_string(),
            private_config_dir: guard.path.display().to_string(),
            allowed_tools,
            servers: server_plans,
            exit_code: Some(exit_code),
            checks_passed,
            resource_budget: resource_budget.clone(),
            error: if exit_code == 0 {
                None
            } else {
                Some(format!("process exited with code {}", exit_code))
            },
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    ensure!(!budget_refused, "pilot_budget_terminal_refusal");
    if exit_code != 0 {
        bail!("host process failed with exit code {}", exit_code);
    }

    Ok(())
}

fn terminal_exit_code(
    status: Result<std::process::ExitStatus>,
    intercepted_term: bool,
    authenticated_stop: bool,
) -> Result<i32> {
    if intercepted_term && authenticated_stop {
        return Ok(0);
    }
    let status = status?;
    ensure!(
        !authenticated_stop || status.success(),
        "pilot stop incomplete: host did not complete normally"
    );
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_group_observation_refuses_live_unknown_or_malformed_members() {
        assert!(!super::mac_group_has_running_processes("10 S\n20 Z+\n", 20).unwrap());
        assert!(super::mac_group_has_running_processes("20 Z\n20 S\n", 20).unwrap());
        assert!(super::mac_group_has_running_processes("20 ?\n", 20).unwrap());
        for value in ["", "unreadable", "20 Z extra", "20"] {
            assert!(super::mac_group_has_running_processes(value, 20).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn mac_zombie_only_group_does_not_fake_a_signal_permission_failure() {
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new("/usr/bin/true")
            .process_group(0)
            .spawn()
            .unwrap();
        for _ in 0..100 {
            if super::owned_host_exited(&mut child).unwrap() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(super::owned_host_exited(&mut child).unwrap());
        let result =
            super::terminate_process_group(child.id(), std::time::Duration::from_millis(5)).await;
        assert!(child.wait().unwrap().success());
        result.unwrap();
    }
    use super::*;

    #[test]
    #[cfg(unix)]
    fn intentional_stop_requires_authenticated_terminal_disposition() {
        use std::os::unix::process::ExitStatusExt;
        let interrupted = || Err(anyhow::anyhow!("pilot host terminated by SIGTERM"));
        assert_eq!(terminal_exit_code(interrupted(), true, true).unwrap(), 0);
        assert!(terminal_exit_code(interrupted(), true, false).is_err());
        // An authenticated receipt cannot turn cancellation, timeout or daemon
        // loss into a successful terminal outcome.
        assert!(terminal_exit_code(interrupted(), false, true).is_err());
        assert!(terminal_exit_code(interrupted(), false, false).is_err());
        assert!(
            terminal_exit_code(Ok(std::process::ExitStatus::from_raw(9)), false, true).is_err()
        );
        assert_eq!(
            terminal_exit_code(Ok(std::process::ExitStatus::from_raw(0)), false, true).unwrap(),
            0
        );
        assert_eq!(
            terminal_exit_code(
                Ok(std::process::ExitStatus::from_raw(17 << 8)),
                false,
                false
            )
            .unwrap(),
            17
        );
    }

    fn dummy_script(path: &Path) {
        fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_state_parent_cannot_alias_either_selected_workspace() {
        let root = tempfile::tempdir().unwrap();
        let filesystem = root.path().join("filesystem");
        let git = root.path().join("git");
        fs::create_dir(&filesystem).unwrap();
        fs::create_dir(&git).unwrap();
        for (i, workspace) in [&filesystem, &git].iter().enumerate() {
            let alias = root.path().join(format!("alias-{i}"));
            std::os::unix::fs::symlink(workspace, &alias).unwrap();
            assert!(PrivateDirGuard::in_parent(&[&filesystem, &git], &alias).is_err());
            assert!(fs::read_dir(workspace).unwrap().next().is_none());
        }
        let guard = PrivateDirGuard::in_parent(&[&filesystem, &git], root.path()).unwrap();
        let path = guard.path.clone();
        drop(guard);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn completed_host_remains_waitable_until_owned_group_cleanup() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 17"])
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !owned_host_exited(&mut child).unwrap() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        // A second observation must still see the same waitable child.
        assert!(owned_host_exited(&mut child).unwrap());
        assert_eq!(child.wait().unwrap().code(), Some(17));
    }

    #[test]
    fn test_missing_claude_executable_fails() {
        let temp = tempfile::tempdir().unwrap();
        let args = PilotLaunchArgs {
            git_workspace: None,
            claude: temp.path().join("nonexistent_claude"),
            workspace: temp.path().to_path_buf(),
            home: None,
            fs_profile: temp.path().join("fs.json"),
            git_profile: temp.path().join("git.json"),
            classifier: None,
            policy: None,
            host_session: None,
            agent_bin: None,
            dry_run: true,
            timeout_seconds: 10,
            ask_wait_seconds: 0,
            json: false,
            prompt: None,
            model: "claude-sonnet-4-20250514".into(),
            mock_daemon_token: Some(crate::token::generate()),
            mock_instance_id: Some(crate::token::generate()),
            provider_env_fd: None,
            linux_budget: None,
            linux_budget_sha256: None,
            allow_command_fixtures: false,
        };
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_instance_prefixed_nonces_and_mismatch_negative_control() {
        let instance_id = format!("inst-live-{}", random_uuid_v4());
        let nonce = format!("{instance_id}.{}", random_uuid_v4());
        assert_eq!(
            nonce.split_once('.').map(|(inst, _)| inst),
            Some(instance_id.as_str())
        );

        // Negative control: foreign or restarted daemon instance mismatch
        let restarted_instance = format!("inst-restarted-{}", random_uuid_v4());
        assert_ne!(
            nonce.split_once('.').map(|(inst, _)| inst),
            Some(restarted_instance.as_str())
        );
    }

    #[test]
    fn test_valid_args_dry_run_generates_correct_plan() {
        let temp = tempfile::tempdir().unwrap();
        let claude = temp.path().join("claude");
        dummy_script(&claude);

        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();

        let fs_profile = temp.path().join("fs.json");
        fs::write(
            &fs_profile,
            r#"{"runtimePath":"/usr/bin/node","packageRoot":"/pkg/fs","tools":[{"name":"read_text_file"}]}"#,
        )
        .unwrap();

        let git_profile = temp.path().join("git.json");
        fs::write(
            &git_profile,
            r#"{"runtimePath":"/usr/bin/python3","tools":[{"name":"git_status"}]}"#,
        )
        .unwrap();

        let test_token = crate::token::generate();
        let test_instance_id = crate::token::generate();

        let git_workspace = temp.path().join("separate-git");
        fs::create_dir(&git_workspace).unwrap();
        let args = PilotLaunchArgs {
            git_workspace: Some(git_workspace.clone()),
            claude,
            workspace: workspace.clone(),
            home: Some(temp.path().to_path_buf()),
            fs_profile,
            git_profile,
            classifier: None,
            policy: None,
            host_session: Some("test-session-123".into()),
            agent_bin: None,
            dry_run: true,
            timeout_seconds: 60,
            ask_wait_seconds: 0,
            json: true,
            prompt: None,
            model: "claude-sonnet-4-20250514".into(),
            mock_daemon_token: Some(test_token.clone()),
            mock_instance_id: Some(test_instance_id.clone()),
            provider_env_fd: None,
            linux_budget: None,
            linux_budget_sha256: None,
            allow_command_fixtures: false,
        };

        let mut config = args.validate().expect("validation should succeed");
        assert_eq!(config.host_session, "test-session-123");
        assert_eq!(config.fs_tools, vec!["read_text_file"]);
        assert_eq!(config.git_tools, vec!["git_status"]);
        assert_eq!(config.fs_runtime_cmd[0], "/usr/bin/node");
        assert_eq!(config.git_runtime_cmd[0], "/usr/bin/python3");

        let guard = PrivateDirGuard::new(&workspace).expect("guard creation");
        assert!(!guard.path.starts_with(&workspace));

        let grants = mint_grants(&config, 1_000_000, &test_instance_id).expect("grants mint");
        assert!(grants.contains_key("filesystem"));
        assert!(grants.contains_key("git"));

        // Verify that the grant verifies with derived key and has instance-prefixed nonce
        let key = child_authority::derive_key(&test_token);
        let fs_grant = &grants["filesystem"];
        assert!(fs_grant.nonce.starts_with(&format!("{test_instance_id}.")));
        assert!(child_authority::verify(
            &key,
            fs_grant,
            "test-session-123",
            "filesystem",
            1_000_050,
        )
        .is_ok());

        let (mcp_config, plans) = write_per_process_mcp_config(&guard.path, &config, &grants, None)
            .expect("write config");
        assert!(mcp_config.exists());
        let actual: serde_json::Value =
            serde_json::from_slice(&fs::read(&mcp_config).unwrap()).unwrap();
        for server in actual["mcpServers"].as_object().unwrap().values() {
            assert_eq!(server["command"], "/usr/bin/env");
            assert_eq!(server["args"][0], "-i");
            assert_eq!(server["args"][1], "--");
            for key in crate::pilot_host::PROVIDER_ENV {
                assert_eq!(server["env"][key], "");
            }
            let words = server["args"].as_array().unwrap();
            assert!(words
                .iter()
                .any(|word| word == config.agent_bin_path.to_str().unwrap()));
            assert!(words.iter().any(|word| word
                .as_str()
                .is_some_and(|w| w.starts_with("AGENTFW_HOST_SESSION="))));
        }

        // Verify tokens are redacted in plans
        assert!(plans["filesystem"].token_redacted);
        assert_eq!(plans["filesystem"].args[7], "[REDACTED]");

        // Verify real server command after --
        assert_eq!(plans["filesystem"].args[10], "--");
        assert_eq!(plans["filesystem"].args[11], "/usr/bin/node");
        assert_eq!(plans["git"].args[10], "--");
        assert_eq!(plans["git"].args[11], "/usr/bin/python3");

        // Verify mcp.json contains environment variables
        let mcp_data: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&mcp_config).unwrap()).unwrap();
        let env_for = |server: &str| {
            mcp_data["mcpServers"][server]["args"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|word| word.as_str().and_then(|word| word.split_once('=')))
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect::<BTreeMap<_, _>>()
        };
        let fs_env = env_for("filesystem");
        let git_env = env_for("git");
        assert_eq!(
            git_env["AGENTFW_WORKSPACE"],
            git_workspace.canonicalize().unwrap().display().to_string()
        );
        assert_eq!(fs_env["AGENTFW_CLASSIFIER_PYTHON"], "/usr/bin/python3");
        assert_eq!(git_env["AGENTFW_CLASSIFIER_PYTHON"], "/usr/bin/python3");
        assert_eq!(fs_env["AGENTFW_HOST_SESSION"], "test-session-123");
        assert_eq!(fs_env["AGENTFW_NATIVE_LIVENESS"], "true");
        assert_eq!(
            fs_env["AGENTFW_WORKSPACE"],
            workspace.canonicalize().unwrap().display().to_string()
        );

        // The credential scrubber must preserve explicitly selected budget
        // authority in each collector's finite environment and launch arguments.
        let budget_path = temp.path().join("selected-budget.json");
        config.linux_budget = Some(budget_path.clone());
        config.linux_budget_sha256 = Some("b".repeat(64));
        let (budget_mcp, _) =
            write_per_process_mcp_config(&guard.path, &config, &grants, None).unwrap();
        let budget_mcp: serde_json::Value =
            serde_json::from_slice(&fs::read(budget_mcp).unwrap()).unwrap();
        for server in budget_mcp["mcpServers"].as_object().unwrap().values() {
            assert_eq!(server["command"], "/usr/bin/env");
            let words = server["args"].as_array().unwrap();
            assert!(words.iter().any(|word| word
                == &serde_json::json!(format!(
                    "{}={}",
                    crate::mcp::linux_budget::ENVIRONMENT,
                    budget_path.display()
                ))));
            assert!(words.iter().any(|word| word
                .as_str()
                .is_some_and(|word| word.starts_with("AGENTFW_PILOT_BUDGET_BINDING="))));
            assert!(words.iter().any(|word| word == "--pilot-budget-binding"));
            assert!(words.iter().any(|word| word == "--pilot-budget-sha256"));
            for key in crate::pilot_host::PROVIDER_ENV {
                assert_eq!(server["env"][key], "");
                assert!(!words.iter().any(|word| word
                    .as_str()
                    .is_some_and(|word| word.starts_with(&format!("{key}=")))));
            }
        }
    }

    #[test]
    fn test_colliding_tools_between_servers_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let claude = temp.path().join("claude");
        dummy_script(&claude);

        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();

        let fs_profile = temp.path().join("fs.json");
        fs::write(&fs_profile, r#"{"tools":[{"name":"shared_tool"}]}"#).unwrap();

        let git_profile = temp.path().join("git.json");
        fs::write(&git_profile, r#"{"tools":[{"name":"shared_tool"}]}"#).unwrap();

        let args = PilotLaunchArgs {
            git_workspace: None,
            claude,
            workspace,
            home: None,
            fs_profile,
            git_profile,
            classifier: None,
            policy: None,
            host_session: None,
            agent_bin: None,
            dry_run: true,
            timeout_seconds: 60,
            ask_wait_seconds: 0,
            json: false,
            prompt: None,
            model: "claude-sonnet-4-20250514".into(),
            mock_daemon_token: Some(crate::token::generate()),
            mock_instance_id: Some(crate::token::generate()),
            provider_env_fd: None,
            linux_budget: None,
            linux_budget_sha256: None,
            allow_command_fixtures: false,
        };

        assert!(args.validate().is_err());
    }

    #[test]
    fn test_unverified_command_json_rejected_outside_mock_mode() {
        let temp = tempfile::tempdir().unwrap();
        let claude = temp.path().join("claude");
        dummy_script(&claude);

        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();

        let fs_profile = temp.path().join("fs.json");
        fs::write(&fs_profile, r#"{"command":"/bin/echo","args":["hello"]}"#).unwrap();

        let git_profile = temp.path().join("git.json");
        fs::write(&git_profile, r#"{"command":"/bin/echo","args":["world"]}"#).unwrap();

        let args = PilotLaunchArgs {
            git_workspace: None,
            claude,
            workspace,
            home: None,
            fs_profile,
            git_profile,
            classifier: None,
            policy: None,
            host_session: None,
            agent_bin: None,
            dry_run: true,
            timeout_seconds: 60,
            ask_wait_seconds: 0,
            json: false,
            prompt: None,
            model: "claude-sonnet-4-20250514".into(),
            mock_daemon_token: None,
            mock_instance_id: None,
            provider_env_fd: None,
            linux_budget: None,
            linux_budget_sha256: None,
            allow_command_fixtures: false,
        };

        let err = args.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("real pilot requires validated ProfileConfig"));
    }

    #[test]
    fn test_missing_profile_rejected_outside_mock_mode() {
        let temp = tempfile::tempdir().unwrap();
        let claude = temp.path().join("claude");
        dummy_script(&claude);

        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();

        let fs_dir = temp.path().join("fs_empty");
        fs::create_dir_all(&fs_dir).unwrap();

        let git_dir = temp.path().join("git_empty");
        fs::create_dir_all(&git_dir).unwrap();

        let args = PilotLaunchArgs {
            git_workspace: None,
            claude,
            workspace,
            home: None,
            fs_profile: fs_dir,
            git_profile: git_dir,
            classifier: None,
            policy: None,
            host_session: None,
            agent_bin: None,
            dry_run: true,
            timeout_seconds: 60,
            ask_wait_seconds: 0,
            json: false,
            prompt: None,
            model: "claude-sonnet-4-20250514".into(),
            mock_daemon_token: None,
            mock_instance_id: None,
            provider_env_fd: None,
            linux_budget: None,
            linux_budget_sha256: None,
            allow_command_fixtures: false,
        };

        let err = args.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("installed MCP server profile not found"));
    }

    #[test]
    fn test_command_fixtures_allowed_with_flag() {
        let temp = tempfile::tempdir().unwrap();
        let claude = temp.path().join("claude");
        dummy_script(&claude);

        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();

        let fs_profile = temp.path().join("fs.json");
        fs::write(&fs_profile, r#"{"command":"/bin/echo","args":["hello"]}"#).unwrap();

        let git_profile = temp.path().join("git.json");
        fs::write(&git_profile, r#"{"command":"/bin/echo","args":["world"]}"#).unwrap();

        let args = PilotLaunchArgs {
            git_workspace: None,
            claude,
            workspace,
            home: None,
            fs_profile,
            git_profile,
            classifier: None,
            policy: None,
            host_session: None,
            agent_bin: None,
            dry_run: true,
            timeout_seconds: 60,
            ask_wait_seconds: 0,
            json: false,
            prompt: None,
            model: "claude-sonnet-4-20250514".into(),
            mock_daemon_token: None,
            mock_instance_id: None,
            provider_env_fd: None,
            linux_budget: None,
            linux_budget_sha256: None,
            allow_command_fixtures: true,
        };

        let cfg = args
            .validate()
            .expect("should succeed with allow_command_fixtures");
        assert_eq!(cfg.fs_runtime_cmd, vec!["/bin/echo", "hello"]);
        assert_eq!(cfg.git_runtime_cmd, vec!["/bin/echo", "world"]);
    }
}
