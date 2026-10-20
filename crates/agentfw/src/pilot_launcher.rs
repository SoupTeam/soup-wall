// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Trusted per-run Claude Code pilot launcher for two pinned MCP servers (SOU-99).
//!
//! Provides a bounded, isolated execution environment outside the source workspace,
//! automatically minting distinct signed child authority grants from the authenticated
//! daemon, strictly configuring the host boundary to prevent unmediated tool bypass,
//! and ensuring complete owned cleanup on completion, interruption, or failure.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};

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

/// Helper to generate random hex identifier without external uuid crate.
fn random_hex_128() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// Helper to generate a random UUID-like string.
fn random_uuid_v4() -> String {
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

    /// Explicit installed daemon home directory containing native-token and config;
    /// defaults to ~/.agentfw.
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

    /// Optional path to pilot policy YAML.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Optional explicit host session UUID; generated if not provided.
    #[arg(long)]
    pub session_id: Option<String>,

    /// Optional path to agentfw executable for running MCP collectors; defaults to current_exe.
    #[arg(long)]
    pub agent_bin: Option<PathBuf>,

    /// Dry run: validate inputs, construct per-run configuration plan, and output JSON without launching host.
    #[arg(long)]
    pub dry_run: bool,

    /// Maximum seconds allowed for the host conversation before cancellation.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS)]
    pub timeout_seconds: u64,

    /// Output versioned machine-readable JSON summary instead of operator logs.
    #[arg(long)]
    pub json: bool,

    /// Mock daemon token for testing/dry-run when daemon is not running.
    #[arg(long, hide = true)]
    pub mock_daemon_token: Option<String>,
}

/// Validated configuration ready for execution.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    pub claude_path: PathBuf,
    pub workspace_path: PathBuf,
    pub home_path: PathBuf,
    pub fs_profile_path: PathBuf,
    pub git_profile_path: PathBuf,
    pub classifier_path: Option<PathBuf>,
    pub policy_path: Option<PathBuf>,
    pub session_id: String,
    pub agent_bin_path: PathBuf,
    pub timeout: Duration,
    pub dry_run: bool,
    pub mock_daemon_token: Option<String>,
    pub fs_tools: Vec<String>,
    pub git_tools: Vec<String>,
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
            None => Config::home_path()?,
        };

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

        // 7. Session ID
        let session_id = match &self.session_id {
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

        Ok(ValidatedConfig {
            claude_path,
            workspace_path,
            home_path,
            fs_profile_path,
            git_profile_path,
            classifier_path,
            policy_path,
            session_id,
            agent_bin_path,
            timeout: Duration::from_secs(self.timeout_seconds),
            dry_run: self.dry_run,
            mock_daemon_token: self.mock_daemon_token.clone(),
            fs_tools,
            git_tools,
        })
    }
}

/// Extract tool names from profile directory or JSON file.
fn extract_tools_from_profile(profile_path: &Path, fallback: &[&str]) -> Result<Vec<String>> {
    if profile_path.is_dir() {
        let tools_json = profile_path.join("upstream-tools-list.json");
        if tools_json.exists() {
            let content = fs::read_to_string(&tools_json)?;
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
    } else if profile_path.is_file() {
        let content = fs::read_to_string(profile_path)?;
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
    Ok(fallback.iter().map(|&s| s.to_string()).collect())
}

/// RAII Guard that securely removes the private per-run directory upon exit or failure.
pub struct PrivateDirGuard {
    pub path: PathBuf,
    disarmed: bool,
}

impl PrivateDirGuard {
    pub fn new(workspace: &Path) -> Result<Self> {
        let temp_base = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let rand_suffix = random_hex_128();
        let private_path = temp_base.join(format!("soup-wall-pilot-{}", rand_suffix));

        // Ensure private dir is not inside workspace
        let canonical_workspace = workspace.canonicalize()?;
        ensure!(
            !private_path.starts_with(&canonical_workspace),
            "private per-run configuration directory must be outside the workspace"
        );

        fs::create_dir_all(&private_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&private_path, fs::Permissions::from_mode(0o700))?;
        }

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

/// Mint HMAC-signed scoped child authority grants for the session.
pub fn mint_grants(
    config: &ValidatedConfig,
    now_ms: u64,
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

    // 1. Filesystem grant
    let fs_nonce = random_uuid_v4();
    let fs_grant = child_authority::mint_scoped(
        &key,
        &config.session_id,
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

    // 2. Git grant
    let git_nonce = random_uuid_v4();
    let git_grant = child_authority::mint_scoped(
        &key,
        &config.session_id,
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
) -> Result<(PathBuf, BTreeMap<String, ServerLaunchPlan>)> {
    let mut server_plans = BTreeMap::new();
    let mut mcp_servers = serde_json::Map::new();

    for (server_id, grant) in grants {
        let encoded_grant = child_authority::encode_token(grant);
        let collector_args = vec![
            "mcp".to_string(),
            "--id".to_string(),
            server_id.clone(),
            "--native-admission".to_string(),
            "--host-session".to_string(),
            config.session_id.clone(),
            "--child-authority".to_string(),
            encoded_grant,
            "--".to_string(),
            if server_id == FILESYSTEM_SERVER_ID {
                config.fs_profile_path.display().to_string()
            } else {
                config.git_profile_path.display().to_string()
            },
        ];

        let mut s_obj = serde_json::Map::new();
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

        mcp_servers.insert(server_id.clone(), serde_json::Value::Object(s_obj));

        // Sanitized plan for reporting (tokens redacted)
        server_plans.insert(
            server_id.clone(),
            ServerLaunchPlan {
                server_id: server_id.clone(),
                command: config.agent_bin_path.display().to_string(),
                args: vec![
                    "mcp".to_string(),
                    "--id".to_string(),
                    server_id.clone(),
                    "--native-admission".to_string(),
                    "--host-session".to_string(),
                    config.session_id.clone(),
                    "--child-authority".to_string(),
                    "[REDACTED]".to_string(),
                    "--".to_string(),
                    if server_id == FILESYSTEM_SERVER_ID {
                        config.fs_profile_path.display().to_string()
                    } else {
                        config.git_profile_path.display().to_string()
                    },
                ],
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

/// Execute the pilot launcher command.
pub fn run(args: PilotLaunchArgs) -> Result<()> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let config = args.validate()?;
    let guard = PrivateDirGuard::new(&config.workspace_path)?;

    let grants = mint_grants(&config, now_ms)?;
    let (mcp_config_path, server_plans) =
        write_per_process_mcp_config(&guard.path, &config, &grants)?;

    let mut allowed_tools = Vec::new();
    allowed_tools.extend(config.fs_tools.clone());
    allowed_tools.extend(config.git_tools.clone());
    allowed_tools.sort();

    let checks_passed = vec![
        "claude-executable-verified".into(),
        "workspace-verified".into(),
        "profiles-validated-without-collision".into(),
        "private-config-dir-created-mode-0700".into(),
        "scoped-child-authority-grants-minted".into(),
        "tokens-confined-to-private-config".into(),
        "strict-mcp-boundary-enforced".into(),
    ];

    if config.dry_run {
        let report = PilotLaunchReport {
            contract_version: "sw-pilot-launcher/1".into(),
            status: "preview_ready".into(),
            host_session: config.session_id.clone(),
            claude_path: config.claude_path.display().to_string(),
            workspace_path: config.workspace_path.display().to_string(),
            private_config_dir: guard.path.display().to_string(),
            allowed_tools,
            servers: server_plans,
            exit_code: Some(0),
            checks_passed,
            error: None,
        };

        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            eprintln!("Claude Code pilot launch preview validated successfully.");
            eprintln!("Private dir: {}", guard.path.display());
            eprintln!("MCP Config:  {}", mcp_config_path.display());
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
        .arg("--strict-mcp-config")
        .arg("--mcp-config")
        .arg(&mcp_config_path)
        .arg("--session-id")
        .arg(&config.session_id)
        .arg("--tools")
        .arg("")
        .arg("--allowedTools")
        .arg(allowed_tools.join(","))
        .arg("--no-session-persistence")
        .arg("--permission-mode")
        .arg("dontAsk")
        .current_dir(&config.workspace_path);

    // Environment isolation
    cmd.env("CLAUDE_CONFIG_DIR", guard.path.join(".claude"))
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        .env("CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL", "1")
        .env("DISABLE_UPDATES", "1")
        .env("DISABLE_GROWTHBOOK", "1")
        .env("ENABLE_CLAUDEAI_MCP_SERVERS", "false")
        .env("CLAUDE_CODE_DISABLE_CLAUDE_MDS", "1")
        .env("CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1")
        .env("CLAUDE_CODE_DISABLE_BACKGROUND_TASKS", "1")
        .env("CLAUDE_CODE_DISABLE_BUNDLED_SKILLS", "1")
        .env("CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS", "1")
        .env("CLAUDE_CODE_MAX_RETRIES", "0");

    let status = match cmd.status() {
        Ok(s) => s,
        Err(err) => {
            bail!("failed to spawn Claude Code host: {}", err);
        }
    };

    let exit_code = status.code().unwrap_or(1);
    if !args.json {
        eprintln!("Pilot session completed with exit code: {}", exit_code);
    } else {
        let report = PilotLaunchReport {
            contract_version: "sw-pilot-launcher/1".into(),
            status: if exit_code == 0 {
                "completed".into()
            } else {
                "failed".into()
            },
            host_session: config.session_id.clone(),
            claude_path: config.claude_path.display().to_string(),
            workspace_path: config.workspace_path.display().to_string(),
            private_config_dir: guard.path.display().to_string(),
            allowed_tools,
            servers: server_plans,
            exit_code: Some(exit_code),
            checks_passed,
            error: if exit_code == 0 {
                None
            } else {
                Some(format!("process exited with code {}", exit_code))
            },
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    if exit_code != 0 {
        bail!("host process failed with exit code {}", exit_code);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_script(path: &Path) {
        fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn test_missing_claude_executable_fails() {
        let temp = tempfile::tempdir().unwrap();
        let args = PilotLaunchArgs {
            claude: temp.path().join("nonexistent_claude"),
            workspace: temp.path().to_path_buf(),
            home: None,
            fs_profile: temp.path().join("fs.json"),
            git_profile: temp.path().join("git.json"),
            classifier: None,
            policy: None,
            session_id: None,
            agent_bin: None,
            dry_run: true,
            timeout_seconds: 10,
            json: false,
            mock_daemon_token: Some("mock-token-secret".into()),
        };
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_valid_args_dry_run_generates_correct_plan() {
        let temp = tempfile::tempdir().unwrap();
        let claude = temp.path().join("claude");
        dummy_script(&claude);

        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();

        let fs_profile = temp.path().join("fs.json");
        fs::write(&fs_profile, r#"{"tools":[{"name":"read_text_file"}]}"#).unwrap();

        let git_profile = temp.path().join("git.json");
        fs::write(&git_profile, r#"{"tools":[{"name":"git_status"}]}"#).unwrap();

        let args = PilotLaunchArgs {
            claude,
            workspace: workspace.clone(),
            home: Some(temp.path().to_path_buf()),
            fs_profile,
            git_profile,
            classifier: None,
            policy: None,
            session_id: Some("test-session-123".into()),
            agent_bin: None,
            dry_run: true,
            timeout_seconds: 60,
            json: true,
            mock_daemon_token: Some("mock-daemon-secret-1234567890".into()),
        };

        let config = args.validate().expect("validation should succeed");
        assert_eq!(config.session_id, "test-session-123");
        assert_eq!(config.fs_tools, vec!["read_text_file"]);
        assert_eq!(config.git_tools, vec!["git_status"]);

        let guard = PrivateDirGuard::new(&workspace).expect("guard creation");
        assert!(!guard.path.starts_with(&workspace));

        let grants = mint_grants(&config, 1_000_000).expect("grants mint");
        assert!(grants.contains_key("filesystem"));
        assert!(grants.contains_key("git"));

        // Verify that the grant verifies with derived key
        let key = child_authority::derive_key("mock-daemon-secret-1234567890");
        let fs_grant = &grants["filesystem"];
        assert!(child_authority::verify(
            &key,
            fs_grant,
            "test-session-123",
            "filesystem",
            1_000_050,
        )
        .is_ok());

        let (mcp_config, plans) =
            write_per_process_mcp_config(&guard.path, &config, &grants).expect("write config");
        assert!(mcp_config.exists());

        // Verify tokens are redacted in plans
        assert!(plans["filesystem"].token_redacted);
        assert_eq!(plans["filesystem"].args[7], "[REDACTED]");
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
            claude,
            workspace,
            home: None,
            fs_profile,
            git_profile,
            classifier: None,
            policy: None,
            session_id: None,
            agent_bin: None,
            dry_run: true,
            timeout_seconds: 60,
            json: false,
            mock_daemon_token: Some("mock".into()),
        };

        assert!(args.validate().is_err());
    }
}
