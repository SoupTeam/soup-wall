// SPDX-License-Identifier: Apache-2.0
//! `agentfw onboard`: one first-use flow that composes the accepted installation,
//! lifecycle, MCP connection, protection-status and self-test commands.
//!
//! `preview` is read-only and prints a concrete plan with its digest. `apply`
//! requires that digest, revalidates every assumption, journals each step and
//! rolls back only this operation's proven changes. `undo` reverses a recorded
//! onboarding. Configured identity is reported separately from witnessed
//! behavior; unobserved host coverage stays unknown.

#[cfg(target_os = "linux")]
mod linux;

use std::path::PathBuf;

use serde_json::{json, Value};

pub const SCHEMA: &str = "sw-onboarding/1";
pub const PROFILE: &str = "linux-local-user-mcp-v1";

/// Stable exit codes, aligned with `self-test`. Clap reports usage errors with 2.
pub const EXIT_OK: i32 = 0;
pub const EXIT_FAILED: i32 = 3;
pub const EXIT_INCOMPLETE: i32 = 4;
pub const EXIT_UNSUPPORTED: i32 = 5;
pub const EXIT_CONFIGURED: i32 = 6;

#[derive(clap::Args, Debug, Clone)]
pub struct Inputs {
    /// Installed Agent executable (absolute; never discovered from PATH).
    #[arg(long)]
    pub agent: PathBuf,
    /// Expected SHA-256 of the Agent executable.
    #[arg(long)]
    pub agent_sha256: String,
    /// Classifier kind for the isolated self-test. Only `rule-baseline` is supported.
    #[arg(long, value_parser = ["rule-baseline"])]
    pub classifier: String,
    #[arg(long)]
    pub classifier_script: PathBuf,
    #[arg(long)]
    pub classifier_sha256: String,
    #[arg(long)]
    pub classifier_python: PathBuf,
    /// Reviewed sw-native/1 registry for the selected MCP server.
    #[arg(long)]
    pub registry: PathBuf,
    #[arg(long)]
    pub registry_sha256: String,
    /// Reviewed agent policy; omit to use the shipped default policy.
    #[arg(long, requires = "policy_sha256")]
    pub policy: Option<PathBuf>,
    #[arg(long, requires = "policy")]
    pub policy_sha256: Option<String>,
    /// Linux: accepted read-only original-server profile (`profile.json` written by
    /// the filesystem or Git profile installer). Its registry and policy are passed
    /// with --registry/--policy; the selected entry must be its original server.
    #[arg(long, requires = "server_profile_sha256")]
    pub server_profile: Option<PathBuf>,
    #[arg(long, requires = "server_profile")]
    pub server_profile_sha256: Option<String>,
    /// Reviewed workspace the selected server works in.
    #[arg(long)]
    pub workspace: PathBuf,
    /// Intended new Agent home (an absolute path named `.agentfw`).
    #[arg(long)]
    pub agent_home: PathBuf,
    /// Claude Code JSON file with an `mcpServers` object.
    #[arg(long)]
    pub host_config: PathBuf,
    /// Existing reviewed server entry in the host configuration.
    #[arg(long)]
    pub server: String,
    /// Loopback port for the new Agent daemon.
    #[arg(long, default_value_t = 8787)]
    pub port: u16,
    /// Optional harmless tool call used to verify the connected server.
    #[arg(long, requires = "probe_args")]
    pub probe_tool: Option<String>,
    #[arg(long, requires = "probe_tool")]
    pub probe_args: Option<String>,
    /// Fresh path for the JSON report (an existing file is never replaced).
    #[arg(long)]
    pub report: PathBuf,
    /// Upper bound for the whole operation.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(30..=3600))]
    pub timeout_seconds: u64,
}

#[derive(clap::Args, Debug, Clone)]
pub struct ApplyArgs {
    #[command(flatten)]
    pub inputs: Inputs,
    /// Digest printed by `onboard preview` for the reviewed plan.
    #[arg(long)]
    pub plan_sha256: String,
}

#[derive(clap::Args, Debug, Clone)]
pub struct UndoArgs {
    #[arg(long)]
    pub agent: PathBuf,
    #[arg(long)]
    pub agent_home: PathBuf,
    #[arg(long)]
    pub host_config: PathBuf,
    #[arg(long)]
    pub server: String,
    /// Also remove the Agent home that onboarding created, including its audit log.
    #[arg(long)]
    pub purge_agent_home: bool,
    #[arg(long)]
    pub report: PathBuf,
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(30..=3600))]
    pub timeout_seconds: u64,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum Command {
    /// Read-only: print the concrete plan, conflicts, prerequisites and its digest.
    Preview(Box<Inputs>),
    /// Apply the reviewed plan (requires its digest), then verify configuration and behavior.
    Apply(Box<ApplyArgs>),
    /// Reverse a recorded onboarding: disconnect, stop and remove only what it owns.
    Undo(Box<UndoArgs>),
}

pub fn base_report(operation: &str, supported: bool) -> serde_json::Map<String, Value> {
    match json!({
        "schema_version": SCHEMA,
        "agentfw_version": env!("CARGO_PKG_VERSION"),
        "operation": operation,
        "profile": {"id": PROFILE, "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
                    "supported": supported},
        "started_at_unix_ms": crate::self_test::now_unix_ms(),
    }) {
        Value::Object(map) => map,
        _ => unreachable!(),
    }
}

/// Entry point; returns the stable process exit code.
pub fn run(command: Command) -> i32 {
    #[cfg(target_os = "linux")]
    {
        linux::run(command)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (operation, report) = match &command {
            Command::Preview(i) => ("preview", i.report.clone()),
            Command::Apply(a) => ("apply", a.inputs.report.clone()),
            Command::Undo(u) => ("undo", u.report.clone()),
        };
        let mut value = base_report(operation, false);
        value.insert("result".into(), json!("unsupported"));
        value.insert("exit_code".into(), json!(EXIT_UNSUPPORTED));
        value.insert("explanation".into(), json!(
            "Linux is the only supported onboarding profile; nothing was changed and no protection is claimed."));
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&report)
        {
            use std::io::Write;
            let _ = file
                .write_all(&serde_json::to_vec_pretty(&Value::Object(value)).unwrap_or_default());
        }
        println!("Onboarding is unsupported on this platform; nothing was changed.");
        EXIT_UNSUPPORTED
    }
}
