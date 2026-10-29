// SPDX-License-Identifier: Apache-2.0
//! Explicit installed private-output edit sessions. No default pilot authority
//! is changed and no filesystem executor is implemented here.
use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

pub(crate) mod diagnostic;
mod profile;
pub(crate) mod quota;
pub(crate) use profile::Profile;
#[cfg(target_os = "linux")]
mod control;
#[cfg(target_os = "linux")]
mod control_io;
#[cfg(target_os = "linux")]
mod inventory;
#[cfg(target_os = "linux")]
mod launch;
#[cfg(target_os = "linux")]
mod record;
#[cfg(target_os = "linux")]
mod refresh;
#[cfg(target_os = "linux")]
mod review;
#[cfg(target_os = "linux")]
mod runtime;
pub(crate) mod transport;

pub const FORMAT: &str = "sw-installed-edit-session/1";
pub const QUOTA_PROFILE: &str = "sw-installed-edit-session/2";
pub const ENDPOINT: &str = "/native/edit-session/v1";
pub const SERVER: &str = "private-output";

#[derive(Args, Debug)]
pub struct Cli {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand, Debug)]
enum Action {
    /// List bounded retained run identities without executing tools or changing state.
    #[cfg(target_os = "linux")]
    Inventory(inventory::Args),
    /// Hand one rechecked inventory selection to an explicitly requested existing action.
    #[cfg(target_os = "linux")]
    WithRun(inventory::WithRun),
    /// Review exact completed-run outputs; private content needs explicit consent.
    #[cfg(target_os = "linux")]
    Review(review::Args),
    /// Diagnose one selected edit run without replaying calls or changing state.
    Status(diagnostic::Args),
    /// Inspect a proposed private output profile without writes or authority.
    Preview(Selection),
    /// Prepare an immutable operator-owned profile; defaults to preview.
    Prepare {
        #[command(flatten)]
        selected: Selection,
        #[arg(long)]
        apply: bool,
        /// New private plan directory, outside the output root.
        #[arg(long)]
        out: PathBuf,
    },
    /// Preview refreshed exact bindings; publication requires the displayed confirmation.
    Refresh {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        sha256: String,
        /// New private immutable plan directory; the original is preserved.
        #[arg(long)]
        out: PathBuf,
        #[arg(long, requires = "confirm")]
        apply: bool,
        /// Exact confirmation_sha256 from the read-only refresh preview.
        #[arg(long, requires = "apply")]
        confirm: Option<String>,
    },
    /// Run one explicitly prepared profile with the genuine pinned Claude host.
    Run {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        sha256: String,
        /// Existing private directory for per-run state, outside the output root.
        #[arg(long)]
        state: PathBuf,
        /// Bounded UTF-8 prompt; never printed in diagnostics or process arguments.
        #[arg(long)]
        prompt_file: PathBuf,
        #[arg(long, default_value_t = 180)]
        timeout_seconds: u64,
        #[arg(long, default_value = "claude-sonnet-4-20250514")]
        model: String,
    },
    /// Inspect or decide existing exact native Ask requests for this run.
    Ask {
        #[arg(long)]
        run: PathBuf,
        #[command(subcommand)]
        action: Ask,
    },
    /// Revoke and stop one exact installed run through its verified owner.
    Stop {
        #[arg(long)]
        run: PathBuf,
        #[arg(long, value_enum)]
        output: Option<crate::pilot_approval::OutputFormat>,
    },
    /// Private host forwarder; never launches an MCP child or grants authority.
    #[command(hide = true)]
    Relay {
        #[arg(long)]
        home: PathBuf,
        #[arg(long)]
        host_session: String,
        #[arg(long)]
        child_authority: String,
        #[arg(long)]
        profile_sha256: String,
    },
}
#[derive(Args, Debug)]
pub struct Selection {
    /// Existing Agent profile containing a verified pilot component.
    #[arg(long)]
    home: PathBuf,
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    claude: PathBuf,
    /// Exact direct-child names; no wildcards or missing-leaf fallback.
    #[arg(long = "read")]
    read: Vec<String>,
    #[arg(long = "create")]
    create: Vec<String>,
    #[arg(long = "replace")]
    replace: Vec<String>,
    /// Explicit operator assertion, not discovery of other same-UID writers.
    #[arg(long)]
    private_sole_writer: bool,
    /// Maximum admitted mutation attempts in one new run (also caps commits).
    #[arg(long, requires = "max_write_bytes")]
    max_mutations: Option<u64>,
    /// Cumulative full-payload reservations; never refunded within an active run.
    #[arg(long, requires = "max_mutations")]
    max_write_bytes: Option<u64>,
}
#[derive(Subcommand, Debug)]
pub enum Ask {
    List,
    Inspect {
        id: String,
    },
    Approve {
        id: String,
        #[arg(long)]
        binding: String,
    },
    Reject {
        id: String,
    },
}

pub fn run(cli: Cli) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        launch::command(cli.command)
    }
    #[cfg(not(target_os = "linux"))]
    {
        if let Action::Status(args) = cli.command {
            return status(args);
        }
        anyhow::bail!("installed_edit_requires_native_linux_x86_64")
    }
}

fn status(args: diagnostic::Args) -> Result<()> {
    let report = diagnostic::inspect(&args);
    if let Some(destination) = &args.support_bundle {
        anyhow::ensure!(
            !destination.starts_with(&args.run) && !args.run.starts_with(destination),
            "edit_status_export_overlaps_run"
        );
        let wrapper = crate::doctor::Report {
            schema: "sw-agent-doctor/1",
            observed_at_ms: crate::protection_status::now_ms(),
            setup: crate::doctor::Outcome::Unknown,
            active_host_call_protection: "unknown",
            scope: "selected_edit_session_read_only_diagnosis",
            checks: vec![],
            pilot: None,
        };
        crate::support_bundle::export_edit(&wrapper, Some(&report), destination)
            .map_err(|_| anyhow::anyhow!("edit_status_support_export_failed"))?;
    }
    if args.json {
        let bytes = serde_json::to_string_pretty(&report)?;
        anyhow::ensure!(bytes.len() <= 128 * 1024, "edit_status_report_cap");
        println!("{bytes}");
    } else {
        println!("{}", diagnostic::text(&report));
    }
    Ok(())
}

#[cfg(test)]
mod grammar_tests {
    use super::*;
    use clap::{CommandFactory, Parser};
    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        edit: Cli,
    }
    #[test]
    fn installed_inventory_types_follow_the_executor_platform_boundary() {
        Command::command().debug_assert();
        let command = Command::command();
        assert!(command.find_subcommand("status").is_some());
        for name in ["inventory", "with-run"] {
            assert_eq!(
                command.find_subcommand(name).is_some(),
                cfg!(target_os = "linux")
            );
        }
        assert!(Command::try_parse_from([
            "edit-session",
            "status",
            "--run",
            "/owned/run",
            "--json"
        ])
        .is_ok());
    }
}
