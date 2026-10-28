// SPDX-License-Identifier: Apache-2.0
//! Explicit installed private-output edit sessions. No default pilot authority
//! is changed and no filesystem executor is implemented here.
use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

mod profile;
pub(crate) use profile::Profile;
#[cfg(target_os = "linux")]
mod launch;
#[cfg(target_os = "linux")]
mod runtime;
pub(crate) mod transport;

pub const FORMAT: &str = "sw-installed-edit-session/1";
pub const ENDPOINT: &str = "/native/edit-session/v1";
pub const SERVER: &str = "private-output";

#[derive(Args, Debug)]
pub struct Cli {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand, Debug)]
enum Action {
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
    /// Preview, archive or explicitly clean one completed installed edit run.
    Archive {
        /// Agent profile containing the verified installed helper component.
        #[arg(long)]
        home: PathBuf,
        #[command(subcommand)]
        action: Archive,
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

#[derive(Subcommand, Debug)]
enum Archive {
    /// Read-only exact inventory and confirmation digest; source stays intact.
    Preview {
        #[arg(long)]
        run: PathBuf,
        /// Existing private archive directory outside the selected run.
        #[arg(long)]
        destination: PathBuf,
    },
    /// Publish a sanitized archive; retain all original run state.
    Apply(ArchivePlan),
    /// Remove only inventoried run state after verifying the sanitized archive.
    Cleanup {
        #[command(flatten)]
        selected: ArchivePlan,
        /// Acknowledge irreversible loss of raw evidence excluded from the archive.
        #[arg(long)]
        acknowledge_evidence_loss: bool,
    },
    /// Read-only inspection of an interrupted cleanup; never resumes deletion.
    Recover {
        #[command(flatten)]
        selected: ArchivePlan,
        #[arg(long)]
        journal: String,
    },
}

#[derive(Args, Debug)]
struct ArchivePlan {
    #[arg(long)]
    plan: PathBuf,
    #[arg(long)]
    confirm: String,
}

pub fn run(cli: Cli) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        launch::command(cli.command)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cli;
        anyhow::bail!("installed_edit_requires_native_linux_x86_64")
    }
}
