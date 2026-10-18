// SPDX-License-Identifier: Apache-2.0
//! Explicit owned-connection profile transitions. Other platforms fail closed.
use super::connection::Options;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct Target {
    #[command(flatten)]
    pub connection: Options,
    #[arg(long)]
    pub source_profile: PathBuf,
    #[arg(long)]
    pub profile: PathBuf,
    /// Authenticated Claude host session whose provenance survives the transition.
    #[arg(long)]
    pub host_session: String,
    /// Reviewed rule-baseline source, required for privileged resource executors.
    #[arg(long)]
    pub classifier_script: Option<PathBuf>,
    /// Preview a still-valid previous snapshot rather than a forward upgrade.
    #[arg(long)]
    pub rollback: bool,
}

#[derive(clap::Subcommand)]
pub enum Command {
    Preview(Target),
    Apply {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        approval: String,
    },
    Status(Options),
    Recover(Options),
    /// Trusted launcher emitted only by the owned publication transaction.
    #[command(hide = true)]
    Collector {
        #[command(flatten)]
        connection: Options,
        #[arg(long)]
        generation: u64,
    },
}

pub fn run(command: Command) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let report = runtime.block_on(super::connection::linux::profile_upgrade::run(command))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = command;
        anyhow::bail!(
            "owned MCP profile transitions require Linux; macOS and Windows are unsupported"
        );
    }
}
