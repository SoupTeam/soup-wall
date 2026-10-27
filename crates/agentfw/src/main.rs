// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentfw::audit::AuditSink;
use agentfw::handlers::{AppState, Sessions};
use agentfw::sandbox::{
    GuardedFileDeleteSpec, GuardedFileRenameSpec, GuardedFileWriteSpec, GuardedNetworkFetchSpec,
    NetworkPolicy, SandboxSpec,
};
use agentfw::Config;
use anyhow::Context;
use clap::{Parser, Subcommand};
use soup_wall_agent::{AgentFirewall, AgentPolicySet, DEFAULT_TAINT_CAP};

#[derive(Parser)]
#[command(name = "agentfw", about = "Agent firewall daemon and tooling")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum NativeApprovalCmd {
    /// List outstanding requests (digests only, no raw arguments).
    List,
    /// Show one request in full, including the exact arguments.
    Inspect {
        #[arg(allow_hyphen_values = true)]
        id: String,
    },
    /// Approve exactly this call; --binding must be the digest shown by inspect.
    Approve {
        #[arg(allow_hyphen_values = true)]
        id: String,
        #[arg(long)]
        binding: String,
    },
    /// Reject this call.
    Reject {
        #[arg(allow_hyphen_values = true)]
        id: String,
    },
}

#[derive(Subcommand)]
enum ChildAuthorityCmd {
    /// Mint a signed grant for one host session and MCP server.
    Mint {
        #[arg(long)]
        session: String,
        #[arg(long)]
        server: String,
        #[arg(long, default_value_t = 300)]
        ttl_seconds: u64,
        #[arg(long, value_delimiter = ',')]
        tools: Vec<String>,
        #[arg(long)]
        agent_id: Option<String>,
        #[arg(long)]
        parent_id: Option<String>,
        #[arg(long, value_delimiter = ',')]
        resources: Option<Vec<String>>,
        /// Current /native/v1/instance identifier; required for scoped grants.
        #[arg(long, allow_hyphen_values = true)]
        instance_id: Option<String>,
        /// Exact live parent binding from /native/v1/instance.
        #[arg(long)]
        parent_binding: Option<String>,
    },
    /// Authenticate a grant and print its verified claims.
    Verify {
        #[arg(long)]
        session: String,
        #[arg(long)]
        server: String,
        #[arg(long)]
        token: String,
    },
}

#[derive(Subcommand)]
enum ClassifierPackageCmd {
    /// Build the deterministic package archive from a source checkout (writes one file).
    Build {
        /// `frozen` (SOU-14) or `rev2` (SOU-34).
        #[arg(long)]
        classifier: String,
        #[arg(long, default_value = ".")]
        source: std::path::PathBuf,
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Validate an archive and show what install would do; writes nothing.
    Preview {
        archive: std::path::PathBuf,
        #[arg(long)]
        python: std::path::PathBuf,
    },
    /// Install and select a package under ~/.agentfw/classifier (private, atomic).
    Install {
        archive: std::path::PathBuf,
        #[arg(long)]
        python: std::path::PathBuf,
    },
    /// Re-verify the selected package, its files, permissions and interpreter.
    Verify,
    /// Show selected, previous and installed packages.
    Inspect,
    /// Select the previous package (verified first).
    Rollback,
    /// Clear leftovers of an interrupted install.
    Recover,
    /// Remove one non-selected package, or everything with --all.
    Remove {
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify and resume an opt-in Linux audit segment store after a stopped writer.
    AuditRetentionRecover {
        /// Agent profile containing config.yaml.
        #[arg(long)]
        home: Option<PathBuf>,
    },
    /// Install and manage the verified rule-classifier package (SOU-64).
    ClassifierPackage {
        #[command(subcommand)]
        action: ClassifierPackageCmd,
    },
    /// Run the daemon.
    Serve,
    /// Diagnose an installed Agent without modifying host settings or starting tools.
    Doctor(agentfw::doctor::DoctorArgs),
    /// Query authenticated runtime diagnostics; unknown protection exits 2.
    ProtectionStatus(agentfw::protection_status::QueryArgs),
    /// Validate a bounded prepared-run diagnostic envelope on stdin; no network or state writes.
    PilotObservation,
    /// Summarize recorded verdicts, or explicitly simulate supplied offline events.
    Replay {
        /// Path to the audit log (defaults to ~/.agentfw/audit.jsonl).
        #[arg(long)]
        log: Option<PathBuf>,
        #[command(flatten)]
        offline: agentfw::offline_replay::OfflineArgs,
    },
    /// Print the settings.json hook block and setup instructions.
    Install,
    /// Manage a user-scoped Agent binary lifecycle.
    Lifecycle {
        #[command(subcommand)]
        command: LifecycleCommand,
    },
    /// Manage an opt-in Linux systemd or macOS launchd user service.
    Service {
        #[arg(long, global = true)]
        home: Option<PathBuf>,
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Check that the daemon is up, and report its enforcement posture.
    ///
    /// Exits non-zero when it is not. The Claude Code hook fails open, so a
    /// stopped daemon does not prevent tools: calls may proceed after a
    /// connection error or hook timeout. Run this before a session, or from a wrapper script.
    Preflight {
        /// Also fail when the daemon is running but still in shadow mode.
        #[arg(long)]
        require_enforce: bool,
        /// Seconds to wait for the health endpoint.
        #[arg(long, default_value_t = 2)]
        timeout_seconds: u64,
    },
    /// Approve one exact tool call that policy would otherwise only ask about.
    ///
    /// The approval is signed, expires, is single-use, and is bound to the exact
    /// arguments given here -- approving `rm -rf ./build` does not authorize
    /// `rm -rf /`.
    ///
    /// It withdraws this firewall's objection to one `ask`. It does not override
    /// your own Claude Code permission rules, and a policy `deny` stays denied.
    Approve {
        /// Session the call belongs to, as reported in the ask.
        #[arg(long)]
        session: String,
        /// Tool name, e.g. `Bash`.
        #[arg(long)]
        tool: String,
        /// The tool's exact arguments as JSON, matching the pending call.
        #[arg(long)]
        args: String,
        /// Minutes the approval stays usable.
        #[arg(long, default_value_t = 5)]
        ttl_minutes: u64,
    },
    /// Proxy an MCP server, pinning its tool manifest at handshake.
    Mcp {
        /// Stable identity for this server (keys its pin + audit). Defaults to a
        /// hash of the command.
        #[arg(long)]
        id: Option<String>,
        /// Admit supported stdio calls and text results using the installed native registry.
        /// This opt-in path fails closed; result release is to the MCP host, not model context.
        #[arg(long)]
        native_admission: bool,
        /// Parent host session to bind this collector and its provenance to.
        #[arg(long)]
        host_session: Option<String>,
        /// Exact private prepared-run budget binding; environment must agree.
        #[arg(long)]
        pilot_budget_binding: Option<PathBuf>,
        /// Frozen canonical identity of the prepared budget selection.
        #[arg(long, requires = "pilot_budget_binding")]
        pilot_budget_sha256: Option<String>,
        /// Authenticated child authority grant token minted for this session and server.
        #[arg(long)]
        child_authority: Option<String>,
        /// With --native-admission: hold one Ask call up to N seconds for a
        /// single-use operator approval (needs `native.approval` in the daemon
        /// config). 0 or absent keeps the default correlated refusal.
        #[arg(long, default_value_t = 0)]
        native_approval_wait_seconds: u64,
        /// Explicit installed daemon home directory containing native-token and config;
        /// defaults to ~/.agentfw or AGENTFW_HOME.
        #[arg(long)]
        home: Option<PathBuf>,
        /// The real server command and its args, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Forward MCP bytes to a daemon-selected verified original runtime (Linux).
    /// No upstream command, project profile or credentials are forwarded.
    McpVerified {
        #[arg(long)]
        id: String,
        #[arg(long)]
        host_session: Option<String>,
        #[arg(long)]
        child_authority: Option<String>,
        #[arg(long)]
        home: Option<PathBuf>,
    },
    /// Manage authenticated child authority grants.
    ChildAuthority {
        #[command(subcommand)]
        action: ChildAuthorityCmd,
    },
    /// Operator commands for pending native MCP Ask approvals (SOU-48).
    /// Approval is explicit single-use authorization, not proof of human presence.
    NativeApproval {
        #[command(subcommand)]
        action: NativeApprovalCmd,
    },
    /// Exercise an installed Agent end to end in an owned temporary workspace (Linux).
    ///
    /// Writes a versioned JSON report. Exit 0 passed, 3 failed, 4 incomplete, 5 unsupported.
    SelfTest(agentfw::self_test::Args),
    #[cfg(windows)]
    /// Preview a native Windows Agent setup against explicitly selected local assets.
    OnboardWindows {
        #[command(subcommand)]
        command: agentfw::windows_onboarding::Command,
    },
    /// First-use onboarding: read-only preview, explicit apply of the reviewed plan, and undo (Linux).
    ///
    /// Exit 0 verified/plan ready/undone, 6 configured but unverified, 3 failed, 4 incomplete or refused, 5 unsupported.
    #[command(subcommand)]
    Onboard(agentfw::onboarding::Command),
    /// Bundled harmless stdio MCP fixture server used by `self-test`.
    #[command(hide = true)]
    SelfTestFixture(agentfw::self_test::FixtureArgs),
    /// Inspect a selected Claude-style MCP JSON config without starting servers.
    /// Only server names and supported transport flags are printed.
    McpInspectConfig {
        #[arg(long)]
        path: PathBuf,
    },
    /// Review, compile, and manage transactional MCP admission profiles.
    McpProfile {
        /// Optional custom agentfw home directory (default: ~/.agentfw).
        #[arg(long)]
        home: Option<PathBuf>,
        #[command(subcommand)]
        command: agentfw::mcp::profile_author::Command,
    },
    /// Manage one explicitly selected Claude Code stdio MCP entry.
    McpConnection {
        #[command(subcommand)]
        command: agentfw::mcp::connection::Command,
    },
    /// Guided Linux pilot from the installed front door: preview,
    /// prepare, run, status or help. Starts only the verified installed
    /// component with its recorded interpreter.
    Pilot {
        /// Private Agent profile holding `pilot-front-door/` (default ~/.agentfw).
        #[arg(long)]
        home: Option<PathBuf>,
        /// The guided command and its options, e.g. `status --prefix DIR`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<std::ffi::OsString>,
    },
    /// Install, verify, update, roll back or remove the guided-pilot front-door component.
    PilotComponent {
        /// Private Agent profile holding `pilot-front-door/` (default ~/.agentfw).
        #[arg(long, global = true)]
        home: Option<PathBuf>,
        #[command(subcommand)]
        action: PilotComponentCmd,
    },
    /// Trusted per-run Claude Code pilot launcher for two pinned MCP servers (SOU-99).
    PilotLaunch(agentfw::pilot_launcher::PilotLaunchArgs),
    /// Read-only inspection using the accepted original-profile workspace validators.
    PilotWorkspaces(agentfw::pilot_launcher::PilotWorkspacesArgs),
    /// Inspect or probe an explicitly selected prepared-pilot Linux budget.
    PilotBudget(agentfw::pilot_budget::BudgetArgs),
    /// Inspect and decide one exact pending call owned by a live pilot run.
    PilotApproval(agentfw::pilot_approval::OperatorArgs),
    /// Run one high-risk command inside the Linux bubblewrap sandbox.
    Sandbox {
        /// Writable directory exposed as `/workspace`.
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// Kill the command after this many seconds.
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        /// Maximum bytes retained from each output stream.
        #[arg(long, default_value_t = 1024 * 1024)]
        max_output_bytes: usize,
        /// The command and args, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Inspect a Bash command and execute it only after an explicit allow
    /// inside the Linux bubblewrap sandbox.
    GuardedShell {
        /// Stable session identifier used by taint tracking and policy.
        #[arg(long, default_value = "guarded-cli")]
        session: String,
        /// Agent identifier used by the policy event.
        #[arg(long, default_value = "root")]
        agent: String,
        /// Monotonic event sequence supplied by the caller.
        #[arg(long, default_value_t = 1)]
        seq: u64,
        /// Writable directory exposed as `/workspace`.
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// Kill the command after this many seconds.
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        /// Maximum bytes retained from each output stream.
        #[arg(long, default_value_t = 1024 * 1024)]
        max_output_bytes: usize,
        /// The Bash command, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Inspect a typed file write and apply it only inside the workspace.
    GuardedWrite {
        /// Stable session identifier used by taint tracking and policy.
        #[arg(long, default_value = "guarded-cli")]
        session: String,
        /// Agent identifier used by the policy event.
        #[arg(long, default_value = "root")]
        agent: String,
        /// Monotonic event sequence supplied by the caller.
        #[arg(long, default_value_t = 1)]
        seq: u64,
        /// Writable workspace that contains the target file.
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// Relative (or workspace-contained absolute) target path.
        #[arg(long)]
        path: PathBuf,
        /// UTF-8 content to write. The value is never included in the result.
        #[arg(long)]
        content: String,
    },
    /// Inspect a typed file deletion and apply it only inside the workspace.
    GuardedDelete {
        #[arg(long, default_value = "guarded-cli")]
        session: String,
        #[arg(long, default_value = "root")]
        agent: String,
        #[arg(long, default_value_t = 1)]
        seq: u64,
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        #[arg(long)]
        path: PathBuf,
    },
    /// Inspect a typed file rename and apply it only inside the workspace.
    GuardedRename {
        #[arg(long, default_value = "guarded-cli")]
        session: String,
        #[arg(long, default_value = "root")]
        agent: String,
        #[arg(long, default_value_t = 1)]
        seq: u64,
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        to: PathBuf,
    },
    /// Inspect a typed WebFetch and retrieve it only through an egress proxy.
    GuardedFetch {
        #[arg(long, default_value = "guarded-cli")]
        session: String,
        #[arg(long, default_value = "root")]
        agent: String,
        #[arg(long, default_value_t = 1)]
        seq: u64,
        /// HTTPS URL to retrieve (HTTP is accepted only for loopback tests).
        #[arg(long)]
        url: String,
        /// Deployment-owned HTTPS egress proxy (loopback HTTP is test-only).
        #[arg(long)]
        proxy_url: String,
        /// Kill the request after this many seconds.
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        /// Maximum UTF-8 response bytes returned to the agent.
        #[arg(long, default_value_t = 1024 * 1024)]
        max_response_bytes: usize,
    },
}

#[derive(Subcommand)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum PilotComponentCmd {
    /// Validate an archive and the interpreter; writes nothing.
    Preview {
        archive: PathBuf,
        /// Expected SHA-256 of the archive file.
        #[arg(long)]
        sha256: String,
        /// Absolute path of the CPython that will run the helpers.
        #[arg(long)]
        python: PathBuf,
    },
    /// Install or update and select a component (private, atomic; the
    /// previous component stays selectable for rollback).
    Install {
        archive: PathBuf,
        #[arg(long)]
        sha256: String,
        #[arg(long)]
        python: PathBuf,
    },
    /// Re-verify the selected component, every file, mode and the interpreter.
    Verify,
    /// Show selected, previous and installed components.
    Inspect,
    /// Select the previous component (verified first).
    Rollback,
    /// Clear leftovers of an interrupted install; the selection is unchanged.
    Recover,
    /// Remove one unselected component, or all component state.
    Remove {
        #[arg(long)]
        component: Option<String>,
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum LifecycleCommand {
    Install {
        version: String,
        candidate: PathBuf,
        #[arg(long)]
        sha256: String,
    },
    Upgrade {
        version: String,
        candidate: PathBuf,
        #[arg(long)]
        sha256: String,
    },
    Rollback,
    Status,
    Recover,
    Start,
    Stop,
    Restart,
    Remove,
    #[command(hide = true)]
    ServeManaged {
        #[arg(long, allow_hyphen_values = true)]
        instance: String,
        #[arg(long)]
        home: PathBuf,
    },
}

#[derive(Subcommand)]
enum ServiceCommand {
    Preview,
    Install,
    Start,
    Stop,
    Restart,
    Inspect,
    Uninstall,
    #[command(hide = true)]
    Launch,
    #[command(hide = true)]
    Ready,
    #[command(hide = true)]
    Shutdown,
}

fn main() -> anyhow::Result<()> {
    // Internal owners must stay synchronous: parent-death ownership belongs to
    // their stable main thread, before any Tokio worker can be created.
    if let Some(status) = agentfw::mcp::linux_owner::early_dispatch() {
        std::process::exit(status);
    }
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::AuditRetentionRecover { home } => {
            let home = home.unwrap_or(Config::home_path()?);
            let cfg = Config::from_yaml(&std::fs::read_to_string(home.join("config.yaml"))?)?;
            let retention = cfg
                .audit_retention
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("audit_retention is not configured"))?;
            #[cfg(any(target_os = "linux", windows))]
            {
                agentfw::audit::recover_retention(retention)?;
                println!("Audit retention verified and ready");
                Ok(())
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                let _ = retention;
                anyhow::bail!("bounded audit retention is supported on Linux and Windows only")
            }
        }
        Cmd::Doctor(args) => std::process::exit(agentfw::doctor::run(args)),
        Cmd::ProtectionStatus(args) => {
            std::process::exit(agentfw::protection_status::run_cli(args))
        }
        Cmd::PilotObservation => std::process::exit(agentfw::pilot_observation::run()),
        Cmd::SelfTest(args) => std::process::exit(agentfw::self_test::run(args)),
        #[cfg(windows)]
        Cmd::OnboardWindows { command } => {
            prepare_lifecycle_process()?;
            agentfw::windows_onboarding::run(command)
        }
        Cmd::Onboard(command) => std::process::exit(agentfw::onboarding::run(command)),
        Cmd::SelfTestFixture(args) => agentfw::self_test::fixture::serve(args),
        Cmd::Serve => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let _direct_guard =
                agentfw::lifecycle::Manager::new(Config::home()?).direct_serve_guard()?;
            tracing_subscriber::fmt().json().init();
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(serve(Config::home()?, None))
        }
        Cmd::Replay { log, offline } => {
            if offline.offline {
                std::process::exit(agentfw::offline_replay::run_cli(&offline));
            }
            let home = Config::home()?;
            let path = log.unwrap_or_else(|| home.join("audit.jsonl"));
            let body = std::fs::read_to_string(&path)?;
            print!("{}", agentfw::replay::summarize(&body).render());
            Ok(())
        }
        Cmd::Install => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            agentfw::token::load_or_create(&home.join("token"))?;
            println!(
                "{}",
                agentfw::install::instructions_for_config(&cfg, &home.join("token"))
            );
            Ok(())
        }
        Cmd::Lifecycle { command } => {
            if let LifecycleCommand::ServeManaged { instance, home } = command {
                tracing_subscriber::fmt().json().init();
                let manager = agentfw::lifecycle::Manager::new(&home);
                manager.verify_managed_boot(&instance, &std::env::current_exe()?)?;
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                if agentfw::service::registered(&home) {
                    agentfw::service::Service::new(&home)?.verify_managed_process(&instance)?;
                }
                return tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?
                    .block_on(serve(home, Some(instance)));
            }
            #[cfg(windows)]
            prepare_lifecycle_process()?;
            let manager = agentfw::lifecycle::Manager::new(Config::home()?);
            match command {
                LifecycleCommand::Install {
                    version,
                    candidate,
                    sha256,
                } => {
                    let record = manager.install(&version, &candidate, &sha256)?;
                    println!("installed {} {}", record.version, record.digest);
                }
                LifecycleCommand::Upgrade {
                    version,
                    candidate,
                    sha256,
                } => {
                    let record = manager.upgrade(&version, &candidate, &sha256)?;
                    println!("upgraded to {} {}", record.version, record.digest);
                }
                LifecycleCommand::Rollback => {
                    let record = manager.rollback()?;
                    println!("rolled back to {} {}", record.version, record.digest);
                }
                LifecycleCommand::Status => {
                    println!("{}", serde_json::to_string_pretty(&manager.status()?)?);
                }
                LifecycleCommand::Recover => {
                    manager.recover()?;
                    println!("recovered lifecycle state");
                }
                LifecycleCommand::Start => {
                    manager.start()?;
                    println!("started owned Agent and confirmed health");
                }
                LifecycleCommand::Stop => {
                    manager.stop()?;
                    println!("stopped owned Agent");
                }
                LifecycleCommand::Restart => {
                    manager.restart()?;
                    println!("restarted owned Agent and confirmed health");
                }
                LifecycleCommand::Remove => {
                    manager.remove()?;
                    println!("removed owned Agent files");
                }
                LifecycleCommand::ServeManaged { .. } => unreachable!(),
            }
            Ok(())
        }
        Cmd::Service { home, command } => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                // Unlike Config::home(), preview must not create the default profile.
                let home = match home {
                    Some(home) => home,
                    None => std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?
                        .join(".agentfw"),
                };
                let service = agentfw::service::Service::new(&home)?;
                match command {
                    ServiceCommand::Preview => {
                        println!("{}", serde_json::to_string_pretty(&service.preview()?)?)
                    }
                    ServiceCommand::Install => {
                        service.install()?;
                        println!("installed user service; Agent remains stopped and login autostart is disabled");
                    }
                    ServiceCommand::Start => {
                        service.start()?;
                        println!("service started and Agent readiness verified");
                    }
                    ServiceCommand::Stop => {
                        service.stop()?;
                        println!("service stopped");
                    }
                    ServiceCommand::Restart => {
                        service.restart()?;
                        println!("service restarted and Agent readiness verified");
                    }
                    ServiceCommand::Inspect => {
                        println!("{}", serde_json::to_string_pretty(&service.inspect())?)
                    }
                    ServiceCommand::Launch => service.launch()?,
                    ServiceCommand::Ready => service.ready()?,
                    ServiceCommand::Shutdown => service.shutdown()?,
                    ServiceCommand::Uninstall => {
                        service.uninstall()?;
                        println!("removed owned service files; Agent versions and user data are preserved");
                    }
                }
                Ok(())
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                let _ = (home, command);
                anyhow::bail!("user service management requires Linux/systemd or macOS/launchd");
            }
        }
        Cmd::Preflight {
            require_enforce,
            timeout_seconds,
        } => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let probe = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(probe_health(&cfg, timeout_seconds));
            let report = agentfw::preflight::evaluate(&probe);
            println!("{}", report.render(require_enforce));
            std::process::exit(report.exit_code(require_enforce));
        }
        Cmd::Approve {
            session,
            tool,
            args,
            ttl_minutes,
        } => {
            let parsed: serde_json::Value = serde_json::from_str(&args)
                .map_err(|e| anyhow::anyhow!("--args must be JSON: {e}"))?;
            let home = Config::home()?;
            let token = agentfw::token::load_or_create(&home.join("token"))?;
            let action = agentfw::grant::ActionRef {
                session,
                tool: tool.clone(),
                args_fingerprint: agentfw::grant::action_fingerprint(&tool, &parsed),
            };
            let nonce = agentfw::token::generate();
            let store = agentfw::grant::GrantStore::new(&home.join("grants"));
            // Issue under the same cross-process epoch lock as live activation
            // and redemption; never mint an unversioned grant after a switch.
            let (_, path) = store.issue(
                &agentfw::grant::derive_key(&token),
                &action,
                now_ms(),
                ttl_minutes.saturating_mul(60_000),
                nonce,
            )?;
            println!(
                "Approved {tool} for {} minute(s). Single use, bound to these exact arguments.
                 Revoke before it is used by deleting:
  {}",
                ttl_minutes,
                path.display()
            );
            Ok(())
        }
        Cmd::ClassifierPackage { action } => {
            use agentfw::classifier_runtime::package as pkg;
            let value = match action {
                ClassifierPackageCmd::Build {
                    classifier,
                    source,
                    out,
                } => {
                    let bytes = pkg::build(pkg::Which::parse(&classifier)?, &source)?;
                    std::fs::write(&out, &bytes)?;
                    serde_json::json!({"action":"build","archive_sha256":pkg::sha(&bytes),
                        "package":pkg::parse(&bytes)?.id(),"out":out})
                }
                ClassifierPackageCmd::Preview { archive, python } => {
                    let store = pkg::Store::new(&Config::home()?);
                    store.preview(&pkg::read_archive_file(&archive)?, &python)?
                }
                ClassifierPackageCmd::Install { archive, python } => {
                    let store = pkg::Store::new(&Config::home()?);
                    store.install(&pkg::read_archive_file(&archive)?, &python)?
                }
                ClassifierPackageCmd::Verify => pkg::Store::new(&Config::home()?).verify()?,
                ClassifierPackageCmd::Inspect => pkg::Store::new(&Config::home()?).inspect()?,
                ClassifierPackageCmd::Rollback => pkg::Store::new(&Config::home()?).rollback()?,
                ClassifierPackageCmd::Recover => pkg::Store::new(&Config::home()?).recover()?,
                ClassifierPackageCmd::Remove { package, all } => {
                    pkg::Store::new(&Config::home()?).remove(package.as_deref(), all)?
                }
            };
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        Cmd::NativeApproval { action } => {
            let home = Config::home()?;
            match action {
                NativeApprovalCmd::List => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&agentfw::native::approval::operator_list(
                            &home
                        ))?
                    );
                }
                NativeApprovalCmd::Inspect { id } => {
                    let v = agentfw::native::approval::operator_inspect(&home, &id)?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                    println!(
                        "To approve exactly this call:\n  agentfw native-approval approve {id} --binding {}",
                        v["binding_sha256"].as_str().unwrap_or("")
                    );
                }
                NativeApprovalCmd::Approve { id, binding } => {
                    let token = agentfw::token::load_or_create(&home.join("token"))?;
                    agentfw::native::approval::operator_approve(&home, &token, &id, &binding)?;
                    println!("Approved {id}. Single use, bound to the exact original call digest.");
                }
                NativeApprovalCmd::Reject { id } => {
                    agentfw::native::approval::operator_reject(&home, &id)?;
                    println!("Rejected {id}.");
                }
            }
            Ok(())
        }
        Cmd::McpInspectConfig { path } => {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            let inventory = agentfw::mcp::input::inspect_host_config(&bytes)?;
            println!("{}", serde_json::to_string_pretty(&inventory)?);
            Ok(())
        }
        Cmd::McpConnection { command } => agentfw::mcp::connection::run(command),
        #[cfg(target_os = "linux")]
        Cmd::Pilot { home, args } => {
            let home = match home {
                Some(home) => home,
                None => agentfw::pilot_component::default_home()?,
            };
            std::process::exit(agentfw::pilot_component::exec_pilot(&home, &args));
        }
        #[cfg(target_os = "linux")]
        Cmd::PilotComponent { home, action } => {
            use agentfw::pilot_component as component;
            let home = match home {
                Some(home) => home,
                None => component::default_home()?,
            };
            let store = component::Store::new(&home);
            let value = match action {
                PilotComponentCmd::Preview {
                    archive,
                    sha256,
                    python,
                } => store.preview(&component::read_archive_file(&archive)?, &sha256, &python)?,
                PilotComponentCmd::Install {
                    archive,
                    sha256,
                    python,
                } => store.install(&component::read_archive_file(&archive)?, &sha256, &python)?,
                PilotComponentCmd::Verify => store.verify()?,
                PilotComponentCmd::Inspect => store.inspect()?,
                PilotComponentCmd::Rollback => store.rollback()?,
                PilotComponentCmd::Recover => store.recover()?,
                PilotComponentCmd::Remove { component, all } => {
                    store.remove(component.as_deref(), all)?
                }
            };
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        Cmd::Pilot { home, args } => {
            let _ = (home, args);
            anyhow::bail!("the installed guided pilot supports native Linux x86_64 only")
        }
        #[cfg(not(target_os = "linux"))]
        Cmd::PilotComponent { home, action } => {
            let _ = (home, action);
            anyhow::bail!("the installed guided pilot supports native Linux x86_64 only")
        }
        Cmd::PilotLaunch(args) => agentfw::pilot_launcher::run(args),
        Cmd::PilotWorkspaces(args) => agentfw::pilot_launcher::inspect_workspaces(args),
        Cmd::PilotApproval(args) if args.output.is_some() => {
            std::process::exit(agentfw::pilot_approval::operator_json(args));
        }
        Cmd::PilotBudget(args) => agentfw::pilot_budget::inspect(args),
        Cmd::PilotApproval(args) => agentfw::pilot_approval::operator(args),
        Cmd::McpProfile { home, command } => {
            let home = match home {
                Some(h) => h,
                None => match &command {
                    agentfw::mcp::profile_author::Command::Preview { .. }
                    | agentfw::mcp::profile_author::Command::Import { .. }
                    | agentfw::mcp::profile_author::Command::Validate { .. }
                    | agentfw::mcp::profile_author::Command::Explain { .. }
                    | agentfw::mcp::profile_author::Command::Diff { .. }
                    | agentfw::mcp::profile_author::Command::Compile { .. } => Config::home_path()?,
                    _ => Config::home()?,
                },
            };
            agentfw::mcp::profile_author::run(command, &home)
        }
        Cmd::ChildAuthority { action } => {
            use agentfw::native::child_authority;
            let home = Config::home()?;
            let path = home.join("native-token");
            let token = std::fs::read_to_string(&path).map_err(|_| {
                anyhow::anyhow!("child authority needs the existing daemon native token")
            })?;
            let token = token.trim();
            anyhow::ensure!(!token.is_empty(), "daemon native token is empty");
            let key = child_authority::derive_key(token);
            match action {
                ChildAuthorityCmd::Mint {
                    session,
                    server,
                    ttl_seconds,
                    tools,
                    agent_id,
                    parent_id,
                    resources,
                    instance_id,
                    parent_binding,
                } => {
                    let scoped = agent_id.is_some() || parent_id.is_some() || resources.is_some();
                    anyhow::ensure!(!scoped || instance_id.as_ref().is_some_and(|id| !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))),
                        "scoped child authority requires --instance-id from the running daemon's authenticated /native/v1/instance endpoint");
                    anyhow::ensure!(
                        agent_id.is_some() || (parent_id.is_none() && resources.is_none()),
                        "scoped parent/resource authority requires --agent-id"
                    );
                    anyhow::ensure!(
                        parent_id.is_some() == parent_binding.is_some(),
                        "--parent-id and --parent-binding are required together"
                    );
                    anyhow::ensure!(
                        parent_binding
                            .as_deref()
                            .is_none_or(agentfw::native::is_digest),
                        "invalid parent binding digest"
                    );
                    let nonce = if scoped {
                        let instance = instance_id.unwrap();
                        match parent_binding {
                            Some(binding) => {
                                format!("{instance}.{binding}.{}", agentfw::token::generate())
                            }
                            None => format!("{instance}.{}", agentfw::token::generate()),
                        }
                    } else {
                        agentfw::token::generate()
                    };
                    let grant = child_authority::mint_scoped(
                        &key,
                        &session,
                        &server,
                        &tools,
                        now_ms(),
                        ttl_seconds.saturating_mul(1000),
                        nonce,
                        agent_id,
                        parent_id,
                        resources,
                    );
                    println!("{}", child_authority::encode_token(&grant));
                }
                ChildAuthorityCmd::Verify {
                    session,
                    server,
                    token,
                } => {
                    let grant =
                        child_authority::verify_token(&key, &token, &session, &server, now_ms())
                            .map_err(|error| anyhow::anyhow!(error.reason()))?;
                    println!("{}", serde_json::to_string(&grant)?);
                }
            }
            Ok(())
        }
        Cmd::McpVerified {
            id,
            host_session,
            child_authority,
            home,
        } => {
            let host = host_session
                .or_else(|| std::env::var("AGENTFW_HOST_SESSION").ok())
                .filter(|value| !value.is_empty())
                .context("--host-session is required")?;
            let authority = child_authority
                .or_else(|| std::env::var("AGENTFW_CHILD_AUTHORITY").ok())
                .filter(|value| !value.is_empty())
                .context("--child-authority is required")?;
            let home = home
                .or_else(|| std::env::var_os("AGENTFW_HOME").map(PathBuf::from))
                .map(Ok)
                .unwrap_or_else(Config::home)?;
            let cfg = Config::from_yaml(&std::fs::read_to_string(home.join("config.yaml"))?)?;
            let selected = cfg
                .native
                .as_ref()
                .and_then(|native| native.execution.as_ref())
                .context("verified original execution is not installed")?;
            let path = home.join("native-token");
            anyhow::ensure!(path.is_file(), "existing native token required");
            let token = agentfw::token::load_or_create(&path)?;
            let preamble = agentfw::native::execution::transport::Preamble {
                contract: agentfw::native::execution::FORMAT.into(),
                catalogue_sha256: selected.catalogue_sha256.clone(),
                server_id: id,
                host_session: host,
                child_authority: authority,
            };
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let result = runtime.block_on(agentfw::native::execution::transport::run_client(
                cfg.endpoint_url(agentfw::native::execution::ENDPOINT),
                token,
                preamble,
            ));
            runtime.shutdown_timeout(Duration::from_millis(100));
            result
        }
        Cmd::Mcp {
            id,
            host_session,
            pilot_budget_binding,
            pilot_budget_sha256,
            child_authority,
            native_admission,
            native_approval_wait_seconds,
            home,
            command,
        } => {
            let host_session = host_session.or_else(|| std::env::var("AGENTFW_HOST_SESSION").ok());
            let child_authority =
                child_authority.or_else(|| std::env::var("AGENTFW_CHILD_AUTHORITY").ok());
            if !native_admission && (host_session.is_some() || child_authority.is_some()) {
                anyhow::bail!("--host-session and --child-authority require --native-admission");
            }
            if host_session.is_some() != child_authority.is_some() {
                anyhow::bail!(
                    "both --host-session and --child-authority must be provided together for authenticated binding"
                );
            }
            let prepared_budget = agentfw::pilot_budget::verify_launch(
                pilot_budget_binding.as_deref(),
                pilot_budget_sha256.as_deref(),
                host_session.as_deref(),
                id.as_deref().unwrap_or(""),
            )?;
            let (cmd, args) = command
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("no server command given after --"))?;
            let home = match home.or_else(|| std::env::var_os("AGENTFW_HOME").map(PathBuf::from)) {
                Some(h) => h,
                None => Config::home()?,
            };
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let server_id = id.unwrap_or_else(|| {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(command.join(" ").as_bytes());
                format!("srv-{:x}", h.finalize()).chars().take(12).collect()
            });
            if native_admission {
                let installed = cfg.native.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("MCP native admission needs an operator-installed registry")
                })?;
                let token_path = home.join("native-token");
                anyhow::ensure!(
                    token_path.is_file(),
                    "MCP native admission needs the existing daemon native token"
                );
                let token = agentfw::token::load_or_create(&token_path)?;
                let native = agentfw::native::NativeState::load(installed, token)?
                    .with_policy_barrier(&home)?;
                let manifest_token_path = home.join("token");
                anyhow::ensure!(
                    manifest_token_path.is_file(),
                    "MCP native admission needs the existing daemon manifest token"
                );
                let manifest_token = agentfw::token::load_or_create(&manifest_token_path)?;
                let liveness_env_enabled = std::env::var("AGENTFW_NATIVE_LIVENESS")
                    .map(|v| {
                        let v = v.trim().to_ascii_lowercase();
                        v != "0" && v != "false" && v != "no" && v != "off"
                    })
                    .unwrap_or(false);
                let env_lease_seconds = std::env::var("AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS")
                    .ok()
                    .and_then(|v| v.trim().parse::<u64>().ok());
                let liveness_opt_in = installed.liveness.is_some()
                    || liveness_env_enabled
                    || env_lease_seconds.is_some();
                let liveness_url = liveness_opt_in.then(|| cfg.endpoint_url("/native/liveness/v1"));
                let liveness_lease_seconds = env_lease_seconds
                    .or_else(|| installed.liveness.as_ref().map(|l| l.default_lease_seconds));
                let admission = agentfw::mcp::admission::AdmissionCfg {
                    host_session,
                    child_authority,
                    daemon_url: cfg.endpoint_url("/native/v1"),
                    manifest_url: cfg.endpoint_url("/mcp"),
                    manifest_token,
                    server_id,
                    native,
                    command: cmd.clone(),
                    args: args.to_vec(),
                    classifier: agentfw::mcp::admission::classifier_from_env()?,
                    resource_profiles: agentfw::mcp::admission::resource_profiles_from_env()?,
                    approval: (native_approval_wait_seconds > 0).then(|| {
                        agentfw::mcp::admission::ApprovalWait {
                            url: cfg.endpoint_url("/native/approval/v1"),
                            wait: Duration::from_secs(native_approval_wait_seconds.min(300)),
                        }
                    }),
                    liveness_url,
                    liveness_lease_seconds,
                };
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?;
                let result = runtime.block_on(agentfw::mcp::admission::run_with_budget(
                    admission,
                    prepared_budget,
                ));
                // Tokio's stdin uses a blocking thread. A closed admission path must
                // exit even when the MCP host keeps its stdin handle open.
                runtime.shutdown_timeout(Duration::from_millis(100));
                return result;
            }
            let token = agentfw::token::load_or_create(&home.join("token"))?;
            let proxy_cfg = agentfw::mcp::proxy::ProxyCfg {
                server_id,
                daemon_url: cfg.endpoint_url("/mcp"),
                token,
                command: cmd.clone(),
                args: args.to_vec(),
            };
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(agentfw::mcp::proxy::run(proxy_cfg))
        }
        Cmd::Sandbox {
            workspace,
            timeout_seconds,
            max_output_bytes,
            command,
        } => {
            let (program, args) = command
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("no command given after --"))?;
            let spec = SandboxSpec {
                program: program.clone(),
                args: args.to_vec(),
                workspace,
                network: NetworkPolicy::Deny,
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let result = agentfw::sandbox::run(spec).await?;
                    println!("{}", serde_json::to_string(&result)?);
                    if result.timed_out || result.status != Some(0) {
                        anyhow::bail!("sandboxed command failed or timed out");
                    }
                    Ok(())
                })
        }
        Cmd::GuardedShell {
            session,
            agent,
            seq,
            workspace,
            timeout_seconds,
            max_output_bytes,
            command,
        } => {
            let command = command.join(" ");
            if command.is_empty() {
                anyhow::bail!("no command given after --");
            }
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let mut firewall = match &cfg.policy {
                Some(path) => AgentFirewall::new(
                    AgentPolicySet::from_yaml(&std::fs::read_to_string(path)?)?,
                    DEFAULT_TAINT_CAP,
                ),
                None => AgentFirewall::with_default_policy(),
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let result = agentfw::sandbox::run_guarded_shell(
                        &mut firewall,
                        agentfw::sandbox::GuardedShellSpec {
                            session,
                            agent,
                            seq,
                            command,
                            workspace,
                            network: agentfw::sandbox::NetworkPolicy::Deny,
                            timeout: Duration::from_secs(timeout_seconds),
                            max_output_bytes,
                        },
                    )
                    .await?;
                    println!("{}", serde_json::to_string(&result)?);
                    if result.execution.timed_out || result.execution.status != Some(0) {
                        anyhow::bail!("guarded sandbox command failed or timed out");
                    }
                    Ok(())
                })
        }
        Cmd::GuardedWrite {
            session,
            agent,
            seq,
            workspace,
            path,
            content,
        } => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let mut firewall = match &cfg.policy {
                Some(path) => AgentFirewall::new(
                    AgentPolicySet::from_yaml(&std::fs::read_to_string(path)?)?,
                    DEFAULT_TAINT_CAP,
                ),
                None => AgentFirewall::with_default_policy(),
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let result = agentfw::sandbox::run_guarded_file_write(
                        &mut firewall,
                        GuardedFileWriteSpec {
                            session,
                            agent,
                            seq,
                            path,
                            content,
                            workspace,
                        },
                    )
                    .await?;
                    println!("{}", serde_json::to_string(&result)?);
                    Ok(())
                })
        }
        Cmd::GuardedDelete {
            session,
            agent,
            seq,
            workspace,
            path,
        } => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let mut firewall = match &cfg.policy {
                Some(path) => AgentFirewall::new(
                    AgentPolicySet::from_yaml(&std::fs::read_to_string(path)?)?,
                    DEFAULT_TAINT_CAP,
                ),
                None => AgentFirewall::with_default_policy(),
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let result = agentfw::sandbox::run_guarded_file_delete(
                        &mut firewall,
                        GuardedFileDeleteSpec {
                            session,
                            agent,
                            seq,
                            path,
                            workspace,
                        },
                    )
                    .await?;
                    println!("{}", serde_json::to_string(&result)?);
                    Ok(())
                })
        }
        Cmd::GuardedRename {
            session,
            agent,
            seq,
            workspace,
            from,
            to,
        } => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let mut firewall = match &cfg.policy {
                Some(path) => AgentFirewall::new(
                    AgentPolicySet::from_yaml(&std::fs::read_to_string(path)?)?,
                    DEFAULT_TAINT_CAP,
                ),
                None => AgentFirewall::with_default_policy(),
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let result = agentfw::sandbox::run_guarded_file_rename(
                        &mut firewall,
                        GuardedFileRenameSpec {
                            session,
                            agent,
                            seq,
                            from,
                            to,
                            workspace,
                        },
                    )
                    .await?;
                    println!("{}", serde_json::to_string(&result)?);
                    Ok(())
                })
        }
        Cmd::GuardedFetch {
            session,
            agent,
            seq,
            url,
            proxy_url,
            timeout_seconds,
            max_response_bytes,
        } => {
            let home = Config::home()?;
            let cfg = match std::fs::read_to_string(home.join("config.yaml")) {
                Ok(s) => Config::from_yaml(&s)?,
                Err(_) => Config::default(),
            };
            let mut firewall = match &cfg.policy {
                Some(path) => AgentFirewall::new(
                    AgentPolicySet::from_yaml(&std::fs::read_to_string(path)?)?,
                    DEFAULT_TAINT_CAP,
                ),
                None => AgentFirewall::with_default_policy(),
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let result = agentfw::sandbox::run_guarded_network_fetch(
                        &mut firewall,
                        GuardedNetworkFetchSpec {
                            session,
                            agent,
                            seq,
                            url,
                            proxy_url,
                            timeout: Duration::from_secs(timeout_seconds),
                            max_response_bytes,
                        },
                    )
                    .await?;
                    println!("{}", serde_json::to_string(&result)?);
                    Ok(())
                })
        }
    }
}

#[cfg(windows)]
fn prepare_lifecycle_process() -> anyhow::Result<()> {
    use anyhow::Context;
    use windows_sys::Win32::Foundation::{
        SetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::{
        GetErrorMode, SetErrorMode, SEM_FAILCRITICALERRORS,
    };

    // SAFETY: This single-threaded CLI owns its process error mode. Preserve
    // existing flags and return loader errors instead of waiting for a system
    // dialog when an upgrade candidate is not a valid Windows executable.
    unsafe { SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS) };

    // Do this in the single-threaded lifecycle CLI before starting any runtime
    // or child. Windows Command::spawn inherits additional inheritable handles
    // even when all three child streams are redirected. A managed daemon must
    // not keep the caller's pipes alive after this CLI exits. Keep these handles
    // open for our own I/O; only the inheritance flag changes, until CLI exit.
    for stream in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle borrows this process's standard handle. It is not
        // closed or replaced here, and the CLI has not started worker threads.
        let handle = unsafe { GetStdHandle(stream) };
        if handle.is_null() {
            continue;
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error()).context("read lifecycle standard handle");
        }
        // SAFETY: The valid borrowed handle stays open. The mask changes only
        // HANDLE_FLAG_INHERIT, preserving all other flags and access rights.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("prevent managed Agent from inheriting lifecycle CLI streams");
        }
    }
    Ok(())
}

/// Probe the daemon's unauthenticated loopback health endpoint. Every failure mode
/// collapses to  with the transport detail, which is what the
/// operator needs: the distinction between refused, reset and timed out does not
/// change the action (start the daemon).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

async fn probe_health(config: &Config, timeout_seconds: u64) -> agentfw::preflight::Probe {
    let url = config.endpoint_url("/health");
    let client = match reqwest::Client::builder()
        // Local daemon probes must not leave the host through a system proxy.
        .no_proxy()
        .timeout(Duration::from_secs(timeout_seconds.max(1)))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            return agentfw::preflight::Probe::Unreachable {
                detail: e.to_string(),
            }
        }
    };
    match client.get(&url).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            agentfw::preflight::Probe::Answered { status, body }
        }
        Err(e) => agentfw::preflight::Probe::Unreachable {
            detail: e.to_string(),
        },
    }
}

fn load_serve_config(home: &std::path::Path) -> anyhow::Result<Config> {
    let path = home.join("config.yaml");
    match std::fs::read_to_string(&path) {
        Ok(s) => Config::from_yaml(&s).with_context(|| {
            format!(
                "cannot parse daemon configuration {}; restore valid config.yaml before restarting",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "cannot read daemon configuration {}; restore config.yaml access before restarting",
                path.display()
            )
        }),
    }
}

async fn serve(home: PathBuf, managed: Option<String>) -> anyhow::Result<()> {
    let cfg = load_serve_config(&home)?;

    let mut firewall = match &cfg.policy {
        Some(p) => AgentFirewall::with_taint_limits(
            AgentPolicySet::from_yaml(&std::fs::read_to_string(p)?)?,
            DEFAULT_TAINT_CAP,
            cfg.provenance.clone(),
        )?,
        None => AgentFirewall::with_default_policy_and_taint_limits(cfg.provenance.clone())?,
    };

    let token = agentfw::token::load_or_create(&home.join("token"))?;
    let audit_path = cfg
        .audit
        .clone()
        .unwrap_or_else(|| home.join("audit.jsonl"));
    let state: agentfw::Shared = Arc::new(AppState {
        native: cfg
            .native
            .as_ref()
            .map(|native| {
                let native_token = agentfw::token::load_or_create(&home.join("native-token"))?;
                let state = agentfw::native::NativeState::load(native, native_token)?
                    .with_execution(native)?
                    .with_policy_barrier(&home)?
                    .with_continuity(&home, &mut firewall)?;
                match &native.approval {
                    Some(approval) => {
                        let hook_token = agentfw::token::load_or_create(&home.join("token"))?;
                        state.with_approval(
                            &home,
                            &agentfw::grant::derive_key(&hook_token),
                            approval.ttl_seconds,
                        )
                    }
                    None => Ok(state),
                }
            })
            .transpose()?,
        firewall: Mutex::new(firewall),
        sessions: Sessions::default(),
        audit: match &cfg.audit_retention {
            Some(retention) => AuditSink::open_retained(retention)?,
            None => AuditSink::open(&audit_path)?,
        },
        spans: agentfw::spans::SpanCache::new(64, cfg.judge.max_span_bytes),
        judge: agentfw::judge::Judge::new(cfg.judge.clone()),
        manifests: agentfw::mcp::store::ManifestStore::new(&home.join("manifests")),
        tools: agentfw::mcp::store::ToolRegistry::with_builtins(),
        grants: agentfw::grant::GrantStore::new(&home.join("grants")),
        grant_ledger: agentfw::grant::GrantLedger::open(&home.join("grants-spent.json")),
        grant_key: agentfw::grant::derive_key(&token),
        config: cfg.clone(),
        token,
    });

    // Managed enrollment is opt-in and pinned to an operator-approved local
    // Console origin and public key. A corrupt persisted signed policy stops
    // startup rather than silently reverting to a permissive default.
    if let Some(managed) = agentfw::managed_sync::ManagedSync::from_environment(&home)? {
        managed.restore(&state)?;
        tokio::spawn(managed.run(state.clone()));
    }

    let (maint_tx, maint_rx) = tokio::sync::watch::channel(false);
    let maint_tx = Arc::new(maint_tx);
    if state.native.is_some() {
        tokio::spawn(agentfw::native::liveness::run_maintenance_loop(
            state.clone(),
            maint_rx,
        ));
    }

    let diagnostics =
        agentfw::protection_status::Runtime::new(&cfg).with_binary(if managed.is_none() {
            std::env::current_exe()
                .ok()
                .and_then(|p| agentfw::lifecycle::sha256_file(&p).ok())
        } else {
            None
        });
    let addr = cfg.socket_address();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(
        addr = %addr,
        enforce = cfg.enforce,
        "agentfw listening ({})",
        if cfg.enforce { "ENFORCING" } else { "shadow mode" }
    );
    if let Some(instance) = managed {
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::get;
        use axum::Json;
        let health = agentfw::lifecycle::ManagedHealth {
            pid: std::process::id(),
            instance,
            binary_digest: agentfw::lifecycle::sha256_file(&std::env::current_exe()?)?,
            config_digest: match std::fs::read(home.join("config.yaml")) {
                Ok(bytes) => {
                    use sha2::{Digest, Sha256};
                    format!("{:x}", Sha256::digest(&bytes))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    use sha2::{Digest, Sha256};
                    format!("{:x}", Sha256::digest(b""))
                }
                Err(error) => return Err(error.into()),
            },
        };
        let diagnostics = diagnostics
            .with_binary(Some(health.binary_digest.clone()))
            .with_lifecycle(health.clone());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown = Arc::new(Mutex::new(Some(shutdown_tx)));
        let read_health = health.clone();
        let read_token = state.token.clone();
        let stop_health = health;
        let stop_token = state.token.clone();
        let router = agentfw::app_with_diagnostics(state, Arc::new(diagnostics)).route(
            "/lifecycle/v1",
            get(move |headers: HeaderMap| {
                let health = read_health.clone();
                let token = read_token.clone();
                async move {
                    let authorized = headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|value| agentfw::token::verify(&token, value));
                    let matches_instance = headers
                        .get("x-agentfw-instance")
                        .and_then(|value| value.to_str().ok())
                        == Some(health.instance.as_str());
                    if authorized && matches_instance {
                        Ok(Json(health))
                    } else {
                        Err(StatusCode::UNAUTHORIZED)
                    }
                }
            })
            .post(move |headers: HeaderMap| {
                let health = stop_health.clone();
                let token = stop_token.clone();
                let shutdown = shutdown.clone();
                let maint_tx = maint_tx.clone();
                async move {
                    let authorized = headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|value| agentfw::token::verify(&token, value));
                    let matches_instance = headers
                        .get("x-agentfw-instance")
                        .and_then(|value| value.to_str().ok())
                        == Some(health.instance.as_str());
                    if !authorized || !matches_instance {
                        return StatusCode::UNAUTHORIZED;
                    }
                    if let Some(sender) = shutdown.lock().unwrap().take() {
                        let _ = sender.send(());
                    }
                    let _ = maint_tx.send(true);
                    StatusCode::OK
                }
            }),
        );
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await?;
    } else {
        axum::serve(
            listener,
            agentfw::app_with_diagnostics(state, Arc::new(diagnostics)),
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn serve_config_defaults_only_when_missing() {
        let home = tempfile::tempdir().unwrap();
        let config = load_serve_config(home.path()).unwrap();
        assert_eq!(
            serde_json::to_value(config).unwrap(),
            serde_json::to_value(Config::default()).unwrap()
        );
        assert!(!home.path().join("config.yaml").exists());
    }

    #[test]
    fn serve_config_preserves_valid_operator_settings() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join("config.yaml"),
            "enforce: true\nport: 18787\n",
        )
        .unwrap();
        let config = load_serve_config(home.path()).unwrap();
        assert!(config.enforce);
        assert_eq!(config.port, 18787);
    }

    #[test]
    fn serve_config_rejects_malformed_yaml() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("config.yaml"), "enforce: [").unwrap();
        let error = load_serve_config(home.path()).unwrap_err();
        assert!(error.to_string().contains("restore valid config.yaml"));
    }

    #[test]
    fn serve_config_rejects_directory_instead_of_defaults() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("config.yaml")).unwrap();
        let error = load_serve_config(home.path()).unwrap_err();
        assert!(error.to_string().contains("restore config.yaml access"));
        let error = error.downcast_ref::<std::io::Error>().unwrap();
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(home.path().join("config.yaml").is_dir());
    }

    #[test]
    fn serve_config_rejects_invalid_utf8_instead_of_defaults() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("config.yaml"), [0xff, 0xfe]).unwrap();
        let error = load_serve_config(home.path()).unwrap_err();
        assert!(error.to_string().contains("restore config.yaml access"));
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn managed_instance_preserves_leading_hyphens() {
        for prefix in ["-", "--"] {
            let expected = format!("{prefix}{}", "a".repeat(43 - prefix.len()));
            let cli = Cli::try_parse_from([
                "agentfw",
                "lifecycle",
                "serve-managed",
                "--instance",
                &expected,
                "--home",
                "owned-profile",
            ])
            .expect("URL-safe instance IDs can begin with hyphens");
            match cli.cmd {
                Cmd::Lifecycle {
                    command: LifecycleCommand::ServeManaged { instance, home },
                } => {
                    assert_eq!(instance, expected);
                    assert_eq!(home, PathBuf::from("owned-profile"));
                }
                _ => panic!("expected the managed lifecycle command"),
            }
        }
    }
}
