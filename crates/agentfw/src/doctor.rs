// SPDX-License-Identifier: Apache-2.0
//! Read-only installed-Agent troubleshooting. Setup readiness is not host-call coverage.

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::lifecycle::{Manager, Status as LifecycleStatus};
use crate::protection_status::{self, Expectations, Mode};
use crate::Config;

#[derive(Args, Debug, Clone)]
pub struct DoctorArgs {
    /// Explicit installed profile; defaults to ~/.agentfw, without creating it.
    #[arg(long)]
    pub home: Option<PathBuf>,
    /// Explicit installed Agent executable, never discovered through PATH.
    #[arg(long)]
    pub agent: Option<PathBuf>,
    /// Explicit Claude-style MCP host settings file (read-only inspection).
    #[arg(long, requires = "server")]
    pub host_config: Option<PathBuf>,
    /// Selected MCP server, never any other entries.
    #[arg(long, requires = "host_config")]
    pub server: Option<String>,
    /// Optional selected rule classifier source, checked against a reviewed digest.
    #[arg(long, requires = "classifier_sha256")]
    pub classifier_script: Option<PathBuf>,
    #[arg(long, requires = "classifier_script")]
    pub classifier_sha256: Option<String>,
    /// Versioned machine-readable JSON instead of short operator explanations.
    #[arg(long)]
    pub json: bool,
    /// Explicit, new private directory for sanitized report + hash manifest.
    #[arg(long)]
    pub support_bundle: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ready,
    Failed,
    Unknown,
    Unsupported,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub source: &'static str,
    pub observed_at_ms: u64,
    pub outcome: Outcome,
    pub reason_code: &'static str,
    pub explanation: &'static str,
    pub next_step: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub observed_at_ms: u64,
    pub setup: Outcome,
    pub active_host_call_protection: &'static str,
    pub scope: &'static str,
    pub checks: Vec<Check>,
}

fn check(
    id: &'static str,
    source: &'static str,
    outcome: Outcome,
    reason_code: &'static str,
    explanation: &'static str,
    next_step: &'static str,
) -> Check {
    Check {
        id,
        source,
        observed_at_ms: protection_status::now_ms(),
        outcome,
        reason_code,
        explanation,
        next_step,
        sha256: None,
    }
}

fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Open only a bounded private regular file. Never traverse a symlink parent or
/// follow a leaf symlink. Nothing here creates, chmods or repairs user files.
#[cfg(unix)]
pub(crate) fn read_private(path: &Path, max: u64) -> anyhow::Result<Vec<u8>> {
    use std::ffi::CString;
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    anyhow::ensure!(path.is_absolute(), "absolute path required");
    let root = File::open("/")?;
    let mut dir = root;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing parent"))?;
    for part in parent.components() {
        match part {
            Component::RootDir => (),
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                anyhow::ensure!(fd >= 0, "unsafe input directory");
                dir = unsafe { File::from_raw_fd(fd) };
            }
            _ => anyhow::bail!("path alias not accepted"),
        }
    }
    let leaf = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("missing filename"))?;
    let leaf = CString::new(leaf.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    anyhow::ensure!(fd >= 0, "unsafe input file");
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    anyhow::ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0
            && meta.len() <= max,
        "input must be an owner-private bounded regular file"
    );
    let mut data = Vec::new();
    file.take(max + 1).read_to_end(&mut data)?;
    anyhow::ensure!(data.len() as u64 <= max, "input too large");
    Ok(data)
}

#[cfg(not(unix))]
pub(crate) fn read_private(_path: &Path, _max: u64) -> anyhow::Result<Vec<u8>> {
    anyhow::bail!("private file inspection unsupported on this platform")
}

fn hash_selected_file(path: &Path, limit: u64) -> anyhow::Result<String> {
    use std::io::Read;
    anyhow::ensure!(path.is_absolute(), "absolute path required");
    let meta = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        meta.file_type().is_file() && meta.len() <= limit,
        "invalid asset"
    );
    // This additionally refuses a symlink swap at open time on Unix.
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = opts.open(path)?;
    let opened = file.metadata()?;
    anyhow::ensure!(opened.is_file() && opened.len() <= limit, "invalid asset");
    let mut hash = Sha256::new();
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let size = file.read(&mut buf)?;
        if size == 0 {
            break;
        }
        total += size as u64;
        anyhow::ensure!(total <= limit, "asset too large");
        hash.update(&buf[..size]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn lifecycle_check(status: &LifecycleStatus) -> Check {
    if status.interrupted {
        check(
            "installation",
            "read_only_lifecycle_manifest",
            Outcome::Failed,
            "lifecycle_interrupted",
            "An installed-version transaction was interrupted.",
            "Review agentfw lifecycle status; only an operator may run lifecycle recover.",
        )
    } else if status.active.is_none() {
        check("installation", "read_only_lifecycle_manifest", Outcome::Failed,
              "agent_not_installed", "No managed Agent version is selected.",
              "Use agentfw lifecycle status; install a reviewed Agent through the existing onboarding workflow.")
    } else if status.detail == "installed binary has changed" {
        check("installation", "read_only_lifecycle_manifest", Outcome::Failed,
              "installed_binary_mismatch", "Selected managed binary does not match its pin.",
              "Review agentfw lifecycle status and the installed binary; do not start an unverified version.")
    } else if status.detail == "running with changed config; restart to apply it" {
        check("installation", "read_only_lifecycle_manifest", Outcome::Failed,
              "host_config_drift", "Disk configuration differs from recorded startup intent.",
              "Review agentfw lifecycle status; an operator must decide whether a controlled restart is appropriate.")
    } else {
        check(
            "installation",
            "read_only_lifecycle_manifest",
            Outcome::Ready,
            "managed_selection_present",
            "Managed installation selection was read without modification.",
            "Compare with authenticated runtime identity; selection alone is not protection.",
        )
    }
}

fn setup(checks: &[&Check]) -> Outcome {
    if checks.iter().any(|c| c.outcome == Outcome::Failed) {
        Outcome::Failed
    } else if checks.iter().any(|c| c.outcome == Outcome::Unsupported) {
        Outcome::Unsupported
    } else if checks.iter().any(|c| c.outcome == Outcome::Unknown) {
        Outcome::Unknown
    } else {
        Outcome::Ready
    }
}

async fn diagnose(args: &DoctorArgs) -> Report {
    let mut checks = Vec::new();
    let mut report = Report {
        schema: "sw-agent-doctor/1",
        observed_at_ms: protection_status::now_ms(),
        setup: Outcome::Unknown,
        active_host_call_protection: "unknown",
        scope: "local_setup_and_authenticated_runtime_not_active_host_execution",
        checks: Vec::new(),
    };
    if !cfg!(target_os = "linux") {
        checks.push(check(
            "platform",
            "compile_target",
            Outcome::Unsupported,
            "platform_unsupported",
            "This doctor currently supports installed Linux Agents only.",
            "Run on the owned Linux installation; do not infer coverage on another platform.",
        ));
        report.setup = Outcome::Unsupported;
        report.checks = checks;
        return report;
    }

    let home = match args.home.clone().map(Ok).unwrap_or_else(Config::home_path) {
        Ok(p) if p.is_absolute() => p,
        _ => {
            checks.push(check(
                "profile",
                "selected_home",
                Outcome::Failed,
                "invalid_profile_home",
                "An absolute installed profile is required.",
                "Pass --home /absolute/path/to/.agentfw.",
            ));
            report.setup = Outcome::Failed;
            report.checks = checks;
            return report;
        }
    };
    let config_bytes = read_private(&home.join("config.yaml"), 1024 * 1024);
    let config = match config_bytes {
        Ok(bytes) => match std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| Config::from_yaml(s).ok())
        {
            Some(cfg) => {
                checks.push(check(
                    "configuration",
                    "private_config_yaml",
                    Outcome::Ready,
                    "config_valid",
                    "Local Agent configuration passed the production validator.",
                    "Compare its digest and registry pin with the authenticated daemon.",
                ));
                Some(cfg)
            }
            None => {
                checks.push(check("configuration", "private_config_yaml", Outcome::Failed,
                    "config_invalid", "Selected configuration is not valid.",
                    "Review config.yaml privately; run agentfw protection-status after correcting it."));
                None
            }
        },
        Err(_) => {
            checks.push(check(
                "configuration",
                "private_config_yaml",
                Outcome::Failed,
                "config_missing_or_unsafe",
                "Config is absent, public, linked or unreadable.",
                "Select a private installed .agentfw directory and owner-only config.yaml.",
            ));
            None
        }
    };

    let intent = Manager::new(&home).inspect_read_only();
    let intent = match intent {
        Ok(value) => {
            checks.push(lifecycle_check(&value));
            Some(value)
        }
        Err(_) => {
            checks.push(check("installation", "read_only_lifecycle_manifest", Outcome::Failed,
                "lifecycle_unverifiable", "Managed selection is unreadable or fails validation.",
                "Review agentfw lifecycle status in the selected profile; never adopt an unknown process."));
            None
        }
    };

    let binary = if let Some(agent) = &args.agent {
        match hash_selected_file(agent, 512 * 1024 * 1024) {
            Ok(sha) => {
                let matches = intent
                    .as_ref()
                    .and_then(|i| i.active.as_ref())
                    .is_none_or(|a| a.digest == sha);
                checks.push(check(
                    "binary",
                    "selected_binary_bytes",
                    if matches {
                        Outcome::Ready
                    } else {
                        Outcome::Failed
                    },
                    if matches {
                        "binary_verified"
                    } else {
                        "binary_pin_mismatch"
                    },
                    if matches {
                        "Selected executable was hashed."
                    } else {
                        "Executable differs from managed selection."
                    },
                    "Compare the selected binary SHA-256 against agentfw lifecycle status.",
                ));
                Some(sha)
            }
            Err(_) => {
                checks.push(check(
                    "binary",
                    "selected_binary_bytes",
                    Outcome::Failed,
                    "binary_missing_or_unverifiable",
                    "Selected executable could not be securely hashed.",
                    "Pass --agent /absolute/path/to/installed/agentfw, not a PATH alias.",
                ));
                None
            }
        }
    } else {
        checks.push(check(
            "binary",
            "explicit_binary_selection",
            Outcome::Unknown,
            "binary_not_selected",
            "No Agent binary was selected for an independent hash.",
            "Pass --agent /absolute/path/to/installed/agentfw.",
        ));
        None
    };

    if let (Some(path), Some(wanted)) = (&args.classifier_script, &args.classifier_sha256) {
        let actual = hash_selected_file(path, 16 * 1024 * 1024);
        let valid = is_digest(wanted) && actual.ok().as_deref() == Some(wanted.as_str());
        checks.push(check(
            "classifier",
            "selected_classifier_bytes",
            if valid {
                Outcome::Ready
            } else {
                Outcome::Failed
            },
            if valid {
                "classifier_pin_verified"
            } else {
                "classifier_pin_mismatch"
            },
            if valid {
                "Selected classifier matches its declared digest."
            } else {
                "Classifier is missing or differs from the reviewed revision."
            },
            "Review the classifier source independently; pass its reviewed SHA-256.",
        ));
    } else {
        checks.push(check("classifier", "classifier_selection", Outcome::Unknown,
            "classifier_not_selected", "No classifier revision was supplied for comparison.",
            "For a script classifier, pass --classifier-script and --classifier-sha256; do not infer runtime use."));
    }

    if let Some(cfg) = &config {
        if !cfg.enforce {
            checks.push(check("enforcement", "validated_disk_config", Outcome::Failed,
                "shadow_mode", "Disk configuration runs in shadow mode; it does not block calls.",
                "Review outcomes before enabling enforcement; apply changes through the existing operator workflow."));
        } else {
            checks.push(check(
                "enforcement",
                "validated_disk_config",
                Outcome::Ready,
                "enforce_requested_on_disk",
                "Disk configuration requests enforcement, not observed host coverage.",
                "Compare with authenticated runtime; a live host-call witness is still required.",
            ));
        }
        if let Some(native) = &cfg.native {
            let registry = hash_selected_file(&native.registry_path, 8 * 1024 * 1024);
            let matches = registry.ok().as_deref() == Some(native.registry_sha256.as_str());
            checks.push(check(
                "registry",
                "selected_native_registry",
                if matches {
                    Outcome::Ready
                } else {
                    Outcome::Failed
                },
                if matches {
                    "registry_pin_verified"
                } else {
                    "registry_pin_mismatch"
                },
                if matches {
                    "Selected native registry matches the configuration pin."
                } else {
                    "Native registry bytes differ or are missing."
                },
                "Review native.registry_path and its expected SHA-256 in private config.yaml.",
            ));
        } else {
            checks.push(check("registry", "validated_disk_config", Outcome::Unknown,
                "native_profile_not_selected", "No native registry is selected.",
                "For MCP native admission, review and install a profile using agentfw mcp-profile; legacy hooks are fail-open."));
        }

        let token = read_private(&home.join("token"), 4096)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .filter(|s| !s.trim().is_empty());
        if let Some(token) = token {
            let expected = Expectations {
                config_sha256: Some(protection_status::config_digest(cfg)),
                binary_sha256: binary.clone(),
                instance: intent
                    .as_ref()
                    .and_then(|i| i.process.as_ref())
                    .map(|p| p.instance.clone()),
                registry_sha256: cfg.native.as_ref().map(|n| n.registry_sha256.clone()),
                ..Default::default()
            };
            let snapshot =
                protection_status::query(cfg, token.trim(), &expected, Duration::from_secs(2))
                    .await;
            match snapshot {
                Ok(value) => {
                    let is_enforcing = value.mode == Mode::Enforcing;
                    checks.push(check("authenticated_runtime", "protection_status_nonce_and_bearer",
                        if is_enforcing { Outcome::Ready } else { Outcome::Failed },
                        if is_enforcing { "runtime_identity_verified" } else { "runtime_shadow" },
                        if is_enforcing { "Daemon identity, startup config and pins matched authenticated status." }
                            else { "Authenticated runtime is in shadow mode." },
                        "Review agentfw protection-status --query-only; transport health is not execution proof."));
                    let selected = intent.as_ref().and_then(|i| i.process.as_ref());
                    if let Some(process) = selected {
                        let same = value.runtime.pid == process.pid
                            && value.runtime.instance == process.instance
                            && value.runtime.binary_sha256.as_deref()
                                == Some(process.binary_digest.as_str());
                        checks.push(check("lifecycle_identity", "manifest_vs_authenticated_runtime",
                            if same { Outcome::Ready } else { Outcome::Failed },
                            if same { "runtime_matches_managed_process" } else { "runtime_not_managed_instance" },
                            if same { "Authenticated daemon is the recorded managed process." } else { "Listener differs from the recorded managed process." },
                            "Review agentfw lifecycle status; do not stop or adopt an unidentified listener."));
                    }
                }
                Err(code) => {
                    let probe_addr = if cfg.bind == "::1" {
                        std::net::SocketAddr::new(
                            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                            cfg.port,
                        )
                    } else {
                        std::net::SocketAddr::from(([127, 0, 0, 1], cfg.port))
                    };
                    let occupied = std::net::TcpStream::connect_timeout(
                        &probe_addr,
                        Duration::from_millis(250),
                    )
                    .is_ok();
                    let (reason, explain) = if code == "status_identity_mismatch" {
                        (
                            "runtime_identity_mismatch",
                            "Live daemon did not match selected disk intent.",
                        )
                    } else if occupied {
                        (
                            "listener_unverifiable",
                            "An occupied port did not supply matching authenticated diagnostics.",
                        )
                    } else {
                        (
                            "daemon_unavailable",
                            "The selected daemon is unreachable or unauthenticated.",
                        )
                    };
                    checks.push(check("authenticated_runtime", "protection_status_nonce_and_bearer",
                        Outcome::Failed, reason, explain,
                        "Check agentfw lifecycle status and agentfw protection-status --query-only; never trust an unverified listener."));
                }
            }
        } else {
            checks.push(check("authenticated_runtime", "private_local_token",
                Outcome::Failed, "auth_token_missing_or_unsafe",
                "Local diagnostic credential is missing or unsafe; no unauthenticated fallback.",
                "Inspect the selected private token file; do not copy credentials into a support bundle."));
        }
    }

    if let (Some(path), Some(server), Some(agent)) = (&args.host_config, &args.server, &args.agent)
    {
        let options = crate::mcp::connection::Options {
            path: path.clone(),
            server: server.clone(),
            home: home.clone(),
            agent: agent.clone(),
            probe_tool: None,
            probe_args: None,
            #[cfg(windows)]
            runtime: None,
        };
        let status = crate::mcp::connection::inspect_read_only(&options).await;
        let (outcome, reason, explain) = match status {
            Ok("configured") => (Outcome::Ready, "host_connection_configured", "Selected host wrapper and authenticated runtime match; execution remains unproven."),
            Ok("unavailable") => (Outcome::Failed, "host_connection_unavailable", "The selected host connection cannot be authenticated."),
            Ok(_) => (Outcome::Unknown, "host_connection_unknown", "Selected host configuration or ownership has drifted."),
            Err(_) => (Outcome::Failed, "host_connection_unsafe_or_invalid", "Host configuration or selected server could not be safely inspected."),
        };
        checks.push(check("host_connection", "read_only_connection_inspect", outcome, reason, explain,
            "Run agentfw mcp-connection inspect with the same explicit --path, --server, --home and --agent; this does not test active calls."));
    } else {
        checks.push(check("host_connection", "explicit_host_selection", Outcome::Unknown,
            "host_connection_not_selected", "No host configuration and server were selected.",
            "Pass --host-config /absolute/host/settings.json --server NAME --agent /absolute/agentfw."));
    }

    // The accepted diagnostics explicitly report every execution_coverage as unknown.
    // No aggregate readiness state is ever proof of an active protected call.
    checks.push(check("active_host_call", "protection_status_coverage_contract",
        Outcome::Unknown, "active_call_not_witnessed",
        "Configuration, heartbeat, counters and isolated tests are not active-host protection evidence.",
        "Exercise and audit an explicitly owned real host call separately, without doctor executing one."));
    // Every explicitly supplied failed/unknown selector participates in setup
    // readiness. Never silently discard a wrong classifier/host/binary pin.
    report.setup = setup(
        &checks
            .iter()
            .filter(|c| c.id != "active_host_call")
            .collect::<Vec<_>>(),
    );
    report.checks = checks;
    report
}

pub fn run(args: DoctorArgs) -> i32 {
    let report = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(diagnose(&args)),
        Err(_) => Report {
            schema: "sw-agent-doctor/1",
            observed_at_ms: protection_status::now_ms(),
            setup: Outcome::Unknown,
            active_host_call_protection: "unknown",
            scope: "local_setup_and_authenticated_runtime_not_active_host_execution",
            checks: vec![check(
                "runtime",
                "local_process",
                Outcome::Unknown,
                "diagnostics_unavailable",
                "Could not create bounded diagnostic runtime.",
                "Try a known good installed Agent executable.",
            )],
        },
    };
    let bundle_error = args
        .support_bundle
        .as_ref()
        .and_then(|path| crate::support_bundle::export(&report, path).err());
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!(
            "Agent doctor (sw-agent-doctor/1): setup {:?}; active-host protection UNKNOWN",
            report.setup
        );
        for c in &report.checks {
            println!(
                "[{:?}] {} ({}): {}\n  Next: {}",
                c.outcome, c.id, c.reason_code, c.explanation, c.next_step
            );
        }
    }
    if bundle_error.is_some() {
        eprintln!("support bundle not written: unsafe destination or I/O failure (no existing output replaced)");
        return 4;
    }
    match report.setup {
        Outcome::Ready => 0,
        Outcome::Failed => 3,
        Outcome::Unknown => 4,
        Outcome::Unsupported => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sensitive_strings_are_not_in_reports() {
        let c = check(
            "auth",
            "test",
            Outcome::Failed,
            "auth_token_missing_or_unsafe",
            "Local credential cannot be read",
            "Inspect privately",
        );
        let serialized = serde_json::to_string(&c).unwrap();
        assert!(!serialized.contains("supersecret"));
        assert!(!serialized.contains("/home/alice"));
    }
    #[test]
    fn digest_requires_lowercase_exactly() {
        assert!(is_digest(&"a".repeat(64)));
        assert!(!is_digest(&"A".repeat(64)));
        assert!(!is_digest("a"));
    }
    #[cfg(unix)]
    #[test]
    fn private_reader_refuses_link_and_public_file() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("secret");
        std::fs::write(&path, b"sentinel").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_private(&path, 16).unwrap(), b"sentinel");
        let link = temp.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_private(&link, 16).is_err());
        assert!(read_private(&path, 3).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&path, 16).is_err());
    }
}
