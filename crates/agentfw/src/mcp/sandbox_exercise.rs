// SPDX-License-Identifier: Apache-2.0
//! Explicit bounded execution, separate from read-only doctor observations.
use clap::{Args, ValueEnum};
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Kind {
    Filesystem,
    Git,
}

#[derive(Debug, Args)]
pub struct Cli {
    /// Explicitly execute real pinned runtimes in owned temporary fixtures.
    #[arg(long)]
    pub execute: bool,
    #[arg(long, value_enum)]
    pub kind: Kind,
    /// Exact installed profile; no PATH search or unsandboxed fallback.
    #[arg(long)]
    pub profile: PathBuf,
    #[arg(long)]
    pub profile_sha256: String,
}

const FORMAT: &str = "sw-linux-sandbox-exercise/1";

pub fn run_cli(args: Cli) -> i32 {
    let mut report = json!({"format":FORMAT,"status":"failed","reason":null,
        "active_protection":false,"cleanup_confirmed":false,
        "limits":{"profile_bytes":65536,"output_bytes":65536,"runtime_seconds":15,
                  "calibration_seconds":5,"report_bytes":131072,"owner_cleanup_ms":3000,"reap_seconds":2},"inputs":null,"observations":null});
    let result = execute(args, &mut report);
    let mut code = match result {
        Ok(()) => {
            report["status"] = json!("passed");
            0
        }
        Err(reason) => {
            report["reason"] = json!(reason);
            if reason == "unsupported_platform" {
                5
            } else {
                3
            }
        }
    };
    if report.to_string().len() > 128 * 1024 {
        report["inputs"] = Value::Null;
        report["observations"] = Value::Null;
        report["status"] = json!("failed");
        report["reason"] = json!("report_output_limit");
        code = 3;
    }
    println!("{}", report);
    code
}

#[cfg(not(target_os = "linux"))]
fn execute(_args: Cli, _report: &mut Value) -> Result<(), &'static str> {
    Err("unsupported_platform")
}

#[cfg(target_os = "linux")]
fn execute(args: Cli, report: &mut Value) -> Result<(), &'static str> {
    use super::server_profile::{self, ProfileConfig};
    use super::server_sandbox::{exercise, open_verified_file};
    use anyhow::Context;
    use sha2::{Digest, Sha256};
    if !args.execute {
        return Err("explicit_execution_required");
    }
    if !args.profile.is_absolute()
        || args.profile.to_str().is_none()
        || args.profile_sha256.len() != 64
        || !args
            .profile_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid_input");
    }
    let load = || -> anyhow::Result<ProfileConfig> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&args.profile)?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.len() <= 65536,
            "invalid_input"
        );
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= 65536 && format!("{:x}", Sha256::digest(&bytes)) == args.profile_sha256,
            "input_identity_mismatch"
        );
        ProfileConfig::read(&bytes)
    };
    let mut profile = load().map_err(|_| "invalid_or_mismatched_profile")?;
    // Exercise the common read-only primitive with independent owned fixtures;
    // profile-specific execution acceptance remains with its existing caller.
    if !match args.kind {
        Kind::Filesystem => {
            server_profile::selected(Some(&profile.format))
                && !server_profile::git_selected(&profile.format)
        }
        Kind::Git => server_profile::git_selected(&profile.format),
    } {
        return Err("unsupported_profile");
    }
    report["inputs"] = json!({"profile":{"path":args.profile,"sha256":args.profile_sha256},
        "kind":match args.kind { Kind::Filesystem=>"filesystem",Kind::Git=>"git" },
        "runtime":{"path":profile.runtime_path,"sha256":profile.runtime_sha256},
        "package":{"path":profile.package_root,"sha256":profile.package_tree_sha256},
        "bwrap":{"path":profile.bwrap_path,"sha256":profile.bwrap_sha256},
        "git":profile.git,"git_launcher":profile.git_launcher,"libraries":profile.libraries});
    // Verify runtime bytes before positive calibration executes anything.
    let mut pins = vec![
        open_verified_file(&profile.runtime_path, &profile.runtime_sha256, true)
            .map_err(|_| "input_identity_mismatch")?,
    ];
    if let Some(git) = &profile.git {
        pins.push(
            open_verified_file(&git.path, &git.sha256, true)
                .map_err(|_| "input_identity_mismatch")?,
        );
    }
    if matches!(args.kind, Kind::Git) && profile.git.is_none() {
        return Err("invalid_input");
    }
    // Refuse every selected asset mismatch before unsandboxed positive
    // calibration; preparation re-pins the same inputs for protected execution.
    pins.push(
        open_verified_file(&profile.bwrap_path, &profile.bwrap_sha256, true)
            .map_err(|_| "input_identity_mismatch")?,
    );
    if let Some(launcher) = &profile.git_launcher {
        pins.push(
            open_verified_file(&launcher.path, &launcher.sha256, true)
                .map_err(|_| "input_identity_mismatch")?,
        );
    }
    for library in &profile.libraries {
        pins.push(
            open_verified_file(&library.path, &library.sha256, false)
                .map_err(|_| "input_identity_mismatch")?,
        );
    }
    if server_profile::package_tree_sha256(&profile.package_root)
        .map_err(|_| "input_identity_mismatch")?
        != profile.package_tree_sha256
    {
        return Err("input_identity_mismatch");
    }
    let owned = tempfile::tempdir().map_err(|_| "fixture_unavailable")?;
    let workspace = owned.path().join("workspace");
    std::fs::create_dir(&workspace).map_err(|_| "fixture_unavailable")?;
    profile.workspace = workspace;
    profile.workspace_identity = None;
    profile.linked_worktree = None;
    profile.filesystem_roots = None;
    profile.workspace_snapshot = None;
    profile.format = match args.kind {
        Kind::Filesystem => server_profile::FORMAT,
        Kind::Git => server_profile::git::FORMAT,
    }
    .to_owned();
    report["exercise_profile"] = json!(profile.format);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "prerequisite_unavailable")?;
    let result = runtime.block_on(async {
        match args.kind {
            Kind::Filesystem => positive(&pins[0], &profile.runtime_path, &["-e", "if (require('node:fs').readFileSync('/dev/null').length !== 0) process.exit(1)"], owned.path()).await.context("calibration_node")?,
            Kind::Git => {
                positive(&pins[0], &profile.runtime_path, &["-I", "-B", "-c", "import pathlib; assert pathlib.Path('/dev/null').read_bytes() == b''"], owned.path()).await.context("calibration_python")?;
                let git = pins.get(1).context("exercise_input_invalid")?;
                let git_name = &profile.git.as_ref().context("exercise_input_invalid")?.path;
                positive(git, git_name, &["init", "--quiet", "."], &profile.workspace).await.context("calibration_git_init")?;
                positive(git, git_name, &["-c", "user.name=Owned exercise", "-c", "user.email=exercise@example.invalid", "commit", "--quiet", "--allow-empty", "-m", "Owned sandbox exercise"], &profile.workspace).await.context("calibration_git_commit")?;
            }
        }
        match args.kind { Kind::Filesystem => exercise::filesystem(profile).await, Kind::Git => exercise::git(profile, false).await }
    });
    drop(pins);
    owned.close().map_err(|_| "exercise_cleanup_unconfirmed")?;
    match result {
        Ok(observation) => {
            report["observations"] = observation;
            report["calibration_passed"] = json!(true);
            report["cleanup_confirmed"] = json!(true);
            Ok(())
        }
        Err(error) => {
            for stage in [
                "calibration_node",
                "calibration_python",
                "calibration_git_init",
                "calibration_git_commit",
            ] {
                if error.chain().any(|cause| cause.to_string() == stage) {
                    report["calibration_stage"] = json!(stage);
                }
            }
            if error
                .chain()
                .any(|cause| cause.to_string() == "exercise_cleanup_confirmed")
            {
                report["cleanup_confirmed"] = json!(true);
            }
            // Fixed public categories. No raw subprocess bytes or arbitrary
            // paths from internal errors enter the machine-readable report.
            let reasons = [
                "exercise_cleanup_unconfirmed",
                "exercise_interrupted",
                "exercise_timeout",
                "exercise_output_limit",
                "exercise_calibration_failed",
                "exercise_witness_failed",
                "exercise_runtime_failed",
                "exercise_input_invalid",
                "exercise_observation_invalid",
            ];
            for reason in reasons {
                if error.chain().any(|cause| cause.to_string() == reason) {
                    return Err(reason);
                }
            }
            Err("prerequisite_or_identity_failed")
        }
    }
}

#[cfg(target_os = "linux")]
async fn positive(
    pin: &std::fs::File,
    program_name: &std::path::Path,
    args: &[&str],
    cwd: &std::path::Path,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    // Execute the verified inode, not a second lookup of its mutable pathname.
    let mut command = tokio::process::Command::new(format!("/proc/self/fd/{}", pin.as_raw_fd()));
    // CPython locates its stdlib using argv[0]. The fd is intentionally
    // CLOEXEC, so /proc/self/fd/N disappears after exec; retain the reviewed
    // installation name without resolving the executable a second time.
    command.as_std_mut().arg0(program_name);
    command
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env("HOME", cwd)
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn().context("exercise_calibration_failed")?;
    match tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await {
        Ok(Ok(status)) => anyhow::ensure!(status.success(), "exercise_calibration_failed"),
        _ => {
            child.start_kill().context("exercise_cleanup_unconfirmed")?;
            anyhow::ensure!(
                matches!(
                    tokio::time::timeout(std::time::Duration::from_secs(2), child.wait()).await,
                    Ok(Ok(_))
                ),
                "exercise_cleanup_unconfirmed"
            );
            anyhow::bail!("exercise_calibration_failed");
        }
    }
    Ok(())
}
