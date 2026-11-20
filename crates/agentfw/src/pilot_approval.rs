// SPDX-License-Identifier: Apache-2.0
//! Run selection for the existing native approval broker. No bearer authority is persisted here.

use crate::hashing::sha256_hex;
use crate::{
    native::{approval, child_authority},
    pilot_launcher::ValidatedConfig,
    Config,
};
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub(crate) mod result;
use result::{tag, Output, Reason};

macro_rules! require {
    ($condition:expr, $reason:ident, $message:literal) => {
        if !$condition {
            return Err(tag(anyhow::anyhow!($message), Reason::$reason));
        }
    };
}

const MAX_RUNS: usize = 16;
const MAX_BYTES: usize = 2 * 1024 * 1024;

mod watch;

#[derive(Args)]
pub struct OperatorArgs {
    /// Run identity printed by pilot-launch, not a caller-selected session label.
    #[arg(long)]
    pub run: String,
    #[arg(long)]
    pub home: Option<PathBuf>,
    #[arg(long, value_enum, global = true)]
    pub output: Option<OutputFormat>,
    #[command(subcommand)]
    pub action: OperatorAction,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    JsonV1,
}

#[derive(Subcommand)]
pub enum OperatorAction {
    /// Watch this run and inspect each request before an explicit decision.
    Watch {
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=30))]
        refresh_seconds: u64,
    },
    /// Revoke both collectors, then stop this exact owned launcher and host group.
    Stop,
    /// Digests and expiry only. Never displays raw arguments.
    List,
    /// Explicitly inspect the exact arguments before deciding.
    Inspect {
        #[arg(allow_hyphen_values = true)]
        id: String,
    },
    /// Approve one previously inspected binding, never an entire run.
    Approve {
        #[arg(allow_hyphen_values = true)]
        id: String,
        #[arg(long)]
        binding: String,
    },
    Reject {
        #[arg(allow_hyphen_values = true)]
        id: String,
        #[arg(long)]
        binding: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    path: PathBuf,
    sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    contract: String,
    run_id: String,
    home: PathBuf,
    instance_id: String,
    registry_sha256: String,
    host_session: String,
    launcher_pid: u32,
    launcher_start: u64,
    manifest_fd: i32,
    expires_at_ms: u64,
    authority_expires_at_ms: u64,
    authorities: BTreeMap<String, String>,
    files: Vec<FileIdentity>,
}

pub struct RunGuard {
    dir: PathBuf,
    run: Run,
    _manifest: fs::File,
}

#[cfg(target_os = "linux")]
pub(crate) fn manifest() -> Result<fs::File> {
    use std::os::fd::FromRawFd;
    let fd = unsafe {
        libc::memfd_create(
            c"agentfw-pilot-run".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    ensure!(fd >= 0, "sealed run metadata unavailable");
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    if fd < 3 {
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        ensure!(copy >= 3, "cannot reserve run metadata descriptor");
        file = unsafe { fs::File::from_raw_fd(copy) };
    }
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn manifest() -> Result<fs::File> {
    anyhow::bail!("sealed pilot run metadata requires Linux")
}

#[cfg(target_os = "linux")]
fn seal(file: &mut fs::File, run: &Run) -> Result<()> {
    seal_bytes(file, &serde_json::to_vec(run)?)
}

#[cfg(target_os = "linux")]
pub(crate) fn seal_bytes(file: &mut fs::File, bytes: &[u8]) -> Result<()> {
    use std::os::fd::AsRawFd;
    file.write_all(bytes)?;
    let flags = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    ensure!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, flags) } == 0,
        "cannot seal run metadata"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn seal(_file: &mut fs::File, _run: &Run) -> Result<()> {
    anyhow::bail!("sealed pilot run metadata requires Linux")
}

#[cfg(target_os = "linux")]
fn verify_manifest(run: &Run, bytes: &[u8]) -> Result<()> {
    verify_sealed(run, bytes)?;
    let arguments = read_file(
        &PathBuf::from(format!("/proc/{}/cmdline", run.launcher_pid)),
        false,
    )?;
    ensure!(
        arguments.split(|b| *b == 0).nth(1) == Some(b"pilot-launch".as_slice()),
        "held manifest is not owned by a pilot launcher"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_sealed(run: &Run, bytes: &[u8]) -> Result<()> {
    verify_sealed_owner(run.launcher_pid, run.launcher_start, run.manifest_fd, bytes)
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_sealed_owner(
    pid: u32,
    start: u64,
    manifest_fd: i32,
    bytes: &[u8],
) -> Result<()> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    ensure!(manifest_fd >= 3, "invalid sealed manifest descriptor");
    ensure!(
        process_start(pid)? == start,
        "pilot launcher identity changed"
    );
    let owner = fs::metadata(format!("/proc/{pid}"))?;
    ensure!(
        owner.uid() == unsafe { libc::getuid() },
        "pilot launcher owner mismatch"
    );
    let process_exe = fs::metadata(format!("/proc/{pid}/exe"))?;
    let selected_exe = fs::metadata(std::env::current_exe()?)?;
    ensure!(
        process_exe.dev() == selected_exe.dev() && process_exe.ino() == selected_exe.ino(),
        "pilot launcher executable differs from this operator CLI"
    );
    let file = fs::File::open(format!("/proc/{pid}/fd/{manifest_fd}"))?;
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    let actual = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    ensure!(
        actual >= 0 && actual & required == required,
        "run metadata is not sealed by the launcher"
    );
    let mut held = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut held)?;
    ensure!(
        held.len() <= MAX_BYTES && held == bytes,
        "run metadata differs from the live launcher's sealed selection"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_manifest(_run: &Run, _bytes: &[u8]) -> Result<()> {
    anyhow::bail!("run-scoped pilot approval requires Linux")
}

pub(crate) fn descriptor(file: &fs::File) -> i32 {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        file.as_raw_fd()
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        -1
    }
}

fn id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "invalid identity"
    );
    Ok(())
}

fn read_file(path: &Path, private: bool) -> Result<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).context("open bounded operator input")?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= MAX_BYTES as u64,
        "invalid or oversized operator input"
    );
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            meta.uid() == unsafe { libc::getuid() }
                && meta.mode() & 0o077 == 0
                && meta.nlink() == 1,
            "operator input must be owned, private and single-link"
        );
    }
    #[cfg(not(unix))]
    ensure!(!private, "run-scoped approval requires qualified Linux");
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_BYTES, "operator input grew beyond cap");
    Ok(bytes)
}

fn private_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "invalid private run directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            meta.uid() == unsafe { libc::getuid() } && meta.mode() & 0o077 == 0,
            "run directory must be owned and private"
        );
    }
    Ok(())
}

fn create_dir(path: &Path) -> Result<()> {
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    builder.create(path)?;
    private_dir(path)
}

fn lock_dir(path: &Path) -> Result<fs::File> {
    lock_dir_for(path, Duration::ZERO)
}

fn lock_dir_for(path: &Path, wait: Duration) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let deadline = std::time::Instant::now() + wait;
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(error).context("lock pilot metadata");
            }
            ensure!(
                std::time::Instant::now() < deadline,
                "another pilot metadata operation is active; retry"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[cfg(not(unix))]
    let _ = wait;
    Ok(file)
}

fn write_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    Ok(())
}

fn prune_inspections(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)?.take(18) {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("inspected-") || !name.ends_with(".json") {
            continue;
        }
        let value: Value = serde_json::from_slice(&read_file(&entry.path(), true)?)?;
        if value["expires_at_ms"]
            .as_u64()
            .is_some_and(|ms| ms <= approval::now_ms())
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

pub(crate) fn process_start(pid: u32) -> Result<u64> {
    ensure!(
        cfg!(target_os = "linux"),
        "pilot Ask continuation is supported only on qualified Linux"
    );
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, rest) = stat.rsplit_once(')').context("invalid process identity")?;
    let fields: Vec<_> = rest.split_whitespace().collect();
    ensure!(
        fields.first().is_some_and(|s| *s != "Z"),
        "pilot launcher is no longer live"
    );
    fields
        .get(19)
        .context("missing process start time")?
        .parse()
        .context("invalid process start time")
}

fn daemon_config(home: &Path) -> Result<Config> {
    Config::from_yaml(std::str::from_utf8(&read_file(
        &home.join("config.yaml"),
        false,
    )?)?)
}

fn token(home: &Path, name: &str) -> Result<String> {
    let bytes = read_file(&home.join(name), true)?;
    let value = std::str::from_utf8(&bytes)?.trim();
    ensure!(
        !value.is_empty() && value.len() <= 1024,
        "invalid daemon token"
    );
    Ok(value.into())
}

/// Existing authenticated endpoint, bounded read and loopback-only destination.
fn snapshot(home: &Path) -> Result<Value> {
    let cfg = daemon_config(home)?;
    let address: std::net::SocketAddr = cfg.socket_address().parse()?;
    ensure!(
        address.ip().is_loopback(),
        "pilot approval requires a loopback daemon"
    );
    let key = token(home, "native-token")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()?;
            let mut response = client
                .get(cfg.endpoint_url("/native/v1/instance"))
                .bearer_auth(key)
                .send()
                .await
                .context("live daemon unavailable; no approval issued")
                .map_err(|error| tag(error, Reason::DaemonUnavailable))?;
            require!(
                response.status().is_success(),
                DaemonRefused,
                "daemon refused operator identity discovery"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    bytes.len().saturating_add(chunk.len()) <= MAX_BYTES,
                    "daemon identity response over cap"
                );
                bytes.extend_from_slice(&chunk);
            }
            let value: Value = serde_json::from_slice(&bytes)?;
            ensure!(
                value["pilot_collectors"]
                    .as_array()
                    .is_some_and(|a| a.len() <= 256)
                    && value["pilot_pending"]
                        .as_array()
                        .is_some_and(|a| a.len() <= 16),
                "daemon lacks bounded pilot identities"
            );
            Ok(value)
        })
}

/// Prepared pilots already opt in to bounded liveness; leave legacy direct
/// non-Ask launchers without that lifecycle on their existing path.
pub(crate) fn liveness_configured(home: &Path) -> Result<bool> {
    Ok(daemon_config(home)?
        .native
        .is_some_and(|native| native.liveness.is_some()))
}

pub fn preflight(config: &ValidatedConfig) -> Result<()> {
    ensure!(cfg!(target_os = "linux") && !config.allow_command_fixtures
        && config.mock_daemon_token.is_none() && config.mock_instance_id.is_none(),
        "--ask-wait-seconds requires original installed profiles on qualified Linux; mocks are unsupported");
    ensure!(
        config.classifier_path.is_some() && config.policy_path.is_some(),
        "--ask-wait-seconds requires explicit --classifier and --policy"
    );
    ensure!(
        config.agent_bin_path.canonicalize()? == std::env::current_exe()?.canonicalize()?,
        "pilot Ask requires collectors from this same agentfw executable"
    );
    ensure!(
        read_file(config.classifier_path.as_ref().unwrap(), false)?
            == include_bytes!("../../../rule_baseline/git_readonly_v1/rule_baseline.py"),
        "pilot Ask requires the accepted two-server git_readonly_v1 classifier bytes"
    );
    ensure!(
        (1..=25).contains(&config.ask_wait_seconds),
        "--ask-wait-seconds must be 1..=25 (existing relay deadline is unchanged)"
    );
    ensure!(
        (1..=3600).contains(&config.timeout.as_secs()),
        "pilot Ask run timeout must be 1..=3600 seconds"
    );
    let cfg = daemon_config(&config.home_path)?;
    let native = cfg
        .native
        .as_ref()
        .context("configure native.approval and native.liveness before pilot Ask")?;
    ensure!(cfg.enforce && !cfg.judge.enabled && native.approval.is_some() && native.liveness.is_some(),
        "pilot Ask requires enforce: true, judge disabled, native.approval and native.liveness; daemon config was not modified");
    ensure!(
        native.liveness.as_ref().unwrap().maintenance_interval_ms <= 1000,
        "pilot Ask cleanup requires native.liveness.maintenance_interval_ms <= 1000"
    );
    for (path, format) in [
        (&config.fs_profile_path, crate::mcp::server_profile::FORMAT),
        (
            &config.git_profile_path,
            crate::mcp::server_profile::git::FORMAT,
        ),
    ] {
        let profile = crate::mcp::server_profile::ProfileConfig::read(&read_file(path, false)?)?;
        ensure!(
            profile.format == format,
            "pilot Ask requires the matching original read-only profile"
        );
        profile.verify_assets()?;
    }
    let live = snapshot(&config.home_path)?;
    ensure!(
        live["approval_enabled"] == true
            && live["liveness_enabled"] == true
            && live["registry_sha256"] == native.registry_sha256,
        "restart daemon with matching approval/liveness/registry settings"
    );
    ensure!(
        !live["pilot_collectors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["host_session"] == config.host_session),
        "host session already has a live collector; select a new run"
    );
    Ok(())
}

impl RunGuard {
    pub fn create(
        config: &ValidatedConfig,
        instance: &str,
        grants: &BTreeMap<String, child_authority::ChildAuthorityGrant>,
    ) -> Result<Self> {
        let home = config.home_path.canonicalize()?;
        let root = home.join("pilot-runs");
        if !root.exists() {
            match create_dir(&root) {
                Ok(()) => (),
                Err(e) if !root.exists() => return Err(e),
                Err(_) => (),
            }
        }
        private_dir(&root)?;
        let _reservation = lock_dir(&root)?;
        ensure!(
            fs::read_dir(&root)?.take(MAX_RUNS + 1).count() < MAX_RUNS,
            "pilot run metadata capacity reached; inspect stale runs before removing them"
        );
        let run_id = format!("{:032x}", rand::random::<u128>());
        let dir = root.join(&run_id);
        let live = snapshot(&config.home_path)?;
        ensure!(
            live["instance_id"] == instance,
            "daemon restarted during launch preparation"
        );
        ensure!(
            grants.len() == 2,
            "both original collector grants are required"
        );
        let key = child_authority::derive_key(&token(&config.home_path, "native-token")?);
        for (server, tools) in [("filesystem", &config.fs_tools), ("git", &config.git_tools)] {
            let grant = grants.get(server).context("missing collector authority")?;
            let verified = child_authority::verify_token(
                &key,
                &child_authority::encode_token(grant),
                &config.host_session,
                server,
                approval::now_ms(),
            )
            .map_err(|_| anyhow::anyhow!("collector authority failed verification"))?;
            ensure!(
                verified.nonce.starts_with(&format!("{instance}."))
                    && verified.granted_tools == *tools
                    && verified.agent_id.as_deref() == Some(format!("claude-{server}").as_str()),
                "collector authority does not match this live launch"
            );
        }
        let mut manifest = manifest()?;
        let run = Run {
            contract: "sw-pilot-run/1".into(),
            run_id,
            home,
            instance_id: instance.into(),
            registry_sha256: live["registry_sha256"]
                .as_str()
                .context("missing registry identity")?
                .into(),
            host_session: config.host_session.clone(),
            launcher_pid: std::process::id(),
            launcher_start: process_start(std::process::id())?,
            manifest_fd: descriptor(&manifest),
            expires_at_ms: approval::now_ms().saturating_add(config.timeout.as_millis() as u64),
            authority_expires_at_ms: grants
                .values()
                .map(|g| g.expires_at_ms)
                .max()
                .context("missing authority expiry")?,
            authorities: grants
                .iter()
                .map(|(server, grant)| {
                    (
                        server.clone(),
                        sha256_hex(child_authority::encode_token(grant).as_bytes()),
                    )
                })
                .collect(),
            files: [
                Some(config.home_path.join("config.yaml")),
                Some(config.fs_profile_path.clone()),
                Some(config.git_profile_path.clone()),
                config.classifier_path.clone(),
                config.policy_path.clone(),
            ]
            .into_iter()
            .flatten()
            .map(|path| {
                Ok(FileIdentity {
                    sha256: sha256_hex(&read_file(&path, false)?),
                    path,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        };
        seal(&mut manifest, &run)?;
        create_dir(&dir)?;
        let guard = Self {
            dir,
            run,
            _manifest: manifest,
        };
        write_new(&guard.dir.join("run.json"), &guard.run)?;
        Ok(guard)
    }
    pub fn id(&self) -> &str {
        &self.run.run_id
    }
    /// Allow existing collectors to finish their private namespace cleanup
    /// before TERM reaches the host group. Never create or signal another owner.
    pub(crate) fn cleanup_waiter(&self) -> impl FnOnce() -> Result<()> + Send + 'static {
        let run = self.run.clone();
        let dir = self.dir.clone();
        move || {
            if has_stop(&dir)? {
                let bytes = read_file(&dir.join("run.json"), true)?;
                read_stop(&dir, &run, &bytes)?;
            }
            // Ordinary host exit is also terminal. Retire only this run's two
            // exact grants before waiting: no late owner may enroll, and live
            // owners are woken to discharge their existing cleanup obligation.
            // No stop marker is created; normal failure/cancellation stays failed.
            revoke(&run)?;
            let deadline = std::time::Instant::now() + Duration::from_secs(6);
            loop {
                let live = snapshot(&run.home)?;
                ensure!(
                    live["instance_id"] == run.instance_id,
                    "daemon changed during selected-owner cleanup"
                );
                if selected_cleanup_complete(&run, &live)? {
                    return Ok(());
                }
                ensure!(
                    std::time::Instant::now() < deadline,
                    "pilot stop incomplete: selected namespace cleanup unconfirmed"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    /// Never broad-cancel a host/session label. Only retire exact observed bindings.
    pub fn finish(&self, host_stopped: bool) -> Result<bool> {
        let live = snapshot(&self.run.home)?;
        ensure!(
            live["instance_id"] == self.run.instance_id,
            "daemon changed; existing liveness retirement owns unused approvals"
        );
        let rows = pending(&self.run, &live)?;
        let ids: Vec<_> = rows.iter().map(|(r, _)| r["pending_id"].clone()).collect();
        for (record, _) in rows {
            let _ = approval::operator_reject_for_session(
                &self.run.home,
                string(&record, "pending_id")?,
                string(&record, "binding_sha256")?,
                string(&record, "session_id")?,
                string(&record, "session_epoch")?,
            );
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(7);
        loop {
            let live = snapshot(&self.run.home)?;
            ensure!(
                live["instance_id"] == self.run.instance_id,
                "daemon restarted during cleanup"
            );
            let owned = live["pilot_collectors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| {
                    self.run
                        .authorities
                        .values()
                        .any(|d| s["authority_sha256"] == *d)
                });
            let pending = live["pilot_pending"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| ids.contains(&r["pending_id"]));
            if !owned && !pending && selected_cleanup_complete(&self.run, &live)? {
                let stopped = if has_stop(&self.dir)? {
                    ensure!(
                        host_stopped,
                        "pilot stop incomplete: host cleanup is unconfirmed"
                    );
                    let bytes = read_file(&self.dir.join("run.json"), true)?;
                    let marker = read_stop(&self.dir, &self.run, &bytes)?;
                    if marker.status == "requested" {
                        revoke(&self.run)?;
                        write_stop(&self.dir, &self.run, &bytes, "revoked")?;
                    }
                    write_stop(&self.dir, &self.run, &bytes, "stopped")?;
                    // Return only the authenticated, exact-run terminal receipt,
                    // never the presence of intent or an operator's exit code.
                    read_stop(&self.dir, &self.run, &bytes)?.status == "stopped"
                } else {
                    fs::remove_dir_all(&self.dir).context("owned run metadata cleanup failed")?;
                    false
                };
                return Ok(stopped);
            }
            ensure!(
                std::time::Instant::now() < deadline,
                "owned collector retirement not confirmed within cleanup budget"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        // Preserve interrupted stops for truthful retry/recovery. Never erase the
        // only evidence that revocation or process cleanup remains incomplete.
        if matches!(has_stop(&self.dir), Ok(false)) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

fn selected_cleanup_complete(run: &Run, live: &Value) -> Result<bool> {
    let rows = live["pilot_cleanup"]
        .as_array()
        .context("pilot stop incomplete: daemon has no selected-owner cleanup observations")?;
    for row in rows {
        if let Some((server, _)) = run
            .authorities
            .iter()
            .find(|(_, digest)| row["authority_sha256"] == **digest)
        {
            ensure!(
                row["host_session"] == run.host_session && row["server_id"] == *server,
                "pilot stop incomplete: foreign namespace cleanup identity"
            );
            if row["verified"] != true {
                return Ok(false);
            }
        }
    }
    // Absence means begin was never admitted. Begin and stop use the same
    // session lock; a spent grant can never register/start a selected owner.
    Ok(true)
}

fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .context("incomplete trusted operator identity")
}

fn pending(run: &Run, live: &Value) -> Result<Vec<(Value, String)>> {
    require!(
        live["instance_id"] == run.instance_id && live["registry_sha256"] == run.registry_sha256,
        DaemonIdentityChanged,
        "wrong or restarted daemon; run cannot be resumed"
    );
    let collectors = live["pilot_collectors"]
        .as_array()
        .context("missing live collector identities")?;
    let mut result = Vec::new();
    for record in live["pilot_pending"]
        .as_array()
        .context("missing pending identities")?
    {
        for collector in collectors {
            let server = string(collector, "server_id")?;
            if collector["active"] == true
                && collector["host_session"] == run.host_session
                && collector["agent_id"] == format!("claude-{server}")
                && run
                    .authorities
                    .get(server)
                    .is_some_and(|d| collector["authority_sha256"] == *d)
                && collector["session_id"] == record["session_id"]
                && collector["session_epoch"] == record["session_epoch"]
            {
                result.push((record.clone(), server.to_string()));
            }
        }
    }
    Ok(result)
}

fn checked_record(home: &Path, observed: &Value) -> Result<Value> {
    let identifier = string(observed, "pending_id")?;
    id(identifier)?;
    let value: Value = serde_json::from_slice(
        &read_file(
            &approval::pending_dir(home).join(format!("{identifier}.json")),
            true,
        )
        .map_err(|error| {
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound)
            {
                tag(error, Reason::PendingUnavailable)
            } else {
                error
            }
        })?,
    )?;
    for key in [
        "pending_id",
        "session_id",
        "session_epoch",
        "tool",
        "binding_sha256",
        "args_sha256",
    ] {
        require!(
            value[key] == observed[key] && value[key].is_string(),
            BindingChanged,
            "pending identity changed; inspect again"
        );
    }
    require!(
        crate::native::canonical_digest(&value["args"]) == string(observed, "args_sha256")?,
        BindingChanged,
        "pending arguments differ from the daemon's original call"
    );
    require!(
        value["scope"] == "native-mcp/approval/v1"
            && value["expires_at_ms"] == observed["expires_at_ms"],
        BindingChanged,
        "pending call expired"
    );
    require!(
        value["expires_at_ms"]
            .as_u64()
            .is_some_and(|t| t > approval::now_ms()),
        PendingExpired,
        "pending call expired"
    );
    Ok(value)
}

fn escaped(value: &Value) -> Result<String> {
    let mut out = String::new();
    for c in serde_json::to_string_pretty(value)?.chars() {
        if !c.is_ascii() || c == '\u{7f}' {
            // ASCII JSON also makes Unicode formatting/invisible characters
            // unambiguous. Encode astral characters as valid surrogate pairs.
            for unit in c.encode_utf16(&mut [0; 2]) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StopMarker {
    contract: String,
    run_sha256: String,
    status: String,
    signature: String,
}

fn has_stop(dir: &Path) -> Result<bool> {
    match fs::symlink_metadata(dir.join("stop.json")) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn stop_mac(marker: &StopMarker, key: &str) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())?;
    mac.update(b"agentfw/pilot-stop-receipt/v1\0");
    mac.update(&serde_json::to_vec(&(
        &marker.contract,
        &marker.run_sha256,
        &marker.status,
    ))?);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn read_stop(dir: &Path, run: &Run, bytes: &[u8]) -> Result<StopMarker> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use subtle::ConstantTimeEq;
    let marker: StopMarker = serde_json::from_slice(&read_file(&dir.join("stop.json"), true)?)?;
    ensure!(
        marker.contract == "sw-pilot-stop/1"
            && marker.run_sha256 == sha256_hex(bytes)
            && matches!(marker.status.as_str(), "requested" | "revoked" | "stopped"),
        "invalid pilot stop receipt"
    );
    let signature = URL_SAFE_NO_PAD.decode(&marker.signature)?;
    ensure!(
        bool::from(signature.ct_eq(&stop_mac(&marker, &token(&run.home, "native-token")?)?)),
        "pilot stop receipt authentication failed"
    );
    Ok(marker)
}

fn write_stop(dir: &Path, run: &Run, bytes: &[u8], status: &str) -> Result<()> {
    // A simultaneous operator/launcher update must not strand a fully cleaned
    // run in `revoked`. Only short metadata writes hold this lock; never I/O to
    // a terminal or the daemon. Keep a bound for a stuck or foreign holder.
    let _reservation = lock_dir_for(dir, Duration::from_secs(2))?;
    if has_stop(dir)? {
        let current = read_stop(dir, run, bytes)?;
        let rank = |value: &str| match value {
            "requested" => 0,
            "revoked" => 1,
            "stopped" => 2,
            _ => 3,
        };
        if rank(&current.status) >= rank(status) {
            return Ok(());
        }
    }
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut marker = StopMarker {
        contract: "sw-pilot-stop/1".into(),
        run_sha256: sha256_hex(bytes),
        status: status.into(),
        signature: String::new(),
    };
    marker.signature =
        URL_SAFE_NO_PAD.encode(stop_mac(&marker, &token(&run.home, "native-token")?)?);
    let temporary = dir.join(format!(".stop-{:032x}", rand::random::<u128>()));
    write_new(&temporary, &marker)?;
    fs::rename(&temporary, dir.join("stop.json"))?;
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn record_inspection(
    dir: &Path,
    receipt: &Path,
    value: &Value,
    display: &str,
    terminal: &mut impl Write,
) -> Result<()> {
    // A blocked pipe/terminal must not prevent the independent stop command.
    // Still persist proof of inspection only after the output was flushed.
    writeln!(terminal, "{display}")
        .map_err(|error| tag(error.into(), Reason::OutputUnavailable))?;
    terminal
        .flush()
        .map_err(|error| tag(error.into(), Reason::OutputUnavailable))?;
    let _reservation = lock_dir(dir)?;
    ensure!(!has_stop(dir)?, "pilot run is stopping or stopped");
    prune_inspections(dir)?;
    ensure!(
        fs::read_dir(dir)?.take(18).count() < 18,
        "inspection receipt capacity reached"
    );
    match write_new(receipt, value) {
        Ok(()) => (),
        Err(e) if !receipt.exists() => return Err(e),
        Err(_) => {
            ensure!(
                serde_json::from_slice::<Value>(&read_file(receipt, true)?)? == *value,
                "inspection receipt changed"
            );
        }
    }
    Ok(())
}

fn stop_config(run: &Run) -> Result<Config> {
    let identity = run
        .files
        .first()
        .context("pilot stop lacks daemon configuration identity")?;
    ensure!(
        identity.path == run.home.join("config.yaml"),
        "pilot stop configuration ownership mismatch"
    );
    let bytes = read_file(&identity.path, false)?;
    ensure!(
        sha256_hex(&bytes) == identity.sha256,
        "pilot stop incomplete: daemon configuration changed"
    );
    // Parse the same verified bytes; never reopen a mutable endpoint selection.
    Config::from_yaml(std::str::from_utf8(&bytes)?)
}

fn revoke(run: &Run) -> Result<()> {
    let cfg = stop_config(run)?;
    let address: std::net::SocketAddr = cfg.socket_address().parse()?;
    ensure!(
        address.ip().is_loopback(),
        "pilot stop requires a loopback daemon"
    );
    let request = crate::native::pilot_stop::Request {
        contract_version: crate::native::pilot_stop::CONTRACT.into(),
        instance_id: run.instance_id.clone(),
        registry_sha256: run.registry_sha256.clone(),
        host_session: run.host_session.clone(),
        authorities: run.authorities.clone(),
        expires_at_ms: run.authority_expires_at_ms,
    };
    let key = token(&run.home, "native-token")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()?;
            let mut response = client
                .post(cfg.endpoint_url(crate::native::pilot_stop::ENDPOINT))
                .bearer_auth(key)
                .json(&request)
                .send()
                .await
                .map_err(|error| tag(error.into(), Reason::DaemonUnavailable))?;
            require!(
                response.status().is_success(),
                StopUnconfirmed,
                "pilot stop incomplete: daemon did not confirm revocation"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    bytes.len().saturating_add(chunk.len()) <= 4096,
                    "pilot stop response exceeds limit"
                );
                bytes.extend_from_slice(&chunk);
            }
            let value: Value = serde_json::from_slice(&bytes)?;
            ensure!(
                value["contract_version"] == crate::native::pilot_stop::CONTRACT
                    && value["instance_id"] == run.instance_id
                    && value["host_session"] == run.host_session
                    && value["status"] == "revoked",
                "pilot stop revocation identity mismatch"
            );
            Ok(())
        })
}

#[cfg(target_os = "linux")]
fn launcher_handle(run: &Run) -> Result<fs::File> {
    process_handle(run.launcher_pid, run.launcher_start)
}

#[cfg(target_os = "linux")]
pub(crate) fn process_handle(pid: u32, start: u64) -> Result<fs::File> {
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
    ensure!(fd >= 0, "pilot stop cannot pin launcher identity");
    let file = unsafe { fs::File::from_raw_fd(fd) };
    ensure!(
        process_start(pid)? == start,
        "pilot stop launcher identity changed"
    );
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn launcher_handle(_run: &Run) -> Result<fs::File> {
    anyhow::bail!("pilot stop requires qualified Linux")
}

#[cfg(target_os = "linux")]
pub(crate) fn signal_launcher(handle: &fs::File) -> Result<()> {
    use std::os::fd::AsRawFd;
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            handle.as_raw_fd(),
            libc::SIGTERM,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    ensure!(
        result == 0,
        "pilot stop incomplete: pinned launcher could not be signalled"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn signal_launcher(_handle: &fs::File) -> Result<()> {
    anyhow::bail!("pilot stop requires qualified Linux")
}

fn stop(
    dir: &Path,
    run: &Run,
    bytes: &[u8],
    expected: &str,
    home: &Path,
    output: &mut Output,
) -> Result<Value> {
    require!(
        run.contract == "sw-pilot-run/1"
            && run.run_id == expected
            && run.home == home
            && run.authorities.len() == 2,
        UnsafeRunRecord,
        "invalid pilot stop ownership"
    );
    let existing = if has_stop(dir)? {
        Some(
            read_stop(dir, run, bytes)
                .map_err(|error| tag(error, Reason::StopOwnershipUnverified))?,
        )
    } else {
        None
    };
    if existing
        .as_ref()
        .is_some_and(|marker| marker.status == "stopped")
    {
        output.identity = verified_identity(run, bytes);
        return Ok(
            json!({"run":run.run_id,"status":"already_stopped","running_effects_rolled_back":false}),
        );
    }
    // A stale/forged durable record is never sufficient to signal a process.
    // Pin the live owner before revocation; pidfd prevents PID reuse during the request.
    let handle = launcher_handle(run)
        .with_context(|| {
            if existing.is_some() {
                "pilot stop incomplete: recorded request has no confirmed live launcher"
            } else {
                "pilot stop unknown ownership: launcher identity is unavailable"
            }
        })
        .map_err(|error| tag(error, Reason::StopOwnershipUnverified))?;
    verify_manifest(run, bytes)
        .context("pilot stop unknown ownership: sealed owner verification failed")
        .map_err(|error| tag(error, Reason::StopOwnershipUnverified))?;
    output.identity = verified_identity(run, bytes);
    write_stop(dir, run, bytes, "requested")?;
    output.stop_requested = true;
    let revoked = revoke(run);
    if revoked.is_ok() {
        write_stop(dir, run, bytes, "revoked")?;
    }
    // Even on daemon loss, request owned process cleanup; do not claim complete revocation.
    signal_launcher(&handle)?;
    revoked?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if read_stop(dir, run, bytes)?.status == "stopped" {
            return Ok(
                json!({"run":run.run_id,"status":"stopped","running_effects_rolled_back":false}),
            );
        }
        require!(
            std::time::Instant::now() < deadline,
            StopUnconfirmed,
            "pilot stop incomplete: owned cleanup was not confirmed"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn operator(args: OperatorArgs) -> Result<()> {
    if let OperatorAction::Watch { refresh_seconds } = args.action {
        return watch::run(args.run, args.home, refresh_seconds);
    }
    operator_to(args, &mut std::io::stdout().lock(), None)
}

fn operator_to(args: OperatorArgs, writer: &mut impl Write, expected: Option<&[u8]>) -> Result<()> {
    let mut output = Output::new(false, operation(&args.action));
    operate(args, &mut output, writer, expected)
}

pub fn operator_json(args: OperatorArgs) -> i32 {
    let mut output = Output::new(true, operation(&args.action));
    let mut writer = std::io::stdout().lock();
    match operate(args, &mut output, &mut writer, None) {
        Ok(()) => 0,
        Err(error) => output.failure(&error, &mut writer),
    }
}

fn operation(action: &OperatorAction) -> &'static str {
    match action {
        OperatorAction::List => "list",
        OperatorAction::Inspect { .. } => "inspect",
        OperatorAction::Approve { .. } => "approve",
        OperatorAction::Reject { .. } => "reject",
        OperatorAction::Stop => "stop",
        OperatorAction::Watch { .. } => "watch",
    }
}

fn verified_identity(run: &Run, bytes: &[u8]) -> Value {
    json!({"run_id": run.run_id, "run_sha256": sha256_hex(bytes),
        "instance_id": run.instance_id, "registry_sha256": run.registry_sha256})
}

fn directory_error(error: anyhow::Error) -> anyhow::Error {
    let missing = error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound);
    tag(
        error,
        if missing {
            Reason::RunUnavailable
        } else {
            Reason::UnsafeRunRecord
        },
    )
}

fn operate(
    args: OperatorArgs,
    output: &mut Output,
    writer: &mut impl Write,
    expected: Option<&[u8]>,
) -> Result<()> {
    require!(
        !matches!(args.action, OperatorAction::Watch { .. }),
        InvalidInput,
        "watch is not a structured result stream"
    );
    require!(
        cfg!(target_os = "linux"),
        UnsupportedPlatform,
        "run-scoped pilot approval requires qualified Linux"
    );
    require!(
        args.run.len() == 32 && args.run.bytes().all(|b| b.is_ascii_hexdigit()),
        InvalidInput,
        "invalid pilot run id"
    );
    let home = match args.home {
        Some(home) => home,
        None => Config::home_path()?,
    }
    .canonicalize()
    .map_err(|error| directory_error(error.into()))?;
    let root = home.join("pilot-runs");
    private_dir(&root).map_err(directory_error)?;
    let dir = root.join(&args.run);
    private_dir(&dir).map_err(directory_error)?;
    let bytes = read_file(&dir.join("run.json"), true)
        .map_err(|error| tag(error, Reason::UnsafeRunRecord))?;
    if let Some(expected) = expected {
        require!(
            bytes == expected,
            SelectionChanged,
            "pilot run identity changed"
        );
    }
    let run: Run = serde_json::from_slice(&bytes)
        .map_err(|error| tag(error.into(), Reason::UnsafeRunRecord))?;
    if matches!(args.action, OperatorAction::Stop) {
        let data = stop(&dir, &run, &bytes, &args.run, &home, output)?;
        return output.emit(&data, "stop_confirmed", "owned_stop_receipt", writer);
    }
    require!(
        !has_stop(&dir)?,
        RunStopping,
        "pilot run is stopping or stopped"
    );
    verify_manifest(&run, &bytes).map_err(|error| tag(error, Reason::UnsafeRunRecord))?;
    require!(
        run.contract == "sw-pilot-run/1"
            && run.run_id == args.run
            && run.home == home
            && run.files.len() == 5
            && run.authorities.len() == 2,
        UnsafeRunRecord,
        "invalid or expired pilot run"
    );
    output.identity = verified_identity(&run, &bytes);
    require!(
        run.expires_at_ms > approval::now_ms(),
        RunExpired,
        "invalid or expired pilot run"
    );
    ensure!(
        process_start(run.launcher_pid)? == run.launcher_start,
        "pilot launcher no longer owns this run"
    );
    for file in &run.files {
        require!(
            sha256_hex(&read_file(&file.path, false)?) == file.sha256,
            SelectionChanged,
            "pilot selection changed; no continuation issued"
        );
    }
    let live = snapshot(&home)?;
    let rows = pending(&run, &live)?;
    if matches!(args.action, OperatorAction::List) {
        let mut summaries = Vec::new();
        for (observed, server) in rows {
            let checked = match checked_record(&home, &observed) {
                Err(error) if output.structured => return Err(error),
                result => result,
            };
            if let Ok(record) = checked {
                summaries.push(json!({"server":server, "tool":record["tool"], "pending_id":record["pending_id"],
                    "binding_sha256":record["binding_sha256"], "expires_at_ms":record["expires_at_ms"], "state":"pending"}));
            }
        }
        return output.emit(&json!(summaries), "listed", "pending_snapshot", writer);
    }
    let identifier = match &args.action {
        OperatorAction::Inspect { id }
        | OperatorAction::Approve { id, .. }
        | OperatorAction::Reject { id, .. } => id.clone(),
        OperatorAction::List | OperatorAction::Stop | OperatorAction::Watch { .. } => {
            unreachable!()
        }
    };
    id(&identifier).map_err(|error| tag(error, Reason::InvalidInput))?;
    let (observed, server) = rows
        .iter()
        .find(|(r, _)| r["pending_id"] == identifier)
        .context("pending call is not owned by this live pilot run")
        .map_err(|error| tag(error, Reason::PendingUnavailable))?;
    let record = checked_record(&home, observed)?;
    let binding = string(&record, "binding_sha256")?;
    output.identity["pending_id"] = json!(identifier);
    output.identity["binding_sha256"] = json!(binding);
    let receipt = dir.join(format!("inspected-{identifier}.json"));
    match args.action {
        OperatorAction::Inspect { .. } => {
            let value = json!({"binding_sha256": binding, "args_sha256": record["args_sha256"],
                "expires_at_ms":record["expires_at_ms"]});
            let data = json!({"server":server,"pending_id":identifier,"tool":record["tool"],
                "args":record["args"],"binding_sha256":binding,"expires_at_ms":record["expires_at_ms"],"state":"pending"});
            let display = output
                .render(&data, "inspection_presented", "exact_pending_arguments")
                .map_err(|error| tag(error, Reason::OutputLimit))?;
            output.emitted = true;
            record_inspection(&dir, &receipt, &value, &display, writer)?;
        }
        OperatorAction::Approve {
            binding: requested, ..
        } => {
            require!(
                requested == binding,
                BindingChanged,
                "binding differs from exact pending call"
            );
            let inspected: Value = serde_json::from_slice(
                &read_file(&receipt, true)
                    .context("inspect this exact call before approval")
                    .map_err(|error| tag(error, Reason::InspectionRequired))?,
            )?;
            require!(
                inspected["binding_sha256"] == binding
                    && inspected["args_sha256"] == record["args_sha256"]
                    && inspected["expires_at_ms"] == record["expires_at_ms"],
                BindingChanged,
                "arguments changed since inspection"
            );
            let submit = if output.structured {
                approval::operator_submit_for_session
            } else {
                approval::operator_approve_for_session
            };
            submit(
                &home,
                &token(&home, "token")?,
                &identifier,
                binding,
                string(&record, "session_id")?,
                string(&record, "session_epoch")?,
            )?;
            let _ = fs::remove_file(receipt);
            output.emit(&json!({"pending_id":identifier,"state":"decision_submitted","decision":"approve","dispatched":"not_observed","released":"not_observed"}),
                "decision_submitted", "approval_submitted", writer)?;
        }
        OperatorAction::Reject {
            binding: requested, ..
        } => {
            require!(
                requested == binding,
                BindingChanged,
                "binding differs from exact pending call"
            );
            approval::operator_reject_for_session(
                &home,
                &identifier,
                binding,
                string(&record, "session_id")?,
                string(&record, "session_epoch")?,
            )?;
            let _ = fs::remove_file(receipt);
            output.emit(
                &json!({"pending_id":identifier,"state":"rejected","released":false}),
                "rejection_submitted",
                "rejection_submitted",
                writer,
            )?;
        }
        OperatorAction::List | OperatorAction::Stop | OperatorAction::Watch { .. } => {
            unreachable!()
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
