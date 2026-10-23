// SPDX-License-Identifier: Apache-2.0
//! Run selection for the existing native approval broker. No bearer authority is persisted here.

use crate::{
    native::{approval, child_authority},
    pilot_launcher::ValidatedConfig,
    Config,
};
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

const MAX_RUNS: usize = 16;
const MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Args)]
pub struct OperatorArgs {
    /// Run identity printed by pilot-launch, not a caller-selected session label.
    #[arg(long)]
    pub run: String,
    #[arg(long)]
    pub home: Option<PathBuf>,
    #[command(subcommand)]
    pub action: OperatorAction,
}

#[derive(Subcommand)]
pub enum OperatorAction {
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
fn manifest() -> Result<fs::File> {
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
    use std::os::fd::AsRawFd;
    file.write_all(&serde_json::to_vec(run)?)?;
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
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    ensure!(run.manifest_fd >= 3, "invalid sealed manifest descriptor");
    ensure!(
        process_start(run.launcher_pid)? == run.launcher_start,
        "pilot launcher identity changed"
    );
    let owner = fs::metadata(format!("/proc/{}", run.launcher_pid))?;
    ensure!(
        owner.uid() == unsafe { libc::getuid() },
        "pilot launcher owner mismatch"
    );
    let process_exe = fs::metadata(format!("/proc/{}/exe", run.launcher_pid))?;
    let selected_exe = fs::metadata(std::env::current_exe()?)?;
    ensure!(
        process_exe.dev() == selected_exe.dev() && process_exe.ino() == selected_exe.ino(),
        "pilot launcher executable differs from this operator CLI"
    );
    let file = fs::File::open(format!("/proc/{}/fd/{}", run.launcher_pid, run.manifest_fd))?;
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

fn descriptor(file: &fs::File) -> i32 {
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

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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

fn process_start(pid: u32) -> Result<u64> {
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
                .context("live daemon unavailable; no approval issued")?;
            ensure!(
                response.status().is_success(),
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
                        digest(child_authority::encode_token(grant).as_bytes()),
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
                    sha256: digest(&read_file(&path, false)?),
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
    /// Never broad-cancel a host/session label. Only retire exact observed bindings.
    pub fn finish(&self, host_stopped: bool) -> Result<()> {
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
            if !owned && !pending {
                if has_stop(&self.dir)? {
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
                } else {
                    fs::remove_dir_all(&self.dir).context("owned run metadata cleanup failed")?;
                }
                return Ok(());
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

fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .context("incomplete trusted operator identity")
}

fn pending(run: &Run, live: &Value) -> Result<Vec<(Value, String)>> {
    ensure!(
        live["instance_id"] == run.instance_id && live["registry_sha256"] == run.registry_sha256,
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
    let value: Value = serde_json::from_slice(&read_file(
        &approval::pending_dir(home).join(format!("{identifier}.json")),
        true,
    )?)?;
    for key in [
        "pending_id",
        "session_id",
        "session_epoch",
        "tool",
        "binding_sha256",
        "args_sha256",
    ] {
        ensure!(
            value[key] == observed[key] && value[key].is_string(),
            "pending identity changed; inspect again"
        );
    }
    ensure!(
        crate::native::canonical_digest(&value["args"]) == string(observed, "args_sha256")?,
        "pending arguments differ from the daemon's original call"
    );
    ensure!(
        value["scope"] == "native-mcp/approval/v1"
            && value["expires_at_ms"] == observed["expires_at_ms"]
            && value["expires_at_ms"]
                .as_u64()
                .is_some_and(|t| t > approval::now_ms()),
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
            && marker.run_sha256 == digest(bytes)
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
        run_sha256: digest(bytes),
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
    writeln!(terminal, "{display}")?;
    terminal.flush()?;
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
        digest(&bytes) == identity.sha256,
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
                .await?;
            ensure!(
                response.status().is_success(),
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
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, run.launcher_pid, 0) as i32 };
    ensure!(fd >= 0, "pilot stop cannot pin launcher identity");
    let file = unsafe { fs::File::from_raw_fd(fd) };
    ensure!(
        process_start(run.launcher_pid)? == run.launcher_start,
        "pilot stop launcher identity changed"
    );
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn launcher_handle(_run: &Run) -> Result<fs::File> {
    anyhow::bail!("pilot stop requires qualified Linux")
}

#[cfg(target_os = "linux")]
fn signal_launcher(handle: &fs::File) -> Result<()> {
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

fn stop(dir: &Path, run: &Run, bytes: &[u8], expected: &str, home: &Path) -> Result<()> {
    ensure!(
        run.contract == "sw-pilot-run/1"
            && run.run_id == expected
            && run.home == home
            && run.authorities.len() == 2,
        "invalid pilot stop ownership"
    );
    let existing = if has_stop(dir)? {
        Some(read_stop(dir, run, bytes)?)
    } else {
        None
    };
    if existing
        .as_ref()
        .is_some_and(|marker| marker.status == "stopped")
    {
        println!(
            "{}",
            json!({"run":run.run_id,"status":"already_stopped","running_effects_rolled_back":false})
        );
        return Ok(());
    }
    // A stale/forged durable record is never sufficient to signal a process.
    // Pin the live owner before revocation; pidfd prevents PID reuse during the request.
    let handle = launcher_handle(run).with_context(|| {
        if existing.is_some() {
            "pilot stop incomplete: recorded request has no confirmed live launcher"
        } else {
            "pilot stop unknown ownership: launcher identity is unavailable"
        }
    })?;
    verify_manifest(run, bytes)
        .context("pilot stop unknown ownership: sealed owner verification failed")?;
    write_stop(dir, run, bytes, "requested")?;
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
            println!(
                "{}",
                json!({"run":run.run_id,"status":"stopped","running_effects_rolled_back":false})
            );
            return Ok(());
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "pilot stop incomplete: owned cleanup was not confirmed"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn operator(args: OperatorArgs) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "run-scoped pilot approval requires qualified Linux"
    );
    ensure!(
        args.run.len() == 32 && args.run.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid pilot run id"
    );
    let home = match args.home {
        Some(home) => home,
        None => Config::home_path()?,
    }
    .canonicalize()?;
    let root = home.join("pilot-runs");
    private_dir(&root)?;
    let dir = root.join(&args.run);
    private_dir(&dir)?;
    let bytes = read_file(&dir.join("run.json"), true)?;
    let run: Run = serde_json::from_slice(&bytes)?;
    if matches!(args.action, OperatorAction::Stop) {
        return stop(&dir, &run, &bytes, &args.run, &home);
    }
    ensure!(!has_stop(&dir)?, "pilot run is stopping or stopped");
    verify_manifest(&run, &bytes)?;
    ensure!(
        run.contract == "sw-pilot-run/1"
            && run.run_id == args.run
            && run.home == home
            && run.files.len() == 5
            && run.authorities.len() == 2
            && run.expires_at_ms > approval::now_ms(),
        "invalid or expired pilot run"
    );
    ensure!(
        process_start(run.launcher_pid)? == run.launcher_start,
        "pilot launcher no longer owns this run"
    );
    for file in &run.files {
        ensure!(
            digest(&read_file(&file.path, false)?) == file.sha256,
            "pilot selection changed; no continuation issued"
        );
    }
    let live = snapshot(&home)?;
    let rows = pending(&run, &live)?;
    if matches!(args.action, OperatorAction::List) {
        let mut summaries = Vec::new();
        for (observed, server) in rows {
            if let Ok(record) = checked_record(&home, &observed) {
                summaries.push(json!({"server":server, "tool":record["tool"], "pending_id":record["pending_id"],
                    "binding_sha256":record["binding_sha256"], "expires_at_ms":record["expires_at_ms"], "state":"pending"}));
            }
        }
        println!("{}", escaped(&json!(summaries))?);
        return Ok(());
    }
    let identifier = match &args.action {
        OperatorAction::Inspect { id }
        | OperatorAction::Approve { id, .. }
        | OperatorAction::Reject { id, .. } => id.clone(),
        OperatorAction::List | OperatorAction::Stop => unreachable!(),
    };
    id(&identifier)?;
    let (observed, server) = rows
        .iter()
        .find(|(r, _)| r["pending_id"] == identifier)
        .context("pending call is not owned by this live pilot run")?;
    let record = checked_record(&home, observed)?;
    let binding = string(&record, "binding_sha256")?;
    let receipt = dir.join(format!("inspected-{identifier}.json"));
    match args.action {
        OperatorAction::Inspect { .. } => {
            let value = json!({"binding_sha256": binding, "args_sha256": record["args_sha256"],
                "expires_at_ms":record["expires_at_ms"]});
            let display = escaped(
                &json!({"server":server,"pending_id":identifier,"tool":record["tool"],
                "args":record["args"],"binding_sha256":binding,"expires_at_ms":record["expires_at_ms"],"state":"pending"}),
            )?;
            let mut terminal = std::io::stdout().lock();
            record_inspection(&dir, &receipt, &value, &display, &mut terminal)?;
        }
        OperatorAction::Approve {
            binding: requested, ..
        } => {
            ensure!(
                requested == binding,
                "binding differs from exact pending call"
            );
            let inspected: Value = serde_json::from_slice(
                &read_file(&receipt, true).context("inspect this exact call before approval")?,
            )?;
            ensure!(
                inspected["binding_sha256"] == binding
                    && inspected["args_sha256"] == record["args_sha256"]
                    && inspected["expires_at_ms"] == record["expires_at_ms"],
                "arguments changed since inspection"
            );
            approval::operator_approve_for_session(
                &home,
                &token(&home, "token")?,
                &identifier,
                binding,
                string(&record, "session_id")?,
                string(&record, "session_epoch")?,
            )?;
            let _ = fs::remove_file(receipt);
            println!(
                "{}",
                json!({"pending_id":identifier,"state":"decision_submitted","decision":"approve","dispatched":"not_observed","released":"not_observed"})
            );
        }
        OperatorAction::Reject {
            binding: requested, ..
        } => {
            ensure!(
                requested == binding,
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
            println!(
                "{}",
                json!({"pending_id":identifier,"state":"rejected","released":false})
            );
        }
        OperatorAction::List | OperatorAction::Stop => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> Run {
        Run {
            contract: "sw-pilot-run/1".into(),
            run_id: "a".repeat(32),
            home: PathBuf::from("/owned"),
            instance_id: "daemon-one".into(),
            registry_sha256: "b".repeat(64),
            host_session: "host-one".into(),
            launcher_pid: 1,
            launcher_start: 1,
            manifest_fd: 3,
            expires_at_ms: u64::MAX,
            authority_expires_at_ms: u64::MAX,
            authorities: BTreeMap::from([("filesystem".into(), "c".repeat(64))]),
            files: vec![],
        }
    }

    #[test]
    #[cfg(unix)]
    fn stop_receipts_bind_exact_run_bytes_and_authentication_and_never_regress() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        create_dir(&home).unwrap();
        write_new(&home.join("native-token"), &"owned-test-key").unwrap();
        let dir = root.path().join("run");
        create_dir(&dir).unwrap();
        let mut run = run();
        run.home = home;
        let bytes = serde_json::to_vec(&run).unwrap();
        for status in ["requested", "revoked", "stopped"] {
            write_stop(&dir, &run, &bytes, status).unwrap();
            assert_eq!(read_stop(&dir, &run, &bytes).unwrap().status, status);
        }
        write_stop(&dir, &run, &bytes, "requested").unwrap();
        assert_eq!(read_stop(&dir, &run, &bytes).unwrap().status, "stopped");
        assert!(read_stop(&dir, &run, b"foreign run bytes").is_err());
        let mut altered: Value =
            serde_json::from_slice(&fs::read(dir.join("stop.json")).unwrap()).unwrap();
        altered["status"] = json!("revoked");
        fs::write(dir.join("stop.json"), serde_json::to_vec(&altered).unwrap()).unwrap();
        assert!(read_stop(&dir, &run, &bytes).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn linked_stop_receipt_is_never_accepted() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        create_dir(&home).unwrap();
        write_new(&home.join("native-token"), &"owned-test-key").unwrap();
        let dir = root.path().join("run");
        create_dir(&dir).unwrap();
        let mut run = run();
        run.home = home;
        let bytes = serde_json::to_vec(&run).unwrap();
        write_stop(&dir, &run, &bytes, "requested").unwrap();
        fs::rename(dir.join("stop.json"), dir.join("linked.json")).unwrap();
        symlink(dir.join("linked.json"), dir.join("stop.json")).unwrap();
        assert!(read_stop(&dir, &run, &bytes).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn stop_completion_waits_for_an_inflight_metadata_update() {
        use std::sync::mpsc;
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        create_dir(&home).unwrap();
        write_new(&home.join("native-token"), &"owned-test-key").unwrap();
        let dir = root.path().join("run");
        create_dir(&dir).unwrap();
        let mut run = run();
        run.home = home;
        let bytes = serde_json::to_vec(&run).unwrap();
        write_stop(&dir, &run, &bytes, "revoked").unwrap();
        let reservation = lock_dir(&dir).unwrap();
        // A permanently held lock still fails within a declared budget.
        assert!(lock_dir_for(&dir, Duration::from_millis(20)).is_err());
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker_dir = dir.clone();
        let worker_run = run.clone();
        let worker_bytes = bytes.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            done_tx
                .send(write_stop(
                    &worker_dir,
                    &worker_run,
                    &worker_bytes,
                    "stopped",
                ))
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(reservation);
        done_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
        assert_eq!(read_stop(&dir, &run, &bytes).unwrap().status, "stopped");
    }

    #[test]
    #[cfg(unix)]
    fn inspection_output_cannot_lock_out_stop_or_record_after_stop() {
        struct Terminal<'a> {
            dir: &'a Path,
            receipt: &'a Path,
            run: &'a Run,
            bytes: &'a [u8],
            stop_on_flush: bool,
        }
        impl Write for Terminal<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                // Includes an arbitrarily blocked stdout: metadata stays available.
                assert!(lock_dir(self.dir).is_ok());
                assert!(!self.receipt.exists());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                assert!(lock_dir(self.dir).is_ok());
                assert!(!self.receipt.exists());
                if self.stop_on_flush {
                    write_stop(self.dir, self.run, self.bytes, "requested").unwrap();
                }
                Ok(())
            }
        }
        for stop_on_flush in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let home = root.path().join("home");
            create_dir(&home).unwrap();
            write_new(&home.join("native-token"), &"owned-test-key").unwrap();
            let dir = root.path().join("run");
            create_dir(&dir).unwrap();
            let mut run = run();
            run.home = home;
            let bytes = serde_json::to_vec(&run).unwrap();
            let receipt = dir.join("inspected-call.json");
            let mut terminal = Terminal {
                dir: &dir,
                receipt: &receipt,
                run: &run,
                bytes: &bytes,
                stop_on_flush,
            };
            let value = json!({"binding_sha256":"owned", "expires_at_ms":u64::MAX});
            let result = record_inspection(&dir, &receipt, &value, "exact call", &mut terminal);
            assert_eq!(result.is_err(), stop_on_flush);
            assert_eq!(receipt.is_file(), !stop_on_flush);
            if !stop_on_flush {
                assert_eq!(
                    serde_json::from_slice::<Value>(&fs::read(&receipt).unwrap()).unwrap(),
                    value
                );
            }
        }
    }

    #[test]
    fn stop_never_sends_credentials_to_a_changed_daemon_destination() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        let path = home.join("config.yaml");
        write_new(&path, &json!({"bind":"127.0.0.1","port":12345})).unwrap();
        let bytes = fs::read(&path).unwrap();
        let mut run = run();
        run.home = home;
        run.files = vec![FileIdentity {
            path: path.clone(),
            sha256: digest(&bytes),
        }];
        assert!(stop_config(&run).is_ok());
        fs::write(&path, b"bind: 127.0.0.1\nport: 54321\n").unwrap();
        assert!(stop_config(&run).is_err());
    }

    fn live() -> Value {
        json!({"instance_id":"daemon-one","registry_sha256":"b".repeat(64),
            "pilot_collectors":[{"active":true,"host_session":"host-one","server_id":"filesystem","agent_id":"claude-filesystem",
                "authority_sha256":"c".repeat(64),"session_id":"native-one","session_epoch":"epoch-one"}],
            "pilot_pending":[{"pending_id":"pending-one","tool":"read_text_file","binding_sha256":"d".repeat(64),
                "session_id":"native-one","session_epoch":"epoch-one"}]})
    }

    #[test]
    fn base64url_pending_ids_with_leading_hyphens_are_positional_values() {
        use clap::Parser;
        #[derive(Parser)]
        struct TestCli {
            #[command(flatten)]
            args: OperatorArgs,
        }
        for action in ["inspect", "approve", "reject"] {
            for id in ["-owned", "--owned", "_owned"] {
                let mut words = vec![
                    "operator".to_string(),
                    "--run".into(),
                    "a".repeat(32),
                    action.into(),
                    id.into(),
                ];
                if action != "inspect" {
                    words.extend(["--binding".into(), "b".repeat(64)]);
                }
                let parsed = TestCli::try_parse_from(words).expect("valid broker id must parse");
                let parsed_id = match parsed.args.action {
                    OperatorAction::Inspect { id }
                    | OperatorAction::Approve { id, .. }
                    | OperatorAction::Reject { id, .. } => id,
                    OperatorAction::List | OperatorAction::Stop => unreachable!(),
                };
                assert_eq!(parsed_id, id);
            }
        }
    }

    #[test]
    fn run_selection_requires_all_authenticated_identities() {
        assert_eq!(pending(&run(), &live()).unwrap().len(), 1);
        for (key, value) in [
            ("host_session", "other-host"),
            ("server_id", "git"),
            ("agent_id", "claude-git"),
            ("authority_sha256", "different-grant"),
            ("session_id", "foreign-collector"),
            ("session_epoch", "old-epoch"),
        ] {
            let mut value_live = live();
            value_live["pilot_collectors"][0][key] = json!(value);
            assert!(
                pending(&run(), &value_live).unwrap().is_empty(),
                "{key} must be authoritative"
            );
        }
        for key in ["instance_id", "registry_sha256"] {
            let mut other = live();
            other[key] = json!("changed");
            assert!(pending(&run(), &other).is_err());
        }
        let mut expired = live();
        expired["pilot_collectors"][0]["active"] = json!(false);
        assert!(pending(&run(), &expired).unwrap().is_empty());
    }

    #[test]
    fn same_label_cannot_select_another_runs_grant() {
        let mut value = live();
        let mut foreign = value["pilot_collectors"][0].clone();
        foreign["authority_sha256"] = json!("e".repeat(64));
        value["pilot_collectors"] = json!([foreign]);
        assert!(pending(&run(), &value).unwrap().is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn raw_arguments_cannot_change_behind_a_trusted_binding() {
        let dir = tempfile::tempdir().unwrap();
        create_dir(&approval::pending_dir(dir.path())).unwrap();
        let args = json!({"path":"/workspace/approved.txt"});
        let observed = json!({"pending_id":"pending-one","session_id":"native-one","session_epoch":"epoch-one",
            "tool":"read_text_file","binding_sha256":"d".repeat(64), "args_sha256":crate::native::canonical_digest(&args)});
        let mut observed = observed;
        observed["expires_at_ms"] = json!(approval::now_ms() + 10_000);
        let mut file = observed.clone();
        file["args"] = args;
        file["scope"] = json!("native-mcp/approval/v1");
        file["expires_at_ms"] = observed["expires_at_ms"].clone();
        let path = approval::pending_dir(dir.path()).join("pending-one.json");
        write_new(&path, &file).unwrap();
        assert!(checked_record(dir.path(), &observed).is_ok());
        for key in [
            "session_id",
            "session_epoch",
            "binding_sha256",
            "args_sha256",
        ] {
            let mut tampered = file.clone();
            tampered[key] = json!("foreign");
            fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
            assert!(checked_record(dir.path(), &observed).is_err(), "{key}");
        }
        file["args"] = json!({"path":"/workspace/other.txt"});
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(checked_record(dir.path(), &observed).is_err());
    }

    #[test]
    fn terminal_control_and_bidi_are_escaped_even_in_explicit_inspection() {
        let text = escaped(&json!({"args":{"text":"\u{1b}[31m\u{9b}31m\u{202e}spoof\u{2066}end"}}))
            .unwrap();
        for c in ['\u{1b}', '\u{9b}', '\u{202e}', '\u{2066}'] {
            assert!(!text.contains(c));
        }
        assert!(text.contains("\\u001b") && text.contains("\\u009b") && text.contains("\\u202e"));
    }

    #[test]
    fn inspection_escapes_invisible_unicode_and_preserves_exact_arguments() {
        let value = json!({"args":{"path":"/workspace/данные\u{ad}\u{180e}😀.txt"}});
        let display = escaped(&value).unwrap();
        assert!(display.is_ascii());
        assert!(display.contains("\\u00ad") && display.contains("\\u180e"));
        assert!(display.contains("\\ud83d\\ude00"));
        assert_eq!(serde_json::from_str::<Value>(&display).unwrap(), value);
    }

    #[test]
    #[cfg(unix)]
    fn private_metadata_rejects_symlinks_and_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record");
        write_new(&path, &json!({"owned":true})).unwrap();
        assert!(read_file(&path, true).is_ok());
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_file(&link, true).is_err());
        }
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_BYTES as u64 + 1)
            .unwrap();
        assert!(read_file(&path, true).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn inspection_pruning_is_bounded_to_own_expired_receipts() {
        let dir = tempfile::tempdir().unwrap();
        write_new(&dir.path().join("run.json"), &json!({"expires_at_ms":0})).unwrap();
        write_new(
            &dir.path().join("inspected-old.json"),
            &json!({"expires_at_ms":0}),
        )
        .unwrap();
        write_new(
            &dir.path().join("inspected-live.json"),
            &json!({"expires_at_ms":u64::MAX}),
        )
        .unwrap();
        write_new(&dir.path().join("other.json"), &json!({"expires_at_ms":0})).unwrap();
        let reservation = lock_dir(dir.path()).unwrap();
        assert!(lock_dir(dir.path()).is_err());
        prune_inspections(dir.path()).unwrap();
        assert!(!dir.path().join("inspected-old.json").exists());
        for name in ["run.json", "inspected-live.json", "other.json"] {
            assert!(dir.path().join(name).is_file());
        }
        drop(reservation);
        assert!(lock_dir(dir.path()).is_ok());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sealed_selection_rejects_disk_tampering_and_lost_launcher_identity() {
        let mut file = manifest().unwrap();
        let mut run = run();
        run.launcher_pid = std::process::id();
        run.launcher_start = process_start(run.launcher_pid).unwrap();
        run.manifest_fd = descriptor(&file);
        seal(&mut file, &run).unwrap();
        let bytes = serde_json::to_vec(&run).unwrap();
        verify_sealed(&run, &bytes).unwrap();
        assert!(
            verify_manifest(&run, &bytes).is_err(),
            "a library test process is not a pilot launcher"
        );
        assert!(file.write_all(b"replacement").is_err());
        let mut changed = run.clone();
        changed.host_session = "other-run".into();
        assert!(verify_sealed(&changed, &serde_json::to_vec(&changed).unwrap()).is_err());
        changed = run.clone();
        changed.launcher_start += 1;
        assert!(verify_sealed(&changed, &serde_json::to_vec(&changed).unwrap()).is_err());
        drop(file);
        assert!(verify_sealed(&run, &bytes).is_err());
    }
}
