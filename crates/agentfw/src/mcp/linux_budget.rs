// SPDX-License-Identifier: Apache-2.0
//! Explicit aggregate limits for the selected Linux MCP sandboxes.
//!
//! The operator prepares delegation. This module changes only one fresh leaf,
//! and never enables controllers, migrates the Agent, or repairs limit drift.
//! A same-UID or privileged host manager is trusted; observations cannot attest
//! to changes made and reverted between samples. No child output is retained.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::ensure;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) const ENVIRONMENT: &str = "AGENTFW_MCP_LINUX_BUDGET";
pub(crate) const FORMAT: &str = "sw-mcp/linux-cgroup-budget/1";
const MAX_CONFIG_BYTES: usize = 16_384;
pub(crate) const CPU_PERIOD_MICROS: u64 = 100_000;
pub(crate) const POLL_MILLIS: u64 = 25;
const CLEANUP_MILLIS: u64 = 3_000;
#[cfg(target_os = "linux")]
const MAX_CONTROL_BYTES: usize = 4_096;
#[cfg(target_os = "linux")]
const MAX_TASKS: usize = 4_096;
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

fn refusal(code: &'static str) -> anyhow::Error {
    anyhow::anyhow!(code)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) format: String,
    pub(crate) delegation_root: PathBuf,
    pub(crate) memory_max_bytes: u64,
    pub(crate) pids_max: u64,
    pub(crate) cpu_quota_micros: u64,
    pub(crate) wall_millis: u64,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxBudgetConfig")
            .field("format", &FORMAT)
            .field("identity", &self.identity())
            .finish_non_exhaustive()
    }
}

impl Config {
    pub(crate) fn load_from_env() -> anyhow::Result<Option<Self>> {
        let Some(path) = std::env::var_os(ENVIRONMENT) else {
            return Ok(None);
        };
        use std::io::Read;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        // Check symlinks on other platforms too. O_NONBLOCK prevents a FIFO
        // from blocking before fstat rejects its type on supported Linux.
        let before =
            std::fs::symlink_metadata(&path).map_err(|_| refusal("mcp_budget_config_invalid"))?;
        ensure!(
            before.is_file() && !before.file_type().is_symlink(),
            "mcp_budget_config_invalid"
        );
        let mut file = options
            .open(&path)
            .map_err(|_| refusal("mcp_budget_config_invalid"))?;
        let metadata = file
            .metadata()
            .map_err(|_| refusal("mcp_budget_config_invalid"))?;
        ensure!(
            metadata.is_file() && metadata.len() <= MAX_CONFIG_BYTES as u64,
            "mcp_budget_config_invalid"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.mode() & 0o022 == 0
                    && metadata.dev() == before.dev()
                    && metadata.ino() == before.ino(),
                "mcp_budget_config_invalid"
            );
        }
        let mut bytes = Vec::with_capacity(MAX_CONFIG_BYTES);
        file.by_ref()
            .take(MAX_CONFIG_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| refusal("mcp_budget_config_invalid"))?;
        Self::read(&bytes).map(Some)
    }

    pub(crate) fn read(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() <= MAX_CONFIG_BYTES, "mcp_budget_config_invalid");
        // The shared strict JSON visitor rejects duplicate keys recursively.
        let super::admission::Strict(value) =
            serde_json::from_slice(bytes).map_err(|_| refusal("mcp_budget_config_invalid"))?;
        let config: Self =
            serde_json::from_value(value).map_err(|_| refusal("mcp_budget_config_invalid"))?;
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        // This describes a Linux path even when parsed on Windows or macOS.
        // Host Path rules would treat /sys/... as drive-relative on Windows and
        // make the same frozen configuration mean different things by host.
        let path = self
            .delegation_root
            .to_str()
            .ok_or_else(|| refusal("mcp_budget_config_invalid"))?;
        let relative = path.strip_prefix("/sys/fs/cgroup/");
        ensure!(
            self.format == FORMAT
                && path.len() <= 4_096
                && !path.contains('\\')
                && !path.chars().any(char::is_control)
                && relative.is_some_and(|relative| {
                    relative
                        .split('/')
                        .all(|part| !part.is_empty() && part != "." && part != "..")
                })
                && (64 * 1024 * 1024..=16 * 1024 * 1024 * 1024).contains(&self.memory_max_bytes)
                && self.memory_max_bytes.is_multiple_of(65_536)
                && (16..=4_096).contains(&self.pids_max)
                && (1_000..=1_600_000).contains(&self.cpu_quota_micros)
                && (1_000..=3_600_000).contains(&self.wall_millis),
            "mcp_budget_config_invalid"
        );
        Ok(())
    }

    pub(crate) fn identity(&self) -> String {
        // The version-1 identity is compact JSON with sorted property names.
        // JSON whitespace and input property order do not change this identity.
        let canonical = std::collections::BTreeMap::from([
            ("format", json!(self.format)),
            ("delegationRoot", json!(self.delegation_root)),
            ("memoryMaxBytes", json!(self.memory_max_bytes)),
            ("pidsMax", json!(self.pids_max)),
            ("cpuQuotaMicros", json!(self.cpu_quota_micros)),
            ("wallMillis", json!(self.wall_millis)),
        ]);
        let bytes = serde_json::to_vec(&canonical).expect("fixed budget fields serialize");
        format!("{:x}", Sha256::digest(bytes))
    }

    fn limits(&self) -> Value {
        json!({"memory_max_bytes":self.memory_max_bytes,
            "memory_swap_max_bytes":0,"pids_max":self.pids_max,
            "cpu_quota_micros":self.cpu_quota_micros,
            "cpu_period_micros":CPU_PERIOD_MICROS,"cpu_burst_micros":0,
            "wall_millis":self.wall_millis,"idle_enforced":false,
            "poll_millis":POLL_MILLIS,"cleanup_millis":CLEANUP_MILLIS})
    }
}

#[derive(Debug, Default, Clone, Serialize)]
struct Stats {
    memory_current_bytes: u64,
    memory_peak_bytes: u64,
    pids_current: u64,
    pids_peak: u64,
    pids_peak_kernel: bool,
    cpu_usage_micros: u64,
    cpu_periods: u64,
    cpu_throttled_periods: u64,
    memory_oom: u64,
    memory_oom_kill: u64,
    pids_max_events: u64,
}

#[derive(Debug)]
struct State {
    stats: Stats,
    reason: &'static str,
    cleanup_verified: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct MembershipFailure {
    phase: &'static str,
    pid: Option<u32>,
    errno: Option<i32>,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct MembershipObservations {
    sampled: std::sync::atomic::AtomicU64,
    departure_candidates: std::sync::atomic::AtomicU64,
    confirmed_departures: std::sync::atomic::AtomicU64,
}

#[cfg(target_os = "linux")]
impl MembershipObservations {
    fn snapshot(&self) -> Value {
        // Counts observations, not unique process identities. Telemetry never
        // feeds authority, membership, limit or cleanup decisions.
        json!({"sampled":self.sampled.load(Ordering::Relaxed),
            "departure_candidates":self.departure_candidates.load(Ordering::Relaxed),
            "confirmed_departures":self.confirmed_departures.load(Ordering::Relaxed)})
    }
}

#[derive(Default)]
struct MembershipFailures(Mutex<Option<MembershipFailure>>);

impl MembershipFailures {
    fn record(&self, phase: &'static str, pid: Option<u32>, errno: Option<i32>) {
        // Cleanup and concurrent observers must not replace the first cause.
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_or_insert(MembershipFailure { phase, pid, errno });
    }

    fn snapshot(&self) -> Option<MembershipFailure> {
        *self.0.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl Default for State {
    fn default() -> Self {
        Self {
            stats: Stats::default(),
            reason: "mcp_budget_enforced",
            cleanup_verified: false,
        }
    }
}

pub(crate) struct OwnedBudget {
    config: Config,
    identity: String,
    leaf: String,
    failure: Arc<AtomicBool>,
    state: Mutex<State>,
    #[cfg(target_os = "linux")]
    linux: linux::Boundary,
}

impl std::fmt::Debug for OwnedBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedLinuxBudget")
            .field("identity", &self.identity)
            .field("leaf", &self.leaf)
            .field("failed", &self.failure.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl OwnedBudget {
    /// Transfer only this owned leaf's cleanup capability to its crash owner.
    /// Quota configuration and live accounting remain in this module.
    #[cfg(target_os = "linux")]
    pub(crate) fn crash_cleanup(
        &self,
    ) -> anyhow::Result<(super::linux_owner::CleanupSpec, Vec<std::fs::File>)> {
        self.linux.crash_cleanup().map_err(refusal)
    }

    pub(crate) fn prepare(config: &Config) -> anyhow::Result<Self> {
        config.validate()?;
        #[cfg(target_os = "linux")]
        {
            let boundary = linux::Boundary::create(config)?;
            let budget = Self {
                config: config.clone(),
                identity: config.identity(),
                leaf: boundary.name.clone(),
                failure: Arc::new(AtomicBool::new(false)),
                state: Mutex::new(State::default()),
                linux: boundary,
            };
            if let Err(code) = budget.linux.configure(config) {
                budget.fail(code);
                return Err(refusal(code));
            }
            budget.check()?;
            Ok(budget)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(refusal("mcp_budget_unsupported"))
        }
    }

    #[cfg(unix)]
    pub(crate) fn attach_fd(&self) -> std::os::fd::RawFd {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            self.linux.procs.as_raw_fd()
        }
        #[cfg(not(target_os = "linux"))]
        {
            -1
        }
    }

    pub(crate) fn failed(&self) -> Arc<AtomicBool> {
        self.failure.clone()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn fail(&self, code: &'static str) {
        // Publish closure before any terminal result is returned. Retain the
        // first cause rather than replacing exhaustion with cleanup metadata.
        self.failure.store(true, Ordering::Release);
        let mut state = self.state();
        if state.reason == "mcp_budget_enforced" {
            state.reason = code;
        }
    }

    fn record(&self, mut stats: Stats) {
        let mut state = self.state();
        stats.pids_peak = stats.pids_peak.max(state.stats.pids_peak);
        state.stats = stats;
    }

    pub(crate) fn verify_attached(&mut self, pid: u32) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            if let Err(code) = self.linux.verify_attached(pid) {
                self.fail(code);
                return Err(refusal(code));
            }
            self.check()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            self.fail("mcp_budget_unsupported");
            Err(refusal("mcp_budget_unsupported"))
        }
    }

    pub(crate) fn check(&self) -> anyhow::Result<()> {
        if self.failure.load(Ordering::Acquire) {
            return Err(refusal(self.state().reason));
        }
        #[cfg(target_os = "linux")]
        {
            match self.linux.observe(&self.config) {
                Ok(stats) => {
                    let code = if stats.memory_oom > 0 || stats.memory_oom_kill > 0 {
                        Some("mcp_budget_memory_exhausted")
                    } else if stats.pids_max_events > 0 {
                        Some("mcp_budget_pids_exhausted")
                    } else if self.linux.started.elapsed()
                        >= std::time::Duration::from_millis(self.config.wall_millis)
                    {
                        Some("mcp_budget_wall_expired")
                    } else {
                        None
                    };
                    self.record(stats);
                    if let Some(code) = code {
                        self.fail(code);
                        return Err(refusal(code));
                    }
                    Ok(())
                }
                Err(code) => {
                    self.fail(code);
                    Err(refusal(code))
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.fail("mcp_budget_unsupported");
            Err(refusal("mcp_budget_unsupported"))
        }
    }

    pub(crate) async fn wait_failure(&self) -> anyhow::Result<()> {
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(POLL_MILLIS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            self.check()?;
        }
    }

    pub(crate) async fn finish(&mut self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            if self.linux.removed {
                return if self.state().cleanup_verified {
                    Ok(())
                } else {
                    Err(refusal("mcp_budget_cleanup_unverified"))
                };
            }
            // Cache last kernel counters even when a previous check has already
            // closed delivery. Reading counters does not restore an invalid limit.
            if let Ok(stats) = self.linux.stats() {
                self.record(stats);
            }
            if self.linux.kill().is_err() {
                self.fail("mcp_budget_cleanup_unverified");
                return Err(refusal("mcp_budget_cleanup_unverified"));
            }
            let deadline =
                tokio::time::Instant::now() + std::time::Duration::from_millis(CLEANUP_MILLIS);
            loop {
                match self.linux.empty() {
                    Ok(true) => {
                        if let Ok(stats) = self.linux.stats() {
                            self.record(stats);
                        }
                        if self.linux.remove().is_ok() {
                            self.state().cleanup_verified = true;
                            return Ok(());
                        }
                    }
                    Ok(false) => {}
                    Err(_) => {
                        self.fail("mcp_budget_cleanup_unverified");
                        return Err(refusal("mcp_budget_cleanup_unverified"));
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    self.fail("mcp_budget_cleanup_unverified");
                    return Err(refusal("mcp_budget_cleanup_unverified"));
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.fail("mcp_budget_unsupported");
            Err(refusal("mcp_budget_unsupported"))
        }
    }

    pub(crate) fn metadata(&self) -> Value {
        let state = self.state();
        #[cfg(target_os = "linux")]
        let membership_failure = self.linux.membership_failures.snapshot();
        #[cfg(target_os = "linux")]
        let membership_observations = Some(self.linux.membership_observations.snapshot());
        #[cfg(not(target_os = "linux"))]
        let membership_observations: Option<Value> = None;
        #[cfg(not(target_os = "linux"))]
        let membership_failure: Option<MembershipFailure> = None;
        json!({"format":FORMAT,"budget_sha256":self.identity,"leaf":self.leaf,
            "limits":self.config.limits(),"reason":state.reason,
            "membership_failure":membership_failure,
            "membership_observations":membership_observations,
            "failed":self.failure.load(Ordering::Acquire),"stats":state.stats,
            "cleanup_verified":state.cleanup_verified})
    }
}

#[cfg(target_os = "linux")]
mod process;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    type Checked<T> = Result<T, &'static str>;
    const CGROUP2_MAGIC: libc::c_long = 0x6367_7270;
    const READ: libc::c_int = libc::O_RDONLY;
    const WRITE: libc::c_int = libc::O_WRONLY;

    fn cstring(bytes: &[u8]) -> Checked<CString> {
        CString::new(bytes).map_err(|_| "mcp_budget_delegation_invalid")
    }

    fn open_at(directory: &File, name: &CStr, flags: libc::c_int) -> Checked<File> {
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err("mcp_budget_observation_failed");
        }
        Ok(unsafe { File::from_raw_fd(raw) })
    }

    fn open_control(directory: &File, name: &'static str, flags: libc::c_int) -> Checked<File> {
        open_at(directory, &cstring(name.as_bytes())?, flags)
    }

    fn directory(path: &Path) -> Checked<(File, File)> {
        // Walk from / using directory-relative, non-following opens. Pin the
        // parent too: a hierarchy root/mount point must never be delegated here.
        let root = CString::new("/").expect("literal path");
        let raw = unsafe { libc::open(root.as_ptr(), READ | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err("mcp_budget_delegation_invalid");
        }
        let mut current = unsafe { File::from_raw_fd(raw) };
        let parts: Vec<_> = path
            .components()
            .filter_map(|part| match part {
                Component::Normal(name) => Some(name),
                _ => None,
            })
            .collect();
        let mut parent = None;
        for (index, part) in parts.iter().enumerate() {
            let next = open_at(
                &current,
                &cstring(part.as_bytes())?,
                READ | libc::O_DIRECTORY,
            )
            .map_err(|_| "mcp_budget_delegation_invalid")?;
            if index + 1 == parts.len() {
                parent = Some(current);
                current = next;
                break;
            }
            current = next;
        }
        Ok((current, parent.ok_or("mcp_budget_delegation_invalid")?))
    }

    fn cgroup_fs(file: &File) -> Checked<()> {
        let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) } != 0
            || unsafe { info.assume_init() }.f_type != CGROUP2_MAGIC
        {
            return Err("mcp_budget_delegation_invalid");
        }
        Ok(())
    }

    fn same(left: &File, right: &File) -> Checked<bool> {
        let left = left
            .metadata()
            .map_err(|_| "mcp_budget_observation_failed")?;
        let right = right
            .metadata()
            .map_err(|_| "mcp_budget_observation_failed")?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }

    pub(super) fn read_record(file: &File, maximum: usize) -> std::io::Result<Vec<u8>> {
        // pread keeps observations independent of earlier reads and never
        // accepts a truncated kernel control record as a complete observation.
        let mut bytes = vec![0_u8; maximum + 1];
        let mut offset = 0;
        loop {
            if offset == bytes.len() {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            let count = unsafe {
                libc::pread(
                    file.as_raw_fd(),
                    bytes[offset..].as_mut_ptr().cast(),
                    bytes.len() - offset,
                    offset as libc::off_t,
                )
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            if count == 0 {
                bytes.truncate(offset);
                return Ok(bytes);
            }
            offset += count as usize;
            if offset > maximum {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
        }
    }

    fn read(file: &File, maximum: usize) -> Checked<Vec<u8>> {
        read_record(file, maximum).map_err(|_| "mcp_budget_observation_failed")
    }

    fn text(file: &File) -> Checked<String> {
        String::from_utf8(read(file, MAX_CONTROL_BYTES)?)
            .map(|value| value.trim().to_owned())
            .map_err(|_| "mcp_budget_observation_failed")
    }

    fn number(file: &File) -> Checked<u64> {
        text(file)?
            .parse::<u64>()
            .map_err(|_| "mcp_budget_observation_failed")
    }

    fn keyed(file: &File) -> Checked<BTreeMap<String, u64>> {
        parse_keyed(&text(file)?)
    }

    pub(super) fn parse_keyed(value: &str) -> Checked<BTreeMap<String, u64>> {
        let mut result = BTreeMap::new();
        for line in value.lines() {
            let mut words = line.split_ascii_whitespace();
            let key = words.next().ok_or("mcp_budget_observation_failed")?;
            let value = words
                .next()
                .ok_or("mcp_budget_observation_failed")?
                .parse::<u64>()
                .map_err(|_| "mcp_budget_observation_failed")?;
            if words.next().is_some() || result.insert(key.to_owned(), value).is_some() {
                return Err("mcp_budget_observation_failed");
            }
        }
        Ok(result)
    }

    fn required(values: &BTreeMap<String, u64>, name: &str) -> Checked<u64> {
        values
            .get(name)
            .copied()
            .ok_or("mcp_budget_observation_failed")
    }

    fn write_control(file: &File, value: &str) -> Checked<()> {
        // Each cgroup write is one complete record; retrying a partial record
        // would create an independent command, so reject it.
        loop {
            let count =
                unsafe { libc::write(file.as_raw_fd(), value.as_ptr().cast(), value.len()) };
            if count == value.len() as isize {
                return Ok(());
            }
            if count < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err("mcp_budget_setup_failed");
        }
    }

    struct Controls {
        memory_max: File,
        memory_swap: File,
        memory_oom_group: File,
        pids_max: File,
        cpu_max: File,
        cpu_burst: Option<File>,
        memory_current: File,
        memory_peak: File,
        pids_current: File,
        pids_peak: Option<File>,
        memory_events: File,
        pids_events: File,
        cpu_stat: File,
        events: File,
        group_type: File,
        subtree: File,
    }

    pub(super) struct Boundary {
        config_root: PathBuf,
        root: File,
        leaf: File,
        pub(super) name: String,
        pub(super) procs: File,
        kill: File,
        root_controllers: File,
        root_subtree: File,
        root_type: File,
        root_procs: File,
        processes: process::Proc,
        expected_leader: Option<(u32, u64, process::Task)>,
        pub(super) membership_failures: MembershipFailures,
        pub(super) membership_observations: MembershipObservations,
        pub(super) started: std::time::Instant,
        pub(super) removed: bool,
    }

    impl Boundary {
        fn membership_error(
            &self,
            phase: &'static str,
            pid: Option<u32>,
            errno: Option<i32>,
        ) -> &'static str {
            self.membership_failures.record(phase, pid, errno);
            "mcp_budget_membership_unverified"
        }

        pub(super) fn crash_cleanup(
            &self,
        ) -> Checked<(super::super::linux_owner::CleanupSpec, Vec<File>)> {
            self.identity()?;
            let files = vec![
                self.root
                    .try_clone()
                    .map_err(|_| "mcp_budget_observation_failed")?,
                self.leaf
                    .try_clone()
                    .map_err(|_| "mcp_budget_observation_failed")?,
                self.kill
                    .try_clone()
                    .map_err(|_| "mcp_budget_observation_failed")?,
                self.procs
                    .try_clone()
                    .map_err(|_| "mcp_budget_observation_failed")?,
                open_control(&self.leaf, "cgroup.events", READ)?,
            ];
            let metadata = self
                .leaf
                .metadata()
                .map_err(|_| "mcp_budget_observation_failed")?;
            let cleanup = super::super::linux_owner::CleanupSpec {
                root_fd: files[0].as_raw_fd(),
                leaf_fd: files[1].as_raw_fd(),
                kill_fd: files[2].as_raw_fd(),
                procs_fd: files[3].as_raw_fd(),
                events_fd: files[4].as_raw_fd(),
                name: self.name.clone(),
                device: metadata.dev(),
                inode: metadata.ino(),
            };
            Ok((cleanup, files))
        }

        pub(super) fn create(config: &Config) -> anyhow::Result<Self> {
            // Validate procfs/PID-namespace correspondence before creating a leaf.
            let processes =
                process::Proc::open().map_err(|_| refusal("mcp_budget_membership_unverified"))?;
            let (root, parent) = directory(&config.delegation_root).map_err(refusal)?;
            cgroup_fs(&root).map_err(refusal)?;
            cgroup_fs(&parent).map_err(refusal)?;
            let metadata = root
                .metadata()
                .map_err(|_| refusal("mcp_budget_delegation_invalid"))?;
            ensure!(
                metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
                "mcp_budget_delegation_invalid"
            );
            let root_controllers =
                open_control(&root, "cgroup.controllers", READ).map_err(refusal)?;
            let root_subtree =
                open_control(&root, "cgroup.subtree_control", READ).map_err(refusal)?;
            let root_type = open_control(&root, "cgroup.type", READ).map_err(refusal)?;
            let root_procs = open_control(&root, "cgroup.procs", READ).map_err(refusal)?;
            validate_root(&root_controllers, &root_subtree, &root_type, &root_procs)
                .map_err(refusal)?;
            let name = format!("agentfw-mcp-{:032x}", rand::random::<u128>());
            let c_name = cstring(name.as_bytes()).map_err(refusal)?;
            if unsafe { libc::mkdirat(root.as_raw_fd(), c_name.as_ptr(), 0o700) } != 0 {
                return Err(refusal("mcp_budget_setup_failed"));
            }
            // Until a guard exists this fresh, empty leaf must be removed on
            // every failed open. No untrusted process has run at this point.
            let opened = (|| {
                let leaf = open_at(&root, &c_name, READ | libc::O_DIRECTORY)?;
                cgroup_fs(&leaf)?;
                let procs = open_control(&leaf, "cgroup.procs", libc::O_RDWR)?;
                let kill = open_control(&leaf, "cgroup.kill", WRITE)?;
                Ok::<_, &'static str>((leaf, procs, kill))
            })();
            let (leaf, procs, kill) = match opened {
                Ok(opened) => opened,
                Err(code) => {
                    unsafe {
                        libc::unlinkat(root.as_raw_fd(), c_name.as_ptr(), libc::AT_REMOVEDIR)
                    };
                    return Err(refusal(code));
                }
            };
            Ok(Self {
                config_root: config.delegation_root.clone(),
                root,
                leaf,
                name,
                procs,
                kill,
                root_controllers,
                root_subtree,
                root_type,
                root_procs,
                processes,
                expected_leader: None,
                membership_failures: MembershipFailures::default(),
                membership_observations: MembershipObservations::default(),
                started: std::time::Instant::now(),
                removed: false,
            })
        }

        pub(super) fn configure(&self, config: &Config) -> Checked<()> {
            for (name, value) in [
                ("memory.max", config.memory_max_bytes.to_string()),
                ("memory.swap.max", "0".to_owned()),
                ("memory.oom.group", "1".to_owned()),
                ("pids.max", config.pids_max.to_string()),
                (
                    "cpu.max",
                    format!("{} {}", config.cpu_quota_micros, CPU_PERIOD_MICROS),
                ),
            ] {
                write_control(&open_control(&self.leaf, name, WRITE)?, &value)?;
            }
            if let Some(file) = optional_control(&self.leaf, "cpu.max.burst")? {
                write_control(&open_control(&self.leaf, "cpu.max.burst", WRITE)?, "0")?;
                if number(&file)? != 0 {
                    return Err("mcp_budget_limit_drift");
                }
            }
            Ok(())
        }

        fn controls(&self) -> Checked<Controls> {
            let open = |name| open_control(&self.leaf, name, READ);
            Ok(Controls {
                memory_max: open("memory.max")?,
                memory_swap: open("memory.swap.max")?,
                memory_oom_group: open("memory.oom.group")?,
                pids_max: open("pids.max")?,
                cpu_max: open("cpu.max")?,
                cpu_burst: optional_control(&self.leaf, "cpu.max.burst")?,
                memory_current: open("memory.current")?,
                memory_peak: open("memory.peak")?,
                pids_current: open("pids.current")?,
                pids_peak: optional_control(&self.leaf, "pids.peak")?,
                memory_events: open("memory.events")?,
                pids_events: open("pids.events")?,
                cpu_stat: open("cpu.stat")?,
                events: open("cgroup.events")?,
                group_type: open("cgroup.type")?,
                subtree: open("cgroup.subtree_control")?,
            })
        }

        fn identity(&self) -> Checked<()> {
            let (current, _) = directory(&self.config_root)?;
            let metadata = current
                .metadata()
                .map_err(|_| "mcp_budget_observation_failed")?;
            if !same(&self.root, &current)?
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err("mcp_budget_limit_drift");
            }
            let leaf = open_at(
                &self.root,
                &cstring(self.name.as_bytes())?,
                READ | libc::O_DIRECTORY,
            )?;
            if !same(&self.leaf, &leaf)? {
                return Err("mcp_budget_limit_drift");
            }
            Ok(())
        }

        pub(super) fn observe(&self, config: &Config) -> Checked<Stats> {
            self.identity()?;
            validate_root(
                &self.root_controllers,
                &self.root_subtree,
                &self.root_type,
                &self.root_procs,
            )?;
            let controls = self.controls()?;
            if number(&controls.memory_max)? != config.memory_max_bytes
                || number(&controls.memory_swap)? != 0
                || number(&controls.memory_oom_group)? != 1
                || number(&controls.pids_max)? != config.pids_max
                || text(&controls.cpu_max)?
                    != format!("{} {}", config.cpu_quota_micros, CPU_PERIOD_MICROS)
                || controls
                    .cpu_burst
                    .as_ref()
                    .map(number)
                    .transpose()?
                    .unwrap_or(0)
                    != 0
                || text(&controls.group_type)? != "domain"
                || !text(&controls.subtree)?.is_empty()
            {
                return Err("mcp_budget_limit_drift");
            }
            let stats = stats(&controls)?;
            if stats.memory_oom > 0 || stats.memory_oom_kill > 0 || stats.pids_max_events > 0 {
                // A known terminal kernel event already requires withdrawal.
                // Preserve its exact bounded cause before victims concurrently
                // disappear from procfs; no further work will be admitted.
                return Ok(stats);
            }
            if stats.pids_current > config.pids_max {
                return Err(self.membership_error("current_task_count", None, None));
            }
            let members = self.members()?;
            if members.len() > MAX_TASKS || members.len() as u64 > config.pids_max {
                return Err(self.membership_error("member_count", None, None));
            }
            for pid in &members {
                self.member(*pid)?;
            }
            if let Some((pid, _, _)) = &self.expected_leader {
                // Keep the attachment-time lifetime pin; a new process with the
                // same numeric PID (even equal start ticks) is never adopted.
                if !members.contains(pid) && self.member(*pid)? {
                    return Err(self.membership_error(
                        "leader_absent_from_snapshot",
                        Some(*pid),
                        None,
                    ));
                }
            }
            Ok(stats)
        }

        pub(super) fn stats(&self) -> Checked<Stats> {
            stats(&self.controls()?)
        }

        fn members(&self) -> Checked<BTreeSet<u32>> {
            let bytes = read(&self.procs, MAX_TASKS * 12)?;
            let value = std::str::from_utf8(&bytes)
                .map_err(|_| self.membership_error("members_utf8", None, None))?;
            let mut members = BTreeSet::new();
            for line in value.lines() {
                let pid = line
                    .parse::<u32>()
                    .map_err(|_| self.membership_error("member_pid_parse", None, None))?;
                if pid == 0 {
                    return Err(self.membership_error("member_zero_pid", None, None));
                }
                // The kernel explicitly permits duplicate entries while
                // processes migrate/exit. The bounded raw record limits work;
                // duplicates themselves do not indicate an ownership failure.
                members.insert(pid);
                if members.len() > MAX_TASKS {
                    return Err(self.membership_error("members_capacity", None, None));
                }
            }
            Ok(members)
        }

        fn process_error(&self, pid: u32, error: process::Error) -> &'static str {
            self.membership_error(error.phase, Some(pid), error.errno)
        }

        fn expected_group(&self, pid: u32) -> Checked<String> {
            let relative = self
                .config_root
                .strip_prefix(CGROUP_ROOT)
                .map_err(|_| self.membership_error("member_root", Some(pid), None))?
                .join(&self.name);
            Ok(format!("0::/{}", relative.to_string_lossy()))
        }

        fn departed(&self, pid: u32, known: Option<&process::Task>) -> Checked<bool> {
            self.membership_observations
                .departure_candidates
                .fetch_add(1, Ordering::Relaxed);
            self.identity()?;
            // Only this same pinned leaf's fresh bounded membership may
            // discharge an exit candidate. No whole-call retry is performed.
            if self.members()?.contains(&pid) {
                return Err(self.membership_error(
                    "member_departure_still_listed",
                    Some(pid),
                    None,
                ));
            }
            self.processes
                .departed(pid, known)
                .map_err(|e| self.process_error(pid, e))?;
            self.membership_observations
                .confirmed_departures
                .fetch_add(1, Ordering::Relaxed);
            Ok(false)
        }

        /// true: a currently verified member; false: confirmed departure.
        fn member(&self, pid: u32) -> Checked<bool> {
            let task = self
                .processes
                .task(pid)
                .map_err(|e| self.process_error(pid, e))?;
            self.member_task(pid, task)
        }

        fn member_task(&self, pid: u32, task: Option<process::Task>) -> Checked<bool> {
            self.membership_observations
                .sampled
                .fetch_add(1, Ordering::Relaxed);
            let known = self
                .expected_leader
                .as_ref()
                .filter(|(leader, _, _)| *leader == pid);
            let Some(task) = task else {
                return self.departed(pid, known.map(|(_, _, task)| task));
            };
            if let Some((_, _, expected)) = known {
                if !task
                    .same(expected)
                    .map_err(|e| self.process_error(pid, e))?
                {
                    return Err(self.membership_error("leader_identity_changed", Some(pid), None));
                }
            }
            let Some((ticks, terminal)) =
                task.identity().map_err(|e| self.process_error(pid, e))?
            else {
                return self.departed(pid, Some(&task));
            };
            if known.is_some_and(|(_, expected_ticks, _)| ticks != *expected_ticks) {
                return Err(self.membership_error("leader_identity_changed", Some(pid), None));
            }
            if terminal {
                return self.departed(pid, Some(&task));
            }
            let Some(group) = task.cgroup().map_err(|e| self.process_error(pid, e))? else {
                return self.departed(pid, Some(&task));
            };
            if group.trim() == self.expected_group(pid)? {
                return Ok(true);
            }
            // A mismatching record can race task exit. Its identity still
            // comes from this same pinned directory, never a reused PID path.
            if task
                .identity()
                .map_err(|e| self.process_error(pid, e))?
                .is_some_and(|(_, terminal)| !terminal)
            {
                return Err(self.membership_error("member_outside_leaf", Some(pid), None));
            }
            self.departed(pid, Some(&task))
        }

        pub(super) fn verify_attached(&mut self, pid: u32) -> Checked<()> {
            let task = self
                .processes
                .task(pid)
                .map_err(|e| self.process_error(pid, e))?
                .ok_or("mcp_budget_attach_unverified")?;
            let (ticks, terminal) = task
                .identity()
                .map_err(|e| self.process_error(pid, e))?
                .ok_or("mcp_budget_attach_unverified")?;
            let expected = self.expected_group(pid)?;
            if terminal
                || !self.members()?.contains(&pid)
                || task
                    .cgroup()
                    .map_err(|e| self.process_error(pid, e))?
                    .is_none_or(|group| group.trim() != expected)
            {
                return Err("mcp_budget_attach_unverified");
            }
            self.expected_leader = Some((pid, ticks, task));
            Ok(())
        }

        pub(super) fn kill(&self) -> Checked<()> {
            write_control(&self.kill, "1")
        }

        pub(super) fn empty(&self) -> Checked<bool> {
            let events = open_control(&self.leaf, "cgroup.events", READ)?;
            Ok(required(&keyed(&events)?, "populated")? == 0 && self.members()?.is_empty())
        }

        pub(super) fn remove(&mut self) -> Checked<()> {
            // Never unlink a replacement with the same name.
            self.identity()?;
            let name = cstring(self.name.as_bytes())?;
            if unsafe { libc::unlinkat(self.root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                != 0
            {
                return Err("mcp_budget_cleanup_unverified");
            }
            self.removed = true;
            Ok(())
        }
    }

    impl Drop for Boundary {
        fn drop(&mut self) {
            if self.removed {
                return;
            }
            let _ = self.kill();
            // Best effort only. Explicit finish is the sole successful cleanup
            // witness; Drop never claims a verified kill or waits without a bound.
            if self.empty().unwrap_or(false) {
                let _ = self.remove();
            }
        }
    }

    fn optional_control(directory: &File, name: &'static str) -> Checked<Option<File>> {
        let name = cstring(name.as_bytes())?;
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                READ | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if raw >= 0 {
            return Ok(Some(unsafe { File::from_raw_fd(raw) }));
        }
        // Capture errno directly at the syscall; helpers or destructors must
        // not turn an unreadable required observation into feature absence.
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err("mcp_budget_observation_failed")
        }
    }

    fn validate_root(
        controllers: &File,
        subtree: &File,
        group_type: &File,
        procs: &File,
    ) -> Checked<()> {
        let controllers = text(controllers)?;
        let subtree = text(subtree)?;
        if text(group_type)? != "domain" || !text(procs)?.is_empty() {
            return Err("mcp_budget_delegation_invalid");
        }
        for required in ["cpu", "memory", "pids"] {
            if !controllers
                .split_ascii_whitespace()
                .any(|name| name == required)
                || !subtree
                    .split_ascii_whitespace()
                    .any(|name| name == required)
            {
                return Err("mcp_budget_controller_unavailable");
            }
        }
        Ok(())
    }

    fn stats(controls: &Controls) -> Checked<Stats> {
        let memory = keyed(&controls.memory_events)?;
        let pids = keyed(&controls.pids_events)?;
        let cpu = keyed(&controls.cpu_stat)?;
        let current = number(&controls.pids_current)?;
        let populated = required(&keyed(&controls.events)?, "populated")?;
        if populated > 1 {
            return Err("mcp_budget_observation_failed");
        }
        Ok(Stats {
            memory_current_bytes: number(&controls.memory_current)?,
            memory_peak_bytes: number(&controls.memory_peak)?,
            pids_current: current,
            pids_peak: controls
                .pids_peak
                .as_ref()
                .map(number)
                .transpose()?
                .unwrap_or(current),
            pids_peak_kernel: controls.pids_peak.is_some(),
            cpu_usage_micros: required(&cpu, "usage_usec")?,
            cpu_periods: required(&cpu, "nr_periods")?,
            cpu_throttled_periods: required(&cpu, "nr_throttled")?,
            memory_oom: required(&memory, "oom")?,
            memory_oom_kill: required(&memory, "oom_kill")?,
            pids_max_events: required(&pids, "max")?,
        })
    }

    #[cfg(test)]
    mod process_record_tests {
        use super::*;

        struct TestChild(std::process::Child);
        impl Drop for TestChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        #[test]
        fn pinned_proc_records_report_a_reaped_task_without_hiding_control_errors() {
            let mut child = TestChild(
                std::process::Command::new("/bin/sleep")
                    .arg("30")
                    .spawn()
                    .unwrap(),
            );
            let pid = child.0.id();
            let records = [
                File::open(format!("/proc/{pid}/cgroup")).unwrap(),
                File::open(format!("/proc/{pid}/stat")).unwrap(),
            ];
            let processes = process::Proc::open().unwrap();
            let task = processes.task(pid).unwrap().unwrap();
            assert!(task.identity().unwrap().is_some());
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            assert!(task.cgroup().unwrap().is_none());
            assert!(task.identity().unwrap().is_none());
            processes.departed(pid, Some(&task)).unwrap();
            for file in records {
                assert_eq!(
                    read_record(&file, MAX_CONTROL_BYTES)
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::ESRCH),
                    "the real pinned procfs record must identify its departed task"
                );

                assert_eq!(
                    read(&file, MAX_CONTROL_BYTES),
                    Err("mcp_budget_observation_failed"),
                    "ordinary controller observations never waive ESRCH"
                );
            }
        }

        fn observation_fixture() -> (tempfile::TempDir, Boundary) {
            // Only the member observation is exercised here. Controller setup
            // is deliberately not represented as a real cgroup containment test.
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(
                root.path(),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            let leaf_path = root.path().join("owned-observation");
            std::fs::create_dir(&leaf_path).unwrap();
            let procs = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(leaf_path.join("cgroup.procs"))
                .unwrap();
            let stub = tempfile::tempfile().unwrap();
            let boundary = Boundary {
                config_root: root.path().canonicalize().unwrap(),
                root: File::open(root.path()).unwrap(),
                leaf: File::open(&leaf_path).unwrap(),
                name: "owned-observation".into(),
                procs,
                kill: stub.try_clone().unwrap(),
                root_controllers: stub.try_clone().unwrap(),
                root_subtree: stub.try_clone().unwrap(),
                root_type: stub.try_clone().unwrap(),
                root_procs: stub,
                processes: process::Proc::open().unwrap(),
                expected_leader: None,
                membership_failures: MembershipFailures::default(),
                membership_observations: MembershipObservations::default(),
                started: std::time::Instant::now(),
                removed: false,
            };
            boundary.identity().unwrap();
            (root, boundary)
        }

        #[test]
        fn sou136_regression_enumerated_exit_before_member_open() {
            let (_root, boundary) = observation_fixture();
            let mut child = TestChild(
                std::process::Command::new("/bin/sleep")
                    .arg("30")
                    .spawn()
                    .unwrap(),
            );
            let pid = child.0.id();
            write_control(&boundary.procs, &format!("{pid}\n")).unwrap();
            let members = boundary.members().unwrap();
            assert!(members.contains(&pid));
            let pinned = boundary.processes.task(pid).unwrap().unwrap();
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            boundary.procs.set_len(0).unwrap();
            // Real procfs directory is held across exit/reap; opening its child
            // record now observes the same kernel boundary as the retained ESRCH.
            assert!(!boundary.member_task(pid, Some(pinned)).unwrap());
            assert!(!boundary.member(pid).unwrap());
            assert!(boundary.membership_failures.snapshot().is_none());
            assert_eq!(
                boundary.membership_observations.snapshot()["confirmed_departures"],
                2
            );
        }

        #[test]
        fn sou136_departure_still_listed_or_unreadable_must_refuse() {
            for malformed in [false, true] {
                let (_root, boundary) = observation_fixture();
                let mut child = TestChild(
                    std::process::Command::new("/bin/sleep")
                        .arg("30")
                        .spawn()
                        .unwrap(),
                );
                let pid = child.0.id();
                let pinned = boundary.processes.task(pid).unwrap().unwrap();
                child.0.kill().unwrap();
                child.0.wait().unwrap();
                let record = if malformed {
                    "unreadable\n".into()
                } else {
                    format!("{pid}\n")
                };
                std::os::unix::fs::FileExt::write_all_at(&boundary.procs, record.as_bytes(), 0)
                    .unwrap();
                assert_eq!(
                    boundary.member_task(pid, Some(pinned)),
                    Err("mcp_budget_membership_unverified")
                );
                assert_eq!(
                    boundary.membership_failures.snapshot().unwrap().phase,
                    if malformed {
                        "member_pid_parse"
                    } else {
                        "member_departure_still_listed"
                    }
                );
                assert_eq!(
                    boundary.membership_observations.snapshot()["confirmed_departures"],
                    0
                );
            }
        }

        #[tokio::test]
        #[ignore = "requires the explicitly owned delegated native SOU-136 service"]
        async fn native_sou136_membership_violation_refuses_owned_child() {
            use std::os::unix::process::CommandExt;
            let root = PathBuf::from(
                std::env::var_os("SOU136_DELEGATION_ROOT")
                    .expect("explicit owned delegation required"),
            );
            let config = Config {
                format: FORMAT.into(),
                delegation_root: root.clone(),
                memory_max_bytes: 512 * 1024 * 1024,
                pids_max: 64,
                cpu_quota_micros: 100_000,
                wall_millis: 120_000,
            };
            config.validate().unwrap();
            let mut budget = OwnedBudget::prepare(&config).unwrap();
            let leaf_name = budget.leaf.clone();
            let quarantine_name = format!("sou136-quarantine-{:032x}", rand::random::<u128>());
            let quarantine = root.join(&quarantine_name);
            std::fs::create_dir(&quarantine).unwrap();
            let quarantine_directory = File::open(&quarantine).unwrap();
            cgroup_fs(&quarantine_directory).unwrap();
            let destination = open_control(&quarantine_directory, "cgroup.procs", WRITE).unwrap();
            let attach = budget.attach_fd();
            let mut command = std::process::Command::new("/bin/sleep");
            command.arg("30");
            // This fixed owned calibration child attaches itself before exec.
            // Parent is the sole reaper and retains Child until after migration;
            // a pidfd alone would not reserve a numeric PID for cgroup.procs.
            unsafe {
                command.pre_exec(move || {
                    if libc::write(attach, b"0".as_ptr().cast(), 1) != 1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = TestChild(command.spawn().unwrap());
            let pid = child.0.id();
            budget.verify_attached(pid).unwrap();
            let task = budget.linux.processes.task(pid).unwrap().unwrap();
            let before = task.identity().unwrap().unwrap();
            assert!(!before.1);
            assert!(child.0.try_wait().unwrap().is_none());
            write_control(&destination, &pid.to_string()).unwrap();
            let after = task.identity().unwrap().unwrap();
            assert_eq!(before, after);
            assert!(child.0.try_wait().unwrap().is_none());
            assert_eq!(
                task.cgroup().unwrap().unwrap().trim(),
                format!(
                    "0::/{}",
                    quarantine
                        .strip_prefix(CGROUP_ROOT)
                        .unwrap()
                        .to_string_lossy()
                )
            );
            let refused = budget.check().unwrap_err();
            assert_eq!(refused.to_string(), "mcp_budget_membership_unverified");
            assert!(budget.failed().load(Ordering::Acquire));
            let diagnostic = budget.linux.membership_failures.snapshot().unwrap();
            assert_eq!(diagnostic.phase, "member_outside_leaf");
            // This is owned fixture cleanup, not a claim that production
            // namespace cleanup can kill an escaped unrelated process.
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            budget.finish().await.unwrap();
            assert!(
                text(&open_control(&quarantine_directory, "cgroup.procs", READ).unwrap())
                    .unwrap()
                    .is_empty()
            );
            drop(destination);
            drop(quarantine_directory);
            std::fs::remove_dir(&quarantine).unwrap();
            assert!(!root.join(leaf_name).exists() && !quarantine.exists());
            println!(
                "{}",
                json!({"event":"sou136_membership_calibration","passed":true,
                "phase":"member_outside_leaf","leader_same_lifetime":true,
                "limits_unchanged":true,"owned_child_reaped":true,"leaf_removed":true,
                "quarantine_removed":true,"production_transport_claimed":false})
            );
        }

        #[test]
        fn sou136_a_live_foreign_member_is_not_an_exit() {
            let (_root, mut boundary) = observation_fixture();
            // Isolate the live-foreign branch; no real leaf or controllers are
            // claimed by this fixture. Full native calibration is separate.
            boundary.config_root = PathBuf::from("/sys/fs/cgroup/observation-only");
            assert_eq!(
                boundary.member(std::process::id()),
                Err("mcp_budget_membership_unverified")
            );
            assert_eq!(
                boundary.membership_failures.snapshot().unwrap().phase,
                "member_outside_leaf"
            );
        }

        #[test]
        fn live_records_bounds_and_other_read_errors_remain_strict() {
            let processes = process::Proc::open().unwrap();
            let live = processes.task(std::process::id()).unwrap().unwrap();
            assert!(!live.cgroup().unwrap().unwrap().is_empty());
            assert!(processes.departed(std::process::id(), Some(&live)).is_err());
            let directory = tempfile::tempdir().unwrap();
            assert_eq!(
                read(&File::open(directory.path()).unwrap(), MAX_CONTROL_BYTES),
                Err("mcp_budget_observation_failed")
            );
            let oversized = tempfile::tempfile().unwrap();
            oversized.set_len((MAX_CONTROL_BYTES + 1) as u64).unwrap();
            assert_eq!(
                read_record(&oversized, MAX_CONTROL_BYTES)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidData
            );
            assert_eq!(
                read(&oversized, MAX_CONTROL_BYTES),
                Err("mcp_budget_observation_failed")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_membership_diagnostic_survives_concurrent_cleanup_observations() {
        let failures = Arc::new(MembershipFailures::default());
        assert!(failures.snapshot().is_none());
        // Synthetic numeric errno: this recorder also compiles on non-Unix hosts.
        failures.record("member_open", Some(123), Some(13));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let failures = Arc::clone(&failures);
                scope.spawn(move || {
                    failures.record("members_capacity", None, None);
                });
            }
        });
        let value = serde_json::to_value(failures.snapshot()).unwrap();
        assert_eq!(value, json!({"phase":"member_open", "pid":123, "errno":13}));
        assert_eq!(value.as_object().unwrap().len(), 3);
    }

    fn valid() -> Value {
        json!({"format":FORMAT,"delegationRoot":"/sys/fs/cgroup/owned/budgets",
            "memoryMaxBytes":268435456,"pidsMax":64,
            "cpuQuotaMicros":50000,"wallMillis":120000})
    }

    #[test]
    fn budget_identity_ignores_input_order_and_whitespace() {
        let config = Config::read(valid().to_string().as_bytes()).unwrap();
        let reordered = format!(
            "{{ \"wallMillis\":120000,\"pidsMax\":64,\"memoryMaxBytes\":268435456,\"delegationRoot\":\"/sys/fs/cgroup/owned/budgets\",\"format\":\"{FORMAT}\",\"cpuQuotaMicros\":50000 }}"
        );
        assert_eq!(
            config.identity(),
            Config::read(reordered.as_bytes()).unwrap().identity()
        );
        assert_eq!(config.identity().len(), 64);
        assert!(!format!("{config:?}").contains("/sys/fs/cgroup/owned"));
    }

    #[test]
    fn budget_parser_rejects_ambiguous_or_incomplete_configuration() {
        for input in [
            b"{}".as_slice(),
            b"null",
            b"[]",
            b"{\"format\":\"x\",\"format\":\"y\"}",
            b"{\"nested\":{\"x\":1,\"x\":2}}",
        ] {
            assert!(Config::read(input).is_err());
        }
        for key in [
            "format",
            "delegationRoot",
            "memoryMaxBytes",
            "pidsMax",
            "cpuQuotaMicros",
            "wallMillis",
        ] {
            let mut value = valid();
            value.as_object_mut().unwrap().remove(key);
            assert!(Config::read(value.to_string().as_bytes()).is_err());
        }
        let mut value = valid();
        value["futureSetting"] = json!(1);
        assert!(Config::read(value.to_string().as_bytes()).is_err());
        assert!(Config::read(&vec![b' '; MAX_CONFIG_BYTES + 1]).is_err());
    }

    #[test]
    fn budget_ranges_and_units_are_frozen() {
        for (key, rejected) in [
            (
                "memoryMaxBytes",
                vec![
                    json!(0),
                    json!(67108863),
                    json!(67108865),
                    json!(17179934720_u64),
                ],
            ),
            (
                "pidsMax",
                vec![json!(0), json!(15), json!(4097), json!(64.0)],
            ),
            (
                "cpuQuotaMicros",
                vec![json!(0), json!(999), json!(1600001), json!("50000")],
            ),
            (
                "wallMillis",
                vec![json!(0), json!(999), json!(3600001), json!(null)],
            ),
        ] {
            for item in rejected {
                let mut value = valid();
                value[key] = item;
                assert!(
                    Config::read(value.to_string().as_bytes()).is_err(),
                    "accepted {key}"
                );
            }
        }
        for (memory, pids, quota, wall) in [
            (67108864_u64, 16, 1000, 1000),
            (17179869184, 4096, 1600000, 3600000),
        ] {
            let mut value = valid();
            value["memoryMaxBytes"] = json!(memory);
            value["pidsMax"] = json!(pids);
            value["cpuQuotaMicros"] = json!(quota);
            value["wallMillis"] = json!(wall);
            assert!(Config::read(value.to_string().as_bytes()).is_ok());
        }
    }

    #[test]
    fn budget_root_cannot_select_global_or_ambiguous_locations() {
        for root in [
            "/",
            "/sys/fs/cgroup",
            "/tmp/owned",
            "relative",
            "/sys/fs/cgroup/../escape",
            "/sys/fs/cgroup/./owned",
            "/sys/fs/cgroup//owned",
            "/sys/fs/cgroup/owned/",
            "/sys/fs/cgroup/owned/./leaf",
            "/sys/fs/cgroup/owned/../leaf",
            "/sys/fs/cgroup/owned\\leaf",
            "/sys/fs/cgroup/",
            "C:\\sys\\fs\\cgroup\\owned",
            "/sys/fs/cgroup/owned\n",
        ] {
            let mut value = valid();
            value["delegationRoot"] = json!(root);
            assert!(Config::read(value.to_string().as_bytes()).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_keyed_records_reject_duplicates_missing_values_and_nonintegers() {
        for value in ["oom", "oom 1 2", "oom -1", "oom 1\noom 2", "oom x"] {
            assert!(linux::parse_keyed(value).is_err());
        }
        let parsed = linux::parse_keyed("oom 0\noom_kill 1\n").unwrap();
        assert_eq!(parsed.get("oom_kill"), Some(&1));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn requested_kernel_budget_has_no_unenforced_platform_fallback() {
        let config = Config::read(valid().to_string().as_bytes()).unwrap();
        assert_eq!(
            OwnedBudget::prepare(&config).unwrap_err().to_string(),
            "mcp_budget_unsupported"
        );
    }
}
