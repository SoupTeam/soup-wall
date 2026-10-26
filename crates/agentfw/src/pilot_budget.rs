// SPDX-License-Identifier: Apache-2.0
//! Explicit prepared-pilot budget selection. The accepted cgroup engine owns
//! enforcement and each leaf; this layer binds a frozen selection to one run.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{ensure, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::mcp::linux_budget::{BoundConfig, Config};

pub(crate) const BINDING_ENV: &str = "AGENTFW_PILOT_BUDGET_BINDING";
const FORMAT: &str = "sw-prepared-pilot-budget/1";
const MAX_BYTES: u64 = 16_384;

#[derive(Args, Debug)]
pub struct BudgetArgs {
    /// Explicit operator-owned accepted Linux budget JSON; no ambient fallback.
    #[arg(long, conflicts_with = "binding", required_unless_present = "binding")]
    pub config: Option<PathBuf>,
    /// Inspect one private run binding without starting a process.
    #[arg(long, conflicts_with = "config", required_unless_present = "config")]
    pub binding: Option<PathBuf>,
    /// Check delegated-root capabilities without creating a cgroup or process.
    #[arg(long, requires = "config")]
    pub probe: bool,
}

pub fn inspect(args: BudgetArgs) -> Result<()> {
    if let Some(path) = args.binding {
        println!("{}", summarize(&path)?);
        return Ok(());
    }
    let config = Config::load_file(args.config.as_deref().expect("clap config selection"))?;
    if args.probe {
        let (_lease, root) = lease_root(&config)?;
        probe(&config)?;
        ensure!(
            root_identity(&config.delegation_root)? == root,
            "pilot_budget_root_changed"
        );
    }
    println!(
        "{}",
        json!({"format":FORMAT,"budget_sha256":config.identity(),
        "status":if args.probe {"available-not-active"} else {"selected-not-active"},
        "scope":"per-original-server-process-tree","protected_children_started":false})
    );
    Ok(())
}

fn probe(config: &Config) -> Result<()> {
    config.probe_delegation()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootIdentity {
    device: u64,
    inode: u64,
}

fn root_identity(path: &Path) -> Result<RootIdentity> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        ensure!(path.canonicalize()? == path, "pilot_budget_root_changed");
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(path)?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "pilot_budget_root_invalid"
        );
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        ensure!(
            unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } == 0,
            "pilot_budget_root_invalid"
        );
        ensure!(
            unsafe { stat.assume_init() }.f_type == 0x6367_7270,
            "pilot_budget_root_invalid"
        );
        Ok(RootIdentity {
            device: meta.dev(),
            inode: meta.ino(),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        anyhow::bail!("mcp_budget_unsupported")
    }
}

fn lease_root(config: &Config) -> Result<(File, RootIdentity)> {
    let root = root_identity(&config.delegation_root)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY);
    }
    let lease = options.open(&config.delegation_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = lease.metadata()?;
        ensure!(
            meta.dev() == root.device && meta.ino() == root.inode,
            "pilot_budget_root_changed"
        );
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "pilot_budget_root_busy"
        );
    }
    ensure!(
        fs::read_dir(&config.delegation_root)?.all(
            |entry| entry.is_ok_and(|entry| entry.file_type().is_ok_and(|kind| !kind.is_dir()))
        ),
        "pilot_budget_root_not_empty"
    );
    let mut bytes = Vec::new();
    File::open(config.delegation_root.join("cgroup.procs"))?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES && bytes.iter().all(u8::is_ascii_whitespace),
        "pilot_budget_root_not_empty"
    );
    Ok((lease, root))
}

fn private_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0,
            "pilot_budget_record_busy"
        );
    }
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= MAX_BYTES,
        "pilot_budget_binding_invalid"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "pilot_budget_binding_invalid"
        );
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "pilot_budget_binding_invalid"
    );
    let crate::mcp::admission::Strict(value) = serde_json::from_slice(&bytes)?;
    Ok(serde_json::from_value(value)?)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    format: String,
    host_session: String,
    budget_sha256: String,
    config: PathBuf,
    root: RootIdentity,
    records: PathBuf,
}

/// Root is an operator-owned substrate, never removed or globally repaired.
/// Holding its lock prevents another cooperating prepared run adopting it.
pub struct RunBudget {
    config: Config,
    binding: Binding,
    pub(crate) binding_path: PathBuf,
    _root_lease: File,
}

impl RunBudget {
    pub(crate) fn for_run(
        source: &Path,
        home: &Path,
        host_session: &str,
        expected: &str,
    ) -> Result<Self> {
        ensure!(
            !host_session.is_empty()
                && host_session.len() <= 128
                && host_session
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
            "pilot_budget_run_mismatch"
        );
        private_directory(home)?;
        let parent = home.join("pilot-budgets");
        match fs::create_dir(&parent) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        private_directory(&parent)?;
        let directory = parent.join(host_session);
        fs::create_dir(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let budget = Self::prepare(source, &directory, host_session, expected)?;
        write_json(
            &directory.join("selection-status.json"),
            &budget.descriptor(),
        )?;
        Ok(budget)
    }

    pub(crate) fn prepare(
        source: &Path,
        private: &Path,
        host_session: &str,
        expected: &str,
    ) -> Result<Self> {
        let config = Config::load_file(source)?;
        ensure!(
            config.identity() == expected,
            "pilot_budget_selection_changed"
        );
        let (lease, root) = lease_root(&config)?;
        probe(&config)?;
        ensure!(
            root_identity(&config.delegation_root)? == root,
            "pilot_budget_root_changed"
        );
        let snapshot = private.join("linux-budget.json");
        write_json(&snapshot, &config)?;
        let records = private.join("budget-records");
        fs::create_dir(&records)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&records, fs::Permissions::from_mode(0o700))?;
        }
        let binding = Binding {
            format: FORMAT.into(),
            host_session: host_session.into(),
            budget_sha256: config.identity(),
            config: snapshot,
            root,
            records,
        };
        let binding_path = private.join("linux-budget-binding.json");
        write_json(&binding_path, &binding)?;
        Ok(Self {
            config,
            binding,
            binding_path,
            _root_lease: lease,
        })
    }

    pub(crate) fn config_path(&self) -> &Path {
        &self.binding.config
    }

    pub(crate) fn descriptor(&self) -> Value {
        json!({"format":FORMAT,"status":"configured-not-observed",
            "budget_sha256":self.binding.budget_sha256,
            "scope":"per-original-server-process-tree"})
    }

    pub(crate) fn summary(&self) -> Result<Value> {
        let value = summarize(&self.binding_path)?;
        ensure!(
            value["budget_sha256"] == self.binding.budget_sha256,
            "pilot_budget_selection_changed"
        );
        Ok(value)
    }

    pub(crate) fn verify_root(&self) -> Result<()> {
        ensure!(
            root_identity(&self.config.delegation_root)? == self.binding.root,
            "pilot_budget_root_changed"
        );
        ensure!(
            fs::read_dir(&self.config.delegation_root)?
                .all(|entry| entry
                    .is_ok_and(|entry| entry.file_type().is_ok_and(|kind| !kind.is_dir()))),
            "pilot_budget_cleanup_unverified"
        );
        let mut bytes = Vec::new();
        File::open(self.config.delegation_root.join("cgroup.procs"))?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES && bytes.iter().all(u8::is_ascii_whitespace),
            "pilot_budget_cleanup_unverified"
        );
        Ok(())
    }
}

/// One immutable selection verified before admission. No later environment or
/// pathname read can replace its accepted limits or delegated-root identity.
#[derive(Clone)]
pub struct VerifiedSelection {
    binding: Binding,
    bound: BoundConfig,
    records: Arc<File>,
}

impl VerifiedSelection {
    pub(crate) fn bound(&self) -> &BoundConfig {
        &self.bound
    }
    pub(crate) fn reserve(&self, server_id: &str) -> Result<ChildRecord> {
        ChildRecord::reserve(self.binding.clone(), Arc::clone(&self.records), server_id)
    }
}

/// CLI/environment/digest must agree. The returned immutable selection is moved
/// into admission, rather than re-reading mutable environment/files at spawn.
pub fn verify_launch(
    path: Option<&Path>,
    expected: Option<&str>,
    host_session: Option<&str>,
    server_id: &str,
) -> Result<Option<VerifiedSelection>> {
    let environmental = std::env::var_os(BINDING_ENV);
    if path.is_none() && environmental.is_none() && expected.is_none() {
        return Ok(None);
    }
    ensure!(
        path.is_some() && expected.is_some() && environmental.as_deref().map(Path::new) == path,
        "pilot_budget_binding_required"
    );
    let selected = read_binding(path.expect("checked binding"), host_session, server_id)?;
    ensure!(
        expected == Some(selected.binding.budget_sha256.as_str()),
        "pilot_budget_selection_changed"
    );
    Ok(Some(selected))
}

fn read_binding(
    path: &Path,
    host_session: Option<&str>,
    server_id: &str,
) -> Result<VerifiedSelection> {
    let actual = std::env::var_os(crate::mcp::linux_budget::ENVIRONMENT)
        .ok_or_else(|| anyhow::anyhow!("pilot_budget_selection_missing"))?;
    read_binding_inner(path, host_session, server_id, Some(Path::new(&actual)))
}

pub(crate) fn verify_daemon_launch(
    path: &Path,
    expected: &str,
    host: &str,
    server: &str,
) -> Result<VerifiedSelection> {
    let selected = read_binding_inner(path, Some(host), server, None)?;
    ensure!(
        expected == selected.binding.budget_sha256,
        "pilot_budget_selection_changed"
    );
    Ok(selected)
}

fn read_binding_inner(
    path: &Path,
    host_session: Option<&str>,
    server_id: &str,
    environmental: Option<&Path>,
) -> Result<VerifiedSelection> {
    let binding: Binding = private_json(path)?;
    ensure!(
        binding.format == FORMAT
            && host_session == Some(binding.host_session.as_str())
            && matches!(server_id, "filesystem" | "git"),
        "pilot_budget_run_mismatch"
    );
    ensure!(
        environmental.is_none_or(|actual| actual == binding.config),
        "pilot_budget_selection_changed"
    );
    let config = Config::load_file(&binding.config)?;
    ensure!(
        config.identity() == binding.budget_sha256
            && root_identity(&config.delegation_root)? == binding.root,
        "pilot_budget_selection_changed"
    );
    let directory = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("pilot_budget_binding_invalid"))?;
    ensure!(
        binding.config == directory.join("linux-budget.json")
            && binding.records == directory.join("budget-records"),
        "pilot_budget_binding_invalid"
    );
    private_directory(directory)?;
    let records = pin_records_directory(&binding.records)?;
    Ok(VerifiedSelection {
        bound: BoundConfig {
            config,
            root: (binding.root.device, binding.root.inode),
        },
        binding,
        records,
    })
}

fn pin_records_directory(path: &Path) -> Result<Arc<File>> {
    private_directory(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY);
    }
    let directory = options.open(path)?;
    verify_records_directory(path, &directory)?;
    Ok(Arc::new(directory))
}

fn verify_records_directory(path: &Path, directory: &File) -> Result<()> {
    private_directory(path).map_err(|_| anyhow::anyhow!("pilot_budget_records_replaced"))?;
    let current = fs::symlink_metadata(path)?;
    let held = directory.metadata()?;
    ensure!(
        current.is_dir() && held.is_dir() && !current.file_type().is_symlink(),
        "pilot_budget_records_replaced"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            current.dev() == held.dev()
                && current.ino() == held.ino()
                && held.uid() == unsafe { libc::geteuid() }
                && held.mode() & 0o077 == 0,
            "pilot_budget_records_replaced"
        );
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    ensure!(path.canonicalize()? == path, "pilot_budget_binding_invalid");
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "pilot_budget_binding_invalid"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "pilot_budget_binding_invalid"
        );
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format: String,
    host_session: String,
    server_id: String,
    budget_sha256: String,
    phase: String,
    budget: Option<Value>,
}

pub(crate) struct ChildRecord {
    path: PathBuf,
    directory: Arc<File>,
    value: Record,
    file: File,
}
impl ChildRecord {
    fn reserve(binding: Binding, directory: Arc<File>, server_id: &str) -> Result<Self> {
        let value = Record {
            format: FORMAT.into(),
            host_session: binding.host_session,
            server_id: server_id.into(),
            budget_sha256: binding.budget_sha256,
            phase: "preparing".into(),
            budget: None,
        };
        // Atomic bounded reservation; concurrent children cannot overwrite or
        // exceed the fixed number of retained attempts for this run.
        for index in 0..64 {
            verify_records_directory(&binding.records, &directory)?;
            let name = format!("{index:02}.json");
            let path = binding.records.join(&name);
            #[cfg(unix)]
            let opened = {
                use std::os::fd::{AsRawFd, FromRawFd};
                let name = std::ffi::CString::new(name)?;
                let raw = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDWR
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o600 as libc::c_uint,
                    )
                };
                if raw < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(unsafe { File::from_raw_fd(raw) })
                }
            };
            #[cfg(not(unix))]
            let opened: std::io::Result<File> = {
                let _ = name;
                Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
            };
            match opened {
                Ok(mut file) => {
                    verify_records_directory(&binding.records, &directory)?;
                    file.write_all(&serde_json::to_vec(&value)?)?;
                    file.sync_all()?;
                    return Ok(Self {
                        path,
                        directory,
                        value,
                        file,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("pilot_budget_observation_limit")
    }
    pub(crate) fn record(&mut self, metadata: Value, terminal: bool) -> Result<()> {
        ensure!(
            metadata.get("budget_sha256").and_then(Value::as_str)
                == Some(self.value.budget_sha256.as_str()),
            "pilot_budget_selection_changed"
        );
        let mut next = self.value.clone();
        next.phase = if terminal {
            "closed"
        } else {
            "active-at-attachment"
        }
        .into();
        next.budget = Some(metadata);
        self.write(&next)?;
        self.value = next;
        Ok(())
    }
}
impl ChildRecord {
    fn write(&mut self, value: &Record) -> Result<()> {
        verify_records_directory(
            self.path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("pilot_budget_records_replaced"))?,
            &self.directory,
        )?;
        #[cfg(unix)]
        {
            use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
            let current = fs::symlink_metadata(&self.path)?;
            let held = self.file.metadata()?;
            ensure!(
                current.dev() == held.dev()
                    && current.ino() == held.ino()
                    && current.is_file()
                    && !current.file_type().is_symlink(),
                "pilot_budget_record_replaced"
            );
            ensure!(
                unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "pilot_budget_record_busy"
            );
        }
        // Update only the pinned owned inode. Never rename over an operator's
        // replacement; readers take a shared lock and reject partial data.
        let result = (|| {
            self.file.rewind()?;
            self.file.set_len(0)?;
            self.file.write_all(&serde_json::to_vec(value)?)?;
            self.file.sync_all()?;
            Ok(())
        })();
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
        result
    }
}

impl Drop for ChildRecord {
    fn drop(&mut self) {
        if self.value.phase != "closed" {
            self.value.phase = "unresolved".into();
            let unresolved = self.value.clone();
            let _ = self.write(&unresolved);
        }
    }
}

fn safe_reason(value: &Value) -> Result<&str> {
    let reason = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("pilot_budget_record_invalid"))?;
    ensure!(
        matches!(
            reason,
            "mcp_budget_enforced"
                | "mcp_budget_memory_exhausted"
                | "mcp_budget_pids_exhausted"
                | "mcp_budget_wall_expired"
                | "mcp_budget_membership_unverified"
                | "mcp_budget_limit_drift"
                | "mcp_budget_observation_failed"
                | "mcp_budget_cleanup_unverified"
                | "mcp_budget_boundary_failed"
                | "mcp_budget_attach_unverified"
                | "mcp_budget_monitor_stopped"
                | "mcp_budget_controller_unavailable"
        ),
        "pilot_budget_record_invalid"
    );
    Ok(reason)
}

pub(crate) fn summarize(path: &Path) -> Result<Value> {
    let binding: Binding = private_json(path)?;
    ensure!(binding.format == FORMAT, "pilot_budget_binding_invalid");
    let config = Config::load_file(&binding.config)?;
    ensure!(
        config.identity() == binding.budget_sha256,
        "pilot_budget_selection_changed"
    );
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("pilot_budget_binding_invalid"))?;
    ensure!(
        binding.records == parent.join("budget-records")
            && binding.config == parent.join("linux-budget.json"),
        "pilot_budget_binding_invalid"
    );
    private_directory(&binding.records)?;
    let mut observations = Vec::new();
    let mut failed = 0;
    let mut unresolved = 0;
    let mut active = 0;
    for entry in fs::read_dir(&binding.records)? {
        let entry = entry?;
        ensure!(observations.len() < 64, "pilot_budget_observation_limit");
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("pilot_budget_record_invalid"))?;
        ensure!(
            name.len() == 7
                && name.ends_with(".json")
                && name.as_bytes()[..2].iter().all(u8::is_ascii_digit),
            "pilot_budget_record_invalid"
        );
        let record: Record = private_json(&entry.path())?;
        ensure!(
            record.format == FORMAT
                && record.host_session == binding.host_session
                && record.budget_sha256 == binding.budget_sha256
                && matches!(record.server_id.as_str(), "filesystem" | "git"),
            "pilot_budget_record_invalid"
        );
        let mut reason = None;
        if let Some(metadata) = &record.budget {
            ensure!(
                metadata["budget_sha256"] == binding.budget_sha256,
                "pilot_budget_record_invalid"
            );
            ensure!(
                metadata["format"] == crate::mcp::linux_budget::FORMAT
                    && metadata["failed"].is_boolean()
                    && metadata["cleanup_verified"].is_boolean(),
                "pilot_budget_record_invalid"
            );
            reason = Some(safe_reason(&metadata["reason"])?);
            if metadata["failed"] == true {
                failed += 1;
            }
            if record.phase == "closed" && metadata["cleanup_verified"] != true {
                unresolved += 1;
            }
        }
        match record.phase.as_str() {
            "closed" => ensure!(record.budget.is_some(), "pilot_budget_record_invalid"),
            "active-at-attachment" => {
                let metadata = record
                    .budget
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("pilot_budget_record_invalid"))?;
                let leaf = metadata["leaf"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("pilot_budget_record_invalid"))?;
                ensure!(
                    leaf.strip_prefix("agentfw-mcp-")
                        .is_some_and(|id| id.len() == 32
                            && id
                                .bytes()
                                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
                    "pilot_budget_record_invalid"
                );
                if config.delegation_root.join(leaf).is_dir() {
                    active += 1;
                } else {
                    unresolved += 1;
                }
            }
            "preparing" | "unresolved" => {
                unresolved += 1;
            }
            _ => anyhow::bail!("pilot_budget_record_invalid"),
        }
        let mut counters = serde_json::Map::new();
        if let Some(metadata) = &record.budget {
            if let Some(stats) = metadata["stats"].as_object() {
                for (name, value) in stats {
                    ensure!(
                        if name == "pids_peak_kernel" {
                            value.is_boolean()
                        } else {
                            value.is_u64()
                        },
                        "pilot_budget_record_invalid"
                    );
                    ensure!(
                        matches!(
                            name.as_str(),
                            "memory_current_bytes"
                                | "memory_peak_bytes"
                                | "memory_oom"
                                | "memory_oom_kill"
                                | "pids_current"
                                | "pids_peak"
                                | "pids_peak_kernel"
                                | "pids_max_events"
                                | "cpu_usage_micros"
                                | "cpu_periods"
                                | "cpu_throttled_periods"
                        ),
                        "pilot_budget_record_invalid"
                    );
                    counters.insert(name.clone(), value.clone());
                }
            }
        }
        observations.push(json!({"server_id":record.server_id,"phase":record.phase,
            "reason":reason,"counters":counters}));
    }
    let status = if unresolved > 0 {
        "unresolved"
    } else if failed > 0 {
        "refused"
    } else if active > 0 {
        "active-at-attachment"
    } else if observations.is_empty() {
        "configured-not-observed"
    } else {
        "closed-enforced"
    };
    if active > 0 {
        ensure!(
            root_identity(&config.delegation_root)? == binding.root,
            "pilot_budget_root_changed"
        );
    }
    Ok(
        json!({"format":FORMAT,"status":status,"budget_sha256":binding.budget_sha256,
        "scope":"per-original-server-process-tree","observed_children":observations.len(),
        "failed_children":failed,"unresolved_children":unresolved,"observations":observations}),
    )
}

#[cfg(all(test, target_os = "linux"))]
mod preowner_witness;

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Binding, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().canonicalize().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let config = Config::read(br#"{"format":"sw-mcp/linux-cgroup-budget/1","delegationRoot":"/sys/fs/cgroup/owned-pilot","memoryMaxBytes":268435456,"pidsMax":64,"cpuQuotaMicros":100000,"wallMillis":30000}"#).unwrap();
        let records = directory.join("budget-records");
        fs::create_dir(&records).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&records, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let config_path = directory.join("linux-budget.json");
        write_json(&config_path, &config).unwrap();
        let binding = Binding {
            format: FORMAT.into(),
            host_session: "owned-host".into(),
            budget_sha256: config.identity(),
            config: config_path,
            root: RootIdentity {
                device: 0,
                inode: 0,
            },
            records,
        };
        let path = directory.join("linux-budget-binding.json");
        write_json(&path, &binding).unwrap();
        (temp, binding, path)
    }

    #[cfg(unix)]
    fn metadata(binding: &Binding, failed: bool, cleanup: bool) -> Value {
        json!({"format":crate::mcp::linux_budget::FORMAT,"budget_sha256":binding.budget_sha256,
            "failed":failed,"cleanup_verified":cleanup,"reason":if failed {"mcp_budget_wall_expired"}
            else {"mcp_budget_enforced"},"stats":{"pids_current":0,"pids_peak_kernel":false},
            "leaf":"agentfw-mcp-00000000000000000000000000000000",
            "membership_failure":{"private_pid":12345}})
    }

    #[cfg(unix)]
    fn selection(binding: &Binding) -> VerifiedSelection {
        VerifiedSelection {
            binding: binding.clone(),
            bound: BoundConfig {
                config: Config::load_file(&binding.config).unwrap(),
                root: (binding.root.device, binding.root.inode),
            },
            records: pin_records_directory(&binding.records).unwrap(),
        }
    }

    #[test]
    fn drift_between_validation_and_snapshot_refuses_before_root_access() {
        let (temp, binding, _path) = fixture();
        let result = RunBudget::prepare(
            &binding.config,
            temp.path(),
            "owned-host",
            "changed-identity",
        );
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("pilot_budget_selection_changed"));
        assert!(!temp.path().join("selection-status.json").exists());
    }

    #[test]
    #[cfg(unix)]
    fn dead_child_without_terminal_receipt_stays_unresolved() {
        let (_temp, binding, path) = fixture();
        let mut record = selection(&binding).reserve("filesystem").unwrap();
        record
            .record(metadata(&binding, false, false), false)
            .unwrap();
        assert_eq!(summarize(&path).unwrap()["status"], "unresolved");
    }

    #[test]
    #[cfg(unix)]
    fn verified_selection_never_reloads_replaced_config_bytes() {
        let (_temp, binding, _path) = fixture();
        let selected = selection(&binding);
        let accepted = selected.bound().config.identity();
        fs::write(&binding.config, b"operator replacement").unwrap();
        assert_eq!(selected.bound().config.identity(), accepted);
        let record = selected.reserve("filesystem").unwrap();
        assert_eq!(record.value.budget_sha256, accepted);
        assert_eq!(fs::read(&binding.config).unwrap(), b"operator replacement");
    }

    #[test]
    #[cfg(unix)]
    fn replaced_records_directory_cannot_redirect_reservation_into_workspace() {
        let (temp, binding, _path) = fixture();
        let selected = selection(&binding);
        let original = temp.path().join("original-records");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let marker = workspace.join("notes.txt");
        fs::write(&marker, b"operator workspace").unwrap();
        fs::rename(&binding.records, &original).unwrap();
        std::os::unix::fs::symlink(&workspace, &binding.records).unwrap();

        assert!(selected
            .reserve("filesystem")
            .err()
            .unwrap()
            .to_string()
            .contains("pilot_budget_records_replaced"));
        assert_eq!(fs::read(&marker).unwrap(), b"operator workspace");
        assert_eq!(fs::read_dir(&workspace).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
        assert!(fs::symlink_metadata(&binding.records)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    #[cfg(unix)]
    fn replaced_records_directory_preserves_both_inventories() {
        use std::os::unix::fs::PermissionsExt;
        let (temp, binding, _path) = fixture();
        let selected = selection(&binding);
        let original = temp.path().join("original-records");
        fs::rename(&binding.records, &original).unwrap();
        fs::create_dir(&binding.records).unwrap();
        fs::set_permissions(&binding.records, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement = binding.records.join("00.json");
        fs::write(&replacement, b"operator replacement").unwrap();

        assert!(selected
            .reserve("git")
            .err()
            .unwrap()
            .to_string()
            .contains("pilot_budget_records_replaced"));
        assert_eq!(fs::read(&replacement).unwrap(), b"operator replacement");
        assert_eq!(fs::read_dir(&binding.records).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
    }

    #[test]
    #[cfg(unix)]
    fn directory_replacement_after_reservation_refuses_record_updates() {
        use std::os::unix::fs::PermissionsExt;
        let (temp, binding, _path) = fixture();
        let mut record = selection(&binding).reserve("filesystem").unwrap();
        let before = fs::read(&record.path).unwrap();
        let original = temp.path().join("original-records");
        fs::rename(&binding.records, &original).unwrap();
        fs::create_dir(&binding.records).unwrap();
        fs::set_permissions(&binding.records, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement = binding.records.join("00.json");
        fs::write(&replacement, b"operator replacement").unwrap();

        assert!(record
            .record(metadata(&binding, false, true), true)
            .err()
            .unwrap()
            .to_string()
            .contains("pilot_budget_records_replaced"));
        drop(record);
        assert_eq!(fs::read(&replacement).unwrap(), b"operator replacement");
        assert_eq!(fs::read(original.join("00.json")).unwrap(), before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicit empty already-delegated owned SOU142_BUDGET_CONFIG"]
    fn native_readonly_preflight_and_bound_root_identity() {
        use std::os::unix::fs::MetadataExt;
        let path = std::env::var_os("SOU142_BUDGET_CONFIG").expect("explicit owned config");
        let config = Config::load_file(Path::new(&path)).unwrap();
        let names = || {
            fs::read_dir(&config.delegation_root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>()
        };
        let before = names();
        config.probe_delegation().unwrap();
        assert_eq!(names(), before, "preflight must not create a cgroup");
        let meta = fs::metadata(&config.delegation_root).unwrap();
        let wrong = BoundConfig {
            config: config.clone(),
            root: (meta.dev(), meta.ino() ^ 1),
        };
        assert!(crate::mcp::linux_budget::OwnedBudget::prepare_bound(&wrong)
            .err()
            .unwrap()
            .to_string()
            .contains("pilot_budget_root_changed"));
        assert_eq!(
            names(),
            before,
            "root drift must refuse before leaf creation"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "private child helper; requires the explicit native witness controller"]
    fn native_owner_first_collector_child() -> Result<()> {
        preowner_witness::child()
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires explicit SOU142_BUDGET_CONFIG, SOU142_OWNER_PROFILE and SOU86_TEST_AGENTFW"]
    fn native_owner_first_preparation_parent_loss() -> Result<()> {
        preowner_witness::reproduce(false).map_err(|_| {
            println!(
                "{}",
                json!({"format":"sou142-owner-first-parent-loss/1","status":"incomplete",
                    "reason":"preowner_witness_setup_or_cleanup_unverified","acceptance_pass":false})
            );
            anyhow::anyhow!("preowner_witness_setup_or_cleanup_unverified")
        })
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires explicit SOU142_BUDGET_CONFIG, SOU142_OWNER_PROFILE and SOU86_TEST_AGENTFW"]
    fn native_owner_first_handback_parent_loss() -> Result<()> {
        preowner_witness::reproduce(true).map_err(|_| {
            println!(
                "{}",
                json!({"format":"sou142-owner-first-parent-loss/1","status":"incomplete",
                "reason":"preowner_witness_setup_or_cleanup_unverified","acceptance_pass":false})
            );
            anyhow::anyhow!("preowner_witness_setup_or_cleanup_unverified")
        })
    }

    #[test]
    #[cfg(unix)]
    fn selected_is_not_active_and_unfinished_children_never_claim_success() {
        let (_temp, binding, path) = fixture();
        assert_eq!(
            summarize(&path).unwrap()["status"],
            "configured-not-observed"
        );
        let record = selection(&binding).reserve("filesystem").unwrap();
        assert_eq!(summarize(&path).unwrap()["status"], "unresolved");
        drop(record);
        assert_eq!(summarize(&path).unwrap()["unresolved_children"], 1);
    }

    #[test]
    #[cfg(unix)]
    fn terminal_refusals_and_missing_cleanup_are_honest_and_public_fields_are_finite() {
        let (_temp, binding, path) = fixture();
        let mut record = selection(&binding).reserve("git").unwrap();
        record
            .record(metadata(&binding, false, true), true)
            .unwrap();
        let value = summarize(&path).unwrap();
        assert_eq!(value["status"], "closed-enforced");
        assert_eq!(value["observations"][0]["counters"]["pids_current"], 0);
        let serialized = value.to_string();
        assert!(!serialized.contains("private_pid"));
        assert!(!serialized.contains("leaf"));
        record.record(metadata(&binding, true, true), true).unwrap();
        assert_eq!(summarize(&path).unwrap()["status"], "refused");
        record
            .record(metadata(&binding, true, false), true)
            .unwrap();
        assert_eq!(summarize(&path).unwrap()["status"], "unresolved");
    }

    #[test]
    #[cfg(unix)]
    fn changed_selection_or_record_identity_is_rejected() {
        let (_temp, binding, path) = fixture();
        let mut record = selection(&binding).reserve("git").unwrap();
        let mut wrong = metadata(&binding, false, true);
        wrong["budget_sha256"] = json!("other-run");
        assert!(record.record(wrong, true).is_err());
        record.value.host_session = "another-host".into();
        let value = record.value.clone();
        record.write(&value).unwrap();
        assert!(summarize(&path).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn record_replacement_is_preserved_and_cannot_be_reported_successful() {
        let (_temp, binding, path) = fixture();
        let mut record = selection(&binding).reserve("filesystem").unwrap();
        fs::remove_file(&record.path).unwrap();
        fs::write(&record.path, b"operator replacement").unwrap();
        assert!(record
            .record(metadata(&binding, false, true), true)
            .is_err());
        let record_path = record.path.clone();
        drop(record);
        assert_eq!(fs::read(record_path).unwrap(), b"operator replacement");
        assert!(summarize(&path).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn retained_attempts_are_bounded_and_cannot_overwrite_each_other() {
        let (_temp, binding, path) = fixture();
        let selected = selection(&binding);
        let mut records = Vec::new();
        for _ in 0..64 {
            records.push(selected.reserve("git").unwrap());
        }
        assert!(selected.reserve("git").is_err());
        assert_eq!(summarize(&path).unwrap()["observed_children"], 64);
    }

    #[test]
    fn strict_binding_rejects_duplicate_fields_and_symlinks() {
        let (_temp, _binding, path) = fixture();
        fs::write(&path, br#"{"format":"x","format":"x"}"#).unwrap();
        assert!(private_json::<Binding>(&path).is_err());
        #[cfg(unix)]
        {
            let link = _temp.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(private_json::<Binding>(&link).is_err());
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_kernel_refuses_before_creating_an_engine_leaf() {
        let (_temp, binding, _path) = fixture();
        let config = Config::load_file(&binding.config).unwrap();
        assert!(lease_root(&config).is_err());
        assert!(probe(&config).is_err());
    }
}
