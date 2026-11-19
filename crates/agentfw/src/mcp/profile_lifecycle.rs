// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Transactional MCP profile lifecycle management.
//! Enforces immutable bundle staging, atomic config.yaml updates,
//! monotonic generation authority, crash recovery, and automated rollback.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::{Config, NativeCfg};
use crate::lifecycle::OperationLock;
use crate::mcp::profile_author::compute_profile_diff;

pub const REQUIRED_BUNDLE_FILES: [&str; 6] = [
    "native-config.json",
    "operator-declarations.json",
    "profile.json",
    "registry.json",
    "resource-profiles.json",
    "source-snapshot.json",
];

pub const STATE_FILE: &str = "profile-state.json";
pub const LOCK_FILE: &str = ".lock";
pub const REVISIONS_DIR: &str = "revisions";
pub const CURRENT_SCHEMA_VERSION: u32 = 1;
pub const MAX_BUNDLE_FILE_BYTES: u64 = 10 * 1024 * 1024; // 10MB per bundle file

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFiles {
    pub bundle_sha256: String,
    pub files: BTreeMap<String, String>,
    pub registry_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Install,
    Upgrade,
    Rollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationPhase {
    Staged,
    ConfigWritten,
    DaemonRestarting,
    Verified,
    RollingBack,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub operation_id: String,
    pub kind: OperationKind,
    pub generation: u64,
    pub bundle_sha256: String,
    pub from_bundle_sha256: Option<String>,
    pub timestamp_utc: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationJournal {
    pub operation_id: String,
    pub kind: OperationKind,
    pub phase: OperationPhase,
    pub reserved_generation: u64,
    pub source_bundle_sha256: Option<String>,
    pub target_bundle_sha256: String,
    pub pre_operation_config: Option<String>,
    pub pre_operation_config_digest: Option<String>,
    pub target_config_digest: String,
    pub was_daemon_running: bool,
    pub pre_daemon_instance: Option<String>,
    #[serde(default)]
    pub pre_daemon_config_digest: Option<String>,
    pub started_at_utc: String,
    #[serde(default)]
    pub config_written: bool,
    #[serde(default)]
    pub displaced_config_path: Option<PathBuf>,
    #[serde(default)]
    pub candidate_daemon_instance: Option<String>,
    #[serde(default)]
    pub compensated_daemon_instance: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub historical_compensated_instances: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileState {
    pub schema_version: u32,
    pub generation: u64,
    pub active_bundle_sha256: Option<String>,
    pub previous_bundle_sha256: Option<String>,
    pub history: Vec<OperationRecord>,
    pub in_progress: Option<OperationJournal>,
}

impl Default for ProfileState {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            generation: 0,
            active_bundle_sha256: None,
            previous_bundle_sha256: None,
            history: Vec::new(),
            in_progress: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledRecord {
    pub operation_id: String,
    pub kind: OperationKind,
    pub generation: u64,
    pub bundle_sha256: String,
    pub previous_bundle_sha256: Option<String>,
    pub config_digest: String,
    pub daemon_restarted: bool,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileStatus {
    pub schema_version: u32,
    pub generation: u64,
    pub active_bundle_sha256: Option<String>,
    pub previous_bundle_sha256: Option<String>,
    pub revisions_count: usize,
    pub daemon_running: bool,
    pub daemon_instance: Option<String>,
    pub configuration_status: String,
    pub runtime_status: String,
    pub host_reload_status: String,
    pub in_progress: Option<OperationJournal>,
    pub last_operation: Option<OperationRecord>,
}

/// Inert preview: approval binds the exact inputs and current configuration.
#[derive(Serialize)]
pub struct ProfilePreview {
    pub format: &'static str,
    pub operation: OperationKind,
    pub source_bundle_sha256: String,
    pub target_bundle_sha256: String,
    pub next_generation: u64,
    pub source_config_sha256: Option<String>,
    pub target_config_sha256: String,
    pub approval_sha256: String,
    pub diff: crate::mcp::profile_author::ProfileDiffSummary,
    pub runtime_status: &'static str,
}

/// Compute SHA-256 hex string of arbitrary bytes.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn now_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{secs}")
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<()> {
    let f = File::open(dir)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Verifies that a path is a safe directory (exists, is dir, not a symlink).
fn ensure_safe_dir(dir: &Path) -> Result<()> {
    ensure!(dir.exists(), "directory does not exist: {}", dir.display());
    let sym_meta = fs::symlink_metadata(dir)
        .with_context(|| format!("failed to read symlink metadata: {}", dir.display()))?;
    ensure!(
        !sym_meta.file_type().is_symlink(),
        "directory path must not be a symlink: {}",
        dir.display()
    );
    ensure!(
        sym_meta.is_dir(),
        "path is not a directory: {}",
        dir.display()
    );
    Ok(())
}

/// Ensures a managed directory exists safely without following symlinks.
fn ensure_safe_managed_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        let sym_meta = fs::symlink_metadata(dir)?;
        ensure!(
            !sym_meta.file_type().is_symlink(),
            "managed directory must not be a symlink: {}",
            dir.display()
        );
        ensure!(
            sym_meta.is_dir(),
            "managed directory path is not a directory: {}",
            dir.display()
        );
    } else {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// Verifies that a file within a bundle is a safe regular file (not a symlink, bounded size).
fn read_bundle_file(path: &Path) -> Result<(Vec<u8>, String)> {
    let sym_meta = fs::symlink_metadata(path)
        .with_context(|| format!("missing bundle file: {}", path.display()))?;
    ensure!(
        !sym_meta.file_type().is_symlink(),
        "bundle file must not be a symlink: {}",
        path.display()
    );
    ensure!(
        sym_meta.is_file(),
        "bundle entry is not a regular file: {}",
        path.display()
    );
    ensure!(
        sym_meta.len() <= MAX_BUNDLE_FILE_BYTES,
        "bundle file {} exceeds maximum size of {} bytes",
        path.display(),
        MAX_BUNDLE_FILE_BYTES
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_BUNDLE_FILE_BYTES,
        "bundle file changed or exceeds supported bound"
    );
    let mut bytes = Vec::new();
    file.take(MAX_BUNDLE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BUNDLE_FILE_BYTES,
        "bundle file exceeds supported bound"
    );
    let digest = sha256_bytes(&bytes);
    Ok((bytes, digest))
}

/// Computes the deterministic SHA-256 bundle digest for a compiled profile directory.
pub fn bundle_digest(dir: &Path) -> Result<String> {
    let files = verify_bundle_files(dir)?;
    Ok(files.bundle_sha256)
}

/// Verifies all required bundle files exist, enforces cross-file consistency, and computes digests.
pub fn verify_bundle_files(dir: &Path) -> Result<BundleFiles> {
    ensure_safe_dir(dir)?;

    let mut file_bytes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut file_digests: BTreeMap<String, String> = BTreeMap::new();
    let mut sorted_files = REQUIRED_BUNDLE_FILES;
    sorted_files.sort_unstable();

    for filename in sorted_files {
        let file_path = dir.join(filename);
        let (bytes, digest) = read_bundle_file(&file_path)?;
        file_bytes.insert(filename.to_string(), bytes);
        file_digests.insert(filename.to_string(), digest);
    }

    let registry_sha256 = file_digests
        .get("registry.json")
        .cloned()
        .context("missing registry.json in verified bundle files")?;

    // Cross-file schema and consistency validation
    // 1. profile.json - strictly validate against complete Profile schema
    let profile = crate::mcp::profile_author::parse_profile_bytes(&file_bytes["profile.json"])
        .context("invalid profile.json: must conform to complete Profile schema")?;
    ensure!(
        profile.format == "sw-mcp/operator-profile/1",
        "unsupported profile.json format"
    );
    ensure!(
        profile.registry_sha256 == registry_sha256,
        "cross-file mismatch: profile.json registry_sha256 does not match registry.json hash"
    );

    // 2. native-config.json
    let native_cfg_val: Value = serde_json::from_slice(&file_bytes["native-config.json"])
        .context("invalid JSON in native-config.json")?;
    let native_reg_sha = native_cfg_val
        .get("native")
        .and_then(|n| n.get("registry_sha256"))
        .and_then(|v| v.as_str());
    ensure!(
        native_reg_sha == Some(&registry_sha256),
        "cross-file mismatch: native-config.json registry_sha256 does not match registry.json hash"
    );

    // 3. operator-declarations.json
    let decl_val: Value = serde_json::from_slice(&file_bytes["operator-declarations.json"])
        .context("invalid JSON in operator-declarations.json")?;
    ensure!(
        decl_val.get("format").and_then(|v| v.as_str()) == Some("sw-mcp/operator-declaration/1"),
        "unsupported operator-declarations.json format"
    );

    // 4. source-snapshot.json
    let snap_val: Value = serde_json::from_slice(&file_bytes["source-snapshot.json"])
        .context("invalid JSON in source-snapshot.json")?;
    ensure!(
        snap_val.get("format").and_then(|v| v.as_str()) == Some("sw-mcp/operator-discovery/1"),
        "unsupported source-snapshot.json format"
    );

    // 5. registry.json: validate using production NativeState::from_bytes
    crate::native::NativeState::from_bytes(
        &file_bytes["registry.json"],
        &registry_sha256,
        "profile-validation-only".into(),
    )
    .context("registry.json failed native validation")?;

    // Cross-verify each tool entry in registry.json with profile.json
    let reg_val: Value = serde_json::from_slice(&file_bytes["registry.json"])
        .context("invalid JSON in registry.json")?;
    let reg_tools = reg_val
        .get("tools")
        .and_then(|t| t.as_array())
        .context("registry.json missing or invalid 'tools' array")?;

    let profile_tools = &profile.tools;

    ensure!(
        reg_tools.len() == profile_tools.len(),
        "tool count mismatch between registry.json ({}) and profile.json ({})",
        reg_tools.len(),
        profile_tools.len()
    );

    for tool_entry in reg_tools {
        let name = tool_entry
            .get("name")
            .and_then(|n| n.as_str())
            .context("tool entry in registry.json missing 'name'")?;
        let prof_tool = profile_tools.get(name).context(format!(
            "tool '{name}' in registry.json not found in profile.json"
        ))?;
        let expected_auth_sha = &prof_tool.authority_sha256;
        let computed_auth_sha = crate::mcp::profile_author::digest(tool_entry);
        ensure!(
            expected_auth_sha == &computed_auth_sha,
            "cross-file authority mismatch: tool '{name}' in registry.json authority hash ({computed_auth_sha}) does not match profile.json ({expected_auth_sha})"
        );
        let reg_action = tool_entry.get("action_class").and_then(|a| a.as_str());
        let prof_action = Some(prof_tool.action_class.as_str());
        ensure!(
            reg_action == prof_action,
            "cross-file action mismatch for tool '{name}': registry {:?} vs profile {:?}",
            reg_action,
            prof_action
        );
        let reg_prov = tool_entry.get("result_provenance").and_then(|p| p.as_str());
        let prof_prov = Some(prof_tool.result_provenance.as_str());
        ensure!(
            reg_prov == prof_prov,
            "cross-file result provenance mismatch for tool '{name}': registry {:?} vs profile {:?}",
            reg_prov,
            prof_prov
        );
        let reg_schema = tool_entry.get("schema_sha256").and_then(|s| s.as_str());
        let prof_schema = Some(prof_tool.schema_sha256.as_str());
        ensure!(
            reg_schema == prof_schema,
            "cross-file schema hash mismatch for tool '{name}': registry {:?} vs profile {:?}",
            reg_schema,
            prof_schema
        );
    }

    crate::mcp::profile_author::verify_compiled_bundle(dir)?;

    let mut bundle_hasher = Sha256::new();
    for (filename, digest) in &file_digests {
        let line = format!("{}:{}\n", filename, digest);
        bundle_hasher.update(line.as_bytes());
    }
    let bundle_sha256 = format!("{:x}", bundle_hasher.finalize());

    Ok(BundleFiles {
        bundle_sha256,
        files: file_digests,
        registry_sha256,
    })
}

pub struct ProfileManager {
    home: PathBuf,
    root: PathBuf,
    revisions: PathBuf,
    state_path: PathBuf,
    lock_path: PathBuf,
    config_path: PathBuf,
    source_override: Option<(String, PathBuf)>,
    operation_override: Option<String>,
}

fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(windows)]
    crate::token::restrict(path)?;
    Ok(file)
}

impl ProfileManager {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let home = if home.is_relative() {
            std::env::current_dir()
                .map(|cwd| cwd.join(&home))
                .unwrap_or(home)
        } else {
            home
        };
        let home = home.canonicalize().unwrap_or(home);
        let root = home.join("mcp-profiles");
        let revisions = root.join(REVISIONS_DIR);
        let state_path = root.join(STATE_FILE);
        let lock_path = root.join(LOCK_FILE);
        let config_path = home.join("config.yaml");
        Self {
            home,
            root,
            revisions,
            state_path,
            lock_path,
            config_path,
            source_override: None,
            operation_override: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_owned_operation(mut self, operation: String) -> Self {
        self.operation_override = Some(operation);
        self
    }

    fn operation_id(&self) -> String {
        self.operation_override
            .clone()
            .unwrap_or_else(|| format!("op-{}", crate::token::generate()))
    }

    /// Explicit owned-connection adoption only. The old standalone commands
    /// retain their strict cached-registry identity checks.
    #[cfg(target_os = "linux")]
    pub(crate) fn with_owned_source(mut self, bundle: String, registry: PathBuf) -> Self {
        self.source_override = Some((bundle, registry));
        self
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn adopt_owned_source(&self, source: &Path, expected_config: &str) -> Result<()> {
        let _lock = self.lock()?;
        let mut state = self.load_state()?;
        ensure!(
            state.in_progress.is_none(),
            "interrupted profile transition requires recovery"
        );
        let bundle = self.stage_revision(source)?;
        ensure!(
            self.config_digest()?.as_deref() == Some(expected_config),
            "Agent configuration changed before adoption"
        );
        let bytes = read_bundle_file(&self.config_path)?.0;
        ensure!(
            sha256_bytes(&bytes) == expected_config,
            "Agent configuration changed during adoption"
        );
        let cfg = Config::from_yaml(std::str::from_utf8(&bytes)?)?;
        let native = cfg.native.context("native source configuration absent")?;
        ensure!(
            native.registry_sha256 == bundle.registry_sha256
                && read_bundle_file(&native.registry_path)?.1 == bundle.registry_sha256,
            "reviewed source differs from installed registry"
        );
        if let Some(active) = &state.active_bundle_sha256 {
            ensure!(*active == bundle.bundle_sha256, "another profile is active");
        } else {
            state.active_bundle_sha256 = Some(bundle.bundle_sha256);
            self.save_state(&state)?;
        }
        Ok(())
    }

    /// Stage the exact reviewed inputs before the owned continuity barrier.
    #[cfg(target_os = "linux")]
    pub(crate) fn stage_owned_revision(&self, source: &Path, expected: &str) -> Result<PathBuf> {
        let _lock = self.lock()?;
        let staged = self.stage_revision(source)?;
        ensure!(
            staged.bundle_sha256 == expected,
            "reviewed profile changed before staging"
        );
        Ok(self.revisions.join(expected))
    }

    /// Acquires exclusive non-blocking advisory lock on mcp-profile operations.
    pub fn lock(&self) -> Result<OperationLock> {
        ensure_safe_managed_dir(&self.home)?;
        ensure_safe_managed_dir(&self.root)?;
        let guard = self.root.join("connection-transition.json");
        let guarded = match fs::symlink_metadata(&guard) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if guarded {
            let bytes = read_bundle_file(&guard)?.0;
            let owner = std::str::from_utf8(&bytes)?.lines().next();
            ensure!(
                owner.is_some() && owner == self.operation_override.as_deref(),
                "owned connection transition pending; use mcp-connection profile recover"
            );
        }
        ensure_safe_managed_dir(&self.revisions)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&self.revisions, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(windows)]
        {
            crate::private_file_windows::ensure_private_directory(&self.root)?;
            crate::private_file_windows::ensure_private_directory(&self.revisions)?;
        }

        if self.lock_path.exists() {
            let meta = fs::symlink_metadata(&self.lock_path)?;
            ensure!(
                !meta.file_type().is_symlink() && meta.is_file(),
                "lock path must be a regular file: {}",
                self.lock_path.display()
            );
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.lock_path, fs::Permissions::from_mode(0o600));
        }

        file.try_lock()
            .context("another mcp-profile lifecycle operation is in progress")?;
        Ok(OperationLock::held(file))
    }

    pub fn load_state(&self) -> Result<ProfileState> {
        if !self.state_path.exists() {
            return Ok(ProfileState::default());
        }
        let (bytes, _) = read_bundle_file(&self.state_path)?;
        let state: ProfileState = serde_json::from_slice(&bytes).with_context(|| {
            format!("invalid profile state json: {}", self.state_path.display())
        })?;
        ensure!(
            state.schema_version == CURRENT_SCHEMA_VERSION,
            "unsupported profile state schema version: {}",
            state.schema_version
        );
        ensure!(
            state.history.len() <= 4096,
            "profile history exceeds supported bound"
        );
        for identity in [
            state.active_bundle_sha256.as_deref(),
            state.previous_bundle_sha256.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            ensure!(
                crate::native::is_digest(identity),
                "invalid profile state revision identity"
            );
        }
        if let Some(journal) = &state.in_progress {
            ensure!(
                !journal.operation_id.is_empty()
                    && journal.operation_id.len() <= 128
                    && journal
                        .operation_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
                "invalid profile journal operation identity"
            );
            ensure!(
                journal.historical_compensated_instances.len() <= 128,
                "profile compensation history exceeds supported bound"
            );
            if let Some(path) = &journal.displaced_config_path {
                ensure!(
                    *path == self.displaced_path(&journal.operation_id),
                    "journal displaced path is outside operation ownership"
                );
            }
        }
        Ok(state)
    }

    pub fn save_state(&self, state: &ProfileState) -> Result<()> {
        ensure_safe_managed_dir(&self.root)?;
        let mut persisted = state.clone();
        // Keep a bounded recent audit window; the in-flight recovery plan is never pruned.
        if persisted.history.len() > 1024 {
            persisted.history.drain(..persisted.history.len() - 1024);
        }
        let json = serde_json::to_string_pretty(&persisted)?;
        ensure!(
            json.len() as u64 <= MAX_BUNDLE_FILE_BYTES,
            "profile state exceeds supported bound"
        );
        let temp = self.root.join(format!(".{}.tmp", crate::token::generate()));
        let mut file = create_private(&temp)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        drop(file);

        fs::rename(&temp, &self.state_path)?;
        sync_dir(&self.root)?;
        Ok(())
    }

    /// Stages a bundle into the immutable revisions repository.
    fn stage_revision(&self, src_dir: &Path) -> Result<BundleFiles> {
        let bundle = verify_bundle_files(src_dir)?;
        let target_dir = self.revisions.join(&bundle.bundle_sha256);

        if target_dir.exists() {
            let existing = verify_bundle_files(&target_dir)?;
            ensure!(
                existing.bundle_sha256 == bundle.bundle_sha256,
                "corrupted existing revision directory at {}",
                target_dir.display()
            );
            return Ok(bundle);
        }

        let stage_dir = self
            .revisions
            .join(format!(".stage-{}", crate::token::generate()));
        fs::create_dir(&stage_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&stage_dir, fs::Permissions::from_mode(0o700))?;
        }

        for filename in REQUIRED_BUNDLE_FILES {
            let src_file = src_dir.join(filename);
            let dst_file = stage_dir.join(filename);
            let content = fs::read(&src_file)?;
            let mut out = create_private(&dst_file)?;
            out.write_all(&content)?;
            out.sync_all()?;
        }
        sync_dir(&stage_dir)?;

        let staged_bundle = match verify_bundle_files(&stage_dir) {
            Ok(b) => b,
            Err(e) => {
                let _ = fs::remove_dir_all(&stage_dir);
                let _ = sync_dir(&self.revisions);
                return Err(e);
            }
        };
        if staged_bundle.bundle_sha256 != bundle.bundle_sha256 {
            let _ = fs::remove_dir_all(&stage_dir);
            let _ = sync_dir(&self.revisions);
            bail!(
                "source bundle was modified during staging: expected {}, got {}",
                bundle.bundle_sha256,
                staged_bundle.bundle_sha256
            );
        }

        fs::rename(&stage_dir, &target_dir)?;
        sync_dir(&self.revisions)?;
        Ok(bundle)
    }

    /// Reads current on-disk config.yaml and returns its SHA-256 digest, or None if absent.
    fn config_digest(&self) -> Result<Option<String>> {
        if self.config_path.exists() {
            let bytes = fs::read(&self.config_path)?;
            Ok(Some(sha256_bytes(&bytes)))
        } else {
            Ok(None)
        }
    }

    /// Prepares config mutation, returning (pre_config, pre_config_digest, target_config_yaml, target_config_digest).
    fn prepare_config(
        &self,
        bundle_sha256: &str,
        registry_sha256: &str,
        expected_active_registry: Option<(&Path, &str)>,
    ) -> Result<(Option<String>, Option<String>, String, String)> {
        let (pre_config, mut cfg) = if self.config_path.exists() {
            let (bytes, _) = read_bundle_file(&self.config_path)?;
            ensure!(
                bytes.len() <= 1024 * 1024,
                "config.yaml exceeds supported 1 MiB bound"
            );
            let text = String::from_utf8(bytes).context("config.yaml must be UTF-8")?;
            let parsed = Config::from_yaml(&text)?;
            (Some(text), parsed)
        } else {
            (None, Config::default())
        };

        if let Some((expected_path, expected_sha)) = expected_active_registry {
            let expected_path = self
                .source_override
                .as_ref()
                .filter(|(bundle, _)| {
                    expected_path == self.revisions.join(bundle).join("registry.json")
                })
                .map_or(expected_path, |(_, path)| path.as_path());
            ensure!(
                pre_config.is_some(),
                "conflict: config.yaml is missing while a profile is active; refusing to overwrite foreign configuration deletion"
            );
            if let Some(nat) = &cfg.native {
                ensure!(
                    nat.registry_path == expected_path && nat.registry_sha256 == expected_sha,
                    "conflict: active profile deployment was externally superseded in config.yaml; refusing to overwrite foreign configuration"
                );
            } else {
                bail!("conflict: config.yaml has no native registry configuration; active profile was disabled or superseded externally");
            }
        }

        let pre_config_digest = pre_config.as_ref().map(|c| sha256_bytes(c.as_bytes()));

        // Point native registry to the immutable revision directory
        cfg.enforce = true;
        cfg.judge.enabled = false;
        let revision_dir = self.revisions.join(bundle_sha256);
        let registry_path = revision_dir.join("registry.json");
        let approval = cfg.native.as_ref().and_then(|n| n.approval.clone());
        let liveness = cfg.native.as_ref().and_then(|n| n.liveness.clone());

        cfg.native = Some(NativeCfg {
            execution: None,
            git_execution: None,
            registry_path,
            registry_sha256: registry_sha256.to_string(),
            approval,
            liveness,
        });
        cfg.validate()?;

        let target_config_yaml = serde_yaml::to_string(&cfg)?;
        let target_config_digest = sha256_bytes(target_config_yaml.as_bytes());

        Ok((
            pre_config,
            pre_config_digest,
            target_config_yaml,
            target_config_digest,
        ))
    }
}

#[cfg(target_os = "macos")]
extern "C" {
    fn renamex_np(
        from: *const std::ffi::c_char,
        to: *const std::ffi::c_char,
        flags: std::ffi::c_uint,
    ) -> std::ffi::c_int;
}

fn atomic_swap(p1: &Path, p2: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c1 = CString::new(p1.as_os_str().as_bytes())?;
        let c2 = CString::new(p2.as_os_str().as_bytes())?;
        let ret = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                c1.as_ptr(),
                libc::AT_FDCWD,
                c2.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c1 = CString::new(p1.as_os_str().as_bytes())?;
        let c2 = CString::new(p2.as_os_str().as_bytes())?;
        let ret = unsafe {
            renamex_np(
                c1.as_ptr(),
                c2.as_ptr(),
                2, // RENAME_SWAP
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        let parent = p1.parent().unwrap_or_else(|| Path::new("."));
        let temp_backup = parent.join(format!(
            "{}.swap-bak",
            p1.file_name().unwrap_or_default().to_string_lossy()
        ));
        let w_p1: Vec<u16> = p1.as_os_str().encode_wide().chain(Some(0)).collect();
        let w_p2: Vec<u16> = p2.as_os_str().encode_wide().chain(Some(0)).collect();
        let w_bak: Vec<u16> = temp_backup
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();

        let res = unsafe {
            windows_sys::Win32::Storage::FileSystem::ReplaceFileW(
                w_p2.as_ptr(),
                w_p1.as_ptr(),
                w_bak.as_ptr(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if res == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let move_res = unsafe {
            windows_sys::Win32::Storage::FileSystem::MoveFileExW(
                w_bak.as_ptr(),
                w_p1.as_ptr(),
                windows_sys::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING,
            )
        };
        if move_res == 0 {
            let err = std::io::Error::last_os_error();
            bail!(
                "atomic swap ReplaceFileW succeeded but MoveFileExW failed ({err}); displaced configuration preserved at {}",
                temp_backup.display()
            );
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        bail!("atomic file swap unsupported on this platform");
    }
}

fn check_daemon_ownership(
    st: &crate::lifecycle::Status,
    target_config: Option<&Config>,
    pre_config_digest: Option<&str>,
) -> Result<()> {
    if st.process.is_some() && !st.running {
        bail!("unresolved daemon process ownership: a daemon process is recorded but is not responding; resolve or stop the daemon before profile operations");
    }
    if st.detail.contains("occupied by an unowned process") {
        bail!("unresolved daemon process ownership: agent port is occupied by an unowned process; resolve or stop the daemon before profile operations");
    }
    if st.running {
        if let Some(proc) = &st.process {
            let empty_digest = sha256_bytes(b"");
            let expected_digest = pre_config_digest.unwrap_or(&empty_digest);
            if proc.config_digest != expected_digest {
                if let Some(pre_digest) = pre_config_digest {
                    bail!(
                        "unresolved daemon process ownership: running daemon configuration digest ({}) does not match config.yaml on disk ({}); restart or sync the daemon before profile operations",
                        proc.config_digest,
                        pre_digest
                    );
                } else {
                    bail!(
                        "unresolved daemon process ownership: running daemon configuration digest ({}) does not match absent config.yaml (expected empty baseline {}); restart or sync the daemon before profile operations",
                        proc.config_digest,
                        empty_digest
                    );
                }
            }
        }
    }
    if !st.running && st.process.is_none() {
        if let Some(cfg) = target_config {
            if crate::lifecycle::port_occupied(cfg) {
                bail!("unresolved daemon process ownership: agent port is occupied by an unowned process; resolve or stop the daemon before profile operations");
            }
        }
    }
    Ok(())
}

fn check_daemon_ownership_post_write(
    st: &crate::lifecycle::Status,
    target_config: Option<&Config>,
    was_running: bool,
    pre_instance: Option<&str>,
) -> Result<()> {
    if !was_running {
        if st.running || st.process.is_some() {
            bail!("unresolved daemon process ownership after config write: an independent daemon was started while baseline was stopped; refusing to commit activation");
        }
    } else {
        let proc = st.process.as_ref().context(
            "unresolved daemon process ownership after config write: baseline daemon process record is missing; refusing to commit activation",
        )?;
        let current_instance = proc.instance.as_str();
        if Some(current_instance) != pre_instance {
            bail!(
                "unresolved daemon process ownership after config write: daemon instance was independently replaced (expected {pre_instance:?}, found {current_instance:?}); refusing to commit activation"
            );
        }
        if !crate::lifecycle::pid_alive(proc.pid)? {
            bail!(
                "unresolved daemon process ownership after config write: baseline daemon is no longer running; refusing to commit activation"
            );
        }
    }

    if st.detail.contains("occupied by an unowned process") {
        bail!("unresolved daemon process ownership after config write: agent port is occupied by an unowned process; refusing to commit activation");
    }
    if !st.running && st.process.is_none() {
        if let Some(cfg) = target_config {
            if crate::lifecycle::port_occupied(cfg) {
                bail!("unresolved daemon process ownership after config write: agent port is occupied by an unowned process; refusing to commit activation");
            }
        }
    }
    Ok(())
}

fn is_daemon_running(st: &crate::lifecycle::Status) -> bool {
    st.running
        || st
            .process
            .as_ref()
            .is_some_and(|p| crate::lifecycle::pid_alive(p.pid).unwrap_or(false))
}

fn check_compensation_ownership(
    st: &crate::lifecycle::Status,
    candidate_inst: Option<&str>,
    was_running: bool,
    pre_instance: Option<&str>,
) -> Result<Option<String>> {
    if is_daemon_running(st) {
        let curr_inst = st.process.as_ref().map(|p| p.instance.as_str());
        if candidate_inst.is_some() && curr_inst == candidate_inst {
            Ok(candidate_inst.map(|s| s.to_string()))
        } else if was_running && pre_instance.is_some() && curr_inst == pre_instance {
            Ok(pre_instance.map(|s| s.to_string()))
        } else {
            bail!(
                "conflict during compensation: an independent daemon was started; leaving superseding daemon and configuration untouched"
            );
        }
    } else {
        if let Some(proc) = &st.process {
            if Some(proc.instance.as_str()) != candidate_inst
                && (!was_running || Some(proc.instance.as_str()) != pre_instance)
            {
                bail!(
                    "conflict during compensation: an independent daemon was recorded; leaving superseding daemon and configuration untouched"
                );
            }
        }
        if st.detail.contains("occupied by an unowned process") {
            bail!(
                "conflict during compensation: agent port is occupied by an unowned process; leaving superseding process and configuration untouched"
            );
        }
        Ok(None)
    }
}

fn check_recovery_daemon_ownership(
    st: &crate::lifecycle::Status,
    journal: &OperationJournal,
) -> Result<()> {
    if !journal.was_daemon_running && (st.running || st.process.is_some()) {
        let is_own_candidate = journal.candidate_daemon_instance.as_deref().is_some()
            && st.process.as_ref().map(|p| p.instance.as_str())
                == journal.candidate_daemon_instance.as_deref();

        if !is_own_candidate {
            let process_digest = st.process.as_ref().map(|p| p.config_digest.as_str());
            let empty_digest = sha256_bytes(b"");
            let baseline_digest = journal
                .pre_operation_config_digest
                .as_deref()
                .unwrap_or(&empty_digest);

            let is_target = process_digest == Some(&journal.target_config_digest);
            let is_baseline = process_digest == Some(baseline_digest);

            if is_target {
                bail!(
                    "conflict during recovery: an independent daemon was started with target configuration while baseline was stopped; refusing to overwrite configuration or stop daemon"
                );
            } else if is_baseline {
                bail!(
                    "conflict during recovery: an independent daemon was started with baseline configuration; refusing to stop it"
                );
            } else {
                bail!(
                    "conflict during recovery: an independent daemon was detected while baseline was stopped; refusing to stop it"
                );
            }
        }
    }

    if journal.was_daemon_running && (st.running || st.process.is_some()) {
        let proc_inst = st.process.as_ref().map(|p| p.instance.as_str());
        let proc_digest = st.process.as_ref().map(|p| p.config_digest.as_str());
        let empty_digest = sha256_bytes(b"");
        let baseline_daemon_digest = journal
            .pre_daemon_config_digest
            .as_deref()
            .or(journal.pre_operation_config_digest.as_deref())
            .unwrap_or(&empty_digest);

        let is_original_pre_daemon = journal.pre_daemon_instance.as_deref() == proc_inst
            && proc_digest == Some(baseline_daemon_digest);

        let is_own_candidate = journal.candidate_daemon_instance.as_deref().is_some()
            && journal.candidate_daemon_instance.as_deref() == proc_inst
            && proc_digest == Some(&journal.target_config_digest);

        let matches_compensation_instance =
            (journal.compensated_daemon_instance.as_deref().is_some()
                && journal.compensated_daemon_instance.as_deref() == proc_inst)
                || journal
                    .historical_compensated_instances
                    .iter()
                    .any(|inst| Some(inst.as_str()) == proc_inst);
        let is_compensated_baseline = matches_compensation_instance
            && (proc_digest == Some(baseline_daemon_digest)
                || proc_digest == journal.pre_operation_config_digest.as_deref());

        if !is_original_pre_daemon && !is_own_candidate && !is_compensated_baseline {
            bail!(
                "conflict during recovery: an independent daemon was started or restarted before candidate launch; preserving running daemon"
            );
        }
    }
    Ok(())
}

impl ProfileManager {
    fn service_operation_lock(&self) -> Result<Option<crate::lifecycle::OperationLock>> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if crate::service::registered(&self.home) {
            let s = crate::service::Service::new(&self.home)?;
            return Ok(Some(s.operation_lock()?));
        }
        Ok(None)
    }

    pub fn candidate_path(&self, op_id: &str) -> PathBuf {
        self.home.join(format!(".candidate-{}.tmp", op_id))
    }

    pub fn displaced_path(&self, op_id: &str) -> PathBuf {
        self.home.join(format!(".displaced-{}", op_id))
    }

    /// Atomically replaces config.yaml, enforcing Compare-and-Swap (CAS) against expected baseline.
    /// Uses candidate_path for scratch preparation and displaced_path for atomic swap so that
    /// incomplete candidate preparation cannot be mistaken for displaced configuration.
    fn write_config(
        &self,
        config_yaml: &str,
        expected_pre_digest: Option<&str>,
        candidate_path: &Path,
        displaced_path: &Path,
    ) -> Result<()> {
        crate::grant::GrantStore::new(&self.home.join("grants"))
            .invalidate_all_for_policy_switch()
            .context("cannot retire previous profile approvals")?;
        if candidate_path.exists() {
            let _ = fs::remove_file(candidate_path);
        }
        let mut file = create_private(candidate_path)?;
        file.write_all(config_yaml.as_bytes())?;
        file.sync_all()?;
        drop(file);
        sync_dir(&self.home)?;

        let candidate_bytes = fs::read(candidate_path)?;
        let candidate_digest = sha256_bytes(&candidate_bytes);
        let expected_candidate_digest = sha256_bytes(config_yaml.as_bytes());
        ensure!(
            candidate_digest == expected_candidate_digest,
            "candidate configuration corrupted during writing"
        );

        if let Some(expected) = expected_pre_digest {
            if !self.config_path.exists() {
                let _ = fs::remove_file(candidate_path);
                bail!("config.yaml unexpectedly disappeared while preparing profile mutation");
            }

            if displaced_path.exists() {
                let _ = fs::remove_file(displaced_path);
            }
            fs::rename(candidate_path, displaced_path)?;
            sync_dir(&self.home)?;

            // Atomically swap candidate config with live config
            if let Err(e) = atomic_swap(displaced_path, &self.config_path) {
                let _ = fs::remove_file(displaced_path);
                return Err(e).context("atomic configuration swap failed");
            }

            // displaced_path now contains the displaced live configuration
            let displaced_bytes = match fs::read(displaced_path) {
                Ok(b) => b,
                Err(e) => {
                    if atomic_swap(displaced_path, &self.config_path).is_ok() {
                        let _ = fs::remove_file(displaced_path);
                    }
                    return Err(e)
                        .context("failed to read displaced configuration after atomic swap");
                }
            };
            let displaced_digest = sha256_bytes(&displaced_bytes);

            if displaced_digest != expected {
                // Intervening write detected! Atomically swap back to restore newer configuration
                if let Err(e) = atomic_swap(displaced_path, &self.config_path) {
                    bail!(
                        "concurrent modification detected: config.yaml changed while preparing profile mutation (expected digest {}, found {}); swap back failed: {e:#}; displaced file preserved at {}",
                        expected,
                        displaced_digest,
                        displaced_path.display()
                    );
                }

                // Inspect what was displaced by the compensating swap back (Finding 2 from Codex)
                let comp_bytes = fs::read(displaced_path)?;
                let comp_digest = sha256_bytes(&comp_bytes);
                if comp_digest == candidate_digest {
                    // Only candidate scratch was displaced. Safe to remove!
                    let _ = fs::remove_file(displaced_path);
                    sync_dir(&self.home)?;
                } else {
                    // Another write (B) occurred between swaps! Swap B back into config.yaml to preserve the newest write!
                    if let Err(e) = atomic_swap(displaced_path, &self.config_path) {
                        bail!(
                            "concurrent modification detected: multiple intervening writes detected; failed to restore newest write {comp_digest}: {e:#}; preserved at {}",
                            displaced_path.display()
                        );
                    }
                    let final_bytes = fs::read(displaced_path).ok();
                    let is_candidate = final_bytes.as_deref().map(sha256_bytes).as_deref()
                        == Some(&candidate_digest);
                    if is_candidate {
                        let _ = fs::remove_file(displaced_path);
                        sync_dir(&self.home)?;
                        bail!(
                            "concurrent modification detected: config.yaml was modified repeatedly while preparing profile mutation (restored newest write {})",
                            comp_digest
                        );
                    } else {
                        sync_dir(&self.home)?;
                        bail!(
                            "concurrent modification detected: config.yaml was modified repeatedly while preparing profile mutation (restored newest write {}; displaced write preserved at {})",
                            comp_digest,
                            displaced_path.display()
                        );
                    }
                }

                bail!(
                    "concurrent modification detected: config.yaml changed while preparing profile mutation (expected digest {}, found {})",
                    expected,
                    displaced_digest
                );
            }

            let _ = fs::remove_file(displaced_path);
            sync_dir(&self.home)?;
            Ok(())
        } else {
            // Initial installation: config.yaml must NOT exist.
            match fs::hard_link(candidate_path, &self.config_path) {
                Ok(_) => {
                    let _ = fs::remove_file(candidate_path);
                    sync_dir(&self.home)?;
                    Ok(())
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = fs::remove_file(candidate_path);
                    bail!("config.yaml unexpectedly appeared while preparing initial installation");
                }
                Err(e) => {
                    let _ = fs::remove_file(candidate_path);
                    Err(e).context("failed to atomically link initial configuration")
                }
            }
        }
    }

    fn restore_config(
        &self,
        pre_operation_config: Option<&str>,
        expected_current_digest: Option<&str>,
        candidate_path: &Path,
        displaced_path: &Path,
    ) -> Result<()> {
        if let Some(text) = pre_operation_config {
            self.write_config(
                text,
                expected_current_digest,
                candidate_path,
                displaced_path,
            )?;
        } else {
            // Initial baseline had no config.
            if let Some(expected) = expected_current_digest {
                if !self.config_path.exists() {
                    bail!("config.yaml unexpectedly disappeared while preparing recovery");
                }
                let cur_bytes = fs::read(&self.config_path)?;
                let cur_digest = sha256_bytes(&cur_bytes);
                if cur_digest != expected {
                    bail!(
                        "conflict: config.yaml changed while preparing recovery/rollback (expected digest {}, found {})",
                        expected,
                        cur_digest
                    );
                }

                if displaced_path.exists() {
                    let _ = fs::remove_file(displaced_path);
                }
                fs::rename(&self.config_path, displaced_path)?;
                sync_dir(&self.home)?;

                // Validate the displaced file captured by rename before deleting (Finding 2)
                let captured_bytes = fs::read(displaced_path)?;
                let captured_digest = sha256_bytes(&captured_bytes);
                if captured_digest != expected {
                    match fs::hard_link(displaced_path, &self.config_path) {
                        Ok(_) => {
                            let _ = fs::remove_file(displaced_path);
                            sync_dir(&self.home)?;
                            bail!(
                                "conflict: config.yaml was externally modified while preparing recovery/rollback (expected digest {}, captured {}); restored configuration to config.yaml",
                                expected,
                                captured_digest
                            );
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                            sync_dir(&self.home)?;
                            bail!(
                                "conflict: config.yaml was repeatedly modified externally; preserved captured configuration at {}",
                                displaced_path.display()
                            );
                        }
                        Err(e) => {
                            sync_dir(&self.home)?;
                            bail!(
                                "conflict: config.yaml was externally modified; failed to restore without clobbering: {e:#}; preserved at {}",
                                displaced_path.display()
                            );
                        }
                    }
                }

                fs::remove_file(displaced_path)?;
                sync_dir(&self.home)?;
            } else if self.config_path.exists() {
                bail!(
                    "config.yaml unexpectedly exists while preparing recovery to absent baseline"
                );
            }
        }
        Ok(())
    }

    fn is_ownership_conflict(err: &anyhow::Error) -> bool {
        let msg = err.to_string();
        msg.contains("conflict:")
            || msg.contains("conflict during")
            || msg.contains("independently")
            || msg.contains("unowned")
            || msg.contains("refusing to stop")
    }

    fn restart_or_start_daemon(
        &self,
        lifecycle: &crate::lifecycle::Manager,
        expected_instance: Option<&str>,
        candidate_instance: Option<&str>,
    ) -> Result<()> {
        let st = lifecycle.status()?;
        if is_daemon_running(&st) {
            let expected = expected_instance.context(
                "conflict: an independent daemon was started before candidate launch; refusing to stop it",
            )?;
            lifecycle.restart_with_ownership_check(Some(expected), true, candidate_instance)
        } else {
            lifecycle.restart_with_ownership_check(None, false, candidate_instance)
        }
    }

    fn restart_and_verify_daemon(
        &self,
        lifecycle: &crate::lifecycle::Manager,
        expected_config_digest: &str,
        expected_instance: Option<&str>,
        was_running: bool,
        candidate_instance: Option<&str>,
    ) -> Result<String> {
        lifecycle.restart_with_ownership_check(
            expected_instance,
            was_running,
            candidate_instance,
        )?;
        let st = lifecycle.status()?;
        ensure!(st.running, "daemon reported not running after restart");
        let proc = st
            .process
            .as_ref()
            .context("missing running daemon process record")?;
        ensure!(
            proc.config_digest == expected_config_digest,
            "daemon restarted with mismatched config digest: expected {}, got {}",
            expected_config_digest,
            proc.config_digest
        );
        if let Some(expected_cand) = candidate_instance {
            ensure!(
                proc.instance == expected_cand,
                "candidate daemon instance mismatch: expected {expected_cand}, got {}",
                proc.instance
            );
        }
        Ok(proc.instance.clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_compensation(
        &self,
        lifecycle: &crate::lifecycle::Manager,
        state: &mut ProfileState,
        op_id: &str,
        kind: OperationKind,
        bundle_sha: &str,
        from_bundle: Option<String>,
        generation: u64,
        pre_config: Option<&str>,
        pre_config_digest: Option<&str>,
        was_running: bool,
        boot_err: &anyhow::Error,
    ) -> Result<()> {
        let _service_lock = self.service_operation_lock()?;
        let commit_lock = lifecycle
            .lock()
            .context("failed to coordinate lifecycle lock for compensation commit")?;
        let cur_cfg = self.config_digest()?;
        if cur_cfg.as_deref() != pre_config_digest {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(state)?;
            bail!(
                "automatic compensation aborted: config.yaml was externally modified before compensation commit (expected baseline digest {}, found {})",
                pre_config_digest.unwrap_or("<none>"),
                cur_cfg.as_deref().unwrap_or("<none>")
            );
        }

        let final_st = lifecycle.status_locked().context(
            "failed to determine daemon lifecycle status under compensation commit lock",
        )?;
        let baseline_cfg = pre_config.and_then(|text| Config::from_yaml(text).ok());
        let expected_comp_inst = if was_running {
            state
                .in_progress
                .as_ref()
                .and_then(|j| j.compensated_daemon_instance.clone())
                .or_else(|| {
                    state
                        .in_progress
                        .as_ref()
                        .and_then(|j| j.pre_daemon_instance.clone())
                })
        } else {
            None
        };
        if let Err(err) = check_daemon_ownership_post_write(
            &final_st,
            baseline_cfg.as_ref(),
            was_running,
            expected_comp_inst.as_deref(),
        ) {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(state)?;
            bail!("automatic compensation conflict: daemon ownership check failed before clearing journal: {err:#}");
        }

        if was_running {
            if !final_st.running {
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(state)?;
                bail!("automatic compensation conflict: baseline daemon unexpectedly stopped before clearing journal");
            }
            let empty_digest = sha256_bytes(b"");
            let baseline_digest = pre_config_digest.unwrap_or(&empty_digest);
            let proc_digest = final_st.process.as_ref().map(|p| p.config_digest.as_str());
            if proc_digest != Some(baseline_digest) {
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(state)?;
                bail!(
                    "automatic compensation conflict: baseline daemon running with mismatched config digest before clearing journal (expected {baseline_digest}, got {proc_digest:?})"
                );
            }
        } else if final_st.running || final_st.process.is_some() {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(state)?;
            bail!("automatic compensation conflict: an independent daemon was detected while baseline was stopped; refusing to clear journal");
        }

        state.history.push(OperationRecord {
            operation_id: op_id.to_string(),
            kind,
            generation,
            bundle_sha256: bundle_sha.to_string(),
            from_bundle_sha256: from_bundle,
            timestamp_utc: now_utc(),
            status: "failed (rolled back)".into(),
            detail: format!("candidate daemon failed to boot ({boot_err:#}); restored baseline"),
        });
        state.in_progress = None;
        self.save_state(state)?;
        drop(commit_lock);
        drop(_service_lock);
        Ok(())
    }

    /// Preview never stages revisions or changes daemon/host configuration.
    pub fn preview_upgrade(&self, profile_dir: &Path) -> Result<ProfilePreview> {
        let state = self.load_state()?;
        self.preview_transition(&state, profile_dir, OperationKind::Upgrade)
    }

    pub fn preview_rollback(&self, revision: Option<&str>) -> Result<ProfilePreview> {
        let state = self.load_state()?;
        let target = revision
            .or(state.previous_bundle_sha256.as_deref())
            .context("no previous profile revision recorded")?;
        ensure!(
            crate::native::is_digest(target),
            "invalid revision identifier"
        );
        self.preview_transition(
            &state,
            &self.revisions.join(target),
            OperationKind::Rollback,
        )
    }

    fn preview_transition(
        &self,
        state: &ProfileState,
        target_dir: &Path,
        kind: OperationKind,
    ) -> Result<ProfilePreview> {
        ensure!(
            state.in_progress.is_none(),
            "interrupted profile operation requires recovery"
        );
        let source = state
            .active_bundle_sha256
            .as_ref()
            .context("no active profile")?;
        ensure!(
            crate::native::is_digest(source),
            "invalid active profile identity"
        );
        let source_dir = self.revisions.join(source);
        let active = verify_bundle_files(&source_dir)?;
        ensure!(
            active.bundle_sha256 == *source,
            "active profile bundle corrupted on disk"
        );
        let target = verify_bundle_files(target_dir)?;
        let old = crate::mcp::profile_author::parse_profile_bytes(&fs::read(
            source_dir.join("profile.json"),
        )?)?;
        let new = crate::mcp::profile_author::parse_profile_bytes(&fs::read(
            target_dir.join("profile.json"),
        )?)?;
        ensure!(
            old.server_id == new.server_id,
            "profile transition cannot change original server identity"
        );
        let (_, source_config, _, target_config) = self.prepare_config(
            &target.bundle_sha256,
            &target.registry_sha256,
            Some((&source_dir.join("registry.json"), &active.registry_sha256)),
        )?;
        let next_generation = state
            .generation
            .checked_add(1)
            .context("generation overflow")?;
        let lifecycle_path = self.home.join("versions/lifecycle.json");
        let lifecycle_digest = if lifecycle_path.exists() {
            Some(sha256_bytes(&fs::read(lifecycle_path)?))
        } else {
            None
        };
        let approval = serde_json::json!({
            "domain": "agentfw/mcp-profile-transition/v1", "operation": kind,
            "home": self.home, "source": source, "target": target.bundle_sha256,
            "generation": next_generation, "source_config": source_config,
            "target_config": target_config, "lifecycle": lifecycle_digest,
        });
        Ok(ProfilePreview {
            format: "sw-mcp/profile-preview/1",
            operation: kind,
            source_bundle_sha256: source.clone(),
            target_bundle_sha256: target.bundle_sha256,
            next_generation,
            source_config_sha256: source_config,
            target_config_sha256: target_config,
            approval_sha256: crate::mcp::profile_author::digest(&approval),
            diff: compute_profile_diff(&source_dir, target_dir)?,
            runtime_status: "not_probed; host reload is not inferred",
        })
    }

    /// Installs an initial profile bundle. Fails if a profile is already active.
    pub fn install(
        &self,
        profile_dir: &Path,
        expected_bundle_sha: Option<&str>,
    ) -> Result<InstalledRecord> {
        let _lock = self.lock()?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if crate::service::registered(&self.home) {
            crate::service::Service::new(&self.home)?.require_instance_launcher()?;
        }
        let mut state = self.load_state()?;
        ensure!(
            state.in_progress.is_none(),
            "another profile operation is in progress or was interrupted: run `agentfw mcp-profile recover`"
        );
        ensure!(
            state.active_bundle_sha256.is_none(),
            "a profile is already active (bundle: {}): use `agentfw mcp-profile upgrade` to update",
            state.active_bundle_sha256.as_deref().unwrap_or_default()
        );

        let bundle = self.stage_revision(profile_dir)?;
        if let Some(expected) = expected_bundle_sha {
            ensure!(
                bundle.bundle_sha256 == expected,
                "bundle digest mismatch: expected {}, got {}",
                expected,
                bundle.bundle_sha256
            );
        }

        let next_gen = state
            .generation
            .checked_add(1)
            .context("generation overflow")?;
        let op_id = self.operation_id();
        let lifecycle = crate::lifecycle::Manager::new(&self.home);

        let (pre_config, pre_config_digest, target_yaml, target_config_digest) =
            self.prepare_config(&bundle.bundle_sha256, &bundle.registry_sha256, None)?;
        let target_cfg = Config::from_yaml(&target_yaml)?;

        // FAIL CLOSED: do NOT swallow status errors into was_running = false
        let daemon_st = lifecycle.status().context(
            "failed to determine daemon lifecycle status; cannot safely install profile",
        )?;
        check_daemon_ownership(&daemon_st, Some(&target_cfg), pre_config_digest.as_deref())?;
        let was_running = daemon_st.running;
        let pre_instance = daemon_st.process.as_ref().map(|p| p.instance.clone());

        let candidate = self.candidate_path(&op_id);
        let displaced = self.displaced_path(&op_id);

        // Hold coordinated service and lifecycle ownership across journal write and config write
        let _service_op_lock = self.service_operation_lock()?;
        let lifecycle_lock = lifecycle
            .lock()
            .context("failed to acquire lifecycle lock for profile installation")?;

        let locked_daemon_st = lifecycle.status_locked().context(
            "failed to determine daemon lifecycle status under lock; cannot safely modify configuration",
        )?;
        check_daemon_ownership(
            &locked_daemon_st,
            Some(&target_cfg),
            pre_config_digest.as_deref(),
        )?;
        ensure!(
            locked_daemon_st.running == was_running
                && locked_daemon_st.process.as_ref().map(|p| p.instance.as_str())
                    == pre_instance.as_deref(),
            "conflict: daemon process was started, stopped, or replaced independently before configuration write"
        );

        // 1. Durably record in_progress journal
        state.in_progress = Some(OperationJournal {
            operation_id: op_id.clone(),
            kind: OperationKind::Install,
            phase: OperationPhase::Staged,
            reserved_generation: next_gen,
            source_bundle_sha256: None,
            target_bundle_sha256: bundle.bundle_sha256.clone(),
            pre_operation_config: pre_config.clone(),
            pre_operation_config_digest: pre_config_digest.clone(),
            target_config_digest: target_config_digest.clone(),
            was_daemon_running: was_running,
            pre_daemon_instance: pre_instance.clone(),
            pre_daemon_config_digest: daemon_st.process.as_ref().map(|p| p.config_digest.clone()),
            started_at_utc: now_utc(),
            config_written: false,
            displaced_config_path: Some(displaced.clone()),
            candidate_daemon_instance: None,
            compensated_daemon_instance: None,
            historical_compensated_instances: Vec::new(),
        });
        self.save_state(&state)?;

        // 2. Write config.yaml with CAS
        self.write_config(
            &target_yaml,
            pre_config_digest.as_deref(),
            &candidate,
            &displaced,
        )?;
        let journal_ref = state.in_progress.as_mut().unwrap();
        journal_ref.config_written = true;
        journal_ref.phase = OperationPhase::ConfigWritten;
        self.save_state(&state)?;

        // Release lifecycle and service locks so status / restart can inspect lifecycle without lock conflict
        drop(lifecycle_lock);
        drop(_service_op_lock);

        // Verify daemon ownership post-write under coordinated lifecycle ownership
        let post_st = lifecycle.status()?;
        if let Err(e) = check_daemon_ownership_post_write(
            &post_st,
            Some(&target_cfg),
            was_running,
            pre_instance.as_deref(),
        ) {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            return Err(e);
        }

        // 3. Daemon restart & verification if running
        let mut verified = true;
        let mut candidate_inst: Option<String> = None;
        let needs_verification = was_running || post_st.running || post_st.process.is_some();
        if needs_verification {
            let inst = crate::token::generate();
            candidate_inst = Some(inst.clone());
            let j = state.in_progress.as_mut().unwrap();
            j.phase = OperationPhase::DaemonRestarting;
            j.candidate_daemon_instance = Some(inst.clone());
            self.save_state(&state)?;

            match self.restart_and_verify_daemon(
                &lifecycle,
                &target_config_digest,
                pre_instance.as_deref(),
                was_running,
                Some(&inst),
            ) {
                Ok(_) => {}
                Err(e) => {
                    // Check for ownership conflict first: NEVER compensate over ownership conflict!
                    if Self::is_ownership_conflict(&e) {
                        state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                        self.save_state(&state)?;
                        bail!("ownership conflict during candidate daemon restart ({e:#}); leaving superseding daemon and configuration untouched");
                    }
                    // Check for supersession before automatic compensation
                    let cur_digest = self.config_digest()?;
                    if cur_digest.as_deref() != Some(&target_config_digest) {
                        state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                        self.save_state(&state)?;
                        bail!("candidate daemon failed to boot ({e:#}); config.yaml was modified externally, refusing to overwrite");
                    }
                    // Automatic compensation: rollback config and restart baseline daemon
                    state.in_progress.as_mut().unwrap().phase = OperationPhase::RollingBack;
                    self.save_state(&state)?;
                    let _service_comp_lock = self.service_operation_lock()?;
                    let comp_lock = lifecycle.lock().context(
                        "failed to coordinate lifecycle lock for automatic compensation",
                    )?;
                    let comp_st = lifecycle.status_locked().context(
                        "failed to determine daemon lifecycle status under compensation lock",
                    )?;
                    let authorized_running = match check_compensation_ownership(
                        &comp_st,
                        candidate_inst.as_deref(),
                        was_running,
                        pre_instance.as_deref(),
                    ) {
                        Ok(auth) => auth,
                        Err(err) => {
                            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                            self.save_state(&state)?;
                            return Err(err);
                        }
                    };
                    self.restore_config(
                        pre_config.as_deref(),
                        Some(&target_config_digest),
                        &candidate,
                        &displaced,
                    )?;
                    drop(comp_lock);
                    drop(_service_comp_lock);
                    if was_running {
                        let comp_inst = crate::token::generate();
                        state
                            .in_progress
                            .as_mut()
                            .unwrap()
                            .compensated_daemon_instance = Some(comp_inst.clone());
                        self.save_state(&state)?;

                        let baseline_restart = self.restart_or_start_daemon(
                            &lifecycle,
                            authorized_running.as_deref(),
                            Some(&comp_inst),
                        );
                        if let Err(re) = baseline_restart {
                            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                            self.save_state(&state)?;
                            bail!("candidate daemon failed to boot ({e:#}) and baseline recovery failed to restart ({re:#})");
                        }
                        let st = lifecycle.status()?;
                        let process_digest = st.process.as_ref().map(|p| p.config_digest.as_str());
                        let empty_digest = sha256_bytes(b"");
                        let baseline_digest = pre_config_digest.as_deref().unwrap_or(&empty_digest);
                        ensure!(
                            st.running && process_digest == Some(baseline_digest) && st.process.as_ref().map(|p| p.instance.as_str()) == Some(&comp_inst),
                            "candidate daemon failed to boot ({e:#}); restored baseline configuration but daemon is not running with baseline configuration"
                        );
                        let journal_ref = state.in_progress.as_mut().unwrap();
                        journal_ref.pre_daemon_instance = Some(comp_inst);
                    } else {
                        let st = lifecycle.status()?;
                        if is_daemon_running(&st) {
                            if let Err(se) = lifecycle.stop() {
                                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                                self.save_state(&state)?;
                                bail!("candidate daemon failed to boot ({e:#}) and failed to stop candidate daemon: {se:#}");
                            }
                        }
                        let post_stop = lifecycle.status()?;
                        if post_stop.running || post_stop.process.is_some() {
                            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                            self.save_state(&state)?;
                            bail!("candidate daemon failed to boot ({e:#}) and process ownership remains unresolved");
                        }
                    }
                    let from_bundle = state.active_bundle_sha256.clone();
                    let current_gen = state.generation;
                    self.finalize_compensation(
                        &lifecycle,
                        &mut state,
                        &op_id,
                        OperationKind::Install,
                        &bundle.bundle_sha256,
                        from_bundle,
                        current_gen,
                        pre_config.as_deref(),
                        pre_config_digest.as_deref(),
                        was_running,
                        &e,
                    )?;
                    bail!("daemon failed to start with new profile ({e:#}); automatically rolled back configuration");
                }
            }
        } else {
            verified = false;
        }

        // 4. Commit state
        // Revalidate configuration ownership and daemon binding under lifecycle and service locks before committing activation
        let _service_lock = self.service_operation_lock()?;
        let commit_lock = lifecycle
            .lock()
            .context("failed to coordinate lifecycle lock for activation commit")?;
        let cur_cfg = self.config_digest()?;
        if cur_cfg.as_deref() != Some(&target_config_digest) {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            bail!(
                "activation aborted: config.yaml was externally modified before activation commit (expected candidate digest {}, found {})",
                target_config_digest,
                cur_cfg.as_deref().unwrap_or("<none>")
            );
        }
        let final_st = lifecycle
            .status_locked()
            .context("failed to determine daemon lifecycle status under commit lock")?;
        if was_running && !final_st.running {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            bail!("activation aborted: daemon unexpectedly stopped before activation commit");
        }
        if let Some(expected_inst) = &candidate_inst {
            let proc_inst = final_st.process.as_ref().map(|p| p.instance.as_str());
            if proc_inst != Some(expected_inst.as_str()) {
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(&state)?;
                bail!(
                    "activation aborted: candidate daemon instance superseded before commit (expected {expected_inst}, found {:?})",
                    proc_inst
                );
            }
        } else if final_st.running || final_st.process.is_some() {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            bail!("activation aborted: an independent daemon was started before activation commit");
        }
        if let Some(proc) = &final_st.process {
            if proc.config_digest != target_config_digest
                && (was_running || post_st.process.is_some())
            {
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(&state)?;
                bail!(
                    "activation aborted: daemon process config digest mismatch before commit (expected {}, got {})",
                    target_config_digest,
                    proc.config_digest
                );
            }
        }

        state.previous_bundle_sha256 = state.active_bundle_sha256.take();
        state.active_bundle_sha256 = Some(bundle.bundle_sha256.clone());
        state.generation = next_gen;
        state.history.push(OperationRecord {
            operation_id: op_id.clone(),
            kind: OperationKind::Install,
            generation: next_gen,
            bundle_sha256: bundle.bundle_sha256.clone(),
            from_bundle_sha256: None,
            timestamp_utc: now_utc(),
            status: "success".into(),
            detail: "installed initial profile".into(),
        });
        state.in_progress = None;
        self.save_state(&state)?;
        drop(commit_lock);

        Ok(InstalledRecord {
            operation_id: op_id,
            kind: OperationKind::Install,
            generation: next_gen,
            bundle_sha256: bundle.bundle_sha256,
            previous_bundle_sha256: None,
            config_digest: target_config_digest,
            daemon_restarted: was_running,
            verified,
        })
    }

    /// Upgrades the active profile to a new revision.
    pub fn upgrade(
        &self,
        profile_dir: &Path,
        expected_bundle_sha: Option<&str>,
        expect_gen: Option<u64>,
        accept_diff: Option<&str>,
    ) -> Result<InstalledRecord> {
        let _lock = self.lock()?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if crate::service::registered(&self.home) {
            crate::service::Service::new(&self.home)?.require_instance_launcher()?;
        }
        let mut state = self.load_state()?;
        ensure!(
            state.in_progress.is_none(),
            "another profile operation is in progress or was interrupted: run `agentfw mcp-profile recover`"
        );
        let active_bundle = state
            .active_bundle_sha256
            .clone()
            .context("no profile is currently active: use `install` first")?;

        if let Some(expected_gen) = expect_gen {
            ensure!(
                state.generation == expected_gen,
                "generation mismatch: expected generation {}, but active generation is {}",
                expected_gen,
                state.generation
            );
        }

        let bundle = self.stage_revision(profile_dir)?;
        if let Some(expected) = expected_bundle_sha {
            ensure!(
                bundle.bundle_sha256 == expected,
                "bundle digest mismatch: expected {}, got {}",
                expected,
                bundle.bundle_sha256
            );
        }
        ensure!(
            bundle.bundle_sha256 != active_bundle,
            "bundle {} is already active",
            bundle.bundle_sha256
        );

        let next_gen = state
            .generation
            .checked_add(1)
            .context("generation overflow")?;

        // Compute semantic diff against active revision
        let active_dir = self.revisions.join(&active_bundle);
        let active_meta = verify_bundle_files(&active_dir)?;
        ensure!(
            active_meta.bundle_sha256 == active_bundle,
            "active profile bundle corrupted on disk"
        );

        let (pre_config, pre_config_digest, target_yaml, target_config_digest) = self
            .prepare_config(
                &bundle.bundle_sha256,
                &bundle.registry_sha256,
                Some((
                    &active_dir.join("registry.json"),
                    &active_meta.registry_sha256,
                )),
            )?;
        let target_cfg = Config::from_yaml(&target_yaml)?;

        let new_dir = self.revisions.join(&bundle.bundle_sha256);
        let preview = self.preview_transition(&state, &new_dir, OperationKind::Upgrade)?;
        ensure!(
            accept_diff == Some(preview.approval_sha256.as_str()),
            "exact preview approval required; rerun preview and use --accept-diff {}",
            preview.approval_sha256
        );

        let op_id = self.operation_id();
        let lifecycle = crate::lifecycle::Manager::new(&self.home);

        // FAIL CLOSED on daemon status
        let daemon_st = lifecycle.status().context(
            "failed to determine daemon lifecycle status; cannot safely upgrade profile",
        )?;
        check_daemon_ownership(&daemon_st, Some(&target_cfg), pre_config_digest.as_deref())?;
        let was_running = daemon_st.running;
        let pre_instance = daemon_st.process.as_ref().map(|p| p.instance.clone());

        let candidate = self.candidate_path(&op_id);
        let displaced = self.displaced_path(&op_id);

        // Hold coordinated service and lifecycle ownership across journal write and config write
        let _service_op_lock = self.service_operation_lock()?;
        let lifecycle_lock = lifecycle
            .lock()
            .context("failed to acquire lifecycle lock for profile upgrade")?;

        let locked_daemon_st = lifecycle.status_locked().context(
            "failed to determine daemon lifecycle status under lock; cannot safely modify configuration",
        )?;
        check_daemon_ownership(
            &locked_daemon_st,
            Some(&target_cfg),
            pre_config_digest.as_deref(),
        )?;
        ensure!(
            locked_daemon_st.running == was_running
                && locked_daemon_st.process.as_ref().map(|p| p.instance.as_str())
                    == pre_instance.as_deref(),
            "conflict: daemon process was started, stopped, or replaced independently before configuration write"
        );

        // 1. Durably record in_progress journal
        state.in_progress = Some(OperationJournal {
            operation_id: op_id.clone(),
            kind: OperationKind::Upgrade,
            phase: OperationPhase::Staged,
            reserved_generation: next_gen,
            source_bundle_sha256: Some(active_bundle.clone()),
            target_bundle_sha256: bundle.bundle_sha256.clone(),
            pre_operation_config: pre_config.clone(),
            pre_operation_config_digest: pre_config_digest.clone(),
            target_config_digest: target_config_digest.clone(),
            was_daemon_running: was_running,
            pre_daemon_instance: pre_instance.clone(),
            pre_daemon_config_digest: daemon_st.process.as_ref().map(|p| p.config_digest.clone()),
            started_at_utc: now_utc(),
            config_written: false,
            displaced_config_path: Some(displaced.clone()),
            candidate_daemon_instance: None,
            compensated_daemon_instance: None,
            historical_compensated_instances: Vec::new(),
        });
        self.save_state(&state)?;

        // 2. Write config.yaml with CAS
        self.write_config(
            &target_yaml,
            pre_config_digest.as_deref(),
            &candidate,
            &displaced,
        )?;
        let journal_ref = state.in_progress.as_mut().unwrap();
        journal_ref.config_written = true;
        journal_ref.phase = OperationPhase::ConfigWritten;
        self.save_state(&state)?;

        // Release lifecycle and service locks so status / restart can inspect lifecycle without lock conflict
        drop(lifecycle_lock);
        drop(_service_op_lock);

        // Verify daemon ownership post-write under coordinated lifecycle ownership
        let post_st = lifecycle.status()?;
        if let Err(e) = check_daemon_ownership_post_write(
            &post_st,
            Some(&target_cfg),
            was_running,
            pre_instance.as_deref(),
        ) {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            return Err(e);
        }

        // 3. Daemon restart & verification if running
        let mut verified = true;
        let mut candidate_inst: Option<String> = None;
        let needs_verification = was_running || post_st.running || post_st.process.is_some();
        if needs_verification {
            let inst = crate::token::generate();
            candidate_inst = Some(inst.clone());
            let j = state.in_progress.as_mut().unwrap();
            j.phase = OperationPhase::DaemonRestarting;
            j.candidate_daemon_instance = Some(inst.clone());
            self.save_state(&state)?;

            match self.restart_and_verify_daemon(
                &lifecycle,
                &target_config_digest,
                pre_instance.as_deref(),
                was_running,
                Some(&inst),
            ) {
                Ok(_) => {}
                Err(e) => {
                    // Check for ownership conflict first: NEVER compensate over ownership conflict!
                    if Self::is_ownership_conflict(&e) {
                        state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                        self.save_state(&state)?;
                        bail!("ownership conflict during candidate daemon restart ({e:#}); leaving superseding daemon and configuration untouched");
                    }
                    // Check for supersession before automatic compensation
                    let cur_digest = self.config_digest()?;
                    if cur_digest.as_deref() != Some(&target_config_digest) {
                        state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                        self.save_state(&state)?;
                        bail!("candidate daemon failed to boot ({e:#}); config.yaml was modified externally, refusing to overwrite");
                    }
                    // Automatic compensation: rollback config and restart daemon
                    state.in_progress.as_mut().unwrap().phase = OperationPhase::RollingBack;
                    self.save_state(&state)?;
                    let _service_comp_lock = self.service_operation_lock()?;
                    let comp_lock = lifecycle.lock().context(
                        "failed to coordinate lifecycle lock for automatic compensation",
                    )?;
                    let comp_st = lifecycle.status_locked().context(
                        "failed to determine daemon lifecycle status under compensation lock",
                    )?;
                    let authorized_running = match check_compensation_ownership(
                        &comp_st,
                        candidate_inst.as_deref(),
                        was_running,
                        pre_instance.as_deref(),
                    ) {
                        Ok(auth) => auth,
                        Err(err) => {
                            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                            self.save_state(&state)?;
                            return Err(err);
                        }
                    };
                    self.restore_config(
                        pre_config.as_deref(),
                        Some(&target_config_digest),
                        &candidate,
                        &displaced,
                    )?;
                    drop(comp_lock);
                    drop(_service_comp_lock);
                    if was_running {
                        let comp_inst = crate::token::generate();
                        state
                            .in_progress
                            .as_mut()
                            .unwrap()
                            .compensated_daemon_instance = Some(comp_inst.clone());
                        self.save_state(&state)?;

                        let baseline_restart = self.restart_or_start_daemon(
                            &lifecycle,
                            authorized_running.as_deref(),
                            Some(&comp_inst),
                        );
                        if let Err(re) = baseline_restart {
                            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                            self.save_state(&state)?;
                            bail!("candidate daemon failed to boot ({e:#}) and baseline recovery failed to restart ({re:#})");
                        }
                        let st = lifecycle.status()?;
                        let process_digest = st.process.as_ref().map(|p| p.config_digest.as_str());
                        let empty_digest = sha256_bytes(b"");
                        let baseline_digest = pre_config_digest.as_deref().unwrap_or(&empty_digest);
                        ensure!(
                            st.running && process_digest == Some(baseline_digest) && st.process.as_ref().map(|p| p.instance.as_str()) == Some(&comp_inst),
                            "candidate daemon failed to boot ({e:#}); restored baseline configuration but daemon is not running with baseline configuration"
                        );
                        let journal_ref = state.in_progress.as_mut().unwrap();
                        journal_ref.pre_daemon_instance = Some(comp_inst);
                    } else {
                        let st = lifecycle.status()?;
                        if is_daemon_running(&st) {
                            if let Err(se) = lifecycle.stop() {
                                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                                self.save_state(&state)?;
                                bail!("candidate daemon failed to boot ({e:#}) and failed to stop candidate daemon: {se:#}");
                            }
                        }
                        let post_stop = lifecycle.status()?;
                        if post_stop.running || post_stop.process.is_some() {
                            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                            self.save_state(&state)?;
                            bail!("candidate daemon failed to boot ({e:#}) and process ownership remains unresolved");
                        }
                    }
                    let current_gen = state.generation;
                    self.finalize_compensation(
                        &lifecycle,
                        &mut state,
                        &op_id,
                        OperationKind::Upgrade,
                        &bundle.bundle_sha256,
                        Some(active_bundle),
                        current_gen,
                        pre_config.as_deref(),
                        pre_config_digest.as_deref(),
                        was_running,
                        &e,
                    )?;
                    bail!("daemon failed to start with upgraded profile ({e:#}); automatically rolled back to healthy baseline");
                }
            }
        } else {
            verified = false;
        }

        // 4. Commit state
        // Revalidate configuration ownership and daemon binding under lifecycle and service locks before committing activation
        let _service_lock = self.service_operation_lock()?;
        let commit_lock = lifecycle
            .lock()
            .context("failed to coordinate lifecycle lock for activation commit")?;
        let cur_cfg = self.config_digest()?;
        if cur_cfg.as_deref() != Some(&target_config_digest) {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            bail!(
                "activation aborted: config.yaml was externally modified before activation commit (expected candidate digest {}, found {})",
                target_config_digest,
                cur_cfg.as_deref().unwrap_or("<none>")
            );
        }
        let final_st = lifecycle
            .status_locked()
            .context("failed to determine daemon lifecycle status under commit lock")?;
        if was_running && !final_st.running {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            bail!("activation aborted: daemon unexpectedly stopped before activation commit");
        }
        if let Some(expected_inst) = &candidate_inst {
            let proc_inst = final_st.process.as_ref().map(|p| p.instance.as_str());
            if proc_inst != Some(expected_inst.as_str()) {
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(&state)?;
                bail!(
                    "activation aborted: candidate daemon instance superseded before commit (expected {expected_inst}, found {:?})",
                    proc_inst
                );
            }
        } else if final_st.running || final_st.process.is_some() {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            bail!("activation aborted: an independent daemon was started before activation commit");
        }
        if let Some(proc) = &final_st.process {
            if proc.config_digest != target_config_digest
                && (was_running || post_st.process.is_some())
            {
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(&state)?;
                bail!(
                    "activation aborted: daemon process config digest mismatch before commit (expected {}, got {})",
                    target_config_digest,
                    proc.config_digest
                );
            }
        }

        state.previous_bundle_sha256 = Some(active_bundle.clone());
        state.active_bundle_sha256 = Some(bundle.bundle_sha256.clone());
        state.generation = next_gen;
        state.history.push(OperationRecord {
            operation_id: op_id.clone(),
            kind: OperationKind::Upgrade,
            generation: next_gen,
            bundle_sha256: bundle.bundle_sha256.clone(),
            from_bundle_sha256: Some(active_bundle),
            timestamp_utc: now_utc(),
            status: "success".into(),
            detail: "upgraded profile".into(),
        });
        state.in_progress = None;
        self.save_state(&state)?;
        drop(commit_lock);

        Ok(InstalledRecord {
            operation_id: op_id,
            kind: OperationKind::Upgrade,
            generation: next_gen,
            bundle_sha256: bundle.bundle_sha256,
            previous_bundle_sha256: state.previous_bundle_sha256,
            config_digest: target_config_digest,
            daemon_restarted: was_running,
            verified,
        })
    }

    /// Rolls back to a previous revision. Strictly increments generation to prevent stale authority replay.
    pub fn rollback(
        &self,
        to_revision: Option<&str>,
        expect_gen: Option<u64>,
        accept_diff: Option<&str>,
    ) -> Result<InstalledRecord> {
        let _lock = self.lock()?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if crate::service::registered(&self.home) {
            crate::service::Service::new(&self.home)?.require_instance_launcher()?;
        }
        let mut state = self.load_state()?;
        ensure!(
            state.in_progress.is_none(),
            "another profile operation is in progress or was interrupted: run `agentfw mcp-profile recover`"
        );
        let active_bundle = state
            .active_bundle_sha256
            .clone()
            .context("no profile is currently active: cannot rollback")?;

        if let Some(expected_gen) = expect_gen {
            ensure!(
                state.generation == expected_gen,
                "generation mismatch: expected generation {}, but active generation is {}",
                expected_gen,
                state.generation
            );
        }

        let target_bundle_sha = match to_revision {
            Some(rev) => {
                ensure!(
                    crate::native::is_digest(rev),
                    "invalid revision identifier: must be a 64-character lowercase hex digest, got {:?}",
                    rev
                );
                rev.to_string()
            }
            None => state.previous_bundle_sha256.clone().context(
                "no previous profile revision recorded to rollback to: specify --revision",
            )?,
        };

        let target_dir = self.revisions.join(&target_bundle_sha);
        ensure!(
            target_dir.is_dir(),
            "target rollback revision directory does not exist: {}",
            target_dir.display()
        );
        let target_bundle = verify_bundle_files(&target_dir)?;
        ensure!(
            target_bundle.bundle_sha256 == target_bundle_sha,
            "corrupted revision repository: directory {} computed digest {} does not match directory name {}",
            target_dir.display(),
            target_bundle.bundle_sha256,
            target_bundle_sha
        );

        let next_gen = state
            .generation
            .checked_add(1)
            .context("generation overflow")?;

        // Compute diff
        let active_dir = self.revisions.join(&active_bundle);
        let active_meta = verify_bundle_files(&active_dir)?;
        ensure!(
            active_meta.bundle_sha256 == active_bundle,
            "active profile bundle corrupted on disk"
        );

        let (pre_config, pre_config_digest, target_yaml, target_config_digest) = self
            .prepare_config(
                &target_bundle.bundle_sha256,
                &target_bundle.registry_sha256,
                Some((
                    &active_dir.join("registry.json"),
                    &active_meta.registry_sha256,
                )),
            )?;
        let target_cfg = Config::from_yaml(&target_yaml)?;

        let preview = self.preview_transition(&state, &target_dir, OperationKind::Rollback)?;
        ensure!(
            accept_diff == Some(preview.approval_sha256.as_str()),
            "exact preview approval required; rerun preview and use --accept-diff {}",
            preview.approval_sha256
        );

        let op_id = self.operation_id();
        let lifecycle = crate::lifecycle::Manager::new(&self.home);

        // FAIL CLOSED on daemon status
        let daemon_st = lifecycle.status().context(
            "failed to determine daemon lifecycle status; cannot safely rollback profile",
        )?;
        check_daemon_ownership(&daemon_st, Some(&target_cfg), pre_config_digest.as_deref())?;
        let was_running = daemon_st.running;
        let pre_instance = daemon_st.process.as_ref().map(|p| p.instance.clone());

        let candidate = self.candidate_path(&op_id);
        let displaced = self.displaced_path(&op_id);

        // Hold coordinated service and lifecycle ownership across journal write and config write
        let _service_op_lock = self.service_operation_lock()?;
        let lifecycle_lock = lifecycle
            .lock()
            .context("failed to acquire lifecycle lock for profile rollback")?;

        let locked_daemon_st = lifecycle.status_locked().context(
            "failed to determine daemon lifecycle status under lock; cannot safely modify configuration",
        )?;
        check_daemon_ownership(
            &locked_daemon_st,
            Some(&target_cfg),
            pre_config_digest.as_deref(),
        )?;
        ensure!(
            locked_daemon_st.running == was_running
                && locked_daemon_st.process.as_ref().map(|p| p.instance.as_str())
                    == pre_instance.as_deref(),
            "conflict: daemon process was started, stopped, or replaced independently before configuration write"
        );

        // 1. Durably record in_progress journal
        state.in_progress = Some(OperationJournal {
            operation_id: op_id.clone(),
            kind: OperationKind::Rollback,
            phase: OperationPhase::Staged,
            reserved_generation: next_gen,
            source_bundle_sha256: Some(active_bundle.clone()),
            target_bundle_sha256: target_bundle.bundle_sha256.clone(),
            pre_operation_config: pre_config.clone(),
            pre_operation_config_digest: pre_config_digest.clone(),
            target_config_digest: target_config_digest.clone(),
            was_daemon_running: was_running,
            pre_daemon_instance: pre_instance.clone(),
            pre_daemon_config_digest: daemon_st.process.as_ref().map(|p| p.config_digest.clone()),
            started_at_utc: now_utc(),
            config_written: false,
            displaced_config_path: Some(displaced.clone()),
            candidate_daemon_instance: None,
            compensated_daemon_instance: None,
            historical_compensated_instances: Vec::new(),
        });
        self.save_state(&state)?;

        // 2. Write config.yaml with CAS
        self.write_config(
            &target_yaml,
            pre_config_digest.as_deref(),
            &candidate,
            &displaced,
        )?;
        let journal_ref = state.in_progress.as_mut().unwrap();
        journal_ref.config_written = true;
        journal_ref.phase = OperationPhase::ConfigWritten;
        self.save_state(&state)?;

        // Release lifecycle and service locks so status / restart can inspect lifecycle without lock conflict
        drop(lifecycle_lock);
        drop(_service_op_lock);

        // Verify daemon ownership post-write under coordinated lifecycle ownership
        let post_st = lifecycle.status()?;
        if let Err(e) = check_daemon_ownership_post_write(
            &post_st,
            Some(&target_cfg),
            was_running,
            pre_instance.as_deref(),
        ) {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            return Err(e);
        }

        // 3. Daemon restart & verification if running
        let mut verified = true;
        let mut candidate_inst: Option<String> = None;
        let needs_verification = was_running || post_st.running || post_st.process.is_some();
        if needs_verification {
            let inst = crate::token::generate();
            candidate_inst = Some(inst.clone());
            let j = state.in_progress.as_mut().unwrap();
            j.phase = OperationPhase::DaemonRestarting;
            j.candidate_daemon_instance = Some(inst.clone());
            self.save_state(&state)?;

            match self.restart_and_verify_daemon(
                &lifecycle,
                &target_config_digest,
                pre_instance.as_deref(),
                was_running,
                Some(&inst),
            ) {
                Ok(_) => {}
                Err(e) => {
                    // Check for ownership conflict first: NEVER compensate over ownership conflict!
                    if Self::is_ownership_conflict(&e) {
                        state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                        self.save_state(&state)?;
                        bail!("ownership conflict during candidate daemon restart ({e:#}); leaving superseding daemon and configuration untouched");
                    }
                    // Check for supersession before automatic compensation
                    let cur_digest = self.config_digest()?;
                    if cur_digest.as_deref() != Some(&target_config_digest) {
                        state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                        self.save_state(&state)?;
                        bail!("rolled-back candidate daemon failed to boot ({e:#}); config.yaml was modified externally, refusing to overwrite");
                    }
                    state.in_progress.as_mut().unwrap().phase = OperationPhase::RollingBack;
                    self.save_state(&state)?;
                    let _service_comp_lock = self.service_operation_lock()?;
                    let comp_lock = lifecycle.lock().context(
                        "failed to coordinate lifecycle lock for automatic compensation",
                    )?;
                    let comp_st = lifecycle.status_locked().context(
                        "failed to determine daemon lifecycle status under compensation lock",
                    )?;
                    let authorized_running = match check_compensation_ownership(
                        &comp_st,
                        candidate_inst.as_deref(),
                        was_running,
                        pre_instance.as_deref(),
                    ) {
                        Ok(auth) => auth,
                        Err(err) => {
                            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                            self.save_state(&state)?;
                            return Err(err);
                        }
                    };
                    self.restore_config(
                        pre_config.as_deref(),
                        Some(&target_config_digest),
                        &candidate,
                        &displaced,
                    )?;
                    drop(comp_lock);
                    drop(_service_comp_lock);
                    if was_running {
                        let comp_inst = crate::token::generate();
                        state
                            .in_progress
                            .as_mut()
                            .unwrap()
                            .compensated_daemon_instance = Some(comp_inst.clone());
                        self.save_state(&state)?;

                        let baseline_restart = self.restart_or_start_daemon(
                            &lifecycle,
                            authorized_running.as_deref(),
                            Some(&comp_inst),
                        );
                        if let Err(re) = baseline_restart {
                            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                            self.save_state(&state)?;
                            bail!("rolled-back candidate daemon failed to boot ({e:#}) and baseline recovery failed ({re:#})");
                        }
                        let st = lifecycle.status()?;
                        let process_digest = st.process.as_ref().map(|p| p.config_digest.as_str());
                        let empty_digest = sha256_bytes(b"");
                        let baseline_digest = pre_config_digest.as_deref().unwrap_or(&empty_digest);
                        ensure!(
                            st.running && process_digest == Some(baseline_digest) && st.process.as_ref().map(|p| p.instance.as_str()) == Some(&comp_inst),
                            "rolled-back candidate daemon failed to boot ({e:#}); restored baseline configuration but daemon is not running with baseline configuration"
                        );
                        let journal_ref = state.in_progress.as_mut().unwrap();
                        journal_ref.pre_daemon_instance = Some(comp_inst);
                    } else {
                        let st = lifecycle.status()?;
                        if is_daemon_running(&st) {
                            if let Err(se) = lifecycle.stop() {
                                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                                self.save_state(&state)?;
                                bail!("candidate daemon failed to boot ({e:#}) and failed to stop candidate daemon: {se:#}");
                            }
                        }
                        let post_stop = lifecycle.status()?;
                        if post_stop.running || post_stop.process.is_some() {
                            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                            self.save_state(&state)?;
                            bail!("candidate daemon failed to boot ({e:#}) and process ownership remains unresolved");
                        }
                    }
                    let from_bundle = state.active_bundle_sha256.clone();
                    self.finalize_compensation(
                        &lifecycle,
                        &mut state,
                        &op_id,
                        OperationKind::Rollback,
                        &target_bundle.bundle_sha256,
                        from_bundle,
                        next_gen,
                        pre_config.as_deref(),
                        pre_config_digest.as_deref(),
                        was_running,
                        &e,
                    )?;
                    bail!("daemon failed to start with rolled-back profile ({e:#}); restored baseline");
                }
            }
        } else {
            verified = false;
        }

        // 4. Commit state
        // Revalidate configuration ownership and daemon binding under lifecycle and service locks before committing activation
        let _service_lock = self.service_operation_lock()?;
        let commit_lock = lifecycle
            .lock()
            .context("failed to coordinate lifecycle lock for activation commit")?;
        let cur_cfg = self.config_digest()?;
        if cur_cfg.as_deref() != Some(&target_config_digest) {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            bail!(
                "activation aborted: config.yaml was externally modified before activation commit (expected candidate digest {}, found {})",
                target_config_digest,
                cur_cfg.as_deref().unwrap_or("<none>")
            );
        }
        let final_st = lifecycle
            .status_locked()
            .context("failed to determine daemon lifecycle status under commit lock")?;
        if was_running && !final_st.running {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            bail!("activation aborted: daemon unexpectedly stopped before activation commit");
        }
        if let Some(expected_inst) = &candidate_inst {
            let proc_inst = final_st.process.as_ref().map(|p| p.instance.as_str());
            if proc_inst != Some(expected_inst.as_str()) {
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(&state)?;
                bail!(
                    "activation aborted: candidate daemon instance superseded before commit (expected {expected_inst}, found {:?})",
                    proc_inst
                );
            }
        } else if final_st.running || final_st.process.is_some() {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            bail!("activation aborted: an independent daemon was started before activation commit");
        }
        if let Some(proc) = &final_st.process {
            if proc.config_digest != target_config_digest
                && (was_running || post_st.process.is_some())
            {
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(&state)?;
                bail!(
                    "activation aborted: daemon process config digest mismatch before commit (expected {}, got {})",
                    target_config_digest,
                    proc.config_digest
                );
            }
        }

        state.previous_bundle_sha256 = Some(active_bundle.clone());
        state.active_bundle_sha256 = Some(target_bundle.bundle_sha256.clone());
        state.generation = next_gen;
        state.history.push(OperationRecord {
            operation_id: op_id.clone(),
            kind: OperationKind::Rollback,
            generation: next_gen,
            bundle_sha256: target_bundle.bundle_sha256.clone(),
            from_bundle_sha256: Some(active_bundle),
            timestamp_utc: now_utc(),
            status: "success".into(),
            detail: "rolled back profile".into(),
        });
        state.in_progress = None;
        self.save_state(&state)?;
        drop(commit_lock);

        Ok(InstalledRecord {
            operation_id: op_id,
            kind: OperationKind::Rollback,
            generation: next_gen,
            bundle_sha256: target_bundle.bundle_sha256,
            previous_bundle_sha256: state.previous_bundle_sha256,
            config_digest: target_config_digest,
            daemon_restarted: was_running,
            verified,
        })
    }

    /// Recovers from an interrupted or crashed operation.
    pub fn recover(&self) -> Result<()> {
        let _lock = self.lock()?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if crate::service::registered(&self.home) {
            crate::service::Service::new(&self.home)?.require_instance_launcher()?;
        }
        let mut state = self.load_state()?;
        let Some(mut journal) = state.in_progress.take() else {
            return Ok(());
        };

        let candidate_path = self.candidate_path(&journal.operation_id);
        let displaced_path = journal
            .displaced_config_path
            .clone()
            .unwrap_or_else(|| self.displaced_path(&journal.operation_id));

        if journal.phase == OperationPhase::Verified {
            if candidate_path.exists() {
                let _ = fs::remove_file(&candidate_path);
                let _ = sync_dir(&self.home);
            }
            if displaced_path.exists() {
                let _ = fs::remove_file(&displaced_path);
                let _ = sync_dir(&self.home);
            }
            // Already verified before crash, can finalize state
            state.previous_bundle_sha256 = journal.source_bundle_sha256.clone();
            state.active_bundle_sha256 = Some(journal.target_bundle_sha256.clone());
            state.generation = journal.reserved_generation;
            state.history.push(OperationRecord {
                operation_id: journal.operation_id,
                kind: journal.kind,
                generation: journal.reserved_generation,
                bundle_sha256: journal.target_bundle_sha256,
                from_bundle_sha256: journal.source_bundle_sha256,
                timestamp_utc: now_utc(),
                status: "success (recovered)".into(),
                detail: "recovered verified operation".into(),
            });
            self.save_state(&state)?;
            return Ok(());
        }

        let lifecycle = crate::lifecycle::Manager::new(&self.home);
        let initial_st = lifecycle.status()?;

        // Before touching any files (candidate_path, displaced_path, config.yaml),
        // verify daemon ownership so independent operator daemons are preserved intact.
        if let Err(e) = check_recovery_daemon_ownership(&initial_st, &journal) {
            journal.phase = OperationPhase::Failed;
            state.in_progress = Some(journal);
            self.save_state(&state)?;
            return Err(e);
        }

        // On Windows, if ReplaceFileW completed but MoveFileExW crashed before moving to displaced_path:
        let swap_bak = PathBuf::from(format!("{}.swap-bak", displaced_path.display()));
        if swap_bak.exists() && !displaced_path.exists() {
            let _ = fs::rename(&swap_bak, &displaced_path);
            let _ = sync_dir(&self.home);
        }

        let mut service_rec_lock = self.service_operation_lock()?;
        let mut rec_lock = Some(
            lifecycle
                .lock()
                .context("failed to coordinate lifecycle lock for recovery")?,
        );

        let locked_st = lifecycle.status_locked().context(
            "failed to determine daemon lifecycle status under recovery lock; cannot safely recover profile",
        )?;
        if let Err(e) = check_recovery_daemon_ownership(&locked_st, &journal) {
            journal.phase = OperationPhase::Failed;
            state.in_progress = Some(journal);
            self.save_state(&state)?;
            return Err(e);
        }

        if candidate_path.exists() {
            let _ = fs::remove_file(&candidate_path);
            sync_dir(&self.home)?;
        }

        // Reconcile displaced configuration if a crash occurred during file swap/restoration
        if displaced_path.exists() {
            let displaced_bytes = fs::read(&displaced_path)?;
            let displaced_digest = sha256_bytes(&displaced_bytes);

            if self.config_path.exists() {
                let cur_bytes = fs::read(&self.config_path)?;
                let cur_digest = sha256_bytes(&cur_bytes);

                if cur_digest == journal.target_config_digest {
                    let baseline_digest = journal.pre_operation_config_digest.as_deref();
                    if displaced_digest == journal.target_config_digest {
                        // Finding 4 (Codex P2): Initial install hard_link succeeded but scratch displaced_path was not unlinked yet.
                        // Both paths contain target config. Simply unlink displaced_path scratch!
                        let _ = fs::remove_file(&displaced_path);
                        sync_dir(&self.home)?;
                    } else if baseline_digest.is_some()
                        && Some(displaced_digest.as_str()) == baseline_digest
                    {
                        // Swap interrupted after swap succeeded: displaced file is expected baseline.
                        // Swap back to restore baseline configuration!
                        if let Err(e) = atomic_swap(&displaced_path, &self.config_path) {
                            journal.phase = OperationPhase::Failed;
                            state.in_progress = Some(journal);
                            self.save_state(&state)?;
                            bail!(
                                "failed to swap baseline configuration back to config.yaml during recovery: {e:#}; displaced file preserved at {}",
                                displaced_path.display()
                            );
                        }
                        // Finding 1 (Codex P1): Validate what was displaced by this recovery swap before deleting!
                        let swapped_bytes = fs::read(&displaced_path)?;
                        let swapped_digest = sha256_bytes(&swapped_bytes);
                        if swapped_digest == journal.target_config_digest {
                            let _ = fs::remove_file(&displaced_path);
                            sync_dir(&self.home)?;
                        } else {
                            // Intervening write! config.yaml was modified before swap back!
                            // Swap back to restore the newer operator configuration to config.yaml!
                            if let Err(e) = atomic_swap(&displaced_path, &self.config_path) {
                                journal.phase = OperationPhase::Failed;
                                state.in_progress = Some(journal);
                                self.save_state(&state)?;
                                bail!(
                                    "conflict during recovery: config.yaml was externally modified before recovery swap; failed to restore: {e:#}; displaced file preserved at {}",
                                    displaced_path.display()
                                );
                            }
                            let comp_bytes = fs::read(&displaced_path)?;
                            let comp_digest = sha256_bytes(&comp_bytes);
                            if comp_digest == displaced_digest {
                                let _ = fs::remove_file(&displaced_path);
                                sync_dir(&self.home)?;
                            }
                            journal.phase = OperationPhase::Failed;
                            state.in_progress = Some(journal);
                            self.save_state(&state)?;
                            bail!(
                                "conflict during recovery: config.yaml was externally superseded before recovery swap (restored newest configuration {})",
                                swapped_digest
                            );
                        }
                    } else {
                        // Finding 1 (Codex P1): Displaced file was SUPERSEDED by an operator!
                        // Swap displaced_path back to config.yaml to preserve the operator's superseded deployment!
                        if let Err(e) = atomic_swap(&displaced_path, &self.config_path) {
                            journal.phase = OperationPhase::Failed;
                            state.in_progress = Some(journal);
                            self.save_state(&state)?;
                            bail!(
                                "conflict during recovery: displaced configuration was externally superseded, but atomic restoration to config.yaml failed: {e:#}; displaced file preserved at {}",
                                displaced_path.display()
                            );
                        }
                        // Finding 1 (Codex P1): Validate what was displaced by this swap before deleting!
                        let swapped_bytes = fs::read(&displaced_path)?;
                        let swapped_digest = sha256_bytes(&swapped_bytes);
                        if swapped_digest == journal.target_config_digest {
                            let _ = fs::remove_file(&displaced_path);
                            sync_dir(&self.home)?;
                        } else {
                            if let Err(e) = atomic_swap(&displaced_path, &self.config_path) {
                                journal.phase = OperationPhase::Failed;
                                state.in_progress = Some(journal);
                                self.save_state(&state)?;
                                bail!(
                                    "conflict during recovery: config.yaml was externally modified; failed to restore: {e:#}; displaced file preserved at {}",
                                    displaced_path.display()
                                );
                            }
                            let final_bytes = fs::read(&displaced_path).ok();
                            if final_bytes.as_deref().map(sha256_bytes).as_deref()
                                == Some(&journal.target_config_digest)
                            {
                                let _ = fs::remove_file(&displaced_path);
                                sync_dir(&self.home)?;
                            }
                        }
                        journal.phase = OperationPhase::Failed;
                        state.in_progress = Some(journal);
                        self.save_state(&state)?;
                        bail!(
                            "conflict during recovery: displaced configuration was externally superseded; restored superseded configuration to config.yaml"
                        );
                    }
                } else if displaced_digest == journal.target_config_digest {
                    // Crash before swap: displaced file was candidate scratch.
                    let _ = fs::remove_file(&displaced_path);
                    sync_dir(&self.home)?;
                } else {
                    // Unexpected external conflict on both files: preserve displaced path and fail
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!(
                        "conflict during recovery: unexpected displaced configuration state (config: {}, displaced: {})",
                        cur_digest,
                        displaced_digest
                    );
                }
            } else {
                // config.yaml does not exist
                if displaced_digest == journal.target_config_digest {
                    // Candidate file from unswapped install or displaced target during restoration to absent baseline
                    let _ = fs::remove_file(&displaced_path);
                    sync_dir(&self.home)?;
                } else if journal.pre_operation_config_digest.as_deref() == Some(&displaced_digest)
                {
                    // Baseline configuration was displaced and config.yaml is absent.
                    // Restore baseline configuration to config.yaml!
                    match fs::hard_link(&displaced_path, &self.config_path) {
                        Ok(_) => {
                            let _ = fs::remove_file(&displaced_path);
                            sync_dir(&self.home)?;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                            sync_dir(&self.home)?;
                        }
                        Err(e) => {
                            sync_dir(&self.home)?;
                            bail!("failed to restore baseline configuration: {e:#}");
                        }
                    }
                } else {
                    // Finding 1 (Codex P1): Displaced file is neither target candidate nor expected baseline!
                    // It could be operator data displaced during compensation of a crashed initial install or intervening write.
                    // Preserve displaced configuration by restoring it to config.yaml if possible, or retaining it!
                    let restored = match fs::hard_link(&displaced_path, &self.config_path) {
                        Ok(_) => {
                            let _ = fs::remove_file(&displaced_path);
                            sync_dir(&self.home)?;
                            true
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                            sync_dir(&self.home)?;
                            false
                        }
                        Err(_) => {
                            sync_dir(&self.home)?;
                            false
                        }
                    };
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    if restored {
                        bail!(
                            "conflict during recovery: displaced configuration does not match target profile; restored to config.yaml"
                        );
                    } else {
                        bail!(
                            "conflict during recovery: displaced configuration does not match target profile; preserved at {}",
                            displaced_path.display()
                        );
                    }
                }
            }
        }

        let current_config = if self.config_path.exists() {
            Some(fs::read_to_string(&self.config_path)?)
        } else {
            None
        };
        let current_digest = current_config
            .as_deref()
            .map(|c| sha256_bytes(c.as_bytes()));

        // If target config was applied to disk (regardless of recorded phase):
        if current_digest.as_deref() == Some(&journal.target_config_digest) {
            self.restore_config(
                journal.pre_operation_config.as_deref(),
                Some(&journal.target_config_digest),
                &candidate_path,
                &displaced_path,
            )?;
            drop(rec_lock.take());
            drop(service_rec_lock.take());

            if journal.was_daemon_running {
                let rec_st = lifecycle.status()?;
                let authorized_running = if is_daemon_running(&rec_st) {
                    let curr_inst = rec_st.process.as_ref().map(|p| p.instance.as_str());
                    if curr_inst == journal.candidate_daemon_instance.as_deref() {
                        journal.candidate_daemon_instance.clone()
                    } else if curr_inst == journal.pre_daemon_instance.as_deref() {
                        journal.pre_daemon_instance.clone()
                    } else if curr_inst == journal.compensated_daemon_instance.as_deref() {
                        journal.compensated_daemon_instance.clone()
                    } else if let Some(matched) = curr_inst.and_then(|ci| {
                        journal
                            .historical_compensated_instances
                            .iter()
                            .find(|h| h.as_str() == ci)
                            .cloned()
                    }) {
                        Some(matched)
                    } else {
                        journal.phase = OperationPhase::Failed;
                        state.in_progress = Some(journal);
                        self.save_state(&state)?;
                        bail!(
                            "conflict during recovery: an independent daemon was started; refusing to stop it"
                        );
                    }
                } else {
                    None
                };

                let recovery_inst = crate::token::generate();
                journal.phase = OperationPhase::RollingBack;
                if let Some(old_comp) = journal.compensated_daemon_instance.take() {
                    if !journal.historical_compensated_instances.contains(&old_comp) {
                        journal.historical_compensated_instances.push(old_comp);
                    }
                }
                journal.compensated_daemon_instance = Some(recovery_inst.clone());
                state.in_progress = Some(journal.clone());
                self.save_state(&state)?;

                let restart_res = self.restart_or_start_daemon(
                    &lifecycle,
                    authorized_running.as_deref(),
                    Some(&recovery_inst),
                );
                if let Err(re) = restart_res {
                    // Do not discard error and do not clear journal
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!("recovery restored configuration but baseline daemon restart failed: {re:#}");
                }
                let st = lifecycle.status()?;
                let process_digest = st.process.as_ref().map(|p| p.config_digest.as_str());
                let proc_inst = st.process.as_ref().map(|p| p.instance.as_str());
                let empty_digest = sha256_bytes(b"");
                let baseline_digest = journal
                    .pre_operation_config_digest
                    .as_deref()
                    .unwrap_or(&empty_digest);
                ensure!(
                    st.running && process_digest == Some(baseline_digest) && proc_inst == Some(&recovery_inst),
                    "recovery restored configuration but daemon is not running with baseline digest"
                );
                journal.historical_compensated_instances.clear();
                state.in_progress = Some(journal.clone());
                self.save_state(&state)?;
            } else {
                // Baseline was stopped and no independent daemon was running.
                let post_stop = lifecycle.status()?;
                if post_stop.running || post_stop.process.is_some() {
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!(
                        "conflict during recovery: an independent daemon was detected while baseline was stopped; refusing to stop it"
                    );
                }
                let baseline_cfg = journal
                    .pre_operation_config
                    .as_deref()
                    .and_then(|text| Config::from_yaml(text).ok());
                if let Err(e) = check_daemon_ownership(&post_stop, baseline_cfg.as_ref(), None) {
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!("recovery restored configuration but daemon ownership check failed: {e:#}; refusing to clear journal");
                }
            }
        } else if current_digest == journal.pre_operation_config_digest {
            drop(rec_lock.take());
            drop(service_rec_lock.take());
            // Configuration matches baseline (including when both are None)!
            let empty_digest = sha256_bytes(b"");
            let baseline_cfg_digest = journal
                .pre_operation_config_digest
                .as_deref()
                .unwrap_or(&empty_digest);

            if journal.was_daemon_running {
                let st = lifecycle.status()?;
                let process_digest = st.process.as_ref().map(|p| p.config_digest.as_str());
                if !st.running || process_digest != Some(baseline_cfg_digest) {
                    let rec_st = lifecycle.status()?;
                    let authorized_running = if is_daemon_running(&rec_st) {
                        let curr_inst = rec_st.process.as_ref().map(|p| p.instance.as_str());
                        if curr_inst == journal.candidate_daemon_instance.as_deref() {
                            journal.candidate_daemon_instance.clone()
                        } else if curr_inst == journal.pre_daemon_instance.as_deref() {
                            journal.pre_daemon_instance.clone()
                        } else if curr_inst == journal.compensated_daemon_instance.as_deref() {
                            journal.compensated_daemon_instance.clone()
                        } else if let Some(matched) = curr_inst.and_then(|ci| {
                            journal
                                .historical_compensated_instances
                                .iter()
                                .find(|h| h.as_str() == ci)
                                .cloned()
                        }) {
                            Some(matched)
                        } else {
                            journal.phase = OperationPhase::Failed;
                            state.in_progress = Some(journal);
                            self.save_state(&state)?;
                            bail!(
                                "conflict during recovery: an independent daemon was started; refusing to stop it"
                            );
                        }
                    } else {
                        None
                    };

                    let recovery_inst = crate::token::generate();
                    journal.phase = OperationPhase::RollingBack;
                    if let Some(old_comp) = journal.compensated_daemon_instance.take() {
                        if !journal.historical_compensated_instances.contains(&old_comp) {
                            journal.historical_compensated_instances.push(old_comp);
                        }
                    }
                    journal.compensated_daemon_instance = Some(recovery_inst.clone());
                    state.in_progress = Some(journal.clone());
                    self.save_state(&state)?;

                    let restart_res = self.restart_or_start_daemon(
                        &lifecycle,
                        authorized_running.as_deref(),
                        Some(&recovery_inst),
                    );
                    if let Err(re) = restart_res {
                        journal.phase = OperationPhase::Failed;
                        state.in_progress = Some(journal);
                        self.save_state(&state)?;
                        bail!("recovery confirmed baseline configuration but baseline daemon restart failed: {re:#}");
                    }
                    let st = lifecycle.status()?;
                    let process_digest = st.process.as_ref().map(|p| p.config_digest.as_str());
                    let proc_inst = st.process.as_ref().map(|p| p.instance.as_str());
                    ensure!(
                        st.running && process_digest == Some(baseline_cfg_digest) && proc_inst == Some(&recovery_inst),
                        "recovery confirmed baseline configuration but daemon is not running with baseline configuration"
                    );
                    journal.historical_compensated_instances.clear();
                    state.in_progress = Some(journal.clone());
                    self.save_state(&state)?;
                } else {
                    let curr_inst = st.process.as_ref().map(|p| p.instance.as_str());
                    let is_original_baseline = journal.pre_daemon_instance.as_deref().is_some()
                        && curr_inst == journal.pre_daemon_instance.as_deref();
                    let is_compensated_baseline =
                        (journal.compensated_daemon_instance.as_deref().is_some()
                            && curr_inst == journal.compensated_daemon_instance.as_deref())
                            || curr_inst.is_some_and(|inst| {
                                journal
                                    .historical_compensated_instances
                                    .iter()
                                    .any(|h| h == inst)
                            });
                    if is_original_baseline {
                        // Original baseline daemon is still running with baseline config; clear unexecuted compensation reservation
                        journal.compensated_daemon_instance = None;
                        journal.historical_compensated_instances.clear();
                        state.in_progress = Some(journal.clone());
                        self.save_state(&state)?;
                    } else if is_compensated_baseline {
                        // Previous recovery restart succeeded with compensated instance
                        if let Some(ci) = curr_inst {
                            journal.compensated_daemon_instance = Some(ci.to_string());
                            journal.historical_compensated_instances.clear();
                            state.in_progress = Some(journal.clone());
                            self.save_state(&state)?;
                        }
                    } else {
                        journal.phase = OperationPhase::Failed;
                        state.in_progress = Some(journal);
                        self.save_state(&state)?;
                        bail!(
                            "conflict during recovery: an independent daemon was started with baseline configuration; refusing to stop it"
                        );
                    }
                }
            } else {
                let st = lifecycle.status()?;
                if st.running || st.process.is_some() {
                    // Daemon was started independently by an operator with baseline configuration.
                    // Preserve the running daemon and report conflict!
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!(
                        "conflict during recovery: an independent daemon was started with baseline configuration; refusing to stop it"
                    );
                }
                let baseline_cfg = journal
                    .pre_operation_config
                    .as_deref()
                    .and_then(|text| Config::from_yaml(text).ok());
                if let Err(e) = check_daemon_ownership(&st, baseline_cfg.as_ref(), None) {
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!("recovery confirmed baseline configuration but daemon ownership check failed: {e:#}; refusing to clear journal");
                }
            }
        } else {
            // External conflict! Neither target nor baseline matched.
            journal.phase = OperationPhase::Failed;
            state.in_progress = Some(journal);
            self.save_state(&state)?;
            bail!(
                "conflict during recovery: current config.yaml does not match target or baseline digest; refusing to clear journal"
            );
        }

        // Revalidate baseline ownership before finalizing recovery under coordinated lifecycle locking
        let _service_lock = self.service_operation_lock()?;
        let commit_lock = lifecycle
            .lock()
            .context("failed to coordinate lifecycle lock for recovery finalization")?;
        let cur_cfg = self.config_digest()?;
        let expected_baseline_digest = journal.pre_operation_config_digest.clone();
        if cur_cfg != expected_baseline_digest {
            journal.phase = OperationPhase::Failed;
            state.in_progress = Some(journal);
            self.save_state(&state)?;
            bail!(
                "conflict during recovery: config.yaml was externally modified before clearing journal (expected baseline digest {:?}, found {:?})",
                expected_baseline_digest,
                cur_cfg
            );
        }

        let final_st = lifecycle.status_locked().context(
            "failed to determine daemon lifecycle status under recovery finalization lock",
        )?;

        let baseline_cfg = journal
            .pre_operation_config
            .as_deref()
            .and_then(|text| Config::from_yaml(text).ok());
        let expected_instance =
            if journal.pre_daemon_instance.as_deref().is_some_and(|pre| {
                final_st.process.as_ref().map(|p| p.instance.as_str()) == Some(pre)
            }) {
                journal.pre_daemon_instance.clone()
            } else if let Some(proc_inst) = final_st.process.as_ref().map(|p| p.instance.as_str()) {
                if journal.compensated_daemon_instance.as_deref() == Some(proc_inst)
                    || journal
                        .historical_compensated_instances
                        .iter()
                        .any(|h| h == proc_inst)
                {
                    Some(proc_inst.to_string())
                } else {
                    journal
                        .compensated_daemon_instance
                        .clone()
                        .or_else(|| journal.pre_daemon_instance.clone())
                }
            } else {
                journal
                    .compensated_daemon_instance
                    .clone()
                    .or_else(|| journal.pre_daemon_instance.clone())
            };

        if let Err(e) = check_daemon_ownership_post_write(
            &final_st,
            baseline_cfg.as_ref(),
            journal.was_daemon_running,
            expected_instance.as_deref(),
        ) {
            journal.phase = OperationPhase::Failed;
            state.in_progress = Some(journal);
            self.save_state(&state)?;
            bail!("conflict during recovery: daemon ownership check failed before clearing journal: {e:#}");
        }

        if journal.was_daemon_running {
            if !final_st.running {
                journal.phase = OperationPhase::Failed;
                state.in_progress = Some(journal);
                self.save_state(&state)?;
                bail!("conflict during recovery: baseline daemon is not running before clearing journal");
            }
            let empty_digest = sha256_bytes(b"");
            let baseline_digest = expected_baseline_digest
                .as_deref()
                .unwrap_or(&empty_digest)
                .to_string();
            let proc_digest = final_st.process.as_ref().map(|p| p.config_digest.as_str());
            if proc_digest != Some(&baseline_digest) {
                journal.phase = OperationPhase::Failed;
                state.in_progress = Some(journal);
                self.save_state(&state)?;
                bail!(
                    "conflict during recovery: baseline daemon running with mismatched config digest before clearing journal (expected {baseline_digest}, got {:?})",
                    proc_digest
                );
            }
        }

        state.history.push(OperationRecord {
            operation_id: journal.operation_id,
            kind: journal.kind,
            generation: state.generation,
            bundle_sha256: journal.target_bundle_sha256,
            from_bundle_sha256: journal.source_bundle_sha256,
            timestamp_utc: now_utc(),
            status: "failed (recovered)".into(),
            detail: "recovery verified baseline configuration and daemon state".into(),
        });
        state.in_progress = None;
        self.save_state(&state)?;
        drop(commit_lock);
        Ok(())
    }

    /// Queries the status of installed MCP profiles and daemon binding.
    pub fn status(&self) -> Result<ProfileStatus> {
        let state = self.load_state()?;
        let lifecycle = crate::lifecycle::Manager::new(&self.home);
        let daemon_st = lifecycle.status();
        let daemon_running = daemon_st.as_ref().is_ok_and(|s| s.running);
        let daemon_instance = daemon_st
            .as_ref()
            .ok()
            .and_then(|s| s.process.as_ref())
            .map(|p| p.instance.clone());
        let configuration_matches = (|| -> Result<bool> {
            let Some(active) = &state.active_bundle_sha256 else {
                return Ok(false);
            };
            let revision = self.revisions.join(active);
            let bundle = verify_bundle_files(&revision)?;
            ensure!(bundle.bundle_sha256 == *active, "active bundle changed");
            let (bytes, _) = read_bundle_file(&self.config_path)?;
            let config = Config::from_yaml(std::str::from_utf8(&bytes)?)?;
            Ok(config.enforce
                && !config.judge.enabled
                && config.native.is_some_and(|native| {
                    native.registry_path == revision.join("registry.json")
                        && native.registry_sha256 == bundle.registry_sha256
                }))
        })();
        let configuration_status = if state.active_bundle_sha256.is_none() {
            "not_configured"
        } else if configuration_matches.as_ref().is_ok_and(|matches| *matches) {
            "configured"
        } else {
            "conflict"
        };
        let runtime_status = if state.in_progress.is_some() {
            "incomplete"
        } else if daemon_st.is_err() {
            "unavailable"
        } else if !daemon_running {
            "unavailable_daemon_stopped"
        } else if configuration_status != "configured" {
            "conflict"
        } else {
            let disk_digest = self.config_digest()?;
            if daemon_st
                .as_ref()
                .ok()
                .and_then(|s| s.process.as_ref())
                .is_some_and(|p| Some(p.config_digest.as_str()) == disk_digest.as_deref())
            {
                "daemon_configuration_verified"
            } else {
                "conflict"
            }
        };

        let revisions_count = if self.revisions.is_dir() {
            fs::read_dir(&self.revisions)?
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
                .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                .count()
        } else {
            0
        };

        let last_operation = state.history.last().cloned();

        Ok(ProfileStatus {
            schema_version: state.schema_version,
            generation: state.generation,
            active_bundle_sha256: state.active_bundle_sha256,
            previous_bundle_sha256: state.previous_bundle_sha256,
            revisions_count,
            daemon_running,
            daemon_instance,
            configuration_status: configuration_status.into(),
            runtime_status: runtime_status.into(),
            host_reload_status: "unverified".into(),
            in_progress: state.in_progress,
            last_operation,
        })
    }
}

#[cfg(test)]
mod tests;
