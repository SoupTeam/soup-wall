// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Transactional MCP profile lifecycle management.
//! Enforces immutable bundle staging, atomic config.yaml updates,
//! monotonic generation authority, crash recovery, and automated rollback.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
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
    pub started_at_utc: String,
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
    pub in_progress: Option<OperationJournal>,
    pub last_operation: Option<OperationRecord>,
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
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read bundle file: {}", path.display()))?;
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
    // 1. profile.json
    let profile_val: Value = serde_json::from_slice(&file_bytes["profile.json"])
        .context("invalid JSON in profile.json")?;
    ensure!(
        profile_val.get("format").and_then(|v| v.as_str()) == Some("sw-mcp/operator-profile/1"),
        "unsupported profile.json format"
    );
    ensure!(
        profile_val.get("registry_sha256").and_then(|v| v.as_str()) == Some(&registry_sha256),
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

    let profile_tools = profile_val
        .get("tools")
        .and_then(|t| t.as_object())
        .context("profile.json missing or invalid 'tools' object")?;

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
        let expected_auth_sha = prof_tool
            .get("authority_sha256")
            .and_then(|a| a.as_str())
            .context(format!(
                "profile.json tool '{name}' missing 'authority_sha256'"
            ))?;
        let computed_auth_sha = crate::mcp::profile_author::digest(tool_entry);
        ensure!(
            expected_auth_sha == computed_auth_sha,
            "cross-file authority mismatch: tool '{name}' in registry.json authority hash ({computed_auth_sha}) does not match profile.json ({expected_auth_sha})"
        );
        let reg_action = tool_entry.get("action_class").and_then(|a| a.as_str());
        let prof_action = prof_tool.get("action_class").and_then(|a| a.as_str());
        ensure!(
            reg_action == prof_action,
            "cross-file action mismatch for tool '{name}': registry {:?} vs profile {:?}",
            reg_action,
            prof_action
        );
        let reg_prov = tool_entry.get("result_provenance").and_then(|p| p.as_str());
        let prof_prov = prof_tool.get("result_provenance").and_then(|p| p.as_str());
        ensure!(
            reg_prov == prof_prov,
            "cross-file result provenance mismatch for tool '{name}': registry {:?} vs profile {:?}",
            reg_prov,
            prof_prov
        );
        let reg_schema = tool_entry.get("schema_sha256").and_then(|s| s.as_str());
        let prof_schema = prof_tool.get("schema_sha256").and_then(|s| s.as_str());
        ensure!(
            reg_schema == prof_schema,
            "cross-file schema hash mismatch for tool '{name}': registry {:?} vs profile {:?}",
            reg_schema,
            prof_schema
        );
    }

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
        }
    }

    /// Acquires exclusive non-blocking advisory lock on mcp-profile operations.
    pub fn lock(&self) -> Result<OperationLock> {
        ensure_safe_managed_dir(&self.home)?;
        ensure_safe_managed_dir(&self.root)?;
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
        let bytes = fs::read(&self.state_path)
            .with_context(|| format!("failed to read state: {}", self.state_path.display()))?;
        let state: ProfileState = serde_json::from_slice(&bytes).with_context(|| {
            format!("invalid profile state json: {}", self.state_path.display())
        })?;
        ensure!(
            state.schema_version == CURRENT_SCHEMA_VERSION,
            "unsupported profile state schema version: {}",
            state.schema_version
        );
        Ok(state)
    }

    pub fn save_state(&self, state: &ProfileState) -> Result<()> {
        ensure_safe_managed_dir(&self.root)?;
        let json = serde_json::to_string_pretty(state)?;
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

        fs::rename(&stage_dir, &target_dir)?;
        sync_dir(&self.revisions)?;

        let final_bundle = verify_bundle_files(&target_dir)?;
        ensure!(
            final_bundle.bundle_sha256 == bundle.bundle_sha256,
            "staged bundle verification failed"
        );
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
    ) -> Result<(Option<String>, Option<String>, String, String)> {
        let (pre_config, mut cfg) = if self.config_path.exists() {
            let text = fs::read_to_string(&self.config_path)?;
            let parsed = Config::from_yaml(&text)?;
            (Some(text), parsed)
        } else {
            (None, Config::default())
        };

        let pre_config_digest = pre_config.as_ref().map(|c| sha256_bytes(c.as_bytes()));

        // Point native registry to the immutable revision directory
        cfg.enforce = true;
        cfg.judge.enabled = false;
        let revision_dir = self.revisions.join(bundle_sha256);
        let registry_path = revision_dir.join("registry.json");
        let approval = cfg.native.as_ref().and_then(|n| n.approval.clone());

        cfg.native = Some(NativeCfg {
            registry_path,
            registry_sha256: registry_sha256.to_string(),
            approval,
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

    /// Atomically replaces config.yaml, enforcing Compare-and-Swap (CAS) against expected baseline.
    fn write_config(&self, config_yaml: &str, expected_pre_digest: Option<&str>) -> Result<()> {
        if self.config_path.exists() {
            let current_text = fs::read_to_string(&self.config_path)?;
            let current_digest = sha256_bytes(current_text.as_bytes());
            if let Some(expected) = expected_pre_digest {
                ensure!(
                    current_digest == expected,
                    "concurrent modification detected: config.yaml changed while preparing profile mutation (expected digest {}, found {})",
                    expected,
                    current_digest
                );
            } else {
                bail!("config.yaml unexpectedly appeared while preparing initial installation");
            }
        } else if expected_pre_digest.is_some() {
            bail!("config.yaml unexpectedly disappeared while preparing profile mutation");
        }

        let temp = self.home.join(format!(".{}.tmp", crate::token::generate()));
        let mut file = create_private(&temp)?;
        file.write_all(config_yaml.as_bytes())?;
        file.sync_all()?;
        drop(file);

        fs::rename(&temp, &self.config_path)?;
        sync_dir(&self.home)?;
        Ok(())
    }

    fn restore_config(&self, pre_operation_config: Option<&str>) -> Result<()> {
        if let Some(text) = pre_operation_config {
            let temp = self.home.join(format!(".{}.tmp", crate::token::generate()));
            let mut file = create_private(&temp)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            drop(file);

            fs::rename(&temp, &self.config_path)?;
            sync_dir(&self.home)?;
        } else if self.config_path.exists() {
            let _ = fs::remove_file(&self.config_path);
            sync_dir(&self.home)?;
        }
        Ok(())
    }

    fn restart_and_verify_daemon(
        &self,
        lifecycle: &crate::lifecycle::Manager,
        expected_config_digest: &str,
    ) -> Result<()> {
        lifecycle.restart()?;
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
        Ok(())
    }

    /// Installs an initial profile bundle. Fails if a profile is already active.
    pub fn install(
        &self,
        profile_dir: &Path,
        expected_bundle_sha: Option<&str>,
    ) -> Result<InstalledRecord> {
        let _lock = self.lock()?;
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
        let op_id = format!("op-{}", crate::token::generate());
        let lifecycle = crate::lifecycle::Manager::new(&self.home);

        // FAIL CLOSED: do NOT swallow status errors into was_running = false
        let daemon_st = lifecycle.status().context(
            "failed to determine daemon lifecycle status; cannot safely install profile",
        )?;
        let was_running = daemon_st.running;
        let pre_instance = daemon_st.process.as_ref().map(|p| p.instance.clone());

        let (pre_config, pre_config_digest, target_yaml, target_config_digest) =
            self.prepare_config(&bundle.bundle_sha256, &bundle.registry_sha256)?;

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
            pre_daemon_instance: pre_instance,
            started_at_utc: now_utc(),
        });
        self.save_state(&state)?;

        // 2. Write config.yaml with CAS
        self.write_config(&target_yaml, pre_config_digest.as_deref())?;
        state.in_progress.as_mut().unwrap().phase = OperationPhase::ConfigWritten;
        self.save_state(&state)?;

        // 3. Daemon restart & verification if running
        let mut verified = true;
        if was_running {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::DaemonRestarting;
            self.save_state(&state)?;
            if let Err(e) = self.restart_and_verify_daemon(&lifecycle, &target_config_digest) {
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
                self.restore_config(pre_config.as_deref())?;
                let baseline_restart = lifecycle.restart();
                if let Err(re) = baseline_restart {
                    state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                    self.save_state(&state)?;
                    bail!("candidate daemon failed to boot ({e:#}) and baseline recovery failed to restart ({re:#})");
                }
                let st = lifecycle.status()?;
                ensure!(
                    st.running,
                    "candidate daemon failed to boot ({e:#}); restored baseline configuration but daemon is not running"
                );
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(&state)?;
                bail!("daemon failed to start with new profile ({e:#}); automatically rolled back configuration");
            }
        } else {
            verified = false;
        }

        // 4. Commit state
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
        let new_dir = self.revisions.join(&bundle.bundle_sha256);
        let diff = compute_profile_diff(&active_dir, &new_dir)?;

        if diff.authority_change_requires_review || !diff.compatible_without_review {
            // Cryptographically bind approval to source bundle, target bundle, and generation
            let approval_token = format!("{}:{}:{}", active_bundle, bundle.bundle_sha256, next_gen);
            let approval_hash = sha256_bytes(approval_token.as_bytes());
            let accepted = match accept_diff {
                Some("yes") => true,
                Some(val) if val == approval_hash => true,
                _ => false,
            };
            ensure!(
                accepted,
                "profile upgrade introduces authority changes requiring confirmation (approval token: {}). Rerun with --accept-diff <token> or --accept-diff yes",
                approval_hash
            );
        }

        let op_id = format!("op-{}", crate::token::generate());
        let lifecycle = crate::lifecycle::Manager::new(&self.home);

        // FAIL CLOSED on daemon status
        let daemon_st = lifecycle.status().context(
            "failed to determine daemon lifecycle status; cannot safely upgrade profile",
        )?;
        let was_running = daemon_st.running;
        let pre_instance = daemon_st.process.as_ref().map(|p| p.instance.clone());

        let (pre_config, pre_config_digest, target_yaml, target_config_digest) =
            self.prepare_config(&bundle.bundle_sha256, &bundle.registry_sha256)?;

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
            pre_daemon_instance: pre_instance,
            started_at_utc: now_utc(),
        });
        self.save_state(&state)?;

        // 2. Write config.yaml with CAS
        self.write_config(&target_yaml, pre_config_digest.as_deref())?;
        state.in_progress.as_mut().unwrap().phase = OperationPhase::ConfigWritten;
        self.save_state(&state)?;

        // 3. Daemon restart & verification if running
        let mut verified = true;
        if was_running {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::DaemonRestarting;
            self.save_state(&state)?;
            if let Err(e) = self.restart_and_verify_daemon(&lifecycle, &target_config_digest) {
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
                self.restore_config(pre_config.as_deref())?;
                let baseline_restart = lifecycle.restart();
                if let Err(re) = baseline_restart {
                    state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                    self.save_state(&state)?;
                    bail!("candidate daemon failed to boot ({e:#}) and baseline recovery failed to restart ({re:#})");
                }
                let st = lifecycle.status()?;
                ensure!(
                    st.running,
                    "candidate daemon failed to boot ({e:#}); restored baseline configuration but daemon is not running"
                );
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(&state)?;
                bail!("daemon failed to start with upgraded profile ({e:#}); automatically rolled back to healthy baseline");
            }
        } else {
            verified = false;
        }

        // 4. Commit state
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
        let diff = compute_profile_diff(&active_dir, &target_dir)?;
        if diff.authority_change_requires_review || !diff.compatible_without_review {
            let approval_token = format!(
                "{}:{}:{}",
                active_bundle, target_bundle.bundle_sha256, next_gen
            );
            let approval_hash = sha256_bytes(approval_token.as_bytes());
            let accepted = match accept_diff {
                Some("yes") => true,
                Some(val) if val == approval_hash => true,
                _ => false,
            };
            ensure!(
                accepted,
                "profile rollback introduces authority changes requiring confirmation (approval token: {}). Rerun with --accept-diff <token> or --accept-diff yes",
                approval_hash
            );
        }

        let op_id = format!("op-{}", crate::token::generate());
        let lifecycle = crate::lifecycle::Manager::new(&self.home);

        // FAIL CLOSED on daemon status
        let daemon_st = lifecycle.status().context(
            "failed to determine daemon lifecycle status; cannot safely rollback profile",
        )?;
        let was_running = daemon_st.running;
        let pre_instance = daemon_st.process.as_ref().map(|p| p.instance.clone());

        let (pre_config, pre_config_digest, target_yaml, target_config_digest) =
            self.prepare_config(&target_bundle.bundle_sha256, &target_bundle.registry_sha256)?;

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
            pre_daemon_instance: pre_instance,
            started_at_utc: now_utc(),
        });
        self.save_state(&state)?;

        // 2. Write config.yaml with CAS
        self.write_config(&target_yaml, pre_config_digest.as_deref())?;
        state.in_progress.as_mut().unwrap().phase = OperationPhase::ConfigWritten;
        self.save_state(&state)?;

        // 3. Daemon restart & verification if running
        let mut verified = true;
        if was_running {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::DaemonRestarting;
            self.save_state(&state)?;
            if let Err(e) = self.restart_and_verify_daemon(&lifecycle, &target_config_digest) {
                // Check for supersession before automatic compensation
                let cur_digest = self.config_digest()?;
                if cur_digest.as_deref() != Some(&target_config_digest) {
                    state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                    self.save_state(&state)?;
                    bail!("rolled-back candidate daemon failed to boot ({e:#}); config.yaml was modified externally, refusing to overwrite");
                }
                state.in_progress.as_mut().unwrap().phase = OperationPhase::RollingBack;
                self.save_state(&state)?;
                self.restore_config(pre_config.as_deref())?;
                let baseline_restart = lifecycle.restart();
                if let Err(re) = baseline_restart {
                    state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                    self.save_state(&state)?;
                    bail!("rolled-back candidate daemon failed to boot ({e:#}) and baseline recovery failed ({re:#})");
                }
                let st = lifecycle.status()?;
                ensure!(
                    st.running,
                    "rolled-back candidate daemon failed to boot ({e:#}); restored baseline configuration but daemon is not running"
                );
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(&state)?;
                bail!("daemon failed to start with rolled-back profile ({e:#}); restored baseline");
            }
        } else {
            verified = false;
        }

        // 4. Commit state
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
        let mut state = self.load_state()?;
        let Some(mut journal) = state.in_progress.take() else {
            return Ok(());
        };

        let lifecycle = crate::lifecycle::Manager::new(&self.home);

        let current_config = if self.config_path.exists() {
            Some(fs::read_to_string(&self.config_path)?)
        } else {
            None
        };
        let current_digest = current_config
            .as_deref()
            .map(|c| sha256_bytes(c.as_bytes()));

        if journal.phase == OperationPhase::Verified {
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

        // If target config was applied to disk (regardless of recorded phase):
        if current_digest.as_deref() == Some(&journal.target_config_digest) {
            self.restore_config(journal.pre_operation_config.as_deref())?;
            if journal.was_daemon_running {
                let restart_res = lifecycle.restart();
                if let Err(re) = restart_res {
                    // Do not discard error and do not clear journal
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!("recovery restored configuration but baseline daemon restart failed: {re:#}");
                }
                let st = lifecycle.status()?;
                ensure!(
                    st.running,
                    "recovery restored configuration but daemon is not running"
                );
            }
        } else if current_digest == journal.pre_operation_config_digest {
            // Configuration matches baseline (including when both are None)!
            if journal.was_daemon_running {
                let st = lifecycle.status()?;
                if !st.running {
                    let restart_res = lifecycle.restart();
                    if let Err(re) = restart_res {
                        journal.phase = OperationPhase::Failed;
                        state.in_progress = Some(journal);
                        self.save_state(&state)?;
                        bail!("recovery confirmed baseline configuration but baseline daemon restart failed: {re:#}");
                    }
                    let st = lifecycle.status()?;
                    ensure!(
                        st.running,
                        "recovery confirmed baseline configuration but daemon is not running"
                    );
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

        self.save_state(&state)?;
        Ok(())
    }

    /// Queries the status of installed MCP profiles and daemon binding.
    pub fn status(&self) -> Result<ProfileStatus> {
        let state = self.load_state()?;
        let lifecycle = crate::lifecycle::Manager::new(&self.home);
        let daemon_st = lifecycle.status().ok();
        let daemon_running = daemon_st.as_ref().map(|s| s.running).unwrap_or(false);
        let daemon_instance = daemon_st
            .as_ref()
            .and_then(|s| s.process.as_ref().map(|p| p.instance.clone()));

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
            in_progress: state.in_progress,
            last_operation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn create_test_profile(dir: &Path, server_id: &str, tool_name: &str) -> String {
        fs::create_dir_all(dir).unwrap();
        let entry = json!({
            "name": tool_name,
            "schema_sha256": "1".repeat(64),
            "action_class": "read_only",
            "result_provenance": "untrusted",
            "egress": [],
            "resource_policy": null
        });
        let auth_sha = crate::mcp::profile_author::digest(&entry);
        let registry = json!({
            "contract_version": crate::native::CONTRACT,
            "registry_id": format!("{server_id}-reg"),
            "tools": [entry]
        });
        let reg_bytes = serde_json::to_vec(&registry).unwrap();
        let reg_hash = sha256_bytes(&reg_bytes);

        let profile = json!({
            "format": "sw-mcp/operator-profile/1",
            "server_id": server_id,
            "server_version": "1.0",
            "snapshot_sha256": "0".repeat(64),
            "declaration_sha256": "0".repeat(64),
            "registry_sha256": reg_hash,
            "tools": {
                tool_name: {
                    "schema_sha256": "1".repeat(64),
                    "definition_sha256": "0".repeat(64),
                    "action_class": "read_only",
                    "result_provenance": "untrusted",
                    "authority_sha256": auth_sha,
                    "review_sha256": "0".repeat(64),
                    "workspace": null,
                    "scoped_resources": [],
                    "egress_selectors": []
                }
            },
            "limits": []
        });
        let native_config = json!({
            "native": {
                "registry_path": dir.join("registry.json"),
                "registry_sha256": reg_hash
            }
        });

        fs::write(dir.join("registry.json"), reg_bytes).unwrap();
        fs::write(
            dir.join("profile.json"),
            serde_json::to_vec(&profile).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("native-config.json"),
            serde_json::to_vec(&native_config).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("operator-declarations.json"),
            b"{\"format\":\"sw-mcp/operator-declaration/1\"}\n",
        )
        .unwrap();
        fs::write(dir.join("resource-profiles.json"), b"[]\n").unwrap();
        fs::write(
            dir.join("source-snapshot.json"),
            b"{\"format\":\"sw-mcp/operator-discovery/1\"}\n",
        )
        .unwrap();

        bundle_digest(dir).unwrap()
    }

    #[test]
    fn bundle_digest_computes_deterministic_sha256() {
        let temp = tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let p1 = root.join("p1");
        let hash1 = create_test_profile(&p1, "srv-1", "tool_a");
        let hash2 = bundle_digest(&p1).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));

        let files = verify_bundle_files(&p1).unwrap();
        assert_eq!(files.bundle_sha256, hash1);
        assert_eq!(files.files.len(), 6);
        assert!(files.files.contains_key("registry.json"));
    }

    #[test]
    fn bundle_digest_fails_on_missing_file() {
        let temp = tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let p1 = root.join("p1");
        create_test_profile(&p1, "srv-1", "tool_a");
        fs::remove_file(p1.join("registry.json")).unwrap();

        assert!(bundle_digest(&p1).is_err());
        assert!(verify_bundle_files(&p1).is_err());
    }

    #[test]
    fn bundle_digest_fails_on_symlink() {
        let temp = tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let p1 = root.join("p1");
        create_test_profile(&p1, "srv-1", "tool_a");
        let reg = p1.join("registry.json");
        fs::remove_file(&reg).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(p1.join("profile.json"), &reg).unwrap();

        #[cfg(unix)]
        assert!(bundle_digest(&p1).is_err());
    }

    #[test]
    fn bundle_digest_fails_on_cross_file_mismatch() {
        let temp = tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let p1 = root.join("p1");
        create_test_profile(&p1, "srv-1", "tool_a");

        // Tamper registry.json without updating profile.json
        fs::write(p1.join("registry.json"), b"[{\"name\":\"tampered\"}]\n").unwrap();
        assert!(verify_bundle_files(&p1).is_err());
    }

    #[test]
    fn profile_state_serde_roundtrip() {
        let state = ProfileState {
            schema_version: 1,
            generation: 42,
            active_bundle_sha256: Some("a".repeat(64)),
            previous_bundle_sha256: Some("b".repeat(64)),
            history: vec![OperationRecord {
                operation_id: "op-1".into(),
                kind: OperationKind::Install,
                generation: 42,
                bundle_sha256: "a".repeat(64),
                from_bundle_sha256: None,
                timestamp_utc: "2026-10-17T15:00:00Z".into(),
                status: "success".into(),
                detail: "initial install".into(),
            }],
            in_progress: None,
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let recovered: ProfileState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, recovered);
    }

    #[test]
    fn profile_manager_lifecycle_install_upgrade_rollback() {
        let home_temp = tempdir().unwrap();
        let home = home_temp.path().canonicalize().unwrap();
        let mgr = ProfileManager::new(&home);

        let p1_dir = home.join("bundle1");
        let hash1 = create_test_profile(&p1_dir, "srv-1", "tool_1");

        // 1. Initial Install
        let rec1 = mgr.install(&p1_dir, None).unwrap();
        assert_eq!(rec1.generation, 1);
        assert_eq!(rec1.bundle_sha256, hash1);
        assert_eq!(rec1.kind, OperationKind::Install);

        let state = mgr.load_state().unwrap();
        assert_eq!(state.generation, 1);
        assert_eq!(state.active_bundle_sha256.as_deref(), Some(hash1.as_str()));
        assert_eq!(state.previous_bundle_sha256, None);

        // Verify config.yaml
        let cfg_str = fs::read_to_string(&mgr.config_path).unwrap();
        let cfg = Config::from_yaml(&cfg_str).unwrap();
        assert!(cfg.enforce);
        assert!(!cfg.judge.enabled);
        assert!(cfg.native.is_some());
        assert_eq!(
            cfg.native.unwrap().registry_path,
            mgr.revisions.join(&hash1).join("registry.json")
        );

        // Duplicate install must fail
        assert!(mgr.install(&p1_dir, None).is_err());

        // 2. Upgrade to Bundle 2
        let p2_dir = home.join("bundle2");
        let hash2 = create_test_profile(&p2_dir, "srv-1", "tool_2");

        // Fails if expect_gen is wrong
        assert!(mgr.upgrade(&p2_dir, None, Some(99), Some("yes")).is_err());

        // Fails if accept_diff is missing due to tool addition
        assert!(mgr.upgrade(&p2_dir, None, Some(1), None).is_err());

        // Succeeds with accept_diff
        let rec2 = mgr.upgrade(&p2_dir, None, Some(1), Some("yes")).unwrap();
        assert_eq!(rec2.generation, 2);
        assert_eq!(rec2.bundle_sha256, hash2);
        assert_eq!(rec2.kind, OperationKind::Upgrade);

        let state2 = mgr.load_state().unwrap();
        assert_eq!(state2.generation, 2);
        assert_eq!(state2.active_bundle_sha256.as_deref(), Some(hash2.as_str()));
        assert_eq!(
            state2.previous_bundle_sha256.as_deref(),
            Some(hash1.as_str())
        );

        // 3. Rollback to Bundle 1
        // ZERO STALE AUTHORITY: generation MUST strictly increment to 3!
        let rec3 = mgr.rollback(None, Some(2), Some("yes")).unwrap();
        assert_eq!(rec3.generation, 3);
        assert_eq!(rec3.bundle_sha256, hash1);
        assert_eq!(rec3.kind, OperationKind::Rollback);

        let state3 = mgr.load_state().unwrap();
        assert_eq!(state3.generation, 3);
        assert_eq!(state3.active_bundle_sha256.as_deref(), Some(hash1.as_str()));
        assert_eq!(
            state3.previous_bundle_sha256.as_deref(),
            Some(hash2.as_str())
        );

        // Status
        let status = mgr.status().unwrap();
        assert_eq!(status.generation, 3);
        assert_eq!(status.active_bundle_sha256.as_deref(), Some(hash1.as_str()));
        assert_eq!(status.revisions_count, 2);
    }

    #[test]
    fn profile_manager_crash_recovery_restores_config() {
        let home_temp = tempdir().unwrap();
        let home = home_temp.path().canonicalize().unwrap();
        let mgr = ProfileManager::new(&home);

        let p1_dir = home.join("bundle1");
        let _ = create_test_profile(&p1_dir, "srv-1", "tool_1");
        mgr.install(&p1_dir, None).unwrap();

        let original_cfg = fs::read_to_string(&mgr.config_path).unwrap();

        // Simulate interrupted upgrade in ConfigWritten phase
        let mut state = mgr.load_state().unwrap();
        let target_cfg = "bind: \"127.0.0.1\"\nport: 9999\nenforce: true\n";
        fs::write(&mgr.config_path, target_cfg).unwrap();

        state.in_progress = Some(OperationJournal {
            operation_id: "op-crashed".into(),
            kind: OperationKind::Upgrade,
            phase: OperationPhase::ConfigWritten,
            reserved_generation: 2,
            source_bundle_sha256: state.active_bundle_sha256.clone(),
            target_bundle_sha256: "b".repeat(64),
            pre_operation_config: Some(original_cfg.clone()),
            pre_operation_config_digest: Some(sha256_bytes(original_cfg.as_bytes())),
            target_config_digest: sha256_bytes(target_cfg.as_bytes()),
            was_daemon_running: false,
            pre_daemon_instance: None,
            started_at_utc: now_utc(),
        });
        mgr.save_state(&state).unwrap();

        // Calling recover() must restore original_cfg and clear in_progress
        mgr.recover().unwrap();

        let state_after = mgr.load_state().unwrap();
        assert!(state_after.in_progress.is_none());
        let restored_cfg = fs::read_to_string(&mgr.config_path).unwrap();
        assert_eq!(restored_cfg, original_cfg);
    }

    #[test]
    fn profile_manager_cas_rejects_concurrent_config_mutation() {
        let home_temp = tempdir().unwrap();
        let home = home_temp.path().canonicalize().unwrap();
        let mgr = ProfileManager::new(&home);

        let p1_dir = home.join("bundle1");
        let _ = create_test_profile(&p1_dir, "srv-1", "tool_1");
        mgr.install(&p1_dir, None).unwrap();

        let p2_dir = home.join("bundle2");
        let _ = create_test_profile(&p2_dir, "srv-1", "tool_2");

        // External actor mutates config.yaml concurrently
        fs::write(
            &mgr.config_path,
            "bind: \"127.0.0.1\"\nport: 1234\nenforce: true\n",
        )
        .unwrap();

        // CAS check inside prepare_config/write_config must fail if pre_config_digest doesn't match
        let err = mgr.write_config("some: new_yaml\n", Some("0".repeat(64).as_str()));
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("concurrent modification detected"));
    }

    #[test]
    fn bundle_fails_when_tool_authority_tampered_in_registry() {
        let temp = tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let p1 = root.join("p1");
        create_test_profile(&p1, "srv-1", "tool_a");

        // Subtle tamper: keep registry valid sw-native/1, but change action_class to network
        let tampered_entry = json!({
            "name": "tool_a",
            "schema_sha256": "1".repeat(64),
            "action_class": "network",
            "result_provenance": "untrusted",
            "egress": [],
            "resource_policy": null
        });
        let reg = json!({
            "contract_version": crate::native::CONTRACT,
            "registry_id": "srv-1-reg",
            "tools": [tampered_entry]
        });
        let reg_bytes = serde_json::to_vec(&reg).unwrap();
        let reg_hash = sha256_bytes(&reg_bytes);

        // Update registry.json and matching hashes in profile.json and native-config.json
        fs::write(p1.join("registry.json"), &reg_bytes).unwrap();
        let mut prof: Value =
            serde_json::from_slice(&fs::read(p1.join("profile.json")).unwrap()).unwrap();
        prof["registry_sha256"] = json!(reg_hash);
        fs::write(p1.join("profile.json"), serde_json::to_vec(&prof).unwrap()).unwrap();
        let mut nat: Value =
            serde_json::from_slice(&fs::read(p1.join("native-config.json")).unwrap()).unwrap();
        nat["native"]["registry_sha256"] = json!(reg_hash);
        fs::write(
            p1.join("native-config.json"),
            serde_json::to_vec(&nat).unwrap(),
        )
        .unwrap();

        // Must fail with cross-file authority mismatch despite valid JSON and matching registry_sha256!
        let err = verify_bundle_files(&p1);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("cross-file authority mismatch") || msg.contains("action mismatch"));
    }

    #[test]
    fn recover_preserves_journal_on_foreign_config_when_initial_was_absent() {
        let home_temp = tempdir().unwrap();
        let home = home_temp.path().canonicalize().unwrap();
        let mgr = ProfileManager::new(&home);

        let mut state = mgr.load_state().unwrap();
        state.in_progress = Some(OperationJournal {
            operation_id: "op-interrupted-install".into(),
            kind: OperationKind::Install,
            phase: OperationPhase::ConfigWritten,
            reserved_generation: 1,
            source_bundle_sha256: None,
            target_bundle_sha256: "b".repeat(64),
            pre_operation_config: None,
            pre_operation_config_digest: None,
            target_config_digest: "c".repeat(64),
            was_daemon_running: false,
            pre_daemon_instance: None,
            started_at_utc: now_utc(),
        });
        mgr.save_state(&state).unwrap();

        // Foreign rogue config appears on disk
        fs::write(&mgr.config_path, "rogue: config\n").unwrap();

        // recover() must detect external conflict because current_digest != None and != target
        let err = mgr.recover();
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("conflict during recovery"));

        // Journal must be preserved in Failed phase
        let state_after = mgr.load_state().unwrap();
        assert!(state_after.in_progress.is_some());
        assert_eq!(
            state_after.in_progress.unwrap().phase,
            OperationPhase::Failed
        );
    }
}
