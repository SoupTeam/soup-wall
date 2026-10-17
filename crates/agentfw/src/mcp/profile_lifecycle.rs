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

/// Verifies all required bundle files exist and calculates deterministic digests.
pub fn verify_bundle_files(dir: &Path) -> Result<BundleFiles> {
    ensure_safe_dir(dir)?;

    let mut file_digests: BTreeMap<String, String> = BTreeMap::new();
    let mut sorted_files = REQUIRED_BUNDLE_FILES;
    sorted_files.sort_unstable();

    for filename in sorted_files {
        let file_path = dir.join(filename);
        let (_, digest) = read_bundle_file(&file_path)?;
        file_digests.insert(filename.to_string(), digest);
    }

    let mut bundle_hasher = Sha256::new();
    for (filename, digest) in &file_digests {
        let line = format!("{}:{}\n", filename, digest);
        bundle_hasher.update(line.as_bytes());
    }
    let bundle_sha256 = format!("{:x}", bundle_hasher.finalize());

    let registry_sha256 = file_digests
        .get("registry.json")
        .cloned()
        .context("missing registry.json in verified bundle files")?;

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
        if !self.home.exists() {
            fs::create_dir_all(&self.home)?;
        }
        if !self.root.exists() {
            fs::create_dir_all(&self.root)?;
        }
        if !self.revisions.exists() {
            fs::create_dir_all(&self.revisions)?;
        }

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
        let state: ProfileState = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid profile state json: {}", self.state_path.display()))?;
        ensure!(
            state.schema_version == CURRENT_SCHEMA_VERSION,
            "unsupported profile state schema version: {}",
            state.schema_version
        );
        Ok(state)
    }

    pub fn save_state(&self, state: &ProfileState) -> Result<()> {
        let json = serde_json::to_string_pretty(state)?;
        let tmp_path = self
            .root
            .join(format!(".state.tmp-{}", std::process::id()));
        let mut file = File::create(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
        }

        fs::rename(&tmp_path, &self.state_path)?;
        Ok(())
    }

    /// Stages a bundle into the immutable revisions repository.
    fn stage_revision(&self, src_dir: &Path) -> Result<BundleFiles> {
        let bundle = verify_bundle_files(src_dir)?;
        let target_dir = self.revisions.join(&bundle.bundle_sha256);

        if target_dir.exists() {
            // Validate existing revision integrity before returning
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
            .join(format!(".stage-{}", bundle.bundle_sha256));
        if stage_dir.exists() {
            let _ = fs::remove_dir_all(&stage_dir);
        }
        fs::create_dir_all(&stage_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&stage_dir, fs::Permissions::from_mode(0o700))?;
        }

        for filename in REQUIRED_BUNDLE_FILES {
            let src_file = src_dir.join(filename);
            let dst_file = stage_dir.join(filename);
            let content = fs::read(&src_file)?;
            let mut out = File::create(&dst_file)?;
            out.write_all(&content)?;
            out.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dst_file, fs::Permissions::from_mode(0o600))?;
            }
        }

        fs::rename(&stage_dir, &target_dir)?;
        let final_bundle = verify_bundle_files(&target_dir)?;
        ensure!(
            final_bundle.bundle_sha256 == bundle.bundle_sha256,
            "staged bundle verification failed"
        );
        Ok(bundle)
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

    fn write_config(&self, config_yaml: &str) -> Result<()> {
        let tmp_path = self
            .home
            .join(format!(".config.yaml.tmp-{}", std::process::id()));
        let mut file = File::create(&tmp_path)?;
        file.write_all(config_yaml.as_bytes())?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
        }
        fs::rename(&tmp_path, &self.config_path)?;
        Ok(())
    }

    fn restore_config(&self, pre_operation_config: Option<&str>) -> Result<()> {
        if let Some(text) = pre_operation_config {
            self.write_config(text)?;
        } else if self.config_path.exists() {
            let _ = fs::remove_file(&self.config_path);
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
        ensure!(
            st.running,
            "daemon reported not running after restart"
        );
        let proc = st.process.as_ref().context("missing running daemon process record")?;
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
        let daemon_st = lifecycle.status().ok();
        let was_running = daemon_st.as_ref().map(|s| s.running).unwrap_or(false);
        let pre_instance = daemon_st
            .as_ref()
            .and_then(|s| s.process.as_ref().map(|p| p.instance.clone()));

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
            pre_operation_config_digest: pre_config_digest,
            target_config_digest: target_config_digest.clone(),
            was_daemon_running: was_running,
            pre_daemon_instance: pre_instance,
            started_at_utc: now_utc(),
        });
        self.save_state(&state)?;

        // 2. Write config.yaml
        self.write_config(&target_yaml)?;
        state.in_progress.as_mut().unwrap().phase = OperationPhase::ConfigWritten;
        self.save_state(&state)?;

        // 3. Daemon restart & verification if running
        let mut verified = true;
        if was_running {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::DaemonRestarting;
            self.save_state(&state)?;
            if let Err(e) = self.restart_and_verify_daemon(&lifecycle, &target_config_digest) {
                // Automatic compensation: rollback config and restart baseline daemon
                state.in_progress.as_mut().unwrap().phase = OperationPhase::RollingBack;
                self.save_state(&state)?;
                self.restore_config(pre_config.as_deref())?;
                let _ = lifecycle.restart();
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

        // Compute semantic diff against active revision
        let active_dir = self.revisions.join(&active_bundle);
        let new_dir = self.revisions.join(&bundle.bundle_sha256);
        let diff = compute_profile_diff(&active_dir, &new_dir)?;

        if diff.authority_change_requires_review || !diff.compatible_without_review {
            let diff_json = serde_json::to_string(&diff)?;
            let diff_hash = sha256_bytes(diff_json.as_bytes());
            let accepted = match accept_diff {
                Some("yes") => true,
                Some(val) if val == diff_hash => true,
                _ => false,
            };
            ensure!(
                accepted,
                "profile upgrade introduces authority changes requiring confirmation (diff hash: {}). Rerun with --accept-diff",
                diff_hash
            );
        }

        let next_gen = state
            .generation
            .checked_add(1)
            .context("generation overflow")?;
        let op_id = format!("op-{}", crate::token::generate());
        let lifecycle = crate::lifecycle::Manager::new(&self.home);
        let daemon_st = lifecycle.status().ok();
        let was_running = daemon_st.as_ref().map(|s| s.running).unwrap_or(false);
        let pre_instance = daemon_st
            .as_ref()
            .and_then(|s| s.process.as_ref().map(|p| p.instance.clone()));

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
            pre_operation_config_digest: pre_config_digest,
            target_config_digest: target_config_digest.clone(),
            was_daemon_running: was_running,
            pre_daemon_instance: pre_instance,
            started_at_utc: now_utc(),
        });
        self.save_state(&state)?;

        // 2. Write config.yaml
        self.write_config(&target_yaml)?;
        state.in_progress.as_mut().unwrap().phase = OperationPhase::ConfigWritten;
        self.save_state(&state)?;

        // 3. Daemon restart & verification if running
        let mut verified = true;
        if was_running {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::DaemonRestarting;
            self.save_state(&state)?;
            if let Err(e) = self.restart_and_verify_daemon(&lifecycle, &target_config_digest) {
                // Automatic compensation: rollback config and restart daemon
                state.in_progress.as_mut().unwrap().phase = OperationPhase::RollingBack;
                self.save_state(&state)?;
                self.restore_config(pre_config.as_deref())?;
                let _ = lifecycle.restart();
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
            Some(rev) => rev.to_string(),
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

        // Compute diff
        let active_dir = self.revisions.join(&active_bundle);
        let diff = compute_profile_diff(&active_dir, &target_dir)?;
        if diff.authority_change_requires_review || !diff.compatible_without_review {
            let diff_json = serde_json::to_string(&diff)?;
            let diff_hash = sha256_bytes(diff_json.as_bytes());
            let accepted = match accept_diff {
                Some("yes") => true,
                Some(val) if val == diff_hash => true,
                _ => false,
            };
            ensure!(
                accepted,
                "profile rollback introduces authority changes requiring confirmation (diff hash: {}). Rerun with --accept-diff",
                diff_hash
            );
        }

        // MONOTONIC GENERATION INCREMENT: Rollback ALWAYS increments generation.
        let next_gen = state
            .generation
            .checked_add(1)
            .context("generation overflow")?;
        let op_id = format!("op-{}", crate::token::generate());
        let lifecycle = crate::lifecycle::Manager::new(&self.home);
        let daemon_st = lifecycle.status().ok();
        let was_running = daemon_st.as_ref().map(|s| s.running).unwrap_or(false);
        let pre_instance = daemon_st
            .as_ref()
            .and_then(|s| s.process.as_ref().map(|p| p.instance.clone()));

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
            pre_operation_config_digest: pre_config_digest,
            target_config_digest: target_config_digest.clone(),
            was_daemon_running: was_running,
            pre_daemon_instance: pre_instance,
            started_at_utc: now_utc(),
        });
        self.save_state(&state)?;

        // 2. Write config.yaml
        self.write_config(&target_yaml)?;
        state.in_progress.as_mut().unwrap().phase = OperationPhase::ConfigWritten;
        self.save_state(&state)?;

        // 3. Daemon restart & verification if running
        let mut verified = true;
        if was_running {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::DaemonRestarting;
            self.save_state(&state)?;
            if let Err(e) = self.restart_and_verify_daemon(&lifecycle, &target_config_digest) {
                state.in_progress.as_mut().unwrap().phase = OperationPhase::RollingBack;
                self.save_state(&state)?;
                self.restore_config(pre_config.as_deref())?;
                let _ = lifecycle.restart();
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
        let Some(journal) = state.in_progress.take() else {
            return Ok(());
        };

        let lifecycle = crate::lifecycle::Manager::new(&self.home);

        match journal.phase {
            OperationPhase::Staged => {
                // Config was never written; only candidate files were staged in revisions/
            }
            OperationPhase::ConfigWritten
            | OperationPhase::DaemonRestarting
            | OperationPhase::RollingBack
            | OperationPhase::Failed => {
                let current_config = if self.config_path.exists() {
                    Some(fs::read_to_string(&self.config_path)?)
                } else {
                    None
                };
                let current_digest =
                    current_config.as_deref().map(|c| sha256_bytes(c.as_bytes()));
                if current_digest.as_deref() == Some(&journal.target_config_digest) {
                    self.restore_config(journal.pre_operation_config.as_deref())?;
                    if journal.was_daemon_running {
                        let _ = lifecycle.restart();
                    }
                }
            }
            OperationPhase::Verified => {
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
            }
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
        let dummy_hash = "0".repeat(64);
        let registry = json!([
            {
                "name": tool_name,
                "description": "test tool",
                "authority": "ReadOnly",
                "inputSchema": { "type": "object" }
            }
        ]);
        let profile = json!({
            "format": "sw-mcp/operator-profile/1",
            "server_id": server_id,
            "server_version": "1.0",
            "snapshot_sha256": dummy_hash,
            "declaration_sha256": dummy_hash,
            "registry_sha256": dummy_hash,
            "tools": {
                tool_name: {
                    "schema_sha256": dummy_hash,
                    "definition_sha256": dummy_hash,
                    "action_class": "read",
                    "result_provenance": "untrusted",
                    "authority_sha256": dummy_hash,
                    "review_sha256": dummy_hash,
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
                "registry_sha256": dummy_hash
            }
        });

        fs::write(dir.join("registry.json"), serde_json::to_vec(&registry).unwrap()).unwrap();
        fs::write(dir.join("profile.json"), serde_json::to_vec(&profile).unwrap()).unwrap();
        fs::write(dir.join("native-config.json"), serde_json::to_vec(&native_config).unwrap()).unwrap();
        fs::write(dir.join("operator-declarations.json"), b"{\"format\":\"sw-mcp/operator-declaration/1\"}\n").unwrap();
        fs::write(dir.join("resource-profiles.json"), b"[]\n").unwrap();
        fs::write(dir.join("source-snapshot.json"), b"{\"format\":\"sw-mcp/operator-discovery/1\"}\n").unwrap();

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
        assert_eq!(state2.previous_bundle_sha256.as_deref(), Some(hash1.as_str()));

        // 3. Rollback to Bundle 1
        // ZERO STALE AUTHORITY: generation MUST strictly increment to 3!
        let rec3 = mgr.rollback(None, Some(2), Some("yes")).unwrap();
        assert_eq!(rec3.generation, 3);
        assert_eq!(rec3.bundle_sha256, hash1);
        assert_eq!(rec3.kind, OperationKind::Rollback);

        let state3 = mgr.load_state().unwrap();
        assert_eq!(state3.generation, 3);
        assert_eq!(state3.active_bundle_sha256.as_deref(), Some(hash1.as_str()));
        assert_eq!(state3.previous_bundle_sha256.as_deref(), Some(hash2.as_str()));

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
}
