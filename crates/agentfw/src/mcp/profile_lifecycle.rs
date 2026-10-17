// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Transactional MCP profile lifecycle management.
//! Enforces immutable bundle staging, atomic config.yaml updates,
//! monotonic generation authority, crash recovery, and automated rollback.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// Compute SHA-256 hex string of arbitrary bytes.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_dummy_bundle(dir: &Path) {
        for (i, name) in REQUIRED_BUNDLE_FILES.iter().enumerate() {
            let path = dir.join(name);
            fs::write(&path, format!("{{\"dummy\": {i}}}\n")).unwrap();
        }
    }

    #[test]
    fn bundle_digest_computes_deterministic_sha256() {
        let temp = tempdir().unwrap();
        create_dummy_bundle(temp.path());

        let digest1 = bundle_digest(temp.path()).unwrap();
        let digest2 = bundle_digest(temp.path()).unwrap();
        assert_eq!(digest1, digest2);
        assert_eq!(digest1.len(), 64);
        assert!(digest1.chars().all(|c| c.is_ascii_hexdigit()));

        let files = verify_bundle_files(temp.path()).unwrap();
        assert_eq!(files.bundle_sha256, digest1);
        assert_eq!(files.files.len(), 6);
        assert!(files.files.contains_key("registry.json"));
    }

    #[test]
    fn bundle_digest_fails_on_missing_file() {
        let temp = tempdir().unwrap();
        create_dummy_bundle(temp.path());
        fs::remove_file(temp.path().join("registry.json")).unwrap();

        assert!(bundle_digest(temp.path()).is_err());
        assert!(verify_bundle_files(temp.path()).is_err());
    }

    #[test]
    fn bundle_digest_fails_on_symlink() {
        let temp = tempdir().unwrap();
        create_dummy_bundle(temp.path());
        let reg = temp.path().join("registry.json");
        fs::remove_file(&reg).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(temp.path().join("profile.json"), &reg).unwrap();

        #[cfg(unix)]
        assert!(bundle_digest(temp.path()).is_err());
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
}
