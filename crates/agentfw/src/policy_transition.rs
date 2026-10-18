// SPDX-License-Identifier: Apache-2.0
//! Cross-process boundary between native MCP release and managed activation.
//!
//! The trusted collector holds a shared lock from admission through the actual
//! write/execution boundary. Activation takes the exclusive lock before any
//! engine/session lock. The inode is never replaced; process death releases its
//! locks. Contention defers activation instead of acknowledging unapplied policy.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{ensure, Context};

pub const CONTRACT: &str = "sw-managed-native/1";

#[derive(Clone)]
pub struct Barrier {
    path: PathBuf,
}

/// Keep alive through the protected boundary; never clone the file descriptor.
pub struct Boundary {
    _file: File,
}

impl Barrier {
    pub fn new(home: &Path) -> anyhow::Result<Self> {
        let barrier = Self {
            path: home.join("managed-native-boundary.lock"),
        };
        drop(barrier.open()?);
        Ok(barrier)
    }

    fn open(&self) -> anyhow::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Open the reparse point itself so descriptor validation rejects it.
            options.custom_flags(0x0020_0000);
        }
        let file = options
            .open(&self.path)
            .context("cannot open managed native boundary")?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file(),
            "managed native boundary is not a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                metadata.nlink() == 1,
                "managed native boundary has multiple links"
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "managed native boundary is a reparse point"
            );
        }
        Ok(file)
    }

    /// Nonblocking: a busy collector must not block the daemon's async worker
    /// or cause a signed deployment to be recorded as rejected.
    pub fn try_activation(&self) -> anyhow::Result<Option<Boundary>> {
        let file = self.open()?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Boundary { _file: file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(error.into()),
        }
    }

    pub async fn release_boundary(&self) -> anyhow::Result<Boundary> {
        let file = self.open()?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match file.try_lock_shared() {
                Ok(()) => return Ok(Boundary { _file: file }),
                Err(TryLockError::Error(error)) => return Err(error.into()),
                Err(TryLockError::WouldBlock) => {
                    ensure!(
                        tokio::time::Instant::now() < deadline,
                        "managed native boundary timed out"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn activation_waits_for_every_independent_collector_boundary() {
        let home = tempfile::tempdir().unwrap();
        let first = Barrier::new(home.path()).unwrap();
        let second = Barrier::new(home.path()).unwrap();
        let a = first.release_boundary().await.unwrap();
        let b = second.release_boundary().await.unwrap();
        assert!(first.try_activation().unwrap().is_none());
        drop(a);
        assert!(first.try_activation().unwrap().is_none());
        drop(b);
        let activation = first.try_activation().unwrap().unwrap();
        assert!(second.try_activation().unwrap().is_none());
        drop(activation);
        assert!(second.try_activation().unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_fifo_symlink_and_hardlink_without_waiting() {
        use std::os::unix::fs::symlink;
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("managed-native-boundary.lock");
        let raw = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
        assert!(Barrier::new(home.path()).is_err());
        std::fs::remove_file(&path).unwrap();
        let target = home.path().join("other");
        std::fs::write(&target, b"unchanged").unwrap();
        symlink(&target, &path).unwrap();
        assert!(Barrier::new(home.path()).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&target, &path).unwrap();
        assert!(Barrier::new(home.path()).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
    }
}
