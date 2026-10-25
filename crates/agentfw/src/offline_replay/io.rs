// SPDX-License-Identifier: Apache-2.0
//! Explicit, bounded file I/O. No Agent profile discovery or target reads.

use super::{Failure, Result};
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::CString;
    use std::fs::{File, Metadata};
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    use std::path::{Component, PathBuf};

    struct Parent {
        directory: File,
        name: CString,
    }

    fn parent(path: &Path) -> Result<Parent> {
        if path.as_os_str().len() > 4096 {
            return Err(Failure("offline_path_bounds"));
        }
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| Failure("offline_current_directory"))?
                .join(path)
        };
        if absolute.as_os_str().len() > 4096 {
            return Err(Failure("offline_path_bounds"));
        }
        let mut names = Vec::new();
        for component in absolute.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => names.push(
                    CString::new(name.as_bytes()).map_err(|_| Failure("offline_path_invalid"))?,
                ),
                _ => return Err(Failure("offline_path_invalid")),
            }
        }
        if names.is_empty() || names.len() > 64 {
            return Err(Failure("offline_path_bounds"));
        }
        let name = names.pop().unwrap();
        let mut directory =
            File::open(PathBuf::from("/")).map_err(|_| Failure("offline_path_open"))?;
        for component in names {
            // SAFETY: pinned directory fd and NUL-terminated owned component;
            // no ancestor symlink is followed, including a substituted parent.
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_DIRECTORY
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK
                        | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(Failure("offline_unsafe_parent"));
            }
            // SAFETY: this newly opened descriptor has one File owner.
            directory = unsafe { File::from_raw_fd(fd) };
        }
        Ok(Parent { directory, name })
    }

    fn identity(metadata: &Metadata) -> (u64, u64, u64, u32, i64, i64, i64, i64) {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mode(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    }

    pub(super) fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
        let parent = parent(path)?;
        // O_NONBLOCK makes FIFOs/devices fail their metadata check without
        // blocking on an attacker-controlled writer. Never allocate from len.
        let fd = unsafe {
            libc::openat(
                parent.directory.as_raw_fd(),
                parent.name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Failure("offline_input_open"));
        }
        // SAFETY: newly opened descriptor, owned only here.
        let mut file = unsafe { File::from_raw_fd(fd) };
        let before = file
            .metadata()
            .map_err(|_| Failure("offline_input_metadata"))?;
        if !before.is_file() {
            return Err(Failure("offline_input_nonregular"));
        }
        if before.len() > limit as u64 {
            return Err(Failure("offline_input_bounds"));
        }
        let mut bytes = Vec::with_capacity((before.len() as usize).min(limit) + 1);
        Read::by_ref(&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure("offline_input_read"))?;
        if bytes.len() > limit {
            return Err(Failure("offline_input_bounds"));
        }
        let after = file
            .metadata()
            .map_err(|_| Failure("offline_input_metadata"))?;
        if identity(&before) != identity(&after) || after.len() != bytes.len() as u64 {
            return Err(Failure("offline_input_changed"));
        }
        Ok(bytes)
    }

    pub(super) fn export(path: &Path, bytes: &[u8]) -> Result<()> {
        let parent = parent(path)?;
        // SAFETY: all parent components are descriptor-pinned; O_EXCL prevents
        // overwrite and rejects a final symlink. Mode is private from creation.
        let fd = unsafe {
            libc::openat(
                parent.directory.as_raw_fd(),
                parent.name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(Failure("offline_export_create_new"));
        }
        // SAFETY: newly created owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        let created = file
            .metadata()
            .map_err(|_| Failure("offline_export_metadata"))?;
        let write = (|| {
            if created.uid() != unsafe { libc::geteuid() }
                || created.mode() & 0o077 != 0
                || created.nlink() != 1
                || !created.is_file()
            {
                return Err(Failure("offline_export_private"));
            }
            file.write_all(bytes)
                .map_err(|_| Failure("offline_export_partial"))?;
            file.sync_all()
                .map_err(|_| Failure("offline_export_sync"))?;
            let after = file
                .metadata()
                .map_err(|_| Failure("offline_export_metadata"))?;
            if after.len() != bytes.len() as u64 || after.nlink() != 1 || after.mode() & 0o077 != 0
            {
                return Err(Failure("offline_export_changed"));
            }
            Ok(())
        })();
        if write.is_err() {
            // Remove only this exact newly created inode, never a replacement.
            let mut current = std::mem::MaybeUninit::<libc::stat>::uninit();
            let mut owned = std::mem::MaybeUninit::<libc::stat>::uninit();
            // Compare native stat fields from both pinned descriptors. dev_t
            // differs by platform; no lossy or same-type conversion is needed.
            let owned_observed = unsafe { libc::fstat(file.as_raw_fd(), owned.as_mut_ptr()) };
            let observed = unsafe {
                libc::fstatat(
                    parent.directory.as_raw_fd(),
                    parent.name.as_ptr(),
                    current.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if observed == 0 && owned_observed == 0 {
                let current = unsafe { current.assume_init() };
                let owned = unsafe { owned.assume_init() };
                if current.st_dev == owned.st_dev && current.st_ino == owned.st_ino {
                    unsafe {
                        libc::unlinkat(parent.directory.as_raw_fd(), parent.name.as_ptr(), 0);
                    }
                }
            }
        }
        write
    }
}

pub(super) fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        unix::read(path, limit)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, limit);
        Err(Failure("offline_platform_unsupported"))
    }
}

pub(super) fn export(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        unix::export(path, bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, bytes);
        Err(Failure("offline_platform_unsupported"))
    }
}

pub(super) fn stdout(bytes: &[u8], output: &mut impl Write) -> Result<()> {
    output
        .write_all(bytes)
        .and_then(|()| output.flush())
        .map_err(|_| Failure("offline_stdout_partial_or_closed"))
}
