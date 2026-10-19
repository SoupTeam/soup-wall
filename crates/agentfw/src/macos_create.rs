// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Constrained, atomic macOS ARM64 regular file creation on local APFS volumes.
//!
//! Staging creates an unpredictable private file outside the workspace on the same
//! qualified APFS volume, validates descriptor ownership and absence of extended ACLs,
//! immediately unlinks the file name to produce an anonymous descriptor, writes complete
//! bounded UTF-8 bytes, and flushes them via `fcntl(F_FULLFSYNC)`.
//! Anonymous descriptor publication solves named-source substitution after unlink.
//! The initial stage creation -> validation -> unlink window occurs in a verified private
//! staging namespace outside the workspace. While mode 0700/0600, UID match, and explicit
//! descriptor ACL checks ensure isolation from other unprivileged users, same-UID host-operator
//! interference during initial name creation is outside the in-process trust boundary.
//! Unlinking by name occurs immediately after creating an empty 0600 file and validating its
//! descriptor and refusal of unsupported ACL entries, BEFORE writing any payload. Any mismatch
//! or uncertainty prior to unlink aborts and preserves unknown/foreign entries with honest
//! incomplete-cleanup attribution, never swept by PID/prefix.
//!
//! Once unlinked (`st_nlink == 0`), the descriptor is strictly anonymous. All payload
//! writes, sync, and cancellation/error cleanup operate solely on the retained descriptor.
//! Dropping `StagedCreate` on cancellation or error closes the descriptor and reclaims
//! the anonymous storage blocks with zero filesystem residue.
//!
//! Publication uses Darwin's `fclonefileat(srcfd, dst_dirfd, dst, flags)` with
//! `CLONE_NOFOLLOW_ANY | CLONE_RESOLVE_BENEATH`. Because `srcfd` is identified by its
//! retained open file descriptor, publication is immune to source-name substitution races.
//! Darwin's clone operation is atomic and returns `EEXIST` on destination collision,
//! preventing accidental overwrite of existing files.
//!
//! Publication creates the destination leaf with 0600 mode bits, but effective access on
//! macOS may also be affected by any inherited ACLs from the workspace parent directory.
//! Callers must note that workspace directory ACLs can extend permissions to other users.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};

use crate::mcp::create_file::{CreateFileCommit, CreateFileError, MAX_CREATE_BYTES};

// Exact Darwin SDK values from sys/fcntl.h, sys/mount.h, sys/clonefile.h:
const O_RESOLVE_BENEATH: i32 = 0x0000_1000;
const O_NOFOLLOW_ANY: i32 = 0x2000_0000;
const F_GETPATH: i32 = 50;
const F_FULLFSYNC: i32 = 51;
const MNT_LOCAL: u32 = 0x0000_1000;
const CLONE_NOFOLLOW_ANY: u32 = 0x0008;
const CLONE_RESOLVE_BENEATH: u32 = 0x0010;
const ACL_FIRST_ENTRY: libc::c_int = 0;

const MAX_LEAF_BYTES: usize = 255;

extern "C" {
    fn fclonefileat(
        srcfd: libc::c_int,
        dst_dirfd: libc::c_int,
        dst: *const libc::c_char,
        flags: u32,
    ) -> libc::c_int;
    fn acl_get_fd(fd: libc::c_int) -> *mut libc::c_void;
    fn acl_valid(acl: *mut libc::c_void) -> libc::c_int;
    fn acl_free(obj_p: *mut libc::c_void) -> libc::c_int;
    fn acl_get_entry(
        acl: *mut libc::c_void,
        entry_id: libc::c_int,
        entry_p: *mut *mut libc::c_void,
    ) -> libc::c_int;
}

fn check_no_extended_acl(fd: libc::c_int) -> Result<(), &'static str> {
    if fd < 0 {
        return Err("acl_invalid_fd");
    }
    // Clear errno before invocation so prior syscall errno cannot decide the result.
    unsafe {
        *libc::__error() = 0;
    }
    let acl = unsafe { acl_get_fd(fd) };
    let get_fd_err = unsafe { *libc::__error() };

    if acl.is_null() {
        // On Darwin, an ACL-free descriptor returns NULL with errno == ENOENT.
        // Any other errno (e.g. EBADF, ENOMEM, EOPNOTSUPP, EACCES, EIO) or errno == 0
        // fails closed: unverified or failed query cannot establish a private namespace.
        if get_fd_err == libc::ENOENT {
            return Ok(());
        }
        return Err("acl_query_failed");
    }

    // Verify ACL structure validity before interpreting entry retrieval.
    let valid_rc = unsafe { acl_valid(acl) };
    if valid_rc != 0 {
        unsafe {
            acl_free(acl);
        }
        return Err("acl_invalid_structure");
    }

    // ACL structure is verified valid by acl_valid. Inspect entries.
    // In Darwin POSIX.1e, with a valid ACL and entry_id = ACL_FIRST_ENTRY:
    //   0  : successfully obtained entry descriptor (an entry exists)
    //  -1 with errno == EINVAL: valid ACL contains zero entries (proven empty)
    //  any other rc/errno: query failure, failing closed.
    let mut entry: *mut libc::c_void = std::ptr::null_mut();
    unsafe {
        *libc::__error() = 0;
    }
    let rc = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
    let get_entry_err = unsafe { *libc::__error() };
    unsafe {
        acl_free(acl);
    }

    if rc == 0 {
        // An extended ACL entry is present; strictly refuse unsupported ACL entries.
        return Err("acl_entries_present");
    }

    if rc == -1 && get_entry_err == libc::EINVAL {
        // Verified valid ACL has zero entries.
        return Ok(());
    }

    Err("acl_entry_query_failed")
}

/// Values included in native admission's immutable create binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CreateIdentity {
    pub root_dev: u64,
    pub root_ino: u64,
}

/// A prepared create owns a boundary-constrained descriptor to the workspace root,
/// with ZERO file bytes created or staged.
pub(crate) struct PreparedCreate {
    workspace_file: File,
    workspace_canonical: String,
    leaf_name: String,
    content: Vec<u8>,
    identity: CreateIdentity,
}

impl std::fmt::Debug for PreparedCreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedCreate")
            .field("workspace_canonical", &self.workspace_canonical)
            .field("leaf_name", &self.leaf_name)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// An anonymously staged file on the same APFS volume.
/// Dropping this struct closes the unlinked file descriptor, automatically
/// reclaiming all storage blocks with zero filesystem residue and no TOCTOU races.
#[must_use = "drop to cancel the anonymous stage, or publish after the execution gate"]
pub(crate) struct StagedCreate {
    prepared: PreparedCreate,
    stage_file: File,
    staged_bytes: usize,
}

impl std::fmt::Debug for StagedCreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedCreate")
            .field("staged_bytes", &self.staged_bytes)
            .finish_non_exhaustive()
    }
}

fn error(code: &'static str) -> CreateFileError {
    CreateFileError {
        code,
        committed: false,
        staged_bytes: 0,
        committed_bytes: 0,
        errno: None,
    }
}

fn io_error(code: &'static str, err: io::Error) -> CreateFileError {
    CreateFileError {
        code,
        committed: false,
        staged_bytes: 0,
        committed_bytes: 0,
        errno: err.raw_os_error(),
    }
}

impl PreparedCreate {
    pub(crate) fn prepare(
        workspace: &Path,
        cwd: &Path,
        original: &str,
        expected_canonical: &str,
        content: &str,
    ) -> Result<Self, CreateFileError> {
        if content.len() > MAX_CREATE_BYTES {
            return Err(error("content_too_large"));
        }

        let workspace_str = trusted_absolute(workspace).map_err(|_| error("invalid_workspace"))?;
        let cwd_str = trusted_absolute(cwd).map_err(|_| error("invalid_cwd"))?;
        if workspace_str != cwd_str {
            return Err(error("cwd_workspace_mismatch"));
        }

        let requested = original_target(&cwd_str, original).map_err(|_| error("invalid_path"))?;
        let expected = trusted_absolute(Path::new(expected_canonical))
            .map_err(|_| error("invalid_expected_path"))?;
        if requested != expected {
            return Err(error("ambiguous_path_alias"));
        }

        // Must be a direct child of the workspace.
        let prefix = format!("{workspace_str}/");
        let leaf = requested
            .strip_prefix(&prefix)
            .filter(|leaf| !leaf.contains('/') && !leaf.is_empty() && leaf.len() <= MAX_LEAF_BYTES)
            .ok_or_else(|| error("unsupported_nested_or_ambiguous_path"))?;

        if leaf == "." || leaf == ".." || leaf.chars().any(char::is_control) {
            return Err(error("invalid_leaf"));
        }

        // Open workspace root directory descriptor.
        let root_c_path =
            CString::new(workspace_str.as_bytes()).map_err(|_| error("workspace_path_nul"))?;
        let root_raw_fd = unsafe {
            libc::open(
                root_c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if root_raw_fd < 0 {
            return Err(io_error(
                "workspace_open_failed",
                io::Error::last_os_error(),
            ));
        }
        let workspace_file = unsafe { File::from_raw_fd(root_raw_fd) };

        check_local_apfs(&workspace_file).map_err(|_| error("filesystem_unsupported_not_apfs"))?;

        let root_meta = workspace_file
            .metadata()
            .map_err(|_| error("workspace_stat_failed"))?;
        if !root_meta.file_type().is_dir() {
            return Err(error("workspace_not_directory"));
        }
        let root_dev = root_meta.dev();
        let root_ino = root_meta.ino();

        let root_canonical =
            get_fd_path(&workspace_file).map_err(|_| error("workspace_path_drift"))?;
        if root_canonical != workspace_str {
            return Err(error("workspace_path_drift"));
        }

        // Verify target leaf component does not exist yet.
        let c_leaf_name = CString::new(leaf.as_bytes()).map_err(|_| error("leaf_name_nul"))?;
        let mut leaf_st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                workspace_file.as_raw_fd(),
                c_leaf_name.as_ptr(),
                &mut leaf_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 {
            return Err(error("destination_already_exists"));
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOENT) {
            return Err(io_error("leaf_stat_failed", err));
        }

        Ok(Self {
            workspace_file,
            workspace_canonical: workspace_str,
            leaf_name: leaf.to_owned(),
            content: content.as_bytes().to_vec(),
            identity: CreateIdentity { root_dev, root_ino },
        })
    }

    pub(crate) fn identity(&self) -> &CreateIdentity {
        &self.identity
    }

    pub(crate) fn stage(self) -> Result<StagedCreate, CreateFileError> {
        self.stage_with_custom_dir(None)
    }

    pub(crate) fn stage_with_custom_dir(
        self,
        custom_stage_dir: Option<&str>,
    ) -> Result<StagedCreate, CreateFileError> {
        // 1. Identify private staging directory on the same APFS volume outside workspace.
        let stage_dir_path = match custom_stage_dir {
            Some(dir) => dir.to_string(),
            None => find_or_create_stage_dir(self.identity.root_dev, &self.workspace_canonical)
                .map_err(error)?,
        };

        let stage_dir_c =
            CString::new(stage_dir_path.as_bytes()).map_err(|_| error("stage_dir_path_nul"))?;
        let stage_dir_fd = unsafe {
            libc::open(
                stage_dir_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if stage_dir_fd < 0 {
            return Err(io_error(
                "stage_dir_open_failed",
                io::Error::last_os_error(),
            ));
        }
        let stage_dir = unsafe { File::from_raw_fd(stage_dir_fd) };

        // Verify staging directory descriptor: kernel-resolved canonical path, ownership, mode, volume, APFS.
        let stage_canonical =
            get_fd_path(&stage_dir).map_err(|_| error("stage_dir_path_unverified"))?;
        if is_within(&stage_canonical, &self.workspace_canonical)
            || is_within(&self.workspace_canonical, &stage_canonical)
        {
            return Err(error("stage_dir_inside_or_overlapping_workspace"));
        }

        let mut dir_st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(stage_dir.as_raw_fd(), &mut dir_st) };
        if rc != 0 {
            return Err(io_error(
                "stage_dir_stat_failed",
                io::Error::last_os_error(),
            ));
        }
        if (dir_st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return Err(error("stage_dir_not_directory"));
        }
        if dir_st.st_uid != unsafe { libc::getuid() } {
            return Err(error("stage_dir_owner_mismatch"));
        }
        if (dir_st.st_mode & 0o777) != 0o700 {
            return Err(error("stage_dir_permissions_invalid"));
        }
        if dir_st.st_dev as u64 != self.identity.root_dev {
            return Err(error("stage_dir_volume_mismatch"));
        }
        check_local_apfs(&stage_dir).map_err(|_| error("stage_dir_not_apfs"))?;
        check_no_extended_acl(stage_dir.as_raw_fd())
            .map_err(|_| error("stage_dir_has_unsupported_acl"))?;

        // 2. Open temporary stage file with O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW_ANY | O_RESOLVE_BENEATH.
        let mut stage_file = None;
        for _ in 0..10 {
            let rand_val: u64 = rand::random();
            let stage_name = format!(".stage.{}.{:016x}", std::process::id(), rand_val);
            let c_stage_name = match CString::new(stage_name.as_bytes()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let stage_fd = unsafe {
                libc::openat(
                    stage_dir.as_raw_fd(),
                    c_stage_name.as_ptr(),
                    libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_RDWR
                        | libc::O_CLOEXEC
                        | O_NOFOLLOW_ANY
                        | O_RESOLVE_BENEATH,
                    0o600,
                )
            };
            if stage_fd >= 0 {
                let file = unsafe { File::from_raw_fd(stage_fd) };
                if check_no_extended_acl(file.as_raw_fd()).is_err() {
                    let _ =
                        unsafe { libc::unlinkat(stage_dir.as_raw_fd(), c_stage_name.as_ptr(), 0) };
                    return Err(error("stage_file_has_unsupported_acl"));
                }
                stage_file = Some((file, stage_name));
                break;
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                return Err(io_error("stage_file_create_failed", err));
            }
        }

        let (mut stage_file, stage_name) =
            stage_file.ok_or_else(|| error("stage_create_exhausted"))?;

        let c_stage_name =
            CString::new(stage_name.as_bytes()).map_err(|_| error("stage_name_nul"))?;
        let cleanup_and_err = |err: CreateFileError| -> CreateFileError {
            unsafe { libc::unlinkat(stage_dir.as_raw_fd(), c_stage_name.as_ptr(), 0) };
            err
        };

        // Verify newly created empty stage file metadata.
        let mut stage_st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(stage_file.as_raw_fd(), &mut stage_st) };
        if rc != 0 {
            return Err(cleanup_and_err(io_error(
                "stage_file_stat_failed",
                io::Error::last_os_error(),
            )));
        }
        if (stage_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(cleanup_and_err(error("stage_file_not_regular")));
        }
        if (stage_st.st_mode & 0o777) != 0o600 {
            return Err(cleanup_and_err(error("stage_file_mode_invalid")));
        }
        if stage_st.st_uid != unsafe { libc::getuid() } {
            return Err(cleanup_and_err(error("stage_file_owner_mismatch")));
        }
        if stage_st.st_dev as u64 != self.identity.root_dev {
            return Err(cleanup_and_err(error("stage_file_volume_mismatch")));
        }
        if stage_st.st_nlink != 1 {
            return Err(cleanup_and_err(error("stage_file_links_invalid")));
        }
        if stage_st.st_size != 0 {
            return Err(cleanup_and_err(error("stage_file_initial_size_nonzero")));
        }

        // 3. Immediately unlink the stage file BEFORE writing any payload.
        // This transitions the descriptor to strictly anonymous before holding sensitive bytes.
        // If writing, syncing, or process terminates, the anonymous descriptor is dropped
        // with zero named filesystem residue.
        let rc = unsafe { libc::unlinkat(stage_dir.as_raw_fd(), c_stage_name.as_ptr(), 0) };
        if rc != 0 {
            return Err(io_error("stage_unlink_failed", io::Error::last_os_error()));
        }

        // Verify st_nlink == 0 on the retained descriptor.
        let mut unlinked_st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(stage_file.as_raw_fd(), &mut unlinked_st) };
        if rc != 0 {
            return Err(io_error(
                "stage_post_unlink_stat_failed",
                io::Error::last_os_error(),
            ));
        }
        if unlinked_st.st_nlink != 0 {
            return Err(error("stage_unlink_incomplete"));
        }

        // Close stage_dir descriptor; retained descriptor is now self-sufficient.
        drop(stage_dir);

        // 4. Write payload bytes to anonymous descriptor with counted progress accounting.
        let mut staged_bytes = 0;
        while staged_bytes < self.content.len() {
            let chunk = &self.content[staged_bytes..];
            match stage_file.write(chunk) {
                Ok(0) => {
                    return Err(CreateFileError {
                        code: "stage_write_failed",
                        committed: false,
                        staged_bytes,
                        committed_bytes: 0,
                        errno: None,
                    });
                }
                Ok(count) => staged_bytes += count,
                Err(e) => {
                    return Err(CreateFileError {
                        code: "stage_write_failed",
                        committed: false,
                        staged_bytes,
                        committed_bytes: 0,
                        errno: e.raw_os_error(),
                    });
                }
            }
        }

        let rc = unsafe { libc::fcntl(stage_file.as_raw_fd(), F_FULLFSYNC) };
        if rc != 0 {
            return Err(CreateFileError {
                code: "stage_flush_failed",
                committed: false,
                staged_bytes,
                committed_bytes: 0,
                errno: io::Error::last_os_error().raw_os_error(),
            });
        }

        Ok(StagedCreate {
            staged_bytes,
            prepared: self,
            stage_file,
        })
    }
}

impl StagedCreate {
    pub(crate) fn publish(self) -> Result<CreateFileCommit, CreateFileError> {
        // 1. Re-validate workspace root descriptor and path.
        let mut root_st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(self.prepared.workspace_file.as_raw_fd(), &mut root_st) };
        if rc != 0 {
            return Err(CreateFileError {
                code: "workspace_root_stat_failed",
                committed: false,
                staged_bytes: self.staged_bytes,
                committed_bytes: 0,
                errno: io::Error::last_os_error().raw_os_error(),
            });
        }
        if root_st.st_dev as u64 != self.prepared.identity.root_dev
            || root_st.st_ino != self.prepared.identity.root_ino
        {
            return Err(CreateFileError {
                code: "workspace_root_inode_drift",
                committed: false,
                staged_bytes: self.staged_bytes,
                committed_bytes: 0,
                errno: None,
            });
        }
        let current_path =
            get_fd_path(&self.prepared.workspace_file).map_err(|_| CreateFileError {
                code: "workspace_path_drift",
                committed: false,
                staged_bytes: self.staged_bytes,
                committed_bytes: 0,
                errno: None,
            })?;
        if current_path != self.prepared.workspace_canonical {
            return Err(CreateFileError {
                code: "workspace_path_drift",
                committed: false,
                staged_bytes: self.staged_bytes,
                committed_bytes: 0,
                errno: None,
            });
        }

        // 2. Pre-publication check: destination leaf must still be absent; fail closed on any non-ENOENT error.
        let c_leaf_name =
            CString::new(self.prepared.leaf_name.as_bytes()).map_err(|_| CreateFileError {
                code: "leaf_name_nul",
                committed: false,
                staged_bytes: self.staged_bytes,
                committed_bytes: 0,
                errno: None,
            })?;
        let mut dest_st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                self.prepared.workspace_file.as_raw_fd(),
                c_leaf_name.as_ptr(),
                &mut dest_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 {
            return Err(CreateFileError {
                code: "destination_already_exists",
                committed: false,
                staged_bytes: self.staged_bytes,
                committed_bytes: 0,
                errno: Some(libc::EEXIST),
            });
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOENT) {
            return Err(CreateFileError {
                code: "destination_stat_failed",
                committed: false,
                staged_bytes: self.staged_bytes,
                committed_bytes: 0,
                errno: err.raw_os_error(),
            });
        }

        // 3. Atomically publish from the anonymous descriptor using fclonefileat.
        let flags = CLONE_NOFOLLOW_ANY | CLONE_RESOLVE_BENEATH;
        let rc = unsafe {
            fclonefileat(
                self.stage_file.as_raw_fd(),
                self.prepared.workspace_file.as_raw_fd(),
                c_leaf_name.as_ptr(),
                flags,
            )
        };

        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EEXIST) {
                return Err(CreateFileError {
                    code: "destination_already_exists",
                    committed: false,
                    staged_bytes: self.staged_bytes,
                    committed_bytes: 0,
                    errno: Some(libc::EEXIST),
                });
            }
            return Err(CreateFileError {
                code: "publication_failed",
                committed: false,
                staged_bytes: self.staged_bytes,
                committed_bytes: 0,
                errno: err.raw_os_error(),
            });
        }

        // At this point, publication succeeded and bytes are committed to disk!
        // Sync the parent directory to make the entry durable.
        let sync_rc = unsafe { libc::fcntl(self.prepared.workspace_file.as_raw_fd(), F_FULLFSYNC) };
        if sync_rc != 0 {
            return Err(CreateFileError {
                code: "directory_sync_failed",
                committed: true,
                staged_bytes: self.staged_bytes,
                committed_bytes: self.staged_bytes,
                errno: io::Error::last_os_error().raw_os_error(),
            });
        }

        Ok(CreateFileCommit {
            committed: true,
            bytes_written: self.staged_bytes,
            file_synced: true,
            directory_synced: true,
        })
    }
}

fn find_or_create_stage_dir(expected_dev: u64, workspace: &str) -> Result<String, &'static str> {
    let tmp = std::env::var_os("AGENTFW_STAGING_DIR")
        .or_else(|| std::env::var_os("TMPDIR"))
        .unwrap_or_else(|| "/private/tmp".into());
    let tmp_path = match tmp.to_str() {
        Some(t) => t.trim_end_matches('/'),
        None => return Err("stage_dir_tmp_invalid"),
    };

    let stage_subdir = format!("{}/.agentfw_stage_{}", tmp_path, unsafe { libc::getuid() });
    if is_within(&stage_subdir, workspace) || is_within(workspace, &stage_subdir) {
        return Err("stage_dir_inside_or_overlapping_workspace");
    }
    let c_path = match CString::new(stage_subdir.as_bytes()) {
        Ok(c) => c,
        Err(_) => return Err("stage_dir_name_invalid"),
    };

    // Ensure mode 0700 private directory exists
    unsafe {
        libc::mkdir(c_path.as_ptr(), 0o700);
    }

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::stat(c_path.as_ptr(), &mut st) };
    if rc != 0 {
        return Err("stage_dir_stat_failed");
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err("stage_dir_not_directory");
    }
    if st.st_uid != unsafe { libc::getuid() } {
        return Err("stage_dir_owner_mismatch");
    }
    if (st.st_mode & 0o777) != 0o700 {
        return Err("stage_dir_permissions_invalid");
    }
    if st.st_dev as u64 != expected_dev {
        return Err("stage_dir_volume_mismatch");
    }

    let dir_fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if dir_fd < 0 {
        return Err("stage_dir_open_failed");
    }
    let acl_res = check_no_extended_acl(dir_fd);
    unsafe {
        libc::close(dir_fd);
    }
    if acl_res.is_err() {
        return Err("stage_dir_has_unsupported_acl");
    }

    Ok(stage_subdir)
}

fn check_local_apfs(file: &File) -> anyhow::Result<()> {
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatfs(file.as_raw_fd(), &mut sfs) };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("failed to fstatfs");
    }
    let fstype = unsafe { CStr::from_ptr(sfs.f_fstypename.as_ptr()) }.to_string_lossy();
    ensure!(
        fstype == "apfs",
        "filesystem unsupported: must be local APFS (found {fstype})"
    );
    ensure!(
        (sfs.f_flags & MNT_LOCAL) != 0,
        "filesystem must be mounted locally"
    );
    Ok(())
}

fn get_fd_path(file: &File) -> anyhow::Result<String> {
    let mut path_buf = [0 as libc::c_char; libc::PATH_MAX as usize];
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), F_GETPATH, path_buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("fcntl F_GETPATH failed");
    }
    let path_str = unsafe { CStr::from_ptr(path_buf.as_ptr()) }
        .to_str()
        .context("F_GETPATH path is not UTF-8")?;
    Ok(path_str.to_owned())
}

fn trusted_absolute(path: &Path) -> anyhow::Result<String> {
    let text = path.to_str().context("path is not Unicode")?;
    validate_absolute(text)?;
    Ok(text.to_owned())
}

fn original_target(cwd: &str, original: &str) -> anyhow::Result<String> {
    ensure!(!original.is_empty(), "path is empty");
    if original.starts_with('/') {
        validate_absolute(original)?;
        return Ok(original.to_owned());
    }
    validate_components(original)?;
    Ok(format!("{cwd}/{original}"))
}

fn validate_absolute(text: &str) -> anyhow::Result<()> {
    ensure!(
        text.starts_with('/') && !text.ends_with('/') && !text.contains('\0'),
        "requires an exact absolute path without trailing slash"
    );
    validate_components(&text[1..])
}

fn validate_components(text: &str) -> anyhow::Result<()> {
    ensure!(!text.is_empty(), "path component string is empty");
    for name in text.split('/') {
        ensure!(
            !name.is_empty() && name != "." && name != ".." && !name.contains('\0'),
            "path contains invalid component (empty, '.', '..', or NUL)"
        );
    }
    Ok(())
}

fn is_within(target: &str, workspace: &str) -> bool {
    target == workspace
        || (target.starts_with(workspace) && target[workspace.len()..].starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::Builder::new().tempdir().unwrap();
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        (dir, canonical)
    }

    #[test]
    fn creates_file_with_exact_bytes_and_mode() {
        let (_dir, ws) = test_dir();
        let ws = ws.as_path();
        let leaf = "test_create.txt";
        let target = ws.join(leaf);
        let content = "HELLO_MACOS_ARM64_APFS_CREATE";

        let prepared = PreparedCreate::prepare(ws, ws, leaf, target.to_str().unwrap(), content)
            .expect("prepare succeeds");

        assert_eq!(prepared.identity().root_dev, ws.metadata().unwrap().dev());
        let staged = prepared.stage().expect("staging succeeds");
        let commit = staged.publish().expect("publication succeeds");

        assert!(commit.committed);
        assert_eq!(commit.bytes_written, content.len());
        assert!(commit.file_synced);

        // Verify target file on disk
        let read_back = std::fs::read_to_string(&target).unwrap();
        assert_eq!(read_back, content);

        let meta = std::fs::metadata(&target).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.nlink(), 1);
    }

    #[test]
    fn refuses_oversized_payload() {
        let (_dir, ws) = test_dir();
        let ws = ws.as_path();
        let leaf = "oversize.txt";
        let target = ws.join(leaf);
        let big_content = "A".repeat(MAX_CREATE_BYTES + 1);

        let err = PreparedCreate::prepare(ws, ws, leaf, target.to_str().unwrap(), &big_content)
            .unwrap_err();

        assert_eq!(err.code, "content_too_large");
        assert!(!commit_marker(&err));
    }

    #[test]
    fn refuses_nested_or_path_traversal() {
        let (_dir, ws) = test_dir();
        let ws = ws.as_path();
        let content = "safe_payload";

        let err = PreparedCreate::prepare(
            ws,
            ws,
            "nested/file.txt",
            ws.join("nested/file.txt").to_str().unwrap(),
            content,
        )
        .unwrap_err();
        assert_eq!(err.code, "unsupported_nested_or_ambiguous_path");

        let err2 = PreparedCreate::prepare(
            ws,
            ws,
            "../outside.txt",
            ws.parent().unwrap().join("outside.txt").to_str().unwrap(),
            content,
        )
        .unwrap_err();
        assert_eq!(err2.code, "invalid_path");
    }

    #[test]
    fn refuses_preexisting_file() {
        let (_dir, ws) = test_dir();
        let ws = ws.as_path();
        let leaf = "existing.txt";
        let target = ws.join(leaf);
        std::fs::write(&target, "EXISTING_CONTENT").unwrap();

        let err = PreparedCreate::prepare(ws, ws, leaf, target.to_str().unwrap(), "NEW_CONTENT")
            .unwrap_err();

        assert_eq!(err.code, "destination_already_exists");
    }

    #[test]
    fn atomic_collision_refusal_on_concurrent_destination() {
        let (_dir, ws) = test_dir();
        let ws = ws.as_path();
        let leaf = "race.txt";
        let target = ws.join(leaf);

        let prepared =
            PreparedCreate::prepare(ws, ws, leaf, target.to_str().unwrap(), "STAGED_PAYLOAD")
                .unwrap();

        let staged = prepared.stage().unwrap();

        // Simulate concurrent creation of destination before publication
        std::fs::write(&target, "RACER_CONTENT").unwrap();

        let err = staged.publish().unwrap_err();
        assert_eq!(err.code, "destination_already_exists");
        assert_eq!(err.errno, Some(libc::EEXIST));

        // Racer content must NOT be overwritten!
        let read_back = std::fs::read_to_string(&target).unwrap();
        assert_eq!(read_back, "RACER_CONTENT");
    }

    fn test_stage_dir() -> (tempfile::TempDir, String) {
        use std::os::unix::fs::PermissionsExt;
        let base_tmp = std::env::var_os("AGENTFW_STAGING_DIR")
            .or_else(|| std::env::var_os("TMPDIR"))
            .unwrap_or_else(|| "/private/tmp".into());
        let dir = tempfile::Builder::new()
            .prefix(".agentfw_test_stage_")
            .tempdir_in(base_tmp)
            .expect("creating isolated test stage dir");
        let path_str = dir.path().to_str().unwrap().to_string();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, path_str)
    }

    #[test]
    fn cancellation_or_drop_leaves_no_disk_residue() {
        let (_dir, ws) = test_dir();
        let ws = ws.as_path();
        let leaf = "cancel.txt";
        let target = ws.join(leaf);

        let prepared =
            PreparedCreate::prepare(ws, ws, leaf, target.to_str().unwrap(), "CANCEL_ME").unwrap();

        let (_stage_holder, stage_dir) = test_stage_dir();
        let staged = prepared.stage_with_custom_dir(Some(&stage_dir)).unwrap();
        // Drop staged explicitly without publishing
        drop(staged);

        // Destination must not exist
        assert!(!target.exists());

        // Staging directory must contain NO temporary files
        if let Ok(entries) = std::fs::read_dir(&stage_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                assert!(
                    !name.starts_with(".stage."),
                    "Lingering stage file found: {name}"
                );
            }
        }
    }

    #[test]
    fn refuses_staging_directory_with_acls() {
        let (_dir, ws) = test_dir();
        let ws = ws.as_path();
        let leaf = "test_acl.txt";
        let target = ws.join(leaf);

        let prepared =
            PreparedCreate::prepare(ws, ws, leaf, target.to_str().unwrap(), "ACL_TEST").unwrap();

        // Use a test-owned staging directory to avoid mutating the shared staging namespace
        let (_stage_holder, stage_dir) = test_stage_dir();

        let add_status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read", &stage_dir])
            .status()
            .expect("executing /bin/chmod +a");
        assert!(
            add_status.success(),
            "installing fixture ACL on stage directory must succeed"
        );

        let err = prepared.stage_with_custom_dir(Some(&stage_dir)).unwrap_err();
        assert_eq!(err.code, "stage_dir_has_unsupported_acl");

        // Clear ACL before drop so tempdir deletion succeeds cleanly
        let _ = std::process::Command::new("/bin/chmod")
            .args(["-N", &stage_dir])
            .status();
    }

    #[test]
    fn acl_validation_controls_positive_negative_and_errors() {
        let (_dir, ws) = test_dir();
        let file_path = ws.join("acl_control.txt");
        let file = File::create(&file_path).unwrap();

        // 1. Positive: regular APFS file has no extended ACLs.
        assert_eq!(check_no_extended_acl(file.as_raw_fd()), Ok(()));

        // 2. Prior errno isolation: ensure prior syscall errno cannot decide the result.
        unsafe {
            *libc::__error() = libc::EACCES;
        }
        assert_eq!(check_no_extended_acl(file.as_raw_fd()), Ok(()));

        // 3. Extended ACL refusal: add an ACL entry to the file.
        let add_status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read", file_path.to_str().unwrap()])
            .status()
            .expect("executing /bin/chmod +a");
        assert!(
            add_status.success(),
            "installing fixture ACL on file must succeed"
        );

        assert_eq!(
            check_no_extended_acl(file.as_raw_fd()),
            Err("acl_entries_present")
        );

        // Clear ACL
        let clear_status = std::process::Command::new("/bin/chmod")
            .args(["-N", file_path.to_str().unwrap()])
            .status()
            .expect("executing /bin/chmod -N");
        assert!(
            clear_status.success(),
            "clearing fixture ACL on file must succeed"
        );
        assert_eq!(check_no_extended_acl(file.as_raw_fd()), Ok(()));

        // 4. Invalid fd refusal (negative fd).
        assert_eq!(check_no_extended_acl(-1), Err("acl_invalid_fd"));

        // 5. Closed / non-existent positive fd query failure (fails closed, not Ok).
        // On Darwin, acl_get_fd on an invalid positive descriptor returns NULL with EBADF != ENOENT.
        assert_eq!(check_no_extended_acl(9999), Err("acl_query_failed"));
    }

    fn commit_marker(err: &CreateFileError) -> bool {
        err.committed
    }
}
