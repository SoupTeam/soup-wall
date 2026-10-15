// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Linux-only, inode-rooted creation of one new direct workspace child.
//!
//! Admission and exact destination/content authority belong to the native
//! broker. Preparation here is read-only; staging begins only after ordinary
//! Allow/release. The broker monitors cancellation while staging and invokes
//! publication separately. This executor never contacts the MCP child.
//!
//! The parent is exactly the pinned workspace inode. Nested targets are refused:
//! merely pinning a nested parent would allow another process to move it outside
//! the authorized root before publication. Root pathname substitutions observed
//! before staging or publication are refused. A concurrent rename of the root
//! *after* the final identity check cannot redirect this descriptor to a
//! replacement inode; authority remains the originally pinned root inode. This
//! is not a guarantee against a same-UID host operator relocating that inode.
//!
//! An unnamed O_TMPFILE is populated and synced, then `linkat` atomically
//! publishes the complete file without replacing any existing leaf. No named
//! staging entry is created or unlinked. A post-publication directory-sync
//! failure reports `committed = true`; suppressing its response cannot undo it.

use std::fmt;
use std::path::{Component, Path};

use crate::sandbox::PinnedWorkspace;

pub const MAX_CREATE_BYTES: usize = crate::native::resource::CREATE_FILE_MAX_CONTENT;
const MAX_PATH_BYTES: usize = 4096;
const MAX_LEAF_BYTES: usize = 255;

/// Privacy-safe effect accounting. No content or destination is formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFileError {
    pub code: &'static str,
    /// True only after a successful publication syscall; never inferred from a
    /// later result release or a directory sync outcome.
    pub committed: bool,
    /// Bytes accepted by the anonymous staging descriptor before this error.
    pub staged_bytes: usize,
    /// Bytes atomically published, even when a later durability check failed.
    pub committed_bytes: usize,
    pub errno: Option<i32>,
}

impl CreateFileError {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            committed: false,
            staged_bytes: 0,
            committed_bytes: 0,
            errno: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn io(code: &'static str) -> Self {
        let mut error = Self::new(code);
        error.errno = std::io::Error::last_os_error().raw_os_error();
        error
    }
}

impl fmt::Display for CreateFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "constrained create refused: code={} committed={} staged_bytes={} committed_bytes={}",
            self.code, self.committed, self.staged_bytes, self.committed_bytes
        )
    }
}

impl std::error::Error for CreateFileError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFileCommit {
    pub committed: bool,
    pub bytes_written: usize,
    pub file_synced: bool,
    pub directory_synced: bool,
}

/// A validated immutable target/content pair and its authorized root handle.
/// Does not contain an execution approval, and cannot be cloned or re-executed.
pub struct PreparedCreate {
    #[cfg(target_os = "linux")]
    state: linux::Prepared,
}

/// An anonymously staged complete file. Dropping this value closes only its
/// unnamed inode; publication is a separate explicit operation so a broker can
/// observe cancellation/unsupported overlap while staging runs off-thread.
#[must_use = "drop to cancel the anonymous stage, or publish after the execution gate"]
pub struct StagedCreate {
    #[cfg(target_os = "linux")]
    state: linux::Staged,
}

impl fmt::Debug for StagedCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagedCreate").finish_non_exhaustive()
    }
}

impl fmt::Debug for PreparedCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedCreate").finish_non_exhaustive()
    }
}

impl PreparedCreate {
    /// Validate all argument bounds, pin the already authorized parent, and
    /// verify a nonexistent leaf without performing a filesystem mutation.
    pub fn prepare(
        workspace: &PinnedWorkspace,
        target: &Path,
        content: &str,
    ) -> Result<Self, CreateFileError> {
        if content.len() > MAX_CREATE_BYTES {
            return Err(CreateFileError::new("content_too_large"));
        }
        let target_text = target
            .to_str()
            .filter(|text| !text.is_empty() && text.len() <= MAX_PATH_BYTES)
            .ok_or_else(|| CreateFileError::new("invalid_path"))?;
        if target_text.chars().any(char::is_control)
            || target_text.contains('\\')
            || target_text.ends_with('/')
        {
            return Err(CreateFileError::new("invalid_path"));
        }
        let relative = workspace
            .relative_path(target)
            .map_err(|_| CreateFileError::new("outside_workspace"))?;
        let mut parts = relative.components();
        let leaf = match (parts.next(), parts.next()) {
            (Some(Component::Normal(leaf)), None) => leaf,
            _ => return Err(CreateFileError::new("unsupported_nested_or_ambiguous_path")),
        };
        let leaf = leaf
            .to_str()
            .filter(|text| !text.is_empty() && text.len() <= MAX_LEAF_BYTES)
            .ok_or_else(|| CreateFileError::new("invalid_leaf"))?;
        // Path::components normalizes `./` and repeated slashes. This profile
        // accepts only the exact canonical leaf spelling, not parser aliases.
        if relative.to_str() != Some(leaf) {
            return Err(CreateFileError::new("ambiguous_path"));
        }
        if target.is_absolute() && workspace.canonical().join(leaf).to_str() != Some(target_text) {
            return Err(CreateFileError::new("ambiguous_absolute_path"));
        }
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                state: linux::Prepared::prepare(workspace, leaf, content)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = leaf;
            Err(CreateFileError::new("unsupported_platform"))
        }
    }

    /// Populate and sync only an anonymous file after native release. This may
    /// run on a blocking worker while the broker monitors its client pipe. A
    /// detached/cancelled worker cannot publish: only the returned staged value
    /// owns that separate capability, and dropping it leaves no named entry.
    pub fn stage(self) -> Result<StagedCreate, CreateFileError> {
        #[cfg(target_os = "linux")]
        {
            Ok(StagedCreate {
                state: self.state.stage(linux::Fault::None)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CreateFileError::new("unsupported_platform"))
        }
    }

    /// Stage and atomically publish after the caller's actual native release.
    /// Every pre-publication failure closes only this operation's anonymous
    /// inode; no destination or foreign staging entry is removed.
    pub fn execute(self) -> Result<CreateFileCommit, CreateFileError> {
        #[cfg(target_os = "linux")]
        {
            self.state.execute(linux::Fault::None)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CreateFileError::new("unsupported_platform"))
        }
    }
}

impl StagedCreate {
    /// Recheck the authorized root and atomically publish once. Cancellation or
    /// result withholding after the link syscall cannot undo committed bytes.
    pub fn publish(self) -> Result<CreateFileCommit, CreateFileError> {
        #[cfg(target_os = "linux")]
        {
            self.state.publish(linux::Fault::None)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CreateFileError::new("unsupported_platform"))
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    pub(super) struct Prepared {
        root: File,
        canonical: PathBuf,
        original: PathBuf,
        dev: u64,
        ino: u64,
        leaf: CString,
        content: Vec<u8>,
    }

    pub(super) struct Staged {
        prepared: Prepared,
        file: File,
        staged: usize,
    }

    #[derive(Clone, Copy)]
    pub(super) enum Fault {
        None,
        #[cfg(test)]
        PartialWrite(usize),
        #[cfg(test)]
        BeforePublish,
        #[cfg(test)]
        DirectorySync,
        #[cfg(test)]
        ProcSource,
    }

    impl Prepared {
        pub(super) fn prepare(
            workspace: &PinnedWorkspace,
            leaf: &str,
            content: &str,
        ) -> Result<Self, CreateFileError> {
            let state = Self {
                root: workspace
                    .duplicate_root_descriptor()
                    .map_err(|_| CreateFileError::new("root_descriptor_unavailable"))?,
                canonical: workspace.canonical().to_path_buf(),
                original: workspace.root_path().to_path_buf(),
                dev: workspace.dev(),
                ino: workspace.ino(),
                leaf: CString::new(leaf).map_err(|_| CreateFileError::new("invalid_leaf"))?,
                content: content.as_bytes().to_vec(),
            };
            state.verify_root()?;
            state.verify_filesystem()?;
            state.require_absent()?;
            Ok(state)
        }

        fn verify_root(&self) -> Result<(), CreateFileError> {
            let matches = |metadata: fs::Metadata| {
                metadata.is_dir() && metadata.dev() == self.dev && metadata.ino() == self.ino
            };
            if !self.root.metadata().is_ok_and(matches)
                || !fs::symlink_metadata(&self.canonical).is_ok_and(matches)
                || !fs::symlink_metadata(&self.original).is_ok_and(matches)
            {
                return Err(CreateFileError::new("workspace_root_substituted"));
            }
            Ok(())
        }

        fn verify_filesystem(&self) -> Result<(), CreateFileError> {
            let mut status: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatfs(self.root.as_raw_fd(), &mut status) } != 0 {
                return Err(CreateFileError::io("filesystem_stat_failed"));
            }
            // Only local Linux filesystems with the required link/O_TMPFILE
            // semantics. The actual O_TMPFILE and sync syscalls must succeed
            // too: there is no named-file or path-only fallback.
            let filesystem = status.f_type as u64;
            if !matches!(
                filesystem,
                0xef53 | 0x5846_5342 | 0x9123_683e | 0x0102_1994 | 0x794c_7630
            ) {
                return Err(CreateFileError::new("unsupported_filesystem"));
            }
            Ok(())
        }

        fn require_absent(&self) -> Result<(), CreateFileError> {
            let mut status: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    self.root.as_raw_fd(),
                    self.leaf.as_ptr(),
                    &mut status,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
            {
                return Err(CreateFileError::new("target_exists"));
            }
            let error = CreateFileError::io("target_stat_failed");
            if error.errno == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(error)
            }
        }

        pub(super) fn stage(self, _fault: Fault) -> Result<Staged, CreateFileError> {
            self.verify_root()?;
            self.require_absent()?;
            let fd = unsafe {
                libc::openat(
                    self.root.as_raw_fd(),
                    c".".as_ptr(),
                    libc::O_TMPFILE | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(CreateFileError::io("anonymous_stage_unavailable"));
            }
            let mut file = unsafe { File::from_raw_fd(fd) };
            // Restore precisely 0600 even under an unusual umask/default ACL.
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    let mut result = CreateFileError::new("stage_permissions_failed");
                    result.errno = error.raw_os_error();
                    result
                })?;
            let metadata = file
                .metadata()
                .map_err(|_| CreateFileError::new("stage_stat_failed"))?;
            if !metadata.is_file()
                || metadata.nlink() != 0
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.permissions().mode() & 0o7777 != 0o600
                || metadata.len() != 0
                || metadata.dev() != self.dev
            {
                return Err(CreateFileError::new("invalid_anonymous_stage"));
            }
            let mut staged = 0;
            while staged < self.content.len() {
                #[cfg(test)]
                if let Fault::PartialWrite(limit) = _fault {
                    if staged >= limit {
                        return Err(with_effects(
                            CreateFileError::new("stage_write_failed"),
                            staged,
                            false,
                        ));
                    }
                }
                let end = {
                    #[cfg(test)]
                    {
                        match _fault {
                            Fault::PartialWrite(limit) => self.content.len().min(limit),
                            _ => self.content.len(),
                        }
                    }
                    #[cfg(not(test))]
                    {
                        self.content.len()
                    }
                };
                match file.write(&self.content[staged..end]) {
                    Ok(0) => {
                        return Err(with_effects(
                            CreateFileError::new("stage_write_failed"),
                            staged,
                            false,
                        ));
                    }
                    Ok(count) => staged += count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        let mut result = CreateFileError::new("stage_write_failed");
                        result.errno = error.raw_os_error();
                        return Err(with_effects(result, staged, false));
                    }
                }
            }
            file.sync_all().map_err(|error| {
                let mut result = CreateFileError::new("stage_sync_failed");
                result.errno = error.raw_os_error();
                with_effects(result, staged, false)
            })?;
            Ok(Staged {
                prepared: self,
                file,
                staged,
            })
        }

        pub(super) fn execute(self, fault: Fault) -> Result<CreateFileCommit, CreateFileError> {
            self.stage(fault)?.publish(fault)
        }

        fn link_stage(&self, file: &File, _fault: Fault) -> Result<(), CreateFileError> {
            #[cfg(test)]
            let direct = !matches!(_fault, Fault::ProcSource);
            #[cfg(not(test))]
            let direct = true;
            if direct {
                if unsafe {
                    libc::linkat(
                        file.as_raw_fd(),
                        c"".as_ptr(),
                        self.root.as_raw_fd(),
                        self.leaf.as_ptr(),
                        libc::AT_EMPTY_PATH,
                    )
                } == 0
                {
                    return Ok(());
                }
                let error = CreateFileError::io("publish_failed");
                if error.errno == Some(libc::EEXIST) {
                    return Err(CreateFileError::new("target_exists"));
                }
                // AT_EMPTY_PATH requires CAP_DAC_READ_SEARCH on some kernels.
                // Only its documented proc-fd source fallback is permitted.
                if !matches!(error.errno, Some(libc::EPERM | libc::ENOENT | libc::EACCES)) {
                    return Err(error);
                }
            }
            let proc_fd = unsafe {
                libc::open(
                    c"/proc/self/fd".as_ptr(),
                    libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if proc_fd < 0 {
                return Err(CreateFileError::io("proc_fd_source_unavailable"));
            }
            let proc_dir = unsafe { File::from_raw_fd(proc_fd) };
            let mut proc_stat: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatfs(proc_dir.as_raw_fd(), &mut proc_stat) } != 0
                || proc_stat.f_type as u64 != 0x9fa0
            {
                return Err(CreateFileError::new("invalid_proc_fd_filesystem"));
            }
            let source = CString::new(file.as_raw_fd().to_string()).expect("numeric descriptor");
            let mut source_stat: libc::stat = unsafe { std::mem::zeroed() };
            let metadata = file
                .metadata()
                .map_err(|_| CreateFileError::new("stage_stat_failed"))?;
            if unsafe { libc::fstatat(proc_dir.as_raw_fd(), source.as_ptr(), &mut source_stat, 0) }
                != 0
                || source_stat.st_dev != metadata.dev()
                || source_stat.st_ino != metadata.ino()
                || source_stat.st_nlink != 0
                || source_stat.st_mode & libc::S_IFMT != libc::S_IFREG
            {
                return Err(CreateFileError::new("invalid_proc_fd_source"));
            }
            // The sole followed symlink is a validated kernel proc descriptor
            // for our still-owned unnamed inode; the destination is one leaf
            // relative to our authorized root FD, with no parent traversal.
            if unsafe {
                libc::linkat(
                    proc_dir.as_raw_fd(),
                    source.as_ptr(),
                    self.root.as_raw_fd(),
                    self.leaf.as_ptr(),
                    libc::AT_SYMLINK_FOLLOW,
                )
            } != 0
            {
                let error = CreateFileError::io("publish_failed");
                if error.errno == Some(libc::EEXIST) {
                    return Err(CreateFileError::new("target_exists"));
                }
                return Err(error);
            }
            Ok(())
        }
    }

    impl Staged {
        pub(super) fn publish(self, fault: Fault) -> Result<CreateFileCommit, CreateFileError> {
            let Self {
                prepared,
                file,
                staged,
            } = self;
            prepared
                .verify_root()
                .map_err(|error| with_effects(error, staged, false))?;
            #[cfg(test)]
            if matches!(fault, Fault::BeforePublish) {
                return Err(with_effects(
                    CreateFileError::new("publish_failed"),
                    staged,
                    false,
                ));
            }
            prepared
                .link_stage(&file, fault)
                .map_err(|error| with_effects(error, staged, false))?;
            let published = file.metadata().map_err(|_| {
                with_effects(CreateFileError::new("published_stat_failed"), staged, true)
            })?;
            if !published.is_file()
                || published.nlink() != 1
                || published.len() != staged as u64
                || published.permissions().mode() & 0o7777 != 0o600
            {
                return Err(with_effects(
                    CreateFileError::new("published_state_changed"),
                    staged,
                    true,
                ));
            }
            // Publication has happened. Never unlink the result on failure: a
            // concurrent host actor could have replaced that leaf by now.
            #[cfg(test)]
            if matches!(fault, Fault::DirectorySync) {
                return Err(with_effects(
                    CreateFileError::new("published_directory_sync_failed"),
                    staged,
                    true,
                ));
            }
            prepared.root.sync_all().map_err(|error| {
                let mut result = CreateFileError::new("published_directory_sync_failed");
                result.errno = error.raw_os_error();
                with_effects(result, staged, true)
            })?;
            Ok(CreateFileCommit {
                committed: true,
                bytes_written: staged,
                file_synced: true,
                directory_synced: true,
            })
        }
    }

    fn with_effects(mut error: CreateFileError, staged: usize, committed: bool) -> CreateFileError {
        error.staged_bytes = staged;
        error.committed = committed;
        error.committed_bytes = if committed { staged } else { 0 };
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_content_and_exact_direct_leaf_before_any_effects() {
        let directory = tempfile::tempdir().unwrap();
        let workspace = PinnedWorkspace::open(directory.path()).unwrap();
        for path in [
            "",
            ".",
            "..",
            "../outside",
            "dir/file",
            "./file",
            "file/",
            "a\\b",
            "a\n",
        ] {
            assert!(
                PreparedCreate::prepare(&workspace, Path::new(path), "safe").is_err(),
                "{path:?}"
            );
        }
        assert!(PreparedCreate::prepare(
            &workspace,
            Path::new("file"),
            &"x".repeat(MAX_CREATE_BYTES + 1)
        )
        .is_err());
        assert!(directory.path().read_dir().unwrap().next().is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_refuses_without_creating_any_entry() {
        let directory = tempfile::tempdir().unwrap();
        let workspace = PinnedWorkspace::open(directory.path()).unwrap();
        let error = PreparedCreate::prepare(&workspace, Path::new("safe.txt"), "text").unwrap_err();
        assert_eq!(error.code, "unsupported_platform");
        assert!(!error.committed);
        assert!(directory.path().read_dir().unwrap().next().is_none());
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::sync::{Arc, Barrier};

        #[test]
        fn creates_exact_utf8_private_file_and_accepts_empty_content() {
            let directory = tempfile::tempdir().unwrap();
            let workspace = PinnedWorkspace::open(directory.path()).unwrap();
            let request =
                PreparedCreate::prepare(&workspace, Path::new("new.txt"), "Привет\n").unwrap();
            assert!(directory.path().read_dir().unwrap().next().is_none());
            let result = request.execute().unwrap();
            assert!(result.committed && result.file_synced && result.directory_synced);
            let target = directory.path().join("new.txt");
            assert_eq!(std::fs::read(&target).unwrap(), "Привет\n".as_bytes());
            let metadata = target.metadata().unwrap();
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(result.bytes_written, "Привет\n".len());
            PreparedCreate::prepare(&workspace, Path::new("empty.txt"), "")
                .unwrap()
                .execute()
                .unwrap();
            assert_eq!(
                std::fs::read(directory.path().join("empty.txt")).unwrap(),
                b""
            );
        }

        #[test]
        fn refuses_every_existing_leaf_type_without_opening_or_changing_it() {
            use std::os::unix::fs::symlink;
            let directory = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            std::fs::write(outside.path().join("original"), "unchanged").unwrap();
            std::fs::write(directory.path().join("regular"), "keep").unwrap();
            std::fs::hard_link(
                outside.path().join("original"),
                directory.path().join("hardlink"),
            )
            .unwrap();
            symlink(
                outside.path().join("original"),
                directory.path().join("symlink"),
            )
            .unwrap();
            std::fs::create_dir(directory.path().join("directory")).unwrap();
            let fifo =
                std::ffi::CString::new(directory.path().join("fifo").to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
            let _socket =
                std::os::unix::net::UnixListener::bind(directory.path().join("socket")).unwrap();
            let workspace = PinnedWorkspace::open(directory.path()).unwrap();
            for leaf in [
                "regular",
                "hardlink",
                "symlink",
                "directory",
                "fifo",
                "socket",
            ] {
                let error =
                    PreparedCreate::prepare(&workspace, Path::new(leaf), "overwrite").unwrap_err();
                assert_eq!(error.code, "target_exists");
                assert!(!error.committed);
            }
            assert_eq!(
                std::fs::read(outside.path().join("original")).unwrap(),
                b"unchanged"
            );
            assert_eq!(
                std::fs::read(directory.path().join("regular")).unwrap(),
                b"keep"
            );
        }

        #[test]
        fn substitution_after_prepare_refuses_both_original_and_replacement_roots() {
            let parent = tempfile::tempdir().unwrap();
            let root = parent.path().join("workspace");
            let moved = parent.path().join("moved");
            std::fs::create_dir(&root).unwrap();
            let workspace = PinnedWorkspace::open(&root).unwrap();
            let request =
                PreparedCreate::prepare(&workspace, Path::new("new.txt"), "secret").unwrap();
            std::fs::rename(&root, &moved).unwrap();
            std::fs::create_dir(&root).unwrap();
            let error = request.execute().unwrap_err();
            assert_eq!(error.code, "workspace_root_substituted");
            assert!(!error.committed);
            assert!(root.read_dir().unwrap().next().is_none());
            assert!(moved.read_dir().unwrap().next().is_none());
        }

        #[test]
        fn moved_nested_parent_is_refused_instead_of_becoming_an_outside_write_handle() {
            let root = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join("nested")).unwrap();
            let workspace = PinnedWorkspace::open(root.path()).unwrap();
            assert!(
                PreparedCreate::prepare(&workspace, Path::new("nested/new.txt"), "no").is_err()
            );
            std::fs::rename(root.path().join("nested"), outside.path().join("moved")).unwrap();
            assert!(
                PreparedCreate::prepare(&workspace, Path::new("nested/new.txt"), "no").is_err()
            );
            assert!(outside
                .path()
                .join("moved")
                .read_dir()
                .unwrap()
                .next()
                .is_none());
        }

        #[test]
        fn target_inserted_after_prepare_is_never_overwritten() {
            let root = tempfile::tempdir().unwrap();
            let workspace = PinnedWorkspace::open(root.path()).unwrap();
            let request =
                PreparedCreate::prepare(&workspace, Path::new("new.txt"), "ours").unwrap();
            std::fs::write(root.path().join("new.txt"), "theirs").unwrap();
            let error = request.execute().unwrap_err();
            assert_eq!(error.code, "target_exists");
            assert!(!error.committed);
            assert_eq!(
                std::fs::read(root.path().join("new.txt")).unwrap(),
                b"theirs"
            );
        }

        #[test]
        fn concurrent_same_leaf_publishes_exactly_one_complete_file() {
            let root = tempfile::tempdir().unwrap();
            let workspace = PinnedWorkspace::open(root.path()).unwrap();
            let barrier = Arc::new(Barrier::new(8));
            let mut threads = Vec::new();
            for index in 0..8 {
                let content = format!("complete payload {index}");
                let request =
                    PreparedCreate::prepare(&workspace, Path::new("new.txt"), &content).unwrap();
                let barrier = Arc::clone(&barrier);
                threads.push(std::thread::spawn(move || {
                    barrier.wait();
                    (content, request.execute())
                }));
            }
            let outcomes: Vec<_> = threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect();
            assert_eq!(
                outcomes.iter().filter(|(_, result)| result.is_ok()).count(),
                1
            );
            let successful = outcomes.iter().find(|(_, result)| result.is_ok()).unwrap();
            assert_eq!(
                std::fs::read(root.path().join("new.txt")).unwrap(),
                successful.0.as_bytes()
            );
            for (_, result) in outcomes {
                if let Err(error) = result {
                    assert_eq!(error.code, "target_exists");
                    assert!(!error.committed);
                }
            }
            assert_eq!(root.path().read_dir().unwrap().count(), 1);
        }

        #[test]
        fn anonymous_partial_write_and_prepublish_failures_leave_no_named_entry() {
            for fault in [linux::Fault::PartialWrite(3), linux::Fault::BeforePublish] {
                let root = tempfile::tempdir().unwrap();
                let workspace = PinnedWorkspace::open(root.path()).unwrap();
                let request =
                    PreparedCreate::prepare(&workspace, Path::new("new.txt"), "abcdef").unwrap();
                let error = request.state.execute(fault).unwrap_err();
                assert!(!error.committed);
                assert!(error.staged_bytes > 0);
                assert_eq!(error.committed_bytes, 0);
                assert!(root.path().read_dir().unwrap().next().is_none());
            }
        }

        #[test]
        fn dropping_a_complete_anonymous_stage_cancels_without_a_named_file() {
            let root = tempfile::tempdir().unwrap();
            let workspace = PinnedWorkspace::open(root.path()).unwrap();
            let staged = PreparedCreate::prepare(&workspace, Path::new("new.txt"), "not published")
                .unwrap()
                .stage()
                .unwrap();
            assert!(root.path().read_dir().unwrap().next().is_none());
            drop(staged);
            assert!(root.path().read_dir().unwrap().next().is_none());
            PreparedCreate::prepare(&workspace, Path::new("new.txt"), "useful continuation")
                .unwrap()
                .stage()
                .unwrap()
                .publish()
                .unwrap();
            assert_eq!(
                std::fs::read(root.path().join("new.txt")).unwrap(),
                b"useful continuation"
            );
        }

        #[test]
        fn root_replacement_after_staging_refuses_publication_and_cleans_anonymous_file() {
            let parent = tempfile::tempdir().unwrap();
            let root = parent.path().join("workspace");
            let moved = parent.path().join("moved");
            std::fs::create_dir(&root).unwrap();
            let workspace = PinnedWorkspace::open(&root).unwrap();
            let staged = PreparedCreate::prepare(&workspace, Path::new("new.txt"), "not published")
                .unwrap()
                .stage()
                .unwrap();
            std::fs::rename(&root, &moved).unwrap();
            std::fs::create_dir(&root).unwrap();
            let error = staged.publish().unwrap_err();
            assert_eq!(error.code, "workspace_root_substituted");
            assert!(!error.committed);
            assert_eq!(error.staged_bytes, "not published".len());
            assert_eq!(error.committed_bytes, 0);
            assert!(root.read_dir().unwrap().next().is_none());
            assert!(moved.read_dir().unwrap().next().is_none());
        }

        #[test]
        fn target_inserted_after_staging_is_refused_by_atomic_publication() {
            let root = tempfile::tempdir().unwrap();
            let workspace = PinnedWorkspace::open(root.path()).unwrap();
            let staged =
                PreparedCreate::prepare(&workspace, Path::new("new.txt"), "our complete bytes")
                    .unwrap()
                    .stage()
                    .unwrap();
            std::fs::write(root.path().join("new.txt"), "other creator").unwrap();
            let error = staged.publish().unwrap_err();
            assert_eq!(error.code, "target_exists");
            assert!(!error.committed);
            assert_eq!(error.staged_bytes, "our complete bytes".len());
            assert_eq!(
                std::fs::read(root.path().join("new.txt")).unwrap(),
                b"other creator"
            );
            assert_eq!(root.path().read_dir().unwrap().count(), 1);
        }

        #[test]
        fn directory_sync_failure_honestly_reports_already_committed_effect() {
            let root = tempfile::tempdir().unwrap();
            let workspace = PinnedWorkspace::open(root.path()).unwrap();
            let request =
                PreparedCreate::prepare(&workspace, Path::new("new.txt"), "actual effect").unwrap();
            let error = request
                .state
                .execute(linux::Fault::DirectorySync)
                .unwrap_err();
            assert!(error.committed);
            assert_eq!(error.committed_bytes, "actual effect".len());
            assert_eq!(
                std::fs::read(root.path().join("new.txt")).unwrap(),
                b"actual effect"
            );
        }

        #[test]
        fn documented_unprivileged_proc_source_preserves_atomic_no_replace() {
            let root = tempfile::tempdir().unwrap();
            let workspace = PinnedWorkspace::open(root.path()).unwrap();
            let request =
                PreparedCreate::prepare(&workspace, Path::new("new.txt"), "proc-fd source")
                    .unwrap();
            request.state.execute(linux::Fault::ProcSource).unwrap();
            assert_eq!(
                std::fs::read(root.path().join("new.txt")).unwrap(),
                b"proc-fd source"
            );
            assert_eq!(root.path().read_dir().unwrap().count(), 1);
        }
    }
}
