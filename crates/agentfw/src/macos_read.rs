// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Metadata-first, descriptor-relative macOS ARM64 document reads.
//!
//! This executor deliberately supports only ordinary, exactly named regular files on
//! local APFS volumes. Every directory from the workspace root and the leaf stay
//! open with nonblocking, boundary-constrained descriptors from preparation through the read.
//! Pins require directory traversal and regular file checks. The executor never
//! executes or maps the file. It does not read contents until `read_bounded` after Allow.
//!
//! Native API contracts: Darwin's `openat(2)`, `fstat(2)`, `fstatat(2)`, `fstatfs(2)`,
//! and `fcntl(2)` with `F_GETPATH`.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, ensure, Context};
use serde::{Deserialize, Serialize};

// Exact Darwin SDK values from sys/fcntl.h, sys/stdio.h, sys/mount.h:
const O_RESOLVE_BENEATH: i32 = 0x0000_1000;
const O_NOFOLLOW_ANY: i32 = 0x2000_0000;
const F_GETPATH: i32 = 50;
const MNT_LOCAL: u32 = 0x0000_1000;

pub const MAX_READ_BYTES: usize = crate::native::resource::MACOS_READ_MAX_CONTENT;

/// Values included in native admission's immutable resource binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReadIdentity {
    pub root_dev: u64,
    pub root_ino: u64,
    pub leaf_dev: u64,
    pub leaf_ino: u64,
    pub leaf_nlink: u64,
    pub leaf_size: u64,
    pub leaf_mtime_sec: i64,
    pub leaf_mtime_nsec: i64,
    pub leaf_ctime_sec: i64,
    pub leaf_ctime_nsec: i64,
}

#[derive(Debug)]
struct PinnedDirectory {
    file: File,
    component_name: String,
    expected_path: String,
    dev: u64,
    ino: u64,
}

/// A prepared read owns descriptor pins with O_NONBLOCK and boundary flags,
/// with ZERO file bytes read.
/// The caller must retain it across native admission and call `read_bounded`
/// only after the correlated native Allow. It consumes itself on read.
#[derive(Debug)]
pub(crate) struct PreparedRead {
    directories: Vec<PinnedDirectory>,
    leaf: File,
    leaf_name: String,
    canonical: String,
    identity: ReadIdentity,
}

struct CancelRead(Arc<AtomicBool>);

impl Drop for CancelRead {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl PreparedRead {
    pub(crate) fn prepare(
        workspace: &Path,
        cwd: &Path,
        original: &str,
        expected_canonical: &str,
    ) -> anyhow::Result<Self> {
        let workspace = trusted_absolute(workspace)?;
        let cwd = trusted_absolute(cwd)?;
        ensure!(
            is_within(&cwd, &workspace),
            "macOS read cwd outside workspace"
        );
        let requested = original_target(&cwd, original)?;
        ensure!(
            requested != workspace && is_within(&requested, &workspace),
            "macOS read target outside workspace"
        );
        let expected = trusted_absolute(Path::new(expected_canonical))?;
        ensure!(requested == expected, "macOS read path alias refused");

        // 1. Open and pin the workspace root directory.
        let root_c_path =
            CString::new(workspace.as_bytes()).context("workspace path contains NUL")?;
        let root_raw_fd = unsafe {
            libc::open(
                root_c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if root_raw_fd < 0 {
            return Err(io::Error::last_os_error())
                .context("failed to open workspace root directory descriptor");
        }
        let root_file = unsafe { File::from_raw_fd(root_raw_fd) };

        // Verify local APFS volume on the root directory.
        check_local_apfs(&root_file)?;

        let root_meta = root_file
            .metadata()
            .context("failed to stat workspace root descriptor")?;
        ensure!(
            root_meta.file_type().is_dir(),
            "workspace root is not a directory"
        );
        let root_dev = root_meta.dev();
        let root_ino = root_meta.ino();

        let root_canonical = get_fd_path(&root_file)?;
        ensure!(
            root_canonical == workspace,
            "macOS read root path drift on descriptor open"
        );

        let mut directories = vec![PinnedDirectory {
            file: root_file,
            component_name: String::new(),
            expected_path: workspace.clone(),
            dev: root_dev,
            ino: root_ino,
        }];

        // 2. Open intermediate directories component-by-component.
        let relative = &requested[workspace.len() + 1..];
        let mut components = relative.split('/').peekable();

        while let Some(name) = components.next() {
            let parent = directories.last().expect("workspace pinned");
            if components.peek().is_none() {
                // Leaf component: validate single file name.
                ensure!(
                    !name.is_empty() && name != "." && name != ".." && !name.contains('/'),
                    "macOS read invalid leaf component"
                );
                let c_name = CString::new(name.as_bytes()).context("leaf name contains NUL")?;

                // Open with O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW_ANY | O_RESOLVE_BENEATH.
                let leaf_raw_fd = unsafe {
                    libc::openat(
                        parent.file.as_raw_fd(),
                        c_name.as_ptr(),
                        libc::O_RDONLY
                            | libc::O_NONBLOCK
                            | libc::O_CLOEXEC
                            | O_NOFOLLOW_ANY
                            | O_RESOLVE_BENEATH,
                    )
                };
                if leaf_raw_fd < 0 {
                    let err = io::Error::last_os_error();
                    return Err(err).context("failed to open read target leaf descriptor");
                }
                let leaf_file = unsafe { File::from_raw_fd(leaf_raw_fd) };

                // Inspect leaf descriptor metadata immediately.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let rc = unsafe { libc::fstat(leaf_file.as_raw_fd(), &mut st) };
                if rc != 0 {
                    return Err(io::Error::last_os_error())
                        .context("failed to fstat leaf descriptor");
                }

                ensure!(
                    (st.st_mode & libc::S_IFMT) == libc::S_IFREG,
                    "macOS read target must be a regular file"
                );
                ensure!(st.st_nlink == 1, "macOS read hardlinks unsupported");
                ensure!(st.st_dev as u64 == root_dev, "macOS read volume changed");
                ensure!(
                    st.st_size as usize <= MAX_READ_BYTES,
                    "macOS read file exceeds size limit"
                );

                return Ok(Self {
                    directories,
                    leaf: leaf_file,
                    leaf_name: name.to_owned(),
                    canonical: requested,
                    identity: ReadIdentity {
                        root_dev,
                        root_ino,
                        leaf_dev: st.st_dev as u64,
                        leaf_ino: st.st_ino,
                        leaf_nlink: st.st_nlink as u64,
                        leaf_size: st.st_size as u64,
                        leaf_mtime_sec: st.st_mtime,
                        leaf_mtime_nsec: st.st_mtime_nsec,
                        leaf_ctime_sec: st.st_ctime,
                        leaf_ctime_nsec: st.st_ctime_nsec,
                    },
                });
            }

            // Intermediate directory component.
            ensure!(
                !name.is_empty() && name != "." && name != ".." && !name.contains('/'),
                "macOS read invalid directory component"
            );
            let c_name = CString::new(name.as_bytes()).context("dir name contains NUL")?;
            let dir_raw_fd = unsafe {
                libc::openat(
                    parent.file.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_DIRECTORY
                        | libc::O_CLOEXEC
                        | O_NOFOLLOW_ANY
                        | O_RESOLVE_BENEATH,
                )
            };
            if dir_raw_fd < 0 {
                return Err(io::Error::last_os_error())
                    .context("failed to open intermediate directory descriptor");
            }
            let dir_file = unsafe { File::from_raw_fd(dir_raw_fd) };
            let dir_meta = dir_file
                .metadata()
                .context("failed to stat intermediate directory descriptor")?;
            ensure!(
                dir_meta.file_type().is_dir(),
                "intermediate path component is not a directory"
            );
            ensure!(
                dir_meta.dev() == root_dev,
                "macOS read intermediate directory volume changed"
            );

            let expected_path = format!("{}/{}", parent.expected_path, name);
            directories.push(PinnedDirectory {
                file: dir_file,
                component_name: name.to_owned(),
                expected_path,
                dev: dir_meta.dev(),
                ino: dir_meta.ino(),
            });
        }

        bail!("macOS read target must be a file")
    }

    pub(crate) fn identity(&self) -> &ReadIdentity {
        &self.identity
    }

    pub(crate) async fn read_bounded(self, max_bytes: usize) -> anyhow::Result<String> {
        let canceled = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = CancelRead(Arc::clone(&canceled));
        tokio::task::spawn_blocking(move || self.read_on_worker(max_bytes, &canceled))
            .await
            .context("macOS read worker failed")?
    }

    fn read_on_worker(mut self, max_bytes: usize, canceled: &AtomicBool) -> anyhow::Result<String> {
        ensure!(
            max_bytes > 0 && max_bytes <= MAX_READ_BYTES,
            "macOS read byte bound invalid"
        );

        // Pre-check: if requested max_bytes is strictly smaller than the prepared file size,
        // refuse immediately before performing I/O or reading bytes.
        ensure!(
            self.identity.leaf_size as usize <= max_bytes,
            "macOS read file size exceeds requested byte bound"
        );

        // 1. Re-validate root directory descriptor and its physical path.
        ensure!(!canceled.load(Ordering::Acquire), "macOS read canceled");
        let root = self.directories.first().expect("workspace pinned");
        let mut root_st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(root.file.as_raw_fd(), &mut root_st) };
        if rc != 0 {
            return Err(io::Error::last_os_error()).context("failed to fstat workspace root");
        }
        ensure!(
            root_st.st_dev as u64 == root.dev && root_st.st_ino == root.ino,
            "workspace root inode drift detected"
        );
        let root_current_path = get_fd_path(&root.file)?;
        ensure!(
            root_current_path == root.expected_path,
            "workspace root path moved or replaced"
        );

        // 2. Re-validate the intermediate parent -> child component chain on disk.
        for i in 0..self.directories.len() - 1 {
            ensure!(!canceled.load(Ordering::Acquire), "macOS read canceled");
            let parent_fd = self.directories[i].file.as_raw_fd();
            let child = &self.directories[i + 1];

            // Verify child file descriptor itself.
            let mut child_fd_st: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::fstat(child.file.as_raw_fd(), &mut child_fd_st) };
            if rc != 0 {
                return Err(io::Error::last_os_error())
                    .context("failed to fstat intermediate directory descriptor");
            }
            ensure!(
                (child_fd_st.st_mode & libc::S_IFMT) == libc::S_IFDIR,
                "pinned intermediate directory is no longer a directory"
            );
            ensure!(
                child_fd_st.st_dev as u64 == child.dev && child_fd_st.st_ino == child.ino,
                "pinned intermediate directory descriptor drift detected"
            );

            // Re-stat the child component on disk relative to its parent descriptor.
            let c_child_name = CString::new(child.component_name.as_bytes())
                .context("child component name contains NUL")?;
            let mut live_child_st: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::fstatat(
                    parent_fd,
                    c_child_name.as_ptr(),
                    &mut live_child_st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error()).context(
                    "macOS read directory hierarchy broken: intermediate component missing on disk",
                );
            }
            ensure!(
                live_child_st.st_dev as u64 == child.dev && live_child_st.st_ino == child.ino,
                "macOS read intermediate directory drift detected: component replaced on disk"
            );

            // Validate that child's physical path has not escaped or moved.
            let child_path = get_fd_path(&child.file)?;
            ensure!(
                child_path == child.expected_path,
                "macOS read intermediate directory path drift: directory moved or escaped"
            );
        }

        // 3. Path drift check on leaf name relative to immediate parent descriptor.
        let parent = self.directories.last().expect("parent directory pinned");
        let c_leaf_name =
            CString::new(self.leaf_name.as_bytes()).context("leaf name contains NUL")?;
        let mut live_st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                parent.file.as_raw_fd(),
                c_leaf_name.as_ptr(),
                &mut live_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error())
                .context("macOS read path drift: leaf file unlinked or inaccessible on disk");
        }
        ensure!(
            live_st.st_dev as u64 == self.identity.leaf_dev
                && live_st.st_ino == self.identity.leaf_ino
                && live_st.st_nlink == 1
                && live_st.st_size as u64 == self.identity.leaf_size
                && live_st.st_mtime == self.identity.leaf_mtime_sec
                && live_st.st_mtime_nsec == self.identity.leaf_mtime_nsec
                && live_st.st_ctime == self.identity.leaf_ctime_sec
                && live_st.st_ctime_nsec == self.identity.leaf_ctime_nsec,
            "macOS read path drift detected: target modified or replaced on disk"
        );

        // 4. Re-validate retained leaf descriptor before reading.
        ensure!(!canceled.load(Ordering::Acquire), "macOS read canceled");
        let mut leaf_st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(self.leaf.as_raw_fd(), &mut leaf_st) };
        if rc != 0 {
            return Err(io::Error::last_os_error()).context("failed to fstat retained leaf");
        }
        ensure!(
            leaf_st.st_dev as u64 == self.identity.leaf_dev
                && leaf_st.st_ino == self.identity.leaf_ino
                && leaf_st.st_nlink as u64 == self.identity.leaf_nlink
                && leaf_st.st_size as u64 == self.identity.leaf_size
                && leaf_st.st_mtime == self.identity.leaf_mtime_sec
                && leaf_st.st_mtime_nsec == self.identity.leaf_mtime_nsec
                && leaf_st.st_ctime == self.identity.leaf_ctime_sec
                && leaf_st.st_ctime_nsec == self.identity.leaf_ctime_nsec,
            "retained leaf descriptor attributes modified"
        );
        let leaf_path = get_fd_path(&self.leaf)?;
        ensure!(
            leaf_path == self.canonical,
            "retained leaf descriptor path drift"
        );

        // 5. Read bounded bytes from the verified descriptor.
        ensure!(!canceled.load(Ordering::Acquire), "macOS read canceled");
        let mut buffer = Vec::new();
        let read_count = (&mut self.leaf)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut buffer)
            .context("failed to read from leaf descriptor")?;

        ensure!(
            read_count <= max_bytes,
            "macOS read file exceeded content limit"
        );

        // 6. Post-read attribute re-check: verify file was not modified concurrently during the read.
        let mut post_leaf_st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(self.leaf.as_raw_fd(), &mut post_leaf_st) };
        if rc != 0 {
            return Err(io::Error::last_os_error())
                .context("failed to post-fstat leaf descriptor after read");
        }
        ensure!(
            post_leaf_st.st_dev as u64 == self.identity.leaf_dev
                && post_leaf_st.st_ino == self.identity.leaf_ino
                && post_leaf_st.st_nlink as u64 == self.identity.leaf_nlink
                && post_leaf_st.st_size as u64 == self.identity.leaf_size
                && post_leaf_st.st_mtime == self.identity.leaf_mtime_sec
                && post_leaf_st.st_mtime_nsec == self.identity.leaf_mtime_nsec
                && post_leaf_st.st_ctime == self.identity.leaf_ctime_sec
                && post_leaf_st.st_ctime_nsec == self.identity.leaf_ctime_nsec,
            "macOS read file attributes modified concurrently during read"
        );

        String::from_utf8(buffer).context("macOS read file content is not valid UTF-8")
    }
}

fn check_local_apfs(file: &File) -> anyhow::Result<()> {
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatfs(file.as_raw_fd(), &mut sfs) };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("failed to fstatfs workspace root");
    }
    let fstype = unsafe { CStr::from_ptr(sfs.f_fstypename.as_ptr()) }.to_string_lossy();
    ensure!(
        fstype == "apfs",
        "macOS read filesystem unsupported: must be local APFS (found {fstype})"
    );
    ensure!(
        (sfs.f_flags & MNT_LOCAL) != 0,
        "macOS read filesystem must be mounted locally"
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
    ensure!(!original.is_empty(), "macOS read path is empty");
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
        "macOS read requires an exact absolute path without trailing slash"
    );
    validate_components(&text[1..])
}

fn validate_components(text: &str) -> anyhow::Result<()> {
    ensure!(
        !text.is_empty(),
        "macOS read path component string is empty"
    );
    for name in text.split('/') {
        ensure!(
            !name.is_empty() && name != "." && name != ".." && !name.contains('\0'),
            "macOS read path contains invalid component (empty, '.', '..', or NUL)"
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
    use std::fs;
    use std::path::PathBuf;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::Builder::new()
            .prefix("macos_read_test_")
            .tempdir()
            .unwrap();
        let root = temp.path().canonicalize().unwrap().join("workspace");
        fs::create_dir(&root).unwrap();
        (temp, root)
    }

    #[tokio::test]
    async fn reads_exact_regular_utf8_and_binds_identity() {
        let (_tmp, root) = fixture();
        let docs = root.join("docs");
        fs::create_dir_all(&docs).unwrap();
        let file_path = docs.join("readme.txt");
        fs::write(&file_path, "hello\n世界").unwrap();

        let file_str = file_path.to_str().unwrap();

        let first = PreparedRead::prepare(&root, &root, "docs/readme.txt", file_str).unwrap();
        let second = PreparedRead::prepare(&root, &root, "docs/readme.txt", file_str).unwrap();
        assert_eq!(first.identity(), second.identity());
        assert_eq!(first.read_bounded(64).await.unwrap(), "hello\n世界");
    }

    #[tokio::test]
    async fn bounded_utf8_contract_refuses_binary_and_oversize() {
        let (_tmp, root) = fixture();
        let bin_path = root.join("binary.bin");
        let large_path = root.join("large.txt");
        fs::write(&bin_path, [0xff, 0xfe, 0xfd]).unwrap();
        fs::write(&large_path, b"12345").unwrap();

        let bin_str = bin_path.to_str().unwrap();
        let large_str = large_path.to_str().unwrap();

        // Binary content refused on read.
        let prep_bin = PreparedRead::prepare(&root, &root, "binary.bin", bin_str).unwrap();
        assert!(prep_bin.read_bounded(64).await.is_err());

        // Oversize content refused pre-read.
        let prep_large = PreparedRead::prepare(&root, &root, "large.txt", large_str).unwrap();
        let err = prep_large.read_bounded(4).await.unwrap_err();
        assert!(format!("{err:#}").contains("exceeds requested byte bound"));

        // Exact bound succeeds.
        let prep_ok = PreparedRead::prepare(&root, &root, "large.txt", large_str).unwrap();
        assert_eq!(prep_ok.read_bounded(5).await.unwrap(), "12345");
    }

    #[test]
    fn refuses_original_aliases_and_traversal() {
        let (_tmp, root) = fixture();
        let root_str = root.to_str().unwrap();

        for alias in [
            "",
            "../outside.txt",
            "docs/../../outside.txt",
            "docs/./readme.txt",
            "docs//readme.txt",
            "/private/tmp/outside.txt",
            "docs/readme.txt/",
        ] {
            assert!(
                PreparedRead::prepare(&root, &root, alias, &format!("{root_str}/dummy")).is_err(),
                "accepted invalid alias: {alias}"
            );
        }
    }

    #[test]
    fn refuses_fifo_without_blocking() {
        let (_tmp, root) = fixture();
        let fifo_path = root.join("test.pipe");
        let c_path = CString::new(fifo_path.to_str().unwrap().as_bytes()).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0);

        let fifo_str = fifo_path.to_str().unwrap();
        let res = PreparedRead::prepare(&root, &root, "test.pipe", fifo_str);
        assert!(res.is_err());
        let err_msg = format!("{:#}", res.err().unwrap());
        assert!(
            err_msg.contains("regular file"),
            "unexpected error message: {err_msg}"
        );
    }

    #[test]
    fn refuses_hardlink_aliases() {
        let (_tmp, root) = fixture();
        let orig = root.join("orig.txt");
        let link = root.join("link.txt");
        fs::write(&orig, "link test").unwrap();
        fs::hard_link(&orig, &link).unwrap();

        let orig_str = orig.to_str().unwrap();
        let res = PreparedRead::prepare(&root, &root, "orig.txt", orig_str);
        assert!(res.is_err());
        let err_msg = format!("{:#}", res.err().unwrap());
        assert!(
            err_msg.contains("hardlinks unsupported"),
            "unexpected error message: {err_msg}"
        );
    }

    #[tokio::test]
    async fn detects_leaf_substitution_drift() {
        let (_tmp, root) = fixture();
        let file_path = root.join("target.txt");
        fs::write(&file_path, "original content").unwrap();

        let file_str = file_path.to_str().unwrap();
        let prep = PreparedRead::prepare(&root, &root, "target.txt", file_str).unwrap();

        // Adversary unlinks original and replaces it with another file at the same name.
        fs::remove_file(&file_path).unwrap();
        fs::write(&file_path, "substituted content").unwrap();

        // Execution drift check must detect the inode change and fail closed.
        let read_res = prep.read_bounded(64).await;
        assert!(read_res.is_err());
        let err_msg = format!("{:#}", read_res.err().unwrap());
        assert!(
            err_msg.contains("path drift detected") || err_msg.contains("modified"),
            "unexpected error: {err_msg}"
        );
    }

    #[tokio::test]
    async fn detects_in_place_modification_drift() {
        let (_tmp, root) = fixture();
        let file_path = root.join("target_mod.txt");
        fs::write(&file_path, "original content").unwrap();

        let file_str = file_path.to_str().unwrap();
        let prep = PreparedRead::prepare(&root, &root, "target_mod.txt", file_str).unwrap();

        // Wait a tiny moment, then modify file in place (changes mtime / size).
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&file_path, "modified longer content").unwrap();

        // Execution drift check must detect the modification and fail closed.
        let read_res = prep.read_bounded(64).await;
        assert!(read_res.is_err());
        let err_msg = format!("{:#}", read_res.err().unwrap());
        assert!(
            err_msg.contains("path drift detected") || err_msg.contains("modified"),
            "unexpected error: {err_msg}"
        );
    }

    #[tokio::test]
    async fn detects_nested_parent_move_out_and_replacement() {
        let (_tmp, root) = fixture();
        let sub1 = root.join("sub1");
        let sub2 = sub1.join("sub2");
        fs::create_dir_all(&sub2).unwrap();
        let file_path = sub2.join("target.txt");
        fs::write(&file_path, "nested content").unwrap();

        let file_str = file_path.to_str().unwrap();
        let prep = PreparedRead::prepare(&root, &root, "sub1/sub2/target.txt", file_str).unwrap();

        // Move sub1 aside and recreate sub1 with a new sub2 and file.
        let moved = root.join("sub1_moved");
        fs::rename(&sub1, &moved).unwrap();
        fs::create_dir_all(&sub2).unwrap();
        fs::write(&file_path, "different nested content").unwrap();

        // The parent->component hierarchy check must detect the intermediate directory substitution.
        let read_res = prep.read_bounded(64).await;
        assert!(read_res.is_err());
        let err_msg = format!("{:#}", read_res.err().unwrap());
        assert!(
            err_msg.contains("intermediate directory drift")
                || err_msg.contains("directory hierarchy broken"),
            "unexpected error: {err_msg}"
        );
    }
}
