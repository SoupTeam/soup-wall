// SPDX-License-Identifier: Apache-2.0
//! Read-only pinned inputs; no ambient home or path aliases.
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use std::{
    ffi::CString,
    fs::File,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Binding {
    path: PathBuf,
    parent: [u64; 5],
    object: [u64; 6],
    change: [i64; 4],
    bytes: usize,
    sha256: String,
}
pub(super) struct Input {
    pub bytes: Vec<u8>,
    pub binding: Binding,
    _file: File,
}
impl Input {
    pub fn read(path: &Path, cap: usize) -> Result<Self> {
        let raw = path.as_os_str().as_bytes();
        ensure!(
            raw.len() > 1
                && raw.len() <= 4096
                && raw[0] == b'/'
                && raw[1..]
                    .split(|b| *b == b'/')
                    .all(|p| !p.is_empty() && p != b"." && p != b".."),
            "candidate_canonical_absolute_input_required"
        );
        let parent = crate::private_export::open_dir(path.parent().context("candidate_parent")?)?;
        let parent_meta = parent.metadata()?;
        let name = CString::new(path.file_name().context("candidate_leaf")?.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        ensure!(fd >= 0, "candidate_input_unavailable");
        let mut file = unsafe { File::from_raw_fd(fd) };
        let before = file.metadata()?;
        ensure!(
            before.is_file()
                && before.nlink() == 1
                && before.uid() == unsafe { libc::geteuid() }
                && matches!(before.mode() & 0o7777, 0o400 | 0o600)
                && before.len() <= cap as u64,
            "candidate_owned_private_regular_input_required"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(cap as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= cap, "candidate_input_cap");
        let binding = |m: &std::fs::Metadata| Binding {
            path: path.to_owned(),
            parent: [
                parent_meta.dev(),
                parent_meta.ino(),
                u64::from(parent_meta.uid()),
                u64::from(parent_meta.gid()),
                u64::from(parent_meta.mode()),
            ],
            object: [
                m.dev(),
                m.ino(),
                u64::from(m.uid()),
                u64::from(m.gid()),
                u64::from(m.mode()),
                m.nlink(),
            ],
            change: [m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()],
            bytes: bytes.len(),
            sha256: super::sha(&bytes),
        };
        ensure!(
            binding(&before) == binding(&file.metadata()?) && before.len() == bytes.len() as u64,
            "candidate_source_changed"
        );
        Ok(Self {
            binding: binding(&before),
            bytes,
            _file: file,
        })
    }
    pub fn recheck(&self) -> Result<()> {
        ensure!(
            Self::read(&self.binding.path, self.bytes.len())?.binding == self.binding,
            "candidate_source_changed"
        );
        Ok(())
    }
}
