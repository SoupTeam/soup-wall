// SPDX-License-Identifier: Apache-2.0
//! Descriptor-relative, bounded snapshots and single-file atomic publication.
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use std::{
    ffi::{CString, OsStr},
    fs::{File, Metadata},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

fn name(value: &OsStr) -> Result<CString> {
    Ok(CString::new(value.as_bytes())?)
}
fn open(parent: &File, leaf: &OsStr, flags: i32, mode: u32) -> Result<Option<File>> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name(leaf)?.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        anyhow::bail!("managed_connection_path_unavailable");
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(super) struct Object {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
impl Object {
    fn of(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
        }
    }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(super) struct Identity {
    object: Object,
    parent: Object,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    sha256: String,
}
fn identity(meta: &Metadata, parent: &Metadata, bytes: &[u8]) -> Identity {
    Identity {
        object: Object::of(meta),
        parent: Object::of(parent),
        size: meta.len(),
        modified: (meta.mtime(), meta.mtime_nsec()),
        changed: (meta.ctime(), meta.ctime_nsec()),
        sha256: super::hash(bytes),
    }
}
fn stable(a: &Metadata, b: &Metadata) -> bool {
    Object::of(a) == Object::of(b)
        && a.nlink() == 1
        && b.nlink() == 1
        && a.len() == b.len()
        && (a.mtime(), a.mtime_nsec(), a.ctime(), a.ctime_nsec())
            == (b.mtime(), b.mtime_nsec(), b.ctime(), b.ctime_nsec())
}

pub(super) fn directory(path: &Path) -> Result<File> {
    let raw = path.as_os_str().as_bytes();
    ensure!(
        raw.len() > 1
            && raw.len() <= 4096
            && raw[0] == b'/'
            && raw[1..]
                .split(|b| *b == b'/')
                .all(|p| !p.is_empty() && p != b"." && p != b".."),
        "managed_connection_canonical_path_required"
    );
    let mut dir = File::open("/")?;
    let mut depth = 0;
    for part in path.components() {
        if let Component::Normal(leaf) = part {
            depth += 1;
            ensure!(depth <= 128, "managed_connection_path_depth");
            dir = open(&dir, leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
                .context("managed_connection_parent_missing")?;
            let m = dir.metadata()?;
            ensure!(
                (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
                    && (m.mode() & 0o022 == 0 || (m.uid() == 0 && m.mode() & 0o1000 != 0)),
                "managed_connection_unsafe_ancestry"
            );
        }
    }
    Ok(dir)
}

pub(super) struct Root {
    path: PathBuf,
    dir: File,
    pub(super) identity: Object,
}
impl Root {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let dir = directory(path)?;
        let meta = dir.metadata()?;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "managed_connection_home_must_be_owner_private"
        );
        Ok(Self {
            path: path.into(),
            dir,
            identity: Object::of(&meta),
        })
    }
    pub(super) fn recheck(&self) -> Result<()> {
        ensure!(
            Object::of(&directory(&self.path)?.metadata()?) == self.identity,
            "managed_connection_home_changed"
        );
        Ok(())
    }
    pub(super) fn snapshot(&self, leaf: &str, cap: usize) -> Result<Snapshot> {
        snapshot_at(
            &self.dir,
            OsStr::new(leaf),
            cap,
            leaf == "managed-console.json" || leaf == "token",
        )
    }
    pub(super) fn publish(
        &self,
        bytes: &[u8],
        validate: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let leaf = format!(".managed-console-stage-{}", crate::token::generate());
        let mut file = open(
            &self.dir,
            OsStr::new(&leaf),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?
        .context("managed_connection_stage_failed")?;
        // A killed writer may leave this bounded private staging file. It is never selected.
        // No broad cleanup: unknown/user files are never removed.
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            let staged_metadata = file.metadata()?;
            #[cfg(test)]
            super::tests::at_publication_boundary();
            validate()?;
            self.recheck()?;
            let selected = open(&self.dir, OsStr::new(&leaf), libc::O_RDONLY, 0)?
                .context("managed_connection_stage_disappeared")?;
            ensure!(
                stable(&staged_metadata, &selected.metadata()?),
                "managed_connection_stage_changed"
            );
            let staged = snapshot_at(&self.dir, OsStr::new(&leaf), bytes.len(), true)?;
            ensure!(
                super::equal(&super::hash(&staged.bytes), &super::hash(bytes)),
                "managed_connection_stage_bytes_changed"
            );
            ensure!(
                unsafe {
                    libc::renameat(
                        self.dir.as_raw_fd(),
                        name(OsStr::new(&leaf))?.as_ptr(),
                        self.dir.as_raw_fd(),
                        c"managed-console.json".as_ptr(),
                    )
                } == 0,
                "managed_connection_publish_failed"
            );
            self.dir
                .sync_all()
                .context("managed_connection_commit_durability_unknown_inspect_before_retry")?;
            Ok(())
        })();
        if result.is_err() {
            // The stage name is unguessable and bound to the opened parent. Unlink
            // only our own object; never remove a substituted path.
            if let Ok(Some(now)) = open(&self.dir, OsStr::new(&leaf), libc::O_RDONLY, 0) {
                if now
                    .metadata()
                    .ok()
                    .zip(file.metadata().ok())
                    .is_some_and(|(a, b)| Object::of(&a) == Object::of(&b))
                {
                    unsafe {
                        libc::unlinkat(self.dir.as_raw_fd(), name(OsStr::new(&leaf))?.as_ptr(), 0)
                    };
                }
            }
        }
        result
    }
}

#[derive(Clone, Serialize)]
pub(super) struct Snapshot {
    pub(super) identity: Option<Identity>,
    #[serde(skip)]
    pub(super) bytes: Vec<u8>,
}
impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        match (&self.identity, &other.identity) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.object == b.object
                    && a.parent == b.parent
                    && a.size == b.size
                    && a.modified == b.modified
                    && a.changed == b.changed
                    && super::equal(&a.sha256, &b.sha256)
            }
            _ => false,
        }
    }
}
impl Eq for Snapshot {}
impl Snapshot {
    pub(super) fn absent() -> Self {
        Self {
            identity: None,
            bytes: vec![],
        }
    }
}
fn snapshot_at(parent: &File, leaf: &OsStr, cap: usize, private: bool) -> Result<Snapshot> {
    let Some(mut file) = open(parent, leaf, libc::O_RDONLY, 0)? else {
        return Ok(Snapshot {
            identity: None,
            bytes: vec![],
        });
    };
    let a = file.metadata()?;
    ensure!(
        a.is_file()
            && a.uid() == unsafe { libc::geteuid() }
            && a.mode() & if private { 0o077 } else { 0o022 } == 0
            && a.nlink() == 1
            && a.len() <= cap as u64,
        "managed_connection_input_must_be_bounded_owner_private_regular_file"
    );
    let mut bytes = Vec::new();
    (&mut file).take((cap + 1) as u64).read_to_end(&mut bytes)?;
    let b = file.metadata()?;
    ensure!(
        bytes.len() <= cap && stable(&a, &b) && bytes.len() as u64 == b.len(),
        "managed_connection_input_changed"
    );
    let selected =
        open(parent, leaf, libc::O_RDONLY, 0)?.context("managed_connection_input_disappeared")?;
    ensure!(
        stable(&b, &selected.metadata()?),
        "managed_connection_input_replaced"
    );
    Ok(Snapshot {
        identity: Some(identity(&b, &parent.metadata()?, &bytes)),
        bytes,
    })
}
pub(super) fn selected(path: &Path, cap: usize) -> Result<Snapshot> {
    let parent = directory(path.parent().context("managed_connection_input_parent")?)?;
    let value = snapshot_at(
        &parent,
        path.file_name().context("managed_connection_input_leaf")?,
        cap,
        true,
    )?;
    ensure!(value.identity.is_some(), "managed_connection_input_missing");
    // Re-open the path's entire ancestry after reading to detect directory substitution.
    ensure!(
        Object::of(&parent.metadata()?)
            == Object::of(&directory(path.parent().unwrap())?.metadata()?),
        "managed_connection_parent_changed"
    );
    Ok(value)
}
