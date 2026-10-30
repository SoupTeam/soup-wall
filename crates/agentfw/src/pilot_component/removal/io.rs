// SPDX-License-Identifier: Apache-2.0
//! No-follow descriptor operations. Only enumerated exact objects may be removed.
use super::{decode, ensure, sha, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::{Component, Path},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub links: u64,
    pub size: u64,
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
}
impl Identity {
    pub fn stable_directory(mut self) -> Self {
        self.links = 0;
        self.size = 0;
        self.mtime = (0, 0);
        self.ctime = (0, 0);
        self
    }
    pub fn from(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            size: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
    pub fn directory(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFDIR
    }
    pub fn object(&self, b: &Self) -> bool {
        (self.device, self.inode, self.uid, self.gid, self.mode)
            == (b.device, b.inode, b.uid, b.gid, b.mode)
    }
}
pub(super) struct Budget {
    started: Instant,
    bytes: usize,
}
impl Budget {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            bytes: 0,
        }
    }
    pub fn tick(&mut self, n: usize) -> Result<()> {
        self.bytes = self.bytes.checked_add(n).context("removal_read_cap")?;
        ensure!(
            self.bytes <= 64 * 1024 * 1024 && self.started.elapsed() < Duration::from_secs(10),
            "removal_read_cap"
        );
        Ok(())
    }
}
pub(super) struct Dir {
    pub fd: OwnedFd,
    path: std::path::PathBuf,
    pub id: Identity,
}
fn cname(s: &str) -> Result<std::ffi::CString> {
    ensure!(
        !s.is_empty() && s != "." && s != ".." && !s.contains('/'),
        "removal_invalid_name"
    );
    Ok(std::ffi::CString::new(s)?)
}
impl Dir {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_mode(path, &[0o700])
    }
    pub fn open_readonly(path: &Path) -> Result<Self> {
        Self::open_mode(path, &[0o500, 0o700])
    }
    fn open_mode(path: &Path, modes: &[u32]) -> Result<Self> {
        let raw = path.as_os_str().as_encoded_bytes();
        ensure!(
            path.is_absolute()
                && raw.len() <= 4096
                && raw.len() > 1
                && !raw.ends_with(b"/")
                && !raw.windows(2).any(|p| p == b"//"),
            "removal_absolute_canonical_path_required"
        );
        let mut fd = super::super::open_path_nofollow(Path::new("/"))?;
        for part in path.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(n) => {
                    fd = super::super::open_dir_at(
                        &fd,
                        n.to_str().context("removal_invalid_name")?,
                    )?;
                    let m = File::from(fd.try_clone()?).metadata()?;
                    ensure!(
                        (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
                            && (m.mode() & 0o022 == 0
                                || (m.uid() == 0 && m.mode() & libc::S_ISVTX != 0)),
                        "removal_unsafe_ancestry"
                    );
                }
                _ => anyhow::bail!("removal_absolute_canonical_path_required"),
            }
        }
        let m = File::from(fd.try_clone()?).metadata()?;
        ensure!(
            m.uid() == unsafe { libc::geteuid() }
                && m.gid() == unsafe { libc::getegid() }
                && modes.contains(&(m.mode() & 0o7777)),
            "removal_private_directory_required"
        );
        Ok(Self {
            fd,
            path: path.into(),
            id: Identity::from(&m),
        })
    }
    pub fn recheck(&self) -> Result<()> {
        ensure!(
            Self::open_mode(&self.path, &[self.id.mode & 0o7777])?
                .id
                .object(&self.id),
            "removal_directory_changed"
        );
        Ok(())
    }
    pub fn names(&self) -> Result<Vec<String>> {
        self.recheck()?;
        let mut v = vec![];
        for e in fs::read_dir(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))? {
            ensure!(v.len() < 4096, "removal_entry_cap");
            let n = e?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("removal_invalid_name"))?;
            cname(&n)?;
            v.push(n);
        }
        v.sort();
        self.recheck()?;
        Ok(v)
    }
    pub fn optional(&self, name: &str) -> Result<Option<Identity>> {
        let n = cname(name)?;
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                n.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(e.into());
        }
        let f = unsafe { File::from_raw_fd(fd) };
        let m = f.metadata()?;
        Ok(Some(Identity::from(&m)))
    }
    pub fn read(&self, name: &str, cap: u64, b: &mut Budget) -> Result<(Vec<u8>, Identity)> {
        b.tick(0)?;
        self.recheck()?;
        let n = cname(name)?;
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                n.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        ensure!(fd >= 0, "removal_file_unavailable");
        let pinned = unsafe { File::from_raw_fd(fd) };
        let m = pinned.metadata()?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.gid() == unsafe { libc::getegid() }
                && matches!(m.mode() & 0o7777, 0o400 | 0o600)
                && m.len() <= cap,
            "removal_file_metadata"
        );
        let proc = File::open("/proc")?;
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::fstatfs(proc.as_raw_fd(), &mut st) } == 0 && st.f_type as u64 == 0x9fa0,
            "removal_proc_unavailable"
        );
        let mut f = File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
        ensure!(
            Identity::from(&f.metadata()?) == Identity::from(&m)
                && unsafe { libc::flistxattr(f.as_raw_fd(), std::ptr::null_mut(), 0) } == 0,
            "removal_file_changed"
        );
        let mut raw = vec![];
        (&mut f).take(cap + 1).read_to_end(&mut raw)?;
        b.tick(raw.len())?;
        let id = Identity::from(&m);
        ensure!(
            raw.len() as u64 == m.len()
                && Identity::from(&f.metadata()?) == id
                && self.optional(name)?.as_ref() == Some(&id),
            "removal_file_changed"
        );
        Ok((raw, id))
    }
    pub fn json<T: serde::de::DeserializeOwned>(
        &self,
        n: &str,
        cap: u64,
        b: &mut Budget,
    ) -> Result<T> {
        decode(&self.read(n, cap, b)?.0)
    }
    pub fn write_new(&self, name: &str, raw: &[u8]) -> Result<()> {
        ensure!(raw.len() <= 512 * 1024, "removal_record_cap");
        self.recheck()?;
        let n = cname(name)?;
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                n.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        ensure!(fd >= 0, "removal_record_publish_failed");
        let mut f = unsafe { File::from_raw_fd(fd) };
        f.write_all(raw)?;
        f.sync_all()?;
        self.sync()
    }
    pub fn sync(&self) -> Result<()> {
        ensure!(
            unsafe { libc::fsync(self.fd.as_raw_fd()) } == 0,
            "removal_directory_sync_failed"
        );
        Ok(())
    }
    pub fn lock(&self) -> Result<Lock<'_>> {
        self.recheck()?;
        ensure!(
            unsafe { libc::flock(self.fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "removal_busy"
        );
        Ok(Lock(self))
    }
    pub fn remove(
        &self,
        name: &str,
        expected: &Identity,
        hash: Option<&str>,
        b: &mut Budget,
    ) -> Result<()> {
        self.recheck()?;
        let now = self.optional(name)?.context("removal_object_missing")?;
        if expected.directory() {
            ensure!(now.object(expected), "removal_object_substituted");
            let child = Self::open(&self.path.join(name))?;
            ensure!(
                child.id.object(expected) && child.names()?.is_empty(),
                "removal_unexpected_entry"
            );
        } else {
            let (raw, id) = self.read(name, 1024 * 1024, b)?;
            ensure!(
                id == *expected && hash.is_some_and(|h| super::same(&sha(&raw), h)),
                "removal_object_substituted"
            );
        }
        let n = cname(name)?;
        ensure!(
            unsafe {
                libc::unlinkat(
                    self.fd.as_raw_fd(),
                    n.as_ptr(),
                    if expected.directory() {
                        libc::AT_REMOVEDIR
                    } else {
                        0
                    },
                )
            } == 0,
            "removal_unlink_failed"
        );
        self.sync()
    }
}
pub(super) struct Lock<'a>(&'a Dir);
impl Drop for Lock<'_> {
    fn drop(&mut self) {
        unsafe { libc::flock(self.0.fd.as_raw_fd(), libc::LOCK_UN) };
    }
}
