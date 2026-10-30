// SPDX-License-Identifier: Apache-2.0
//! Private control records stay relative to pinned directory descriptors.
use anyhow::{ensure, Context, Result};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
    time::{Duration, Instant},
};

pub(super) const CAP: u64 = 16384;
pub(super) struct Dir(File);

impl Dir {
    pub fn open(path: &Path) -> Result<Self> {
        ensure!(
            path.is_absolute() && path.as_os_str().len() <= 4096,
            "edit_control_path"
        );
        let mut dir = File::open("/")?;
        let mut rebuilt = std::path::PathBuf::from("/");
        for part in path.components() {
            match part {
                Component::RootDir => (),
                Component::Normal(name) => {
                    let m = dir.metadata()?;
                    ensure!(
                        m.is_dir()
                            && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
                            && (m.mode() & 0o022 == 0 || m.mode() & libc::S_ISVTX != 0),
                        "edit_control_ancestry"
                    );
                    let name_c = CString::new(name.as_bytes())?;
                    let fd = unsafe {
                        libc::openat(
                            dir.as_raw_fd(),
                            name_c.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    ensure!(fd >= 0, "edit_control_directory");
                    dir = unsafe { File::from_raw_fd(fd) };
                    rebuilt.push(name);
                }
                _ => anyhow::bail!("edit_control_alias"),
            }
        }
        ensure!(
            rebuilt.as_os_str() == path.as_os_str(),
            "edit_control_alias"
        );
        Self::private(dir)
    }
    fn private(file: File) -> Result<Self> {
        let m = file.metadata()?;
        ensure!(
            m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "edit_control_private_directory"
        );
        Ok(Self(file))
    }
    pub fn child(&self, name: &str) -> Result<Self> {
        let name = CString::new(name)?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        ensure!(fd >= 0, "edit_control_home");
        Self::private(unsafe { File::from_raw_fd(fd) })
    }
    pub fn identity(&self) -> Result<(u64, u64)> {
        let m = self.0.metadata()?;
        Ok((m.dev(), m.ino()))
    }
    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        let name = CString::new(name)?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let m = file.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0
                && m.nlink() == 1
                && m.len() <= CAP,
            "edit_control_file"
        );
        let mut bytes = Vec::new();
        (&file).take(CAP + 1).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        ensure!(
            bytes.len() as u64 == m.len()
                && m.len() == after.len()
                && m.ctime() == after.ctime()
                && m.ctime_nsec() == after.ctime_nsec()
                && m.mtime() == after.mtime()
                && m.mtime_nsec() == after.mtime_nsec(),
            "edit_control_changed"
        );
        Ok(bytes)
    }
    pub fn optional(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match self.read(name) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
    pub fn write_new(&self, name: &str, bytes: &[u8]) -> Result<()> {
        ensure!(bytes.len() as u64 <= CAP, "edit_control_cap");
        let name = CString::new(name)?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        ensure!(fd >= 0, "edit_control_publish");
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        file.sync_all()?;
        self.0.sync_all()?;
        Ok(())
    }
    pub fn lock(&self) -> Result<Lock<'_>> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Lock(self));
            }
            ensure!(
                std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock
                    && Instant::now() < deadline,
                "edit_control_busy"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    pub fn replace(&self, name: &str, bytes: &[u8]) -> Result<()> {
        // Caller holds the short metadata lock, never across HTTP/process waits.
        let temporary = format!(".stop-{}", crate::token::generate());
        self.write_new(&temporary, bytes)?;
        let temporary = CString::new(temporary)?;
        let name = CString::new(name)?;
        ensure!(
            unsafe {
                libc::renameat(
                    self.0.as_raw_fd(),
                    temporary.as_ptr(),
                    self.0.as_raw_fd(),
                    name.as_ptr(),
                )
            } == 0,
            "edit_control_rename"
        );
        self.0.sync_all().context("edit_control_sync")
    }
}
pub(super) struct Lock<'a>(&'a Dir);
impl Drop for Lock<'_> {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0 .0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn descriptor_records_refuse_links_fifo_foreign_modes_and_oversize() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = Dir::open(tmp.path()).unwrap();
        dir.write_new("good", b"bounded").unwrap();
        assert_eq!(dir.read("good").unwrap(), b"bounded");
        std::fs::hard_link(tmp.path().join("good"), tmp.path().join("hard")).unwrap();
        assert!(dir.read("good").is_err());
        symlink("hard", tmp.path().join("link")).unwrap();
        assert!(dir.read("link").is_err());
        let fifo = CString::new(tmp.path().join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(dir.read("fifo").is_err());
        dir.write_new("public", b"x").unwrap();
        std::fs::set_permissions(
            tmp.path().join("public"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(dir.read("public").is_err());
        dir.write_new("large", b"").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(tmp.path().join("large"))
            .unwrap()
            .set_len(CAP + 1)
            .unwrap();
        assert!(dir.read("large").is_err());
        assert!(dir.optional("absent").unwrap().is_none());
        assert!(dir.optional("fifo").is_err());
    }
    #[test]
    fn replaced_directory_does_not_redirect_held_records() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("selected");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let selected = Dir::open(&path).unwrap();
        std::fs::rename(&path, tmp.path().join("retained")).unwrap();
        symlink(tmp.path().join("retained"), &path).unwrap();
        assert!(Dir::open(&path).is_err());
        selected.write_new("proof", b"owned").unwrap();
        assert_eq!(
            std::fs::read(tmp.path().join("retained/proof")).unwrap(),
            b"owned"
        );
    }
}
