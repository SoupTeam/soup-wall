// SPDX-License-Identifier: Apache-2.0
//! Descriptor-pinned, owner-private exact file selection; never enumerate state.
use std::{
    ffi::{CStr, CString},
    fs::{File, Metadata},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Path,
    time::{Duration, Instant},
};

pub(in crate::edit_session) type Result<T> = std::result::Result<T, &'static str>;
pub(in crate::edit_session) struct Budget {
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
    pub fn tick(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or("diagnostic_read_budget")?;
        if self.bytes > 2 * 1024 * 1024 || self.started.elapsed() > Duration::from_secs(10) {
            return Err("diagnostic_read_budget");
        }
        Ok(())
    }
}

pub(in crate::edit_session) fn stable(a: &Metadata, b: &Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.len(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
        a.uid(),
        a.gid(),
        a.mode(),
        a.nlink(),
    ) == (
        b.dev(),
        b.ino(),
        b.len(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
        b.uid(),
        b.gid(),
        b.mode(),
        b.nlink(),
    )
}

pub(in crate::edit_session) struct Directory(File);
fn openat(parent: &File, name: &CStr, flags: i32) -> Result<Option<File>> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err("selected_state_unavailable_or_unsafe");
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}
fn protected(meta: &Metadata, private: bool) -> bool {
    let uid = unsafe { libc::geteuid() };
    meta.is_dir()
        && if private {
            meta.uid() == uid && meta.mode() & 0o077 == 0
        } else {
            (meta.uid() == 0 || meta.uid() == uid)
                && (meta.mode() & 0o022 == 0
                    || (meta.uid() == 0 && meta.mode() & libc::S_ISVTX != 0))
        }
}
impl Directory {
    pub fn observation_lock(&self) -> Result<()> {
        if unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("selected_output_writer_busy");
        }
        Ok(())
    }
    pub fn immutable(&self, name: &str, cap: u64, budget: &mut Budget) -> Result<Vec<u8>> {
        let (bytes, meta) = self
            .read_observed(name, cap, budget, false)?
            .ok_or("selected_state_missing")?;
        if meta.mode() & 0o7777 != 0o400 {
            return Err("selected_plan_not_immutable");
        }
        Ok(bytes)
    }
    pub fn open(path: &Path) -> Result<Self> {
        let raw = path.as_os_str().as_bytes();
        if !path.is_absolute() || raw.len() > 4096 || raw.len() < 2 {
            return Err("selected_run_path_invalid");
        }
        let names: Vec<_> = raw[1..].split(|b| *b == b'/').collect();
        if names.len() > 128
            || names
                .iter()
                .any(|n| n.is_empty() || *n == b"." || *n == b"..")
        {
            return Err("selected_run_path_invalid");
        }
        let mut current = File::open("/").map_err(|_| "selected_state_unavailable_or_unsafe")?;
        for (index, part) in names.iter().enumerate() {
            let name = CString::new(*part).map_err(|_| "selected_run_path_invalid")?;
            current = openat(&current, &name, libc::O_RDONLY | libc::O_DIRECTORY)?
                .ok_or("selected_state_missing")?;
            let meta = current
                .metadata()
                .map_err(|_| "selected_state_unavailable_or_unsafe")?;
            if !protected(&meta, index + 1 == names.len()) {
                return Err("selected_state_owner_or_ancestry_unsafe");
            }
        }
        Ok(Self(current))
    }
    pub fn child_dir(&self, name: &str) -> Result<Self> {
        let name = CString::new(name).map_err(|_| "selected_state_unavailable_or_unsafe")?;
        if name.as_bytes().contains(&b'/') {
            return Err("selected_state_unavailable_or_unsafe");
        }
        let file = openat(&self.0, &name, libc::O_RDONLY | libc::O_DIRECTORY)?
            .ok_or("selected_state_missing")?;
        if !protected(
            &file
                .metadata()
                .map_err(|_| "selected_state_unavailable_or_unsafe")?,
            true,
        ) {
            return Err("selected_state_owner_or_ancestry_unsafe");
        }
        Ok(Self(file))
    }
    pub fn metadata(&self) -> Result<Metadata> {
        self.0
            .metadata()
            .map_err(|_| "selected_state_unavailable_or_unsafe")
    }
    pub fn read(&self, name: &str, cap: u64, budget: &mut Budget) -> Result<Option<Vec<u8>>> {
        self.read_observed(name, cap, budget, false)
            .map(|value| value.map(|(bytes, _)| bytes))
    }
    pub fn read_output(
        &self,
        name: &str,
        cap: u64,
        budget: &mut Budget,
    ) -> Result<Option<(Vec<u8>, Metadata)>> {
        self.read_observed(name, cap, budget, true)
    }
    fn read_observed(
        &self,
        name: &str,
        cap: u64,
        budget: &mut Budget,
        output: bool,
    ) -> Result<Option<(Vec<u8>, Metadata)>> {
        budget.tick(0)?;
        let name = CString::new(name).map_err(|_| "selected_state_unavailable_or_unsafe")?;
        if name.as_bytes().contains(&b'/') || matches!(name.as_bytes(), b"." | b"..") {
            return Err("selected_state_unavailable_or_unsafe");
        }
        // O_PATH verifies type before opening anything capable of device I/O.
        let Some(pinned) = openat(&self.0, &name, libc::O_PATH)? else {
            return Ok(None);
        };
        let before = pinned
            .metadata()
            .map_err(|_| "selected_state_unavailable_or_unsafe")?;
        if !before.is_file()
            || before.nlink() != 1
            || before.uid() != unsafe { libc::geteuid() }
            || before.mode() & 0o077 != 0
            || before.len() > cap
        {
            return Err("selected_state_type_owner_or_bound_unsafe");
        }
        // A second pathname open could touch a substituted device before fstat.
        // Reopen the held regular inode through the fixed proc descriptor alias,
        // after verifying that this is the kernel proc filesystem.
        let mut file = reopen_regular(&pinned)?;
        if !stable(
            &before,
            &file.metadata().map_err(|_| "selected_state_changed")?,
        ) {
            return Err("selected_state_changed");
        }
        if output
            && (before.gid() != unsafe { libc::getegid() }
                || before.mode() & 0o7777 != 0o600
                || unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) } != 0)
        {
            return Err("current_output_metadata_unsupported");
        }
        let mut bytes = Vec::with_capacity((before.len() as usize).min(cap as usize));
        let mut buffer = [0u8; 8192];
        loop {
            budget.tick(0)?;
            let max = (cap as usize + 1)
                .saturating_sub(bytes.len())
                .min(buffer.len());
            if max == 0 {
                return Err("selected_state_type_owner_or_bound_unsafe");
            }
            let n = file
                .read(&mut buffer[..max])
                .map_err(|_| "selected_state_unavailable_or_unsafe")?;
            if n == 0 {
                break;
            }
            budget.tick(n)?;
            bytes.extend_from_slice(&buffer[..n]);
            if bytes.len() as u64 > cap {
                return Err("selected_state_type_owner_or_bound_unsafe");
            }
        }
        if bytes.len() as u64 != before.len()
            || !stable(
                &before,
                &file.metadata().map_err(|_| "selected_state_changed")?,
            )
        {
            return Err("selected_state_changed");
        }
        let current = openat(&self.0, &name, libc::O_PATH)?.ok_or("selected_state_changed")?;
        if !stable(
            &before,
            &current.metadata().map_err(|_| "selected_state_changed")?,
        ) {
            return Err("selected_state_changed");
        }
        Ok(Some((bytes, before)))
    }
}

fn reopen_regular(pinned: &File) -> Result<File> {
    let proc_name = CString::new("/proc").unwrap();
    let proc_fd = unsafe {
        libc::open(
            proc_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if proc_fd < 0 {
        return Err("diagnostic_kernel_descriptor_unavailable");
    }
    let proc = unsafe { File::from_raw_fd(proc_fd) };
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(proc.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type as u64 != 0x9fa0
    {
        return Err("diagnostic_kernel_descriptor_unavailable");
    }
    let process = CString::new(std::process::id().to_string()).unwrap();
    let process = openat(&proc, &process, libc::O_RDONLY | libc::O_DIRECTORY)?
        .ok_or("diagnostic_kernel_descriptor_unavailable")?;
    let fd_dir = openat(&process, c"fd", libc::O_RDONLY | libc::O_DIRECTORY)?
        .ok_or("diagnostic_kernel_descriptor_unavailable")?;
    let number = CString::new(pinned.as_raw_fd().to_string()).unwrap();
    // Following this fixed kernel-owned descriptor alias is intentional; it
    // does not resolve the operator-selected pathname a second time.
    let fd = unsafe {
        libc::openat(
            fd_dir.as_raw_fd(),
            number.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err("diagnostic_kernel_descriptor_unavailable");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }
    fn write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[test]
    fn refuses_fifo_device_links_hardlinks_and_bound_before_reading() {
        let temp = fixture();
        let dir = Directory::open(temp.path()).unwrap();
        write(&temp.path().join("regular"), b"private-secret-canary");
        symlink("regular", temp.path().join("linked")).unwrap();
        std::fs::hard_link(temp.path().join("regular"), temp.path().join("hard")).unwrap();
        let fifo = CString::new(temp.path().join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let started = Instant::now();
        for name in ["regular", "linked", "hard", "fifo"] {
            assert!(dir.read(name, 8, &mut Budget::new()).is_err());
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(Directory::open(Path::new("/dev")).is_err());
        assert!(dir.read("../outside", 64, &mut Budget::new()).is_err());
    }
    #[test]
    fn refuses_redirected_and_writable_ancestors() {
        let temp = fixture();
        let inner = temp.path().join("inner");
        std::fs::create_dir(&inner).unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).unwrap();
        let leaf = inner.join("leaf");
        std::fs::create_dir(&leaf).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(Directory::open(&leaf).is_ok());
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Directory::open(&leaf).is_err());
        symlink(&leaf, temp.path().join("alias")).unwrap();
        assert!(Directory::open(&temp.path().join("alias")).is_err());
    }
    #[test]
    fn exact_private_read_and_missing_are_distinct_from_invalid() {
        let temp = fixture();
        write(&temp.path().join("data"), b"bounded");
        let dir = Directory::open(temp.path()).unwrap();
        assert_eq!(
            dir.read("data", 7, &mut Budget::new()).unwrap(),
            Some(b"bounded".to_vec())
        );
        assert!(dir.read("data", 6, &mut Budget::new()).is_err());
        assert_eq!(dir.read("missing", 7, &mut Budget::new()).unwrap(), None);
    }
    #[test]
    fn held_regular_descriptor_survives_a_leaf_swap_without_opening_the_replacement() {
        let temp = fixture();
        let selected = temp.path().join("selected");
        write(&selected, b"original");
        let directory = Directory::open(temp.path()).unwrap();
        let pinned = openat(&directory.0, c"selected", libc::O_PATH)
            .unwrap()
            .unwrap();
        std::fs::remove_file(&selected).unwrap();
        let fifo = CString::new(selected.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let mut reopened = reopen_regular(&pinned).unwrap();
        let mut bytes = Vec::new();
        reopened.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        assert!(directory.read("selected", 16, &mut Budget::new()).is_err());
    }
}
