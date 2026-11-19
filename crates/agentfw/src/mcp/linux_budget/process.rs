// SPDX-License-Identifier: Apache-2.0
//! Pinned procfs observations. A missing record is a departure candidate, never
//! proof by itself. The caller must reobserve its exact owned cgroup as well.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const FLAGS: libc::c_int = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
const PROC_MAGIC: libc::c_long = 0x9fa0;

#[derive(Clone, Copy, Debug)]
pub(super) struct Error {
    pub(super) phase: &'static str,
    pub(super) errno: Option<i32>,
}

impl Error {
    fn io(phase: &'static str, error: std::io::Error) -> Self {
        Self {
            phase,
            errno: error.raw_os_error(),
        }
    }
    fn invalid(phase: &'static str) -> Self {
        Self { phase, errno: None }
    }
}

type Result<T> = std::result::Result<T, Error>;

fn missing(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOENT) | Some(libc::ESRCH))
}

fn proc_file(file: &File, device: Option<u64>, directory: bool) -> Result<()> {
    let meta = file
        .metadata()
        .map_err(|e| Error::io("member_proc_fs", e))?;
    if device.is_some_and(|device| meta.dev() != device)
        || (directory && !meta.is_dir())
        || (!directory && !meta.is_file())
    {
        return Err(Error::invalid("member_proc_type"));
    }
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(Error::io("member_proc_fs", std::io::Error::last_os_error()));
    }
    if unsafe { stat.assume_init() }.f_type != PROC_MAGIC {
        return Err(Error::invalid("member_proc_fs"));
    }
    Ok(())
}

fn open_at(
    directory: &File,
    name: &str,
    is_directory: bool,
    phase: &'static str,
) -> Result<Option<File>> {
    let name = CString::new(name).map_err(|_| Error::invalid(phase))?;
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            FLAGS | if is_directory { libc::O_DIRECTORY } else { 0 },
        )
    };
    if raw >= 0 {
        return Ok(Some(unsafe { File::from_raw_fd(raw) }));
    }
    let error = std::io::Error::last_os_error();
    if missing(&error) {
        Ok(None)
    } else {
        Err(Error::io(phase, error))
    }
}

pub(super) struct Proc {
    root: File,
    device: u64,
}

impl Proc {
    pub(super) fn open() -> Result<Self> {
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(FLAGS | libc::O_DIRECTORY)
            .open("/proc")
            .map_err(|e| Error::io("proc_root_open", e))?;
        proc_file(&root, None, true)?;
        let device = root
            .metadata()
            .map_err(|e| Error::io("proc_root_fs", e))?
            .dev();
        // pidfd_open and this procfs must use the same PID namespace. `self` is
        // a kernel magic link under the already validated, pinned proc root.
        let mut bytes = [0u8; 32];
        let count = unsafe {
            libc::readlinkat(
                root.as_raw_fd(),
                c"self".as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if count <= 0
            || count as usize >= bytes.len()
            || std::str::from_utf8(&bytes[..count as usize])
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                != Some(std::process::id())
        {
            return Err(Error::invalid("proc_namespace"));
        }
        let processes = Self { root, device };
        let own = processes
            .task(std::process::id())?
            .ok_or_else(|| Error::invalid("proc_namespace"))?;
        let status = own
            .record("status", "proc_namespace")?
            .ok_or_else(|| Error::invalid("proc_namespace"))?;
        namespace_status(std::process::id(), &status)?;
        Ok(processes)
    }

    pub(super) fn task(&self, pid: u32) -> Result<Option<Task>> {
        if pid == 0 {
            return Err(Error::invalid("member_zero_pid"));
        }
        let Some(directory) = open_at(&self.root, &pid.to_string(), true, "member_proc_open")?
        else {
            return Ok(None);
        };
        proc_file(&directory, Some(self.device), true)?;
        Ok(Some(Task {
            directory,
            pid,
            device: self.device,
        }))
    }

    /// One bounded close-out observation, after the exact cgroup excludes PID.
    /// No numeric lookup may adopt a replacement, even with equal start ticks.
    pub(super) fn departed(&self, pid: u32, known: Option<&Task>) -> Result<()> {
        let current = self.task(pid)?;
        if let Some(current) = &current {
            let Some(known) = known else {
                return Err(Error::invalid("member_departure_reused"));
            };
            if !current.same(known)? {
                return Err(Error::invalid("member_departure_reused"));
            }
            if current.identity()?.is_some_and(|(_, terminal)| !terminal) {
                return Err(Error::invalid("member_departure_live"));
            }
        }
        let pidfd = pidfd(pid)?;
        match pidfd {
            None => {
                // ESRCH alone is insufficient: rule out a now-addressable
                // replacement after that syscall. A zombie not yet reaped has
                // a pidfd, so this branch requires complete numeric absence.
                if self.task(pid)?.is_some() {
                    return Err(Error::invalid("member_departure_unverified"));
                }
            }
            Some(pidfd) => {
                if !exited(&pidfd)? {
                    return Err(Error::invalid("member_departure_live"));
                }
                if let Some(last) = self.task(pid)? {
                    let Some(known) = known else {
                        return Err(Error::invalid("member_departure_reused"));
                    };
                    if !last.same(known)? {
                        return Err(Error::invalid("member_departure_reused"));
                    }
                    if last.identity()?.is_some_and(|(_, terminal)| !terminal) {
                        return Err(Error::invalid("member_departure_live"));
                    }
                }
            }
        }
        Ok(())
    }
}

pub(super) struct Task {
    directory: File,
    pid: u32,
    device: u64,
}

impl Task {
    pub(super) fn same(&self, other: &Self) -> Result<bool> {
        let left = self
            .directory
            .metadata()
            .map_err(|e| Error::io("member_identity_read", e))?;
        let right = other
            .directory
            .metadata()
            .map_err(|e| Error::io("member_identity_read", e))?;
        Ok(self.pid == other.pid && left.dev() == right.dev() && left.ino() == right.ino())
    }

    fn record(&self, name: &str, phase: &'static str) -> Result<Option<Vec<u8>>> {
        let Some(file) = open_at(&self.directory, name, false, phase)? else {
            return Ok(None);
        };
        proc_file(&file, Some(self.device), false)?;
        record_bytes(
            super::linux::read_record(&file, super::MAX_CONTROL_BYTES),
            phase,
        )
    }

    pub(super) fn cgroup(&self) -> Result<Option<String>> {
        self.record("cgroup", "member_cgroup_read")?
            .map(parse_cgroup)
            .transpose()
    }

    pub(super) fn identity(&self) -> Result<Option<(u64, bool)>> {
        let Some(bytes) = self.record("stat", "member_identity_read")? else {
            return Ok(None);
        };
        parse_identity(self.pid, &bytes).map(Some)
    }
}

fn record_bytes(bytes: std::io::Result<Vec<u8>>, phase: &'static str) -> Result<Option<Vec<u8>>> {
    match bytes {
        Ok(bytes) => Ok(Some(bytes)),
        // Only ESRCH is the reviewed pinned proc_single_show exit case.
        // ENOENT on a read, unlike lookup, remains an observation failure.
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(None),
        Err(error) => Err(Error::io(phase, error)),
    }
}

fn parse_cgroup(bytes: Vec<u8>) -> Result<String> {
    let value = String::from_utf8(bytes).map_err(|_| Error::invalid("member_utf8"))?;
    let invalid = || Error::invalid("member_cgroup_parse");
    let record = value.strip_suffix('\n').ok_or_else(invalid)?;
    let path = record.strip_prefix("0::/").ok_or_else(invalid)?;
    if record.chars().any(char::is_control)
        || (!path.is_empty() && path.split('/').any(|part| matches!(part, "" | "." | "..")))
    {
        return Err(invalid());
    }
    Ok(value)
}

fn namespace_status(pid: u32, bytes: &[u8]) -> Result<()> {
    // A proc mount from an ancestor PID namespace can coincidentally report
    // the same numeric self PID. NSpid must prove no additional namespace level.
    let invalid = || Error::invalid("proc_namespace");
    let value = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let rows: Vec<_> = value
        .lines()
        .filter_map(|line| line.strip_prefix("NSpid:"))
        .collect();
    if rows.len() != 1 {
        return Err(invalid());
    }
    let ids: Vec<_> = rows[0].split_ascii_whitespace().collect();
    if ids.len() != 1 || ids[0].parse::<u32>().ok() != Some(pid) {
        return Err(invalid());
    }
    Ok(())
}

fn parse_identity(pid: u32, bytes: &[u8]) -> Result<(u64, bool)> {
    let invalid = || Error::invalid("member_identity_parse");
    let value = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let (number, rest) = value.split_once(" (").ok_or_else(invalid)?;
    if number.parse::<u32>().ok() != Some(pid) {
        return Err(invalid());
    }
    let close = rest.rfind(')').ok_or_else(invalid)?;
    let fields: Vec<_> = rest[close + 1..].split_ascii_whitespace().collect();
    let state = *fields.first().ok_or_else(invalid)?;
    if !matches!(
        state,
        "R" | "S" | "D" | "Z" | "T" | "t" | "X" | "x" | "K" | "W" | "P" | "I"
    ) {
        return Err(invalid());
    }
    let ticks = fields
        .get(19)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    Ok((ticks, matches!(state, "Z" | "X" | "x")))
}

fn pidfd(pid: u32) -> Result<Option<File>> {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw >= 0 {
        return Ok(Some(unsafe { File::from_raw_fd(raw as libc::c_int) }));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(None)
    } else {
        Err(Error::io("member_pidfd_open", error))
    }
}

fn exited(pidfd: &File) -> Result<bool> {
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let count = unsafe { libc::poll(&mut poll, 1, 0) };
    if count < 0 {
        return Err(Error::io(
            "member_pidfd_poll",
            std::io::Error::last_os_error(),
        ));
    }
    poll_state(count, poll.revents)
}

fn poll_state(count: libc::c_int, events: libc::c_short) -> Result<bool> {
    if count == 0 && events == 0 {
        return Ok(false);
    }
    if count == 1 && events & libc::POLLIN != 0 && events & !(libc::POLLIN | libc::POLLHUP) == 0 {
        return Ok(true);
    }
    Err(Error::invalid("member_pidfd_poll"))
}

#[cfg(test)]
mod tests;
