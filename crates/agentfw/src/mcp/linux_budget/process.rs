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
mod tests {
    use super::*;

    struct Child(std::process::Child);
    impl Child {
        fn new() -> Self {
            Self(
                std::process::Command::new("/bin/sleep")
                    .arg("30")
                    .spawn()
                    .unwrap(),
            )
        }
    }
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn sou136_real_relative_open_observes_esrch_after_reap() {
        let proc = Proc::open().unwrap();
        let mut child = Child::new();
        let task = proc.task(child.0.id()).unwrap().unwrap();
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let raw = unsafe { libc::openat(task.directory.as_raw_fd(), c"cgroup".as_ptr(), FLAGS) };
        assert!(raw < 0);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        assert!(task.cgroup().unwrap().is_none());
        proc.departed(task.pid, Some(&task)).unwrap();
    }

    #[test]
    fn sou136_fork_exec_preserves_the_pinned_lifetime_until_exit() {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};
        let proc = Proc::open().unwrap();
        let mut child = Child(
            Command::new("/bin/sh")
                .args(["-c", "printf R; read line; exec /bin/sleep 30"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id();
        let stdout = child.0.stdout.as_mut().unwrap();
        let mut ready = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut ready, 1, 2000) }, 1);
        let mut byte = [0];
        stdout.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"R");
        let task = proc.task(pid).unwrap().unwrap();
        let identity = task.identity().unwrap().unwrap();
        let group = task.cgroup().unwrap().unwrap();
        child.0.stdin.take().unwrap().write_all(b"go\n").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let comm = task
                .record("comm", "member_identity_read")
                .unwrap()
                .unwrap();
            if comm == b"sleep\n" {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "owned exec did not complete"
            );
            std::thread::yield_now();
        }
        assert_eq!(task.identity().unwrap().unwrap(), identity);
        assert_eq!(task.cgroup().unwrap().unwrap(), group);
        assert!(task.same(&proc.task(pid).unwrap().unwrap()).unwrap());
        assert_eq!(
            proc.departed(pid, Some(&task)).unwrap_err().phase,
            "member_departure_live"
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        proc.departed(pid, Some(&task)).unwrap();
    }

    #[test]
    fn sou136_exited_unreaped_child_requires_readable_pidfd() {
        let proc = Proc::open().unwrap();
        let mut child = Child::new();
        let pid = child.0.id();
        let task = proc.task(pid).unwrap().unwrap();
        let handle = pidfd(pid).unwrap().unwrap();
        assert!(!exited(&handle).unwrap());
        child.0.kill().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !exited(&handle).unwrap() {
            assert!(
                std::time::Instant::now() < deadline,
                "owned exit did not complete"
            );
            std::thread::yield_now();
        }
        assert!(task.identity().unwrap().unwrap().1);
        proc.departed(pid, Some(&task)).unwrap();
        child.0.wait().unwrap();
    }

    #[test]
    fn sou136_live_process_and_changed_inode_cannot_discharge_departure() {
        let proc = Proc::open().unwrap();
        let pid = std::process::id();
        let own = proc.task(pid).unwrap().unwrap();
        assert_eq!(
            proc.departed(pid, Some(&own)).unwrap_err().phase,
            "member_departure_live"
        );
        let child = Child::new();
        let other = proc.task(child.0.id()).unwrap().unwrap();
        // Same reported numeric PID, different retained kernel PID-directory
        // inode. Equal/synthetic start ticks cannot grant this replacement.
        let replaced = Task {
            directory: other.directory,
            pid,
            device: other.device,
        };
        assert!(!own.same(&replaced).unwrap());
        assert_eq!(
            proc.departed(pid, Some(&replaced)).unwrap_err().phase,
            "member_departure_reused"
        );
        assert_eq!(
            proc.departed(pid, None).unwrap_err().phase,
            "member_departure_reused"
        );
    }

    #[test]
    fn sou136_numeric_absence_is_distinct_from_a_terminal_pinned_task() {
        let proc = Proc::open().unwrap();
        let mut child = Child::new();
        let pid = child.0.id();
        let pinned = proc.task(pid).unwrap().unwrap();
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(proc.task(pid).unwrap().is_none());
        proc.departed(pid, None).unwrap();
        proc.departed(pid, Some(&pinned)).unwrap();
    }

    #[test]
    fn sou136_proc_namespace_rejects_missing_or_multiple_namespace_levels() {
        namespace_status(42, b"Name:\towned\nNSpid:\t42\n").unwrap();
        for bytes in [
            b"NSpid:\t42 42\n".as_slice(),
            b"NSpid:\t43\n",
            b"NSpid:\t42\nNSpid:\t42\n",
            b"Name:\tonly\n",
            b"NSpid:\t\n",
            b"NSpid:\tno\n",
            b"NSpid:\t\xff\n",
        ] {
            assert_eq!(
                namespace_status(42, bytes).unwrap_err().phase,
                "proc_namespace"
            );
        }
    }

    #[test]
    fn sou136_wrong_proc_device_or_filesystem_is_never_an_exit() {
        let file = tempfile::tempfile().unwrap();
        assert!(proc_file(&file, None, false).is_err());
        let directory = tempfile::tempdir().unwrap();
        assert!(proc_file(&File::open(directory.path()).unwrap(), None, true).is_err());
        let own = File::open("/proc/self/stat").unwrap();
        assert!(proc_file(&own, Some(u64::MAX), false).is_err());
        assert!(proc_file(&own, None, true).is_err());
    }

    #[test]
    fn sou136_lookup_errno_candidates_exclude_permissions_and_other_errors() {
        for errno in [libc::ENOENT, libc::ESRCH] {
            assert!(missing(&std::io::Error::from_raw_os_error(errno)));
        }
        for errno in [
            libc::EACCES,
            libc::EPERM,
            libc::EIO,
            libc::ENOTDIR,
            libc::ELOOP,
            libc::EMFILE,
            libc::EBADF,
        ] {
            assert!(!missing(&std::io::Error::from_raw_os_error(errno)));
        }
    }

    #[test]
    fn sou136_pinned_read_only_waives_reviewed_esrch_not_lookup_enoent() {
        assert!(record_bytes(
            Err(std::io::Error::from_raw_os_error(libc::ESRCH)),
            "member_cgroup_read"
        )
        .unwrap()
        .is_none());
        for errno in [
            libc::ENOENT,
            libc::EACCES,
            libc::EPERM,
            libc::EIO,
            libc::EINVAL,
            libc::EBADF,
        ] {
            let error = record_bytes(
                Err(std::io::Error::from_raw_os_error(errno)),
                "member_identity_read",
            )
            .unwrap_err();
            assert_eq!(error.phase, "member_identity_read");
            assert_eq!(error.errno, Some(errno));
        }
        assert_eq!(
            record_bytes(Ok(vec![]), "member_identity_read").unwrap(),
            Some(vec![])
        );
    }

    #[test]
    fn sou136_pidfd_unexpected_poll_states_never_prove_departure() {
        assert!(!poll_state(0, 0).unwrap());
        assert!(poll_state(1, libc::POLLIN).unwrap());
        assert!(poll_state(1, libc::POLLIN | libc::POLLHUP).unwrap());
        for (count, events) in [
            (1, 0),
            (1, libc::POLLHUP),
            (1, libc::POLLIN | libc::POLLERR),
            (1, libc::POLLNVAL),
            (1, libc::POLLOUT),
            (2, libc::POLLIN),
            (0, libc::POLLIN),
        ] {
            assert_eq!(
                poll_state(count, events).unwrap_err().phase,
                "member_pidfd_poll"
            );
        }
    }

    #[test]
    fn sou136_malformed_cgroup_records_never_become_departure_candidates() {
        for bytes in [b"0::/\n".as_slice(), b"0::/owned/child\n"] {
            assert_eq!(parse_cgroup(bytes.to_vec()).unwrap().as_bytes(), bytes);
        }
        for bytes in [
            b"".as_slice(),
            b"unrelated\n",
            b"0::relative\n",
            b"0::/owned",
            b"0::/owned\n0::/other\n",
            b"0::/owned\r\n",
            b"0::/owned\0\n",
            b"0::/owned/../other\n",
            b"0::/owned//child\n",
            b"0::/\xff\n",
        ] {
            assert!(parse_cgroup(bytes.to_vec()).is_err());
        }
    }

    #[test]
    fn sou136_stat_identity_requires_pid_shape_state_and_start() {
        let stat = |pid: u32, state: &str, ticks: &str| {
            format!(
                "{pid} (comm with ) parentheses) {state} {} {ticks} 0\n",
                ["0"; 18].join(" ")
            )
        };
        assert_eq!(
            parse_identity(42, stat(42, "S", "7").as_bytes()).unwrap(),
            (7, false)
        );
        assert_eq!(
            parse_identity(42, stat(42, "Z", "7").as_bytes()).unwrap(),
            (7, true)
        );
        for bytes in [
            stat(43, "S", "7"),
            stat(42, "invalid", "7"),
            stat(42, "S", "bad"),
            "42 (x) S 0".into(),
            "malformed".into(),
        ] {
            assert_eq!(
                parse_identity(42, bytes.as_bytes()).unwrap_err().phase,
                "member_identity_parse"
            );
        }
        assert!(parse_identity(42, b"42 (\xff) S").is_err());
    }
}
