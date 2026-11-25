// SPDX-License-Identifier: Apache-2.0
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
