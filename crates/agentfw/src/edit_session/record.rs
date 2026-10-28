// SPDX-License-Identifier: Apache-2.0
//! Retained diagnostic bindings. These local records are not runtime authority
//! or authenticated proof that a mutation committed or reached its caller.
use anyhow::{ensure, Context as _, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

pub(super) const FORMAT: &str = "sw-installed-edit-diagnostic-context/1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessIdentity {
    pub pid: u32,
    pub start_ticks: u64,
    pub boot_id: String,
    pub uid: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ListenerIdentity {
    pub fd: u32,
    pub inode: u64,
    pub device: u64,
}

impl ListenerIdentity {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.fd <= i32::MAX as u32 && self.inode != 0,
            "edit_listener_identity_invalid"
        );
        Ok(())
    }
}

impl ProcessIdentity {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.pid > 0
                && self.start_ticks > 0
                && self.boot_id.len() == 36
                && self.boot_id.bytes().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                    }
                }),
            "edit_process_identity_invalid"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    pub format: String,
    pub run: PathBuf,
    pub home: PathBuf,
    pub profile_sha256: String,
    pub host_session: String,
    pub instance_id: String,
    pub config_sha256: String,
    pub listener: ListenerIdentity,
    pub started_at_ms: u64,
    pub owner: ProcessIdentity,
}

impl Context {
    pub fn validate(&self) -> Result<()> {
        fn selected(path: &Path) -> bool {
            path.is_absolute()
                && path.as_os_str().len() <= 4096
                && path
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        }
        ensure!(
            self.format == FORMAT
                && selected(&self.run)
                && selected(&self.home)
                && self.home.parent() == Some(self.run.as_path())
                && self
                    .home
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| {
                        n.len() == 43
                            && n.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                    })
                && crate::native::is_digest(&self.profile_sha256)
                && crate::native::identifier(&self.host_session)
                && crate::native::identifier(&self.instance_id)
                && crate::native::is_digest(&self.config_sha256)
                && self.started_at_ms > 0,
            "edit_diagnostic_context_invalid"
        );
        self.owner.validate()?;
        self.listener.validate()
    }
}

fn read_at(dir: &File, name: &std::ffi::CStr, cap: u64) -> Result<(Vec<u8>, u32)> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    ensure!(fd >= 0, "edit_process_unavailable");
    let file = unsafe { File::from_raw_fd(fd) };
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() <= cap,
        "edit_process_metadata"
    );
    let mut bytes = Vec::new();
    (&file).take(cap + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    ensure!(
        bytes.len() as u64 <= cap
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.uid() == after.uid(),
        "edit_process_changed"
    );
    Ok((bytes, after.uid()))
}

fn start_ticks(bytes: &[u8], pid: u32) -> Result<u64> {
    let text = std::str::from_utf8(bytes)?;
    let (first, tail) = text
        .rsplit_once(") ")
        .context("edit_process_stat_invalid")?;
    ensure!(
        first
            .split_once(" (")
            .is_some_and(|(n, _)| n == pid.to_string()),
        "edit_process_pid_mismatch"
    );
    // tail starts at field 3 (state); field 22 is the process start clock.
    let value = tail
        .split_ascii_whitespace()
        .nth(19)
        .context("edit_process_stat_invalid")?
        .parse::<u64>()?;
    ensure!(value > 0, "edit_process_start_invalid");
    Ok(value)
}

/// Observe only this numeric process and fixed kernel boot identity. No signal,
/// executable launch, process enumeration or authority mutation is performed.
pub(super) fn process_identity(pid: u32) -> Result<ProcessIdentity> {
    ensure!(
        pid > 0 && pid <= i32::MAX as u32,
        "edit_process_pid_invalid"
    );
    let proc = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/proc")?;
    let name = std::ffi::CString::new(pid.to_string())?;
    let fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(fd >= 0, "edit_process_unavailable");
    let selected = unsafe { File::from_raw_fd(fd) };
    let (first, uid) = read_at(&selected, c"stat", 8192)?;
    ensure!(
        uid == unsafe { libc::geteuid() },
        "edit_process_foreign_owner"
    );
    let start = start_ticks(&first, pid)?;
    // The fixed boot observation is descriptor-opened, never selected by JSON.
    let mut boot_parent = proc;
    for name in [c"sys", c"kernel", c"random"] {
        let fd = unsafe {
            libc::openat(
                boot_parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        ensure!(fd >= 0, "edit_process_boot_unavailable");
        boot_parent = unsafe { File::from_raw_fd(fd) };
    }
    let (boot, boot_uid) = read_at(&boot_parent, c"boot_id", 64)?;
    ensure!(boot_uid == 0, "edit_process_boot_owner");
    let boot = std::str::from_utf8(&boot)?;
    let (second, second_uid) = read_at(&selected, c"stat", 8192)?;
    ensure!(
        uid == second_uid && start == start_ticks(&second, pid)?,
        "edit_process_changed"
    );
    let result = ProcessIdentity {
        pid,
        start_ticks: start,
        boot_id: boot.trim_end_matches('\n').into(),
        uid,
    };
    result.validate()?;
    Ok(result)
}

/// Capture the already-bound descriptor before it is moved into the existing
/// server. This records diagnostic identity without duplicating the listener.
pub(super) fn listener_identity(fd: i32) -> Result<ListenerIdentity> {
    ensure!(fd >= 0, "edit_listener_identity_invalid");
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstat(fd, &mut stat) } == 0
            && stat.st_mode & libc::S_IFMT == libc::S_IFSOCK
            && stat.st_uid == unsafe { libc::geteuid() },
        "edit_listener_identity_unavailable"
    );
    let result = ListenerIdentity {
        fd: fd as u32,
        inode: stat.st_ino,
        device: stat.st_dev,
    };
    result.validate()?;
    Ok(result)
}

/// Check one exact kernel descriptor alias belonging to the recorded owner.
/// There is no process/descriptor enumeration, socket opening or token access.
/// Local context remains descriptive; this rejects drift before credentials are
/// sent to the retained endpoint, rather than treating PID existence as custody.
pub(super) fn observe_listener(
    owner: &ProcessIdentity,
    expected: &ListenerIdentity,
    bind: &str,
    port: u16,
) -> Result<()> {
    owner.validate()?;
    expected.validate()?;
    ensure!(
        process_identity(owner.pid)? == *owner,
        "edit_listener_owner_changed"
    );
    let proc = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/proc")?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(proc.as_raw_fd(), &mut filesystem) } == 0
            && filesystem.f_type as u64 == 0x9fa0,
        "edit_listener_kernel_descriptor_unavailable"
    );
    ensure!(
        matches!(bind, "127.0.0.1" | "::1") && port != 0,
        "edit_listener_endpoint_invalid"
    );
    let pid = std::ffi::CString::new(owner.pid.to_string())?;
    let open_directory = |parent: &File, name: &std::ffi::CStr| -> Result<File> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        ensure!(fd >= 0, "edit_listener_kernel_descriptor_unavailable");
        Ok(unsafe { File::from_raw_fd(fd) })
    };
    let process = open_directory(&proc, pid.as_c_str())?;
    ensure!(
        process.metadata()?.uid() == owner.uid,
        "edit_listener_foreign_owner"
    );
    // A loopback address belongs to a network namespace. The caller must not
    // authenticate to a different namespace's listener merely because the
    // selected owner's socket is valid in its own namespace.
    let current_pid = std::ffi::CString::new(std::process::id().to_string())?;
    let current = open_directory(&proc, current_pid.as_c_str())?;
    let namespace = |process: &File| -> Result<(u64, u64)> {
        let directory = open_directory(process, c"ns")?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // This fixed proc namespace alias is followed only for metadata; no
        // namespace descriptor is opened and setns is never invoked.
        ensure!(
            unsafe { libc::fstatat(directory.as_raw_fd(), c"net".as_ptr(), &mut stat, 0) } == 0
                && stat.st_ino != 0,
            "edit_listener_namespace_unavailable"
        );
        Ok((stat.st_dev, stat.st_ino))
    };
    ensure!(
        namespace(&process)? == namespace(&current)?,
        "edit_listener_network_namespace_mismatch"
    );
    let directory = open_directory(&process, c"fd")?;
    ensure!(
        directory.metadata()?.uid() == owner.uid,
        "edit_listener_foreign_owner"
    );
    let number = std::ffi::CString::new(expected.fd.to_string())?;
    let wanted = format!("socket:[{}]", expected.inode);
    let read_link = || -> Result<()> {
        let mut bytes = [0u8; 128];
        let size = unsafe {
            libc::readlinkat(
                directory.as_raw_fd(),
                number.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        ensure!(
            size > 0
                && (size as usize) < bytes.len()
                && &bytes[..size as usize] == wanted.as_bytes(),
            "edit_listener_descriptor_changed"
        );
        Ok(())
    };
    read_link()?;
    // Following the verified, fixed kernel FD alias for metadata cannot open a
    // user-selected device. A concurrent replacement is refused by type/inode.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatat(directory.as_raw_fd(), number.as_ptr(), &mut stat, 0) } == 0
            && stat.st_mode & libc::S_IFMT == libc::S_IFSOCK
            && stat.st_ino == expected.inode
            && stat.st_dev == expected.device
            && stat.st_uid == owner.uid,
        "edit_listener_descriptor_changed"
    );
    read_link()?;
    // The exact FD/inode must also be the LISTEN socket for this endpoint in
    // that process's network namespace. Holding an unrelated socket is not
    // custody of a destination selected through local JSON.
    let started = std::time::Instant::now();
    let network = open_directory(&process, c"net")?;
    let (table, uid) = read_at(
        &network,
        if bind == "::1" { c"tcp6" } else { c"tcp" },
        128 * 1024,
    )?;
    ensure!(uid == 0 || uid == owner.uid, "edit_listener_foreign_owner");
    validate_endpoint(&table, expected.inode, owner.uid, bind, port)?;
    ensure!(
        started.elapsed() <= std::time::Duration::from_secs(1),
        "edit_listener_observation_time_bound"
    );
    ensure!(
        process_identity(owner.pid)? == *owner,
        "edit_listener_owner_changed"
    );
    Ok(())
}

fn validate_endpoint(bytes: &[u8], inode: u64, uid: u32, bind: &str, port: u16) -> Result<()> {
    ensure!(bytes.len() <= 128 * 1024, "edit_listener_table_bound");
    let table = std::str::from_utf8(bytes)?;
    let expected = match bind {
        "127.0.0.1" => format!("0100007F:{port:04X}"),
        "::1" => format!("00000000000000000000000001000000:{port:04X}"),
        _ => anyhow::bail!("edit_listener_endpoint_invalid"),
    };
    let mut lines = table.lines();
    let header = lines.next().context("edit_listener_table_invalid")?;
    ensure!(
        header.contains("local_address") && header.contains("inode"),
        "edit_listener_table_invalid"
    );
    let mut matched = false;
    for (index, line) in lines.enumerate() {
        ensure!(index < 1024, "edit_listener_table_bound");
        let mut parts = line.split_ascii_whitespace();
        let _slot = parts.next().context("edit_listener_table_invalid")?;
        let local = parts.next().context("edit_listener_table_invalid")?;
        let _remote = parts.next().context("edit_listener_table_invalid")?;
        let state = parts.next().context("edit_listener_table_invalid")?;
        let owner = parts
            .nth(3)
            .context("edit_listener_table_invalid")?
            .parse::<u32>()?;
        let observed = parts
            .nth(1)
            .context("edit_listener_table_invalid")?
            .parse::<u64>()?;
        if observed != inode {
            continue;
        }
        ensure!(
            !matched && local == expected && state == "0A" && owner == uid,
            "edit_listener_endpoint_changed"
        );
        matched = true;
    }
    ensure!(matched, "edit_listener_endpoint_unavailable");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parser_handles_parentheses_without_confusing_start_time() {
        let tail = (0..20)
            .map(|i| (i + 1).to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let raw = format!("41 (command ) with ( brackets) {tail}\n");
        assert_eq!(start_ticks(raw.as_bytes(), 41).unwrap(), 20);
        assert!(start_ticks(raw.as_bytes(), 42).is_err());
        assert!(start_ticks(b"41 (short) S 1", 41).is_err());
    }

    #[test]
    fn process_identity_matches_current_process_and_refuses_missing_pid() {
        let first = process_identity(std::process::id()).unwrap();
        assert_eq!(first, process_identity(std::process::id()).unwrap());
        assert_eq!(first.uid, unsafe { libc::geteuid() });
        assert!(process_identity(0).is_err());
        assert!(process_identity(u32::MAX).is_err());
    }

    #[test]
    fn exact_listener_binding_refuses_a_foreign_or_replaced_descriptor() {
        let owner = process_identity(std::process::id()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let expected = listener_identity(listener.as_raw_fd()).unwrap();
        let port = listener.local_addr().unwrap().port();
        observe_listener(&owner, &expected, "127.0.0.1", port).unwrap();
        let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut wrong = expected.clone();
        wrong.fd = other.as_raw_fd() as u32;
        assert!(observe_listener(&owner, &wrong, "127.0.0.1", port).is_err());
        assert!(observe_listener(
            &owner,
            &expected,
            "127.0.0.1",
            other.local_addr().unwrap().port()
        )
        .is_err());
        let file = File::open("/dev/null").unwrap();
        assert!(listener_identity(file.as_raw_fd()).is_err());
        wrong.fd = file.as_raw_fd() as u32;
        assert!(observe_listener(&owner, &wrong, "127.0.0.1", port).is_err());
        let mut changed = owner.clone();
        changed.start_ticks += 1;
        assert!(observe_listener(&changed, &expected, "127.0.0.1", port).is_err());
        drop(listener);
        assert!(observe_listener(&owner, &expected, "127.0.0.1", port).is_err());
    }

    #[test]
    fn endpoint_table_requires_exact_loopback_listen_owner_and_finite_records() {
        let header = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
        let row = "0: 0100007F:CAFE 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 1234 1\n";
        let bytes = format!("{header}{row}");
        validate_endpoint(bytes.as_bytes(), 1234, 1000, "127.0.0.1", 0xcafe).unwrap();
        for raw in [
            bytes.replace("0A", "01"),
            bytes.replace("1000", "1001"),
            bytes.replace("CAFE", "CAFF"),
            format!("{bytes}{row}"),
        ] {
            assert!(validate_endpoint(raw.as_bytes(), 1234, 1000, "127.0.0.1", 0xcafe).is_err());
        }
        assert!(validate_endpoint(
            format!("{header}{}", row.repeat(1025)).as_bytes(),
            4321,
            1000,
            "127.0.0.1",
            0xcafe
        )
        .is_err());
    }
}
