// SPDX-License-Identifier: Apache-2.0
//! Private crash ownership for the selected Linux MCP sandboxes.
//!
//! The outer owner never enters the resource cgroup. A trusted namespace PID 1
//! owns the original server and exits on loss of its private lease. No lease or
//! cgroup descriptor is inherited by the original, untrusted server.

#[cfg(target_os = "linux")]
pub(crate) const LEASE_FD_PLACEHOLDER: &str = "@agentfw-owner-private-lease@";
pub(crate) const FORMAT: &str = "sw-mcp/linux-crash-owner/1";
#[cfg(target_os = "linux")]
pub(crate) const STARTUP_MILLIS: u64 = 3_000;
#[cfg(target_os = "linux")]
pub(crate) const POLL_MILLIS: u64 = 25;
#[cfg(target_os = "linux")]
pub(crate) const CLEANUP_MILLIS: u64 = 3_000;
#[cfg(target_os = "linux")]
pub(crate) const HEARTBEAT_MILLIS: u64 = 100;
#[cfg(target_os = "linux")]
pub(crate) const LEASE_MILLIS: u64 = 1_500;

#[cfg(target_os = "linux")]
pub(crate) use linux::{spawn, BudgetPrepare, CleanupSpec, LaunchSpec, OwnerGuard};

#[cfg(not(target_os = "linux"))]
pub(crate) struct OwnerGuard;

#[cfg(not(target_os = "linux"))]
impl OwnerGuard {
    pub(crate) fn failed(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true))
    }
    pub(crate) fn check(&self) -> anyhow::Result<()> {
        anyhow::bail!("mcp_owner_platform_unsupported")
    }
    pub(crate) async fn wait_failure(&self) -> anyhow::Result<()> {
        self.check()
    }
    pub(crate) async fn finish(&mut self) -> anyhow::Result<()> {
        self.check()
    }
    pub(crate) async fn quiesce(&self) -> anyhow::Result<()> {
        self.check()
    }
    pub(crate) fn metadata(&self) -> serde_json::Value {
        serde_json::json!({"format":FORMAT,"reason":"mcp_owner_platform_unsupported"})
    }
}

/// Dispatch the private, descriptor-authenticated helpers before building Tokio.
/// These entry points provide no authority without the inherited private socket.
#[doc(hidden)]
pub fn early_dispatch() -> Option<i32> {
    #[cfg(target_os = "linux")]
    {
        linux::early_dispatch()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::os::unix::process::CommandExt;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use anyhow::{bail, ensure, Context};
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use tokio::io::AsyncWriteExt;
    use tokio::process::Child;

    use super::{
        CLEANUP_MILLIS, FORMAT, HEARTBEAT_MILLIS, LEASE_FD_PLACEHOLDER, LEASE_MILLIS, POLL_MILLIS,
        STARTUP_MILLIS,
    };

    const OWNER_ARG: &str = "--agentfw-mcp-owner-v1";
    const PID1_ARG: &str = "--agentfw-mcp-pid1-v1";
    const MAX_PACKET: usize = 65_536;
    const MAX_ARGS: usize = 2_048;
    const MAX_FDS: usize = 128;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct BudgetPrepare {
        pub config: super::super::linux_budget::Config,
        pub root: (u64, u64),
        pub root_fd: RawFd,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BudgetPrepared {
        format: String,
        instance: String,
        budget: super::super::linux_budget::PreparedBudget,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct CleanupSpec {
        pub root_fd: RawFd,
        pub leaf_fd: RawFd,
        pub kill_fd: RawFd,
        pub procs_fd: RawFd,
        pub events_fd: RawFd,
        pub name: String,
        pub device: u64,
        pub inode: u64,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct LaunchSpec {
        pub bwrap_fd: RawFd,
        pub owner_executable_fd: RawFd,
        pub inherited_fds: Vec<RawFd>,
        pub bwrap_args: Vec<String>,
        pub budget_attach_fd: Option<RawFd>,
        pub budget_cleanup: Option<CleanupSpec>,
        pub budget_prepare: Option<BudgetPrepare>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Startup {
        launch: LaunchSpec,
        collector_pid: u32,
        collector_start_ticks: u64,
        collector_pidfd: RawFd,
        budget_transfer_fd: Option<RawFd>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ready {
        format: String,
        instance: String,
        owner_pid: u32,
        owner_start_ticks: u64,
        sandbox_pid: u32,
        sandbox_start_ticks: u64,
        pid1_pid: u32,
        pid1_start_ticks: u64,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CleanupReport {
        format: String,
        instance: String,
        process_reaped: bool,
        namespace_terminated: bool,
        owned_resources_removed: bool,
        runtime_failure: bool,
        reason: String,
        #[serde(default)]
        sandbox_exit: Option<SandboxExit>,
    }

    /// Fixed status from the owned wrapper, observed before cleanup can kill it.
    /// This does not identify the original server's exception or attest effects.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SandboxExit {
        code: Option<u8>,
        signal: Option<u8>,
        before_quiesce: bool,
    }

    impl SandboxExit {
        fn valid(&self) -> bool {
            self.code.is_some() != self.signal.is_some()
                && self.signal.is_none_or(|signal| (1..=64).contains(&signal))
        }
        fn observed(status: std::process::ExitStatus, expected: bool) -> Self {
            Self {
                code: status.code().and_then(|code| u8::try_from(code).ok()),
                signal: status.signal().and_then(|signal| u8::try_from(signal).ok()),
                before_quiesce: !expected,
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Heartbeat {
        format: String,
        instance: String,
        deadline_millis: u64,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RuntimeFailure {
        format: String,
        instance: String,
        reason: String,
        #[serde(default)]
        sandbox_exit: Option<SandboxExit>,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OwnerEvent {
        Cleanup(CleanupReport),
        Heartbeat(Heartbeat),
        Failure(RuntimeFailure),
        Control(Control),
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Control {
        format: String,
        instance: String,
        action: String,
    }

    struct ParentState {
        reason: &'static str,
        report: Option<CleanupReport>,
        finishing: bool,
        quiesced: bool,
        sandbox_exit: Option<SandboxExit>,
    }

    pub(crate) struct OwnerProcess {
        pub child: Child,
        pub sandbox_pid: u32,
        pub guard: OwnerGuard,
        pub budget: Option<super::super::linux_budget::OwnedBudget>,
    }

    pub(crate) struct OwnerGuard {
        ready: Ready,
        failed: Arc<AtomicBool>,
        complete: Arc<AtomicBool>,
        state: Arc<Mutex<ParentState>>,
        changed: Arc<tokio::sync::Notify>,
        writer: tokio::sync::Mutex<tokio::net::UnixStream>,
        monitor: Option<tokio::task::JoinHandle<()>>,
    }

    fn failure(code: &'static str) -> anyhow::Error {
        anyhow::anyhow!(code)
    }

    fn failure_code(value: &str) -> Option<&'static str> {
        match value {
            "mcp_owner_sandbox_failed" => Some("mcp_owner_sandbox_failed"),
            "mcp_owner_namespace_lost" => Some("mcp_owner_namespace_lost"),
            "mcp_owner_control_failed" => Some("mcp_owner_control_failed"),
            "mcp_owner_control_invalid" => Some("mcp_owner_control_invalid"),
            "mcp_owner_control_closed" => Some("mcp_owner_control_closed"),
            "mcp_owner_parent_lost" => Some("mcp_owner_parent_lost"),
            "mcp_owner_startup_failed" => Some("mcp_owner_startup_failed"),
            _ => None,
        }
    }

    fn encode<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
        let packet = serde_json::to_vec(value)?;
        ensure!(packet.len() <= MAX_PACKET, "mcp_owner_control_oversized");
        let mut frame = Vec::with_capacity(packet.len() + 4);
        frame.extend_from_slice(&(packet.len() as u32).to_be_bytes());
        frame.extend_from_slice(&packet);
        Ok(frame)
    }

    fn decode<T: for<'a> Deserialize<'a>>(packet: &[u8]) -> anyhow::Result<T> {
        serde_json::from_slice(packet).context("mcp_owner_control_invalid")
    }

    fn receive<T: for<'a> Deserialize<'a>>(stream: &mut UnixStream) -> anyhow::Result<T> {
        let mut length = [0_u8; 4];
        stream
            .read_exact(&mut length)
            .context("mcp_owner_control_closed")?;
        let length = u32::from_be_bytes(length) as usize;
        ensure!(
            length > 0 && length <= MAX_PACKET,
            "mcp_owner_control_invalid"
        );
        let mut packet = vec![0; length];
        stream
            .read_exact(&mut packet)
            .context("mcp_owner_control_closed")?;
        decode(&packet)
    }

    fn send<T: Serialize>(stream: &mut UnixStream, value: &T) -> anyhow::Result<()> {
        // UnixStream::write may issue sendto(MSG_NOSIGNAL), intentionally denied
        // by the filesystem profile. This private inherited socket needs only
        // ordinary write; keep the established network filter unchanged.
        let bytes = encode(value)?;
        let mut offset = 0;
        while offset < bytes.len() {
            let count = unsafe {
                libc::write(
                    stream.as_raw_fd(),
                    bytes[offset..].as_ptr().cast(),
                    bytes.len() - offset,
                )
            };
            if count < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            ensure!(count > 0, "mcp_owner_control_closed");
            offset += count as usize;
        }
        Ok(())
    }

    fn send_budget_fds(
        socket: &UnixDatagram,
        prepared: &BudgetPrepared,
        files: &[File],
    ) -> anyhow::Result<()> {
        ensure!(
            files.len() == super::super::linux_budget::PREPARED_FDS,
            "mcp_owner_budget_packet_invalid"
        );
        send_descriptor_packet(socket, serde_json::to_vec(prepared)?, files)
    }

    fn send_descriptor_packet(
        socket: &UnixDatagram,
        mut bytes: Vec<u8>,
        files: &[File],
    ) -> anyhow::Result<()> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_PACKET && files.len() <= MAX_FDS,
            "mcp_owner_budget_packet_invalid"
        );
        let descriptors: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();
        let descriptor_bytes = std::mem::size_of_val(descriptors.as_slice());
        let control_size = unsafe { libc::CMSG_SPACE(descriptor_bytes as u32) } as usize;
        // usize storage supplies cmsghdr alignment; byte arrays do not.
        let mut control = vec![0_usize; control_size.div_ceil(std::mem::size_of::<usize>())];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control_size;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            ensure!(!header.is_null(), "mcp_owner_budget_packet_invalid");
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(descriptor_bytes as u32) as usize;
            std::ptr::copy_nonoverlapping(
                descriptors.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                descriptor_bytes,
            );
        }
        let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
        ensure!(
            sent == bytes.len() as isize,
            "mcp_owner_budget_transfer_failed"
        );
        Ok(())
    }

    fn receive_budget_fds(socket: &UnixDatagram) -> std::io::Result<(BudgetPrepared, Vec<File>)> {
        let invalid = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mcp_owner_budget_packet_invalid",
            )
        };
        let mut bytes = vec![0_u8; MAX_PACKET];
        let descriptor_bytes =
            super::super::linux_budget::PREPARED_FDS * std::mem::size_of::<RawFd>();
        let control_size = unsafe { libc::CMSG_SPACE(descriptor_bytes as u32) } as usize;
        let mut control = vec![0_usize; control_size.div_ceil(std::mem::size_of::<usize>())];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control_size;
        let count =
            unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if count < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut files = Vec::new();
        let mut valid_headers = 0;
        let mut headers_valid = true;
        // Take ownership of every delivered SCM_RIGHTS handle before checking
        // framing, so rejection/truncation cannot leak received descriptors.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                let minimum = libc::CMSG_LEN(0) as usize;
                let offset = header
                    .cast::<u8>()
                    .offset_from(message.msg_control.cast::<u8>());
                if offset < 0
                    || (*header).cmsg_len < minimum
                    || (*header).cmsg_len > message.msg_controllen.saturating_sub(offset as usize)
                {
                    headers_valid = false;
                    break;
                }
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    valid_headers += 1;
                    let length = (*header).cmsg_len - minimum;
                    headers_valid &= length.is_multiple_of(std::mem::size_of::<RawFd>());
                    for index in 0..length / std::mem::size_of::<RawFd>() {
                        let descriptor = std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                        );
                        if descriptor < 0 {
                            headers_valid = false;
                        } else {
                            files.push(File::from_raw_fd(descriptor));
                        }
                    }
                } else {
                    headers_valid = false;
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        if count == 0
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || !headers_valid
            || valid_headers != 1
            || files.len() != super::super::linux_budget::PREPARED_FDS
        {
            return Err(invalid());
        }
        let prepared = serde_json::from_slice(&bytes[..count as usize]).map_err(|_| invalid())?;
        Ok((prepared, files))
    }

    async fn adopt_budget(
        socket: UnixDatagram,
        requested: &BudgetPrepare,
    ) -> anyhow::Result<(super::super::linux_budget::OwnedBudget, String)> {
        socket.set_nonblocking(true)?;
        // SAFETY: socket is uniquely owned by adopt_budget and not shared or concurrently closed.
        let socket = unsafe { tokio::io::unix::AsyncFd::register(socket) }?;
        let (prepared, files) = loop {
            let mut readable = socket.readable().await?;
            match readable.try_io(|socket| receive_budget_fds(socket.get_ref())) {
                Ok(result) => break result?,
                Err(_) => continue,
            }
        };
        ensure!(
            prepared.format == FORMAT
                && prepared.instance.len() == 32
                && prepared
                    .instance
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "mcp_owner_budget_packet_invalid"
        );
        #[cfg(test)]
        budget_adoption_barrier(&prepared.budget)?;
        let budget = super::super::linux_budget::OwnedBudget::adopt_prepared(
            &super::super::linux_budget::BoundConfig {
                config: requested.config.clone(),
                root: requested.root,
            },
            &prepared.budget,
            files,
        )?;
        let acknowledgement = serde_json::to_vec(&Control {
            format: FORMAT.to_owned(),
            instance: prepared.instance.clone(),
            action: "budget-adopted".to_owned(),
        })?;
        loop {
            let mut writable = socket.writable().await?;
            match writable.try_io(|socket| socket.get_ref().send(&acknowledgement)) {
                Ok(result) => {
                    ensure!(
                        result? == acknowledgement.len(),
                        "mcp_owner_budget_transfer_failed"
                    );
                    break;
                }
                Err(_) => continue,
            }
        }
        Ok((budget, prepared.instance))
    }

    fn await_budget_adoption(
        transfer: &UnixDatagram,
        collector: &File,
        instance: &str,
    ) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_millis(STARTUP_MILLIS);
        loop {
            ensure!(!readable(collector.as_raw_fd())?, "mcp_owner_parent_lost");
            ensure!(
                Instant::now() < deadline,
                "mcp_owner_budget_adoption_unverified"
            );
            let mut descriptors = [
                libc::pollfd {
                    fd: transfer.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: collector.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let result = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    POLL_MILLIS as i32,
                )
            };
            if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            ensure!(result >= 0, "mcp_owner_budget_adoption_unverified");
            if descriptors[0].revents & libc::POLLIN != 0 {
                let mut bytes = [0_u8; 1024];
                let count = unsafe {
                    libc::recv(
                        transfer.as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        libc::MSG_TRUNC,
                    )
                };
                ensure!(
                    count > 0 && count as usize <= bytes.len(),
                    "mcp_owner_budget_adoption_unverified"
                );
                let adopted: Control = decode(&bytes[..count as usize])?;
                ensure!(
                    adopted.format == FORMAT
                        && adopted.instance == instance
                        && adopted.action == "budget-adopted",
                    "mcp_owner_budget_adoption_unverified"
                );
                ensure!(!readable(collector.as_raw_fd())?, "mcp_owner_parent_lost");
                return Ok(());
            }
        }
    }

    #[cfg(test)]
    fn budget_adoption_barrier(
        prepared: &super::super::linux_budget::PreparedBudget,
    ) -> anyhow::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let Some(path) = std::env::var_os("SOU142_TEST_HANDOFF_BARRIER") else {
            return Ok(());
        };
        let path = std::path::PathBuf::from(path);
        let staged = path.with_extension("staged");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&staged)?;
        file.write_all(&serde_json::to_vec(prepared)?)?;
        file.sync_all()?;
        std::fs::rename(staged, &path)?;
        // This test-only barrier pauses the collector after the real owner has
        // created its leaf, before adoption ACK can release a sandbox process.
        let deadline = Instant::now() + Duration::from_secs(30);
        while !path.with_extension("cancel").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        bail!("mcp_owner_test_handoff_cancelled")
    }

    fn nonblocking(fd: RawFd) -> anyhow::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        ensure!(
            flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
            "mcp_owner_descriptor_invalid"
        );
        Ok(())
    }

    fn process_ticks(pid: u32) -> anyhow::Result<u64> {
        let value = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .context("mcp_owner_process_identity_unavailable")?;
        let (_, tail) = value
            .rsplit_once(')')
            .context("mcp_owner_process_identity_invalid")?;
        tail.split_whitespace()
            .nth(19)
            .context("mcp_owner_process_identity_invalid")?
            .parse()
            .context("mcp_owner_process_identity_invalid")
    }

    fn pidfd(pid: u32) -> anyhow::Result<File> {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        ensure!(raw >= 0, "mcp_owner_pidfd_unavailable");
        Ok(unsafe { File::from_raw_fd(raw as RawFd) })
    }

    fn readable(fd: RawFd) -> anyhow::Result<bool> {
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        ensure!(result >= 0, "mcp_owner_liveness_unverified");
        Ok(result > 0)
    }

    fn monotonic_millis() -> anyhow::Result<u64> {
        let mut now = std::mem::MaybeUninit::<libc::timespec>::uninit();
        ensure!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, now.as_mut_ptr()) } == 0,
            "mcp_owner_liveness_unverified"
        );
        let now = unsafe { now.assume_init() };
        let seconds = u64::try_from(now.tv_sec).context("mcp_owner_liveness_unverified")?;
        let nanos = u64::try_from(now.tv_nsec).context("mcp_owner_liveness_unverified")?;
        seconds
            .checked_mul(1_000)
            .and_then(|millis| millis.checked_add(nanos / 1_000_000))
            .context("mcp_owner_liveness_unverified")
    }

    fn set_cloexec(fd: RawFd, value: bool) -> anyhow::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        ensure!(flags >= 0, "mcp_owner_descriptor_invalid");
        let flags = if value {
            flags | libc::FD_CLOEXEC
        } else {
            flags & !libc::FD_CLOEXEC
        };
        ensure!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } == 0,
            "mcp_owner_descriptor_invalid"
        );
        Ok(())
    }

    fn sealed_startup(startup: &Startup) -> anyhow::Result<File> {
        let name = CString::new("agentfw-mcp-owner-launch").expect("literal name");
        let raw = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        ensure!(raw >= 0, "mcp_owner_launch_unavailable");
        let mut file = unsafe { File::from_raw_fd(raw) };
        let packet = serde_json::to_vec(startup)?;
        ensure!(packet.len() <= MAX_PACKET, "mcp_owner_launch_invalid");
        file.write_all(&packet)?;
        ensure!(
            unsafe {
                libc::fcntl(
                    raw,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_SEAL
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_WRITE,
                )
            } == 0,
            "mcp_owner_launch_unavailable"
        );
        Ok(file)
    }

    fn read_startup(fd: RawFd) -> anyhow::Result<Startup> {
        ensure!(fd >= 3, "mcp_owner_launch_invalid");
        set_cloexec(fd, true)?;
        let expected =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        ensure!(
            unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } == expected,
            "mcp_owner_launch_invalid"
        );
        let bytes = pinned_text(fd)?;
        decode(bytes.as_bytes())
    }

    fn validate(spec: &LaunchSpec) -> anyhow::Result<()> {
        ensure!(
            spec.bwrap_args.len() <= MAX_ARGS && !spec.bwrap_args.is_empty(),
            "mcp_owner_launch_invalid"
        );
        ensure!(
            spec.bwrap_args.iter().map(String::len).sum::<usize>() <= MAX_PACKET / 2,
            "mcp_owner_launch_invalid"
        );
        ensure!(
            spec.inherited_fds.len() <= MAX_FDS,
            "mcp_owner_launch_invalid"
        );
        let fds: BTreeSet<_> = spec.inherited_fds.iter().copied().collect();
        ensure!(
            fds.len() == spec.inherited_fds.len() && fds.iter().all(|fd| *fd >= 3),
            "mcp_owner_launch_invalid"
        );
        ensure!(fds.contains(&spec.bwrap_fd), "mcp_owner_launch_invalid");
        ensure!(
            fds.contains(&spec.owner_executable_fd),
            "mcp_owner_launch_invalid"
        );
        ensure!(
            spec.bwrap_args.iter().any(|arg| arg == "--as-pid-1")
                && spec.bwrap_args.iter().any(|arg| arg == "--die-with-parent")
                && spec
                    .bwrap_args
                    .iter()
                    .filter(|arg| arg.as_str() == LEASE_FD_PLACEHOLDER)
                    .count()
                    == 2,
            "mcp_owner_launch_invalid"
        );
        if let Some(fd) = spec.budget_attach_fd {
            ensure!(fds.contains(&fd), "mcp_owner_launch_invalid");
        }
        if let Some(requested) = &spec.budget_prepare {
            ensure!(
                spec.budget_attach_fd.is_none()
                    && spec.budget_cleanup.is_none()
                    && fds.contains(&requested.root_fd),
                "mcp_owner_budget_request_invalid"
            );
        }
        if let Some(cleanup) = &spec.budget_cleanup {
            ensure!(
                cleanup.name.starts_with("agentfw-mcp-")
                    && cleanup.name.len() == 44
                    && cleanup.name[12..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit()),
                "mcp_owner_cleanup_identity_invalid"
            );
            ensure!(
                [
                    cleanup.root_fd,
                    cleanup.leaf_fd,
                    cleanup.kill_fd,
                    cleanup.procs_fd,
                    cleanup.events_fd
                ]
                .iter()
                .all(|fd| fds.contains(fd)),
                "mcp_owner_launch_invalid"
            );
        }
        for fd in fds {
            set_cloexec(fd, true)?;
        }
        Ok(())
    }

    pub(crate) async fn spawn(spec: LaunchSpec) -> anyhow::Result<OwnerProcess> {
        validate(&spec)?;
        let (parent, child_control) =
            UnixStream::pair().context("mcp_owner_control_unavailable")?;
        parent.set_nonblocking(true)?;
        let control_fd = child_control.as_raw_fd();
        let (mut budget_parent, budget_child) = if spec.budget_prepare.is_some() {
            let (parent, child) = UnixDatagram::pair()?;
            (Some(parent), Some(child))
        } else {
            (None, None)
        };
        let collector = pidfd(std::process::id())?;
        let startup = sealed_startup(&Startup {
            launch: spec.clone(),
            collector_pid: std::process::id(),
            collector_start_ticks: process_ticks(std::process::id())?,
            collector_pidfd: collector.as_raw_fd(),
            budget_transfer_fd: budget_child.as_ref().map(AsRawFd::as_raw_fd),
        })?;
        let startup_fd = startup.as_raw_fd();
        let mut command =
            tokio::process::Command::new(format!("/proc/self/fd/{}", spec.owner_executable_fd));
        command
            .arg(OWNER_ARG)
            .arg(control_fd.to_string())
            .arg(startup_fd.to_string())
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false)
            .process_group(0);
        let mut fds = spec.inherited_fds.clone();
        fds.push(control_fd);
        fds.push(startup_fd);
        fds.push(collector.as_raw_fd());
        fds.extend(budget_child.as_ref().map(AsRawFd::as_raw_fd));
        unsafe {
            command.pre_exec(move || {
                if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for fd in &fds {
                    if libc::fcntl(*fd, libc::F_SETFD, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = command.spawn().context("mcp_owner_spawn_failed")?;
        drop(child_control);
        drop(budget_child);
        let mut prepared_budget = None;
        let started = async {
            let budget_instance = if let Some(requested) = &spec.budget_prepare {
                let (budget, instance) = adopt_budget(
                    budget_parent
                        .take()
                        .context("mcp_owner_budget_transfer_failed")?,
                    requested,
                )
                .await?;
                prepared_budget = Some(budget);
                Some(instance)
            } else {
                None
            };
            let stream = tokio::net::UnixStream::from_std(parent.try_clone()?)?;
            let mut reader = stream;
            use tokio::io::AsyncReadExt;
            let length = reader.read_u32().await? as usize;
            ensure!(
                length > 0 && length <= MAX_PACKET,
                "mcp_owner_control_invalid"
            );
            let mut packet = vec![0; length];
            reader.read_exact(&mut packet).await?;
            let ready: Ready = decode(&packet)?;
            ensure!(
                ready.format == FORMAT
                    && budget_instance
                        .as_ref()
                        .is_none_or(|instance| *instance == ready.instance)
                    && Some(ready.owner_pid) == child.id()
                    && process_ticks(ready.owner_pid)? == ready.owner_start_ticks
                    && process_ticks(ready.sandbox_pid)? == ready.sandbox_start_ticks
                    && process_ticks(ready.pid1_pid)? == ready.pid1_start_ticks,
                "mcp_owner_startup_identity_invalid"
            );
            let owner_pidfd = pidfd(ready.owner_pid)?;
            Ok::<_, anyhow::Error>((reader, ready, owner_pidfd))
        };
        let (reader, ready, owner_pidfd) =
            match tokio::time::timeout(Duration::from_millis(STARTUP_MILLIS), started).await {
                Ok(Ok(value)) => value,
                _ => {
                    // EOF is the owner's unconditional cleanup request. Do not kill
                    // it before it can verify its own resources.
                    let _ = parent.shutdown(std::net::Shutdown::Both);
                    let _ = tokio::time::timeout(
                        Duration::from_millis(CLEANUP_MILLIS + 500),
                        child.wait(),
                    )
                    .await;
                    let _ = child.start_kill();
                    let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
                    bail!("mcp_owner_startup_failed");
                }
            };
        let writer = tokio::net::UnixStream::from_std(parent)?;
        let failed = Arc::new(AtomicBool::new(false));
        let complete = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(ParentState {
            reason: "mcp_owner_active",
            report: None,
            finishing: false,
            quiesced: false,
            sandbox_exit: None,
        }));
        let changed = Arc::new(tokio::sync::Notify::new());
        let monitor = tokio::spawn(parent_monitor(
            reader,
            owner_pidfd,
            ready.instance.clone(),
            Arc::clone(&failed),
            Arc::clone(&complete),
            Arc::clone(&state),
            Arc::clone(&changed),
        ));
        Ok(OwnerProcess {
            sandbox_pid: ready.sandbox_pid,
            child,
            budget: prepared_budget,
            guard: OwnerGuard {
                ready,
                failed,
                complete,
                state,
                changed,
                writer: tokio::sync::Mutex::new(writer),
                monitor: Some(monitor),
            },
        })
    }

    async fn parent_monitor(
        stream: tokio::net::UnixStream,
        owner_pidfd: File,
        instance: String,
        failed: Arc<AtomicBool>,
        complete: Arc<AtomicBool>,
        state: Arc<Mutex<ParentState>>,
        changed: Arc<tokio::sync::Notify>,
    ) {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut interval = tokio::time::interval(Duration::from_millis(POLL_MILLIS));
        let mut lease_deadline = monotonic_millis().unwrap_or(0).saturating_add(LEASE_MILLIS);
        let reason = 'monitor: loop {
            tokio::select! {
                _ = interval.tick() => {
                    if readable(owner_pidfd.as_raw_fd()).unwrap_or(true) {
                        // Drain a completed ack before treating exit as loss.
                        match stream.try_read(&mut buffer) {
                            Ok(count) if count > 0 => bytes.extend_from_slice(&buffer[..count]),
                            _ => break "mcp_owner_lost",
                        }
                    } else if monotonic_millis().unwrap_or(u64::MAX) >= lease_deadline
                        && !state.lock().unwrap_or_else(|error| error.into_inner()).finishing {
                        match stream.try_read(&mut buffer) {
                            Ok(count) if count > 0 => bytes.extend_from_slice(&buffer[..count]),
                            _ => break "mcp_owner_liveness_expired",
                        }
                    }
                }
                ready = stream.readable() => {
                    if ready.is_err() { break "mcp_owner_control_failed"; }
                    match stream.try_read(&mut buffer) {
                        Ok(0) => break "mcp_owner_lost",
                        Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(_) => break "mcp_owner_control_failed",
                    }
                }
            }
            if bytes.len() > MAX_PACKET + 4 {
                break "mcp_owner_control_invalid";
            }
            while bytes.len() >= 4 {
                let length =
                    u32::from_be_bytes(bytes[..4].try_into().expect("four bytes")) as usize;
                if length == 0 || length > MAX_PACKET {
                    break 'monitor "mcp_owner_control_invalid";
                }
                if bytes.len() >= length + 4 {
                    let event = decode::<OwnerEvent>(&bytes[4..length + 4]);
                    bytes.drain(..length + 4);
                    match event {
                        Ok(OwnerEvent::Cleanup(report))
                            if report.format == FORMAT
                                && report.instance == instance
                                && report.sandbox_exit.as_ref().is_none_or(SandboxExit::valid) =>
                        {
                            let success = report.process_reaped
                                && report.namespace_terminated
                                && report.owned_resources_removed;
                            let mut value = state.lock().unwrap_or_else(|error| error.into_inner());
                            if !failed.load(Ordering::Acquire) {
                                value.reason = if report.runtime_failure {
                                    failure_code(&report.reason)
                                        .unwrap_or("mcp_owner_control_invalid")
                                } else if success {
                                    "mcp_owner_cleanup_verified"
                                } else {
                                    "mcp_owner_cleanup_unverified"
                                };
                            }
                            let runtime_failure = report.runtime_failure;
                            if value.sandbox_exit.is_none() {
                                value.sandbox_exit = report.sandbox_exit.clone();
                            }
                            value.report = Some(report);
                            complete.store(true, Ordering::Release);
                            if !success || runtime_failure {
                                failed.store(true, Ordering::Release);
                            }
                            drop(value);
                            changed.notify_waiters();
                            return;
                        }
                        Ok(OwnerEvent::Heartbeat(heartbeat))
                            if heartbeat.format == FORMAT && heartbeat.instance == instance =>
                        {
                            let now = monotonic_millis().unwrap_or(u64::MAX);
                            if heartbeat.deadline_millis > now.saturating_add(LEASE_MILLIS) {
                                break 'monitor "mcp_owner_control_invalid";
                            }
                            lease_deadline = lease_deadline.max(heartbeat.deadline_millis);
                        }
                        Ok(OwnerEvent::Failure(event))
                            if event.format == FORMAT
                                && event.instance == instance
                                && event.sandbox_exit.as_ref().is_none_or(SandboxExit::valid) =>
                        {
                            let Some(reason) = failure_code(&event.reason) else {
                                break 'monitor "mcp_owner_control_invalid";
                            };
                            let mut value = state.lock().unwrap_or_else(|error| error.into_inner());
                            if !failed.load(Ordering::Acquire) {
                                value.reason = reason;
                            }
                            if value.sandbox_exit.is_none() {
                                value.sandbox_exit = event.sandbox_exit;
                            }
                            failed.store(true, Ordering::Release);
                            drop(value);
                            changed.notify_waiters();
                        }
                        Ok(OwnerEvent::Control(event))
                            if event.format == FORMAT
                                && event.instance == instance
                                && event.action == "quiesced" =>
                        {
                            state
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .quiesced = true;
                            changed.notify_waiters();
                        }
                        _ => break 'monitor "mcp_owner_control_invalid",
                    }
                } else {
                    break;
                }
            }
            if monotonic_millis().unwrap_or(u64::MAX) >= lease_deadline
                && !state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .finishing
            {
                break "mcp_owner_liveness_expired";
            }
        };
        let mut value = state.lock().unwrap_or_else(|error| error.into_inner());
        if !failed.load(Ordering::Acquire) {
            value.reason = reason;
        }
        failed.store(true, Ordering::Release);
        drop(value);
        changed.notify_waiters();
    }

    impl OwnerGuard {
        pub(crate) fn failed(&self) -> Arc<AtomicBool> {
            Arc::clone(&self.failed)
        }
        pub(crate) fn check(&self) -> anyhow::Result<()> {
            if self.failed.load(Ordering::Acquire) {
                return Err(failure(
                    self.state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .reason,
                ));
            }
            Ok(())
        }
        pub(crate) async fn wait_failure(&self) -> anyhow::Result<()> {
            loop {
                let notified = self.changed.notified();
                self.check()?;
                if self.complete.load(Ordering::Acquire) {
                    return Err(failure("mcp_owner_monitor_stopped"));
                }
                notified.await;
            }
        }
        pub(crate) async fn quiesce(&self) -> anyhow::Result<()> {
            let command = Control {
                format: FORMAT.to_owned(),
                instance: self.ready.instance.clone(),
                action: "quiesce".to_owned(),
            };
            tokio::time::timeout(Duration::from_millis(500), async {
                self.writer
                    .lock()
                    .await
                    .write_all(&encode(&command)?)
                    .await?;
                loop {
                    let notified = self.changed.notified();
                    if self
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .quiesced
                    {
                        break;
                    }
                    self.check()?;
                    notified.await;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .map_err(|_| failure("mcp_owner_control_failed"))??;
            Ok(())
        }
        pub(crate) async fn finish(&mut self) -> anyhow::Result<()> {
            if !self.complete.load(Ordering::Acquire) {
                self.state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .finishing = true;
                let command = Control {
                    format: FORMAT.to_owned(),
                    instance: self.ready.instance.clone(),
                    action: "stop".to_owned(),
                };
                let result =
                    tokio::time::timeout(Duration::from_millis(CLEANUP_MILLIS + 500), async {
                        self.writer
                            .lock()
                            .await
                            .write_all(&encode(&command)?)
                            .await?;
                        loop {
                            let notified = self.changed.notified();
                            if self.complete.load(Ordering::Acquire) {
                                break;
                            }
                            notified.await;
                        }
                        Ok::<_, anyhow::Error>(())
                    })
                    .await;
                if !matches!(result, Ok(Ok(()))) {
                    return Err(failure("mcp_owner_cleanup_unverified"));
                }
            }
            ensure!(
                self.complete.load(Ordering::Acquire),
                "mcp_owner_cleanup_unverified"
            );
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            ensure!(
                state
                    .report
                    .as_ref()
                    .is_some_and(|report| report.process_reaped
                        && report.namespace_terminated
                        && report.owned_resources_removed),
                "mcp_owner_cleanup_unverified"
            );
            Ok(())
        }
        pub(crate) fn metadata(&self) -> Value {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            json!({"format":FORMAT,"instance":self.ready.instance,
                "owner_pid":self.ready.owner_pid,"owner_start_ticks":self.ready.owner_start_ticks,
                "sandbox_pid":self.ready.sandbox_pid,"sandbox_start_ticks":self.ready.sandbox_start_ticks,
                "pid1_pid":self.ready.pid1_pid,"pid1_start_ticks":self.ready.pid1_start_ticks,
                "startup_bound_ms":STARTUP_MILLIS,"poll_ms":POLL_MILLIS,"cleanup_bound_ms":CLEANUP_MILLIS,
                "heartbeat_ms":HEARTBEAT_MILLIS,"lease_ms":LEASE_MILLIS,
                "reason":state.reason,"sandbox_exit":state.sandbox_exit,
                "failed":self.failed.load(Ordering::Acquire),"cleanup":state.report})
        }
    }

    impl Drop for OwnerGuard {
        fn drop(&mut self) {
            if let Some(monitor) = self.monitor.take() {
                monitor.abort();
            }
            // Closing every collector endpoint is itself an authenticated stop.
            // shutdown affects the duplicated reader endpoint immediately too.
            if let Ok(stream) = self.writer.try_lock() {
                unsafe {
                    libc::shutdown(stream.as_raw_fd(), libc::SHUT_RDWR);
                }
            }
        }
    }

    fn inherited_socket(fd: RawFd) -> anyhow::Result<UnixStream> {
        ensure!(fd >= 3, "mcp_owner_descriptor_invalid");
        let mut kind = 0;
        let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
        ensure!(
            unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    (&mut kind as *mut libc::c_int).cast(),
                    &mut length,
                )
            } == 0
                && kind == libc::SOCK_STREAM,
            "mcp_owner_descriptor_invalid"
        );
        set_cloexec(fd, true)?;
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        stream.set_read_timeout(Some(Duration::from_millis(STARTUP_MILLIS)))?;
        stream.set_write_timeout(Some(Duration::from_millis(STARTUP_MILLIS)))?;
        Ok(stream)
    }

    pub(super) fn early_dispatch() -> Option<i32> {
        let args: Vec<_> = std::env::args_os().collect();
        let kind = args.get(1)?.to_str()?;
        if kind != OWNER_ARG && kind != PID1_ARG {
            return None;
        }
        // Raw writes are required under the unchanged filesystem seccomp
        // filter. A vanished private peer is an error, never a fatal SIGPIPE.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }
        let result = (|| {
            let fd = args
                .get(2)
                .and_then(|value| value.to_str())
                .and_then(|value| value.parse::<RawFd>().ok())
                .context("mcp_owner_descriptor_invalid")?;
            if kind == OWNER_ARG {
                ensure!(args.len() == 4, "mcp_owner_launch_invalid");
                let startup_fd = args[3]
                    .to_str()
                    .and_then(|value| value.parse::<RawFd>().ok())
                    .context("mcp_owner_launch_invalid")?;
                owner(inherited_socket(fd)?, read_startup(startup_fd)?)
            } else {
                ensure!(
                    args.get(3).is_some_and(|arg| arg == "--") && args.len() >= 5,
                    "mcp_owner_launch_invalid"
                );
                let command = args[4..].to_vec();
                namespace_pid1(inherited_socket(fd)?, &command)
            }
        })();
        Some(if result.is_ok() { 0 } else { 1 })
    }

    fn peer(stream: &UnixStream) -> anyhow::Result<u32> {
        let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        ensure!(
            unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    credentials.as_mut_ptr().cast(),
                    &mut length,
                )
            } == 0,
            "mcp_owner_parent_identity_invalid"
        );
        let credentials = unsafe { credentials.assume_init() };
        ensure!(
            credentials.uid == unsafe { libc::geteuid() } && credentials.pid > 0,
            "mcp_owner_parent_identity_invalid"
        );
        Ok(credentials.pid as u32)
    }

    fn close_stdio() {
        for fd in 0..=2 {
            unsafe {
                libc::close(fd);
            }
        }
    }

    struct LeafFallback {
        spec: Option<CleanupSpec>,
        _pins: Vec<File>,
        armed: bool,
    }

    impl Drop for LeafFallback {
        fn drop(&mut self) {
            if self.armed {
                // Covers every ordinary early return after a private, validated
                // capsule was received, including collector death mid-startup.
                // SIGKILL still relies on the surviving collector/PID 1 path.
                let _ = cleanup_leaf(self.spec.as_ref());
            }
        }
    }

    fn observe_wrapper_exit(
        child: &mut std::process::Child,
        control: &mut UnixStream,
        instance: &str,
        expected: bool,
        first_exit: &mut Option<SandboxExit>,
    ) -> anyhow::Result<Option<bool>> {
        let Some(status) = child.try_wait()? else {
            return Ok(None);
        };
        let failed = !status.success() && !expected;
        first_exit.get_or_insert_with(|| SandboxExit::observed(status, expected));
        if failed {
            send(
                control,
                &RuntimeFailure {
                    format: FORMAT.to_owned(),
                    instance: instance.to_owned(),
                    reason: "mcp_owner_sandbox_failed".to_owned(),
                    sandbox_exit: first_exit.clone(),
                },
            )?;
        }
        close_stdio();
        Ok(Some(failed))
    }

    fn owner(mut control: UnixStream, startup: Startup) -> anyhow::Result<()> {
        let collector_pid = peer(&control)?;
        ensure!(
            collector_pid == startup.collector_pid,
            "mcp_owner_parent_identity_invalid"
        );
        ensure!(
            startup.collector_pidfd >= 3,
            "mcp_owner_parent_identity_invalid"
        );
        set_cloexec(startup.collector_pidfd, true)?;
        let collector = unsafe { File::from_raw_fd(startup.collector_pidfd) };
        let mut spec = startup.launch;
        validate(&spec)?;
        let mut leaf_fallback = LeafFallback {
            spec: spec.budget_cleanup.clone(),
            _pins: Vec::new(),
            armed: true,
        };
        if readable(collector.as_raw_fd())? {
            bail!("mcp_owner_parent_lost");
        }
        ensure!(
            collector_pid == unsafe { libc::getppid() } as u32
                && process_ticks(collector_pid)? == startup.collector_start_ticks,
            "mcp_owner_parent_identity_invalid"
        );
        let instance = format!("{:032x}", rand::random::<u128>());
        ensure!(
            startup.budget_transfer_fd.is_some() == spec.budget_prepare.is_some(),
            "mcp_owner_budget_request_invalid"
        );
        let mut owned_budget = None;
        let mut budget_root = None;
        if let Some(requested) = &spec.budget_prepare {
            let transfer_fd = startup
                .budget_transfer_fd
                .context("mcp_owner_budget_request_invalid")?;
            ensure!(
                transfer_fd >= 3
                    && !spec.inherited_fds.contains(&transfer_fd)
                    && transfer_fd != control.as_raw_fd()
                    && transfer_fd != collector.as_raw_fd(),
                "mcp_owner_budget_request_invalid"
            );
            set_cloexec(transfer_fd, true)?;
            let transfer = unsafe { UnixDatagram::from_raw_fd(transfer_fd) };
            transfer.set_read_timeout(Some(Duration::from_millis(STARTUP_MILLIS)))?;
            transfer.set_write_timeout(Some(Duration::from_millis(STARTUP_MILLIS)))?;
            budget_root = Some(unsafe { File::from_raw_fd(requested.root_fd) });
            ensure!(!readable(collector.as_raw_fd())?, "mcp_owner_parent_lost");
            let budget = super::super::linux_budget::OwnedBudget::prepare_pinned(
                &super::super::linux_budget::BoundConfig {
                    config: requested.config.clone(),
                    root: requested.root,
                },
                budget_root
                    .as_ref()
                    .context("mcp_owner_budget_request_invalid")?,
            )?;
            let (cleanup, pins) = budget.crash_cleanup()?;
            leaf_fallback.spec = Some(cleanup.clone());
            leaf_fallback._pins = pins;
            let (prepared, descriptors) = budget.export_prepared()?;
            owned_budget = Some(budget);
            ensure!(!readable(collector.as_raw_fd())?, "mcp_owner_parent_lost");
            send_budget_fds(
                &transfer,
                &BudgetPrepared {
                    format: FORMAT.to_owned(),
                    instance: instance.clone(),
                    budget: prepared,
                },
                &descriptors,
            )?;
            await_budget_adoption(&transfer, &collector, &instance)?;
            spec.budget_attach_fd = owned_budget.as_ref().map(|budget| budget.attach_fd());
            spec.budget_cleanup = Some(cleanup);
        }
        // Keep all owner capabilities alive through startup and cleanup. The
        // wrapper inherits none of the root, cleanup or handback descriptors.
        let _budget_root = budget_root;
        let _owned_budget = owned_budget;
        let (mut lease, inner_lease) = UnixStream::pair()?;
        lease.set_read_timeout(Some(Duration::from_millis(STARTUP_MILLIS)))?;
        lease.set_write_timeout(Some(Duration::from_millis(STARTUP_MILLIS)))?;
        let (mut info, info_writer) = UnixStream::pair()?;
        info.set_read_timeout(Some(Duration::from_millis(STARTUP_MILLIS)))?;
        let lease_fd = inner_lease.as_raw_fd();
        let info_fd = info_writer.as_raw_fd();
        let args: Vec<_> = spec
            .bwrap_args
            .iter()
            .map(|arg| {
                if arg == LEASE_FD_PLACEHOLDER {
                    lease_fd.to_string()
                } else {
                    arg.clone()
                }
            })
            .collect();
        let mut command = Command::new(format!("/proc/self/fd/{}", spec.bwrap_fd));
        command
            .arg("--info-fd")
            .arg(info_fd.to_string())
            .args(&args)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let parent = unsafe { libc::getpid() };
        let inherited: Vec<_> = spec
            .inherited_fds
            .iter()
            .copied()
            .filter(|fd| {
                *fd != spec.bwrap_fd
                    && spec
                        .budget_prepare
                        .as_ref()
                        .is_none_or(|request| request.root_fd != *fd)
                    && Some(*fd) != spec.budget_attach_fd
                    && !spec.budget_cleanup.as_ref().is_some_and(|cleanup| {
                        [
                            cleanup.root_fd,
                            cleanup.leaf_fd,
                            cleanup.kill_fd,
                            cleanup.procs_fd,
                            cleanup.events_fd,
                        ]
                        .contains(fd)
                    })
            })
            .chain([lease_fd, info_fd])
            .collect();
        let attach = spec.budget_attach_fd;
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::getppid() != parent
                {
                    return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                }
                if let Some(fd) = attach {
                    if libc::write(fd, b"0\n".as_ptr().cast(), 2) != 2 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let scheduling = libc::sched_param { sched_priority: 0 };
                    if libc::sched_setscheduler(0, libc::SCHED_OTHER, &scheduling) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::setrlimit(libc::RLIMIT_RTPRIO, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for fd in &inherited {
                    if libc::fcntl(*fd, libc::F_SETFD, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                bail!("mcp_owner_sandbox_spawn_failed");
            }
        };
        drop(inner_lease);
        drop(info_writer);
        let sandbox_pid = child.id();
        let mut namespace = None;
        let setup = (|| {
            let mut bytes = Vec::new();
            let mut byte = [0];
            while bytes.len() < 4_096 {
                ensure!(
                    info.read(&mut byte)? == 1,
                    "mcp_owner_sandbox_identity_invalid"
                );
                bytes.push(byte[0]);
                if byte[0] == b'\n' && bytes.contains(&b'}') {
                    break;
                }
            }
            let value: Value = decode(&bytes)?;
            let pid1_pid = value
                .get("child-pid")
                .and_then(Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok())
                .context("mcp_owner_sandbox_identity_invalid")?;
            namespace = Some(pidfd(pid1_pid)?);
            let hello = Control {
                format: FORMAT.to_owned(),
                instance: instance.clone(),
                action: "prepare".to_owned(),
            };
            send(&mut lease, &hello)?;
            let prepared: Control = receive(&mut lease)?;
            ensure!(
                prepared.format == FORMAT
                    && prepared.instance == instance
                    && prepared.action == "prepared",
                "mcp_owner_namespace_identity_invalid"
            );
            ensure!(!readable(collector.as_raw_fd())?, "mcp_owner_parent_lost");
            ensure!(child.try_wait()?.is_none(), "mcp_owner_sandbox_lost");
            send(
                &mut lease,
                &Control {
                    action: "start".to_owned(),
                    ..hello
                },
            )?;
            let started: Control = receive(&mut lease)?;
            ensure!(
                started.format == FORMAT
                    && started.instance == instance
                    && started.action == "started",
                "mcp_owner_namespace_identity_invalid"
            );
            let owner_pid = unsafe { libc::getpid() } as u32;
            let ready = Ready {
                format: FORMAT.to_owned(),
                instance: instance.clone(),
                owner_pid,
                owner_start_ticks: process_ticks(owner_pid)?,
                sandbox_pid,
                sandbox_start_ticks: process_ticks(sandbox_pid)?,
                pid1_pid,
                pid1_start_ticks: process_ticks(pid1_pid)?,
            };
            send(&mut control, &ready)
        })();
        let mut reason = if setup.is_ok() {
            "mcp_owner_stop_requested"
        } else {
            "mcp_owner_startup_failed"
        };
        let mut reaped = false;
        let mut first_exit = None;
        let mut first_failure = if setup.is_err() {
            Some("mcp_owner_startup_failed")
        } else {
            None
        };
        let operation = (|| -> anyhow::Result<()> {
            if setup.is_ok() {
                control.set_nonblocking(true)?;
                lease.set_nonblocking(true)?;
                let mut pending = Vec::new();
                let mut last_heartbeat = Instant::now();
                let mut last_parent_heartbeat = Instant::now();
                let mut namespace_closed = None;
                let mut quiescing = false;
                'owner: loop {
                    if !reaped {
                        if let Some(failed) = observe_wrapper_exit(
                            &mut child,
                            &mut control,
                            &instance,
                            quiescing,
                            &mut first_exit,
                        )? {
                            reaped = true;
                            if failed {
                                first_failure.get_or_insert("mcp_owner_sandbox_failed");
                            }
                        }
                    }
                    if readable(collector.as_raw_fd()).unwrap_or(true) {
                        reason = "mcp_owner_parent_lost";
                        break;
                    }
                    if last_parent_heartbeat.elapsed() >= Duration::from_millis(HEARTBEAT_MILLIS) {
                        send(
                            &mut control,
                            &Heartbeat {
                                format: FORMAT.to_owned(),
                                instance: instance.clone(),
                                deadline_millis: monotonic_millis()?
                                    .checked_add(LEASE_MILLIS)
                                    .context("mcp_owner_liveness_unverified")?,
                            },
                        )?;
                        last_parent_heartbeat = Instant::now();
                    }
                    if !reaped
                        && namespace_closed.is_none()
                        && last_heartbeat.elapsed() >= Duration::from_millis(HEARTBEAT_MILLIS)
                    {
                        let deadline = monotonic_millis()?
                            .checked_add(LEASE_MILLIS)
                            .context("mcp_owner_liveness_unverified")?;
                        if lease.write_all(&deadline.to_be_bytes()).is_err() {
                            namespace_closed = Some(Instant::now());
                        }
                        last_heartbeat = Instant::now();
                    }
                    if !reaped
                        && namespace_closed.is_some_and(|closed| {
                            closed.elapsed() >= Duration::from_millis(CLEANUP_MILLIS)
                        })
                    {
                        reason = "mcp_owner_namespace_lost";
                        break;
                    }
                    let mut bytes = [0_u8; 4_096];
                    match control.read(&mut bytes) {
                        Ok(0) => {
                            reason = "mcp_owner_control_closed";
                            break;
                        }
                        Ok(count) => {
                            pending.extend_from_slice(&bytes[..count]);
                            if pending.len() > MAX_PACKET + 4 {
                                reason = "mcp_owner_control_invalid";
                                break;
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            reason = "mcp_owner_control_closed";
                            break;
                        }
                    }
                    while pending.len() >= 4 {
                        let length =
                            u32::from_be_bytes(pending[..4].try_into().expect("four bytes"))
                                as usize;
                        if length == 0 || length > MAX_PACKET {
                            reason = "mcp_owner_control_invalid";
                            break 'owner;
                        }
                        if pending.len() < length + 4 {
                            break;
                        }
                        let received: Control = decode(&pending[4..length + 4])?;
                        pending.drain(..length + 4);
                        if received.format != FORMAT || received.instance != instance {
                            reason = "mcp_owner_control_invalid";
                            break 'owner;
                        }
                        match received.action.as_str() {
                            "quiesce" => {
                                // Observe a competing prior exit at the actual
                                // intent boundary, not only at the loop's start.
                                if !reaped {
                                    if let Some(failed) = observe_wrapper_exit(
                                        &mut child,
                                        &mut control,
                                        &instance,
                                        quiescing,
                                        &mut first_exit,
                                    )? {
                                        reaped = true;
                                        if failed {
                                            first_failure.get_or_insert("mcp_owner_sandbox_failed");
                                        }
                                    }
                                }
                                quiescing = true;
                                send(
                                    &mut control,
                                    &Control {
                                        format: FORMAT.to_owned(),
                                        instance: instance.clone(),
                                        action: "quiesced".to_owned(),
                                    },
                                )?;
                            }
                            "stop" => break 'owner,
                            _ => {
                                reason = "mcp_owner_control_invalid";
                                break 'owner;
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(POLL_MILLIS));
                }
            }
            Ok(())
        })();
        if operation.is_err() {
            reason = "mcp_owner_control_failed";
        }
        if reason != "mcp_owner_stop_requested" {
            first_failure.get_or_insert(reason);
        }
        // Private EOF reaches only the trusted PID 1. It cannot be kept alive
        // by a descendant that inherited the original server's ordinary stdio.
        let _ = lease.shutdown(std::net::Shutdown::Both);
        let deadline = Instant::now() + Duration::from_millis(CLEANUP_MILLIS);
        if !reaped {
            let _ = child.kill();
        }
        let resources = cleanup_leaf(spec.budget_cleanup.as_ref());
        leaf_fallback.armed = false;
        if !reaped {
            loop {
                if child.try_wait()?.is_some() {
                    reaped = true;
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let namespace_terminated = namespace.as_ref().is_some_and(|namespace| loop {
            if readable(namespace.as_raw_fd()).unwrap_or(false) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        });
        close_stdio();
        control.set_nonblocking(false)?;
        let report = CleanupReport {
            format: FORMAT.to_owned(),
            instance,
            process_reaped: reaped,
            namespace_terminated,
            owned_resources_removed: resources.is_ok(),
            runtime_failure: first_failure.is_some(),
            reason: first_failure.unwrap_or(reason).to_owned(),
            sandbox_exit: first_exit,
        };
        let _ = send(&mut control, &report);
        ensure!(
            reaped && namespace_terminated && resources.is_ok(),
            "mcp_owner_cleanup_unverified"
        );
        setup?;
        operation
    }

    fn pinned_text(fd: RawFd) -> anyhow::Result<String> {
        let mut bytes = [0_u8; 65_537];
        let count = unsafe { libc::pread(fd, bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        ensure!(
            count >= 0 && (count as usize) < bytes.len(),
            "mcp_owner_cleanup_unverified"
        );
        String::from_utf8(bytes[..count as usize].to_vec()).context("mcp_owner_cleanup_unverified")
    }

    fn cleanup_leaf(spec: Option<&CleanupSpec>) -> anyhow::Result<()> {
        let Some(spec) = spec else {
            return Ok(());
        };
        let mut pinned = std::mem::MaybeUninit::<libc::stat>::uninit();
        ensure!(
            unsafe { libc::fstat(spec.leaf_fd, pinned.as_mut_ptr()) } == 0,
            "mcp_owner_cleanup_identity_unverified"
        );
        let pinned = unsafe { pinned.assume_init() };
        ensure!(
            pinned.st_dev == spec.device && pinned.st_ino == spec.inode,
            "mcp_owner_cleanup_identity_changed"
        );
        let name =
            CString::new(spec.name.as_bytes()).context("mcp_owner_cleanup_identity_invalid")?;
        let identity = || -> anyhow::Result<Option<bool>> {
            let raw = unsafe {
                libc::openat(
                    spec.root_fd,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                    return Ok(None);
                }
                bail!("mcp_owner_cleanup_identity_unverified");
            }
            let file = unsafe { File::from_raw_fd(raw) };
            let metadata = file.metadata()?;
            Ok(Some(
                metadata.dev() == spec.device && metadata.ino() == spec.inode,
            ))
        };
        let removed = || -> anyhow::Result<bool> {
            // A renamed, still live leaf retains this mandatory interface.
            // A removed leaf's already-open controls may return ENODEV, so use
            // a descriptor-relative lookup as well as absence of its old name.
            let events = CString::new("cgroup.events").expect("literal name");
            let raw = unsafe {
                libc::openat(
                    spec.leaf_fd,
                    events.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if raw >= 0 {
                drop(unsafe { File::from_raw_fd(raw) });
                return Ok(false);
            }
            let error = std::io::Error::last_os_error().raw_os_error();
            ensure!(
                matches!(error, Some(libc::ENOENT | libc::ENODEV)),
                "mcp_owner_cleanup_identity_unverified"
            );
            Ok(identity()?.is_none())
        };
        if identity()?.is_none() && removed()? {
            return Ok(());
        }
        // This handle still names only our original leaf even if its pathname
        // was renamed or replaced. Never direct a kill at the replacement.
        ensure!(
            unsafe { libc::write(spec.kill_fd, b"1".as_ptr().cast(), 1) } == 1,
            "mcp_owner_cleanup_unverified"
        );
        let deadline = Instant::now() + Duration::from_millis(CLEANUP_MILLIS);
        loop {
            match identity()? {
                None if removed()? => return Ok(()),
                None | Some(false) => bail!("mcp_owner_cleanup_identity_changed"),
                Some(true) => {}
            }
            let events = pinned_text(spec.events_fd)?;
            let populated = events
                .lines()
                .find_map(|line| line.strip_prefix("populated "));
            if populated == Some("0") && pinned_text(spec.procs_fd)?.trim().is_empty() {
                ensure!(
                    identity()? == Some(true),
                    "mcp_owner_cleanup_identity_changed"
                );
                if unsafe { libc::unlinkat(spec.root_fd, name.as_ptr(), libc::AT_REMOVEDIR) } == 0 {
                    return Ok(());
                }
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                    return Ok(());
                }
            }
            ensure!(Instant::now() < deadline, "mcp_owner_cleanup_unverified");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn namespace_pid1(mut lease: UnixStream, command: &[std::ffi::OsString]) -> anyhow::Result<()> {
        ensure!(
            unsafe { libc::getpid() } == 1,
            "mcp_owner_namespace_required"
        );
        let mut death_signal: libc::c_int = 0;
        ensure!(
            unsafe {
                libc::prctl(
                    libc::PR_GET_PDEATHSIG,
                    &mut death_signal as *mut libc::c_int,
                    0,
                    0,
                    0,
                )
            } == 0
                && death_signal == libc::SIGKILL,
            "mcp_owner_parent_death_unavailable"
        );
        ensure!(
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0
                && unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0,
            "mcp_owner_private_lease_unavailable"
        );
        let hello: Control = receive(&mut lease)?;
        ensure!(
            hello.format == FORMAT
                && hello.instance.len() == 32
                && hello.instance.bytes().all(|byte| byte.is_ascii_hexdigit())
                && hello.action == "prepare",
            "mcp_owner_namespace_identity_invalid"
        );
        send(
            &mut lease,
            &Control {
                action: "prepared".to_owned(),
                format: hello.format.clone(),
                instance: hello.instance.clone(),
            },
        )?;
        let start: Control = receive(&mut lease)?;
        ensure!(
            start.format == FORMAT && start.instance == hello.instance && start.action == "start",
            "mcp_owner_namespace_identity_invalid"
        );
        ensure!(!readable(lease.as_raw_fd())?, "mcp_owner_parent_lost");
        let mut original = Command::new(&command[0]);
        original
            .args(&command[1..])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        unsafe {
            original.pre_exec(|| {
                // The original runtime receives exactly stdio. Even an ambient
                // descriptor retained by bubblewrap must not cross this exec.
                if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = original
            .spawn()
            .context("mcp_owner_original_spawn_failed")?;
        send(
            &mut lease,
            &Control {
                action: "started".to_owned(),
                ..hello
            },
        )?;
        close_stdio();
        nonblocking(lease.as_raw_fd())?;
        // Absolute CLOCK_MONOTONIC deadlines prevent a buffered old heartbeat
        // from extending the lease after an owner has stopped or died.
        let mut lease_deadline = monotonic_millis()?
            .checked_add(LEASE_MILLIS)
            .context("mcp_owner_liveness_unverified")?;
        let mut pending = Vec::new();
        loop {
            if readable(lease.as_raw_fd()).unwrap_or(true) {
                let mut bytes = [0_u8; 128];
                match lease.read(&mut bytes) {
                    Ok(0) => return Err(failure("mcp_owner_parent_lost")),
                    Ok(count) => pending.extend_from_slice(&bytes[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    _ => return Err(failure("mcp_owner_control_failed")),
                }
                ensure!(pending.len() <= 135, "mcp_owner_control_invalid");
                while pending.len() >= 8 {
                    let deadline =
                        u64::from_be_bytes(pending[..8].try_into().expect("eight bytes"));
                    pending.drain(..8);
                    let now = monotonic_millis()?;
                    ensure!(
                        deadline <= now.saturating_add(LEASE_MILLIS),
                        "mcp_owner_control_invalid"
                    );
                    lease_deadline = lease_deadline.max(deadline);
                }
            }
            if monotonic_millis()? >= lease_deadline {
                return Err(failure("mcp_owner_liveness_expired"));
            }
            if let Some(status) = reap_namespace_children(&mut child)? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(failure("mcp_owner_original_failed"))
                };
            }
            std::thread::sleep(Duration::from_millis(POLL_MILLIS));
        }
    }

    fn reap_namespace_children(
        child: &mut std::process::Child,
    ) -> anyhow::Result<Option<std::process::ExitStatus>> {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        // Inspect without reaping first, so Child remains the only owner that
        // waits for the original server. Bound adopted-zombie work per tick.
        for _ in 0..64 {
            let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            let result = unsafe {
                libc::waitid(
                    libc::P_ALL,
                    0,
                    info.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(failure("mcp_owner_namespace_reap_failed"));
            }
            let pid = unsafe { info.assume_init().si_pid() };
            if pid == 0 {
                break;
            }
            if pid == child.id() as libc::pid_t {
                return Ok(child.try_wait()?);
            }
            let mut status = 0;
            if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } < 0 {
                return Err(failure("mcp_owner_namespace_reap_failed"));
            }
        }
        Ok(None)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn packets_are_bounded_and_strict() {
            assert!(encode(&"x".repeat(MAX_PACKET)).is_err());
            assert!(decode::<Control>(
                br#"{"format":"x","instance":"y","action":"stop","extra":1}"#
            )
            .is_err());
            let message = Control {
                format: FORMAT.to_owned(),
                instance: "a".repeat(32),
                action: "stop".to_owned(),
            };
            let encoded = encode(&message).unwrap();
            assert_eq!(
                u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize,
                encoded.len() - 4
            );
            assert_eq!(decode::<Control>(&encoded[4..]).unwrap().action, "stop");
        }

        fn prepared_packet() -> BudgetPrepared {
            BudgetPrepared {
                format: FORMAT.to_owned(),
                instance: "a".repeat(32),
                budget: super::super::super::linux_budget::PreparedBudget {
                    budget_sha256: "b".repeat(64),
                    leaf: format!("agentfw-mcp-{}", "c".repeat(32)),
                    device: 1,
                    inode: 2,
                    started_monotonic_nanos: 1,
                },
            }
        }

        #[test]
        fn prepared_descriptor_packet_is_exact_and_cloexec() {
            let (sender, receiver) = UnixDatagram::pair().unwrap();
            let files = (0..super::super::super::linux_budget::PREPARED_FDS)
                .map(|_| File::open("/dev/null").unwrap())
                .collect::<Vec<_>>();
            send_budget_fds(&sender, &prepared_packet(), &files).unwrap();
            let (prepared, received) = receive_budget_fds(&receiver).unwrap();
            assert_eq!(prepared.budget.budget_sha256, "b".repeat(64));
            assert_eq!(received.len(), files.len());
            for file in received {
                assert_ne!(
                    unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                    0
                );
            }
        }

        #[test]
        fn rejected_descriptor_packets_close_all_delivered_capabilities() {
            for (count, malformed) in [(7, false), (8, true), (9, false)] {
                let (sender, receiver) = UnixDatagram::pair().unwrap();
                let (mut observer, capability) = UnixStream::pair().unwrap();
                observer
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let capability: std::os::fd::OwnedFd = capability.into();
                let capability = File::from(capability);
                let files = (0..count)
                    .map(|_| capability.try_clone().unwrap())
                    .collect::<Vec<_>>();
                let bytes = if malformed {
                    b"{".to_vec()
                } else {
                    serde_json::to_vec(&prepared_packet()).unwrap()
                };
                send_descriptor_packet(&sender, bytes, &files).unwrap();
                drop(files);
                drop(capability);
                assert!(receive_budget_fds(&receiver).is_err());
                let mut byte = [0];
                assert_eq!(
                    observer.read(&mut byte).unwrap(),
                    0,
                    "rejected SCM_RIGHTS must close every delivered duplicate"
                );
            }
        }

        #[test]
        fn prepared_descriptor_packet_requires_rights_and_rejects_body_truncation() {
            let (sender, receiver) = UnixDatagram::pair().unwrap();
            sender
                .send(&serde_json::to_vec(&prepared_packet()).unwrap())
                .unwrap();
            assert!(receive_budget_fds(&receiver).is_err());
            sender.send(&vec![b' '; MAX_PACKET + 1]).unwrap();
            assert!(receive_budget_fds(&receiver).is_err());
        }
        #[test]
        fn only_owned_leaf_names_and_descriptor_sets_are_accepted() {
            let file = File::open("/dev/null").unwrap();
            let fd = file.as_raw_fd();
            let mut spec = LaunchSpec {
                bwrap_fd: fd,
                owner_executable_fd: fd,
                inherited_fds: vec![fd],
                bwrap_args: vec![
                    "--as-pid-1".to_owned(),
                    "--die-with-parent".to_owned(),
                    LEASE_FD_PLACEHOLDER.to_owned(),
                    LEASE_FD_PLACEHOLDER.to_owned(),
                ],
                budget_attach_fd: None,
                budget_cleanup: None,
                budget_prepare: None,
            };
            validate(&spec).unwrap();
            spec.inherited_fds.push(fd);
            assert!(validate(&spec).is_err());
            spec.inherited_fds.pop();
            spec.budget_cleanup = Some(CleanupSpec {
                root_fd: fd,
                leaf_fd: fd,
                kill_fd: fd,
                procs_fd: fd,
                events_fd: fd,
                name: "../another-session".to_owned(),
                device: 0,
                inode: 0,
            });
            assert!(validate(&spec).is_err());
        }
        #[test]
        fn pidfd_pins_a_process_and_private_socket_rejects_regular_files() {
            let process = pidfd(std::process::id()).unwrap();
            assert!(!readable(process.as_raw_fd()).unwrap());
            let file = File::open("/dev/null").unwrap();
            assert!(inherited_socket(file.as_raw_fd()).is_err());
        }

        #[test]
        fn renamed_or_replaced_leaf_kills_only_the_original_and_never_claims_removal() {
            for replacement in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let name = format!("agentfw-mcp-{}", "a".repeat(32));
                let original = root.path().join(&name);
                std::fs::create_dir(&original).unwrap();
                std::fs::write(original.join("cgroup.events"), "populated 1\n").unwrap();
                std::fs::write(original.join("cgroup.procs"), "123\n").unwrap();
                std::fs::write(original.join("cgroup.kill"), "0").unwrap();
                let root_fd = File::open(root.path()).unwrap();
                let leaf = File::open(&original).unwrap();
                let events = File::open(original.join("cgroup.events")).unwrap();
                let procs = File::open(original.join("cgroup.procs")).unwrap();
                let kill = std::fs::OpenOptions::new()
                    .write(true)
                    .open(original.join("cgroup.kill"))
                    .unwrap();
                let metadata = leaf.metadata().unwrap();
                let capsule = CleanupSpec {
                    root_fd: root_fd.as_raw_fd(),
                    leaf_fd: leaf.as_raw_fd(),
                    events_fd: events.as_raw_fd(),
                    procs_fd: procs.as_raw_fd(),
                    kill_fd: kill.as_raw_fd(),
                    name: name.clone(),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                };
                let moved = root.path().join("moved-owned-leaf");
                std::fs::rename(&original, &moved).unwrap();
                if replacement {
                    std::fs::create_dir(&original).unwrap();
                    std::fs::write(original.join("cgroup.kill"), "unrelated").unwrap();
                }
                assert_eq!(
                    cleanup_leaf(Some(&capsule)).unwrap_err().to_string(),
                    "mcp_owner_cleanup_identity_changed"
                );
                assert_eq!(
                    std::fs::read_to_string(moved.join("cgroup.kill")).unwrap(),
                    "1"
                );
                if replacement {
                    assert_eq!(
                        std::fs::read_to_string(original.join("cgroup.kill")).unwrap(),
                        "unrelated"
                    );
                }
            }
        }

        #[test]
        fn startup_plan_is_sealed_and_bound_to_its_original_collector() {
            let collector = pidfd(std::process::id()).unwrap();
            let file = File::open("/dev/null").unwrap();
            let fd = file.as_raw_fd();
            let startup = Startup {
                launch: LaunchSpec {
                    bwrap_fd: fd,
                    owner_executable_fd: fd,
                    inherited_fds: vec![fd],
                    bwrap_args: Vec::new(),
                    budget_attach_fd: None,
                    budget_cleanup: None,
                    budget_prepare: None,
                },
                collector_pid: std::process::id(),
                collector_start_ticks: process_ticks(std::process::id()).unwrap(),
                collector_pidfd: collector.as_raw_fd(),
                budget_transfer_fd: None,
            };
            let mut sealed = sealed_startup(&startup).unwrap();
            assert!(sealed.write_all(b"tamper").is_err());
            let decoded = read_startup(sealed.as_raw_fd()).unwrap();
            assert_eq!(decoded.collector_pid, std::process::id());
            assert_eq!(
                decoded.collector_start_ticks,
                process_ticks(std::process::id()).unwrap()
            );
            assert_eq!(decoded.collector_pidfd, collector.as_raw_fd());
        }

        #[tokio::test]
        async fn verified_cleanup_does_not_erase_an_earlier_or_late_runtime_fault() {
            for prior_event in [false, true] {
                let (reader, mut writer) = UnixStream::pair().unwrap();
                reader.set_nonblocking(true).unwrap();
                let failed = Arc::new(AtomicBool::new(false));
                let complete = Arc::new(AtomicBool::new(false));
                let state = Arc::new(Mutex::new(ParentState {
                    reason: "mcp_owner_active",
                    report: None,
                    finishing: true,
                    quiesced: false,
                    sandbox_exit: None,
                }));
                let changed = Arc::new(tokio::sync::Notify::new());
                let instance = "b".repeat(32);
                let task = tokio::spawn(parent_monitor(
                    tokio::net::UnixStream::from_std(reader).unwrap(),
                    pidfd(std::process::id()).unwrap(),
                    instance.clone(),
                    Arc::clone(&failed),
                    Arc::clone(&complete),
                    Arc::clone(&state),
                    changed,
                ));
                if prior_event {
                    writer
                        .write_all(
                            &encode(&RuntimeFailure {
                                format: FORMAT.to_owned(),
                                instance: instance.clone(),
                                reason: "mcp_owner_sandbox_failed".to_owned(),
                                sandbox_exit: Some(SandboxExit {
                                    code: Some(7),
                                    signal: None,
                                    before_quiesce: true,
                                }),
                            })
                            .unwrap(),
                        )
                        .unwrap();
                }
                writer
                    .write_all(
                        &encode(&CleanupReport {
                            format: FORMAT.to_owned(),
                            instance,
                            process_reaped: true,
                            namespace_terminated: true,
                            owned_resources_removed: true,
                            runtime_failure: true,
                            reason: "mcp_owner_sandbox_failed".to_owned(),
                            sandbox_exit: Some(SandboxExit {
                                code: Some(9),
                                signal: None,
                                before_quiesce: false,
                            }),
                        })
                        .unwrap(),
                    )
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(1), task)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(failed.load(Ordering::Acquire));
                assert!(complete.load(Ordering::Acquire));
                let state = state.lock().unwrap();
                assert_eq!(state.reason, "mcp_owner_sandbox_failed");
                assert!(state.report.as_ref().unwrap().owned_resources_removed);
                assert_eq!(
                    state.sandbox_exit.as_ref().unwrap().code,
                    Some(if prior_event { 7 } else { 9 })
                );
            }
        }

        #[test]
        fn wrapper_exit_records_real_code_and_signal_without_accepting_malformed_status() {
            for (raw, code, signal) in [(7 << 8, Some(7), None), (libc::SIGKILL, None, Some(9))] {
                let status = SandboxExit::observed(std::process::ExitStatus::from_raw(raw), false);
                assert!(status.valid());
                assert_eq!((status.code, status.signal), (code, signal));
                assert!(status.before_quiesce);
            }
            for status in [
                SandboxExit {
                    code: None,
                    signal: None,
                    before_quiesce: true,
                },
                SandboxExit {
                    code: Some(1),
                    signal: Some(9),
                    before_quiesce: true,
                },
                SandboxExit {
                    code: None,
                    signal: Some(0),
                    before_quiesce: true,
                },
                SandboxExit {
                    code: None,
                    signal: Some(65),
                    before_quiesce: true,
                },
            ] {
                assert!(!status.valid());
            }
        }
    }
}
