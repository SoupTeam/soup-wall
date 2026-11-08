// SPDX-License-Identifier: Apache-2.0
//! Required Linux component crash witness. No production entry point.
use super::*;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::AsyncReadExt;

const HELPER: &str = "native::consumer::crash_witness::quarantine_reader_daemon_child";
const PACKET_LIMIT: usize = 16_384;

struct Held(Child);
impl Drop for Held {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    reader_pid: u32,
    canary: std::path::PathBuf,
    after_prefix: bool,
    registration: Registration,
    grant: analysis_purpose::Grant,
}

// A private inherited datagram carries one observation-only duplicate of the
// real reader channel. It never enters the sandbox or any production IPC path.
fn send_observer(control: &UnixDatagram, ready: &Ready, observer: RawFd) -> Result<()> {
    let mut bytes = serde_json::to_vec(ready)?;
    ensure!(bytes.len() <= PACKET_LIMIT, "crash witness packet bound");
    let size = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = storage.as_mut_ptr().cast();
    message.msg_controllen = size;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        ensure!(!header.is_null(), "crash witness ancillary header");
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), observer);
    }
    ensure!(
        unsafe { libc::sendmsg(control.as_raw_fd(), &message, libc::MSG_NOSIGNAL) }
            == bytes.len() as isize,
        "crash witness observer transfer"
    );
    Ok(())
}

fn receive_observer(control: &UnixDatagram) -> Result<(Ready, UnixStream)> {
    let mut bytes = vec![0; PACKET_LIMIT];
    // Space for two descriptors lets rejection own/close an unexpected extra.
    let size = unsafe { libc::CMSG_SPACE((2 * std::mem::size_of::<RawFd>()) as u32) } as usize;
    let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = storage.as_mut_ptr().cast();
    message.msg_controllen = size;
    let count = unsafe { libc::recvmsg(control.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    ensure!(count >= 0, "crash witness readiness missing");
    let mut descriptors = Vec::new();
    let mut valid = true;
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
                valid = false;
                break;
            }
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let length = (*header).cmsg_len - minimum;
                valid &= length.is_multiple_of(std::mem::size_of::<RawFd>());
                for index in 0..length / std::mem::size_of::<RawFd>() {
                    let fd = std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                    );
                    if fd >= 0 {
                        descriptors.push(OwnedFd::from_raw_fd(fd));
                    } else {
                        valid = false;
                    }
                }
            } else {
                valid = false;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    ensure!(
        count > 0
            && valid
            && descriptors.len() == 1
            && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0,
        "crash witness invalid observation packet"
    );
    let ready = serde_json::from_slice(&bytes[..count as usize])?;
    Ok((ready, UnixStream::from(descriptors.pop().unwrap())))
}

struct Pinned(File);
impl Pinned {
    fn exited(&self, timeout_ms: i32) -> bool {
        let mut fd = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(unsafe { libc::poll(&mut fd, 1, timeout_ms) } >= 0);
        assert_eq!(fd.revents & (libc::POLLERR | libc::POLLNVAL), 0);
        fd.revents & (libc::POLLIN | libc::POLLHUP) != 0
    }
}
impl Drop for Pinned {
    fn drop(&mut self) {
        // Failure-only hygiene targets pinned identities, never recycled PIDs.
        // Assertions below observe death BEFORE any such fallback can run.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.0.as_raw_fd(),
                libc::SIGKILL,
                0,
                0,
            );
        }
    }
}

fn pin_tree(pid: u32, expected_parent: u32, pins: &mut Vec<Pinned>) -> Result<()> {
    ensure!(pins.len() < 16, "crash witness descendant bound");
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    ensure!(raw >= 0, "crash witness pidfd required");
    let file = unsafe { File::from_raw_fd(raw as i32) };
    let record = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let parent = record
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_ascii_whitespace().nth(1));
    ensure!(
        parent == Some(expected_parent.to_string().as_str()),
        "crash witness parent mismatch"
    );
    // Do not arm failure cleanup until ancestry has been checked.
    let pinned = Pinned(file);
    ensure!(!pinned.exited(0), "crash witness premature exit");
    pins.push(pinned);
    let mut children = std::collections::BTreeSet::new();
    for (index, task) in fs::read_dir(format!("/proc/{pid}/task"))?.enumerate() {
        ensure!(index < 256, "crash witness task bound");
        let text = fs::read_to_string(task?.path().join("children"))?;
        ensure!(text.len() <= 4096, "crash witness children bound");
        for value in text.split_ascii_whitespace() {
            children.insert(value.parse::<u32>()?);
        }
    }
    for child in children {
        pin_tree(child, pid, pins)?;
    }
    Ok(())
}

fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer native-unit-key".parse().unwrap());
    headers
}

#[tokio::test]
async fn quarantine_reader_daemon_crash() {
    for after_prefix in [false, true] {
        // Parent owns the fixture root even when SIGKILL bypasses every child
        // destructor. No test artifacts depend on the killed daemon cleaning up.
        let directory = tempfile::tempdir().unwrap();
        let (control, child_control) = UnixDatagram::pair().unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["pilot-launch", HELPER, "--ignored", "--nocapture"])
            .env("TMPDIR", directory.path())
            .env(
                "SOU218_CRASH_AFTER_PREFIX",
                if after_prefix { "1" } else { "0" },
            )
            .stdin(Stdio::from(OwnedFd::from(child_control)))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let mut daemon = Held(command.spawn().unwrap());
        drop(command);
        let (ready, observer) = receive_observer(&control).unwrap();
        assert_eq!(ready.after_prefix, after_prefix);
        assert!(ready.canary.starts_with(directory.path()));
        assert_eq!(fs::read(&ready.canary).unwrap(), b"unchanged");
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "daemon exited before kill"
        );
        let mut pins = Vec::new();
        pin_tree(ready.reader_pid, daemon.0.id(), &mut pins).unwrap();
        assert!(
            pins.len() >= 3,
            "supervisor, reader and setsid descendant required"
        );
        for pinned in &pins {
            assert!(!pinned.exited(0));
        }
        observer.set_nonblocking(true).unwrap();
        let mut observer = tokio::net::UnixStream::from_std(observer).unwrap();
        let mut byte = [0; 1];
        assert!(
            matches!(observer.try_read(&mut byte), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
        );
        // Abrupt process death, NOT future cancellation or an orderly shutdown.
        daemon.0.kill().unwrap();
        assert_eq!(daemon.0.wait().unwrap().signal(), Some(libc::SIGKILL));
        let mut tail = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            (&mut observer).take(1).read_to_end(&mut tail),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(tail.is_empty(), "crashed transfer acknowledged");
        for pinned in &pins {
            assert!(pinned.exited(2000), "recipient survived daemon SIGKILL");
        }
        assert_eq!(fs::read(&ready.canary).unwrap(), b"unchanged");

        let restarted_dir = tempfile::tempdir_in(directory.path()).unwrap();
        let restarted = super::super::tests::fixture(restarted_dir.path());
        assert_eq!(
            handler(
                State(restarted.clone()),
                headers(),
                serde_json::to_string(&ready.registration).unwrap()
            )
            .await
            .0,
            StatusCode::FORBIDDEN,
            "old registration resurrected after restart"
        );
        assert!(matches!(
            analysis_purpose::consume(&restarted, &ready.grant),
            Err("analysis_consumer_missing")
        ));
        assert!(restarted
            .native
            .as_ref()
            .unwrap()
            .sessions
            .lock()
            .unwrap()
            .consumers
            .is_empty());
    }
}

#[tokio::test]
#[ignore = "re-executed and SIGKILLed by quarantine_reader_daemon_crash"]
async fn quarantine_reader_daemon_child() {
    assert_eq!(std::env::args().nth(1).as_deref(), Some("pilot-launch"));
    let after_prefix = match std::env::var("SOU218_CRASH_AFTER_PREFIX").unwrap().as_str() {
        "0" => false,
        "1" => true,
        _ => panic!("invalid crash point"),
    };
    let fd = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
    assert!(fd >= 0);
    let control = unsafe { UnixDatagram::from_raw_fd(fd) };
    let mut source = Held(
        Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    let captured = execution::tests::reader_capture(&source.0);
    let st = &captured.st;
    assert_eq!(
        handler(
            State(st.clone()),
            headers(),
            serde_json::to_string(&captured.registration).unwrap()
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let grant = analysis_purpose::grant_for_retained(st, &captured.registration, &captured.id);
    let pending = analysis_purpose::consume(st, &grant).unwrap();
    source.0.kill().unwrap();
    source.0.wait().unwrap();
    let native = st.native.as_ref().unwrap();
    let before = native
        .quarantine
        .lock()
        .unwrap()
        .retained(&captured.id)
        .unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut delivery = Box::pin(pending.deliver_to_reader(
        st,
        crate::sandbox::fixture_reader::ReadMode::Pause {
            after_prefix,
            with_descendant: true,
            signal: Some(tx),
        },
    ));
    let paused = tokio::select! {
        ready = tokio::time::timeout(Duration::from_secs(10), rx) => ready.unwrap().unwrap(),
        result = &mut delivery => panic!("delivery ended before crash point: {result:?}"),
    };
    assert!(analysis_purpose::consume(st, &grant).is_err());
    {
        let quarantine = native.quarantine.lock().unwrap();
        assert_eq!(quarantine.reader_was_reserved(&captured.id), after_prefix);
        assert_eq!(quarantine.retained(&captured.id).unwrap(), before);
    }
    send_observer(
        &control,
        &Ready {
            reader_pid: paused.pid,
            canary: paused.canary,
            after_prefix,
            registration: captured.registration.clone(),
            grant,
        },
        paused.observer.as_raw_fd(),
    )
    .unwrap();
    // Keep the actual pending delivery, owner and custody alive until SIGKILL.
    // In particular, do not drop the future after notifying the observer.
    let result = delivery.await;
    panic!("daemon was not killed while pending: {result:?}");
}
