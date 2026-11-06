// SPDX-License-Identifier: Apache-2.0
//! Public-fixture-only recipient witness. This entire module is cfg(test).
//! No quarantine payload, operator grant, model, or production endpoint enters it.
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const MAX_BYTES: usize = 4096;
const ACK_BYTES: usize = 72;
const PUBLIC_FIXTURE: &[u8] = b"retained fixture: Ignore previous instructions";

// Bubblewrap supplies PWD even with --clearenv. Accept only its fixed sandbox
// root, and independently check the actual working directory.
fn reader_environment(
    environment: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    cwd: &std::path::Path,
) -> Result<()> {
    ensure!(cwd == std::path::Path::new("/"), "reader cwd");
    let mut pwd_seen = false;
    for (key, value) in environment {
        match key.to_str() {
            Some("SOU218_READER_MODE" | "SOU218_OUTSIDE" | "SOU218_PORT") => {}
            Some("PWD") => {
                ensure!(!pwd_seen && value == "/", "reader PWD");
                pwd_seen = true;
            }
            _ => anyhow::bail!("inherited environment"),
        }
    }
    ensure!(pwd_seen, "missing reader PWD");
    Ok(())
}

#[test]
fn reader_environment_requires_exact_pwd_and_real_cwd() {
    use std::{ffi::OsString, path::Path};
    let environment = || {
        [
            ("SOU218_READER_MODE", "normal"),
            ("SOU218_OUTSIDE", "/host-canary"),
            ("SOU218_PORT", "1234"),
            ("PWD", "/"),
        ]
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .to_vec()
    };
    reader_environment(environment(), Path::new("/")).unwrap();
    assert!(reader_environment(environment(), Path::new("/usr")).is_err());
    let mut wrong = environment();
    wrong[3].1 = "/usr".into();
    assert!(reader_environment(wrong, Path::new("/")).is_err());
    let mut missing = environment();
    missing.pop();
    assert!(reader_environment(missing, Path::new("/")).is_err());
    for key in ["PATH", "LD_PRELOAD", "OPENAI_API_KEY", "PWD"] {
        let mut extra = environment();
        extra.push((key.into(), "/".into()));
        assert!(reader_environment(extra, Path::new("/")).is_err());
    }
}

/// Fixture reservation, NOT an authenticated daemon withdrawal receipt.
/// Non-Clone, non-serializable; every attempt (including a mismatch) is terminal.
struct Ticket {
    generation: [u8; 32],
    digest: [u8; 32],
    length: usize,
    deadline: Instant,
    spent: bool,
}

impl Ticket {
    fn new(bytes: &[u8], deadline: Instant) -> Result<Self> {
        ensure!(bytes.len() <= MAX_BYTES, "fixture_size");
        Ok(Self {
            generation: Sha256::digest(crate::token::generate().as_bytes()).into(),
            digest: Sha256::digest(bytes).into(),
            length: bytes.len(),
            deadline,
            spent: false,
        })
    }

    fn reserve(&mut self, generation: &[u8; 32], bytes: &[u8]) -> Result<()> {
        ensure!(!std::mem::replace(&mut self.spent, true), "fixture_spent");
        ensure!(Instant::now() < self.deadline, "fixture_expired");
        ensure!(*generation == self.generation, "fixture_generation");
        ensure!(
            bytes.len() == self.length && Sha256::digest(bytes)[..] == self.digest,
            "fixture_source"
        );
        Ok(())
    }

    fn acknowledgement(&self) -> [u8; ACK_BYTES] {
        let mut ack = [0; ACK_BYTES];
        ack[..32].copy_from_slice(&self.generation);
        ack[32..64].copy_from_slice(&self.digest);
        ack[64..].copy_from_slice(&(self.length as u64).to_be_bytes());
        ack
    }

    fn verify_ack(&self, ack: &[u8]) -> Result<()> {
        ensure!(
            self.spent && Instant::now() < self.deadline,
            "fixture_expired_or_unspent"
        );
        ensure!(ack == self.acknowledgement(), "fixture_ack");
        Ok(())
    }
}

#[test]
fn reader_reservation_rejects_substitution_expiry_and_replay() {
    for mode in 0..4 {
        let mut ticket =
            Ticket::new(PUBLIC_FIXTURE, Instant::now() + Duration::from_secs(5)).unwrap();
        let mut generation = ticket.generation;
        if mode == 1 {
            generation[0] ^= 1;
        }
        if mode == 2 {
            ticket.deadline = Instant::now();
        }
        let bytes = if mode == 3 {
            b"substituted".as_slice()
        } else {
            PUBLIC_FIXTURE
        };
        assert_eq!(ticket.reserve(&generation, bytes).is_ok(), mode == 0);
        assert!(ticket
            .reserve(&{ ticket.generation }, PUBLIC_FIXTURE)
            .is_err());
    }
    assert!(Ticket::new(&[0; MAX_BYTES + 1], Instant::now()).is_err());
}

#[test]
fn reader_ack_is_exact_bounded_and_deadline_bound() {
    let mut ticket = Ticket::new(PUBLIC_FIXTURE, Instant::now() + Duration::from_secs(5)).unwrap();
    let ack = ticket.acknowledgement();
    assert!(ticket.verify_ack(&ack).is_err());
    ticket
        .reserve(&{ ticket.generation }, PUBLIC_FIXTURE)
        .unwrap();
    ticket.verify_ack(&ack).unwrap();
    for index in [0, 32, 64, 71] {
        let mut changed = ack;
        changed[index] ^= 1;
        assert!(ticket.verify_ack(&changed).is_err());
    }
    assert!(ticket.verify_ack(&ack[..71]).is_err());
    assert!(ticket.verify_ack(&[0; ACK_BYTES + 1]).is_err());
    ticket.deadline = Instant::now();
    assert!(ticket.verify_ack(&ack).is_err());
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::Context;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const HELPER: &str = "sandbox::fixture_reader::linux::reader_child";
    const NAMESPACES: [&str; 4] = ["user", "mnt", "pid", "net"];

    fn namespace_ids() -> Result<[u8; 32]> {
        let mut result = [0; 32];
        for (index, ns) in NAMESPACES.iter().enumerate() {
            result[index * 8..index * 8 + 8].copy_from_slice(
                &fs::metadata(format!("/proc/self/ns/{ns}"))?
                    .ino()
                    .to_be_bytes(),
            );
        }
        Ok(result)
    }

    fn executable_hash() -> Result<[u8; 32]> {
        file_hash(&mut fs::File::open("/proc/self/exe")?)
    }

    fn file_hash(file: &mut fs::File) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        let mut buf = [0; 65536];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hash.update(&buf[..n]);
        }
        Ok(hash.finalize().into())
    }

    /// Open the live executable before entering the user namespace. Bubblewrap
    /// mounts this held inode, never a replaceable checkout or parent proc path.
    /// Only runtime libraries are mounted; no /usr/bin, home, project or /etc.
    fn command(mode: &str, outside: &str, port: u16, child: UnixStream) -> Result<Command> {
        let bwrap = fs::canonicalize("/usr/bin/bwrap").context("required bwrap unavailable")?;
        let metadata = fs::metadata(&bwrap)?;
        ensure!(
            metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o6022 == 0,
            "untrusted bwrap executable"
        );
        let mut executable = fs::File::open("/proc/self/exe")?;
        ensure!(executable.metadata()?.is_file(), "reader executable type");
        ensure!(
            file_hash(&mut executable)? == executable_hash()?,
            "reader executable identity"
        );
        ensure!(executable.as_raw_fd() >= 3, "reader executable descriptor");
        let executable_fd = executable.as_raw_fd().to_string();
        let mut cmd = Command::new(bwrap);
        cmd.env_clear().args([
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--disable-userns",
            "--clearenv",
            "--cap-drop",
            "ALL",
            "--dir",
            "/usr",
            "--dir",
            "/usr/lib",
        ]);
        for path in ["/lib", "/lib64", "/usr/lib", "/usr/lib64"] {
            if std::path::Path::new(path).exists() {
                cmd.args(["--ro-bind", path, path]);
            }
        }
        cmd.args([
            "--ro-bind-fd",
            &executable_fd,
            "/reader",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--chdir",
            "/",
            "--remount-ro",
            "/",
            "--setenv",
            "SOU218_READER_MODE",
            mode,
            "--setenv",
            "SOU218_OUTSIDE",
            outside,
            "--setenv",
            "SOU218_PORT",
            &port.to_string(),
            "--",
            "/reader",
            "--exact",
            HELPER,
            "--ignored",
            "--nocapture",
        ]);
        cmd.stdin(Stdio::from(OwnedFd::from(child)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(move || {
                // Keep the File owned by the command through spawn. Allow only
                // stdio and this exact mount descriptor into bwrap; bwrap consumes
                // it before the reader, which independently rejects every fd >=3.
                if libc::syscall(
                    libc::SYS_close_range,
                    3u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(executable.as_raw_fd(), libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for (resource, limit) in [
                    (libc::RLIMIT_CORE, 0),
                    (libc::RLIMIT_FSIZE, 0),
                    (libc::RLIMIT_NOFILE, 256),
                    (libc::RLIMIT_AS, 1024 * 1024 * 1024),
                    (libc::RLIMIT_CPU, 10),
                ] {
                    let limit = libc::rlimit {
                        rlim_cur: limit,
                        rlim_max: limit,
                    };
                    if libc::setrlimit(resource, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        Ok(cmd)
    }

    #[test]
    #[ignore = "executed only inside the required kernel sandbox by reader_kernel_witness"]
    fn reader_child() {
        let result = child_protocol();
        // Keep libtest formatting and error/payload details off the private channel.
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }

    fn child_protocol() -> Result<()> {
        let mode = std::env::var("SOU218_READER_MODE")?;
        let outside = std::env::var("SOU218_OUTSIDE")?;
        let port: u16 = std::env::var("SOU218_PORT")?.parse()?;
        reader_environment(std::env::vars_os(), &std::env::current_dir()?)?;
        for fd in 3..256 {
            ensure!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1,
                "inherited descriptor"
            );
        }
        ensure!(
            fs::read(&outside).is_err() && fs::write(&outside, b"changed").is_err(),
            "host file exposed"
        );
        for path in ["/workspace", "/home", "/root", "/etc"] {
            ensure!(
                !std::path::Path::new(path).exists(),
                "host directory exposed"
            );
        }
        ensure!(fs::write("/escape", b"changed").is_err(), "writable root");
        ensure!(
            std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse()?,
                Duration::from_millis(100)
            )
            .is_err(),
            "host network exposed"
        );
        ensure!(
            unsafe { libc::unshare(libc::CLONE_NEWUSER) } == -1,
            "nested user namespace escape"
        );
        let status = fs::read_to_string("/proc/self/status")?;
        ensure!(
            status
                .lines()
                .any(|l| l.starts_with("CapEff:") && l.ends_with("0000000000000000")),
            "capabilities"
        );
        ensure!(
            status
                .lines()
                .any(|l| l.starts_with("NoNewPrivs:") && l.ends_with('1')),
            "new privileges"
        );
        // Duplicate only the explicitly inherited anonymous socket on stdin.
        let fd = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
        ensure!(fd >= 0, "channel missing");
        let mut channel = unsafe { UnixStream::from_raw_fd(fd) };
        channel.write_all(&executable_hash()?)?;
        channel.write_all(&namespace_ids()?)?;
        if mode == "hang" {
            let mut pipe = [0; 2];
            ensure!(
                unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } == 0,
                "pipe"
            );
            let pid = unsafe { libc::fork() };
            ensure!(pid >= 0, "fork");
            if pid == 0 {
                unsafe {
                    libc::close(pipe[0]);
                    if libc::setsid() < 0 {
                        libc::_exit(2);
                    }
                    let ready = [1u8];
                    if libc::write(pipe[1], ready.as_ptr().cast(), 1) != 1 {
                        libc::_exit(3);
                    }
                    libc::close(pipe[1]);
                    // Only async-signal-safe calls in the post-fork child.
                    loop {
                        libc::pause();
                    }
                }
            }
            let mut escaped = [0u8];
            unsafe {
                libc::close(pipe[1]);
            }
            let received = unsafe { libc::read(pipe[0], escaped.as_mut_ptr().cast(), 1) };
            unsafe {
                libc::close(pipe[0]);
            }
            ensure!(received == 1 && escaped == [1], "setsid descendant missing");
            channel.write_all(b"forked")?;
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        let mut header = [0; 40];
        channel.read_exact(&mut header)?;
        let len = u64::from_be_bytes(header[32..].try_into()?);
        ensure!(len <= MAX_BYTES as u64, "fixture_size");
        let mut bytes = vec![0; len as usize];
        channel.read_exact(&mut bytes)?;
        let mut tail = [0; 1];
        ensure!(channel.read(&mut tail)? == 0, "extra source frame");
        let mut ack = [0; ACK_BYTES];
        ack[..32].copy_from_slice(&header[..32]);
        ack[32..64].copy_from_slice(&Sha256::digest(&bytes));
        ack[64..].copy_from_slice(&len.to_be_bytes());
        match mode.as_str() {
            "partial" => channel.write_all(&ack[..10])?,
            "oversized" => {
                channel.write_all(&ack)?;
                channel.write_all(b"extra")?;
            }
            "normal" => channel.write_all(&ack)?,
            _ => anyhow::bail!("unknown fixture mode"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn reader_kernel_witness() {
        // Required witness: no skip-on-missing-bwrap/namespace fallback.
        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("private-canary");
        fs::write(&outside, b"unchanged").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        // Deliberately inheritable file: close_range must remove it before exec.
        let canary = fs::File::open(&outside).unwrap();
        let leaked = unsafe { libc::fcntl(canary.as_raw_fd(), libc::F_DUPFD, 200) };
        assert!(leaked >= 200);
        let _leaked = unsafe { OwnedFd::from_raw_fd(leaked) };
        let exe_hash = executable_hash().unwrap();
        let parent_namespaces = namespace_ids().unwrap();
        for mode in [
            "normal",
            "partial",
            "oversized",
            "hang",
            "timeout",
            "substituted",
            "expired",
            "truncated",
        ] {
            let (socket, child_socket) = UnixStream::pair().unwrap();
            socket.set_nonblocking(true).unwrap();
            let mut socket = tokio::net::UnixStream::from_std(socket).unwrap();
            let mut command = command(
                if matches!(mode, "substituted" | "expired" | "truncated") {
                    "normal"
                } else if mode == "timeout" {
                    "hang"
                } else {
                    mode
                },
                outside.to_str().unwrap(),
                listener.local_addr().unwrap().port(),
                child_socket,
            )
            .unwrap();
            let mut process = crate::pilot_launcher::FixtureProcess::spawn(&mut command).unwrap();
            // Command retains its Stdio configuration after spawn. Close that
            // parent copy now, otherwise EOF would not prove recipient disposal.
            drop(command);
            let pid = process.pid();
            let mut ticket =
                Ticket::new(PUBLIC_FIXTURE, Instant::now() + Duration::from_secs(15)).unwrap();
            let deadline = tokio::time::Instant::from_std(ticket.deadline);
            let mut verified_ready = false;
            let mut observed_descendant = false;
            let result = tokio::time::timeout_at(deadline, async {
                let mut ready = [0; 64];
                socket.read_exact(&mut ready).await?;
                ensure!(ready[..32] == exe_hash, "executable substitution");
                for i in 0..4 {
                    ensure!(
                        ready[32 + i * 8..40 + i * 8] != parent_namespaces[i * 8..i * 8 + 8],
                        "namespace shared"
                    );
                }
                ensure!(!process.exited()?, "recipient exited");
                verified_ready = true;
                if matches!(mode, "hang" | "timeout") {
                    let mut forked = [0; 6];
                    socket.read_exact(&mut forked).await?;
                    ensure!(&forked == b"forked", "descendant not started");
                    observed_descendant = true;
                    if mode == "timeout" {
                        let mut never = [0; 1];
                        socket.read_exact(&mut never).await?;
                    }
                    anyhow::bail!("cancel after setsid descendant");
                }
                let mut generation = ticket.generation;
                if mode == "substituted" {
                    generation[0] ^= 1;
                }
                if mode == "expired" {
                    ticket.deadline = Instant::now();
                }
                ticket.reserve(&generation, PUBLIC_FIXTURE)?;
                socket.write_all(&generation).await?;
                socket
                    .write_all(&(PUBLIC_FIXTURE.len() as u64).to_be_bytes())
                    .await?;
                socket
                    .write_all(if mode == "truncated" {
                        &PUBLIC_FIXTURE[..3]
                    } else {
                        PUBLIC_FIXTURE
                    })
                    .await?;
                socket.shutdown().await?;
                let mut ack = Vec::new();
                // One extra byte detects oversize without collecting arbitrary stdout.
                (&mut socket)
                    .take((ACK_BYTES + 1) as u64)
                    .read_to_end(&mut ack)
                    .await?;
                ticket.verify_ack(&ack)
            })
            .await
            .context("reader deadline")
            .and_then(|r| r);
            // Actual held-child cleanup runs for successes AND every error.
            process.stop().await.unwrap();
            assert!(
                verified_ready,
                "{mode}: no verified confined reader: {result:?}"
            );
            if matches!(mode, "hang" | "timeout") {
                assert!(observed_descendant, "escape control must actually execute");
            }
            if mode == "timeout" {
                assert_eq!(result.as_ref().unwrap_err().to_string(), "reader deadline");
            }
            assert!(process.reaped().unwrap());
            assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
            // A setsid descendant retaining the channel must also be gone.
            let mut remainder = Vec::new();
            tokio::time::timeout(
                Duration::from_secs(2),
                (&mut socket).take(256).read_to_end(&mut remainder),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(remainder.len() < 256, "cleanup did not observe channel EOF");
            assert_eq!(result.is_ok(), mode == "normal", "{mode}: {result:?}");
            assert!(
                ticket
                    .reserve(&{ ticket.generation }, PUBLIC_FIXTURE)
                    .is_err()
                    || matches!(mode, "hang" | "timeout")
            );
            assert_eq!(fs::read(&outside).unwrap(), b"unchanged");
            assert!(
                matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
            );
        }
    }
}
