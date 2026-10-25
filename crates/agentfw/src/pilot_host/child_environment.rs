// SPDX-License-Identifier: Apache-2.0
//! Trusted child-environment guard for the exact pinned compiled Bun host.
//! The channel acknowledges installation only; it carries no provider inputs.
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

pub(crate) struct Guard {
    parent: UnixStream,
    child: UnixStream,
}

impl Guard {
    pub(crate) fn install(command: &mut Command, private: &std::path::Path) -> Result<Self> {
        let code = [
            b"import {createRequire} from \"node:module\"; const require=createRequire(\"file:///agentfw-provider-child-environment.cjs\");\n".as_slice(),
            include_bytes!("child_environment.cjs").as_slice(),
        ].concat();
        let (parent, child) = UnixStream::pair()?;
        let config = private.join("host-bun.toml");
        std::fs::write(&config, b"")?;
        command
            .env(
                "BUN_OPTIONS",
                format!(
                    "--preload=data:text/javascript;base64,{} --config={} --no-env-file",
                    STANDARD.encode(code),
                    config.display()
                ),
            )
            .env("BUN_RUNTIME_TRANSPILER_CACHE_PATH", "0")
            .env("DO_NOT_TRACK", "1")
            .env("AGENTFW_PROVIDER_READY_FD", child.as_raw_fd().to_string());
        let fd = child.as_raw_fd();
        // Guard owns the descriptor until after spawn. The parent retains
        // CLOEXEC; only the exact forked host inherits this installation check.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(Self { parent, child })
    }

    pub(crate) fn confirm_until(self, host_deadline: Instant) -> Result<()> {
        let Self { mut parent, child } = self;
        drop(child);
        // Darwin can reject SO_RCVTIMEO after the peer closes even while its
        // complete acknowledgement remains buffered. Nonblocking I/O and poll
        // preserve the absolute deadline without changing a closed socket's
        // timeout options or treating an I/O error as successful readiness.
        parent.set_nonblocking(true)?;
        // Readiness consumes the existing host budget. Neither partial reads
        // nor waiting for EOF may restart that budget or the startup cap.
        let deadline = host_deadline.min(Instant::now() + Duration::from_secs(3));
        let read = |parent: &mut UnixStream, bytes: &mut [u8]| -> Result<usize> {
            loop {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|value| !value.is_zero())
                    .ok_or_else(|| anyhow::anyhow!("provider_child_environment_unavailable"))?;
                match parent.read(bytes) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        let mut poll = libc::pollfd {
                            fd: parent.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        // The startup cap bounds this to at most 3000ms.
                        // Round down and recheck the deadline before reading.
                        if unsafe { libc::poll(&mut poll, 1, remaining.as_millis() as i32) } < 0 {
                            let error = std::io::Error::last_os_error();
                            if error.kind() != std::io::ErrorKind::Interrupted {
                                return Err(error.into());
                            }
                        }
                    }
                    result => return Ok(result?),
                }
            }
        };
        let mut ready = [0; 19];
        let mut offset = 0;
        while offset < ready.len() {
            let count = read(&mut parent, &mut ready[offset..])?;
            ensure!(count > 0, "provider_child_environment_unavailable");
            offset += count;
        }
        ensure!(
            &ready == b"sw-provider-ready/1",
            "provider_child_environment_unavailable"
        );
        let mut tail = [0];
        ensure!(
            read(&mut parent, &mut tail)? == 0,
            "provider_child_environment_unavailable"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installation_check_carries_no_provider_values_and_ignored_guard_refuses() {
        for installed in [false, true] {
            let private = tempfile::tempdir().unwrap();
            let mut command = Command::new("/usr/bin/python3");
            command
                .env_clear()
                .env("ANTHROPIC_API_KEY", "owned-marker-test");
            command.arg("-c").arg(if installed {
                r#"
import os
fd=int(os.environ['AGENTFW_PROVIDER_READY_FD'])
os.write(fd,b'sw-provider-ready/1');os.close(fd)
"#
            } else {
                "pass"
            });
            let guard = Guard::install(&mut command, private.path()).unwrap();
            let startup = command
                .get_envs()
                .find(|(key, _)| *key == "BUN_OPTIONS")
                .unwrap()
                .1
                .unwrap()
                .to_str()
                .unwrap();
            let encoded = startup
                .strip_prefix("--preload=data:text/javascript;base64,")
                .unwrap()
                .split(' ')
                .next()
                .unwrap();
            assert!(STANDARD
                .decode(encoded)
                .unwrap()
                .ends_with(include_bytes!("child_environment.cjs")));
            assert!(!startup.contains("owned-marker-test"));
            let mut child = command.spawn().unwrap();
            let confirmation = guard.confirm_until(Instant::now() + Duration::from_secs(3));
            assert_eq!(confirmation.is_ok(), installed, "{confirmation:?}");
            assert!(child.wait().unwrap().success());
        }
    }

    #[test]
    fn closed_peer_requires_exact_complete_ready_and_eof() {
        use std::io::Write;
        for (payload, accepted) in [
            (b"sw-provider-ready/1".as_slice(), true),
            (b"sw-provider-ready/1x".as_slice(), false),
            (b"sw-provider-ready/".as_slice(), false),
            (b"".as_slice(), false),
        ] {
            let (parent, mut child) = UnixStream::pair().unwrap();
            child.write_all(payload).unwrap();
            let guard = Guard { parent, child };
            assert_eq!(
                guard
                    .confirm_until(Instant::now() + Duration::from_secs(3))
                    .is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn complete_ready_without_eof_cannot_extend_the_host_deadline() {
        use std::io::Write;
        let (parent, mut child) = UnixStream::pair().unwrap();
        child.write_all(b"sw-provider-ready/1").unwrap();
        let _still_open = child.try_clone().unwrap();
        let guard = Guard { parent, child };
        assert!(guard
            .confirm_until(Instant::now() + Duration::from_millis(30))
            .is_err());
    }

    #[test]
    fn even_complete_ready_and_eof_cannot_rescue_an_expired_host_budget() {
        use std::io::Write;
        let (parent, mut child) = UnixStream::pair().unwrap();
        let deadline = Instant::now();
        child.write_all(b"sw-provider-ready/1").unwrap();
        let guard = Guard { parent, child };
        // The complete valid message and EOF are already available. The old
        // readiness check accepted them and then started a fresh host timer.
        assert!(guard.confirm_until(deadline).is_err());
    }
}
