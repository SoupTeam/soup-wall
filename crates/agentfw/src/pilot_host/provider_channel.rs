// SPDX-License-Identifier: Apache-2.0
//! Do not release provider inputs until the exact spawned host has installed
//! its trusted preload. Inherited FDs contain code, never credentials.
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

use anyhow::{ensure, Context, Result};

pub(crate) struct Bootstrap {
    parent: UnixDatagram,
    code: File,
    child: UnixDatagram,
    provider: Vec<u8>,
}

fn sealed(bytes: &[u8]) -> Result<File> {
    let name = c"agentfw-provider-code";
    let raw =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    ensure!(raw >= 0, "provider_bootstrap_unavailable");
    let mut file = unsafe { File::from_raw_fd(raw) };
    file.write_all(bytes)?;
    ensure!(
        unsafe {
            libc::fcntl(
                raw,
                libc::F_ADD_SEALS,
                libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK,
            )
        } == 0,
        "provider_bootstrap_unavailable"
    );
    Ok(file)
}

impl Bootstrap {
    pub(crate) fn configure(
        command: &mut Command,
        values: Vec<(std::ffi::OsString, std::ffi::OsString)>,
        private: &std::path::Path,
    ) -> Result<Self> {
        let mut provider = std::collections::BTreeMap::new();
        for (key, value) in values {
            let key = key
                .into_string()
                .map_err(|_| anyhow::anyhow!("provider_input_invalid"))?;
            let value = value
                .into_string()
                .map_err(|_| anyhow::anyhow!("provider_input_invalid"))?;
            ensure!(
                super::PROVIDER_ENV.contains(&key.as_str()) && !value.contains('\0'),
                "provider_input_invalid"
            );
            provider.insert(key, value);
        }
        let provider = serde_json::to_vec(&provider)?;
        ensure!(provider.len() <= 16384, "provider_input_invalid");
        let code = sealed(include_bytes!("provider_preload.cjs"))?;
        let (parent, child) = UnixDatagram::pair()?;
        parent.set_read_timeout(Some(Duration::from_secs(3)))?;
        child.set_read_timeout(Some(Duration::from_secs(3)))?;
        let enabled: libc::c_int = 1;
        ensure!(
            unsafe {
                libc::setsockopt(
                    parent.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&enabled as *const libc::c_int).cast(),
                    std::mem::size_of_val(&enabled) as libc::socklen_t,
                )
            } == 0,
            "provider_bootstrap_unavailable"
        );
        let config = private.join("host-bun.toml");
        std::fs::write(&config, b"")?;
        command
            .env(
                "BUN_OPTIONS",
                format!(
                    "--preload=/proc/self/fd/{} --config={} --no-env-file",
                    code.as_raw_fd(),
                    config.display()
                ),
            )
            .env("AGENTFW_PROVIDER_CHANNEL", child.as_raw_fd().to_string())
            .env("AGENTFW_PROVIDER_CODE", code.as_raw_fd().to_string());
        let descriptors = [code.as_raw_fd(), child.as_raw_fd()];
        // The Bootstrap owns both descriptors until after spawn. CLOEXEC is
        // cleared in the forked host only, never in the multithreaded parent.
        unsafe {
            command.pre_exec(move || {
                for descriptor in descriptors {
                    if libc::fcntl(descriptor, libc::F_SETFD, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        Ok(Self {
            parent,
            child,
            code,
            provider,
        })
    }

    pub(crate) fn deliver(self, pid: u32) -> Result<()> {
        let Self {
            parent,
            child,
            code,
            provider,
        } = self;
        drop(child);
        drop(code);
        receive_ready(&parent, pid).context("provider_bootstrap_unavailable")?;
        ensure!(
            parent.send(&provider)? == provider.len(),
            "provider_bootstrap_unavailable"
        );
        Ok(())
    }
}

fn receive_ready(socket: &UnixDatagram, pid: u32) -> Result<()> {
    let mut greeting = [0u8; 32];
    let mut iov = libc::iovec {
        iov_base: greeting.as_mut_ptr().cast(),
        iov_len: greeting.len(),
    };
    // Aligned, bounded ancillary storage; only one kernel SCM_CREDENTIALS.
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    let count = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    let mut valid = count == 19
        && &greeting[..19] == b"sw-provider-ready/1"
        && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0;
    let mut credentials = None;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let item = unsafe { &*header };
        if item.cmsg_level == libc::SOL_SOCKET
            && item.cmsg_type == libc::SCM_CREDENTIALS
            && item.cmsg_len
                == unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as u32) } as usize
            && credentials.is_none()
        {
            credentials = Some(unsafe {
                std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>())
            });
        } else {
            valid = false;
            // Even a rejected/truncated ancillary packet owns any delivered FDs.
            if item.cmsg_level == libc::SOL_SOCKET && item.cmsg_type == libc::SCM_RIGHTS {
                let bytes = item
                    .cmsg_len
                    .saturating_sub(unsafe { libc::CMSG_LEN(0) } as usize);
                for index in 0..bytes / std::mem::size_of::<i32>() {
                    let fd = unsafe {
                        std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>().add(index))
                    };
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    ensure!(valid, "provider_bootstrap_unavailable");
    let credentials = credentials.context("provider_bootstrap_unavailable")?;
    ensure!(
        credentials.pid > 0
            && credentials.pid as u32 == pid
            && credentials.uid == unsafe { libc::geteuid() },
        "provider_bootstrap_unavailable"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn prepared(script: &str) -> (Command, Bootstrap, tempfile::TempDir) {
        let private = tempfile::tempdir().unwrap();
        let mut command = Command::new("/usr/bin/python3");
        command.arg("-c").arg(script).env_clear();
        let bootstrap = Bootstrap::configure(
            &mut command,
            vec![("ANTHROPIC_API_KEY".into(), "owned-channel-canary".into())],
            private.path(),
        )
        .unwrap();
        (command, bootstrap, private)
    }

    #[test]
    fn host_provider_channel_is_anonymous_sealed_and_credential_free_at_exec() {
        let (mut command, bootstrap, _private) = prepared(
            r#"
import os,socket,json
assert 'ANTHROPIC_API_KEY' not in os.environ
s=socket.socket(fileno=int(os.environ['AGENTFW_PROVIDER_CHANNEL']))
s.send(b'sw-provider-ready/1')
assert json.loads(s.recv(16385)) == {'ANTHROPIC_API_KEY':'owned-channel-canary'}
"#,
        );
        assert_eq!(bootstrap.code.metadata().unwrap().nlink(), 0);
        assert!(
            unsafe { libc::fcntl(bootstrap.code.as_raw_fd(), libc::F_GET_SEALS) }
                & libc::F_SEAL_WRITE
                != 0
        );
        assert!(!command
            .get_envs()
            .any(|(key, _)| super::super::PROVIDER_ENV.contains(&key.to_str().unwrap())));
        let mut child = command.spawn().unwrap();
        bootstrap.deliver(child.id()).unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn provider_channel_refuses_forked_sender_and_ignored_preload_without_releasing_input() {
        for script in [
            r#"
import os,socket
s=socket.socket(fileno=int(os.environ['AGENTFW_PROVIDER_CHANNEL']))
if os.fork()==0:
 s.send(b'sw-provider-ready/1')
 try: value=s.recv(16385); os._exit(5 if value else 0)
 except OSError: os._exit(0)
_,status=os.wait(); raise SystemExit(os.waitstatus_to_exitcode(status))
"#,
            "pass",
        ] {
            let (mut command, bootstrap, _private) = prepared(script);
            let mut child = command.spawn().unwrap();
            assert!(bootstrap.deliver(child.id()).is_err());
            assert!(child.wait().unwrap().success());
        }
    }
}
