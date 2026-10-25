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
use std::time::Duration;

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
        parent.set_read_timeout(Some(Duration::from_secs(3)))?;
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

    pub(crate) fn confirm(self) -> Result<()> {
        let Self { mut parent, child } = self;
        drop(child);
        let mut ready = [0; 19];
        parent.read_exact(&mut ready)?;
        ensure!(
            &ready == b"sw-provider-ready/1",
            "provider_child_environment_unavailable"
        );
        let mut tail = [0];
        ensure!(
            parent.read(&mut tail)? == 0,
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
            assert_eq!(guard.confirm().is_ok(), installed);
            assert!(child.wait().unwrap().success());
        }
    }
}
