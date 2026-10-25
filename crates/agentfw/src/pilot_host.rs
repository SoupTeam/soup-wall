// SPDX-License-Identifier: Apache-2.0
//! Executable configuration boundary for the pinned Linux pilot host (SOU-117).
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};

pub(crate) const CLAUDE_SHA256: &str =
    "fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7";

// These are operator-selected provider transport inputs, never project settings.
pub(crate) const PROVIDER_ENV: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
];

fn reject_managed_sources(root: &Path) -> Result<()> {
    for name in [
        "managed-settings.json",
        "managed-settings.d",
        "managed-mcp.json",
    ] {
        match fs::symlink_metadata(root.join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => anyhow::bail!("pilot host isolation does not support machine-managed settings or MCP configuration"),
        }
    }
    Ok(())
}

pub(crate) fn validate(claude: &Path, fixtures: bool) -> Result<()> {
    if fixtures {
        return Ok(());
    }
    ensure!(
        cfg!(all(target_os = "linux", target_arch = "x86_64")),
        "project-isolated pilot requires the pinned Linux x86_64 Claude host"
    );
    reject_managed_sources(Path::new("/etc/claude-code"))?;
    let bytes = fs::read(claude).context("read pinned pilot host")?;
    ensure!(
        format!("{:x}", Sha256::digest(bytes)) == CLAUDE_SHA256,
        "project-isolated pilot requires repository-pinned Claude Code 2.1.251"
    );
    Ok(())
}

/// Consume the prepared entry's anonymous sealed carrier, or preserve explicit
/// operator environment support for existing direct pilot-launch invocations.
pub(crate) fn provider_inputs(fd: Option<i32>) -> Result<Vec<(OsString, OsString)>> {
    let Some(fd) = fd else {
        return Ok(PROVIDER_ENV
            .iter()
            .filter_map(|key| std::env::var_os(key).map(|value| (OsString::from(key), value)))
            .collect());
    };
    #[cfg(target_os = "linux")]
    {
        use std::io::{Read, Seek};
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::MetadataExt;
        ensure!(fd >= 3, "provider_input_invalid");
        // The descriptor is consumed exactly once; CLOEXEC is also required so
        // it cannot be inherited by the host, collector or any helper.
        ensure!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0,
            "provider_input_invalid"
        );
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let descriptor = file.as_raw_fd();
        ensure!(
            unsafe { libc::fcntl(descriptor, libc::F_GETFD) } & libc::FD_CLOEXEC != 0
                || unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
            "provider_input_invalid"
        );
        let seals = unsafe { libc::fcntl(descriptor, libc::F_GET_SEALS) };
        let required =
            libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
        let meta = file.metadata()?;
        ensure!(
            seals >= 0
                && seals & required == required
                && meta.is_file()
                && meta.len() <= 16384
                && meta.nlink() == 0,
            "provider_input_invalid"
        );
        file.rewind()?;
        let mut raw = Vec::new();
        file.take(16385).read_to_end(&mut raw)?;
        ensure!(raw.len() <= 16384, "provider_input_invalid");
        let crate::mcp::admission::Strict(value) =
            serde_json::from_slice(&raw).map_err(|_| anyhow::anyhow!("provider_input_invalid"))?;
        let values: std::collections::BTreeMap<String, String> =
            serde_json::from_value(value).map_err(|_| anyhow::anyhow!("provider_input_invalid"))?;
        ensure!(
            values
                .keys()
                .all(|key| PROVIDER_ENV.contains(&key.as_str()))
                && values.values().all(|value| !value.contains('\0')),
            "provider_input_invalid"
        );
        Ok(values
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        anyhow::bail!("provider_input_unsupported");
    }
}

pub(crate) fn isolate(
    command: &mut Command,
    private: &Path,
    provider: Vec<(OsString, OsString)>,
) -> Result<()> {
    configure(command, private, provider)
}

fn configure(
    command: &mut Command,
    private: &Path,
    provider: Vec<(OsString, OsString)>,
) -> Result<()> {
    let home = private.join("host-home");
    let temporary = private.join("host-tmp");
    let helper_path = private.join("host-path");
    fs::create_dir(&home)?;
    fs::create_dir(&temporary)?;
    fs::create_dir(&helper_path)?;
    let settings = private.join("host-settings.json");
    fs::write(
        &settings,
        b"{\"disableAllHooks\":true,\"enabledPlugins\":{}}\n",
    )?;
    command
        .env_clear()
        .envs(provider)
        .env("PATH", &helper_path)
        .env("HOME", &home)
        .env("TMPDIR", &temporary)
        .env("LANG", "C.UTF-8")
        .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
        .arg("--setting-sources")
        .arg("")
        .arg("--settings")
        .arg(settings);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_sources_including_dangling_symlinks_are_unsupported() {
        let root = tempfile::tempdir().unwrap();
        reject_managed_sources(root.path()).unwrap();
        for name in [
            "managed-settings.json",
            "managed-settings.d",
            "managed-mcp.json",
        ] {
            let path = root.path().join(name);
            fs::write(&path, b"{}").unwrap();
            assert!(reject_managed_sources(root.path()).is_err());
            fs::remove_file(&path).unwrap();
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink("missing", &path).unwrap();
                assert!(reject_managed_sources(root.path()).is_err());
                fs::remove_file(&path).unwrap();
            }
        }
    }

    #[test]
    fn project_environment_cannot_select_executable_configuration() {
        let private = tempfile::tempdir().unwrap();
        let mut command = Command::new("/trusted/claude");
        for key in [
            "PATH",
            "LD_PRELOAD",
            "PYTHONPATH",
            "BASH_ENV",
            "CLAUDE_CONFIG_DIR",
            "CLAUDE_CODE_SETTINGS_PATH",
            "CLAUDE_CODE_PLUGIN_CACHE_DIR",
            "AGENTFW_TOKEN",
        ] {
            command.env(key, "/untrusted/project");
        }
        configure(
            &mut command,
            private.path(),
            vec![("ANTHROPIC_API_KEY".into(), "owned-provider".into())],
        )
        .unwrap();
        let env = command
            .get_envs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            env.get(std::ffi::OsStr::new("PATH")).unwrap().unwrap(),
            private.path().join("host-path").as_os_str()
        );
        for key in [
            "LD_PRELOAD",
            "PYTHONPATH",
            "BASH_ENV",
            "CLAUDE_CODE_SETTINGS_PATH",
            "CLAUDE_CODE_PLUGIN_CACHE_DIR",
            "AGENTFW_TOKEN",
        ] {
            assert!(!env.contains_key(std::ffi::OsStr::new(key)));
        }
        assert_eq!(
            fs::read_dir(private.path().join("host-path"))
                .unwrap()
                .count(),
            0
        );
        let args = command.get_args().collect::<Vec<_>>();
        assert_eq!(args[0], "--setting-sources");
        assert_eq!(args[1], "");
        assert_eq!(
            env.get(std::ffi::OsStr::new("ANTHROPIC_API_KEY"))
                .unwrap()
                .unwrap(),
            "owned-provider"
        );
        assert_eq!(
            fs::read_to_string(private.path().join("host-settings.json")).unwrap(),
            "{\"disableAllHooks\":true,\"enabledPlugins\":{}}\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_host_path_refuses_ambient_git_without_spawning_a_helper() {
        let private = tempfile::tempdir().unwrap();
        let mut command = Command::new("/usr/bin/python3");
        command.arg("-c").arg(
            r#"
import os,subprocess
assert os.environ['ANTHROPIC_API_KEY']=='owned-host-only'
try: subprocess.run(['git','--version'],check=True)
except FileNotFoundError: pass
else: raise AssertionError('ambient helper executed')
"#,
        );
        configure(
            &mut command,
            private.path(),
            vec![("ANTHROPIC_API_KEY".into(), "owned-host-only".into())],
        )
        .unwrap();
        assert!(command.status().unwrap().success());
    }

    #[test]
    fn arbitrary_executable_cannot_claim_pinned_host_isolation() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("unverified-host");
        fs::write(&file, b"not pinned").unwrap();
        assert!(validate(&file, false).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_provider_carrier_is_consumed_and_never_accepts_extra_or_duplicate_authority() {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
        fn carrier(bytes: &[u8], sealed: bool) -> i32 {
            let name = std::ffi::CString::new("owned-provider-test").unwrap();
            let fd = unsafe {
                libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
            };
            assert!(fd >= 3);
            let mut file = unsafe { fs::File::from_raw_fd(fd) };
            file.write_all(bytes).unwrap();
            if sealed {
                assert_eq!(
                    unsafe {
                        libc::fcntl(
                            file.as_raw_fd(),
                            libc::F_ADD_SEALS,
                            libc::F_SEAL_SEAL
                                | libc::F_SEAL_WRITE
                                | libc::F_SEAL_GROW
                                | libc::F_SEAL_SHRINK,
                        )
                    },
                    0
                );
            }
            file.into_raw_fd()
        }
        let fd = carrier(br#"{"ANTHROPIC_API_KEY":"owned-api-canary"}"#, true);
        let values = provider_inputs(Some(fd)).unwrap();
        assert_eq!(
            values,
            vec![("ANTHROPIC_API_KEY".into(), "owned-api-canary".into())]
        );
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        for bytes in [
            br#"{"LD_PRELOAD":"owned-loader"}"#.as_slice(),
            br#"{"ANTHROPIC_API_KEY":"a","ANTHROPIC_API_KEY":"b"}"#.as_slice(),
            br#"{"ANTHROPIC_API_KEY":"bad\u0000value"}"#.as_slice(),
            b"not-json",
        ] {
            assert!(provider_inputs(Some(carrier(bytes, true))).is_err());
        }
        assert!(provider_inputs(Some(-1)).is_err());
        // An unopened high descriptor must be rejected before File takes ownership.
        let unopened = 1_000_000;
        assert_eq!(unsafe { libc::fcntl(unopened, libc::F_GETFD) }, -1);
        assert!(provider_inputs(Some(unopened)).is_err());
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(provider_inputs(Some(socket.into_raw_fd())).is_err());
        assert!(provider_inputs(Some(carrier(b"{}", false))).is_err());
        assert!(provider_inputs(Some(carrier(&[b'x'; 16385], true))).is_err());
    }
}
