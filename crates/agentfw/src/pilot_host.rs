// SPDX-License-Identifier: Apache-2.0
//! Executable configuration boundary for the pinned Linux pilot host (SOU-117).
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
mod exec_boundary;

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

/// Restrict successful host/descendant execs to the already selected runtime
/// assets. In particular the host's internal PATH Git probes must not exec a
/// diagnostic process carrying the host's provider environment.
pub(crate) fn restrict_exec(
    command: &mut Command,
    claude: &Path,
    agent: &Path,
    profiles: [&Path; 2],
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut allowed = vec![
            claude.to_path_buf(),
            agent.to_path_buf(),
            "/usr/bin/env".into(),
        ];
        for path in profiles {
            let profile = crate::mcp::server_profile::ProfileConfig::read(&fs::read(path)?)?;
            allowed.extend([profile.runtime_path, profile.bwrap_path]);
            allowed.extend(profile.libraries.into_iter().map(|library| library.path));
            allowed.extend(profile.git.into_iter().map(|library| library.path));
            allowed.extend(profile.git_launcher.into_iter().map(|library| library.path));
        }
        // This is the explicit operator/selected classifier interpreter already
        // passed through the collector's finite role environment.
        allowed.push(
            std::env::var_os("AGENTFW_CLASSIFIER_PYTHON")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| "/usr/bin/python3".into()),
        );
        // An operator may have installed the selected Git at the very pathname
        // used by Claude's ambient Git probes. Such an inventory cannot separate
        // the two roles: refuse rather than granting that diagnostic execution.
        use std::os::unix::fs::MetadataExt;
        let system_git = ["/usr/bin/git", "/bin/git"]
            .into_iter()
            .filter_map(|path| fs::metadata(path).ok())
            .map(|meta| (meta.dev(), meta.ino()))
            .collect::<std::collections::BTreeSet<_>>();
        for path in &allowed {
            let meta = fs::metadata(path)?;
            ensure!(
                !system_git.contains(&(meta.dev(), meta.ino())),
                "provider_host_system_git_conflict"
            );
        }
        exec_boundary::install(command, &allowed).context("provider_host_exec_boundary_unavailable")
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command, claude, agent, profiles);
        anyhow::bail!("provider_host_exec_boundary_unsupported")
    }
}

fn configure(
    command: &mut Command,
    private: &Path,
    provider: Vec<(OsString, OsString)>,
) -> Result<()> {
    let home = private.join("host-home");
    let temporary = private.join("host-tmp");
    fs::create_dir(&home)?;
    fs::create_dir(&temporary)?;
    let settings = private.join("host-settings.json");
    fs::write(
        &settings,
        b"{\"disableAllHooks\":true,\"enabledPlugins\":{}}\n",
    )?;
    command
        .env_clear()
        .envs(provider)
        .env("PATH", "/usr/bin:/bin")
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
            "/usr/bin:/bin"
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

    #[test]
    fn arbitrary_executable_cannot_claim_pinned_host_isolation() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("unverified-host");
        fs::write(&file, b"not pinned").unwrap();
        assert!(validate(&file, false).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_exec_boundary_refuses_unselected_helpers_and_replaced_executables() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let selected = root.path().join("selected");
        fs::copy("/usr/bin/true", &selected).unwrap();
        fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).unwrap();
        let mut allowed = vec![selected.clone()];
        // The kernel checks the ELF interpreter as an executable too.
        for interpreter in ["/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"] {
            if Path::new(interpreter).exists() {
                allowed.push(interpreter.into());
            }
        }
        let mut good = Command::new(&selected);
        exec_boundary::install(&mut good, &allowed).unwrap();
        assert!(good.status().unwrap().success());
        let marker = root.path().join("must-not-exist");
        let mut bad = Command::new("/usr/bin/touch");
        bad.arg(&marker)
            .env("ANTHROPIC_API_KEY", "owned-never-exec");
        exec_boundary::install(&mut bad, &allowed).unwrap();
        assert_eq!(bad.spawn().unwrap_err().raw_os_error(), Some(libc::EACCES));
        assert!(!marker.exists());
        let mut replaced = Command::new(&selected);
        exec_boundary::install(&mut replaced, &allowed).unwrap();
        fs::rename(&selected, root.path().join("previous")).unwrap();
        fs::copy("/usr/bin/true", &selected).unwrap();
        assert_eq!(
            replaced.spawn().unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
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
