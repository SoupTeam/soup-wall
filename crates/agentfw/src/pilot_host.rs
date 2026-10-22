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
const PROVIDER_ENV: &[&str] = &[
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

pub(crate) fn isolate(command: &mut Command, private: &Path) -> Result<()> {
    let provider = PROVIDER_ENV
        .iter()
        .filter_map(|key| std::env::var_os(key).map(|value| (OsString::from(key), value)))
        .collect::<Vec<_>>();
    configure(command, private, provider)
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
}
