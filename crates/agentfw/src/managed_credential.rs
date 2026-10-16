// SPDX-License-Identifier: Apache-2.0
//! Explicit, fail-closed managed Agent enrollment credential sources (SOU-55).
//! A selected file is loaded before each request; env credentials are never
//! reused if that file is missing, unsafe or malformed.

use anyhow::{ensure, Context, Result};
use std::path::PathBuf;

#[derive(Debug)]
pub enum CredentialSource {
    Environment(String),
    File(PathBuf),
}

impl CredentialSource {
    pub fn from_environment() -> Result<Self> {
        if let Some(value) = std::env::var_os("SOUP_MANAGED_AGENT_TOKEN_FILE") {
            let path = PathBuf::from(value);
            ensure!(path.is_absolute() && path.file_name().is_some(),
                "managed Agent token file must be an absolute filename");
            return Ok(Self::File(path));
        }
        let token = std::env::var("SOUP_MANAGED_AGENT_TOKEN")
            .context("missing separate Agent credential")?;
        validate_token(&token)?;
        Ok(Self::Environment(token))
    }

    pub fn load(&self) -> Result<String> {
        match self {
            Self::Environment(token) => Ok(token.clone()),
            Self::File(path) => load_private_token(path),
        }
    }
}

fn validate_token(value: &str) -> Result<()> {
    ensure!(value.len() == 52 && value.starts_with("sw_agent_")
        && value.bytes().skip(9).all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid managed Agent credential");
    Ok(())
}

#[cfg(unix)]
fn load_private_token(path: &std::path::Path) -> Result<String> {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    ensure!(path.is_absolute() && path.file_name().is_some(), "invalid token file path");
    // O_NOFOLLOW refuses final-component symlinks; O_NONBLOCK avoids FIFOs
    // stalling on open even if path type changes between checks.
    let mut fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path).context("cannot open managed token file")?;
    let meta = fd.metadata().context("cannot inspect managed token file")?;
    ensure!(meta.is_file() && meta.len() <= 64 && meta.len() >= 52 && meta.nlink() == 1,
        "managed token file is not a bounded regular private file");
    ensure!(meta.uid() == unsafe { libc::geteuid() } && (meta.mode() & 0o077) == 0,
        "managed token file must belong to the Agent user and deny group/other access");
    let mut bytes = Vec::new();
    fd.take(65).read_to_end(&mut bytes).context("cannot read managed token file")?;
    ensure!(bytes.len() == 52, "invalid managed token file length");
    let token = String::from_utf8(bytes).context("invalid managed token file encoding")?;
    validate_token(&token)?;
    Ok(token)
}

#[cfg(not(unix))]
fn load_private_token(_path: &std::path::Path) -> Result<String> {
    anyhow::bail!("managed token file mode requires Unix private-file enforcement")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::{fs::PermissionsExt, ffi::OsStrExt}, time::Duration};

    fn write_private(path: &std::path::Path, token: &str) {
        fs::write(path, token).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn token(ch: char) -> String { format!("sw_agent_{}", ch.to_string().repeat(43)) }

    #[test]
    fn secure_file_reload_and_failure_no_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credential");
        let source = CredentialSource::File(path.clone());
        assert!(source.load().is_err());
        let one = token('a');
        write_private(&path, &one);
        assert_eq!(source.load().unwrap(), one);
        let next = dir.path().join("next");
        let two = token('b');
        write_private(&next, &two);
        fs::rename(&next, &path).unwrap();
        assert_eq!(source.load().unwrap(), two);
        fs::remove_file(&path).unwrap();
        assert!(source.load().is_err());
        write_private(&path, &token('c'));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(source.load().is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert!(source.load().is_err());
    }

    #[test]
    fn fifo_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe");
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        assert!(CredentialSource::File(path).load().is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
