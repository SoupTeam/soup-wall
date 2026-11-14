// SPDX-License-Identifier: Apache-2.0
//! Exact CA-byte custody for one installed Linux pilot host.
//!
//! The prepared entry sends an anonymous sealed descriptor. The launcher checks
//! it again and gives only the host an inherited high descriptor, exposed as
//! SSL_CERT_FILE=/proc/self/fd/N. No source path or CA bytes are logged.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Seek};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{ensure, Result};
use rustls_pki_types::pem::PemObject;
use sha2::{Digest, Sha256};

const MAX_CA_BYTES: u64 = 2 * 1024 * 1024;
const REQUIRED_SEALS: i32 =
    libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
const INVALID: &str = "provider_ca_input_invalid";

pub(crate) struct SelectedCa {
    fd: OwnedFd,
}

impl SelectedCa {
    /// This closure runs only in the exact forked host before exec. Other
    /// launcher children see the duplicate with CLOEXEC still set.
    pub(crate) fn install(&self, host: &mut Command) {
        let fd = self.fd.as_raw_fd();
        unsafe {
            host.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

fn certificate_only(raw: &[u8]) -> Result<()> {
    // The host consumes a PEM file. Reject non-certificate blocks and junk
    // that a permissive PEM iterator might otherwise silently ignore.
    let begin = b"-----BEGIN CERTIFICATE-----";
    let end = b"-----END CERTIFICATE-----";
    let mut open = false;
    let mut encoded = false;
    let mut blocks = 0usize;
    for line in raw.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line == begin {
            ensure!(!open, "{INVALID}");
            open = true;
            encoded = false;
        } else if line == end {
            ensure!(open && encoded, "{INVALID}");
            open = false;
            blocks += 1;
            ensure!(blocks <= 64, "{INVALID}");
        } else if open {
            ensure!(
                !line.is_empty()
                    && line.iter().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || *byte == b'+'
                            || *byte == b'/'
                            || *byte == b'='
                    }),
                "{INVALID}"
            );
            encoded = true;
        } else {
            ensure!(line.iter().all(u8::is_ascii_whitespace), "{INVALID}");
        }
    }
    ensure!(!open && blocks > 0, "{INVALID}");
    let mut parsed = 0;
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for certificate in rustls_pki_types::CertificateDer::pem_slice_iter(raw) {
        let certificate = certificate.map_err(|_| anyhow::anyhow!(INVALID))?;
        roots
            .add(certificate)
            .map_err(|_| anyhow::anyhow!(INVALID))?;
        parsed += 1;
    }
    ensure!(parsed == blocks, "{INVALID}");
    Ok(())
}

fn verified(fd: i32, expected: &str) -> Result<SelectedCa> {
    ensure!(
        fd >= 3
            && expected.len() == 64
            && expected
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{INVALID}"
    );
    // Ownership of this descriptor begins here. Closing it on every failure
    // keeps a malformed carrier from reaching any later subprocess.
    let mut input = unsafe { File::from_raw_fd(fd) };
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    let metadata = input.metadata().map_err(|_| anyhow::anyhow!(INVALID))?;
    ensure!(
        seals >= 0
            && seals & REQUIRED_SEALS == REQUIRED_SEALS
            && metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.nlink() == 0
            && (1..=MAX_CA_BYTES).contains(&metadata.len()),
        "{INVALID}"
    );
    let mut raw = Vec::new();
    input.rewind().map_err(|_| anyhow::anyhow!(INVALID))?;
    input
        .read_to_end(&mut raw)
        .map_err(|_| anyhow::anyhow!(INVALID))?;
    ensure!(raw.len() as u64 == metadata.len(), "{INVALID}");
    ensure!(
        format!("{:x}", Sha256::digest(&raw)) == expected,
        "{INVALID}"
    );
    certificate_only(&raw)?;
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 64) };
    ensure!(duplicate >= 64, "{INVALID}");
    Ok(SelectedCa {
        fd: unsafe { OwnedFd::from_raw_fd(duplicate) },
    })
}

pub(crate) fn bind(
    provider: &mut [(OsString, OsString)],
    sealed_provider: bool,
    ca_fd: Option<i32>,
    ca_sha256: Option<&str>,
) -> Result<Option<SelectedCa>> {
    if !sealed_provider {
        ensure!(ca_fd.is_none() && ca_sha256.is_none(), "{INVALID}");
        return Ok(None);
    }
    let selected = provider
        .iter_mut()
        .find(|(key, _)| key.as_os_str() == OsStr::new("SSL_CERT_FILE"));
    let Some((_, path)) = selected else {
        ensure!(ca_fd.is_none() && ca_sha256.is_none(), "{INVALID}");
        return Ok(None);
    };
    ensure!(!path.is_empty(), "{INVALID}");
    let (Some(fd), Some(expected)) = (ca_fd, ca_sha256) else {
        anyhow::bail!(INVALID);
    };
    let snapshot = verified(fd, expected)?;
    *path = format!("/proc/self/fd/{}", snapshot.fd.as_raw_fd()).into();
    Ok(Some(snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // Public fixture certificate only; no private key or provider credential.
    const CA: &[u8] = include_bytes!("../../../proxy/tests/fixtures/saml/local-idp-cert.pem");

    fn sealed(bytes: &[u8]) -> i32 {
        let name = std::ffi::CString::new("sou195-ca-fixture").unwrap();
        let fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC)
        };
        assert!(fd >= 3);
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, REQUIRED_SEALS) },
            0
        );
        std::mem::forget(file);
        fd
    }

    #[test]
    fn sealed_ca_requires_matching_hash_and_explicit_selected_path() {
        let hash = format!("{:x}", Sha256::digest(CA));
        let mut provider = vec![("SSL_CERT_FILE".into(), "/operator/ca.pem".into())];
        let snapshot = bind(&mut provider, true, Some(sealed(CA)), Some(&hash))
            .unwrap()
            .unwrap();
        assert!(provider[0]
            .1
            .to_string_lossy()
            .starts_with("/proc/self/fd/"));
        assert_eq!(
            snapshot.fd.as_raw_fd().to_string(),
            provider[0].1.to_string_lossy().rsplit('/').next().unwrap()
        );
        assert!(
            unsafe { libc::fcntl(snapshot.fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC != 0
        );
        assert!(bind(&mut provider, true, Some(sealed(CA)), Some(&"0".repeat(64))).is_err());
    }

    #[test]
    fn whitespace_separated_certificate_bundle_remains_exact_bytes() {
        let mut bundle = Vec::new();
        bundle.extend_from_slice(b" \t\n");
        bundle.extend_from_slice(CA);
        bundle.extend_from_slice(b"\n \t\n");
        bundle.extend_from_slice(CA);
        bundle.extend_from_slice(b"\n\t\n");
        let hash = format!("{:x}", Sha256::digest(&bundle));
        let mut provider = vec![("SSL_CERT_FILE".into(), "/operator/ca.pem".into())];
        assert!(
            bind(&mut provider, true, Some(sealed(&bundle)), Some(&hash))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn absent_selection_or_descriptor_never_becomes_default_trust() {
        let hash = format!("{:x}", Sha256::digest(CA));
        let mut none = vec![("ANTHROPIC_API_KEY".into(), "fixture".into())];
        assert!(bind(&mut none, true, Some(sealed(CA)), Some(&hash)).is_err());
        let mut selected = vec![("SSL_CERT_FILE".into(), "/operator/ca.pem".into())];
        assert!(bind(&mut selected, true, None, None).is_err());
        assert!(bind(&mut selected, false, Some(sealed(CA)), Some(&hash)).is_err());
    }

    #[test]
    fn non_certificate_or_unsealed_material_refuses() {
        let hash = format!("{:x}", Sha256::digest(b"not a certificate"));
        let mut selected = vec![("SSL_CERT_FILE".into(), "/operator/ca.pem".into())];
        assert!(bind(
            &mut selected,
            true,
            Some(sealed(b"not a certificate")),
            Some(&hash)
        )
        .is_err());
        let name = std::ffi::CString::new("sou195-unsealed-fixture").unwrap();
        let fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC)
        };
        assert!(fd >= 3);
        assert!(bind(&mut selected, true, Some(fd), Some(&hash)).is_err());
    }
}
