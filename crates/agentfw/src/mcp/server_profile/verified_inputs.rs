// SPDX-License-Identifier: Apache-2.0
//! A single Ask's observations, never a persisted authority or an mtime cache.
//!
//! Only an already enabled kernel fs-verity measurement permits skipping byte
//! reads. All other inputs are hashed again. This code never enables fs-verity
//! or changes an installed asset. Metadata checks supplement, not replace, the
//! kernel proof, whose digest is deliberately distinct from the profile SHA.

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    canonical: PathBuf,
    kind: fs::FileType,
    size: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    unix: [u64; 9],
}

impl Identity {
    fn read(path: &Path, metadata: &fs::Metadata) -> anyhow::Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            canonical: path.canonicalize()?,
            kind: metadata.file_type(),
            size: metadata.len(),
            modified: metadata.modified()?,
            #[cfg(unix)]
            unix: [
                metadata.dev(),
                metadata.ino(),
                metadata.mode() as u64,
                metadata.uid() as u64,
                metadata.gid() as u64,
                metadata.nlink(),
                metadata.ctime() as u64,
                metadata.ctime_nsec() as u64,
                metadata.mtime_nsec() as u64,
            ],
        })
    }
}

#[derive(Clone)]
struct FileProof {
    identity: Identity,
    sha256: String,
    verity: Option<Vec<u8>>,
    lease: Option<std::sync::Arc<super::read_lease::Guard>>,
}

#[derive(Clone, Default)]
pub(super) struct Inputs {
    files: BTreeMap<PathBuf, FileProof>,
    entries: BTreeMap<PathBuf, Identity>,
    lease_owner: Option<std::sync::Arc<super::read_lease::Owner>>,
}

impl Inputs {
    pub(super) fn validate_leases(&self) -> anyhow::Result<()> {
        ensure!(
            self.files
                .values()
                .filter_map(|proof| proof.lease.as_ref())
                .all(|lease| lease.valid()),
            "selected asset read lease lost"
        );
        Ok(())
    }

    pub(super) fn counts(&self) -> (usize, usize, usize) {
        let immutable = self
            .files
            .values()
            .filter(|proof| proof.verity.is_some())
            .count();
        let leased = self
            .files
            .values()
            .filter(|proof| proof.lease.is_some())
            .count();
        (immutable, leased, self.files.len() - immutable - leased)
    }
}

pub(super) enum Verification<'a> {
    Full,
    Capture(&'a mut Inputs),
    Resume(&'a Inputs),
}

impl Verification<'_> {
    pub(super) fn entry(&mut self, path: &Path) -> anyhow::Result<()> {
        if matches!(self, Self::Full) {
            return Ok(());
        }
        let identity = Identity::read(path, &fs::symlink_metadata(path)?)?;
        match self {
            Self::Full => return Ok(()),
            Self::Capture(inputs) => {
                if let Some(previous) = inputs.entries.insert(path.to_owned(), identity.clone()) {
                    ensure!(
                        previous == identity,
                        "selected asset changed during verification"
                    );
                }
            }
            Self::Resume(inputs) => ensure!(
                inputs.entries.get(path) == Some(&identity),
                "selected asset identity or metadata changed during approval"
            ),
        }
        Ok(())
    }

    pub(super) fn digest(&mut self, path: &Path, size: u64) -> anyhow::Result<String> {
        if matches!(self, Self::Full) {
            let file = super::open_regular(path)?;
            let mut hash = Sha256::new();
            let count = std::io::copy(&mut file.take(size + 1), &mut hash)?;
            ensure!(count == size, "selected asset changed during hashing");
            return Ok(format!("{:x}", hash.finalize()));
        }
        self.entry(path)?;
        let mut file = super::open_regular(path)?;
        let before = Identity::read(path, &file.metadata()?)?;
        ensure!(
            before.size == size && Identity::read(path, &fs::metadata(path)?)? == before,
            "selected asset size changed during verification"
        );
        let verity = measure(&file)?;
        let previous = match self {
            Self::Resume(inputs) => Some(
                inputs
                    .files
                    .get(path)
                    .context("selected asset was not verified before approval")?
                    .clone(),
            ),
            Self::Capture(inputs) => inputs.files.get(path).cloned(),
            Self::Full => None,
        };
        if let Some(previous) = &previous {
            ensure!(
                previous.identity == before,
                "selected asset identity or metadata changed during approval"
            );
            if let Some(lease) = &previous.lease {
                ensure!(lease.valid(), "selected asset read lease lost");
            }
            if let Some(expected) = &previous.verity {
                // A missing/failed proof cannot downgrade to a cached content
                // hash. A new Ask/process must establish its own observations.
                ensure!(
                    verity.as_ref() == Some(expected),
                    "selected asset immutable proof lost"
                );
            }
            if previous.verity.is_some() || previous.lease.is_some() {
                ensure!(
                    Identity::read(path, &file.metadata()?)? == before
                        && Identity::read(path, &fs::metadata(path)?)? == before,
                    "selected asset metadata changed during verification"
                );
                let sha256 = previous.sha256.clone();
                self.entry(path)?;
                return Ok(sha256);
            }
        }
        let lease = if verity.is_none() && previous.is_none() && size >= 65_536 {
            if let Self::Capture(inputs) = self {
                if inputs.lease_owner.is_none() {
                    inputs.lease_owner = super::read_lease::Owner::new(&file);
                }
                match &inputs.lease_owner {
                    Some(owner) => owner.acquire(&file)?,
                    None => None,
                }
            } else {
                None
            }
        } else {
            None
        };
        let mut hash = Sha256::new();
        let count = std::io::copy(&mut file.by_ref().take(size + 1), &mut hash)?;
        ensure!(
            count == size
                && Identity::read(path, &file.metadata()?)? == before
                && Identity::read(path, &fs::metadata(path)?)? == before,
            "selected asset changed during hashing"
        );
        let sha256 = format!("{:x}", hash.finalize());
        if let Some(lease) = &lease {
            ensure!(
                lease.valid(),
                "selected asset read lease lost during capture"
            );
        }
        if let Some(previous) = &previous {
            ensure!(
                sha256 == previous.sha256,
                "selected asset bytes changed during approval"
            );
        }
        if let Self::Capture(inputs) = self {
            let proof = FileProof {
                identity: before,
                sha256: sha256.clone(),
                verity,
                lease,
            };
            if let Some(previous) = inputs.files.insert(path.to_owned(), proof.clone()) {
                ensure!(
                    previous.identity == proof.identity
                        && previous.sha256 == proof.sha256
                        && previous.verity == proof.verity,
                    "selected asset changed during verification"
                );
            }
        }
        self.entry(path)?;
        Ok(sha256)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn measure(file: &fs::File) -> anyhow::Result<Option<Vec<u8>>> {
    use std::os::fd::AsRawFd;
    // _IOWR('f', 134, struct fsverity_digest): the UAPI header is four
    // bytes, independently of the capacity of its variable trailing digest.
    const FS_IOC_MEASURE_VERITY: libc::Ioctl = 0xc004_6686_u32 as libc::Ioctl;
    #[repr(C)]
    struct Measurement {
        algorithm: u16,
        size: u16,
        digest: [u8; 64],
    }
    let mut value = Measurement {
        algorithm: 0,
        size: 64,
        digest: [0; 64],
    };
    if unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_MEASURE_VERITY, &mut value) } != 0 {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::ENODATA | libc::ENOTTY | libc::EOPNOTSUPP)
        ) {
            return Ok(None);
        }
        return Err(error).context("selected asset immutable proof unavailable");
    }
    ensure!(
        matches!((value.algorithm, value.size), (1, 32) | (2, 64)),
        "unsupported selected asset immutable proof"
    );
    let mut proof = value.algorithm.to_ne_bytes().to_vec();
    proof.extend_from_slice(&value.digest[..value.size as usize]);
    Ok(Some(proof))
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn measure(_file: &fs::File) -> anyhow::Result<Option<Vec<u8>>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutable_files_are_read_again_and_replacement_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asset");
        fs::write(&path, b"original").unwrap();
        let mut inputs = Inputs::default();
        let original = Verification::Capture(&mut inputs).digest(&path, 8).unwrap();
        assert_eq!(
            Verification::Resume(&inputs).digest(&path, 8).unwrap(),
            original
        );
        fs::write(&path, b"tampered").unwrap();
        assert!(Verification::Resume(&inputs).digest(&path, 8).is_err());
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"original").unwrap();
        assert!(Verification::Resume(&inputs).digest(&path, 8).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn identical_bytes_do_not_hide_mode_or_symlink_changes() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asset");
        fs::write(&path, b"original").unwrap();
        let mut inputs = Inputs::default();
        Verification::Capture(&mut inputs).digest(&path, 8).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(Verification::Resume(&inputs).digest(&path, 8).is_err());
        fs::rename(&path, dir.path().join("other")).unwrap();
        symlink("other", &path).unwrap();
        assert!(Verification::Resume(&inputs).digest(&path, 8).is_err());
    }

    #[test]
    fn a_missing_kernel_proof_never_uses_a_saved_sha() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asset");
        fs::write(&path, b"original").unwrap();
        let mut inputs = Inputs::default();
        Verification::Capture(&mut inputs).digest(&path, 8).unwrap();
        inputs.files.get_mut(&path).unwrap().verity = Some(vec![0; 34]);
        assert!(Verification::Resume(&inputs).digest(&path, 8).is_err());
    }

    #[test]
    fn matching_metadata_cannot_substitute_for_a_kernel_proof() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asset");
        fs::write(&path, b"original").unwrap();
        let mut inputs = Inputs::default();
        Verification::Capture(&mut inputs).digest(&path, 8).unwrap();
        fs::write(&path, b"tampered").unwrap();
        // Model a write which evades a metadata-only shortcut. The byte hash
        // must still reject, independently of mtime/ctime/identity matching.
        let current = Identity::read(&path, &fs::metadata(&path).unwrap()).unwrap();
        inputs.entries.insert(path.clone(), current.clone());
        inputs.files.get_mut(&path).unwrap().identity = current;
        assert!(Verification::Resume(&inputs).digest(&path, 8).is_err());
    }

    #[test]
    fn tree_addition_removal_and_directory_replacement_are_not_reused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("package");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("asset"), b"original").unwrap();
        let mut inputs = Inputs::default();
        let original =
            super::super::package_tree_sha256_with(&root, &mut Verification::Capture(&mut inputs))
                .unwrap();
        assert_eq!(
            super::super::package_tree_sha256_with(&root, &mut Verification::Resume(&inputs))
                .unwrap(),
            original
        );
        fs::write(root.join("extra"), b"unverified").unwrap();
        assert!(
            super::super::package_tree_sha256_with(&root, &mut Verification::Resume(&inputs))
                .is_err()
        );
        fs::remove_file(root.join("extra")).unwrap();
        fs::remove_file(root.join("asset")).unwrap();
        assert!(
            super::super::package_tree_sha256_with(&root, &mut Verification::Resume(&inputs))
                .is_err()
        );
        fs::rename(&root, dir.path().join("old")).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("asset"), b"original").unwrap();
        assert!(
            super::super::package_tree_sha256_with(&root, &mut Verification::Resume(&inputs))
                .is_err()
        );
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[ignore = "requires an operator-owned, already fs-verity-enabled fixture on native Linux"]
    fn native_verity_reuse_requires_a_real_immutable_inode() {
        let path = PathBuf::from(
            std::env::var_os("SOU124_VERITY_FIXTURE").expect("explicit immutable fixture required"),
        );
        let size = fs::metadata(&path).unwrap().len();
        assert!(size <= super::super::MAX_TREE_BYTES);
        let mut inputs = Inputs::default();
        let digest = Verification::Capture(&mut inputs)
            .digest(&path, size)
            .unwrap();
        assert_eq!(inputs.counts(), (1, 0, 0));
        // The in-memory SHA is reused only with the real measured digest.
        assert_eq!(
            Verification::Resume(&inputs).digest(&path, size).unwrap(),
            digest
        );
        assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
        inputs
            .files
            .get_mut(&path)
            .unwrap()
            .verity
            .as_mut()
            .unwrap()[2] ^= 1;
        assert!(Verification::Resume(&inputs).digest(&path, size).is_err());
    }
}
