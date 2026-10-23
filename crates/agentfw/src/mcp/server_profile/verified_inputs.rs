// SPDX-License-Identifier: Apache-2.0
//! A single Ask's observations, never a persisted authority or an mtime cache.
//!
//! Only an already enabled kernel fs-verity measurement or retained valid local
//! read lease permits skipping byte reads. Other inputs are hashed again. This
//! code never enables fs-verity or changes an installed asset. Metadata checks supplement, not replace, the
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
    #[cfg(windows)]
    windows: [u64; 5],
}

impl Identity {
    fn read(path: &Path, metadata: &fs::Metadata) -> anyhow::Result<Self> {
        Self::with_canonical(path, metadata, canonical_identity(path, metadata)?)
    }

    fn with_canonical(
        _path: &Path,
        metadata: &fs::Metadata,
        canonical: PathBuf,
    ) -> anyhow::Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            canonical,
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
            #[cfg(windows)]
            windows: windows_identity(_path, metadata)?,
        })
    }
    fn read_open(path: &Path, file: &fs::File) -> anyhow::Result<Self> {
        let metadata = file.metadata()?;
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let canonical = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
                .or_else(|_| path.canonicalize())?;
            ensure!(
                canonical.is_absolute(),
                "selected asset canonical identity invalid"
            );
            Self::with_canonical(path, &metadata, canonical)
        }
        #[cfg(not(target_os = "linux"))]
        Self::read(path, &metadata)
    }

    fn matches_metadata(&self, path: &Path, metadata: &fs::Metadata) -> anyhow::Result<bool> {
        Ok(*self == Self::with_canonical(path, metadata, self.canonical.clone())?)
    }
}

#[cfg(target_os = "linux")]
fn canonical_identity(path: &Path, observed: &fs::Metadata) -> anyhow::Result<PathBuf> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    if observed.is_symlink() {
        // Preserve resolved-target identity for links, including chains/escapes.
        return Ok(path.canonicalize()?);
    }
    // O_PATH follows the final target just like canonicalize, without opening
    // its bytes. Symlink entry identity is checked separately by entry().
    // /proc/self/fd reports that exact retained dentry's canonical path, avoiding
    // a separate userspace lstat traversal for every ancestor of every file.
    // Compare all retained metadata before accepting its path; a raced lookup
    // is an error, not a metadata/cache shortcut. Unsupported proc uses realpath.
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)?;
    let current = file.metadata()?;
    ensure!(
        current.file_type() == observed.file_type()
            && current.len() == observed.len()
            && current.modified()? == observed.modified()?
            && current.dev() == observed.dev()
            && current.ino() == observed.ino()
            && current.mode() == observed.mode()
            && current.uid() == observed.uid()
            && current.gid() == observed.gid()
            && current.nlink() == observed.nlink()
            && current.ctime() == observed.ctime()
            && current.ctime_nsec() == observed.ctime_nsec(),
        "selected asset changed during identity lookup"
    );
    match fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())) {
        Ok(value) if value.is_absolute() => Ok(value),
        _ => Ok(path.canonicalize()?),
    }
}

#[cfg(not(target_os = "linux"))]
fn canonical_identity(path: &Path, _observed: &fs::Metadata) -> anyhow::Result<PathBuf> {
    Ok(path.canonicalize()?)
}

#[cfg(windows)]
fn windows_identity(path: &Path, metadata: &fs::Metadata) -> anyhow::Result<[u64; 5]> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    };
    // Stable Win32 handle queries are used instead of unstable MetadataExt
    // identity methods. Directory handles require BACKUP_SEMANTICS.
    let file = fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(
        file.metadata()?.file_type() == metadata.file_type()
            && file.metadata()?.len() == metadata.len()
            && file.metadata()?.modified()? == metadata.modified()?,
        "selected asset changed during identity query"
    );
    Ok([
        info.dwFileAttributes as u64,
        ((info.ftCreationTime.dwHighDateTime as u64) << 32)
            | info.ftCreationTime.dwLowDateTime as u64,
        info.dwVolumeSerialNumber as u64,
        info.nNumberOfLinks as u64,
        ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
    ])
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
        self.observe_identity(path, identity)
    }

    fn observe_identity(&mut self, path: &Path, identity: Identity) -> anyhow::Result<()> {
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
        self.digest_with(path, size, None)
    }

    pub(super) fn tree_digest(
        &mut self,
        path: &Path,
        metadata: &fs::Metadata,
    ) -> anyhow::Result<String> {
        self.digest_with(path, metadata.len(), Some(metadata))
    }

    fn close_identity(
        &mut self,
        path: &Path,
        file: &fs::File,
        before: &Identity,
        tree: bool,
    ) -> anyhow::Result<()> {
        if tree {
            let after = Identity::read_open(path, file)?;
            ensure!(
                after == *before && before.matches_metadata(path, &fs::symlink_metadata(path)?)?,
                "selected asset changed during verification"
            );
            self.observe_identity(path, after)
        } else {
            ensure!(
                Identity::read(path, &file.metadata()?)? == *before
                    && Identity::read(path, &fs::metadata(path)?)? == *before,
                "selected asset metadata changed during verification"
            );
            self.entry(path)
        }
    }

    fn digest_with(
        &mut self,
        path: &Path,
        size: u64,
        tree_metadata: Option<&fs::Metadata>,
    ) -> anyhow::Result<String> {
        if matches!(self, Self::Full) {
            let file = super::open_regular(path)?;
            let mut hash = Sha256::new();
            let count = std::io::copy(&mut file.take(size + 1), &mut hash)?;
            ensure!(count == size, "selected asset changed during hashing");
            return Ok(format!("{:x}", hash.finalize()));
        }
        // Only the package walker uses this path: it binds every ancestor
        // directory before/after descent and handles symlinks separately. A
        // regular leaf is bound by its exact opened descriptor plus both lstat
        // observations; no extra ancestor traversal/O_PATH open is necessary.
        let tree = cfg!(target_os = "linux") && tree_metadata.is_some();
        if !tree {
            self.entry(path)?;
        }
        let mut file = super::open_regular(path)?;
        let before = if tree {
            Identity::read_open(path, &file)?
        } else {
            Identity::read(path, &file.metadata()?)?
        };
        let same_path = if let Some(metadata) = tree_metadata.filter(|_| tree) {
            metadata.is_file() && before.matches_metadata(path, metadata)?
        } else {
            Identity::read(path, &fs::metadata(path)?)? == before
        };
        ensure!(
            before.size == size && same_path,
            "selected asset size changed during verification"
        );
        if tree {
            self.observe_identity(path, before.clone())?;
        }
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
                self.close_identity(path, &file, &before, tree)?;
                let sha256 = previous.sha256.clone();
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
        ensure!(count == size, "selected asset changed during hashing");
        self.close_identity(path, &file, &before, tree)?;
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
        Ok(sha256)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn measure(file: &fs::File) -> anyhow::Result<Option<Vec<u8>>> {
    use std::os::fd::AsRawFd;
    let mut value = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), value.as_mut_ptr()) } != 0 {
        return Ok(None); // Capture hashes; an existing proof cannot downgrade on resume.
    }
    verity_on_filesystem(unsafe { value.assume_init() }.f_type as u64, || {
        measure_kernel(file)
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn verity_on_filesystem<T>(
    kind: u64,
    operation: impl FnOnce() -> anyhow::Result<Option<T>>,
) -> anyhow::Result<Option<T>> {
    // Only kernel-enforced ext4/f2fs/btrfs verity is content authority. FUSE
    // forwards MEASURE_VERITY to its userspace server, which can forge a digest.
    // https://github.com/torvalds/linux/blob/v6.17/fs/fuse/ioctl.c
    if matches!(kind, 0xef53 | 0xf2f5_2010 | 0x9123_683e) {
        operation()
    } else {
        Ok(None)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn measure_kernel(file: &fs::File) -> anyhow::Result<Option<Vec<u8>>> {
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

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn userspace_or_remote_verity_claim_never_becomes_content_authority() {
        use std::cell::Cell;
        for kind in [0x6573_5546, 0x6969, 0xff53_4d42, 0x794c_7630, 0] {
            let queried = Cell::new(false);
            let forged = verity_on_filesystem(kind, || {
                queried.set(true);
                Ok(Some(vec![7; 34]))
            })
            .unwrap();
            assert!(
                !queried.get(),
                "untrusted filesystem ioctl must not be consulted"
            );
            assert!(
                forged.is_none(),
                "userspace measurement must force full hashing"
            );
        }
        assert_eq!(
            verity_on_filesystem(0xef53, || Ok(Some(vec![7; 34]))).unwrap(),
            Some(vec![7; 34])
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_path_identity_preserves_resolved_links_and_rejects_raced_metadata() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("actual");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("asset");
        fs::write(&file, b"original").unwrap();
        let alias = root.path().join("alias");
        symlink(&directory, &alias).unwrap();
        for path in [&file, &alias.join("asset"), &directory, &alias] {
            let metadata = fs::symlink_metadata(path).unwrap();
            assert_eq!(
                canonical_identity(path, &metadata).unwrap(),
                path.canonicalize().unwrap()
            );
        }
        let file_link = root.path().join("runtime-link");
        symlink(&file, &file_link).unwrap();
        let followed = fs::metadata(&file_link).unwrap();
        assert_eq!(
            canonical_identity(&file_link, &followed).unwrap(),
            file.canonicalize().unwrap()
        );
        let mut inputs = Inputs::default();
        let digest = Verification::Capture(&mut inputs)
            .digest(&file_link, 8)
            .unwrap();
        assert_eq!(
            Verification::Resume(&inputs).digest(&file_link, 8).unwrap(),
            digest
        );
        fs::remove_file(&file_link).unwrap();
        symlink(&file, &file_link).unwrap();
        assert!(Verification::Resume(&inputs).digest(&file_link, 8).is_err());
        let observed = fs::metadata(&file).unwrap();
        fs::rename(&file, directory.join("old")).unwrap();
        fs::write(&file, b"original").unwrap();
        assert!(canonical_identity(&file, &observed).is_err());
        let link_metadata = fs::symlink_metadata(&alias).unwrap();
        assert!(link_metadata.is_symlink());
        assert_eq!(
            canonical_identity(&alias, &link_metadata).unwrap(),
            directory.canonicalize().unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_symlink_target_is_usable_but_retargeting_never_reuses_approval() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let other = root.path().join("other");
        let runtime = root.path().join("runtime");
        fs::write(&target, b"same bytes").unwrap();
        fs::write(&other, b"same bytes").unwrap();
        symlink(&target, &runtime).unwrap();
        let mut inputs = Inputs::default();
        let digest = Verification::Capture(&mut inputs)
            .digest(&runtime, 10)
            .unwrap();
        assert_eq!(
            Verification::Resume(&inputs).digest(&runtime, 10).unwrap(),
            digest
        );
        fs::remove_file(&runtime).unwrap();
        symlink(&other, &runtime).unwrap();
        assert!(Verification::Resume(&inputs).digest(&runtime, 10).is_err());
    }

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

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_tree_leaf_refuses_stale_observation_and_all_mutations() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        for mutation in ["mode", "replacement", "link", "bytes"] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("asset");
            fs::write(&path, b"original").unwrap();
            let mut inputs = Inputs::default();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let digest = Verification::Capture(&mut inputs)
                .tree_digest(&path, &metadata)
                .unwrap();
            assert_eq!(
                Verification::Resume(&inputs)
                    .tree_digest(&path, &metadata)
                    .unwrap(),
                digest
            );
            match mutation {
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap(),
                "replacement" => {
                    fs::rename(&path, root.path().join("old")).unwrap();
                    fs::write(&path, b"original").unwrap();
                }
                "link" => {
                    fs::rename(&path, root.path().join("old")).unwrap();
                    symlink("old", &path).unwrap();
                }
                _ => fs::write(&path, b"tampered").unwrap(),
            }
            // Stale read_dir metadata cannot authorize a changed inode/link.
            assert!(Verification::Resume(&inputs)
                .tree_digest(&path, &metadata)
                .is_err());
            let current = fs::symlink_metadata(&path).unwrap();
            assert!(Verification::Resume(&inputs)
                .tree_digest(&path, &current)
                .is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_tree_metadata_is_never_content_authority() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("asset");
        fs::write(&path, b"original").unwrap();
        let mut inputs = Inputs::default();
        Verification::Capture(&mut inputs)
            .tree_digest(&path, &fs::symlink_metadata(&path).unwrap())
            .unwrap();
        fs::write(&path, b"tampered").unwrap();
        let file = fs::File::open(&path).unwrap();
        let current = Identity::read_open(&path, &file).unwrap();
        inputs.entries.insert(path.clone(), current.clone());
        inputs.files.get_mut(&path).unwrap().identity = current;
        assert!(Verification::Resume(&inputs)
            .tree_digest(&path, &fs::symlink_metadata(&path).unwrap())
            .is_err());
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
