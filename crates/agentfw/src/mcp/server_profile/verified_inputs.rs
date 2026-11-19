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

// Timing is diagnostic only; never read by proof/admission decisions.
#[derive(Clone, Default)]
struct CaptureCost {
    hashed_files: u64,
    hashed_bytes: u64,
    digest_time: std::time::Duration,
    proof_time: std::time::Duration,
    hash_time: std::time::Duration,
}

// Bound the underlying read before buffering: prefetch must never read past
// the size+1 sentinel. The larger block reduces traced read syscalls while
// retaining the same descriptor, full byte hash and caller identity checks.
fn hash_bounded(reader: impl Read, size: u64, hash: &mut Sha256) -> std::io::Result<u64> {
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, reader.take(size + 1));
    std::io::copy(&mut reader, hash)
}

#[derive(Clone, Default)]
pub(super) struct Inputs {
    files: BTreeMap<PathBuf, FileProof>,
    entries: BTreeMap<PathBuf, Identity>,
    trees: BTreeMap<PathBuf, usize>,
    lease_owner: Option<std::sync::Arc<super::read_lease::Owner>>,
    capture_cost: CaptureCost,
}

impl Inputs {
    pub(super) fn capture_cost(&self) -> serde_json::Value {
        let cost = &self.capture_cost;
        serde_json::json!({"event":"mcp_verified_inputs_capture_cost",
            "hashed_files":cost.hashed_files,"hashed_bytes":cost.hashed_bytes,
            "digest_ms":cost.digest_time.as_secs_f64()*1000.0,
            "proof_ms":cost.proof_time.as_secs_f64()*1000.0,
            "hash_ms":cost.hash_time.as_secs_f64()*1000.0,
            "identity_and_overhead_ms":cost.digest_time.saturating_sub(cost.proof_time)
                .saturating_sub(cost.hash_time).as_secs_f64()*1000.0})
    }

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
    pub(super) fn tree_entries(&mut self, root: &Path, count: usize) -> anyhow::Result<()> {
        // Every visited path is checked against entries/files on resume. Equal
        // cardinality therefore also proves that no captured path disappeared,
        // independently of directory timestamp granularity.
        let previous = match self {
            Self::Full => return Ok(()),
            Self::Capture(inputs) => inputs.trees.insert(root.to_owned(), count),
            Self::Resume(inputs) => Some(
                *inputs
                    .trees
                    .get(root)
                    .context("selected package was not verified before approval")?,
            ),
        };
        ensure!(
            previous.is_none_or(|previous| previous == count),
            "selected package entry set changed during approval"
        );
        Ok(())
    }

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
            let count = hash_bounded(file, size, &mut hash)?;
            ensure!(count == size, "selected asset changed during hashing");
            return Ok(format!("{:x}", hash.finalize()));
        }
        let timed_capture = matches!(self, Self::Capture(_));
        let start_timing = || timed_capture.then(std::time::Instant::now);
        let elapsed = |started: Option<std::time::Instant>| {
            started.map_or(std::time::Duration::ZERO, |started| started.elapsed())
        };
        let digest_started = start_timing();
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
        // Resume cannot adopt a new immutable proof: only a proof captured for
        // this exact Ask can authorize reuse. In the rehash/read-lease cases a
        // fresh verity ioctl would be unused; do not query it for every leaf.
        // Existing verity proofs must still be measured and compared below.
        let proof_started = start_timing();
        let verity = if previous.as_ref().is_none_or(|proof| proof.verity.is_some()) {
            measure(&file)?
        } else {
            None
        };
        let mut proof_time = elapsed(proof_started);
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
        let lease_started = start_timing();
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
        proof_time += elapsed(lease_started);
        let hash_started = start_timing();
        let mut hash = Sha256::new();
        let count = hash_bounded(file.by_ref(), size, &mut hash)?;
        ensure!(count == size, "selected asset changed during hashing");
        let mut hash_time = elapsed(hash_started);
        self.close_identity(path, &file, &before, tree)?;
        let finalize_started = start_timing();
        let sha256 = format!("{:x}", hash.finalize());
        hash_time += elapsed(finalize_started);
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
            inputs.capture_cost.hashed_files += 1;
            inputs.capture_cost.hashed_bytes += count;
            inputs.capture_cost.digest_time += elapsed(digest_started);
            inputs.capture_cost.proof_time += proof_time;
            inputs.capture_cost.hash_time += hash_time;
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
mod tests;
