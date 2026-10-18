// SPDX-License-Identifier: Apache-2.0
//! Linux-only synchronous, owner-verified audit segments. The manifest describes
//! ordering and intentional pruning; its digest detects accidents, not an owner
//! who changes both data and manifest.

use super::RetentionConfig;
use anyhow::{anyhow, bail, ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

const MANIFEST: &str = "manifest.json";
const PENDING: &str = "manifest.pending";
const LOCK: &str = "writer.lock";
const MAX_MANIFEST: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Segment {
    id: u64,
    closed: bool,
    bytes: u64,
    sha256: Option<String>,
    partial_tail: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    limits: ManifestLimits,
    generation: u64,
    next_id: u64,
    pruned_through: u64,
    pending_prune: Option<u64>,
    segments: Vec<Segment>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestLimits {
    segment_size_bytes: u64,
    segment_count: usize,
    total_disk_bytes: u64,
    max_record_bytes: usize,
}

impl From<&RetentionConfig> for ManifestLimits {
    fn from(config: &RetentionConfig) -> Self {
        Self {
            segment_size_bytes: config.segment_size_bytes,
            segment_count: config.segment_count,
            total_disk_bytes: config.total_disk_bytes,
            max_record_bytes: config.max_record_bytes,
        }
    }
}

impl Manifest {
    fn validate(&self, config: &RetentionConfig) -> Result<()> {
        ensure!(
            self.version == 1 && self.generation > 0,
            "audit manifest is corrupt"
        );
        ensure!(
            self.limits.segment_size_bytes == config.segment_size_bytes
                && self.limits.segment_count == config.segment_count
                && self.limits.total_disk_bytes == config.total_disk_bytes
                && self.limits.max_record_bytes == config.max_record_bytes,
            "audit retention limits differ from the owned manifest"
        );
        ensure!(
            !self.segments.is_empty() && self.segments.len() <= config.segment_count,
            "audit manifest is corrupt"
        );
        let mut previous = self.pruned_through;
        for (index, segment) in self.segments.iter().enumerate() {
            ensure!(
                segment.id == previous + 1 && segment.id < self.next_id,
                "audit segment order is corrupt"
            );
            ensure!(
                segment.bytes <= config.segment_size_bytes,
                "audit segment exceeds configured limit"
            );
            ensure!(
                segment.closed == segment.sha256.is_some(),
                "audit manifest is corrupt"
            );
            ensure!(
                segment.closed || !segment.partial_tail,
                "audit manifest is corrupt"
            );
            ensure!(
                segment.closed || index == self.segments.len() - 1,
                "audit manifest is corrupt"
            );
            if let Some(hash) = &segment.sha256 {
                ensure!(
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                    "audit manifest is corrupt"
                );
            }
            previous = segment.id;
        }
        ensure!(self.next_id == previous + 1, "audit manifest is corrupt");
        if let Some(id) = self.pending_prune {
            ensure!(
                self.segments.len() == config.segment_count
                    && self.segments[0].id == id
                    && self.segments[0].closed,
                "audit manifest is corrupt"
            );
        }
        Ok(())
    }
}

struct OwnedDir {
    parent: File,
    name: CString,
    dir: File,
    dev: libc::dev_t,
    ino: libc::ino_t,
}

fn c_name(name: &str) -> CString {
    CString::new(name).expect("static audit file name")
}

fn stat_fd(fd: libc::c_int) -> Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to writable storage and fd is a live descriptor.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        bail!("audit file identity unavailable");
    }
    Ok(unsafe { stat.assume_init() })
}

fn stat_name(dir: &File, name: &CStr) -> Result<Option<libc::stat>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: name is NUL terminated and stat points to writable storage.
    let result = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(Some(unsafe { stat.assume_init() }))
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        bail!("audit path identity unavailable")
    }
}

fn open_at(dir: &File, name: &CStr, flags: libc::c_int, mode: libc::mode_t) -> Result<File> {
    // O_NONBLOCK prevents a pre-open FIFO substitution from hanging the daemon.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            mode,
        )
    };
    if fd < 0 {
        bail!("audit owned file could not be opened");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn same_identity(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn verify_private_filesystem(dir: &File) -> Result<()> {
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: info points to writable storage and dir is a live directory fd.
    ensure!(
        unsafe { libc::fstatfs(dir.as_raw_fd(), info.as_mut_ptr()) } == 0,
        "audit filesystem could not be verified"
    );
    let kind = unsafe { info.assume_init() }.f_type as u64;
    // Native local Linux filesystems with meaningful owner/mode checks. Refuse
    // drvfs, network/FUSE mounts and unknown permission models.
    ensure!(
        matches!(
            kind,
            0xef53
                | 0x5846_5342
                | 0x9123_683e
                | 0x2fc1_2fc1
                | 0xf2f5_2010
                | 0x0102_1994
                | 0x794c_7630
        ),
        "audit retention requires a supported private Linux filesystem"
    );
    Ok(())
}

fn check_file(dir: &File, name: &CStr, file: &File) -> Result<()> {
    let held = stat_fd(file.as_raw_fd())?;
    let named = stat_name(dir, name)?.ok_or_else(|| anyhow!("audit owned file disappeared"))?;
    ensure!(
        same_identity(&held, &named),
        "audit owned file was replaced"
    );
    ensure!(
        held.st_mode & libc::S_IFMT == libc::S_IFREG
            && held.st_uid == unsafe { libc::geteuid() }
            && held.st_nlink == 1
            && held.st_mode & 0o077 == 0,
        "audit owned file is unsafe"
    );
    Ok(())
}

impl OwnedDir {
    fn open(path: &Path) -> Result<Self> {
        ensure!(path.is_absolute(), "audit directory must be absolute");
        let mut parts = path.components();
        ensure!(
            matches!(parts.next(), Some(Component::RootDir)),
            "audit directory must be absolute"
        );
        let names: Vec<_> = parts.collect();
        ensure!(
            !names.is_empty()
                && names
                    .iter()
                    .all(|part| matches!(part, Component::Normal(_))),
            "audit directory has unsafe components"
        );
        let root = CString::new("/").unwrap();
        let fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        ensure!(fd >= 0, "audit directory root unavailable");
        let mut parent = unsafe { File::from_raw_fd(fd) };
        for part in &names[..names.len() - 1] {
            let Component::Normal(part) = part else {
                unreachable!()
            };
            let name = CString::new(part.as_bytes())?;
            parent = open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        }
        let Component::Normal(last) = names[names.len() - 1] else {
            unreachable!()
        };
        let name = CString::new(last.as_bytes())?;
        if stat_name(&parent, &name)?.is_none() {
            let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
            ensure!(result == 0, "audit directory could not be created");
            parent
                .sync_all()
                .map_err(|_| anyhow!("audit directory publication failed"))?;
        }
        let dir = open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let stat = stat_fd(dir.as_raw_fd())?;
        verify_private_filesystem(&dir)?;
        ensure!(
            stat.st_mode & libc::S_IFMT == libc::S_IFDIR
                && stat.st_uid == unsafe { libc::geteuid() }
                && stat.st_mode & 0o077 == 0,
            "audit directory must be owner-only"
        );
        let owned = Self {
            parent,
            name,
            dir,
            dev: stat.st_dev,
            ino: stat.st_ino,
        };
        owned.check()?;
        Ok(owned)
    }

    fn check(&self) -> Result<()> {
        let held = stat_fd(self.dir.as_raw_fd())?;
        let named = stat_name(&self.parent, &self.name)?
            .ok_or_else(|| anyhow!("audit directory disappeared"))?;
        ensure!(
            same_identity(&held, &named) && held.st_dev == self.dev && held.st_ino == self.ino,
            "audit directory was replaced"
        );
        ensure!(
            held.st_uid == unsafe { libc::geteuid() } && held.st_mode & 0o077 == 0,
            "audit directory is unsafe"
        );
        Ok(())
    }

    fn open_existing(&self, name: &CStr) -> Result<Option<File>> {
        if stat_name(&self.dir, name)?.is_none() {
            return Ok(None);
        }
        let file = open_at(&self.dir, name, libc::O_RDWR | libc::O_APPEND, 0)?;
        check_file(&self.dir, name, &file)?;
        Ok(Some(file))
    }

    fn create(&self, name: &CStr) -> Result<File> {
        let file = open_at(
            &self.dir,
            name,
            libc::O_RDWR | libc::O_APPEND | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        check_file(&self.dir, name, &file)?;
        self.dir
            .sync_all()
            .map_err(|_| anyhow!("audit file publication failed"))?;
        Ok(file)
    }

    fn unlink_checked(&self, name: &CStr, held: &File) -> Result<()> {
        check_file(&self.dir, name, held)?;
        ensure!(
            unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) } == 0,
            "audit owned file could not be pruned"
        );
        self.dir
            .sync_all()
            .map_err(|_| anyhow!("audit prune publication failed"))?;
        Ok(())
    }
}

fn segment_name(id: u64) -> CString {
    c_name(&format!("segment-{id:020}.jsonl"))
}

fn read_manifest(dir: &OwnedDir, name: &CStr) -> Result<Option<Manifest>> {
    let Some(mut file) = dir.open_existing(name)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_MANIFEST + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("audit manifest unreadable"))?;
    ensure!(bytes.len() <= MAX_MANIFEST, "audit manifest exceeds limit");
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| anyhow!("audit manifest is corrupt"))
}

fn publish(dir: &OwnedDir, manifest: &mut Manifest) -> Result<()> {
    dir.check()?;
    ensure!(
        dir.open_existing(&c_name(PENDING))?.is_none(),
        "audit pending manifest requires recovery"
    );
    manifest.generation = manifest
        .generation
        .checked_add(1)
        .ok_or_else(|| anyhow!("audit generation exhausted"))?;
    let bytes = serde_json::to_vec(manifest)?;
    ensure!(bytes.len() <= MAX_MANIFEST, "audit manifest exceeds limit");
    let pending_name = c_name(PENDING);
    let mut pending = dir.create(&pending_name)?;
    pending
        .write_all(&bytes)
        .map_err(|_| anyhow!("audit manifest write failed"))?;
    pending
        .sync_all()
        .map_err(|_| anyhow!("audit manifest sync failed"))?;
    check_file(&dir.dir, &pending_name, &pending)?;
    ensure!(
        unsafe {
            libc::renameat(
                dir.dir.as_raw_fd(),
                pending_name.as_ptr(),
                dir.dir.as_raw_fd(),
                c_name(MANIFEST).as_ptr(),
            )
        } == 0,
        "audit manifest publication failed"
    );
    dir.dir
        .sync_all()
        .map_err(|_| anyhow!("audit manifest publication sync failed"))?;
    Ok(())
}

fn load_or_create(dir: &OwnedDir, config: &RetentionConfig) -> Result<Manifest> {
    let mut current = read_manifest(dir, &c_name(MANIFEST))?;
    if let Some(pending) = read_manifest(dir, &c_name(PENDING))? {
        pending.validate(config)?;
        let expected = current.as_ref().map_or(1, |m| m.generation + 1);
        ensure!(
            pending.generation == expected,
            "audit pending manifest order is corrupt"
        );
        ensure!(
            unsafe {
                libc::renameat(
                    dir.dir.as_raw_fd(),
                    c_name(PENDING).as_ptr(),
                    dir.dir.as_raw_fd(),
                    c_name(MANIFEST).as_ptr(),
                )
            } == 0,
            "audit pending manifest could not be completed"
        );
        dir.dir
            .sync_all()
            .map_err(|_| anyhow!("audit manifest recovery sync failed"))?;
        current = Some(pending);
    }
    let manifest = if let Some(current) = current {
        current
    } else {
        let initial = Manifest {
            version: 1,
            limits: ManifestLimits::from(config),
            generation: 1,
            next_id: 2,
            pruned_through: 0,
            pending_prune: None,
            segments: vec![Segment {
                id: 1,
                closed: false,
                bytes: 0,
                sha256: None,
                partial_tail: false,
            }],
        };
        let mut file = dir.create(&c_name(MANIFEST))?;
        let bytes = serde_json::to_vec(&initial)?;
        file.write_all(&bytes)
            .map_err(|_| anyhow!("audit manifest write failed"))?;
        file.sync_all()
            .map_err(|_| anyhow!("audit manifest sync failed"))?;
        initial
    };
    manifest.validate(config)?;
    Ok(manifest)
}

fn scan(file: &mut File, max: u64, line_max: usize) -> Result<(u64, String, bool)> {
    use std::io::Seek;
    file.rewind()
        .map_err(|_| anyhow!("audit segment unreadable"))?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("audit segment unreadable"))?;
    ensure!(
        bytes.len() as u64 <= max,
        "audit segment exceeds configured limit"
    );
    let mut start = 0;
    let mut partial = false;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            ensure!(
                index + 1 - start <= line_max,
                "audit record exceeds configured limit"
            );
            serde_json::from_slice::<serde_json::Value>(&bytes[start..index])
                .map_err(|_| anyhow!("audit segment contains a corrupt record"))?;
            start = index + 1;
        }
    }
    if start != bytes.len() {
        ensure!(
            bytes.len() - start <= line_max,
            "audit partial record exceeds configured limit"
        );
        partial = true;
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok((bytes.len() as u64, digest, partial))
}

struct LimitedWriter {
    bytes: Vec<u8>,
    max: usize,
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.max.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other(
                "audit record exceeds configured limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) struct RetainedSink {
    dir: OwnedDir,
    config: RetentionConfig,
    manifest: Manifest,
    lock: File,
    active: File,
    active_bytes: u64,
    manifest_identity: (libc::dev_t, libc::ino_t),
    failed: bool,
    #[cfg(test)]
    fail_after_bytes: Option<usize>,
    #[cfg(test)]
    fail_errno: Option<i32>,
}

impl RetainedSink {
    #[cfg(test)]
    pub(super) fn inject_write_error(&mut self, errno: i32) {
        self.fail_errno = Some(errno);
    }

    pub(super) fn health(&self) -> serde_json::Value {
        let state = if self.failed || self.check_active().is_err() {
            "unavailable"
        } else {
            "healthy"
        };
        serde_json::json!({"mode":"retained","state":state,
            "reason": if state == "healthy" { None } else { Some("audit_unavailable") },
            "retained_segments":self.manifest.segments.len(),
            "pruned_through":self.manifest.pruned_through})
    }

    pub(super) fn open(config: &RetentionConfig, recover: bool) -> Result<Self> {
        config.validate()?;
        let dir = OwnedDir::open(&config.directory)?;
        let lock_name = c_name(LOCK);
        let lock = match dir.open_existing(&lock_name)? {
            Some(file) => file,
            None => dir.create(&lock_name)?,
        };
        ensure!(
            lock.metadata()
                .map_err(|_| anyhow!("audit lock size unavailable"))?
                .len()
                == 0,
            "audit lock file is unsafe"
        );
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another audit writer owns this directory"
        );
        dir.check()?;
        let mut manifest = load_or_create(&dir, config)?;
        if let Some(id) = manifest.pending_prune {
            let name = segment_name(id);
            if let Some(file) = dir.open_existing(&name)? {
                let segment = &manifest.segments[0];
                let (bytes, digest, _) = scan(
                    &mut file.try_clone()?,
                    config.segment_size_bytes,
                    config.max_record_bytes,
                )?;
                ensure!(
                    bytes == segment.bytes && Some(&digest) == segment.sha256.as_ref(),
                    "audit segment changed before prune"
                );
                dir.unlink_checked(&name, &file)?;
            }
            manifest.segments.remove(0);
            manifest.pruned_through = id;
            manifest.pending_prune = None;
            publish(&dir, &mut manifest)?;
        }
        for segment in &manifest.segments {
            let name = segment_name(segment.id);
            let mut file = match dir.open_existing(&name)? {
                Some(file) => file,
                None if !segment.closed && segment.bytes == 0 => dir.create(&name)?,
                None => bail!("audit retained segment is missing"),
            };
            let (bytes, digest, partial) = scan(
                &mut file,
                config.segment_size_bytes,
                config.max_record_bytes,
            )?;
            if segment.closed {
                ensure!(
                    bytes == segment.bytes
                        && Some(&digest) == segment.sha256.as_ref()
                        && partial == segment.partial_tail,
                    "audit closed segment is corrupt"
                );
            } else if partial && !recover {
                bail!("audit active segment has an incomplete tail; run audit-retention recover");
            }
        }
        let last = manifest
            .segments
            .last()
            .ok_or_else(|| anyhow!("audit manifest is empty"))?;
        let active_name = segment_name(last.id);
        let active = if last.closed {
            // A crash between closing and reserving the next segment is resumed.
            Self::reserve_next(&dir, config, &mut manifest)?
        } else {
            dir.open_existing(&active_name)?
                .ok_or_else(|| anyhow!("audit active segment missing"))?
        };
        let active_bytes = active
            .metadata()
            .map_err(|_| anyhow!("audit active size unavailable"))?
            .len();
        let manifest_file = dir
            .open_existing(&c_name(MANIFEST))?
            .ok_or_else(|| anyhow!("audit manifest missing"))?;
        let manifest_stat = stat_fd(manifest_file.as_raw_fd())?;
        let mut sink = Self {
            dir,
            config: config.clone(),
            manifest,
            lock,
            active,
            active_bytes,
            manifest_identity: (manifest_stat.st_dev, manifest_stat.st_ino),
            failed: false,
            #[cfg(test)]
            fail_after_bytes: None,
            #[cfg(test)]
            fail_errno: None,
        };
        if recover {
            let mut checked = sink.active.try_clone()?;
            let (_, _, partial) = scan(
                &mut checked,
                config.segment_size_bytes,
                config.max_record_bytes,
            )?;
            if partial {
                sink.rotate(true)?;
            }
        }
        sink.check_active()?;
        Ok(sink)
    }

    fn reserve_next(
        dir: &OwnedDir,
        config: &RetentionConfig,
        manifest: &mut Manifest,
    ) -> Result<File> {
        if manifest.segments.len() == config.segment_count {
            let id = manifest.segments[0].id;
            let bytes = manifest.segments[0].bytes;
            let hash = manifest.segments[0].sha256.clone();
            ensure!(
                manifest.segments[0].closed,
                "audit retention has no closed segment to prune"
            );
            manifest.pending_prune = Some(id);
            publish(dir, manifest)?;
            let name = segment_name(id);
            let file = dir
                .open_existing(&name)?
                .ok_or_else(|| anyhow!("audit prune segment missing"))?;
            let (actual_bytes, actual_hash, _) = scan(
                &mut file.try_clone()?,
                config.segment_size_bytes,
                config.max_record_bytes,
            )?;
            ensure!(
                actual_bytes == bytes && Some(actual_hash) == hash,
                "audit segment changed before prune"
            );
            dir.unlink_checked(&name, &file)?;
            manifest.segments.remove(0);
            manifest.pruned_through = id;
            manifest.pending_prune = None;
            publish(dir, manifest)?;
        }
        let id = manifest.next_id;
        manifest.next_id = manifest
            .next_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("audit segment id exhausted"))?;
        manifest.segments.push(Segment {
            id,
            closed: false,
            bytes: 0,
            sha256: None,
            partial_tail: false,
        });
        publish(dir, manifest)?;
        let name = segment_name(id);
        match dir.open_existing(&name)? {
            Some(file) => Ok(file),
            None => dir.create(&name),
        }
    }

    fn rotate(&mut self, allow_partial: bool) -> Result<()> {
        self.check_active()?;
        self.active
            .sync_all()
            .map_err(|_| anyhow!("audit segment sync failed"))?;
        let mut copy = self.active.try_clone()?;
        let (bytes, digest, partial) = scan(
            &mut copy,
            self.config.segment_size_bytes,
            self.config.max_record_bytes,
        )?;
        ensure!(!partial || allow_partial, "audit active tail is incomplete");
        let last = self
            .manifest
            .segments
            .last_mut()
            .ok_or_else(|| anyhow!("audit manifest is empty"))?;
        last.closed = true;
        last.bytes = bytes;
        last.sha256 = Some(digest);
        last.partial_tail = partial;
        publish(&self.dir, &mut self.manifest)?;
        self.active = Self::reserve_next(&self.dir, &self.config, &mut self.manifest)?;
        self.active_bytes = 0;
        let manifest_file = self
            .dir
            .open_existing(&c_name(MANIFEST))?
            .ok_or_else(|| anyhow!("audit manifest missing"))?;
        let stat = stat_fd(manifest_file.as_raw_fd())?;
        self.manifest_identity = (stat.st_dev, stat.st_ino);
        Ok(())
    }

    fn check_active(&self) -> Result<()> {
        self.dir.check()?;
        check_file(&self.dir.dir, &c_name(LOCK), &self.lock)?;
        let mut manifest_file = self
            .dir
            .open_existing(&c_name(MANIFEST))?
            .ok_or_else(|| anyhow!("audit manifest missing"))?;
        let manifest_stat = stat_fd(manifest_file.as_raw_fd())?;
        ensure!(
            (manifest_stat.st_dev, manifest_stat.st_ino) == self.manifest_identity,
            "audit manifest was replaced"
        );
        let mut manifest_bytes = Vec::new();
        Read::by_ref(&mut manifest_file)
            .take((MAX_MANIFEST + 1) as u64)
            .read_to_end(&mut manifest_bytes)
            .map_err(|_| anyhow!("audit manifest unreadable"))?;
        ensure!(
            manifest_bytes == serde_json::to_vec(&self.manifest)?,
            "audit manifest changed outside writer"
        );
        let id = self
            .manifest
            .segments
            .last()
            .ok_or_else(|| anyhow!("audit manifest is empty"))?
            .id;
        check_file(&self.dir.dir, &segment_name(id), &self.active)?;
        ensure!(
            self.active
                .metadata()
                .map_err(|_| anyhow!("audit segment size unavailable"))?
                .len()
                == self.active_bytes,
            "audit active segment changed outside writer"
        );
        Ok(())
    }

    pub(super) fn write_serialized(&mut self, line: &impl Serialize) -> Result<()> {
        ensure!(!self.failed, "audit sink requires explicit recovery");
        let result = self.write_inner(line);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn write_inner(&mut self, line: &impl Serialize) -> Result<()> {
        let mut writer = LimitedWriter {
            bytes: Vec::with_capacity(1024),
            max: self.config.max_record_bytes - 1,
        };
        serde_json::to_writer(&mut writer, line)
            .map_err(|_| anyhow!("audit record exceeds configured limit or cannot serialize"))?;
        writer.bytes.push(b'\n');
        let len = writer.bytes.len() as u64;
        self.check_active()?;
        if self.active_bytes + len > self.config.segment_size_bytes {
            self.rotate(false)?;
            self.check_active()?;
        }
        #[cfg(test)]
        if let Some(bytes) = self.fail_after_bytes.take() {
            self.active
                .write_all(&writer.bytes[..bytes.min(writer.bytes.len())])?;
            self.active.sync_data()?;
            bail!("injected short audit write");
        }
        #[cfg(test)]
        if let Some(errno) = self.fail_errno.take() {
            return Err(std::io::Error::from_raw_os_error(errno).into());
        }
        self.active
            .write_all(&writer.bytes)
            .map_err(|_| anyhow!("audit segment write failed"))?;
        self.active
            .sync_data()
            .map_err(|_| anyhow!("audit segment sync failed"))?;
        self.active_bytes += len;
        Ok(())
    }
}

/// Explicitly resume a stopped sink after verifying the owned directory. A
/// partial active tail is retained as evidence and sealed before a new segment.
pub fn recover_retention(config: &RetentionConfig) -> Result<()> {
    let _sink = RetainedSink::open(config, true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(path: &Path) -> RetentionConfig {
        RetentionConfig {
            version: 1,
            directory: path.to_path_buf(),
            segment_size_bytes: 64 * 1024,
            segment_count: 2,
            total_disk_bytes: 300_000,
            max_record_bytes: 1024,
        }
    }

    fn event(index: usize) -> serde_json::Value {
        json!({"at_ms":index,"session":"synthetic","event":"native_call", "verdict":"allow",
            "shadow":false,"seq":index,"raw":"x".repeat(700)})
    }

    #[test]
    fn rotates_prunes_and_reopens_without_exceeding_declared_bytes() {
        let root = tempfile::tempdir().unwrap();
        let config = config(&root.path().join("retained"));
        let mut sink = RetainedSink::open(&config, false).unwrap();
        for index in 0..230 {
            sink.write_serialized(&event(index)).unwrap();
        }
        assert!(sink.manifest.pruned_through > 0);
        let last_id = sink.manifest.segments.last().unwrap().id;
        assert!(sink.manifest.segments.len() <= 2);
        drop(sink);
        let mut reopened = RetainedSink::open(&config, false).unwrap();
        assert_eq!(reopened.manifest.segments.last().unwrap().id, last_id);
        reopened.write_serialized(&event(231)).unwrap();
        let used: u64 = std::fs::read_dir(&config.directory)
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum();
        assert!(used <= config.total_disk_bytes, "owned bytes {used}");
    }

    #[test]
    fn second_writer_and_replaced_active_path_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let config = config(&root.path().join("retained"));
        let mut sink = RetainedSink::open(&config, false).unwrap();
        assert!(RetainedSink::open(&config, false).is_err());
        let name = segment_name(1);
        let path = config.directory.join(name.to_str().unwrap());
        let moved = config.directory.join("operator-owned");
        std::fs::rename(&path, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &path).unwrap();
        let status = sink.health().to_string();
        assert!(status.contains("unavailable"));
        assert!(!status.contains("operator-owned"));
        assert!(sink.write_serialized(&event(1)).is_err());
        assert_eq!(std::fs::read(&moved).unwrap().len(), 0);
    }

    #[test]
    fn short_write_requires_explicit_recovery_and_keeps_tail() {
        let root = tempfile::tempdir().unwrap();
        let config = config(&root.path().join("retained"));
        let mut sink = RetainedSink::open(&config, false).unwrap();
        sink.write_serialized(&event(1)).unwrap();
        sink.fail_after_bytes = Some(17);
        assert!(sink.write_serialized(&event(2)).is_err());
        assert!(sink.write_serialized(&event(3)).is_err());
        drop(sink);
        assert!(RetainedSink::open(&config, false).is_err());
        recover_retention(&config).unwrap();
        let mut reopened = RetainedSink::open(&config, false).unwrap();
        assert!(reopened.manifest.segments[0].partial_tail);
        reopened.write_serialized(&event(4)).unwrap();
    }

    #[test]
    fn valid_interrupted_manifest_publication_is_completed_on_restart() {
        let root = tempfile::tempdir().unwrap();
        let config = config(&root.path().join("retained"));
        let sink = RetainedSink::open(&config, false).unwrap();
        let mut pending = sink.manifest.clone();
        pending.generation += 1;
        let bytes = serde_json::to_vec(&pending).unwrap();
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(config.directory.join(PENDING))
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        drop(sink);
        let reopened = RetainedSink::open(&config, false).unwrap();
        assert_eq!(reopened.manifest.generation, pending.generation);
        assert!(!config.directory.join(PENDING).exists());
    }

    #[test]
    fn missing_or_changed_closed_segment_stops_startup() {
        let root = tempfile::tempdir().unwrap();
        let config = config(&root.path().join("retained"));
        let mut sink = RetainedSink::open(&config, false).unwrap();
        for index in 0..100 {
            sink.write_serialized(&event(index)).unwrap();
        }
        let closed = sink.manifest.segments[0].id;
        drop(sink);
        let path = config
            .directory
            .join(segment_name(closed).to_str().unwrap());
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"{}\n").unwrap();
        assert!(RetainedSink::open(&config, false).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(RetainedSink::open(&config, false).is_err());
    }

    #[test]
    fn concurrent_events_are_complete_and_oversized_record_fails() {
        let root = tempfile::tempdir().unwrap();
        let config = config(&root.path().join("retained"));
        let sink = std::sync::Arc::new(super::super::AuditSink::open_retained(&config).unwrap());
        let workers: Vec<_> = (0..8)
            .map(|worker| {
                let sink = sink.clone();
                std::thread::spawn(move || {
                    for index in 0..10 {
                        sink.write_native(
                            &json!({"event":"native_call","worker":worker,"index":index}),
                        )
                        .unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(sink
            .write_native(&json!({"event":"native_call","raw":"x".repeat(2000)}))
            .is_err());
        drop(sink);
        let body =
            std::fs::read_to_string(config.directory.join(segment_name(1).to_str().unwrap()))
                .unwrap();
        assert_eq!(body.lines().count(), 80);
        assert!(body
            .lines()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok()));
    }

    #[test]
    fn replaced_directory_is_refused_before_another_write() {
        let root = tempfile::tempdir().unwrap();
        let config = config(&root.path().join("retained"));
        let mut sink = RetainedSink::open(&config, false).unwrap();
        sink.write_serialized(&event(1)).unwrap();
        let moved = root.path().join("moved-private-store");
        std::fs::rename(&config.directory, &moved).unwrap();
        std::fs::create_dir(&config.directory).unwrap();
        let before = std::fs::read(moved.join(segment_name(1).to_str().unwrap())).unwrap();
        assert!(sink.write_serialized(&event(2)).is_err());
        assert_eq!(
            std::fs::read(moved.join(segment_name(1).to_str().unwrap())).unwrap(),
            before
        );
    }

    #[test]
    fn replaced_manifest_is_refused_without_overwriting_operator_file() {
        let root = tempfile::tempdir().unwrap();
        let config = config(&root.path().join("retained"));
        let mut sink = RetainedSink::open(&config, false).unwrap();
        let path = config.directory.join(MANIFEST);
        std::fs::rename(&path, config.directory.join("saved-manifest")).unwrap();
        use std::os::unix::fs::OpenOptionsExt;
        let mut replacement = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        replacement.write_all(b"operator file").unwrap();
        assert!(sink.write_serialized(&event(1)).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"operator file");
    }

    #[test]
    fn interrupted_prune_after_unlink_is_completed_without_another_delete() {
        let root = tempfile::tempdir().unwrap();
        let config = config(&root.path().join("retained"));
        let mut sink = RetainedSink::open(&config, false).unwrap();
        for index in 0..100 {
            sink.write_serialized(&event(index)).unwrap();
        }
        let oldest = sink.manifest.segments[0].id;
        sink.manifest.pending_prune = Some(oldest);
        publish(&sink.dir, &mut sink.manifest).unwrap();
        let path = config
            .directory
            .join(segment_name(oldest).to_str().unwrap());
        std::fs::remove_file(path).unwrap();
        drop(sink);
        let reopened = RetainedSink::open(&config, false).unwrap();
        assert_eq!(reopened.manifest.pruned_through, oldest);
        assert!(reopened.manifest.pending_prune.is_none());
    }

    #[test]
    fn disk_full_failure_poisoned_sink_recovers_after_space_restored() {
        let root = tempfile::tempdir().unwrap();
        let config = config(&root.path().join("retained"));
        let mut sink = RetainedSink::open(&config, false).unwrap();
        sink.fail_errno = Some(libc::ENOSPC);
        assert!(sink.write_serialized(&event(1)).is_err());
        assert_eq!(sink.health()["state"], "unavailable");
        assert!(sink.write_serialized(&event(2)).is_err());
        drop(sink);
        recover_retention(&config).unwrap();
        let mut reopened = RetainedSink::open(&config, false).unwrap();
        reopened.write_serialized(&event(3)).unwrap();
    }
}
