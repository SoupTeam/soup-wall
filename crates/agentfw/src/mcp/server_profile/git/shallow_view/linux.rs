// SPDX-License-Identifier: Apache-2.0
//! Immutable namespace data plus sticky source withdrawal. Inotify is a
//! directory revocation witness, never content authority. Retained same-FD
//! local read leases independently cover mapped writers. Each call still
//! traverses enforcing native admission and result inspection; these source
//! data proofs are never permission or a cached approval.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{ensure, Context};
use serde_json::Value;
use tokio::process::Command;

use super::super::super::read_lease;
use super::{
    decode_object, oid, packed_references, Object, OriginTarget, MAX_OBJECT_BYTES, MAX_REFS,
    MAX_TAG_DEPTH,
};

const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_OBJECTS: usize = 128;
const MAX_WATCHES: usize = 256;
const MAX_DIRECTORIES: usize = 128;
const ROOT: &str = "/workspace/.git";

struct Withdrawal {
    file: File,
    broken: bool,
    watches: BTreeSet<i32>,
    leases: Vec<Arc<read_lease::Guard>>,
    lease_owner: Option<Arc<read_lease::Owner>>,
}

impl std::fmt::Debug for Withdrawal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Withdrawal")
            .field("broken", &self.broken)
            .field("watches", &self.watches.len())
            .field("leases", &self.leases.len())
            .finish_non_exhaustive()
    }
}

impl Withdrawal {
    fn new() -> anyhow::Result<Self> {
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        ensure!(fd >= 0, "Git shallow observer unavailable");
        Ok(Self {
            file: unsafe { File::from_raw_fd(fd) },
            broken: false,
            watches: BTreeSet::new(),
            leases: Vec::new(),
            lease_owner: None,
        })
    }

    fn protect(&mut self, file: &File) -> anyhow::Result<()> {
        if self.lease_owner.is_none() {
            self.lease_owner = read_lease::Owner::new(file);
        }
        let owner = self
            .lease_owner
            .as_ref()
            .context("Git shallow read proofs unavailable")?;
        let lease = owner
            .acquire(file)?
            .context("Git shallow source has a writer or cannot be protected")?;
        ensure!(lease.valid(), "Git shallow source changed during capture");
        self.leases.push(lease);
        Ok(())
    }

    fn leases_valid(&mut self) -> bool {
        if self.broken || !self.leases.iter().all(|lease| lease.valid()) {
            self.broken = true;
            return false;
        }
        true
    }

    fn watch(&mut self, directory: &File) -> anyhow::Result<()> {
        ensure!(self.watches.len() < MAX_WATCHES, "Git shallow watch limit");
        let path = CString::new(format!("/proc/self/fd/{}", directory.as_raw_fd()))?;
        let mask = libc::IN_ONLYDIR
            | libc::IN_MODIFY
            | libc::IN_ATTRIB
            | libc::IN_CLOSE_WRITE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF
            | libc::IN_UNMOUNT;
        let id = unsafe { libc::inotify_add_watch(self.file.as_raw_fd(), path.as_ptr(), mask) };
        ensure!(id >= 0, "Git shallow watch unavailable");
        self.watches.insert(id);
        Ok(())
    }

    fn valid(&mut self) -> bool {
        if !self.leases_valid() {
            return false;
        }
        let mut buffer = [0_u8; 8192];
        loop {
            let count = unsafe {
                libc::read(
                    self.file.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if count > 0 {
                // Every subscribed event withdraws the view, including queue
                // overflow/watch removal. Restoring bytes cannot revive it.
                self.broken = true;
                return false;
            }
            if count == 0 {
                self.broken = true;
                return false;
            }
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => return self.leases_valid(),
                _ => {
                    self.broken = true;
                    return false;
                }
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct View {
    source: Mutex<Withdrawal>,
    available: BTreeSet<String>,
    directories: BTreeSet<PathBuf>,
    images: Vec<(PathBuf, File)>,
    object_witness: bool,
    linked: Option<super::super::linked_worktree::Binding>,
}

fn owned(metadata: &std::fs::Metadata) -> anyhow::Result<()> {
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0,
        "Git shallow metadata must remain owned and not shared writable"
    );
    Ok(())
}

fn child(parent: &File, name: &str, directory: bool) -> anyhow::Result<File> {
    ensure!(
        !name.is_empty() && !name.contains('/') && name != "." && name != "..",
        "Git shallow component invalid"
    );
    let name = CString::new(name)?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    owned(&metadata)?;
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        },
        "Git shallow metadata type unsupported"
    );
    Ok(file)
}

#[cfg(test)]
std::thread_local! {
    // Synchronous owned-fixture barrier on this test thread only. No runtime
    // flag, environment variable or production caller can install this hook.
    static AFTER_OBJECT_WITNESS_GIT_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

fn object_witness_directory(workspace: &File) -> anyhow::Result<(File, Withdrawal)> {
    let mut source = Withdrawal::new()?;
    // Observation must precede the first dependent directory-entry lookup.
    // A later watch cannot report a substitution which already happened.
    source.watch(workspace)?;
    let git = child(workspace, ".git", true)?;
    #[cfg(test)]
    {
        let action = AFTER_OBJECT_WITNESS_GIT_OPEN.with(|slot| slot.borrow_mut().take());
        if let Some(action) = action {
            action();
        }
    }
    ensure!(
        source.valid(),
        "Git object witness workspace changed during lookup"
    );
    Ok((git, source))
}

fn entries(directory: &File) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        ensure!(names.len() < 1024, "Git shallow directory entry limit");
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("Git metadata name is not UTF-8"))?;
        ensure!(
            !name.ends_with(".lock"),
            "Git metadata write is in progress"
        );
        names.push(name);
    }
    names.sort();
    Ok(names)
}

fn stamp(metadata: &std::fs::Metadata) -> (u64, u64, u64, u32, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn read_file(mut file: File, limit: usize) -> anyhow::Result<Vec<u8>> {
    let before = file.metadata()?;
    ensure!(
        before.nlink() == 1,
        "hard-linked Git shallow metadata unsupported"
    );
    ensure!(
        before.len() <= limit as u64,
        "Git shallow file exceeds limit"
    );
    let mut bytes = Vec::new();
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit && stamp(&before) == stamp(&file.metadata()?),
        "Git shallow file changed during capture"
    );
    Ok(bytes)
}

fn optional_directory(parent: &File, name: &str) -> anyhow::Result<Option<File>> {
    match child(parent, name, true) {
        Ok(file) => Ok(Some(file)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn sealed(bytes: &[u8]) -> anyhow::Result<File> {
    let name = c"git-shallow-image";
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    ensure!(fd >= 0, "Git shallow image unavailable");
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    ensure!(
        unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } == 0,
        "Git shallow image sealing failed"
    );
    Ok(file)
}

struct Capture {
    source: Withdrawal,
    refs: BTreeMap<String, Option<String>>,
    directories: BTreeSet<PathBuf>,
    images: Vec<(PathBuf, File)>,
    objects: File,
    object_cache: BTreeMap<String, Object>,
    bytes: usize,
    packed: BTreeSet<String>,
    tracked: bool,
    origins: BTreeMap<String, OriginTarget>,
}

impl Capture {
    fn read(&mut self, file: File, limit: usize) -> anyhow::Result<Vec<u8>> {
        // Inotify alone misses MAP_SHARED writes. The accepted local-file
        // lease primitive rejects existing writers/mappings and permanently
        // withdraws on a later write-open before releasing that writer.
        // It retains this same opened inode; no lease is reacquired.
        self.source.protect(&file)?;
        let bytes = read_file(file, limit)?;
        ensure!(
            self.source.valid(),
            "Git shallow source changed during capture"
        );
        Ok(bytes)
    }

    fn optional(
        &mut self,
        parent: &File,
        name: &str,
        limit: usize,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        match child(parent, name, false) {
            Ok(file) => Ok(Some(self.read(file, limit)?)),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn image(&mut self, path: impl Into<PathBuf>, bytes: &[u8]) -> anyhow::Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .context("Git reference image overflow")?;
        ensure!(
            self.bytes <= MAX_IMAGE_BYTES,
            "Git shallow image exceeds limit"
        );
        self.images.push((path.into(), sealed(bytes)?));
        Ok(())
    }

    fn directory(&mut self, path: impl Into<PathBuf>) -> anyhow::Result<()> {
        self.directories.insert(path.into());
        ensure!(
            self.directories.len() <= MAX_DIRECTORIES,
            "Git shallow directory limit"
        );
        Ok(())
    }

    fn loose_refs(&mut self, directory: File, prefix: &str, depth: usize) -> anyhow::Result<()> {
        ensure!(depth <= 10, "Git shallow depth limit");
        self.source.watch(&directory)?;
        self.directory(Path::new(ROOT).join(prefix))?;
        for name in entries(&directory)? {
            if self.tracked && prefix == "refs" {
                ensure!(
                    matches!(name.as_str(), "heads" | "tags" | "remotes"),
                    "Git tracked reference directory unsupported"
                );
            }
            let relative = format!("{prefix}/{name}");
            if let Ok(nested) = child(&directory, &name, true) {
                if self.tracked && relative.starts_with("refs/remotes") {
                    ensure!(
                        relative == "refs/remotes"
                            || relative == "refs/remotes/origin"
                            || super::is_origin_reference(&relative),
                        "Git origin directory unsupported"
                    );
                }
                self.loose_refs(nested, &relative, depth + 1)?;
                continue;
            }
            ensure!(
                super::is_metadata_reference(&relative)
                    || self.tracked && super::is_origin_reference(&relative),
                "Git shallow namespace unsupported"
            );
            let bytes = self.read(child(&directory, &name, false)?, 256)?;
            let target = if self.tracked && super::is_origin_reference(&relative) {
                let target = super::origin_target(&relative, &bytes)?;
                let id = match &target {
                    OriginTarget::Object(id) => Some(id.clone()),
                    OriginTarget::Symbolic(_) => None,
                };
                self.origins.insert(relative.clone(), target);
                id
            } else {
                std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|s| oid(s.strip_suffix('\n').unwrap_or(s)).ok())
            };
            self.refs.insert(relative.clone(), target);
            ensure!(
                self.refs.len() <= MAX_REFS,
                "Git shallow count exceeds limit"
            );
            self.image(Path::new(ROOT).join(relative), &bytes)?;
        }
        Ok(())
    }

    fn object(&mut self, id: &str) -> anyhow::Result<Object> {
        if let Some(object) = self.object_cache.get(id) {
            return Ok(object.clone());
        }
        oid(id)?;
        ensure!(
            self.object_cache.len() < MAX_OBJECTS,
            "Git shallow object count limit"
        );
        let prefix = child(&self.objects, &id[..2], true)?;
        self.source.watch(&prefix)?;
        let bytes = self.read(child(&prefix, &id[2..], false)?, MAX_OBJECT_BYTES)?;
        let object = decode_object(id, &bytes)?;
        self.image(
            Path::new(ROOT)
                .join("objects")
                .join(&id[..2])
                .join(&id[2..]),
            &bytes,
        )?;
        self.object_cache.insert(id.to_owned(), object.clone());
        Ok(object)
    }

    fn target(&mut self, id: &str, tag: bool) -> anyhow::Result<Option<String>> {
        let mut id = id.to_owned();
        let mut expected_tag = None;
        let mut seen = BTreeSet::new();
        for depth in 0..=MAX_TAG_DEPTH {
            ensure!(seen.insert(id.clone()), "Git shallow tag cycle");
            match self.object(&id)? {
                Object::Commit => return Ok((expected_tag != Some(true)).then_some(id)),
                Object::Tag {
                    target,
                    target_is_tag,
                } if tag && depth < MAX_TAG_DEPTH && expected_tag != Some(false) => {
                    id = target;
                    expected_tag = Some(target_is_tag);
                }
                _ => return Ok(None),
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CaptureMode {
    SelectedShallow,
    ObjectWitness,
    TrackedObjectWitness,
}

impl View {
    pub(crate) fn capture(workspace: &File) -> anyhow::Result<Arc<Self>> {
        Self::capture_inner(workspace, CaptureMode::SelectedShallow, None)
    }

    /// Additive component capture. Existing selected-profile behavior is
    /// unchanged; this snapshot also withdraws on workspace entry changes.
    pub(crate) fn capture_object_witness(workspace: &File) -> anyhow::Result<Arc<Self>> {
        Self::capture_inner(workspace, CaptureMode::ObjectWitness, None)
    }

    pub(crate) fn capture_tracked_object_witness(workspace: &File) -> anyhow::Result<Arc<Self>> {
        Self::capture_inner(workspace, CaptureMode::TrackedObjectWitness, None)
    }

    pub(crate) fn capture_linked(
        workspace: &File,
        binding: &super::super::linked_worktree::Binding,
    ) -> anyhow::Result<Arc<Self>> {
        Self::capture_inner(workspace, CaptureMode::ObjectWitness, Some(binding))
    }

    fn capture_inner(
        workspace: &File,
        mode: CaptureMode,
        linked: Option<&super::super::linked_worktree::Binding>,
    ) -> anyhow::Result<Arc<Self>> {
        let object_witness = mode != CaptureMode::SelectedShallow;
        let tracked = mode == CaptureMode::TrackedObjectWitness;
        owned(&workspace.metadata()?)?;
        let mut linked_admin = None;
        let mut controls = Vec::new();
        let (git, observed) = if let Some(binding) = linked {
            let mut source = Withdrawal::new()?;
            source.watch(workspace)?;
            let (admin, common, watches) = binding.roots(workspace)?;
            source.watch(&admin)?;
            source.watch(&common)?;
            for pin in watches {
                source.watch(&pin)?;
            }
            controls = binding.controls(workspace, &admin)?;
            linked_admin = Some(admin);
            (common, Some(source))
        } else if object_witness {
            let (git, source) = object_witness_directory(workspace)?;
            (git, Some(source))
        } else {
            // Preserve legacy capture's lookup/observation order and scope.
            (child(workspace, ".git", true)?, None)
        };
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        ensure!(
            unsafe { libc::fstatfs(git.as_raw_fd(), filesystem.as_mut_ptr()) } == 0,
            "Git shallow filesystem observation failed"
        );
        ensure!(
            matches!(
                unsafe { filesystem.assume_init() }.f_type as u64,
                0xef53 | 0x5846_5342 | 0x9123_683e | 0x0102_1994
            ),
            "Git shallow filesystem unsupported"
        );
        let mut source = match observed {
            Some(source) => source,
            None => Withdrawal::new()?,
        };
        source.watch(&git)?;
        // A pending lock is an unsupported/racy state, never a retry that
        // silently acquires authority over a different reference image.
        entries(&git)?;
        let objects = child(&git, "objects", true)?;
        source.watch(&objects)?;
        for name in ["info", "pack"] {
            let directory = child(&objects, name, true)?;
            source.watch(&directory)?;
            let names = entries(&directory)?;

            ensure!(
                name != "info"
                    || !names
                        .iter()
                        .any(|name| matches!(name.as_str(), "alternates" | "http-alternates")),
                "Git object indirection is unsupported"
            );
        }
        let mut capture = Capture {
            source,
            refs: BTreeMap::new(),
            directories: BTreeSet::new(),
            images: Vec::new(),
            objects,
            object_cache: BTreeMap::new(),
            bytes: 0,
            packed: BTreeSet::new(),
            tracked,
            origins: BTreeMap::new(),
        };
        let mut control_bytes = BTreeMap::new();
        for (name, file, expected) in controls {
            owned(&file.metadata()?)?;
            let bytes = capture.read(file, 8192)?;
            ensure!(
                bytes == expected,
                "linked_worktree_redirection_or_selection_mismatch"
            );
            control_bytes.insert(name, bytes);
        }
        capture.directory(format!("{ROOT}/objects"))?;
        capture.directory(format!("{ROOT}/info"))?;
        let config = capture.read(child(&git, "config", false)?, 8192)?;
        if tracked {
            super::super::super::git_local_clone::validate_config(&config)?;
        } else {
            super::super::validate_configuration(&config)?;
        }
        capture.image(format!("{ROOT}/config"), &config)?;
        let head_root = linked_admin.as_ref().unwrap_or(&git);
        let head = capture.read(child(head_root, "HEAD", false)?, 256)?;
        capture.image(format!("{ROOT}/HEAD"), &head)?;
        if let Some(index) = capture.optional(head_root, "index", 8 * 1024 * 1024)? {
            capture.image(format!("{ROOT}/index"), &index)?;
        }
        let pack_directory = child(&capture.objects, "pack", true)?;
        capture.directory(format!("{ROOT}/objects/pack"))?;
        let pack_names = entries(&pack_directory)?;
        ensure!(pack_names.len() <= 8, "Git pack file count limit");
        for name in &pack_names {
            let stem = name
                .strip_suffix(".pack")
                .or_else(|| name.strip_suffix(".idx"))
                .or_else(|| name.strip_suffix(".rev"))
                .context("Git pack auxiliary format unsupported")?;
            super::oid(
                stem.strip_prefix("pack-")
                    .context("Git pack name invalid")?,
            )?;
            let peer = if name.ends_with(".pack") {
                format!("{stem}.idx")
            } else {
                format!("{stem}.pack")
            };
            ensure!(pack_names.contains(&peer), "Git pack/index pair missing");
            if name.ends_with(".idx") || name.ends_with(".rev") {
                continue;
            }
            let pack = capture.read(child(&pack_directory, name, false)?, MAX_IMAGE_BYTES)?;
            let index = capture.read(child(&pack_directory, &peer, false)?, 1072 + 128 * 28)?;
            let reverse_name = format!("{stem}.rev");
            if pack_names.contains(&reverse_name) {
                let reverse =
                    capture.read(child(&pack_directory, &reverse_name, false)?, 52 + 128 * 4)?;
                super::reverse_index(&reverse, &pack, &index)?;
                capture.image(format!("{ROOT}/objects/pack/{reverse_name}"), &reverse)?;
            }
            let parsed = super::packed_objects(&pack, &index)?;
            for (id, object) in parsed {
                ensure!(
                    capture.object_cache.len() < MAX_OBJECTS
                        && capture.object_cache.insert(id.clone(), object).is_none(),
                    "Git packed object overlap or count limit"
                );
                capture.packed.insert(id);
            }
            capture.image(format!("{ROOT}/objects/pack/{name}"), &pack)?;
            capture.image(format!("{ROOT}/objects/pack/{peer}"), &index)?;
        }
        if let Some(packed) = capture.optional(&git, "packed-refs", 65_536)? {
            let parsed = if tracked {
                super::tracked_packed_references(&packed)?
            } else {
                packed_references(&packed)?
            };
            // Git may consult the packed peeled optimization. It must match
            // the exact bounded object chain, never become a second target.
            for (name, peeled) in &parsed.peels {
                ensure!(
                    capture.target(&parsed.refs[name], true)?.as_ref() == Some(peeled),
                    "Git packed peeled target differs from its object chain"
                );
            }
            for (name, id) in &parsed.refs {
                if tracked && super::is_origin_reference(name) {
                    capture
                        .origins
                        .insert(name.clone(), OriginTarget::Object(id.clone()));
                }
            }
            capture.refs = parsed
                .refs
                .into_iter()
                .map(|(name, id)| (name, Some(id)))
                .collect();
            capture.image(format!("{ROOT}/packed-refs"), &packed)?;
        }
        let refs = child(&git, "refs", true)?;
        ensure!(
            entries(&refs)?
                .iter()
                .all(|name| matches!(name.as_str(), "heads" | "tags")
                    || tracked && name == "remotes"),
            "Git reference namespace unsupported"
        );
        capture.loose_refs(refs, "refs", 0)?;
        super::validate_origin_references(&capture.origins)?;
        if let Some(info) = optional_directory(&git, "info")? {
            capture.source.watch(&info)?;
            ensure!(
                entries(&info)?.iter().all(|name| name == "exclude"),
                "Git repository info machinery unsupported"
            );
            if let Some(exclude) = capture.optional(&info, "exclude", 65_536)? {
                capture.image(format!("{ROOT}/info/exclude"), &exclude)?;
            }
        }
        for prefix in entries(&capture.objects)? {
            if matches!(prefix.as_str(), "info" | "pack") {
                continue;
            }
            ensure!(
                prefix.len() == 2
                    && prefix
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "Git object directory unsupported"
            );
            let directory = child(&capture.objects, &prefix, true)?;
            capture.source.watch(&directory)?;
            capture.directory(format!("{ROOT}/objects/{prefix}"))?;
            for suffix in entries(&directory)? {
                ensure!(
                    !capture.packed.contains(&format!("{prefix}{suffix}")),
                    "Git duplicate loose/packed object storage unsupported"
                );
                capture.object(&format!("{prefix}{suffix}"))?;
            }
        }
        if let Some(bytes) = capture.optional(&git, "shallow", 64 * 41)? {
            for boundary in super::boundaries(&bytes)? {
                ensure!(
                    capture.object_cache.get(&boundary) == Some(&Object::Commit),
                    "Git shallow boundary is not an available supported local commit"
                );
            }
            capture.image(format!("{ROOT}/shallow"), &bytes)?;
        }
        let mut supported = BTreeMap::new();
        for (name, id) in capture.refs.clone() {
            let valid = id.is_some_and(|id| {
                capture
                    .target(&id, name.starts_with("refs/tags/"))
                    .ok()
                    .flatten()
                    .is_some()
            });
            supported.insert(name, valid);
        }
        let head_text = std::str::from_utf8(&head)?;
        let head_text = head_text.strip_suffix('\n').unwrap_or(head_text);
        if let Some(reference) = head_text.strip_prefix("ref: ") {
            ensure!(
                reference.starts_with("refs/heads/") && supported.get(reference) == Some(&true),
                "Git shallow HEAD target unsupported"
            );
        } else {
            ensure!(
                capture.target(&oid(head_text)?, false)?.is_some(),
                "Git detached HEAD target unsupported"
            );
        }
        ensure!(
            capture.source.valid(),
            "Git shallow source changed during capture"
        );
        if let Some(binding) = linked {
            use sha2::{Digest, Sha256};
            use std::os::unix::fs::FileExt;
            for (path, file) in &capture.images {
                let mut bytes = vec![0; usize::try_from(file.metadata()?.len())?];
                file.read_exact_at(&mut bytes, 0)?;
                control_bytes.insert(
                    path.strip_prefix("/workspace/")?
                        .to_str()
                        .context("linked_worktree_path_encoding")?
                        .to_owned(),
                    bytes,
                );
            }
            let mut digest = Sha256::new();
            for (name, bytes) in control_bytes {
                digest.update(name.as_bytes());
                digest.update([0]);
                digest.update(hex::encode(Sha256::digest(bytes)).as_bytes());
                digest.update(b"\n");
            }
            ensure!(
                hex::encode(digest.finalize()) == binding.inputs_sha256,
                "linked_worktree_selected_inputs_changed"
            );
            binding.revalidate_roots()?;
            ensure!(capture.source.valid(), "linked_worktree_source_changed");
        }
        Ok(Arc::new(Self {
            linked: linked.cloned(),
            available: capture.object_cache.keys().cloned().collect(),
            source: Mutex::new(capture.source),
            directories: capture.directories,
            images: capture.images,
            object_witness,
        }))
    }

    pub(crate) fn object_witness_valid(&self) -> anyhow::Result<()> {
        ensure!(self.object_witness, "Git object witness capture required");
        ensure!(
            self.source.lock().is_ok_and(|mut source| source.valid()),
            "Git object witness source withdrawn"
        );
        Ok(())
    }

    /// Read the very same sealed descriptors which `mount` consumes. Never
    /// reopen source paths or infer kind from the cache's Unsupported variant.
    pub(crate) fn object_witness_images(&self) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
        use std::os::unix::fs::FileExt;
        self.object_witness_valid()?;
        let mut result = BTreeMap::new();
        let mut total = 0usize;
        for (path, file) in &self.images {
            let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
            let required =
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
            ensure!(
                seals >= 0 && seals & required == required,
                "Git object image is not sealed"
            );
            let size = usize::try_from(file.metadata()?.len())?;
            total = total
                .checked_add(size)
                .context("Git object image overflow")?;
            ensure!(total <= MAX_IMAGE_BYTES, "Git object image bound");
            let mut bytes = vec![0; size];
            file.read_exact_at(&mut bytes, 0)?;
            let relative = path
                .strip_prefix("/workspace/")?
                .to_str()
                .context("Git image path encoding")?;
            ensure!(
                result.insert(relative.to_owned(), bytes).is_none(),
                "duplicate Git image"
            );
        }
        self.object_witness_valid()?;
        Ok(result)
    }

    pub(crate) fn validate_call(&self, tool: &str, args: &Value) -> anyhow::Result<()> {
        if let Some(binding) = &self.linked {
            binding.revalidate_roots()?;
        }
        ensure!(
            self.source.lock().is_ok_and(|mut source| source.valid()),
            "Git shallow source changed; a new protected session is required"
        );
        let key = match tool {
            "git_show" => Some("revision"),
            "git_diff" => Some("target"),
            _ => None,
        };
        if let Some(reference) = key.and_then(|key| args[key].as_str()) {
            if reference != "HEAD" {
                ensure!(
                    self.available.contains(&reference.to_ascii_lowercase()),
                    "Git shallow local object unavailable"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn mount(&self, command: &mut Command, pins: &mut Vec<File>) -> anyhow::Result<()> {
        if let Some(binding) = &self.linked {
            binding.revalidate_roots()?;
        }
        ensure!(
            self.source.lock().is_ok_and(|mut source| source.valid()),
            "Git shallow source changed during startup"
        );
        if let Some(binding) = &self.linked {
            binding.mount_workspace(command, pins)?;
        }
        command.args(["--size", "16777216", "--tmpfs", ROOT]);
        for path in &self.directories {
            command.arg("--dir").arg(path);
        }
        for (path, image) in &self.images {
            let image = image.try_clone()?;
            // An anonymous memfd has no host pathname to resolve across the
            // new user namespace. Copy its sealed bytes using bwrap's bounded
            // data-file primitive; bwrap closes the input before server exec.
            command
                .arg("--ro-bind-data")
                .arg(image.as_raw_fd().to_string())
                .arg(path);
            pins.push(image);
        }
        command.args(["--remount-ro", ROOT]);
        if self.linked.is_some() {
            command.args(["--remount-ro", "/workspace"]);
        }
        Ok(())
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    fn fixture() -> (tempfile::TempDir, String) {
        fixture_in(None)
    }

    fn fixture_in(parent: Option<&Path>) -> (tempfile::TempDir, String) {
        let root = match parent {
            Some(parent) => tempfile::tempdir_in(parent).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let git = root.path().join(".git");
        for directory in [
            "refs/heads",
            "refs/tags",
            "objects/info",
            "objects/pack",
            "info",
        ] {
            std::fs::create_dir_all(git.join(directory)).unwrap();
        }
        std::fs::write(
            git.join("config"),
            "[core]\nrepositoryformatversion = 0\nbare = false\n",
        )
        .unwrap();
        std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let payload = format!("tree {}\n\nOwned.\n", "a".repeat(40));
        let raw = format!("commit {}\0{payload}", payload.len()).into_bytes();
        let id = sha1_smol::Sha1::from(&raw).digest().to_string();
        let mut compressor =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        compressor.write_all(&raw).unwrap();
        std::fs::create_dir(git.join("objects").join(&id[..2])).unwrap();
        std::fs::write(
            git.join("objects").join(&id[..2]).join(&id[2..]),
            compressor.finish().unwrap(),
        )
        .unwrap();
        std::fs::write(git.join("refs/heads/main"), format!("{id}\n")).unwrap();
        std::fs::write(git.join("refs/tags/lightweight"), format!("{id}\n")).unwrap();
        std::fs::write(git.join("shallow"), format!("{id}\n")).unwrap();
        (root, id)
    }

    #[test]
    fn object_witness_observes_workspace_before_git_lookup() {
        let (root, _) = fixture();
        let (replacement, _) = fixture();
        let workspace = File::open(root.path()).unwrap();
        let selected = root.path().join(".git");
        let retained = root.path().join("owned-retained-directory");
        let incoming = replacement.path().join(".git");

        // Calibrate the old observation order with only owned directories:
        // the held directory and the current entry differ, but watches added
        // after the exchange have no retrospective event to consume.
        let held = child(&workspace, ".git", true).unwrap();
        std::fs::rename(&selected, &retained).unwrap();
        std::fs::rename(&incoming, &selected).unwrap();
        let mut late = Withdrawal::new().unwrap();
        late.watch(&workspace).unwrap();
        late.watch(&held).unwrap();
        assert_ne!(
            held.metadata().unwrap().ino(),
            child(&workspace, ".git", true)
                .unwrap()
                .metadata()
                .unwrap()
                .ino()
        );
        assert!(
            late.valid(),
            "late observation cannot cover a prior entry exchange"
        );
        drop(late);
        drop(held);
        std::fs::rename(&selected, &incoming).unwrap();
        std::fs::rename(&retained, &selected).unwrap();

        // Repeat at the exact old gap in the real object-witness capture.
        // Hook installation is private to this test thread and consumed once.
        let selected_copy = selected.clone();
        let retained_copy = retained.clone();
        let incoming_copy = incoming.clone();
        AFTER_OBJECT_WITNESS_GIT_OPEN.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(selected_copy, retained_copy).unwrap();
                std::fs::rename(incoming_copy, selected).unwrap();
            }));
        });
        let captured = View::capture_object_witness(&workspace);
        assert!(AFTER_OBJECT_WITNESS_GIT_OPEN.with(|slot| slot.borrow().is_none()));
        assert!(captured.is_err());
        assert!(captured
            .unwrap_err()
            .to_string()
            .contains("workspace changed during lookup"));

        let selected = root.path().join(".git");
        std::fs::rename(&selected, &incoming).unwrap();
        std::fs::rename(&retained, &selected).unwrap();
        let fresh = View::capture_object_witness(&workspace).unwrap();
        fresh.object_witness_valid().unwrap();
        fresh
            .validate_call("git_show", &serde_json::json!({"revision":"HEAD"}))
            .unwrap();
    }

    // The fresh positive fixture needs an independently observed writer-close
    // boundary. Production capture still refuses any uncertain source state.
    struct MappingClose {
        file: File,
        watch: i32,
        name: Vec<u8>,
    }

    impl MappingClose {
        fn new(path: &Path) -> Self {
            let directory = File::open(path.parent().unwrap()).unwrap();
            let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            assert!(fd >= 0, "owned mapper-close observer unavailable");
            let file = unsafe { File::from_raw_fd(fd) };
            let anchor = CString::new(format!("/proc/self/fd/{}", directory.as_raw_fd())).unwrap();
            let watch = unsafe {
                libc::inotify_add_watch(
                    file.as_raw_fd(),
                    anchor.as_ptr(),
                    libc::IN_ONLYDIR | libc::IN_CLOSE_WRITE,
                )
            };
            assert!(watch >= 0, "owned mapper-close watch unavailable");
            Self {
                file,
                watch,
                name: path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            }
        }

        fn closed(&self) -> bool {
            let mut found = false;
            let mut bytes = [0_u8; 4096];
            for _ in 0..16 {
                let count = unsafe {
                    libc::read(
                        self.file.as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                    )
                };
                if count < 0 {
                    match std::io::Error::last_os_error().raw_os_error() {
                        Some(libc::EINTR) => continue,
                        Some(libc::EAGAIN) => return found,
                        other => panic!("owned mapper-close read failed: {other:?}"),
                    }
                }
                assert!(count > 0, "owned mapper-close observer closed");
                let count = count as usize;
                let header = std::mem::size_of::<libc::inotify_event>();
                let mut offset = 0;
                while offset < count {
                    assert!(count - offset >= header, "truncated mapper-close event");
                    let event = unsafe {
                        std::ptr::read_unaligned(
                            bytes.as_ptr().add(offset).cast::<libc::inotify_event>(),
                        )
                    };
                    let end = offset + header + event.len as usize;
                    assert!(end <= count, "truncated mapper-close name");
                    assert_eq!(
                        event.mask & (libc::IN_Q_OVERFLOW | libc::IN_IGNORED | libc::IN_UNMOUNT),
                        0,
                        "owned mapper-close observation lost"
                    );
                    assert_eq!(event.wd, self.watch, "owned mapper-close watch changed");
                    let name = bytes[offset + header..end]
                        .split(|byte| *byte == 0)
                        .next()
                        .unwrap();
                    if event.mask & libc::IN_CLOSE_WRITE != 0 && name == self.name {
                        found = true;
                    }
                    offset = end;
                }
            }
            panic!("owned mapper-close events exceed bound");
        }

        fn wait(&self) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                if self.closed() {
                    return;
                }
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                assert!(
                    !remaining.is_zero(),
                    "timed out waiting for owned mapper CLOSE_WRITE"
                );
                let mut fd = libc::pollfd {
                    fd: self.file.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let result = unsafe { libc::poll(&mut fd, 1, remaining.as_millis().max(1) as i32) };
                if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                {
                    continue;
                }
                assert!(
                    result > 0,
                    "timed out or failed waiting for owned mapper CLOSE_WRITE"
                );
                assert_eq!(
                    fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL),
                    0,
                    "owned mapper-close poll observation lost"
                );
            }
        }
    }

    struct Mapping {
        _file: File,
        address: *mut u8,
        length: usize,
    }

    impl Mapping {
        fn new(path: &Path) -> Self {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let file = loop {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(path)
                {
                    Ok(file) => break file,
                    Err(error)
                        if error.raw_os_error() == Some(libc::EAGAIN)
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(error) => panic!("owned writable mapping did not open promptly: {error}"),
                }
            };
            let length = file.metadata().unwrap().len() as usize;
            let address = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    file.as_raw_fd(),
                    0,
                )
            };
            assert_ne!(address, libc::MAP_FAILED);
            Self {
                _file: file,
                address: address.cast(),
                length,
            }
        }

        fn first(&self) -> u8 {
            unsafe { self.address.read_volatile() }
        }

        fn set_first(&self, value: u8) {
            unsafe {
                self.address.write_volatile(value);
                assert_eq!(
                    libc::msync(self.address.cast(), self.length, libc::MS_SYNC),
                    0
                );
            }
        }
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::munmap(self.address.cast(), self.length) }, 0);
        }
    }

    #[test]
    fn mapped_writes_demonstrate_why_inotify_is_not_content_authority() {
        for parent in [None, Some(Path::new("/dev/shm"))] {
            let (root, _) = fixture_in(parent);
            let path = root.path().join(".git/shallow");
            let before = std::fs::read(&path).unwrap();
            let mut observer = Withdrawal::new().unwrap();
            observer
                .watch(&File::open(path.parent().unwrap()).unwrap())
                .unwrap();
            let mapping = Mapping::new(&path);
            mapping.set_first(if mapping.first() == b'a' { b'b' } else { b'a' });
            assert_ne!(std::fs::read(&path).unwrap(), before);
            assert!(observer.valid(), "this reproducer expects the inotify blind interval while the writable FD remains open");
            mapping.set_first(before[0]);
        }
    }

    #[test]
    fn mappings_existing_before_capture_refuse_even_after_byte_restoration() {
        for parent in [None, Some(Path::new("/dev/shm"))] {
            let (root, _) = fixture_in(parent);
            let path = root.path().join(".git/shallow");
            let before = std::fs::read(&path).unwrap();
            let close = MappingClose::new(&path);
            let mapping = Mapping::new(&path);
            assert!(
                !close.closed(),
                "mapper close cannot complete while its writer remains open"
            );
            let workspace = File::open(root.path()).unwrap();
            assert!(View::capture(&workspace).is_err());
            mapping.set_first(if before[0] == b'a' { b'b' } else { b'a' });
            assert_ne!(std::fs::read(&path).unwrap(), before);
            assert!(View::capture(&workspace).is_err());
            mapping.set_first(before[0]);
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert!(View::capture(&workspace).is_err());
            assert!(
                !close.closed(),
                "restored bytes cannot establish mapper closure"
            );
            drop(mapping);
            close.wait();
            let view = View::capture(&workspace).unwrap();
            for _ in 0..8 {
                view.validate_call("git_show", &serde_json::json!({"revision":"HEAD"}))
                    .unwrap();
            }
        }
    }

    #[test]
    fn mapping_created_after_capture_cannot_hide_write_restore_between_boundaries() {
        for parent in [None, Some(Path::new("/dev/shm"))] {
            let (root, _) = fixture_in(parent);
            let path = root.path().join(".git/shallow");
            let before = std::fs::read(&path).unwrap();
            let workspace = File::open(root.path()).unwrap();
            let view = View::capture(&workspace).unwrap();
            let args = serde_json::json!({"revision":"HEAD"});
            view.validate_call("git_show", &args).unwrap();
            let mapping = Mapping::new(&path);
            mapping.set_first(if before[0] == b'a' { b'b' } else { b'a' });
            assert_ne!(std::fs::read(&path).unwrap(), before);
            mapping.set_first(before[0]);
            assert_eq!(std::fs::read(&path).unwrap(), before);
            // No validation occurred between write and restore. The retained
            // kernel proof still records the write-open break permanently.
            assert!(view.validate_call("git_show", &args).is_err());
            drop(mapping);
            assert!(view.validate_call("git_show", &args).is_err());
            let fresh = View::capture(&workspace).unwrap();
            fresh.validate_call("git_show", &args).unwrap();
        }
    }

    #[test]
    fn reference_image_is_sealed_and_source_withdrawal_is_sticky() {
        let (root, id) = fixture();
        let view = View::capture(&File::open(root.path()).unwrap()).unwrap();
        let args = serde_json::json!({"repo_path":"/workspace","revision":"HEAD"});
        view.validate_call("git_show", &args).unwrap();
        view.validate_call("git_show", &serde_json::json!({"revision":"HEAD"}))
            .unwrap();
        let image = &view
            .images
            .iter()
            .find(|(path, _)| path == Path::new("/workspace/.git/shallow"))
            .unwrap()
            .1;
        let seals = unsafe { libc::fcntl(image.as_raw_fd(), libc::F_GET_SEALS) };
        assert_eq!(seals & libc::F_SEAL_WRITE, libc::F_SEAL_WRITE);
        let path = root.path().join(".git/shallow");
        std::fs::write(&path, format!("{}\n", "b".repeat(40))).unwrap();
        assert!(view.validate_call("git_show", &args).is_err());
        std::fs::write(&path, format!("{id}\n")).unwrap();
        assert!(view.validate_call("git_show", &args).is_err());
    }

    #[test]
    fn replacing_a_reference_does_not_transfer_the_original_view() {
        let (root, id) = fixture();
        let view = View::capture(&File::open(root.path()).unwrap()).unwrap();
        let reference = root.path().join(".git/refs/heads/main");
        std::fs::rename(&reference, reference.with_file_name("retired")).unwrap();
        std::fs::write(&reference, format!("{id}\n")).unwrap();
        assert!(view
            .validate_call("git_show", &serde_json::json!({"revision":"HEAD"}))
            .is_err());
    }

    #[test]
    fn template_free_repository_does_not_require_an_info_directory() {
        let (root, _) = fixture();
        std::fs::remove_dir(root.path().join(".git/info")).unwrap();
        let view = View::capture(&File::open(root.path()).unwrap()).unwrap();
        view.validate_call("git_show", &serde_json::json!({"revision":"HEAD"}))
            .unwrap();
    }
}
