// SPDX-License-Identifier: Apache-2.0
//! Installed guided-pilot front door.
//!
//! The accepted guided pilot (`scripts/pilot.py`, SOU-138) is a set of Python
//! helpers. This module installs those helper bytes as a private, verified
//! component and starts them from the installed Agent with an exact recorded
//! interpreter, so an operator needs no checkout, no project-provided helper
//! and no ambient Python selection. The helpers keep one implementation of
//! preparation and run semantics; nothing here prepares, runs or reports
//! protection itself.
//!
//! A component is a deterministic ustar archive: a canonical `manifest.json`
//! (schema `sw-pilot-front-door-component/1`) followed by every listed file in
//! manifest order. Component id = SHA-256 of the manifest bytes.
//!
//! Layout under `<home>/pilot-front-door/` (private, owner-only):
//! `components/<id>/{manifest.json,tree/...}`, `current.json`, `previous.json`,
//! `journal.json` (only while an install is in flight) and transient
//! `staging-*` directories. Nothing outside this directory is touched.

use std::collections::BTreeSet;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, ensure, Context};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub mod removal;

pub const COMPONENT_SCHEMA: &str = "sw-pilot-front-door-component/1";
pub const POINTER_SCHEMA: &str = "sw-pilot-front-door-current/1";
pub const SOURCE_FORMAT: &str = "sw-pilot-source-identity/1";
/// Interpreter range the helpers are qualified with (they need `tomllib`).
pub const PYTHON_RANGE: &str = "cpython>=3.11,<3.14";
const PYTHON_MIN: (u32, u32) = (3, 11);
const PYTHON_MAX_EXCLUSIVE: (u32, u32) = (3, 14);
pub const ENTRY: &str = "scripts/pilot.py";
pub const SOURCE_FILE: &str = "source-identity.json";
const MANIFEST: &str = "manifest.json";
const TREE: &str = "tree";
const DIR_NAME: &str = "pilot-front-door";
const MAX_ARCHIVE: usize = 32 * 1024 * 1024;
const MAX_FILE: u64 = 1024 * 1024;
// The full helper and runtime-notice closure contains 142 files. Archive,
// manifest and individual-file byte budgets remain independently enforced.
const MAX_FILES: usize = 160;
const MAX_MANIFEST: usize = 64 * 1024;
const MAX_NAME: usize = 100;
const MAX_INTERPRETER: u64 = 256 * 1024 * 1024;

pub fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------- manifest

/// Fields are declared in sorted order: the canonical bytes are compact JSON
/// with sorted keys, so a re-serialization must reproduce the manifest exactly.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub mode: String,
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub commit: String,
    pub tree: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub entry: String,
    pub files: Vec<FileEntry>,
    pub python: String,
    pub schema: String,
    pub source: Source,
}

impl FileEntry {
    fn mode_bits(&self) -> u32 {
        if self.mode == "0500" {
            0o500
        } else {
            0o400
        }
    }
}

fn valid_path(path: &str) -> bool {
    path.len() <= MAX_NAME
        && !path.is_empty()
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        })
}

/// Directories implied by the listed files, e.g. `scripts` for `scripts/pilot.py`.
fn implied_dirs(manifest: &Manifest) -> BTreeSet<String> {
    let mut dirs = BTreeSet::new();
    for entry in &manifest.files {
        let mut at = entry.path.as_str();
        while let Some(index) = at.rfind('/') {
            at = &at[..index];
            dirs.insert(at.to_string());
        }
    }
    dirs
}

pub fn parse_manifest(bytes: &[u8]) -> anyhow::Result<Manifest> {
    ensure!(
        bytes.len() <= MAX_MANIFEST,
        "manifest exceeds the size limit"
    );
    let manifest: Manifest = serde_json::from_slice(bytes).context("malformed manifest")?;
    ensure!(
        serde_json::to_vec(&manifest)? == bytes,
        "manifest is not canonical"
    );
    ensure!(
        manifest.schema == COMPONENT_SCHEMA,
        "unsupported manifest schema"
    );
    ensure!(manifest.entry == ENTRY, "unsupported component entry point");
    ensure!(
        manifest.python == PYTHON_RANGE,
        "unsupported interpreter requirement"
    );
    ensure!(
        is_hex(&manifest.source.commit, 40) && is_hex(&manifest.source.tree, 40),
        "manifest source identity is invalid"
    );
    ensure!(
        !manifest.files.is_empty() && manifest.files.len() <= MAX_FILES,
        "manifest file count is out of range"
    );
    let mut previous: Option<&str> = None;
    for entry in &manifest.files {
        ensure!(
            valid_path(&entry.path) && entry.path != MANIFEST,
            "unsupported component path: {}",
            entry.path
        );
        ensure!(
            previous.is_none_or(|p| p < entry.path.as_str()),
            "manifest paths are duplicated or not sorted"
        );
        previous = Some(&entry.path);
        ensure!(
            entry.mode == "0400" || entry.mode == "0500",
            "unsupported file mode for {}",
            entry.path
        );
        ensure!(
            is_hex(&entry.sha256, 64) && entry.size <= MAX_FILE,
            "invalid digest or size for {}",
            entry.path
        );
    }
    let names: BTreeSet<&str> = manifest.files.iter().map(|e| e.path.as_str()).collect();
    ensure!(
        names.contains(ENTRY) && names.contains(SOURCE_FILE),
        "manifest misses the entry point or the source identity"
    );
    for dir in implied_dirs(&manifest) {
        ensure!(
            !names.contains(dir.as_str()),
            "a listed file is also a directory: {dir}"
        );
    }
    Ok(manifest)
}

/// The recorded source identity must be exactly the manifest's clean commit.
fn check_source_identity(manifest: &Manifest, bytes: &[u8]) -> anyhow::Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Identity {
        format: String,
        source: Recorded,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Recorded {
        commit: String,
        dirty: bool,
        files_sha256: String,
        tree: String,
    }
    let identity: Identity =
        serde_json::from_slice(bytes).context("malformed component source identity")?;
    ensure!(
        identity.format == SOURCE_FORMAT
            && !identity.source.dirty
            && is_hex(&identity.source.files_sha256, 64)
            && identity.source.commit == manifest.source.commit
            && identity.source.tree == manifest.source.tree,
        "component source identity does not match the manifest"
    );
    Ok(())
}

// ------------------------------------------------------------------ archive

fn field_str(field: &[u8]) -> anyhow::Result<&str> {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    ensure!(
        field[end..].iter().all(|b| *b == 0),
        "archive header field has trailing data"
    );
    std::str::from_utf8(&field[..end]).context("archive header field is not UTF-8")
}

fn field_octal(field: &[u8]) -> anyhow::Result<u64> {
    let text = std::str::from_utf8(field)
        .context("archive numeric field is not UTF-8")?
        .trim_matches(|c| c == ' ' || c == '\0');
    ensure!(
        !text.is_empty() && text.bytes().all(|b| (b'0'..=b'7').contains(&b)),
        "archive numeric field is invalid"
    );
    Ok(u64::from_str_radix(text, 8)?)
}

/// One strict ustar member: a regular file named exactly `expected`.
fn member<'a>(bytes: &'a [u8], at: &mut usize, expected: &str) -> anyhow::Result<&'a [u8]> {
    ensure!(*at + 512 <= bytes.len(), "archive is truncated");
    let header = &bytes[*at..*at + 512];
    ensure!(
        &header[257..263] == b"ustar\0" && &header[263..265] == b"00",
        "archive member is not ustar"
    );
    let name = field_str(&header[0..100])?;
    ensure!(
        name == expected,
        "unexpected, duplicated or unlisted archive member: {name}"
    );
    ensure!(
        header[156] == b'0',
        "archive member {name} is not a regular file (links, devices and directories are refused)"
    );
    ensure!(
        header[157..257].iter().all(|b| *b == 0),
        "archive member {name} carries a link target"
    );
    ensure!(
        header[345..512].iter().all(|b| *b == 0),
        "archive member {name} has a path prefix or extra header data"
    );
    let stored = field_octal(&header[148..156])?;
    let mut copy = header.to_vec();
    copy[148..156].copy_from_slice(b"        ");
    let actual: u64 = copy.iter().map(|b| *b as u64).sum();
    ensure!(stored == actual, "archive header checksum mismatch");
    let size = field_octal(&header[124..136])?;
    ensure!(
        size <= MAX_FILE.max(MAX_MANIFEST as u64),
        "archive member exceeds the size limit"
    );
    let start = *at + 512;
    let end = start + size as usize;
    let padded = start + (size as usize).div_ceil(512) * 512;
    ensure!(padded <= bytes.len(), "archive is truncated");
    ensure!(
        bytes[end..padded].iter().all(|b| *b == 0),
        "archive member padding is not zero"
    );
    *at = padded;
    Ok(&bytes[start..end])
}

#[derive(Debug, Clone)]
pub struct Package {
    pub manifest: Manifest,
    pub manifest_bytes: Vec<u8>,
    pub contents: Vec<Vec<u8>>,
}

impl Package {
    pub fn id(&self) -> String {
        sha(&self.manifest_bytes)
    }
}

/// Strict reader: manifest first, then exactly the listed files in order with
/// their sizes and digests, then the end-of-archive marker and nothing else.
pub fn parse(bytes: &[u8]) -> anyhow::Result<Package> {
    ensure!(bytes.len() <= MAX_ARCHIVE, "archive exceeds the size limit");
    let mut at = 0usize;
    let manifest_bytes = member(bytes, &mut at, MANIFEST)?.to_vec();
    let manifest = parse_manifest(&manifest_bytes)?;
    let mut contents = Vec::with_capacity(manifest.files.len());
    for entry in &manifest.files {
        let data = member(bytes, &mut at, &entry.path)?;
        ensure!(
            data.len() as u64 == entry.size && sha(data) == entry.sha256,
            "archive member {} does not match the manifest",
            entry.path
        );
        if entry.path == SOURCE_FILE {
            check_source_identity(&manifest, data)?;
        }
        contents.push(data.to_vec());
    }
    ensure!(
        bytes.len() == at + 1024 && bytes[at..].iter().all(|b| *b == 0),
        "archive has unlisted members or trailing data"
    );
    Ok(Package {
        manifest,
        manifest_bytes,
        contents,
    })
}

pub fn read_archive_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_ARCHIVE as u64,
        "the archive is not a regular file within the size limit"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_ARCHIVE as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_ARCHIVE, "archive exceeds the size limit");
    Ok(bytes)
}

// -------------------------------------------------------------- interpreter

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PythonRecord {
    pub path: String,
    pub sha256: String,
    pub version: String,
}

fn hash_file(path: &Path, limit: u64) -> anyhow::Result<String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(total <= limit, "file exceeds the hash size limit");
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// The exact interpreter the operator names: absolute, canonical, CPython in
/// the supported range. Never looked up on PATH.
pub fn probe_python(python: &Path) -> anyhow::Result<PythonRecord> {
    ensure!(
        python.is_absolute(),
        "--python must be an absolute path to a local CPython (no PATH lookup, no download)"
    );
    let canonical = python
        .canonicalize()
        .with_context(|| format!("interpreter not found: {}", python.display()))?;
    let metadata = std::fs::metadata(&canonical)?;
    ensure!(
        metadata.is_file() && metadata.mode() & 0o022 == 0,
        "interpreter is not a regular file protected from group/other writes"
    );
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        metadata.uid() == 0 || metadata.uid() == uid,
        "interpreter is owned by another user"
    );
    let output = std::process::Command::new(&canonical)
        .args([
            "-I",
            "-S",
            "-c",
            "import sys;print(sys.implementation.name, *sys.version_info[:3])",
        ])
        .env_clear()
        .current_dir("/")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .context("interpreter could not be started")?;
    ensure!(output.status.success(), "interpreter probe failed");
    let text = String::from_utf8(output.stdout)?;
    let parts: Vec<&str> = text.split_whitespace().collect();
    ensure!(parts.len() == 4, "interpreter probe output is unexpected");
    ensure!(parts[0] == "cpython", "interpreter is not CPython");
    let (major, minor): (u32, u32) = (parts[1].parse()?, parts[2].parse()?);
    ensure!(
        (major, minor) >= PYTHON_MIN && (major, minor) < PYTHON_MAX_EXCLUSIVE,
        "interpreter {major}.{minor} is outside the supported range {PYTHON_RANGE}"
    );
    Ok(PythonRecord {
        path: canonical
            .to_str()
            .context("interpreter path is not UTF-8")?
            .to_string(),
        sha256: hash_file(&canonical, MAX_INTERPRETER)?,
        version: format!("{major}.{minor}.{}", parts[3]),
    })
}

// ------------------------------------------------------------ private files

fn private_ok(metadata: &std::fs::Metadata) -> bool {
    // SAFETY: geteuid has no preconditions.
    metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0
}

fn write_private(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    // The umask may only remove bits; set the exact listed mode.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn sync_dir(dir: &Path) {
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", crate::token::generate()));
    write_private(&tmp, bytes, 0o600)?;
    std::fs::rename(&tmp, path)?;
    sync_dir(path.parent().context("path has no parent")?);
    Ok(())
}

fn read_private(path: &Path, limit: u64, mode: Option<u32>) -> anyhow::Result<Vec<u8>> {
    let metadata =
        std::fs::symlink_metadata(path).with_context(|| format!("missing {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "{} is not a regular file (links are refused)",
        path.display()
    );
    ensure!(
        private_ok(&metadata) && metadata.nlink() == 1,
        "{} is not private to its owner",
        path.display()
    );
    if let Some(mode) = mode {
        ensure!(
            metadata.mode() & 0o7777 == mode,
            "{} has an unexpected mode",
            path.display()
        );
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut bytes = Vec::new();
    options
        .open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "{} exceeds the size limit",
        path.display()
    );
    Ok(bytes)
}

fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Create the directory if absent, then require it private (never adopted or repaired).
fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    if std::fs::symlink_metadata(dir).is_err() {
        create_private_dir(dir)?;
    }
    verify_private_dir(dir)
}

fn verify_private_dir(dir: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(dir)
        .with_context(|| format!("{} is not installed", dir.display()))?;
    ensure!(
        metadata.file_type().is_dir() && private_ok(&metadata),
        "{} must be a private directory owned by the current user",
        dir.display()
    );
    Ok(())
}

/// No linked ancestors between the filesystem root and `root`.
fn check_ancestors(root: &Path) -> anyhow::Result<()> {
    for part in root.ancestors() {
        if part.as_os_str().is_empty() {
            continue;
        }
        if let Ok(metadata) = std::fs::symlink_metadata(part) {
            ensure!(
                !metadata.file_type().is_symlink(),
                "{} is a link; refusing a redirected component location",
                part.display()
            );
        }
    }
    Ok(())
}

// ------------------------------------------- descriptor-anchored removal

const MAX_REMOVE_DEPTH: usize = 32;
const MAX_REMOVE_ENTRIES: usize = 4096;

fn c_name(name: &str) -> anyhow::Result<std::ffi::CString> {
    ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.contains('/'),
        "unsupported path component"
    );
    Ok(std::ffi::CString::new(name)?)
}

fn owned(fd: libc::c_int, what: &str) -> anyhow::Result<OwnedFd> {
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("cannot open {what} without following links"));
    }
    // SAFETY: `fd` was just returned by open/openat and is owned only here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open the directory `name` below `parent`; a link is never followed.
fn open_dir_at(parent: &OwnedFd, name: &str) -> anyhow::Result<OwnedFd> {
    let cname = c_name(name)?;
    // SAFETY: valid descriptor and NUL-terminated name; the result is checked.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            cname.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned(fd, name)
}

fn stat_fd(fd: &OwnedFd) -> anyhow::Result<libc::stat> {
    // SAFETY: zeroed is a valid initial value for the plain C struct.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid descriptor and out pointer.
    ensure!(
        unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } == 0,
        "cannot inspect an opened directory"
    );
    Ok(st)
}

/// `name` below `parent`, inspected without following a link.
fn stat_at(parent: &OwnedFd, name: &str) -> anyhow::Result<Option<libc::stat>> {
    let cname = c_name(name)?;
    // SAFETY: zeroed is a valid initial value for the plain C struct.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid descriptor, name and out pointer.
    let code = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            cname.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if code != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).with_context(|| format!("cannot inspect {name}"));
    }
    Ok(Some(st))
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn require_private_fd(fd: &OwnedFd, what: &str) -> anyhow::Result<()> {
    let st = stat_fd(fd)?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        is_dir(&st) && st.st_uid == uid && st.st_mode & 0o077 == 0,
        "{what} is not a private directory of the current user; refusing to delete through it"
    );
    Ok(())
}

/// Open an absolute directory one component at a time from `/`. Every
/// component, including each parent, is opened without following a link.
fn open_path_nofollow(path: &Path) -> anyhow::Result<OwnedFd> {
    ensure!(
        path.is_absolute(),
        "the component location must be absolute"
    );
    // SAFETY: constant NUL-terminated path; the result is checked.
    let mut fd = owned(
        unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        },
        "/",
    )?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = name.to_str().context("non-UTF-8 component location")?;
                fd = open_dir_at(&fd, name).with_context(|| {
                    format!(
                        "{} has a linked or missing parent; refusing a redirected component location",
                        path.display()
                    )
                })?;
            }
            _ => bail!("the component location must be a plain absolute path"),
        }
    }
    Ok(fd)
}

fn unlink_at(parent: &OwnedFd, name: &str, flags: libc::c_int) -> anyhow::Result<()> {
    let cname = c_name(name)?;
    // SAFETY: valid descriptor and NUL-terminated name; the result is checked.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), cname.as_ptr(), flags) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("cannot remove {name}"));
    }
    Ok(())
}

/// Remove `name` below the open directory `parent`. Descent happens only
/// through descriptors opened without following links, and each opened
/// directory must be the inspected one; a link is removed as a link.
fn remove_tree_at(
    parent: &OwnedFd,
    name: &str,
    depth: usize,
    budget: &mut usize,
) -> anyhow::Result<()> {
    ensure!(depth <= MAX_REMOVE_DEPTH, "component tree is too deep");
    let st = stat_at(parent, name)?.with_context(|| format!("{name} disappeared"))?;
    if !is_dir(&st) {
        return unlink_at(parent, name, 0);
    }
    let dir = open_dir_at(parent, name)?;
    let opened = stat_fd(&dir)?;
    ensure!(
        opened.st_dev == st.st_dev && opened.st_ino == st.st_ino,
        "{name} changed during removal"
    );
    let mut names = Vec::new();
    // The descriptor's own directory, not a path lookup.
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
        let entry = entry?;
        names.push(
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF-8 name in the component tree"))?,
        );
    }
    for child in names {
        *budget = budget
            .checked_sub(1)
            .context("the component tree has too many entries")?;
        remove_tree_at(&dir, &child, depth + 1, budget)?;
    }
    unlink_at(parent, name, libc::AT_REMOVEDIR)
}

// ------------------------------------------------------------------- store

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pointer {
    pub component: String,
    pub python: PythonRecord,
    pub schema: String,
}

/// A component whose every file, mode, the tree shape and the interpreter
/// were verified just now.
#[derive(Debug, Clone)]
pub struct Verified {
    pub id: String,
    pub tree: PathBuf,
    pub manifest: Manifest,
    pub python: PythonRecord,
}

/// A failure with a stable reason and the exact preparation action.
#[derive(Debug)]
pub struct Unavailable {
    pub reason: &'static str,
    pub action: String,
    pub detail: String,
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} ({})", self.reason, self.detail, self.action)
    }
}

impl std::error::Error for Unavailable {}

const INSTALL_ACTION: &str = "build the component in a clean reviewed checkout with `python3 -B scripts/build-pilot-front-door.py --out FILE`, then run `agentfw pilot-component install FILE --sha256 ARCHIVE_SHA256 --python /ABSOLUTE/python3`";

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(home: &Path) -> Self {
        let home = if home.is_absolute() {
            home.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(home))
                .unwrap_or_else(|_| home.to_path_buf())
        };
        Self {
            root: home.join(DIR_NAME),
        }
    }

    /// The Agent home, opened from `/` without following any link.
    fn open_home(&self) -> anyhow::Result<OwnedFd> {
        open_path_nofollow(self.root.parent().context("component root has no parent")?)
    }

    /// The private component root, or None when nothing is installed. Every
    /// parent is resolved through no-follow descriptors.
    fn open_root(&self) -> anyhow::Result<Option<(OwnedFd, OwnedFd)>> {
        let home = self.open_home()?;
        let Some(st) = stat_at(&home, DIR_NAME)? else {
            return Ok(None);
        };
        ensure!(
            is_dir(&st),
            "the component directory is linked or not a directory; refusing to delete through it"
        );
        let root = open_dir_at(&home, DIR_NAME)?;
        require_private_fd(&root, "the component directory")?;
        Ok(Some((home, root)))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    fn components(&self) -> PathBuf {
        self.root.join("components")
    }
    fn current_path(&self) -> PathBuf {
        self.root.join("current.json")
    }
    fn previous_path(&self) -> PathBuf {
        self.root.join("previous.json")
    }
    fn journal_path(&self) -> PathBuf {
        self.root.join("journal.json")
    }

    fn interrupted(&self) -> bool {
        std::fs::symlink_metadata(self.journal_path()).is_ok()
    }

    fn refuse_interrupted(&self) -> anyhow::Result<()> {
        ensure!(
            !self.interrupted(),
            "an interrupted component install was detected: run `agentfw pilot-component recover`"
        );
        Ok(())
    }

    fn read_pointer(&self, path: &Path) -> anyhow::Result<Option<Pointer>> {
        if std::fs::symlink_metadata(path).is_err() {
            return Ok(None);
        }
        let pointer: Pointer = serde_json::from_slice(&read_private(path, 16 * 1024, None)?)
            .context("selection pointer is malformed")?;
        ensure!(
            pointer.schema == POINTER_SCHEMA && is_hex(&pointer.component, 64),
            "selection pointer is invalid"
        );
        Ok(Some(pointer))
    }

    /// Verify one installed component and the interpreter recorded for it.
    pub fn verify_component(&self, id: &str, python: &PythonRecord) -> anyhow::Result<Verified> {
        ensure!(is_hex(id, 64), "invalid component id");
        check_ancestors(&self.root)?;
        verify_private_dir(&self.root)?;
        verify_private_dir(&self.components())?;
        let dir = self.components().join(id);
        verify_private_dir(&dir).with_context(|| format!("component {id} cannot be used"))?;
        let mut top = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            top.push(entry?.file_name().to_string_lossy().into_owned());
        }
        top.sort();
        ensure!(
            top == [MANIFEST, TREE],
            "component directory has missing or unlisted entries"
        );
        let manifest_bytes = read_private(&dir.join(MANIFEST), MAX_MANIFEST as u64, Some(0o400))?;
        ensure!(sha(&manifest_bytes) == id, "component manifest was altered");
        let manifest = parse_manifest(&manifest_bytes)?;
        let tree = dir.join(TREE);
        // Walk the whole tree: exactly the listed files and their directories.
        let mut files = BTreeSet::new();
        let mut dirs = BTreeSet::new();
        let mut stack = vec![(tree.clone(), String::new())];
        while let Some((path, relative)) = stack.pop() {
            verify_private_dir(&path)?;
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .to_str()
                    .context("non-UTF-8 name")?
                    .to_string();
                let rel = if relative.is_empty() {
                    name
                } else {
                    format!("{relative}/{name}")
                };
                let kind = entry.file_type()?;
                ensure!(!kind.is_symlink(), "component contains a link: {rel}");
                if kind.is_dir() {
                    ensure!(dirs.insert(rel.clone()), "duplicate directory {rel}");
                    ensure!(dirs.len() <= MAX_FILES, "too many component directories");
                    stack.push((entry.path(), rel));
                } else {
                    ensure!(kind.is_file(), "component contains a special file: {rel}");
                    files.insert(rel);
                    ensure!(files.len() <= MAX_FILES, "too many component files");
                }
            }
        }
        let listed: BTreeSet<String> = manifest.files.iter().map(|e| e.path.clone()).collect();
        if let Some(extra) = files.difference(&listed).next() {
            bail!("unlisted file in the installed component: {extra}");
        }
        if let Some(missing) = listed.difference(&files).next() {
            bail!("listed file missing from the installed component: {missing}");
        }
        ensure!(
            dirs == implied_dirs(&manifest),
            "the installed component has unlisted directories"
        );
        for entry in &manifest.files {
            let bytes = read_private(&tree.join(&entry.path), MAX_FILE, Some(entry.mode_bits()))
                .with_context(|| format!("component file {} cannot be used", entry.path))?;
            ensure!(
                bytes.len() as u64 == entry.size && sha(&bytes) == entry.sha256,
                "component file {} changed since installation",
                entry.path
            );
            if entry.path == SOURCE_FILE {
                check_source_identity(&manifest, &bytes)?;
            }
        }
        // The recorded interpreter must still be the very same canonical binary.
        let interpreter = Path::new(&python.path);
        let canonical = interpreter
            .canonicalize()
            .with_context(|| format!("interpreter missing: {}", python.path))?;
        ensure!(
            canonical == interpreter && canonical.is_file(),
            "interpreter path now resolves elsewhere"
        );
        ensure!(
            hash_file(interpreter, MAX_INTERPRETER)? == python.sha256,
            "interpreter was replaced since installation"
        );
        Ok(Verified {
            id: id.to_string(),
            tree,
            manifest,
            python: python.clone(),
        })
    }

    /// The selected component, verified now. No fallback to anything else.
    pub fn current(&self) -> Result<Verified, Unavailable> {
        let fail = |reason, action: &str, detail: String| Unavailable {
            reason,
            action: action.to_string(),
            detail,
        };
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return Err(fail(
                "unsupported_platform",
                "use native Ubuntu 24.04 x86_64",
                "the installed front door supports native Linux x86_64 only".into(),
            ));
        }
        if self.interrupted() {
            return Err(fail(
                "front_door_component_interrupted",
                "run `agentfw pilot-component recover`, then `agentfw pilot-component verify`",
                "an interrupted component install was detected".into(),
            ));
        }
        let pointer = match self.read_pointer(&self.current_path()) {
            Ok(Some(pointer)) => pointer,
            Ok(None) => {
                return Err(fail(
                    "front_door_component_not_installed",
                    INSTALL_ACTION,
                    format!("no component is selected under {}", self.root.display()),
                ))
            }
            Err(error) => {
                return Err(fail(
                    "front_door_component_invalid",
                    INSTALL_ACTION,
                    format!("{error:#}"),
                ))
            }
        };
        self.verify_component(&pointer.component, &pointer.python)
            .map_err(|error| {
                let detail = format!("{error:#}");
                if detail.contains("interpreter") {
                    fail(
                        "front_door_interpreter_changed",
                        "install the component again with `agentfw pilot-component install FILE --sha256 ARCHIVE_SHA256 --python /ABSOLUTE/python3`",
                        detail,
                    )
                } else {
                    fail(
                        "front_door_component_changed",
                        "run `agentfw pilot-component rollback`, or install the reviewed component again",
                        detail,
                    )
                }
            })
    }

    pub fn preview(&self, archive: &[u8], expected: &str, python: &Path) -> anyhow::Result<Value> {
        ensure!(
            sha(archive) == expected,
            "archive SHA-256 does not match --sha256"
        );
        let package = parse(archive)?;
        let record = probe_python(python)?;
        Ok(
            json!({"action":"preview","writes":false,"component":package.id(),
            "source":package.manifest.source,"files":package.manifest.files.len(),
            "python":record,"target":self.components().join(package.id())}),
        )
    }

    /// Install or update: stage, verify, then select atomically. A failed
    /// install leaves the previous selection and component unchanged.
    pub fn install(&self, archive: &[u8], expected: &str, python: &Path) -> anyhow::Result<Value> {
        ensure!(
            cfg!(all(target_os = "linux", target_arch = "x86_64")),
            "the installed front door supports native Linux x86_64 only"
        );
        ensure!(
            sha(archive) == expected,
            "archive SHA-256 does not match --sha256"
        );
        let package = parse(archive)?;
        let record = probe_python(python)?;
        check_ancestors(&self.root)?;
        ensure_private_dir(&self.root)?;
        ensure_private_dir(&self.components())?;
        self.refuse_interrupted()?;
        let id = package.id();
        let target = self.components().join(&id);
        let previous = self.read_pointer(&self.current_path())?;
        let staging = self
            .root
            .join(format!("staging-{}", crate::token::generate()));
        atomic_write(
            &self.journal_path(),
            &serde_json::to_vec(&json!({"op":"install","component":id,
                "staging":staging.file_name().and_then(|n| n.to_str())}))?,
        )?;
        let published = (|| -> anyhow::Result<()> {
            if std::fs::symlink_metadata(&target).is_err() {
                create_private_dir(&staging)?;
                write_private(&staging.join(MANIFEST), &package.manifest_bytes, 0o400)?;
                let tree = staging.join(TREE);
                create_private_dir(&tree)?;
                for dir in implied_dirs(&package.manifest) {
                    create_private_dir(&tree.join(dir))?;
                }
                for (entry, bytes) in package.manifest.files.iter().zip(&package.contents) {
                    write_private(&tree.join(&entry.path), bytes, entry.mode_bits())?;
                }
                sync_dir(&staging);
                std::fs::rename(&staging, &target)?;
                sync_dir(&self.components());
            }
            // New or already present, it must verify before it can be selected.
            self.verify_component(&id, &record)?;
            if let Some(old) = previous.as_ref().filter(|p| p.component != id) {
                atomic_write(&self.previous_path(), &serde_json::to_vec(old)?)?;
            }
            atomic_write(
                &self.current_path(),
                &serde_json::to_vec(&Pointer {
                    component: id.clone(),
                    python: record.clone(),
                    schema: POINTER_SCHEMA.into(),
                })?,
            )?;
            Ok(())
        })();
        match published {
            Ok(()) => {
                std::fs::remove_file(self.journal_path())?;
                sync_dir(&self.root);
                Ok(
                    json!({"action":"install","component":id,"source":package.manifest.source,
                    "files":package.manifest.files.len(),"python":record,
                    "previous":previous.map(|p| p.component)}),
                )
            }
            Err(error) => {
                // Selection changes only in the final atomic rename; clean what was staged.
                if let (Ok(Some((_, root))), Some(name)) = (
                    self.open_root(),
                    staging.file_name().and_then(|n| n.to_str()),
                ) {
                    if matches!(stat_at(&root, name), Ok(Some(_))) {
                        let mut budget = MAX_REMOVE_ENTRIES;
                        let _ = remove_tree_at(&root, name, 0, &mut budget);
                    }
                    let _ = unlink_at(&root, "journal.json", 0);
                }
                Err(error.context("install failed; the previous selection is unchanged"))
            }
        }
    }

    /// Component integrity only. Protection is reported by `agentfw pilot status`.
    pub fn verify(&self) -> anyhow::Result<Value> {
        let verified = self.current().map_err(anyhow::Error::new)?;
        Ok(json!({"action":"verify","ok":true,"component":verified.id,
            "source":verified.manifest.source,"files":verified.manifest.files.len(),
            "python":verified.python,
            "note":"component integrity only; it never reports protection"}))
    }

    pub fn inspect(&self) -> anyhow::Result<Value> {
        let current = self.read_pointer(&self.current_path())?;
        let previous = self.read_pointer(&self.previous_path())?;
        let mut installed = Vec::new();
        if self.components().is_dir() {
            for entry in std::fs::read_dir(self.components())? {
                installed.push(entry?.file_name().to_string_lossy().into_owned());
            }
        }
        installed.sort();
        Ok(
            json!({"action":"inspect","root":self.root,"current":current,"previous":previous,
            "installed":installed,"interrupted_install":self.interrupted()}),
        )
    }

    pub fn rollback(&self) -> anyhow::Result<Value> {
        self.refuse_interrupted()?;
        let previous = self
            .read_pointer(&self.previous_path())?
            .context("there is no previous component to roll back to")?;
        let current = self.read_pointer(&self.current_path())?;
        // The target must verify before the pointer moves.
        self.verify_component(&previous.component, &previous.python)?;
        if let Some(current) = &current {
            atomic_write(&self.previous_path(), &serde_json::to_vec(current)?)?;
        }
        atomic_write(&self.current_path(), &serde_json::to_vec(&previous)?)?;
        Ok(json!({"action":"rollback","component":previous.component,
            "previous":current.map(|c| c.component)}))
    }

    /// Clear leftovers of an interrupted install. The selection never changes here.
    pub fn recover(&self) -> anyhow::Result<Value> {
        let mut removed = Vec::new();
        let mut had_journal = false;
        if let Some((_, root)) = self.open_root()? {
            let mut names = Vec::new();
            for entry in std::fs::read_dir(format!("/proc/self/fd/{}", root.as_raw_fd()))? {
                names.push(entry?.file_name().to_string_lossy().into_owned());
            }
            names.sort();
            for name in names {
                if !name.starts_with("staging-") {
                    continue;
                }
                // A linked staging entry is never followed; only owned directories go.
                if stat_at(&root, &name)?.is_some_and(|st| is_dir(&st)) {
                    let mut budget = MAX_REMOVE_ENTRIES;
                    remove_tree_at(&root, &name, 0, &mut budget)?;
                    removed.push(name);
                }
            }
            if stat_at(&root, "journal.json")?.is_some() {
                unlink_at(&root, "journal.json", 0)?;
                had_journal = true;
            }
        }
        let selected = self
            .read_pointer(&self.current_path())?
            .map(|p| p.component);
        Ok(
            json!({"action":"recover","removed_staging":removed,"cleared_journal":had_journal,
            "selected":selected}),
        )
    }

    /// Remove one non-selected component, or everything this module owns with
    /// `all`. Prepared pilot selections, host settings and projects live
    /// elsewhere and are never touched. Every parent is resolved from `/`
    /// through no-follow descriptors, `pilot-front-door` and `components`
    /// must be private directories of the current user, and deletion only
    /// descends through those descriptors, so a redirected parent is refused
    /// before anything is removed.
    pub fn remove(&self, component: Option<&str>, all: bool) -> anyhow::Result<Value> {
        ensure!(
            component.is_some() != all,
            "give exactly one of --component <id> or --all"
        );
        let (home, root) = self.open_root()?.context("nothing is installed")?;
        let mut budget = MAX_REMOVE_ENTRIES;
        if all {
            drop(root);
            remove_tree_at(&home, DIR_NAME, 0, &mut budget)?;
            return Ok(json!({"action":"remove","all":true,"root":self.root}));
        }
        let id = component.expect("checked");
        ensure!(is_hex(id, 64), "invalid component id");
        let selected = self.read_pointer(&self.current_path())?;
        ensure!(
            selected.as_ref().map(|p| p.component.as_str()) != Some(id),
            "that component is selected; roll back first or use --all"
        );
        ensure!(
            stat_at(&root, "components")?.is_some_and(|st| is_dir(&st)),
            "the components directory is linked or missing; refusing to delete through it"
        );
        let components = open_dir_at(&root, "components")?;
        require_private_fd(&components, "the components directory")?;
        let entry = stat_at(&components, id)?.context("component is not installed")?;
        ensure!(is_dir(&entry), "component entry is not a directory");
        remove_tree_at(&components, id, 0, &mut budget)?;
        if let Some(previous) = self.read_pointer(&self.previous_path())? {
            if previous.component == id {
                unlink_at(&root, "previous.json", 0)?;
            }
        }
        Ok(json!({"action":"remove","component":id}))
    }
}

/// Default component home: `AGENTFW_HOME` is not consulted; the installed
/// Agent profile `~/.agentfw` unless `--home` names another private directory.
pub fn default_home() -> anyhow::Result<PathBuf> {
    crate::config::Config::home_path()
}

/// `agentfw pilot ...`: verify the selected component and replace this process
/// with the accepted helper under the recorded interpreter. Exit status and
/// signal disposition are the helper's own.
pub fn exec_pilot(home: &Path, args: &[std::ffi::OsString]) -> i32 {
    use std::os::unix::process::CommandExt;

    let command = args
        .first()
        .and_then(|a| a.to_str())
        .filter(|a| {
            matches!(
                *a,
                "preview"
                    | "preflight"
                    | "prepare"
                    | "run"
                    | "status"
                    | "maintenance"
                    | "provider"
                    | "configuration"
                    | "project"
                    | "policy-activation"
                    | "budget-preset"
                    | "worktree-selection"
                    | "filesystem-roots"
                    | "snapshot"
                    | "demo"
                    | "roadmap-support"
                    | "help"
            )
        })
        .unwrap_or("help");
    let store = Store::new(home);
    let verified = match store.current() {
        Ok(verified) => verified,
        Err(unavailable) => {
            println!(
                "{}",
                json!({"format":"sw-pilot-front-door/1","command":command,"status":"failed",
                    "executed":false,"reason":unavailable.reason,
                    "detail":unavailable.detail,"action":unavailable.action})
            );
            eprintln!(
                "agentfw pilot: {}. {}. Next: {}",
                unavailable.reason, unavailable.detail, unavailable.action
            );
            return 2;
        }
    };
    let error = std::process::Command::new(&verified.python.path)
        .arg("-I")
        .arg("-B")
        .arg(verified.tree.join(ENTRY))
        .arg("--agent-home")
        .arg(home)
        .args(args)
        .exec();
    println!(
        "{}",
        json!({"format":"sw-pilot-front-door/1","command":command,"status":"failed",
            "executed":false,"reason":"front_door_helper_start_failed","detail":error.to_string()})
    );
    eprintln!("agentfw pilot: the verified helper could not be started: {error}");
    2
}

/// Only this fixed entry can be selected by the edit self-test front door.
pub fn exec_private_edit_self_test(home: &Path, args: &[std::ffi::OsString]) -> i32 {
    const ENTRY: &str = "scripts/private_edit_self_test.py";
    let verified = match Store::new(home).current() {
        Ok(verified) => verified,
        Err(_) => {
            return crate::self_test::private_edit::unexecuted(
                "incomplete",
                "installed_component_unavailable",
            );
        }
    };
    if !verified
        .manifest
        .files
        .iter()
        .any(|file| file.path == ENTRY)
    {
        return crate::self_test::private_edit::unexecuted(
            "unsupported",
            "installed_component_has_no_edit_self_test",
        );
    }
    let _error = exec_helper(&verified, ENTRY, args);
    crate::self_test::private_edit::unexecuted("incomplete", "installed_helper_start_failed")
}

fn exec_helper(verified: &Verified, entry: &str, args: &[std::ffi::OsString]) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    std::process::Command::new(&verified.python.path)
        .arg("-I")
        .arg("-B")
        .arg(verified.tree.join(entry))
        .args(args)
        .exec()
}

#[cfg(test)]
mod tests;
