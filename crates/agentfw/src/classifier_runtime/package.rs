// SPDX-License-Identifier: Apache-2.0
//! Owned, verified rule-classifier package (SOU-64).
//!
//! A package is a deterministic ustar archive holding exactly `manifest.json`, the
//! selected classifier source (byte-identical, pinned by SHA-256) and `worker.py`
//! (framing only). Installation never downloads anything: the operator supplies the
//! archive and a local Python interpreter. All operations touch only
//! `<home>/classifier/`; unrelated installations are left alone.
//!
//! Layout under `<home>/classifier/` (Linux profile; private, owner-only):
//! `packages/<id>/{manifest.json,rule_baseline.py,worker.py}` (id = SHA-256 of the
//! manifest bytes), `current.json`, `previous.json`, `journal.json` (only while an
//! install is in flight) and transient `staging-*` directories.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[cfg(windows)]
use super::platform_windows as platform;

pub const PACKAGE_SCHEMA: &str = "sw-classifier-package/1";
pub const CURRENT_SCHEMA: &str = "sw-classifier-current/1";
pub const WORKER_PROTOCOL: &str = "sw-classifier-worker/1";
/// Frozen SOU-14 classifier and SOU-34 revision; never rewritten, separately selectable.
pub const FROZEN_SHA256: &str = "d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd";
/// Reviewed framing code (`rule_baseline/runtime/worker.py`). A rebuilt manifest around any
/// other framing bytes is refused: the manifest's own hashes only prove self-consistency.
pub const WORKER_SHA256: &str = "ecd1d972a034f05676d44d4bf9ce7f74f15ced4605a70d18721db63f118ca38c";
pub const REV2_SHA256: &str = "d0b4fc02720ee5ff38dec73d5992c6bdee9eda8595282e33015e60d07ce33ea5";
const MAX_FILE: usize = 1024 * 1024;
const MAX_ARCHIVE: usize = 4 * 1024 * 1024;
const MAX_INTERPRETER_HASH_BYTES: u64 = 256 * 1024 * 1024;
const MIN_PYTHON: (u32, u32) = (3, 9);
const CLASSIFIER_FILE: &str = "rule_baseline.py";
const WORKER_FILE: &str = "worker.py";
const MANIFEST_FILE: &str = "manifest.json";

pub fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The two selectable classifier revisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    Frozen,
    Rev2,
}

impl Which {
    pub fn parse(name: &str) -> anyhow::Result<Self> {
        match name {
            "frozen" => Ok(Self::Frozen),
            "rev2" => Ok(Self::Rev2),
            _ => bail!("classifier must be `frozen` or `rev2`"),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Frozen => "frozen",
            Self::Rev2 => "rev2",
        }
    }
    pub fn pinned_sha256(self) -> &'static str {
        match self {
            Self::Frozen => FROZEN_SHA256,
            Self::Rev2 => REV2_SHA256,
        }
    }
    fn source_path(self) -> &'static str {
        match self {
            Self::Frozen => "rule_baseline/rule_baseline.py",
            Self::Rev2 => "rule_baseline/rev2/rule_baseline.py",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub sha256: String,
    pub size: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Interpreter {
    pub implementation: String,
    pub min_version: String,
    pub isolated: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub classifier: String,
    pub source_path: String,
    pub worker_protocol: String,
    pub interpreter: Interpreter,
    pub files: BTreeMap<String, FileEntry>,
}

/// A parsed and validated archive. Nothing has been written anywhere yet.
pub struct Package {
    pub manifest_bytes: Vec<u8>,
    pub manifest: Manifest,
    pub which: Which,
    pub classifier: Vec<u8>,
    pub worker: Vec<u8>,
}

impl Package {
    pub fn id(&self) -> String {
        sha(&self.manifest_bytes)
    }
}

// ---------------------------------------------------------------- tar (ustar)

fn octal(value: u64, width: usize) -> Vec<u8> {
    format!("{:0w$o}\0", value, w = width - 1).into_bytes()
}

fn tar_entry(out: &mut Vec<u8>, name: &str, data: &[u8]) {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(&octal(0o644, 8));
    header[108..116].copy_from_slice(&octal(0, 8));
    header[116..124].copy_from_slice(&octal(0, 8));
    header[124..136].copy_from_slice(&octal(data.len() as u64, 12));
    header[136..148].copy_from_slice(&octal(0, 12));
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|b| *b as u32).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    out.resize(out.len() + (512 - data.len() % 512) % 512, 0);
}

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

/// Strict reader: only regular files with the three expected names, in order,
/// ustar headers with valid checksums, exact end-of-archive marker, nothing after.
fn read_archive(bytes: &[u8]) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    ensure!(bytes.len() <= MAX_ARCHIVE, "archive exceeds the size limit");
    let expected = [MANIFEST_FILE, CLASSIFIER_FILE, WORKER_FILE];
    let mut members = BTreeMap::new();
    let mut at = 0usize;
    for name in expected {
        ensure!(at + 512 <= bytes.len(), "archive is truncated");
        let header = &bytes[at..at + 512];
        ensure!(
            &header[257..263] == b"ustar\0" && &header[263..265] == b"00",
            "archive member is not ustar"
        );
        ensure!(
            field_str(&header[0..100])? == name,
            "unexpected or reordered archive member"
        );
        ensure!(
            header[156] == b'0',
            "archive member is not a regular file (links, devices and directories are refused)"
        );
        ensure!(
            header[345..500].iter().all(|b| *b == 0) && header[500..512].iter().all(|b| *b == 0),
            "archive member has a path prefix or extra header data"
        );
        let stored = field_octal(&header[148..156])?;
        let mut copy = header.to_vec();
        copy[148..156].copy_from_slice(b"        ");
        let actual: u64 = copy.iter().map(|b| *b as u64).sum();
        ensure!(stored == actual, "archive header checksum mismatch");
        let size = field_octal(&header[124..136])? as usize;
        ensure!(size <= MAX_FILE, "archive member exceeds the size limit");
        let start = at + 512;
        let end = start + size;
        let padded = start + size.div_ceil(512) * 512;
        ensure!(padded <= bytes.len(), "archive is truncated");
        ensure!(
            bytes[end..padded].iter().all(|b| *b == 0),
            "archive member padding is not zero"
        );
        members.insert(name.to_string(), bytes[start..end].to_vec());
        at = padded;
    }
    ensure!(
        bytes.len() == at + 1024 && bytes[at..].iter().all(|b| *b == 0),
        "archive has unexpected members or trailing data"
    );
    Ok(members)
}

// ------------------------------------------------------------ build / validate

fn read_bounded(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("cannot open {}", path.display()))?
        .take(MAX_FILE as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_FILE,
        "{} exceeds the size limit",
        path.display()
    );
    Ok(bytes)
}

/// Build the deterministic archive from a source checkout (a developer/CI step).
/// The classifier bytes must match the pinned digest exactly: a CRLF checkout or an
/// edited file is refused rather than packaged.
pub fn build(which: Which, source_root: &Path) -> anyhow::Result<Vec<u8>> {
    let classifier = read_bounded(&source_root.join(which.source_path()))?;
    ensure!(
        sha(&classifier) == which.pinned_sha256(),
        "classifier source does not match the pinned SHA-256 (line endings or edits?)"
    );
    let worker = read_bounded(&source_root.join("rule_baseline/runtime/worker.py"))?;
    ensure!(
        sha(&worker) == WORKER_SHA256,
        "worker.py does not match the reviewed framing code (line endings or edits?)"
    );
    Ok(assemble(which, &classifier, &worker))
}

/// Lay out the archive for already-read bytes. No pin is checked here: `parse` is the
/// single acceptance gate, which is why tests can feed it forged framing code.
#[doc(hidden)]
pub fn assemble(which: Which, classifier: &[u8], worker: &[u8]) -> Vec<u8> {
    let manifest = Manifest {
        schema: PACKAGE_SCHEMA.into(),
        classifier: which.name().into(),
        source_path: which.source_path().into(),
        worker_protocol: WORKER_PROTOCOL.into(),
        interpreter: Interpreter {
            implementation: "CPython".into(),
            min_version: format!("{}.{}", MIN_PYTHON.0, MIN_PYTHON.1),
            isolated: true,
        },
        files: BTreeMap::from([
            (
                CLASSIFIER_FILE.to_string(),
                FileEntry {
                    sha256: sha(classifier),
                    size: classifier.len(),
                },
            ),
            (
                WORKER_FILE.to_string(),
                FileEntry {
                    sha256: sha(worker),
                    size: worker.len(),
                },
            ),
        ]),
    };
    // Canonical bytes: serde_json emits struct fields in declaration order and the
    // map in key order, so the same inputs always give the same bytes.
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("manifest serializes");
    let mut out = Vec::new();
    tar_entry(&mut out, MANIFEST_FILE, &manifest_bytes);
    tar_entry(&mut out, CLASSIFIER_FILE, classifier);
    tar_entry(&mut out, WORKER_FILE, worker);
    out.resize(out.len() + 1024, 0);
    out
}

/// Parse and fully validate an archive without writing anything.
pub fn parse(bytes: &[u8]) -> anyhow::Result<Package> {
    let members = read_archive(bytes)?;
    let manifest_bytes = members[MANIFEST_FILE].clone();
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).context("manifest is not valid")?;
    ensure!(
        manifest.schema == PACKAGE_SCHEMA,
        "unsupported package schema"
    );
    ensure!(
        manifest.worker_protocol == WORKER_PROTOCOL,
        "unsupported worker protocol"
    );
    ensure!(
        manifest.interpreter.implementation == "CPython"
            && manifest.interpreter.isolated
            && manifest.interpreter.min_version == format!("{}.{}", MIN_PYTHON.0, MIN_PYTHON.1),
        "unsupported interpreter profile"
    );
    let which = Which::parse(&manifest.classifier)?;
    ensure!(
        manifest.source_path == which.source_path(),
        "manifest source path mismatch"
    );
    ensure!(
        manifest.files.len() == 2
            && manifest.files.contains_key(CLASSIFIER_FILE)
            && manifest.files.contains_key(WORKER_FILE),
        "manifest lists unexpected files"
    );
    for (name, entry) in &manifest.files {
        ensure!(
            matches!(name.as_str(), CLASSIFIER_FILE | WORKER_FILE) && is_digest(&entry.sha256),
            "manifest lists unexpected files"
        );
        let data = &members[name];
        ensure!(
            data.len() == entry.size && sha(data) == entry.sha256,
            "{name} does not match the manifest"
        );
    }
    ensure!(
        manifest.files[WORKER_FILE].sha256 == WORKER_SHA256,
        "worker framing code is not the reviewed worker.py"
    );
    ensure!(
        manifest.files[CLASSIFIER_FILE].sha256 == which.pinned_sha256(),
        "classifier bytes are not the pinned {} revision",
        which.name()
    );
    // The manifest must be the canonical rendering of itself (no hidden data).
    ensure!(
        serde_json::to_vec_pretty(&manifest)? == manifest_bytes,
        "manifest is not canonical"
    );
    Ok(Package {
        manifest_bytes,
        manifest,
        which,
        classifier: members[CLASSIFIER_FILE].clone(),
        worker: members[WORKER_FILE].clone(),
    })
}

pub fn read_archive_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file(),
        "archive must be a regular file (links are refused)"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_ARCHIVE as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_ARCHIVE, "archive exceeds the size limit");
    Ok(bytes)
}

// ------------------------------------------------------------- interpreter

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PythonRecord {
    pub path: String,
    pub sha256: String,
    pub version: String,
}

fn hash_file(path: &Path, limit: u64) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(total <= limit, "interpreter exceeds the hash size limit");
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Probe an explicitly supplied interpreter: absolute path, CPython >= 3.9.
pub fn probe_python(python: &Path) -> anyhow::Result<PythonRecord> {
    ensure!(
        python.is_absolute(),
        "--python must be an absolute path to a local interpreter (no PATH lookup, no downloads)"
    );
    let canonical = python
        .canonicalize()
        .with_context(|| format!("interpreter not found: {}", python.display()))?;
    // The ordinary `C:\...` spelling is recorded and run, not the verbatim `\\?\` one.
    #[cfg(windows)]
    let canonical = platform::plain_path(canonical);
    #[cfg(windows)]
    platform::ensure_plain_file(&canonical)?;
    ensure!(canonical.is_file(), "interpreter is not a file");
    let mut command = std::process::Command::new(&canonical);
    command
        .args([
            "-I",
            "-c",
            "import sys;print(sys.implementation.name, sys.version_info[0], sys.version_info[1], sys.version_info[2])",
        ])
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    let output = command
        .output()
        .context("interpreter could not be started")?;
    ensure!(output.status.success(), "interpreter probe failed");
    let text = String::from_utf8(output.stdout)?;
    let parts: Vec<&str> = text.split_whitespace().collect();
    ensure!(parts.len() == 4, "interpreter probe output is unexpected");
    ensure!(parts[0] == "cpython", "interpreter is not CPython");
    let (major, minor): (u32, u32) = (parts[1].parse()?, parts[2].parse()?);
    ensure!(
        (major, minor) >= MIN_PYTHON,
        "interpreter is older than Python {}.{}",
        MIN_PYTHON.0,
        MIN_PYTHON.1
    );
    Ok(PythonRecord {
        path: canonical
            .to_str()
            .context("interpreter path is not UTF-8")?
            .to_string(),
        sha256: hash_file(&canonical, MAX_INTERPRETER_HASH_BYTES)?,
        version: format!("{major}.{minor}.{}", parts[3]),
    })
}

// ------------------------------------------------------------------- store

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pointer {
    pub schema: String,
    pub package: String,
    pub python: PythonRecord,
}

/// A package whose files, permissions and interpreter were verified just now.
#[derive(Debug, Clone)]
pub struct Verified {
    pub id: String,
    pub dir: PathBuf,
    pub classifier_name: String,
    pub classifier_sha256: String,
    pub worker_sha256: String,
    pub python: PythonRecord,
}

pub struct Store {
    root: PathBuf,
}

#[cfg(unix)]
fn private_ok(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0
}

fn ensure_supported() -> anyhow::Result<()> {
    ensure!(
        cfg!(unix) || cfg!(all(windows, target_arch = "x86_64")),
        "the classifier package supports the Linux/Unix and native Windows x86_64 profiles only"
    );
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8], read_only: bool) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    options.mode(if read_only { 0o400 } else { 0o600 });
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Windows files are created with a protected owner-only DACL instead of mode
/// bits; the read-only attribute adds nothing against the owner and would only
/// make cleanup fail, so `read_only` has no Windows meaning.
#[cfg(windows)]
fn write_private(path: &Path, bytes: &[u8], _read_only: bool) -> anyhow::Result<()> {
    platform::write_private(path, bytes)
}

#[cfg(unix)]
fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", crate::token::generate()));
    write_private(&tmp, bytes, false)?;
    std::fs::rename(&tmp, path)?;
    sync_dir(path.parent().context("path has no parent")?);
    Ok(())
}

#[cfg(windows)]
fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    platform::atomic_write(path, bytes)
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

/// NTFS metadata changes are journaled and every file is flushed before it is
/// published; Windows has no portable directory flush.
#[cfg(windows)]
fn sync_dir(_dir: &Path) {}

#[cfg(unix)]
fn read_private(path: &Path, limit: usize, _replaceable: bool) -> anyhow::Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let metadata =
        std::fs::symlink_metadata(path).with_context(|| format!("missing {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "{} is not a regular file (links and reparse points are refused)",
        path.display()
    );
    ensure!(
        private_ok(&metadata),
        "{} is not private to its owner",
        path.display()
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_NOFOLLOW);
    let mut bytes = Vec::new();
    options
        .open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "{} exceeds the size limit",
        path.display()
    );
    Ok(bytes)
}

/// Pointer and journal files are replaced atomically and may be re-read by a
/// concurrent verifier (`replaceable`); payload files never are.
#[cfg(windows)]
fn read_private(path: &Path, limit: usize, replaceable: bool) -> anyhow::Result<Vec<u8>> {
    platform::read_private(path, limit, replaceable)
}

/// Create the directory if it is absent, then require it to be private to the
/// current user (never adopted or repaired when it already exists).
#[cfg(unix)]
fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let metadata = std::fs::symlink_metadata(dir)?;
    ensure!(
        metadata.file_type().is_dir() && private_ok(&metadata),
        "{} must be a private directory owned by the current user",
        dir.display()
    );
    Ok(())
}

#[cfg(windows)]
fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        platform::create_dir(dir)?;
    }
    platform::verify_dir(dir).with_context(|| {
        format!(
            "{} must be a private directory of the current user",
            dir.display()
        )
    })
}

/// A directory this module created earlier must still be private and unlinked.
#[cfg(unix)]
fn verify_private_dir(dir: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(dir)
        .with_context(|| format!("{} is not installed", dir.display()))?;
    ensure!(
        metadata.file_type().is_dir() && private_ok(&metadata),
        "package directory is not private or is linked"
    );
    Ok(())
}

#[cfg(windows)]
fn verify_private_dir(dir: &Path) -> anyhow::Result<()> {
    platform::verify_dir(dir).context("package directory is not private or is linked")
}

/// No linked or redirected ancestors between the filesystem root and `root`.
#[cfg(unix)]
fn check_ancestors(root: &Path) -> anyhow::Result<()> {
    for part in root.ancestors() {
        if part.as_os_str().is_empty() {
            continue;
        }
        let metadata = std::fs::symlink_metadata(part)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "{} is a link; refusing to use a redirected profile",
            part.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn check_ancestors(root: &Path) -> anyhow::Result<()> {
    platform::check_ancestors(root)
}

/// Cleanup commands delete below the root, so a root that is itself a symbolic link, a
/// junction or any other reparse point is refused: nothing outside the profile is reached.
fn ensure_root_not_linked(root: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("cannot inspect the classifier directory"),
    };
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse = false;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink() && !reparse,
        "the classifier directory is linked or redirected; refusing to delete through it"
    );
    // A plain final directory may still be reached through an ancestor symlink
    // or NTFS junction. Runtime selection rejects that spelling; destructive
    // recovery/removal must enforce the same boundary before touching files.
    check_ancestors(root)?;
    Ok(())
}

/// A new private staging directory (mode 0700 / owner-only DACL).
#[cfg(unix)]
fn create_staging(dir: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
fn create_staging(dir: &Path) -> anyhow::Result<()> {
    platform::create_dir(dir)
}

impl Store {
    pub fn new(home: &Path) -> Self {
        Self {
            root: home.join("classifier"),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn packages(&self) -> PathBuf {
        self.root.join("packages")
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

    fn ensure_private_dirs(&self) -> anyhow::Result<()> {
        ensure_supported()?;
        for dir in [&self.root, &self.packages()] {
            ensure_private_dir(dir)?;
        }
        check_ancestors(&self.root)
    }

    fn read_pointer(&self, path: &Path) -> anyhow::Result<Option<Pointer>> {
        if !path.exists() {
            return Ok(None);
        }
        let pointer: Pointer = serde_json::from_slice(&read_private(path, 16 * 1024, true)?)
            .context("pointer file is not valid")?;
        ensure!(
            pointer.schema == CURRENT_SCHEMA,
            "unsupported pointer schema"
        );
        ensure!(is_digest(&pointer.package), "pointer package id is invalid");
        Ok(Some(pointer))
    }

    /// Verify one package directory and the interpreter recorded for it.
    pub fn verify_package(&self, id: &str, python: &PythonRecord) -> anyhow::Result<Verified> {
        ensure_supported()?;
        ensure!(is_digest(id), "invalid package id");
        let dir = self.packages().join(id);
        verify_private_dir(&dir).with_context(|| format!("package {id} cannot be used"))?;
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            names.push(entry?.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        ensure!(
            names == [MANIFEST_FILE, CLASSIFIER_FILE, WORKER_FILE],
            "package directory has missing or unexpected entries"
        );
        let manifest_bytes = read_private(&dir.join(MANIFEST_FILE), 64 * 1024, false)?;
        ensure!(sha(&manifest_bytes) == id, "manifest was altered");
        let classifier = read_private(&dir.join(CLASSIFIER_FILE), MAX_FILE, false)?;
        let worker = read_private(&dir.join(WORKER_FILE), MAX_FILE, false)?;
        // Re-run the full archive-level validation on the installed bytes.
        let mut archive = Vec::new();
        tar_entry(&mut archive, MANIFEST_FILE, &manifest_bytes);
        tar_entry(&mut archive, CLASSIFIER_FILE, &classifier);
        tar_entry(&mut archive, WORKER_FILE, &worker);
        archive.resize(archive.len() + 1024, 0);
        let package = parse(&archive).context("installed package no longer verifies")?;
        // The recorded interpreter must still be the very same binary.
        let interpreter = Path::new(&python.path);
        let metadata = std::fs::metadata(interpreter)
            .with_context(|| format!("interpreter missing: {}", python.path))?;
        ensure!(metadata.is_file(), "interpreter is not a file");
        ensure!(
            hash_file(interpreter, MAX_INTERPRETER_HASH_BYTES)? == python.sha256,
            "interpreter was replaced since installation (re-run install)"
        );
        Ok(Verified {
            id: id.to_string(),
            dir,
            classifier_name: package.manifest.classifier.clone(),
            classifier_sha256: package.manifest.files[CLASSIFIER_FILE].sha256.clone(),
            worker_sha256: package.manifest.files[WORKER_FILE].sha256.clone(),
            python: python.clone(),
        })
    }

    /// The currently selected package, verified now. No fallback to anything else.
    pub fn current(&self) -> anyhow::Result<Verified> {
        ensure_supported()?;
        // The selection pointer is read through these directories, so a junction or a
        // foreign ACL on any of them must stop runtime selection before the read.
        #[cfg(windows)]
        {
            check_ancestors(&self.root)?;
            verify_private_dir(&self.root)?;
            verify_private_dir(&self.packages())?;
        }
        // Runtime selection and every worker start share the interrupted-install gate.
        ensure!(
            !self.journal_path().exists(),
            "an interrupted install was detected: run `agentfw classifier-package recover`"
        );
        let pointer = self.read_pointer(&self.current_path())?.context(
            "no classifier package is installed: run `agentfw classifier-package install`",
        )?;
        self.verify_package(&pointer.package, &pointer.python)
    }

    /// Identity of the selection pointer without re-hashing the package: the selected
    /// package id and the interpreter record it pins. Used to tell whether an already
    /// verified worker still belongs to the current selection; it never replaces `current`,
    /// which every worker start still uses.
    pub fn selected_identity(&self) -> anyhow::Result<(String, PythonRecord)> {
        ensure_supported()?;
        ensure!(
            !self.journal_path().exists(),
            "an interrupted install was detected: run `agentfw classifier-package recover`"
        );
        let pointer = self.read_pointer(&self.current_path())?.context(
            "no classifier package is installed: run `agentfw classifier-package install`",
        )?;
        Ok((pointer.package, pointer.python))
    }

    pub fn preview(&self, archive: &[u8], python: &Path) -> anyhow::Result<Value> {
        let package = parse(archive)?;
        let record = probe_python(python)?;
        Ok(
            json!({"action":"preview","package":package.id(),"classifier":package.which.name(),
            "classifier_sha256":package.manifest.files[CLASSIFIER_FILE].sha256,
            "worker_sha256":package.manifest.files[WORKER_FILE].sha256,
            "python":record,"target":self.packages().join(package.id()),
            "writes":false}),
        )
    }

    pub fn install(&self, archive: &[u8], python: &Path) -> anyhow::Result<Value> {
        self.ensure_private_dirs()?;
        ensure!(
            !self.journal_path().exists(),
            "an interrupted install was detected: run `agentfw classifier-package recover`"
        );
        let package = parse(archive)?;
        let record = probe_python(python)?;
        let id = package.id();
        let target = self.packages().join(&id);
        let previous = self.read_pointer(&self.current_path())?;
        let staging = self
            .root
            .join(format!("staging-{}", crate::token::generate()));
        atomic_write(
            &self.journal_path(),
            &serde_json::to_vec(&json!({"op":"install","package":id,"staging":
                staging.file_name().and_then(|n| n.to_str())}))?,
        )?;
        let published = (|| -> anyhow::Result<()> {
            if !target.exists() {
                create_staging(&staging)?;
                write_private(&staging.join(MANIFEST_FILE), &package.manifest_bytes, true)?;
                write_private(&staging.join(CLASSIFIER_FILE), &package.classifier, true)?;
                write_private(&staging.join(WORKER_FILE), &package.worker, true)?;
                sync_dir(&staging);
                std::fs::rename(&staging, &target)?;
                sync_dir(&self.packages());
            }
            // Whether new or already present, it must verify before it can be selected.
            self.verify_package(&id, &record)?;
            if let Some(old) = &previous {
                atomic_write(&self.previous_path(), &serde_json::to_vec(old)?)?;
            }
            atomic_write(
                &self.current_path(),
                &serde_json::to_vec(&Pointer {
                    schema: CURRENT_SCHEMA.into(),
                    package: id.clone(),
                    python: record.clone(),
                })?,
            )?;
            Ok(())
        })();
        match published {
            Ok(()) => {
                let _ = std::fs::remove_file(self.journal_path());
                Ok(
                    json!({"action":"install","package":id,"classifier":package.which.name(),
                    "python":record,"previous":previous.map(|p| p.package)}),
                )
            }
            Err(error) => {
                // Selection only changes in the last atomic rename; clean what we staged.
                let _ = std::fs::remove_dir_all(&staging);
                let _ = std::fs::remove_file(self.journal_path());
                Err(error)
            }
        }
    }

    /// Report package health. Fails on an interrupted install or any altered file.
    pub fn verify(&self) -> anyhow::Result<Value> {
        ensure_supported()?;
        ensure!(
            !self.journal_path().exists(),
            "an interrupted install was detected: run `agentfw classifier-package recover`"
        );
        let verified = self.current()?;
        Ok(json!({"action":"verify","ok":true,"package":verified.id,
            "classifier":verified.classifier_name,"classifier_sha256":verified.classifier_sha256,
            "worker_sha256":verified.worker_sha256,"python":verified.python}))
    }

    pub fn inspect(&self) -> anyhow::Result<Value> {
        ensure_supported()?;
        let current = self.read_pointer(&self.current_path())?;
        let previous = self.read_pointer(&self.previous_path())?;
        let mut installed = Vec::new();
        if self.packages().is_dir() {
            for entry in std::fs::read_dir(self.packages())? {
                installed.push(entry?.file_name().to_string_lossy().into_owned());
            }
        }
        installed.sort();
        Ok(
            json!({"action":"inspect","root":self.root,"current":current,"previous":previous,
            "installed":installed,"interrupted_install":self.journal_path().exists()}),
        )
    }

    pub fn rollback(&self) -> anyhow::Result<Value> {
        self.ensure_private_dirs()?;
        let previous = self
            .read_pointer(&self.previous_path())?
            .context("there is no previous package to roll back to")?;
        let current = self.read_pointer(&self.current_path())?;
        // The target must verify before the pointer moves.
        self.verify_package(&previous.package, &previous.python)?;
        if let Some(current) = &current {
            atomic_write(&self.previous_path(), &serde_json::to_vec(current)?)?;
        }
        atomic_write(&self.current_path(), &serde_json::to_vec(&previous)?)?;
        Ok(json!({"action":"rollback","package":previous.package,
            "previous":current.map(|c| c.package)}))
    }

    /// Clear leftovers of an interrupted install. Selection is never changed here.
    pub fn recover(&self) -> anyhow::Result<Value> {
        ensure_supported()?;
        ensure_root_not_linked(&self.root)?;
        let mut removed = Vec::new();
        if self.root.is_dir() {
            for entry in std::fs::read_dir(&self.root)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("staging-") && entry.file_type()?.is_dir() {
                    std::fs::remove_dir_all(entry.path())?;
                    removed.push(name);
                }
            }
        }
        let had_journal = self.journal_path().exists();
        if had_journal {
            std::fs::remove_file(self.journal_path())?;
        }
        Ok(json!({"action":"recover","removed_staging":removed,"cleared_journal":had_journal}))
    }

    /// Remove one non-selected package, or everything this module owns with `all`.
    pub fn remove(&self, package: Option<&str>, all: bool) -> anyhow::Result<Value> {
        ensure_supported()?;
        ensure!(
            package.is_some() != all,
            "give exactly one of --package <id> or --all"
        );
        ensure_root_not_linked(&self.root)?;
        if all {
            ensure!(self.root.is_dir(), "nothing is installed");
            std::fs::remove_dir_all(&self.root)?;
            return Ok(json!({"action":"remove","all":true}));
        }
        let id = package.expect("checked");
        ensure!(is_digest(id), "invalid package id");
        let selected = self.read_pointer(&self.current_path())?;
        ensure!(
            selected.as_ref().map(|p| p.package.as_str()) != Some(id),
            "that package is selected; roll back or use --all"
        );
        let dir = self.packages().join(id);
        let metadata = std::fs::symlink_metadata(&dir).context("package is not installed")?;
        ensure!(
            metadata.file_type().is_dir(),
            "package entry is not a directory"
        );
        std::fs::remove_dir_all(&dir)?;
        if let Some(previous) = self.read_pointer(&self.previous_path())? {
            if previous.package == id {
                std::fs::remove_file(self.previous_path())?;
            }
        }
        Ok(json!({"action":"remove","package":id}))
    }
}
