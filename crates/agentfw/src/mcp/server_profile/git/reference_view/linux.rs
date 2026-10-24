// SPDX-License-Identifier: Apache-2.0
//! Immutable namespace data plus sticky source withdrawal. Inotify is a
//! revocation witness, not an authority or a permission cache. Each call still
//! traverses the enforcing native admission and result-inspection paths.

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

use super::{
    decode_object, oid, packed_references, Object, MAX_OBJECT_BYTES, MAX_REFS, MAX_TAG_DEPTH,
};

const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_OBJECTS: usize = 128;
const MAX_WATCHES: usize = 256;
const MAX_DIRECTORIES: usize = 128;
const ROOT: &str = "/workspace/.git";

#[derive(Debug)]
struct Withdrawal {
    file: File,
    broken: bool,
    watches: BTreeSet<i32>,
}

impl Withdrawal {
    fn new() -> anyhow::Result<Self> {
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        ensure!(fd >= 0, "Git local-reference observer unavailable");
        Ok(Self {
            file: unsafe { File::from_raw_fd(fd) },
            broken: false,
            watches: BTreeSet::new(),
        })
    }

    fn watch(&mut self, directory: &File) -> anyhow::Result<()> {
        ensure!(
            self.watches.len() < MAX_WATCHES,
            "Git local-reference watch limit"
        );
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
        ensure!(id >= 0, "Git local-reference watch unavailable");
        self.watches.insert(id);
        Ok(())
    }

    fn valid(&mut self) -> bool {
        if self.broken {
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
                Some(libc::EAGAIN) => return true,
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
    refs: BTreeMap<String, bool>,
    directories: BTreeSet<PathBuf>,
    images: Vec<(PathBuf, File)>,
    objects: File,
}

fn owned(metadata: &std::fs::Metadata) -> anyhow::Result<()> {
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0,
        "Git local-reference metadata must remain owned and not shared writable"
    );
    Ok(())
}

fn child(parent: &File, name: &str, directory: bool) -> anyhow::Result<File> {
    ensure!(
        !name.is_empty() && !name.contains('/') && name != "." && name != "..",
        "Git local-reference component invalid"
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
        "Git local-reference metadata type unsupported"
    );
    Ok(file)
}

fn entries(directory: &File) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        ensure!(
            names.len() < 1024,
            "Git local-reference directory entry limit"
        );
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
        "hard-linked Git local-reference metadata unsupported"
    );
    ensure!(
        before.len() <= limit as u64,
        "Git local-reference file exceeds limit"
    );
    let mut bytes = Vec::new();
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit && stamp(&before) == stamp(&file.metadata()?),
        "Git local-reference file changed during capture"
    );
    Ok(bytes)
}

fn optional(parent: &File, name: &str, limit: usize) -> anyhow::Result<Option<Vec<u8>>> {
    match child(parent, name, false) {
        Ok(file) => Ok(Some(read_file(file, limit)?)),
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
    let name = c"git-local-reference-image";
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    ensure!(fd >= 0, "Git local-reference image unavailable");
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    ensure!(
        unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } == 0,
        "Git local-reference image sealing failed"
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
}

impl Capture {
    fn image(&mut self, path: impl Into<PathBuf>, bytes: &[u8]) -> anyhow::Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .context("Git reference image overflow")?;
        ensure!(
            self.bytes <= MAX_IMAGE_BYTES,
            "Git local-reference image exceeds limit"
        );
        self.images.push((path.into(), sealed(bytes)?));
        Ok(())
    }

    fn directory(&mut self, path: impl Into<PathBuf>) -> anyhow::Result<()> {
        self.directories.insert(path.into());
        ensure!(
            self.directories.len() <= MAX_DIRECTORIES,
            "Git local-reference directory limit"
        );
        Ok(())
    }

    fn loose_refs(&mut self, directory: File, prefix: &str, depth: usize) -> anyhow::Result<()> {
        ensure!(depth <= 10, "Git local-reference depth limit");
        self.source.watch(&directory)?;
        self.directory(Path::new(ROOT).join(prefix))?;
        for name in entries(&directory)? {
            let relative = format!("{prefix}/{name}");
            if let Ok(nested) = child(&directory, &name, true) {
                self.loose_refs(nested, &relative, depth + 1)?;
                continue;
            }
            ensure!(
                super::super::is_local_reference(&relative),
                "Git local-reference namespace unsupported"
            );
            let bytes = read_file(child(&directory, &name, false)?, 256)?;
            let target = std::str::from_utf8(&bytes)
                .ok()
                .and_then(|s| oid(s.strip_suffix('\n').unwrap_or(s)).ok());
            self.refs.insert(relative.clone(), target);
            ensure!(
                self.refs.len() <= MAX_REFS,
                "Git local-reference count exceeds limit"
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
            "Git local-reference object count limit"
        );
        let prefix = child(&self.objects, &id[..2], true)?;
        self.source.watch(&prefix)?;
        let bytes = read_file(child(&prefix, &id[2..], false)?, MAX_OBJECT_BYTES)?;
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

    fn target(&mut self, id: &str, tag: bool) -> anyhow::Result<bool> {
        let mut id = id.to_owned();
        let mut expected_tag = None;
        let mut seen = BTreeSet::new();
        for depth in 0..=MAX_TAG_DEPTH {
            ensure!(seen.insert(id.clone()), "Git local-reference tag cycle");
            match self.object(&id)? {
                Object::Commit => return Ok(expected_tag != Some(true)),
                Object::Tag {
                    target,
                    target_is_tag,
                } if tag && depth < MAX_TAG_DEPTH && expected_tag != Some(false) => {
                    id = target;
                    expected_tag = Some(target_is_tag);
                }
                _ => return Ok(false),
            }
        }
        Ok(false)
    }
}

impl View {
    pub(crate) fn capture(workspace: &File) -> anyhow::Result<Arc<Self>> {
        owned(&workspace.metadata()?)?;
        let git = child(workspace, ".git", true)?;
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        ensure!(
            unsafe { libc::fstatfs(git.as_raw_fd(), filesystem.as_mut_ptr()) } == 0,
            "Git local-reference filesystem observation failed"
        );
        ensure!(
            matches!(
                unsafe { filesystem.assume_init() }.f_type as u64,
                0xef53 | 0x5846_5342 | 0x9123_683e | 0x0102_1994
            ),
            "Git local-reference filesystem unsupported"
        );
        let mut source = Withdrawal::new()?;
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
        };
        capture.directory(format!("{ROOT}/objects"))?;
        capture.directory(format!("{ROOT}/info"))?;
        let config = read_file(child(&git, "config", false)?, 8192)?;
        super::super::validate_configuration(&config)?;
        capture.image(format!("{ROOT}/config"), &config)?;
        let head = read_file(child(&git, "HEAD", false)?, 256)?;
        capture.image(format!("{ROOT}/HEAD"), &head)?;
        if let Some(index) = optional(&git, "index", 8 * 1024 * 1024)? {
            capture.image(format!("{ROOT}/index"), &index)?;
        }
        if let Some(packed) = optional(&git, "packed-refs", 65_536)? {
            capture.refs = packed_references(&packed)?
                .into_iter()
                .map(|(name, id)| (name, Some(id)))
                .collect();
            capture.image(format!("{ROOT}/packed-refs"), &packed)?;
        }
        let refs = child(&git, "refs", true)?;
        ensure!(
            entries(&refs)?
                .iter()
                .all(|name| matches!(name.as_str(), "heads" | "tags")),
            "Git reference namespace unsupported"
        );
        capture.loose_refs(refs, "refs", 0)?;
        if let Some(info) = optional_directory(&git, "info")? {
            capture.source.watch(&info)?;
            ensure!(
                entries(&info)?.iter().all(|name| name == "exclude"),
                "Git repository info machinery unsupported"
            );
            if let Some(exclude) = optional(&info, "exclude", 65_536)? {
                capture.image(format!("{ROOT}/info/exclude"), &exclude)?;
            }
        }
        let mut supported = BTreeMap::new();
        for (name, id) in capture.refs.clone() {
            let valid = id.is_some_and(|id| {
                capture
                    .target(&id, name.starts_with("refs/tags/"))
                    .unwrap_or(false)
            });
            supported.insert(name, valid);
        }
        let head_text = std::str::from_utf8(&head)?;
        let head_text = head_text.strip_suffix('\n').unwrap_or(head_text);
        if let Some(reference) = head_text.strip_prefix("ref: ") {
            ensure!(
                reference.starts_with("refs/heads/") && supported.get(reference) == Some(&true),
                "Git local-reference HEAD target unsupported"
            );
        } else {
            ensure!(
                capture.target(&oid(head_text)?, false)?,
                "Git detached HEAD target unsupported"
            );
        }
        ensure!(
            capture.source.valid(),
            "Git local-reference source changed during capture"
        );
        Ok(Arc::new(Self {
            source: Mutex::new(capture.source),
            refs: supported,
            directories: capture.directories,
            images: capture.images,
            objects: capture.objects,
        }))
    }

    pub(crate) fn validate_call(&self, tool: &str, args: &Value) -> anyhow::Result<()> {
        ensure!(
            self.source.lock().is_ok_and(|mut source| source.valid()),
            "Git local-reference source changed; a new protected session is required"
        );
        let key = match tool {
            "git_show" => Some("revision"),
            "git_diff" => Some("target"),
            _ => None,
        };
        if let Some(reference) = key.and_then(|key| args[key].as_str()) {
            if super::super::is_local_reference(reference) {
                ensure!(
                    self.refs.get(reference) == Some(&true),
                    "Git local-reference target unavailable or unsupported"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn mount(&self, command: &mut Command, pins: &mut Vec<File>) -> anyhow::Result<()> {
        ensure!(
            self.source.lock().is_ok_and(|mut source| source.valid()),
            "Git local-reference source changed during startup"
        );
        command.args(["--size", "16777216", "--tmpfs", ROOT]);
        for path in &self.directories {
            command.arg("--dir").arg(path);
        }
        let objects = self.objects.try_clone()?;
        command
            .arg("--ro-bind-fd")
            .arg(objects.as_raw_fd().to_string())
            .arg(format!("{ROOT}/objects"));
        pins.push(objects);
        // No newly created alternates file can become visible in this session.
        command.args([
            "--size",
            "4096",
            "--tmpfs",
            &format!("{ROOT}/objects/info"),
            "--remount-ro",
            &format!("{ROOT}/objects/info"),
        ]);
        for (path, image) in &self.images {
            let image = image.try_clone()?;
            command
                .arg("--ro-bind-fd")
                .arg(image.as_raw_fd().to_string())
                .arg(path);
            pins.push(image);
        }
        command.args(["--remount-ro", ROOT]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, String) {
        let root = tempfile::tempdir().unwrap();
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
        (root, id)
    }

    #[test]
    fn reference_image_is_sealed_and_source_withdrawal_is_sticky() {
        let (root, id) = fixture();
        let view = View::capture(&File::open(root.path()).unwrap()).unwrap();
        let args = serde_json::json!({"repo_path":"/workspace","revision":"refs/heads/main"});
        view.validate_call("git_show", &args).unwrap();
        assert!(view
            .validate_call(
                "git_show",
                &serde_json::json!({"revision":"refs/heads/missing"})
            )
            .is_err());
        view.validate_call("git_show", &serde_json::json!({"revision":"HEAD"}))
            .unwrap();
        let image = &view
            .images
            .iter()
            .find(|(path, _)| path == Path::new("/workspace/.git/refs/heads/main"))
            .unwrap()
            .1;
        let seals = unsafe { libc::fcntl(image.as_raw_fd(), libc::F_GET_SEALS) };
        assert_eq!(seals & libc::F_SEAL_WRITE, libc::F_SEAL_WRITE);
        let path = root.path().join(".git/refs/heads/main");
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
            .validate_call(
                "git_show",
                &serde_json::json!({"revision":"refs/heads/main"})
            )
            .is_err());
    }

    #[test]
    fn template_free_repository_does_not_require_an_info_directory() {
        let (root, _) = fixture();
        std::fs::remove_dir(root.path().join(".git/info")).unwrap();
        let view = View::capture(&File::open(root.path()).unwrap()).unwrap();
        view.validate_call(
            "git_show",
            &serde_json::json!({"revision":"refs/heads/main"}),
        )
        .unwrap();
    }
}
