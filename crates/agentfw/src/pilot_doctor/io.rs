// SPDX-License-Identifier: Apache-2.0
//! Descriptor-only asset inspection. Package links are hashed as link text,
//! never followed; all selected input paths themselves must be link-free.
//! Only the installed system-library list permits bounded root-owned loader
//! aliases, resolved without following a pathname through the kernel.
use anyhow::Result;
#[cfg(unix)]
use anyhow::{ensure, Context};
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::{
    collections::BTreeMap,
    io::Read,
    time::{Duration, Instant},
};
use std::{fs::File, path::Path};

pub(super) struct Budget {
    #[cfg(unix)]
    start: Instant,
    #[cfg(unix)]
    bytes: u64,
    #[cfg(unix)]
    entries: usize,
}
impl Budget {
    pub fn new() -> Self {
        Self {
            #[cfg(unix)]
            start: Instant::now(),
            #[cfg(unix)]
            bytes: 0,
            #[cfg(unix)]
            entries: 0,
        }
    }
    #[cfg(unix)]
    fn tick(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes as u64)
            .context("asset budget")?;
        ensure!(
            self.bytes <= 1536 * 1024 * 1024 && self.start.elapsed() <= Duration::from_secs(30),
            "asset budget"
        );
        Ok(())
    }
}

#[cfg(unix)]
fn stable(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
        && a.uid() == b.uid()
        && a.mode() == b.mode()
        && a.nlink() == b.nlink()
}
#[cfg(unix)]
fn hash_file(mut file: File, budget: &mut Budget) -> Result<String> {
    let before = file.metadata()?;
    let mut hash = Sha256::new();
    let mut buf = [0; 16384];
    let mut count = 0u64;
    loop {
        budget.tick(0)?;
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        budget.tick(n)?;
        count += n as u64;
        ensure!(count <= before.len(), "asset changed");
        hash.update(&buf[..n]);
    }
    ensure!(
        count == before.len() && stable(&before, &file.metadata()?),
        "asset changed"
    );
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(unix)]
pub(super) fn asset(path: &Path, budget: &mut Budget) -> Result<String> {
    hash_file(
        crate::doctor::open_bounded(path, 512 * 1024 * 1024, false)?,
        budget,
    )
}
#[cfg(not(unix))]
pub(super) fn asset(_: &Path, _: &mut Budget) -> Result<String> {
    anyhow::bail!("unsupported")
}

/// The accepted installers retain loader paths such as `/lib64/ld-linux-*`,
/// including the distribution's root-owned `/lib -> usr/lib` aliases. This
/// exception is exclusively for their system-library list: selected profiles,
/// runtimes, private inputs and package trees keep their no-follow rules.
#[cfg(target_os = "linux")]
pub(super) fn system_library(path: &Path, budget: &mut Budget) -> Result<String> {
    system_library_from(File::open("/")?, path, budget, 0)
}
#[cfg(not(target_os = "linux"))]
pub(super) fn system_library(_: &Path, _: &mut Budget) -> Result<String> {
    anyhow::bail!("system library inspection requires Linux")
}

#[cfg(target_os = "linux")]
fn system_library_from(root: File, path: &Path, budget: &mut Budget, owner: u32) -> Result<String> {
    use std::{
        collections::VecDeque,
        ffi::{CString, OsString},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::Component,
    };

    fn selected(parts: &[OsString]) -> bool {
        matches!(
            parts.first().and_then(|s| s.to_str()),
            Some("lib" | "lib64")
        ) && parts.len() >= 2
            || parts.first().is_some_and(|s| s == "usr")
                && matches!(parts.get(1).and_then(|s| s.to_str()), Some("lib" | "lib64"))
                && parts.len() >= 3
    }
    fn parts(path: &Path, base: &[OsString]) -> Result<Vec<OsString>> {
        ensure!(
            path.as_os_str().as_bytes().len() <= 4096,
            "system library path limit"
        );
        let mut result = if path.is_absolute() {
            vec![]
        } else {
            base.to_vec()
        };
        let mut unresolved_normal = false;
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => (),
                Component::Normal(name) => {
                    ensure!(
                        !name.as_bytes().iter().any(|b| b.is_ascii_control()),
                        "system library path"
                    );
                    result.push(name.to_owned());
                    unresolved_normal = true;
                }
                Component::ParentDir => {
                    // Leading parents refer to the already resolved parent.
                    // Collapsing `unopened/..` would be incorrect if unopened
                    // were itself a link. Refuse that unusual alias instead.
                    ensure!(!unresolved_normal, "ambiguous system library link");
                    ensure!(result.pop().is_some(), "system library path escape");
                }
                _ => anyhow::bail!("system library path"),
            }
        }
        ensure!(result.len() <= 128, "system library component limit");
        Ok(result)
    }
    fn safe_directory(file: &File, owner: u32) -> Result<()> {
        let meta = file.metadata()?;
        ensure!(
            meta.is_dir() && meta.uid() == owner && meta.mode() & 0o022 == 0,
            "unsafe system library ancestry"
        );
        Ok(())
    }

    ensure!(path.is_absolute(), "absolute system library required");
    // The explicitly selected input is normalized. Relative link targets may
    // contain `..`, but are normalized in memory and must remain in a system
    // library namespace before any of their components are opened.
    ensure!(
        path.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "system library input alias"
    );
    let initial = parts(path, &[])?;
    ensure!(selected(&initial), "system library namespace");
    safe_directory(&root, owner)?;
    let mut directory = root.try_clone()?;
    let mut resolved = Vec::new();
    let mut pending: VecDeque<_> = initial.into();
    let mut links = 0usize;
    let mut steps = 0usize;
    while let Some(name) = pending.pop_front() {
        budget.tick(0)?;
        steps += 1;
        ensure!(steps <= 1024, "system library resolution limit");
        let name_c = CString::new(name.as_bytes())?;
        // O_PATH pins the inode even when it is a symbolic link. In particular,
        // readlinkat(fd, "") below reads this exact link, not a replaced name.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        ensure!(fd >= 0, "system library component unavailable");
        let pinned = unsafe { File::from_raw_fd(fd) };
        let meta = pinned.metadata()?;
        ensure!(meta.uid() == owner, "unsafe system library owner");
        if meta.file_type().is_symlink() {
            links += 1;
            ensure!(links <= 40, "system library link limit");
            let mut target = [0u8; 4097];
            let size = unsafe {
                libc::readlinkat(
                    pinned.as_raw_fd(),
                    c"".as_ptr(),
                    target.as_mut_ptr().cast(),
                    target.len(),
                )
            };
            ensure!(size > 0 && size < 4097, "system library link limit");
            let mut replacement = parts(
                Path::new(std::ffi::OsStr::from_bytes(&target[..size as usize])),
                &resolved,
            )?;
            replacement.extend(pending);
            ensure!(
                replacement.len() <= 128
                    && replacement
                        .iter()
                        .map(|s| s.as_bytes().len() + 1)
                        .sum::<usize>()
                        <= 4096
                    && selected(&replacement),
                "system library link escapes namespace"
            );
            pending = replacement.into();
            resolved.clear();
            directory = root.try_clone()?;
            continue;
        }
        ensure!(
            meta.mode() & 0o022 == 0,
            "writable system library component"
        );
        if !pending.is_empty() {
            safe_directory(&pinned, owner)?;
            resolved.push(name);
            directory = pinned;
            continue;
        }
        ensure!(
            meta.is_file() && meta.nlink() == 1 && meta.len() <= 512 * 1024 * 1024,
            "system library file type/limit"
        );
        // O_PATH cannot supply bytes. Open relative to its already pinned
        // safe parent, refuse a newly substituted link and compare identity
        // before passing the final readable descriptor to the bounded hasher.
        let read_fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        ensure!(read_fd >= 0, "system library read unavailable");
        let readable = unsafe { File::from_raw_fd(read_fd) };
        ensure!(
            stable(&meta, &readable.metadata()?),
            "system library changed"
        );
        return hash_file(readable, budget);
    }
    anyhow::bail!("system library path incomplete")
}

#[cfg(unix)]
pub(super) fn directory(path: &Path) -> Result<File> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::Component,
    };
    ensure!(path.is_absolute(), "absolute directory required");
    let mut dir = File::open("/")?;
    for part in path.components() {
        match part {
            Component::RootDir => (),
            Component::Normal(name) => {
                let c = CString::new(name.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        c.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                ensure!(fd >= 0, "unsafe directory");
                dir = unsafe { File::from_raw_fd(fd) };
            }
            _ => anyhow::bail!("path alias"),
        }
    }
    let m = dir.metadata()?;
    ensure!(
        (m.uid() == unsafe { libc::geteuid() } || m.uid() == 0) && m.mode() & 0o022 == 0,
        "unsafe directory owner"
    );
    Ok(dir)
}
#[cfg(not(unix))]
pub(super) fn directory(_: &Path) -> Result<File> {
    anyhow::bail!("unsupported")
}

#[cfg(unix)]
pub(super) fn tree(path: &Path, budget: &mut Budget) -> Result<String> {
    use std::{
        ffi::{CStr, CString},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        },
    };
    struct Listing(*mut libc::DIR);
    impl Drop for Listing {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    fn walk(
        dir: File,
        prefix: &str,
        depth: usize,
        entries: &mut BTreeMap<String, Vec<u8>>,
        budget: &mut Budget,
    ) -> Result<()> {
        ensure!(depth <= 32, "tree depth");
        budget.tick(0)?;
        let before = dir.metadata()?;
        ensure!(
            (before.uid() == unsafe { libc::geteuid() } || before.uid() == 0)
                && before.mode() & 0o022 == 0,
            "unsafe tree directory"
        );
        let copy = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        ensure!(copy >= 0, "directory copy");
        let list = unsafe { libc::fdopendir(copy) };
        if list.is_null() {
            unsafe {
                libc::close(copy);
            }
            anyhow::bail!("directory listing");
        }
        let list = Listing(list);
        loop {
            budget.tick(0)?;
            let entry = unsafe { libc::readdir(list.0) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_str()?;
            if name == "." || name == ".." {
                continue;
            }
            budget.entries += 1;
            ensure!(
                budget.entries <= 65536 && !name.chars().any(char::is_control),
                "tree entry limit"
            );
            let relative = format!("{prefix}{name}");
            ensure!(relative.len() <= 4096, "tree path limit");
            let c = CString::new(name)?;
            let mut meta: libc::stat = unsafe { std::mem::zeroed() };
            ensure!(
                unsafe {
                    libc::fstatat(
                        dir.as_raw_fd(),
                        c.as_ptr(),
                        &mut meta,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } == 0,
                "tree metadata"
            );
            let record = match meta.st_mode & libc::S_IFMT {
                libc::S_IFLNK => {
                    // Match the accepted typed tree representation without opening
                    // the target. A link can never redirect a diagnostic file read.
                    let mut buf = [0u8; 4097];
                    let size = unsafe {
                        libc::readlinkat(
                            dir.as_raw_fd(),
                            c.as_ptr(),
                            buf.as_mut_ptr().cast(),
                            buf.len(),
                        )
                    };
                    ensure!(size > 0 && size < 4097, "tree link limit");
                    let target = std::str::from_utf8(&buf[..size as usize])?;
                    ensure!(
                        !target.starts_with('/') && !target.chars().any(char::is_control),
                        "tree link"
                    );
                    let mut level = depth;
                    for part in Path::new(target).components() {
                        match part {
                            std::path::Component::Normal(_) => level += 1,
                            std::path::Component::CurDir => (),
                            std::path::Component::ParentDir if level > 0 => level -= 1,
                            _ => anyhow::bail!("tree link escapes"),
                        }
                    }
                    format!("L\0{relative}\0{target}\n").into_bytes()
                }
                libc::S_IFDIR | libc::S_IFREG => {
                    let flags = libc::O_RDONLY
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK
                        | libc::O_CLOEXEC
                        | if meta.st_mode & libc::S_IFMT == libc::S_IFDIR {
                            libc::O_DIRECTORY
                        } else {
                            0
                        };
                    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
                    ensure!(fd >= 0, "tree open");
                    let file = unsafe { File::from_raw_fd(fd) };
                    let current = file.metadata()?;
                    ensure!(
                        current.dev() as u128 == meta.st_dev as u128
                            && current.ino() == meta.st_ino
                            && (current.uid() == unsafe { libc::geteuid() } || current.uid() == 0)
                            && current.mode() & 0o022 == 0,
                        "tree changed or unsafe"
                    );
                    if current.is_dir() {
                        walk(file, &format!("{relative}/"), depth + 1, entries, budget)?;
                        format!("D\0{relative}\n").into_bytes()
                    } else {
                        ensure!(
                            current.is_file()
                                && current.nlink() == 1
                                && current.len() <= 512 * 1024 * 1024,
                            "tree file type/limit"
                        );
                        format!("F\0{relative}\0{}\n", hash_file(file, budget)?).into_bytes()
                    }
                }
                _ => anyhow::bail!("tree file type"),
            };
            ensure!(
                entries.insert(relative, record).is_none(),
                "duplicate entry"
            );
        }
        ensure!(stable(&before, &dir.metadata()?), "tree changed");
        Ok(())
    }
    let mut entries = BTreeMap::new();
    walk(directory(path)?, "", 0, &mut entries, budget)?;
    let mut hash = Sha256::new();
    for record in entries.values() {
        hash.update(record);
    }
    Ok(format!("{:x}", hash.finalize()))
}
#[cfg(not(unix))]
pub(super) fn tree(_: &Path, _: &mut Budget) -> Result<String> {
    anyhow::bail!("unsupported")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn descriptor_tree_matches_accepted_digest_and_refuses_special_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/file"), b"selected bytes").unwrap();
        symlink("sub/file", root.join("alias")).unwrap();
        assert_eq!(
            tree(&root, &mut Budget::new()).unwrap(),
            crate::mcp::server_profile::package_tree_sha256(&root).unwrap()
        );
        assert!(asset(&root.join("alias"), &mut Budget::new()).is_err());
        let linked = root.join("linked-dir");
        symlink(root.join("sub"), &linked).unwrap();
        assert!(directory(&linked).is_err());
        std::fs::set_permissions(
            root.join("sub/file"),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(tree(&root, &mut Budget::new()).is_err());
    }
    #[test]
    fn fifo_is_refused_without_blocking_and_bytes_are_bounded() {
        use std::os::unix::ffi::OsStrExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let fifo = root.join("fifo");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(asset(&fifo, &mut Budget::new()).is_err());
        assert!(tree(&root, &mut Budget::new()).is_err());
        let mut budget = Budget::new();
        budget.bytes = 1536 * 1024 * 1024;
        assert!(budget.tick(1).is_err());
    }
    #[test]
    fn hardlinked_asset_refused_and_content_changes_affect_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = root.join("file");
        std::fs::write(&file, b"first").unwrap();
        let a = asset(&file, &mut Budget::new()).unwrap();
        std::fs::write(&file, b"second").unwrap();
        assert_ne!(a, asset(&file, &mut Budget::new()).unwrap());
        std::fs::hard_link(&file, root.join("alias")).unwrap();
        assert!(asset(&file, &mut Budget::new()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_library_aliases_are_descriptor_resolved_but_selected_assets_refuse_them() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::create_dir(root.join("usr/lib64")).unwrap();
        let file = root.join("usr/lib/loader.so");
        std::fs::write(&file, b"reviewed system loader").unwrap();
        symlink("usr/lib", root.join("lib")).unwrap();
        symlink("/usr/lib", root.join("lib64")).unwrap();
        symlink("loader.so", root.join("usr/lib/alias.so")).unwrap();
        symlink("../lib/loader.so", root.join("usr/lib64/relative.so")).unwrap();
        let expected = asset(&file, &mut Budget::new()).unwrap();
        for path in [
            "/lib/loader.so",
            "/lib64/alias.so",
            "/usr/lib/loader.so",
            "/usr/lib64/relative.so",
        ] {
            assert_eq!(
                system_library_from(
                    File::open(&root).unwrap(),
                    Path::new(path),
                    &mut Budget::new(),
                    unsafe { libc::geteuid() },
                )
                .unwrap(),
                expected
            );
        }
        assert!(asset(&root.join("lib/loader.so"), &mut Budget::new()).is_err());
        assert!(crate::doctor::read_private(&root.join("lib/loader.so"), 128).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_library_rejects_escapes_cycles_unsafe_ancestry_and_special_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::create_dir(root.join("private")).unwrap();
        std::fs::write(root.join("private/secret"), b"must not be read").unwrap();
        std::fs::write(root.join("usr/lib/loader.so"), b"system bytes").unwrap();
        symlink("/private/secret", root.join("usr/lib/escape.so")).unwrap();
        symlink(
            "../../private/secret",
            root.join("usr/lib/relative-escape.so"),
        )
        .unwrap();
        symlink("cycle.so", root.join("usr/lib/cycle.so")).unwrap();
        symlink("sub/../loader.so", root.join("usr/lib/ambiguous.so")).unwrap();
        let inspect = |path: &str, owner| {
            system_library_from(
                File::open(&root).unwrap(),
                Path::new(path),
                &mut Budget::new(),
                owner,
            )
        };
        let owner = unsafe { libc::geteuid() };
        for path in [
            "/private/secret",
            "/usr/lib/escape.so",
            "/usr/lib/relative-escape.so",
            "/usr/lib/cycle.so",
            "/usr/lib/ambiguous.so",
            "/usr/lib/../lib/loader.so",
        ] {
            assert!(inspect(path, owner).is_err(), "{path}");
        }
        assert!(inspect("/usr/lib/loader.so", owner.wrapping_add(1)).is_err());
        std::fs::set_permissions(root.join("usr"), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(inspect("/usr/lib/loader.so", owner).is_err());
        std::fs::set_permissions(root.join("usr"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(
            root.join("usr/lib/loader.so"),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(inspect("/usr/lib/loader.so", owner).is_err());
        let fifo = root.join("usr/lib/fifo");
        let fifo_c =
            std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(fifo.as_os_str()))
                .unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(inspect("/usr/lib/fifo", owner).is_err());
    }
}
