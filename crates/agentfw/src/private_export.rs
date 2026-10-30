// SPDX-License-Identifier: Apache-2.0
//! Shared bounded owner-private create-new publication, with pinned cleanup.
use anyhow::{ensure, Context};
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString, OsStr},
    fs::{File, Metadata},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

fn c(s: &OsStr) -> anyhow::Result<CString> {
    Ok(CString::new(s.as_bytes())?)
}
fn openat(parent: &File, name: &CStr, flags: i32) -> anyhow::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    ensure!(fd >= 0, "export_selected_object_unavailable");
    Ok(unsafe { File::from_raw_fd(fd) })
}
/// Reuse the publication primitive's descriptor walk; never resolve a link.
fn open_dir(path: &Path) -> anyhow::Result<File> {
    ensure!(
        path.is_absolute() && path.as_os_str().len() <= 4096,
        "export_absolute_bounded_parent_required"
    );
    let mut dir = File::open("/")?;
    let mut depth = 0;
    for part in path.components() {
        match part {
            Component::RootDir => (),
            Component::Normal(name) => {
                depth += 1;
                ensure!(depth <= 128, "export_parent_depth_cap");
                dir = openat(&dir, &c(name)?, libc::O_RDONLY | libc::O_DIRECTORY)?;
                let meta = dir.metadata()?;
                ensure!(
                    (meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() })
                        && (meta.mode() & 0o022 == 0
                            || (meta.uid() == 0 && meta.mode() & libc::S_ISVTX != 0)),
                    "export_parent_ancestry_unsafe"
                );
            }
            _ => anyhow::bail!("export_parent_alias_refused"),
        }
    }
    Ok(dir)
}
fn same_object(a: &Metadata, b: &Metadata) -> bool {
    (a.dev(), a.ino(), a.uid(), a.gid(), a.mode()) == (b.dev(), b.ino(), b.uid(), b.gid(), b.mode())
}
fn stable_file(a: &Metadata, b: &Metadata) -> bool {
    same_object(a, b)
        && a.nlink() == 1
        && b.nlink() == 1
        && (
            a.len(),
            a.mtime(),
            a.mtime_nsec(),
            a.ctime(),
            a.ctime_nsec(),
        ) == (
            b.len(),
            b.mtime(),
            b.mtime_nsec(),
            b.ctime(),
            b.ctime_nsec(),
        )
}

#[derive(serde::Serialize, PartialEq, Eq)]
pub(crate) struct DestinationBinding {
    path: PathBuf,
    parent_device: u64,
    parent_inode: u64,
    parent_uid: u32,
    parent_gid: u32,
    parent_mode: u32,
}
/// An exact new destination, retaining its independently opened parent handle.
pub(crate) struct Destination {
    parent: File,
    target: CString,
    binding: DestinationBinding,
}
impl Destination {
    pub(crate) fn select(path: &Path) -> anyhow::Result<Self> {
        let raw = path.as_os_str().as_bytes();
        ensure!(
            raw.len() > 1
                && raw.len() <= 4096
                && raw[0] == b'/'
                && raw[1..]
                    .split(|b| *b == b'/')
                    .all(|s| !s.is_empty() && s != b"." && s != b".."),
            "export_canonical_destination_required"
        );
        let parent = open_dir(path.parent().context("export_parent_missing")?)?;
        let meta = parent.metadata()?;
        ensure!(
            meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "export_parent_must_be_owner_private"
        );
        let target = c(path.file_name().context("export_leaf_missing")?)?;
        ensure!(target.as_bytes().len() <= 128, "export_leaf_cap");
        let mut object: libc::stat = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    target.as_ptr(),
                    &mut object,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
            "export_destination_exists_or_unavailable"
        );
        Ok(Self {
            parent,
            target,
            binding: DestinationBinding {
                path: path.to_owned(),
                parent_device: meta.dev(),
                parent_inode: meta.ino(),
                parent_uid: meta.uid(),
                parent_gid: meta.gid(),
                parent_mode: meta.mode(),
            },
        })
    }
    pub(crate) fn binding(&self) -> &DestinationBinding {
        &self.binding
    }
    fn recheck(&self) -> anyhow::Result<()> {
        let current = Self::select(&self.binding.path)?;
        ensure!(
            current.binding == self.binding
                && same_object(&current.parent.metadata()?, &self.parent.metadata()?),
            "export_parent_changed"
        );
        Ok(())
    }
    pub(crate) fn publish(
        &self,
        entries: &[(&str, &[u8])],
        validate: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        ensure!(
            !entries.is_empty() && entries.len() <= 9,
            "export_file_count"
        );
        let mut unique = BTreeSet::new();
        let mut total = 0usize;
        let mut names = Vec::new();
        for (name, bytes) in entries {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && !name.starts_with('.')
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    && unique.insert(*name),
                "export_leaf_invalid"
            );
            total = total.checked_add(bytes.len()).context("export_byte_cap")?;
            ensure!(total <= 144 * 1024, "export_byte_cap");
            names.push(CString::new(*name)?);
        }
        self.recheck()?;
        let stage = CString::new(format!(".agentfw-doctor-{}", crate::token::generate()))?;
        ensure!(
            unsafe { libc::mkdirat(self.parent.as_raw_fd(), stage.as_ptr(), 0o700) } == 0,
            "export_stage_create_failed"
        );
        // If opening the newly created name fails, its identity is unverified;
        // preserve it for operator inspection instead of deleting a substitute.
        let output = openat(&self.parent, &stage, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let meta = output.metadata()?;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o7777 == 0o700,
            "export_stage_unsafe"
        );
        let mut staging = Staging {
            parent: &self.parent,
            name: stage,
            output,
            identity: meta,
            files: Vec::new(),
            published: false,
        };
        for (name, (_, bytes)) in names.into_iter().zip(entries) {
            let fd = unsafe {
                libc::openat(
                    staging.output.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            ensure!(fd >= 0, "export_file_create_failed");
            let mut file = unsafe { File::from_raw_fd(fd) };
            let written = file.write_all(bytes).and_then(|()| file.sync_all());
            let identity = file.metadata()?;
            staging.files.push(OwnedFile {
                name,
                file,
                identity,
            });
            written.context("export_copy_or_sync_failed")?;
        }
        staging
            .output
            .sync_all()
            .context("export_stage_sync_failed")?;
        validate()?;
        self.recheck()?;
        staging.verify()?;
        let moved = unsafe {
            libc::renameat2(
                self.parent.as_raw_fd(),
                staging.name.as_ptr(),
                self.parent.as_raw_fd(),
                self.target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        ensure!(
            moved == 0,
            "export_destination_exists_or_publication_failed"
        );
        staging.published = true;
        self.parent
            .sync_all()
            .context("export_published_parent_sync_incomplete")?;
        Ok(())
    }
}
struct OwnedFile {
    name: CString,
    file: File,
    identity: Metadata,
}
struct Staging<'a> {
    parent: &'a File,
    name: CString,
    output: File,
    identity: Metadata,
    files: Vec<OwnedFile>,
    published: bool,
}
impl Staging<'_> {
    fn selected(&self) -> anyhow::Result<()> {
        let current = openat(self.parent, &self.name, libc::O_PATH | libc::O_DIRECTORY)?;
        ensure!(
            same_object(&self.identity, &current.metadata()?)
                && same_object(&self.identity, &self.output.metadata()?),
            "export_stage_changed"
        );
        Ok(())
    }
    fn file_matches(&self, file: &OwnedFile) -> anyhow::Result<()> {
        let current = openat(&self.output, &file.name, libc::O_PATH)?;
        ensure!(
            file.identity.is_file()
                && file.identity.uid() == unsafe { libc::geteuid() }
                && file.identity.mode() & 0o7777 == 0o600
                && stable_file(&file.identity, &current.metadata()?)
                && stable_file(&file.identity, &file.file.metadata()?),
            "export_stage_file_changed"
        );
        Ok(())
    }
    fn verify(&self) -> anyhow::Result<()> {
        self.selected()?;
        for file in &self.files {
            self.file_matches(file)?;
        }
        // Only the finite allowlisted stage is enumerated, never source state.
        let dir = openat(&self.output, c".", libc::O_RDONLY | libc::O_DIRECTORY)?;
        use std::os::fd::IntoRawFd;
        let fd = dir.into_raw_fd();
        let ptr = unsafe { libc::fdopendir(fd) };
        if ptr.is_null() {
            unsafe { libc::close(fd) };
            anyhow::bail!("export_stage_enumeration_failed");
        }
        struct Stream(*mut libc::DIR);
        impl Drop for Stream {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let stream = Stream(ptr);
        let mut seen = BTreeSet::new();
        loop {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let row = unsafe { libc::readdir(stream.0) };
            if row.is_null() {
                ensure!(
                    std::io::Error::last_os_error().raw_os_error() == Some(0),
                    "export_stage_enumeration_failed"
                );
                break;
            }
            let name = unsafe { CStr::from_ptr((*row).d_name.as_ptr()) };
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            ensure!(
                seen.len() < self.files.len()
                    && self.files.iter().any(|f| f.name.as_c_str() == name)
                    && seen.insert(name.to_owned()),
                "export_stage_unexpected_entry"
            );
        }
        ensure!(seen.len() == self.files.len(), "export_stage_entry_missing");
        Ok(())
    }
}
impl Drop for Staging<'_> {
    fn drop(&mut self) {
        if self.published || self.selected().is_err() {
            return;
        }
        for file in &self.files {
            if self.file_matches(file).is_ok() {
                unsafe {
                    libc::unlinkat(self.output.as_raw_fd(), file.name.as_ptr(), 0);
                }
            }
        }
        // rmdir cannot remove an injected entry or recursively delete anything.
        if self.selected().is_ok() {
            unsafe {
                libc::unlinkat(
                    self.parent.as_raw_fd(),
                    self.name.as_ptr(),
                    libc::AT_REMOVEDIR,
                );
            }
        }
    }
}
pub(crate) fn publish(
    destination: &Path,
    entries: &[(&str, &[u8])],
    validate: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    Destination::select(destination)?.publish(entries, validate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };
    #[test]
    fn confirmation_destination_pins_the_exact_parent_object() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let parent = temp.path().join("parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let selected = Destination::select(&parent.join("set")).unwrap();
        assert!(Destination::select(&parent.join("./set")).is_err());
        assert!(
            selected.binding()
                != Destination::select(&parent.join("other"))
                    .unwrap()
                    .binding()
        );
        fs::rename(&parent, temp.path().join("held")).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(parent.join("sentinel"), b"keep").unwrap();
        assert!(selected
            .publish(&[("a.txt", b"first"), ("b.txt", b"last")], || Ok(()))
            .is_err());
        assert_eq!(fs::read(parent.join("sentinel")).unwrap(), b"keep");
        assert_eq!(fs::read_dir(temp.path().join("held")).unwrap().count(), 0);
    }
    fn stage(parent: &Path) -> PathBuf {
        fs::read_dir(parent)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .as_bytes()
                    .starts_with(b".agentfw-doctor-")
            })
            .unwrap()
    }
    #[test]
    fn injected_stage_entries_are_neither_published_nor_recursively_deleted() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(publish(
            &temp.path().join("set"),
            &[("a.txt", b"first"), ("b.txt", b"last")],
            || {
                fs::write(stage(temp.path()).join("unrelated"), b"preserve")?;
                Ok(())
            }
        )
        .is_err());
        let stage = stage(temp.path());
        assert!(!temp.path().join("set").exists());
        assert_eq!(fs::read_dir(&stage).unwrap().count(), 1);
        assert_eq!(fs::read(stage.join("unrelated")).unwrap(), b"preserve");
    }
    #[test]
    fn substituted_stage_file_and_stage_name_remain_unmodified() {
        for replace_directory in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let sentinel = temp.path().join("sentinel");
            fs::write(&sentinel, b"outside").unwrap();
            assert!(publish(
                &temp.path().join("set"),
                &[("a.txt", b"first"), ("b.txt", b"last")],
                || {
                    let selected = stage(temp.path());
                    if replace_directory {
                        fs::rename(&selected, temp.path().join("held"))?;
                        fs::create_dir(&selected)?;
                        fs::set_permissions(&selected, fs::Permissions::from_mode(0o700))?;
                        fs::write(selected.join("unrelated"), b"preserve")?;
                    } else {
                        fs::remove_file(selected.join("b.txt"))?;
                        fs::hard_link(&sentinel, selected.join("b.txt"))?;
                    }
                    Ok(())
                }
            )
            .is_err());
            assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
            assert!(!temp.path().join("set").exists());
            if replace_directory {
                assert_eq!(
                    fs::read(stage(temp.path()).join("unrelated")).unwrap(),
                    b"preserve"
                );
                assert_eq!(fs::read(temp.path().join("held/a.txt")).unwrap(), b"first");
            } else {
                assert_eq!(
                    fs::read(stage(temp.path()).join("b.txt")).unwrap(),
                    b"outside"
                );
            }
        }
    }
    #[test]
    fn private_exact_files_no_overwrite_and_failed_validation_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let out = temp.path().join("bundle");
        let entries = [
            ("manifest.json", b"finite".as_slice()),
            ("result.txt", b"selected"),
        ];
        assert!(publish(&out, &entries, || anyhow::bail!("changed")).is_err());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
        publish(&out, &entries, || Ok(())).unwrap();
        assert_eq!(
            fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(out.join("result.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(fs::read(out.join("result.txt")).unwrap(), b"selected");
        assert!(publish(&out, &entries, || Ok(())).is_err());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
        let alias = temp.path().join("alias");
        symlink(&out, &alias).unwrap();
        assert!(publish(&alias.join("escape"), &entries, || Ok(())).is_err());
        assert!(!out.join("escape").exists());
        assert!(
            publish(&temp.path().join("bad"), &[("../escape", b"data")], || Ok(
                ()
            ))
            .is_err()
        );
    }
    #[test]
    fn substituted_publication_parent_preserves_replacement_and_cleans_owned_stage() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("selected");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let held = temp.path().join("original");
        assert!(publish(
            &parent.join("bundle"),
            &[("result.txt", b"private")],
            || {
                fs::rename(&parent, &held)?;
                fs::create_dir(&parent)?;
                fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
                fs::write(parent.join("sentinel"), b"unrelated")?;
                Ok(())
            }
        )
        .is_err());
        assert_eq!(fs::read_dir(&held).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 1);
        assert_eq!(fs::read(parent.join("sentinel")).unwrap(), b"unrelated");
    }
}
