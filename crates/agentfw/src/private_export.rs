// SPDX-License-Identifier: Apache-2.0
//! Shared bounded owner-private create-new directory publication. No archive walk.
use std::path::Path;

pub(crate) fn publish(
    destination: &Path,
    entries: &[(&str, &[u8])],
    validate: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    use anyhow::{ensure, Context};
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;
    ensure!(
        !entries.is_empty() && entries.len() <= 9,
        "export_file_count"
    );
    let mut unique = std::collections::BTreeSet::new();
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
    fn c(s: &OsStr) -> anyhow::Result<CString> {
        Ok(CString::new(s.as_bytes())?)
    }

    /// Every path segment is opened relative to an already pinned descriptor.
    fn open_dir(path: &Path) -> anyhow::Result<File> {
        ensure!(path.is_absolute(), "absolute path required");
        let mut dir = File::open("/")?;
        for part in path.components() {
            match part {
                Component::RootDir => (),
                Component::Normal(name) => {
                    let name = c(name)?;
                    let fd = unsafe {
                        libc::openat(
                            dir.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    ensure!(fd >= 0, "unsafe output parent");
                    dir = unsafe { File::from_raw_fd(fd) };
                }
                _ => anyhow::bail!("parent path aliases not permitted"),
            }
        }
        Ok(dir)
    }

    fn create_file(dir: &File, name: &std::ffi::CStr, bytes: &[u8]) -> anyhow::Result<()> {
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        ensure!(fd >= 0, "cannot create new private support file");
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    struct Staging {
        parent: File,
        stage: CString,
        output: File,
        published: bool,
        names: Vec<CString>,
    }

    impl Drop for Staging {
        fn drop(&mut self) {
            if self.published {
                return;
            }
            for name in &self.names {
                unsafe {
                    libc::unlinkat(self.output.as_raw_fd(), name.as_ptr(), 0);
                }
            }
            unsafe {
                libc::unlinkat(
                    self.parent.as_raw_fd(),
                    self.stage.as_ptr(),
                    libc::AT_REMOVEDIR,
                );
            }
        }
    }

    let parent_path = destination.parent().context("missing destination parent")?;
    let target = c(destination
        .file_name()
        .context("missing destination name")?)?;
    ensure!(!target.as_bytes().is_empty(), "empty destination name");
    let parent = open_dir(parent_path)?;
    let owner = parent.metadata()?;
    ensure!(
        owner.is_dir() && owner.uid() == unsafe { libc::geteuid() } && owner.mode() & 0o077 == 0,
        "support output parent must be owner-only"
    );
    let stage = CString::new(format!(".agentfw-doctor-{}", crate::token::generate()))?;
    let ok = unsafe { libc::mkdirat(parent.as_raw_fd(), stage.as_ptr(), 0o700) };
    ensure!(ok == 0, "unable to create private support stage");
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            stage.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        unsafe {
            libc::unlinkat(parent.as_raw_fd(), stage.as_ptr(), libc::AT_REMOVEDIR);
        }
        anyhow::bail!("cannot open private support stage");
    }
    let output = unsafe { File::from_raw_fd(fd) };
    let mut staging = Staging {
        parent,
        stage,
        output,
        published: false,
        names,
    };
    for (name, (_, bytes)) in staging.names.iter().zip(entries) {
        create_file(&staging.output, name, bytes)?;
    }
    staging.output.sync_all()?;
    // Rename without clobbering an existing file, link or directory, even in a
    // concurrent publication. The directory is published in one atomic step.
    validate()?;
    let current_parent = open_dir(parent_path)?;
    let current_owner = current_parent.metadata()?;
    ensure!(
        current_owner.uid() == unsafe { libc::geteuid() } && current_owner.mode() & 0o077 == 0,
        "export_parent_permissions_changed"
    );
    ensure!(
        current_parent.metadata()?.dev() == owner.dev()
            && current_parent.metadata()?.ino() == owner.ino(),
        "export_parent_changed"
    );
    let moved = unsafe {
        libc::renameat2(
            staging.parent.as_raw_fd(),
            staging.stage.as_ptr(),
            staging.parent.as_raw_fd(),
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    ensure!(
        moved == 0,
        "support destination already exists or cannot be published"
    );
    staging.published = true;
    staging.parent.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };
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
