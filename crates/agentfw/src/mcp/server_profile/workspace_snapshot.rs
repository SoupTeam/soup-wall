// SPDX-License-Identifier: Apache-2.0
//! Explicit private snapshot input custody. This reuses the original strict
//! single-root profile and mounts only hash-verified kernel-sealed file images.
use super::WorkspaceIdentity;
use anyhow::ensure;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

pub const FORMAT: &str = "sw-private-workspace-snapshot/1";
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub sha256: String,
    pub identity: WorkspaceIdentity,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub format: String,
    pub generation: PathBuf,
    pub generation_identity: WorkspaceIdentity,
    pub workspace_identity: WorkspaceIdentity,
    pub receipt_sha256: String,
    pub tree_sha256: String,
    pub entries: Vec<Entry>,
    pub lease_identity: WorkspaceIdentity,
}
impl Binding {
    pub fn validate(&self, workspace: &Path) -> anyhow::Result<()> {
        ensure!(
            self.format == FORMAT
                && super::normal_absolute(&self.generation)
                && workspace == self.generation.join("workspace")
                && self.entries.len() <= 256
                && crate::native::is_digest(&self.receipt_sha256)
                && crate::native::is_digest(&self.tree_sha256),
            "workspace_snapshot_binding_schema"
        );
        let (mut total, mut files, mut directories) = (0u64, 0, 0);
        let mut previous = "";
        for entry in &self.entries {
            let path = Path::new(&entry.path);
            ensure!(
                !entry.path.is_empty()
                    && entry.path.len() <= 4096
                    && !entry.path.chars().any(char::is_control)
                    && !path.is_absolute()
                    && path.components().all(|p| matches!(p, Component::Normal(_)))
                    && entry.path.split('/').all(|p| !matches!(p, "" | "." | ".."))
                    && entry.path.as_str() > previous
                    && path.components().count() <= 33,
                "workspace_snapshot_entry_schema"
            );
            previous = &entry.path;
            match entry.kind.as_str() {
                "file" => {
                    files += 1;
                    total = total
                        .checked_add(entry.size)
                        .ok_or_else(|| anyhow::anyhow!("workspace_snapshot_byte_bound"))?;
                    ensure!(
                        entry.size <= 8 * 1024 * 1024 && crate::native::is_digest(&entry.sha256),
                        "workspace_snapshot_entry_schema"
                    );
                }
                "directory" => {
                    directories += 1;
                    ensure!(
                        entry.size == 0 && entry.sha256.is_empty(),
                        "workspace_snapshot_entry_schema"
                    );
                }
                _ => anyhow::bail!("workspace_snapshot_entry_schema"),
            }
        }
        ensure!(
            files <= 128 && directories < 128 && total <= 32 * 1024 * 1024,
            "workspace_snapshot_tree_bound"
        );
        let content:Vec<_>=self.entries.iter().map(|e|serde_json::json!({"path":e.path,"kind":e.kind,"size":e.size,"sha256":e.sha256})).collect();
        ensure!(
            crate::native::canonical_digest(&serde_json::json!(content)) == self.tree_sha256,
            "workspace_snapshot_tree_hash_changed"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::mcp::server_profile::filesystem_roots::{
        linux::{self as base, Observer},
        Root,
    };
    use anyhow::Context;
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        fs::{self, File},
        io::{Read, Seek, SeekFrom, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, PermissionsExt},
        },
    };
    use tokio::process::Command;
    fn sealed(bytes: &[u8]) -> anyhow::Result<File> {
        let fd = unsafe {
            libc::memfd_create(
                c"private-workspace-snapshot".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        ensure!(fd >= 0, "workspace_snapshot_image_unavailable");
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        file.seek(SeekFrom::Start(0))?;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        ensure!(
            unsafe {
                libc::fcntl(
                    fd,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL,
                )
            } == 0,
            "workspace_snapshot_image_unsealed"
        );
        Ok(file)
    }
    fn stamp(m: &fs::Metadata) -> [u64; 10] {
        [
            m.dev(),
            m.ino(),
            m.uid() as u64,
            m.mode() as u64,
            m.nlink(),
            m.len(),
            m.mtime() as u64,
            m.mtime_nsec() as u64,
            m.ctime() as u64,
            m.ctime_nsec() as u64,
        ]
    }
    fn bytes(file: &File, limit: u64) -> anyhow::Result<Vec<u8>> {
        let before = file.metadata()?;
        let mut raw = Vec::new();
        Read::take(file, limit + 1).read_to_end(&mut raw)?;
        ensure!(
            raw.len() as u64 == before.len()
                && raw.len() as u64 <= limit
                && stamp(&before) == stamp(&file.metadata()?),
            "workspace_snapshot_content_changed"
        );
        Ok(raw)
    }
    #[derive(Debug)]
    pub(crate) struct View {
        directories: Vec<PathBuf>,
        files: Vec<(PathBuf, File)>,
    }
    // Keep the descriptor, immutable expected tree and observer in one traversal.
    #[allow(clippy::too_many_arguments)]
    fn walk(
        directory: &File,
        prefix: &Path,
        expected: &BTreeMap<PathBuf, &Entry>,
        observer: &Observer,
        mount: u64,
        seen: &mut usize,
        view: &mut View,
        depth: usize,
    ) -> anyhow::Result<()> {
        ensure!(depth <= 32, "workspace_snapshot_tree_bound");
        observer.watch(directory)?;
        for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
            let entry = entry?;
            *seen += 1;
            ensure!(*seen <= 256, "workspace_snapshot_tree_bound");
            let path = prefix.join(entry.file_name());
            let selected = expected
                .get(&path)
                .context("workspace_snapshot_extra_entry")?;
            let file = base::child(directory, &entry.file_name(), selected.kind == "directory")?;
            let m = file.metadata()?;
            ensure!(
                WorkspaceIdentity::from_metadata(&m) == selected.identity
                    && base::mount_id(&file)? == mount
                    && m.mode() & 0o777
                        == if selected.kind == "directory" {
                            0o500
                        } else {
                            0o400
                        },
                "workspace_snapshot_object_changed"
            );
            base::owned(&file)?;
            if selected.kind == "directory" {
                ensure!(m.is_dir(), "workspace_snapshot_object_changed");
                view.directories.push(path.clone());
                walk(
                    &file,
                    &path,
                    expected,
                    observer,
                    mount,
                    seen,
                    view,
                    depth + 1,
                )?;
            } else {
                ensure!(
                    m.is_file() && m.len() == selected.size,
                    "workspace_snapshot_object_changed"
                );
                let raw = bytes(&file, 8 * 1024 * 1024)?;
                ensure!(
                    format!("{:x}", Sha256::digest(&raw)) == selected.sha256,
                    "workspace_snapshot_content_changed"
                );
                view.files.push((path, sealed(&raw)?));
            }
        }
        Ok(())
    }
    impl View {
        pub(crate) fn capture(binding: &Binding, workspace: &Path) -> anyhow::Result<Self> {
            binding.validate(workspace)?;
            let root = Root {
                id: "snapshot".into(),
                path: binding.generation.clone(),
                identity: binding.generation_identity.clone(),
                scope: "read-only".into(),
            };
            let generation = base::open(&root)?;
            base::local_mount(&generation)?;
            let receipt_file =
                base::child(&generation, std::ffi::OsStr::new("receipt.json"), false)?;
            base::owned(&receipt_file)?;
            ensure!(
                receipt_file.metadata()?.mode() & 0o777 == 0o400,
                "workspace_snapshot_receipt_changed"
            );
            let raw = bytes(&receipt_file, 65536)?;
            ensure!(
                format!("{:x}", Sha256::digest(&raw)) == binding.receipt_sha256,
                "workspace_snapshot_receipt_changed"
            );
            let receipt: serde_json::Value = serde_json::from_slice(&raw)?;
            ensure!(
                receipt["entries"] == serde_json::to_value(&binding.entries)?
                    && receipt["tree_sha256"] == binding.tree_sha256
                    && receipt["format"] == FORMAT
                    && receipt["workspace_identity"]
                        == serde_json::to_value(&binding.workspace_identity)?
                    && receipt["generation_identity"]
                        == serde_json::to_value(&binding.generation_identity)?,
                "workspace_snapshot_receipt_changed"
            );
            let complete = base::child(&generation, std::ffi::OsStr::new("complete.json"), false)?;
            base::owned(&complete)?;
            let complete: serde_json::Value = serde_json::from_slice(&bytes(&complete, 65536)?)?;
            ensure!(
                complete
                    == serde_json::json!({"format":FORMAT,"receipt_sha256":binding.receipt_sha256,"generation_identity":binding.generation_identity}),
                "workspace_snapshot_incomplete_generation"
            );
            let lease = base::child(&generation, std::ffi::OsStr::new("lease"), false)?;
            base::owned(&lease)?;
            ensure!(
                WorkspaceIdentity::from_metadata(&lease.metadata()?) == binding.lease_identity
                    && lease.metadata()?.mode() & 0o777 == 0o600,
                "workspace_snapshot_lease_changed"
            );
            let file = base::child(&generation, std::ffi::OsStr::new("workspace"), true)?;
            ensure!(
                WorkspaceIdentity::from_metadata(&file.metadata()?) == binding.workspace_identity
                    && file.metadata()?.mode() & 0o777 == 0o500,
                "workspace_snapshot_root_changed"
            );
            base::local_mount(&file)?;
            let mut observer = Observer::new()?;
            let expected = binding
                .entries
                .iter()
                .map(|e| (PathBuf::from(&e.path), e))
                .collect();
            let mut view = Self {
                directories: Vec::new(),
                files: Vec::new(),
            };
            let mut seen = 0;
            walk(
                &file,
                Path::new(""),
                &expected,
                &observer,
                base::mount_id(&file)?,
                &mut seen,
                &mut view,
                0,
            )?;
            ensure!(
                seen == binding.entries.len() && observer.valid(),
                "workspace_snapshot_incomplete_generation"
            );
            base::open(&root)?;
            Ok(view)
        }
        pub(crate) fn mount(
            &self,
            command: &mut Command,
            pins: &mut Vec<File>,
        ) -> anyhow::Result<()> {
            command.args(["--size", "1048576", "--tmpfs", "/workspace"]);
            let mut directories = self.directories.clone();
            directories.sort();
            for directory in directories {
                command
                    .arg("--dir")
                    .arg(Path::new("/workspace").join(directory));
            }
            for (path, file) in &self.files {
                let pin = file.try_clone()?;
                command
                    .arg("--ro-bind-fd")
                    .arg(pin.as_raw_fd().to_string())
                    .arg(Path::new("/workspace").join(path));
                pins.push(pin);
            }
            command.args(["--remount-ro", "/workspace"]);
            Ok(())
        }
    }
}
#[cfg(target_os = "linux")]
pub(crate) use linux::View;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::Read,
        os::{fd::AsRawFd, unix::fs::PermissionsExt},
    };
    fn sha(raw: &[u8]) -> String {
        format!("{:x}", Sha256::digest(raw))
    }
    fn fixture() -> (tempfile::TempDir, Binding) {
        let temp = tempfile::tempdir().unwrap();
        let generation = temp.path().join("snapshot");
        fs::create_dir(&generation).unwrap();
        fs::set_permissions(&generation, fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = generation.join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("note.txt"), b"owned captured bytes\n").unwrap();
        fs::set_permissions(
            workspace.join("note.txt"),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o500)).unwrap();
        fs::write(generation.join("lease"), b"").unwrap();
        fs::set_permissions(generation.join("lease"), fs::Permissions::from_mode(0o600)).unwrap();
        let id = |path: &Path| WorkspaceIdentity::from_metadata(&fs::metadata(path).unwrap());
        let entries = vec![Entry {
            path: "note.txt".into(),
            kind: "file".into(),
            size: 21,
            sha256: sha(b"owned captured bytes\n"),
            identity: id(&workspace.join("note.txt")),
        }];
        let tree = crate::native::canonical_digest(
            &serde_json::json!([{"path":"note.txt","kind":"file","size":21,"sha256":sha(b"owned captured bytes\n")} ]),
        );
        let receipt = serde_json::json!({"format":FORMAT,"entries":entries,"tree_sha256":tree,"generation_identity":id(&generation),"workspace_identity":id(&workspace)});
        let raw = serde_json::to_vec(&receipt).unwrap();
        fs::write(generation.join("receipt.json"), &raw).unwrap();
        let complete = serde_json::json!({"format":FORMAT,"receipt_sha256":sha(&raw),"generation_identity":id(&generation)});
        fs::write(
            generation.join("complete.json"),
            serde_json::to_vec(&complete).unwrap(),
        )
        .unwrap();
        for name in ["receipt.json", "complete.json"] {
            fs::set_permissions(generation.join(name), fs::Permissions::from_mode(0o400)).unwrap();
        }
        let binding = Binding {
            format: FORMAT.into(),
            generation_identity: id(&generation),
            workspace_identity: id(&workspace),
            receipt_sha256: sha(&raw),
            tree_sha256: tree,
            entries,
            lease_identity: id(&generation.join("lease")),
            generation,
        };
        (temp, binding)
    }
    #[test]
    fn workspace_snapshot_execution_uses_hash_verified_kernel_sealed_images() {
        let (_temp, binding) = fixture();
        let workspace = binding.generation.join("workspace");
        let view = View::capture(&binding, &workspace).unwrap();
        let mut command = tokio::process::Command::new("/owned/bwrap");
        let mut pins = Vec::new();
        view.mount(&mut command, &mut pins).unwrap();
        assert_eq!(pins.len(), 1);
        let seals = unsafe { libc::fcntl(pins[0].as_raw_fd(), libc::F_GET_SEALS) };
        assert_eq!(
            seals,
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL
        );
        assert_eq!(
            unsafe { libc::pwrite(pins[0].as_raw_fd(), b"x".as_ptr().cast(), 1, 0) },
            -1
        );
        fs::set_permissions(
            workspace.join("note.txt"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(workspace.join("note.txt"), "tampered").unwrap();
        fs::set_permissions(
            workspace.join("note.txt"),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        let mut captured = String::new();
        std::fs::File::open(format!("/proc/self/fd/{}", pins[0].as_raw_fd()))
            .unwrap()
            .read_to_string(&mut captured)
            .unwrap();
        assert_eq!(captured, "owned captured bytes\n");
        assert!(View::capture(&binding, &workspace).is_err());
    }
    #[test]
    fn workspace_snapshot_incomplete_replaced_and_cross_profile_inputs_refuse() {
        let (_temp, binding) = fixture();
        let workspace = binding.generation.join("workspace");
        fs::remove_file(binding.generation.join("complete.json")).unwrap();
        assert!(View::capture(&binding, &workspace).is_err());
        let mut changed = binding.clone();
        changed.entries[0].path = "../outside".into();
        assert!(changed.validate(&workspace).is_err());
        changed = binding.clone();
        changed.workspace_identity.inode += 1;
        assert!(View::capture(&changed, &workspace).is_err());
    }
}
