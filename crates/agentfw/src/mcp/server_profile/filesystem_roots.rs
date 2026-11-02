// SPDX-License-Identifier: Apache-2.0
//! Separately selected filesystem roots. Namespace IDs never discover host paths.
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const FORMAT: &str = "sw-mcp/filesystem-multi-root-readonly/1";
pub const BINDING_FORMAT: &str = "sw-pilot-filesystem-roots/1";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub id: String,
    pub path: PathBuf,
    pub identity: super::WorkspaceIdentity,
    pub scope: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub format: String,
    pub roots: Vec<Root>,
}

impl Binding {
    pub fn validate_schema(&self, workspace: &Path) -> anyhow::Result<()> {
        ensure!(
            self.format == BINDING_FORMAT && (2..=4).contains(&self.roots.len()),
            "filesystem_roots_binding_schema"
        );
        for (index, root) in self.roots.iter().enumerate() {
            ensure!(
                !root.id.is_empty()
                    && root.id.len() <= 32
                    && root.id.as_bytes()[0].is_ascii_lowercase()
                    && root.id.bytes().all(|c| c.is_ascii_lowercase()
                        || c.is_ascii_digit()
                        || matches!(c, b'_' | b'-'))
                    && root.scope == "read-only"
                    && super::normal_absolute(&root.path)
                    && root.path != Path::new("/"),
                "filesystem_roots_binding_schema"
            );
            for other in &self.roots[..index] {
                ensure!(
                    other.id < root.id
                        && other.identity != root.identity
                        && !other.path.starts_with(&root.path)
                        && !root.path.starts_with(&other.path),
                    "filesystem_roots_duplicate_or_overlap"
                );
            }
        }
        ensure!(
            self.roots[0].path == workspace,
            "filesystem_roots_workspace_mismatch"
        );
        Ok(())
    }

    pub fn arguments(&self) -> Vec<String> {
        self.roots
            .iter()
            .map(|r| format!("/workspace/{}", r.id))
            .collect()
    }

    /// All arguments remain original bytes. The pinned schema supplies required
    /// fields/defaults; the only supported no-resource tool enumerates all roots.
    pub fn resources<'a>(
        &'a self,
        name: &str,
        args: &'a serde_json::Value,
    ) -> anyhow::Result<Vec<(&'a Root, PathBuf)>> {
        let map = args.as_object().context("filesystem_roots_arguments")?;
        if name == "list_allowed_directories" {
            ensure!(map.is_empty(), "filesystem_roots_arguments");
            return Ok(self.roots.iter().map(|r| (r, PathBuf::new())).collect());
        }
        let paths: Vec<&serde_json::Value> = match name {
            "read_multiple_files" => map
                .get("paths")
                .and_then(|p| p.as_array())
                .context("filesystem_roots_paths")?
                .iter()
                .collect(),
            "read_file"
            | "read_text_file"
            | "list_directory"
            | "list_directory_with_sizes"
            | "directory_tree"
            | "search_files"
            | "get_file_info" => vec![map.get("path").context("filesystem_roots_path")?],
            _ => anyhow::bail!("filesystem_roots_unsupported_tool"),
        };
        ensure!(
            !paths.is_empty() && paths.len() <= 64,
            "filesystem_roots_paths_bound"
        );
        paths
            .into_iter()
            .map(|value| {
                let path = value.as_str().context("filesystem_roots_path")?;
                // Existing schema validation already enforces normalized /workspace
                // syntax. Require a selected root ID for EVERY resource, too.
                super::validate_workspace_path(value)?;
                let mut parts = path
                    .strip_prefix("/workspace/")
                    .context("filesystem_roots_unbound_path")?
                    .split('/');
                let id = parts.next().context("filesystem_roots_unbound_path")?;
                let root = self
                    .roots
                    .iter()
                    .find(|r| r.id == id)
                    .context("filesystem_roots_unbound_path")?;
                Ok((root, parts.collect::<PathBuf>()))
            })
            .collect()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        ffi::CString,
        fs::{self, File},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        sync::Mutex,
    };
    use tokio::process::Command;

    fn child(parent: &File, name: &std::ffi::OsStr, directory: bool) -> anyhow::Result<File> {
        let name = CString::new(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC
                    | if directory { libc::O_DIRECTORY } else { 0 },
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn owned(file: &File) -> anyhow::Result<()> {
        let m = file.metadata()?;
        ensure!(
            m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o022 == 0
                && (m.is_dir() || m.is_file() && m.nlink() == 1),
            "filesystem_roots_unsafe_entry"
        );
        Ok(())
    }

    fn open(root: &Root) -> anyhow::Result<File> {
        let mut file = File::open("/")?;
        for component in root.path.components() {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::Normal(name) => file = child(&file, name, true)?,
                _ => anyhow::bail!("filesystem_roots_canonical_root_required"),
            }
        }
        owned(&file)?;
        ensure!(
            super::super::WorkspaceIdentity::from_metadata(&file.metadata()?) == root.identity,
            "filesystem_roots_selected_root_changed"
        );
        Ok(file)
    }

    // Inotify is a sticky topology witness only on the supported local
    // filesystems. Remote/FUSE/overlay mutations need not produce its events;
    // never treat successful watch registration there as root confinement.
    fn local_mount(file: &File) -> anyhow::Result<()> {
        let mut metadata = std::mem::MaybeUninit::<libc::statfs>::uninit();
        ensure!(
            unsafe { libc::fstatfs(file.as_raw_fd(), metadata.as_mut_ptr()) } == 0,
            "filesystem_roots_mount_identity_unavailable"
        );
        ensure!(
            matches!(
                unsafe { metadata.assume_init() }.f_type as u64,
                0xef53 | 0x58465342 | 0x9123683e | 0x01021994
            ),
            "filesystem_roots_local_filesystem_required"
        );
        Ok(())
    }

    fn mount_id(file: &File) -> anyhow::Result<u64> {
        let raw = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
        raw.lines()
            .find_map(|line| line.strip_prefix("mnt_id:").map(str::trim))
            .context("filesystem_roots_mount_identity_unavailable")?
            .parse()
            .map_err(Into::into)
    }

    #[cfg(test)]
    #[test]
    fn filesystem_roots_reject_nonlocal_topology_observers() {
        assert!(local_mount(&File::open("/proc").unwrap()).is_err());
        let owned = tempfile::tempdir().unwrap();
        local_mount(&File::open(owned.path()).unwrap()).unwrap();
    }

    #[derive(Debug)]
    struct Observer {
        file: File,
        broken: bool,
        directories: usize,
        entries: usize,
    }
    impl Observer {
        fn new() -> anyhow::Result<Self> {
            let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            ensure!(fd >= 0, "filesystem_roots_observer_unavailable");
            Ok(Self {
                file: unsafe { File::from_raw_fd(fd) },
                broken: false,
                directories: 0,
                entries: 0,
            })
        }
        fn valid(&mut self) -> bool {
            if self.broken {
                return false;
            }
            let mut bytes = [0u8; 8192];
            loop {
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
                        Some(libc::EAGAIN) => return true,
                        _ => {}
                    }
                }
                // Any event, overflow or lost watch permanently withdraws the
                // root set. This witnesses topology, never content/permission.
                self.broken = true;
                return false;
            }
        }
        fn tree(&mut self, directory: &File, mount: u64, depth: usize) -> anyhow::Result<()> {
            self.directories += 1;
            ensure!(
                depth <= 32 && self.directories <= 128,
                "filesystem_roots_tree_bound"
            );
            owned(directory)?;
            ensure!(
                mount_id(directory)? == mount,
                "filesystem_roots_nested_mount_unsupported"
            );
            let path = CString::new(format!("/proc/self/fd/{}", directory.as_raw_fd()))?;
            let mask = libc::IN_ONLYDIR
                | libc::IN_ATTRIB
                | libc::IN_CREATE
                | libc::IN_DELETE
                | libc::IN_MOVED_FROM
                | libc::IN_MOVED_TO
                | libc::IN_MOVE_SELF
                | libc::IN_DELETE_SELF
                | libc::IN_UNMOUNT;
            ensure!(
                unsafe { libc::inotify_add_watch(self.file.as_raw_fd(), path.as_ptr(), mask) } >= 0,
                "filesystem_roots_observer_unavailable"
            );
            // Subscribe BEFORE inspecting children, and refuse every link. This
            // covers recursive original tree/search tools as well as path arrays.
            for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
                let entry = entry?;
                self.entries += 1;
                ensure!(self.entries <= 32768, "filesystem_roots_tree_bound");
                let metadata = fs::symlink_metadata(entry.path())?;
                ensure!(
                    metadata.is_dir() || metadata.is_file(),
                    "filesystem_roots_unsafe_entry"
                );
                let file = child(directory, &entry.file_name(), metadata.is_dir())?;
                owned(&file)?;
                let actual = file.metadata()?;
                ensure!(
                    metadata.dev() == actual.dev()
                        && metadata.ino() == actual.ino()
                        && mount_id(&file)? == mount,
                    "filesystem_roots_entry_changed"
                );
                if actual.is_dir() {
                    self.tree(&file, mount, depth + 1)?;
                }
            }
            ensure!(self.valid(), "filesystem_roots_source_withdrawn");
            Ok(())
        }
    }

    #[derive(Debug)]
    pub(crate) struct Guard {
        binding: Binding,
        roots: Vec<File>,
        observer: Mutex<Observer>,
    }
    impl Guard {
        pub(crate) fn capture(binding: &Binding) -> anyhow::Result<Self> {
            binding.validate_schema(
                &binding
                    .roots
                    .first()
                    .context("filesystem_roots_count")?
                    .path,
            )?;
            let mut observer = Observer::new()?;
            let mut roots = Vec::new();
            for root in &binding.roots {
                let file = open(root)?;
                local_mount(&file)?;
                observer.tree(&file, mount_id(&file)?, 0)?;
                roots.push(file);
            }
            let guard = Self {
                binding: binding.clone(),
                roots,
                observer: Mutex::new(observer),
            };
            guard.validate()?;
            Ok(guard)
        }
        fn validate(&self) -> anyhow::Result<()> {
            let mut observer = self
                .observer
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem_roots_source_withdrawn"))?;
            ensure!(observer.valid(), "filesystem_roots_source_withdrawn");
            for root in &self.binding.roots {
                open(root)?;
            }
            ensure!(observer.valid(), "filesystem_roots_source_withdrawn");
            Ok(())
        }
        pub(crate) fn validate_call(
            &self,
            name: &str,
            args: &serde_json::Value,
        ) -> anyhow::Result<()> {
            self.validate()?;
            for (root, relative) in self.binding.resources(name, args)? {
                let ordinal = self
                    .binding
                    .roots
                    .iter()
                    .position(|r| r.id == root.id)
                    .context("filesystem_roots_unbound_path")?;
                let mut file = self.roots[ordinal].try_clone()?;
                let parts: Vec<_> = relative.components().collect();
                for (index, component) in parts.iter().enumerate() {
                    let std::path::Component::Normal(name) = component else {
                        anyhow::bail!("filesystem_roots_path");
                    };
                    match child(&file, name, index + 1 < parts.len()) {
                        Ok(next) => {
                            owned(&next)?;
                            ensure!(
                                mount_id(&next)? == mount_id(&self.roots[ordinal])?,
                                "filesystem_roots_nested_mount_unsupported"
                            );
                            file = next;
                        }
                        Err(e)
                            if e.downcast_ref::<std::io::Error>().is_some_and(|io| {
                                matches!(
                                    io.kind(),
                                    std::io::ErrorKind::NotFound
                                        | std::io::ErrorKind::NotADirectory
                                )
                            }) =>
                        {
                            break
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            self.validate()
        }
        pub(crate) fn mount(
            &self,
            command: &mut Command,
            pins: &mut Vec<File>,
        ) -> anyhow::Result<()> {
            self.validate()?;
            command.args(["--size", "1048576", "--tmpfs", "/workspace"]);
            for (root, file) in self.binding.roots.iter().zip(&self.roots) {
                let pin = file.try_clone()?;
                command
                    .arg("--ro-bind-fd")
                    .arg(pin.as_raw_fd().to_string())
                    .arg(format!("/workspace/{}", root.id));
                pins.push(pin);
            }
            command.args(["--remount-ro", "/workspace"]);
            self.validate()
        }
    }
}
#[cfg(target_os = "linux")]
pub(crate) use linux::Guard;

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub(crate) struct Guard;
#[cfg(not(target_os = "linux"))]
impl Guard {
    pub(crate) fn validate_call(&self, _: &str, _: &serde_json::Value) -> anyhow::Result<()> {
        anyhow::bail!("filesystem_roots_platform_unsupported")
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{fs, os::unix::fs::symlink};

    fn fixture() -> (tempfile::TempDir, Binding) {
        let temp = tempfile::tempdir().unwrap();
        let mut roots = Vec::new();
        for id in ["alpha", "beta"] {
            let path = temp.path().join(id);
            fs::create_dir(&path).unwrap();
            fs::write(path.join("note.txt"), format!("Owned {id} content")).unwrap();
            roots.push(Root {
                id: id.into(),
                identity: super::super::WorkspaceIdentity::from_metadata(
                    &fs::metadata(&path).unwrap(),
                ),
                path,
                scope: "read-only".into(),
            });
        }
        (
            temp,
            Binding {
                format: BINDING_FORMAT.into(),
                roots,
            },
        )
    }

    #[test]
    fn filesystem_roots_validate_every_resource_and_no_ambient_default() {
        let (_temp, binding) = fixture();
        let guard = Guard::capture(&binding).unwrap();
        for (tool, args) in [
            (
                "read_text_file",
                json!({"path":"/workspace/alpha/note.txt"}),
            ),
            ("list_directory", json!({"path":"/workspace/beta"})),
            (
                "search_files",
                json!({"path":"/workspace/alpha","pattern":"*.txt"}),
            ),
            (
                "read_multiple_files",
                json!({"paths":["/workspace/alpha/note.txt","/workspace/beta/note.txt"]}),
            ),
            ("list_allowed_directories", json!({})),
            (
                "get_file_info",
                json!({"path":"/workspace/beta/missing.txt"}),
            ),
        ] {
            guard.validate_call(tool, &args).unwrap();
        }
        for args in [
            json!({"paths":["/workspace/alpha/note.txt","/workspace/unselected/canary"]}),
            json!({"paths":["/workspace/alpha/note.txt","/workspace/alpha/../beta/note.txt"]}),
            json!({"paths":["/workspace/alpha/note.txt","relative"]}),
            json!({"paths":[]}),
        ] {
            assert!(guard.validate_call("read_multiple_files", &args).is_err());
        }
        for path in [
            "/workspace",
            "/workspace/",
            "/workspace/unknown",
            "/workspace/alpha/./note.txt",
        ] {
            assert!(guard
                .validate_call("read_text_file", &json!({"path":path}))
                .is_err());
        }
        assert!(guard
            .validate_call(
                "write_file",
                &json!({"path":"/workspace/alpha/note.txt","content":"new"})
            )
            .is_err());
    }

    #[test]
    fn filesystem_roots_refuse_alias_topology_and_sticky_recovery() {
        let (temp, binding) = fixture();
        let canary = temp.path().join("unselected");
        fs::create_dir(&canary).unwrap();
        fs::write(canary.join("canary"), "NEVER-READ").unwrap();
        let guard = Guard::capture(&binding).unwrap();
        let link = binding.roots[0].path.join("escape");
        symlink(&canary, &link).unwrap();
        assert!(guard
            .validate_call("directory_tree", &json!({"path":"/workspace/alpha"}))
            .is_err());
        fs::remove_file(&link).unwrap();
        assert!(guard
            .validate_call(
                "read_text_file",
                &json!({"path":"/workspace/beta/note.txt"})
            )
            .is_err());
        let fresh = Guard::capture(&binding).unwrap();
        fresh
            .validate_call(
                "read_text_file",
                &json!({"path":"/workspace/beta/note.txt"}),
            )
            .unwrap();
        symlink(&canary, &link).unwrap();
        assert!(Guard::capture(&binding).is_err());
        assert_eq!(
            fs::read_to_string(canary.join("canary")).unwrap(),
            "NEVER-READ"
        );
    }

    #[test]
    fn filesystem_roots_replacement_missing_duplicate_overlap_refuse() {
        let (temp, binding) = fixture();
        let guard = Guard::capture(&binding).unwrap();
        fs::rename(&binding.roots[1].path, temp.path().join("old-beta")).unwrap();
        assert!(Guard::capture(&binding).is_err());
        fs::create_dir(&binding.roots[1].path).unwrap();
        assert!(Guard::capture(&binding).is_err());
        assert!(guard
            .validate_call("list_directory", &json!({"path":"/workspace/alpha"}))
            .is_err());
        let mut changed = binding.clone();
        changed.roots[1].identity = changed.roots[0].identity.clone();
        assert!(changed.validate_schema(&binding.roots[0].path).is_err());
        changed = binding.clone();
        changed.roots[1].path = changed.roots[0].path.join("nested");
        assert!(changed.validate_schema(&binding.roots[0].path).is_err());
    }

    #[test]
    fn filesystem_roots_profile_custody_and_original_schema_are_exclusive() {
        let (_temp, binding) = fixture();
        let profile = json!({"format":FORMAT,"workspace":binding.roots[0].path,
            "workspaceIdentity":binding.roots[0].identity,"filesystemRoots":binding,
            "runtimePath":"/owned/node","runtimeSha256":"0".repeat(64),
            "packageRoot":"/owned/package","packageTreeSha256":"0".repeat(64),
            "bwrapPath":"/owned/bwrap","bwrapSha256":"0".repeat(64),"libraries":[]});
        super::super::ProfileConfig::read(&serde_json::to_vec(&profile).unwrap()).unwrap();
        let mut changed = profile.clone();
        changed["format"] = json!(super::super::FORMAT);
        assert!(super::super::ProfileConfig::read(&serde_json::to_vec(&changed).unwrap()).is_err());
        changed = profile.clone();
        changed.as_object_mut().unwrap().remove("filesystemRoots");
        assert!(super::super::ProfileConfig::read(&serde_json::to_vec(&changed).unwrap()).is_err());
        let mut manifest = super::super::original_manifest();
        super::super::classify_manifest_for(FORMAT, &manifest).unwrap();
        manifest["tools"][0]["inputSchema"]["additionalProperties"] = json!(true);
        assert!(super::super::classify_manifest_for(FORMAT, &manifest).is_err());
    }
}
