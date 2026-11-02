// SPDX-License-Identifier: Apache-2.0
//! Optional file-link topology. Every executable file mount comes from the
//! retained checked descriptor; no source directory is mounted in this view.
use super::WorkspaceIdentity;
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "sw-mcp/filesystem-multi-root-file-links-readonly/1";
pub const BINDING_FORMAT: &str = "sw-pilot-filesystem-root-file-links/1";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub path: String,
    pub target: String,
    pub identity: WorkspaceIdentity,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub root: String,
    pub path: String,
    pub chain: Vec<Link>,
    pub final_path: String,
    pub final_identity: WorkspaceIdentity,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::mcp::server_profile::filesystem_roots::{
        linux::{self as base, Observer},
        Binding,
    };
    use anyhow::{ensure, Context};
    use std::{
        collections::BTreeMap,
        ffi::CString,
        fs::{self, File},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        },
        path::{Component, Path, PathBuf},
        sync::Mutex,
    };
    use tokio::process::Command;

    #[derive(Debug)]
    enum Kind {
        Directory,
        File,
        Link(String),
    }
    #[derive(Debug)]
    struct Node {
        file: File,
        kind: Kind,
    }
    fn normal(parent: &Path, target: &str) -> anyhow::Result<PathBuf> {
        ensure!(
            !target.is_empty() && !target.starts_with('/') && target.len() <= 4096,
            "filesystem_links_relative_file_link_required"
        );
        let mut result = parent.to_path_buf();
        for component in Path::new(target).components() {
            match component {
                Component::Normal(name) => result.push(name),
                Component::CurDir => {}
                Component::ParentDir => ensure!(result.pop(), "filesystem_links_root_escape"),
                _ => anyhow::bail!("filesystem_links_root_escape"),
            }
        }
        ensure!(
            !result.as_os_str().is_empty(),
            "filesystem_links_directory_link_unsupported"
        );
        Ok(result)
    }
    fn scan(
        directory: &File,
        prefix: &Path,
        nodes: &mut BTreeMap<PathBuf, Node>,
        observer: &Observer,
        mount: u64,
        counts: &mut [usize; 3],
        depth: usize,
    ) -> anyhow::Result<()> {
        counts[0] += 1;
        ensure!(
            depth <= 32 && counts[0] <= 128,
            "filesystem_links_tree_bound"
        );
        base::owned(directory)?;
        ensure!(
            base::mount_id(directory)? == mount,
            "filesystem_links_nested_mount_unsupported"
        );
        observer.watch(directory)?;
        for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
            let entry = entry?;
            ensure!(nodes.len() < 512, "filesystem_links_tree_bound");
            let name = entry.file_name();
            let path = prefix.join(&name);
            let text = path.to_str().context("filesystem_links_unsupported_name")?;
            ensure!(
                !text.chars().any(char::is_control),
                "filesystem_links_unsupported_name"
            );
            let named = fs::symlink_metadata(entry.path())?;
            let (file, kind) = if named.file_type().is_symlink() {
                counts[2] += 1;
                ensure!(counts[2] <= 128, "filesystem_links_link_bound");
                let name = CString::new(name.as_encoded_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                ensure!(fd >= 0, "filesystem_links_link_unavailable");
                let file = unsafe { File::from_raw_fd(fd) };
                let mut bytes = [0u8; 4097];
                let length = unsafe {
                    libc::readlinkat(fd, c"".as_ptr(), bytes.as_mut_ptr().cast(), bytes.len())
                };
                ensure!(length > 0 && length <= 4096, "filesystem_links_link_bound");
                let target = std::str::from_utf8(&bytes[..length as usize])?.to_owned();
                normal(prefix, &target)?;
                ensure!(
                    file.metadata()?.uid() == unsafe { libc::geteuid() }
                        && file.metadata()?.nlink() == 1,
                    "filesystem_links_unsafe_entry"
                );
                (file, Kind::Link(target))
            } else {
                let file = base::child(directory, &name, named.is_dir())?;
                base::owned(&file)?;
                if named.is_dir() {
                    (file, Kind::Directory)
                } else {
                    counts[1] += 1;
                    ensure!(counts[1] <= 256, "filesystem_links_file_bound");
                    (file, Kind::File)
                }
            };
            let actual = file.metadata()?;
            ensure!(
                named.dev() == actual.dev()
                    && named.ino() == actual.ino()
                    && base::mount_id(&file)? == mount,
                "filesystem_links_entry_changed"
            );
            let recurse = matches!(kind, Kind::Directory);
            nodes.insert(path.clone(), Node { file, kind });
            if recurse {
                let dir = nodes[&path].file.try_clone()?;
                scan(&dir, &path, nodes, observer, mount, counts, depth + 1)?;
            }
        }
        Ok(())
    }
    fn resolve<'a>(
        nodes: &'a BTreeMap<PathBuf, Node>,
        path: &Path,
    ) -> anyhow::Result<(&'a Node, PathBuf, Vec<Link>)> {
        let mut current = path.to_path_buf();
        let mut chain = Vec::new();
        loop {
            for parent in current
                .ancestors()
                .skip(1)
                .filter(|p| !p.as_os_str().is_empty())
            {
                ensure!(
                    nodes
                        .get(parent)
                        .is_some_and(|n| matches!(n.kind, Kind::Directory)),
                    "filesystem_links_directory_link_unsupported"
                );
            }
            let node = nodes
                .get(&current)
                .context("filesystem_links_missing_link_target")?;
            let Kind::Link(target) = &node.kind else {
                return Ok((node, current, chain));
            };
            let text = current
                .to_str()
                .context("filesystem_links_unsupported_name")?;
            ensure!(
                chain.len() < 8 && !chain.iter().any(|link: &Link| link.path == text),
                "filesystem_links_cycle_or_chain_bound"
            );
            chain.push(Link {
                path: text.into(),
                target: target.clone(),
                identity: WorkspaceIdentity::from_metadata(&node.file.metadata()?),
            });
            current = normal(current.parent().unwrap_or(Path::new("")), target)?;
        }
    }
    #[derive(Debug)]
    pub(crate) struct Guard {
        binding: Binding,
        roots: Vec<File>,
        nodes: Vec<BTreeMap<PathBuf, Node>>,
        observer: Mutex<Observer>,
    }
    impl Guard {
        pub(crate) fn capture(binding: &Binding) -> anyhow::Result<Self> {
            binding.validate_schema(
                &binding
                    .roots
                    .first()
                    .context("filesystem_links_count")?
                    .path,
            )?;
            ensure!(
                binding.format == BINDING_FORMAT,
                "filesystem_links_selection_required"
            );
            let mut observer = Observer::new()?;
            let (mut roots, mut trees, mut observed) = (Vec::new(), Vec::new(), Vec::new());
            let mut counts = [0; 3];
            for root in &binding.roots {
                let file = base::open(root)?;
                base::local_mount(&file)?;
                let mut nodes = BTreeMap::new();
                scan(
                    &file,
                    Path::new(""),
                    &mut nodes,
                    &observer,
                    base::mount_id(&file)?,
                    &mut counts,
                    0,
                )?;
                for (path, node) in &nodes {
                    if matches!(node.kind, Kind::Link(_)) {
                        let (final_node, final_path, chain) = resolve(&nodes, path)?;
                        ensure!(
                            matches!(final_node.kind, Kind::File),
                            "filesystem_links_directory_link_unsupported"
                        );
                        observed.push(Selection {
                            root: root.id.clone(),
                            path: path.to_str().unwrap().into(),
                            chain,
                            final_path: final_path.to_str().unwrap().into(),
                            final_identity: WorkspaceIdentity::from_metadata(
                                &final_node.file.metadata()?,
                            ),
                        });
                    }
                }
                roots.push(file);
                trees.push(nodes);
            }
            ensure!(
                binding.links.as_ref() == Some(&observed) && observer.valid(),
                "filesystem_links_selected_object_changed"
            );
            let guard = Self {
                binding: binding.clone(),
                roots,
                nodes: trees,
                observer: Mutex::new(observer),
            };
            guard.validate()?;
            Ok(guard)
        }
        fn validate(&self) -> anyhow::Result<()> {
            let mut observer = self
                .observer
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem_links_source_withdrawn"))?;
            ensure!(observer.valid(), "filesystem_links_source_withdrawn");
            for root in &self.binding.roots {
                base::open(root)?;
            }
            ensure!(observer.valid(), "filesystem_links_source_withdrawn");
            Ok(())
        }
        pub(crate) fn validate_call(
            &self,
            name: &str,
            args: &serde_json::Value,
        ) -> anyhow::Result<()> {
            self.validate()?;
            for (root, path) in self.binding.resources(name, args)? {
                let index = self
                    .binding
                    .roots
                    .iter()
                    .position(|r| r.id == root.id)
                    .context("filesystem_links_root")?;
                if !path.as_os_str().is_empty() && self.nodes[index].contains_key(&path) {
                    resolve(&self.nodes[index], &path)?;
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
            for ((root, _retained_root), nodes) in
                self.binding.roots.iter().zip(&self.roots).zip(&self.nodes)
            {
                let base = PathBuf::from(format!("/workspace/{}", root.id));
                command.arg("--dir").arg(&base);
                for (path, node) in nodes {
                    let target = base.join(path);
                    match &node.kind {
                        Kind::Directory => {
                            command.arg("--dir").arg(target);
                        }
                        Kind::Link(value) => {
                            command.arg("--symlink").arg(value).arg(target);
                        }
                        Kind::File => {
                            let pin = node.file.try_clone()?;
                            command
                                .arg("--ro-bind-fd")
                                .arg(pin.as_raw_fd().to_string())
                                .arg(target);
                            pins.push(pin);
                        }
                    }
                }
            }
            command.args(["--remount-ro", "/workspace"]);
            self.validate()
        }
    }
}
#[cfg(target_os = "linux")]
pub(crate) use linux::Guard;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::mcp::server_profile::filesystem_roots::{Binding, Root};
    use serde_json::json;
    use std::{
        fs,
        os::{fd::AsRawFd, unix::fs::symlink},
    };
    fn fixture() -> (tempfile::TempDir, Binding) {
        let temp = tempfile::tempdir().unwrap();
        let mut roots = Vec::new();
        for id in ["alpha", "beta"] {
            let path = temp.path().join(id);
            fs::create_dir(&path).unwrap();
            fs::write(path.join("note.txt"), format!("owned {id}\n")).unwrap();
            roots.push(Root {
                id: id.into(),
                identity: WorkspaceIdentity::from_metadata(&fs::metadata(&path).unwrap()),
                path,
                scope: "read-only".into(),
            });
        }
        symlink("note.txt", roots[0].path.join("link")).unwrap();
        let path = roots[0].path.join("link");
        let links = vec![Selection {
            root: "alpha".into(),
            path: "link".into(),
            chain: vec![Link {
                path: "link".into(),
                target: "note.txt".into(),
                identity: WorkspaceIdentity::from_metadata(&fs::symlink_metadata(path).unwrap()),
            }],
            final_path: "note.txt".into(),
            final_identity: WorkspaceIdentity::from_metadata(
                &fs::metadata(roots[0].path.join("note.txt")).unwrap(),
            ),
        }];
        (
            temp,
            Binding {
                format: BINDING_FORMAT.into(),
                roots,
                links: Some(links),
            },
        )
    }
    #[test]
    fn filesystem_links_pin_execution_objects_and_original_argument_arrays() {
        let (_temp, binding) = fixture();
        let guard = Guard::capture(&binding).unwrap();
        guard
            .validate_call(
                "read_multiple_files",
                &json!({"paths":["/workspace/alpha/link","/workspace/beta/note.txt"]}),
            )
            .unwrap();
        assert!(guard
            .validate_call(
                "read_multiple_files",
                &json!({"paths":["/workspace/alpha/link","/workspace/unknown/canary"]})
            )
            .is_err());
        // Deterministic check -> namespace construction -> source substitution ->
        // use: the EXACT fds supplied to bwrap still yield the checked objects.
        let mut command = tokio::process::Command::new("/owned/bwrap");
        let mut pins = Vec::new();
        guard.mount(&mut command, &mut pins).unwrap();
        let arguments: Vec<_> = command
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(arguments.iter().any(|a| a == "--symlink"));
        assert!(!arguments.iter().any(|a| a == "--bind-fd"));
        let outside = binding.roots[1].path.join("note.txt");
        fs::remove_file(binding.roots[0].path.join("link")).unwrap();
        symlink(&outside, binding.roots[0].path.join("link")).unwrap();
        fs::rename(
            binding.roots[0].path.join("note.txt"),
            binding.roots[0].path.join("old"),
        )
        .unwrap();
        fs::write(binding.roots[0].path.join("note.txt"), "replacement").unwrap();
        let mut found = false;
        for (index, arg) in arguments.iter().enumerate() {
            if arg == "--ro-bind-fd" && arguments[index + 2] == "/workspace/alpha/note.txt" {
                found = true;
                let fd: i32 = arguments[index + 1].parse().unwrap();
                let pin = pins.iter().find(|f| f.as_raw_fd() == fd).unwrap();
                assert_eq!(
                    fs::read_to_string(format!("/proc/self/fd/{}", pin.as_raw_fd())).unwrap(),
                    "owned alpha\n"
                );
            }
        }
        assert!(found, "checked file fd must supply the execution mount");
        assert!(guard
            .validate_call("read_text_file", &json!({"path":"/workspace/alpha/link"}))
            .is_err());
        assert_eq!(fs::read_to_string(outside).unwrap(), "owned beta\n");
    }
    #[test]
    fn filesystem_links_refuse_retargets_cycles_directory_links_and_profile_replay() {
        let (_temp, binding) = fixture();
        let link = binding.roots[0].path.join("link");
        for target in [
            "../beta/note.txt",
            "/workspace/beta/note.txt",
            ".",
            "link",
            "missing",
        ] {
            fs::remove_file(&link).unwrap();
            symlink(target, &link).unwrap();
            assert!(Guard::capture(&binding).is_err(), "{target}");
        }
        let mut strict = binding.clone();
        strict.format = super::super::filesystem_roots::BINDING_FORMAT.into();
        assert!(strict.validate_schema(&strict.roots[0].path).is_err());
    }
    #[test]
    fn filesystem_links_root_replacement_and_observer_withdrawal_are_sticky() {
        let (temp, binding) = fixture();
        let guard = Guard::capture(&binding).unwrap();
        fs::rename(&binding.roots[0].path, temp.path().join("retained-alpha")).unwrap();
        fs::create_dir(&binding.roots[0].path).unwrap();
        assert!(guard
            .validate_call("list_directory", &json!({"path":"/workspace/beta"}))
            .is_err());
        assert!(Guard::capture(&binding).is_err());
    }
}
