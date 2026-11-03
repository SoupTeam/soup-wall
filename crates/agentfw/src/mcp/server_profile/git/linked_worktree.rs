// SPDX-License-Identifier: Apache-2.0
//! Explicit operator-selected roots. Repository strings never choose authority.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const FORMAT: &str = "sw-mcp/git-linked-worktree-readonly/1";
pub const BINDING_FORMAT: &str = "sw-pilot-linked-worktree/1";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Root {
    pub path: PathBuf,
    pub identity: super::super::WorkspaceIdentity,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub format: String,
    pub workspace: Root,
    pub git_dir: Root,
    pub common_dir: Root,
    pub inputs_sha256: String,
}

impl Binding {
    pub fn validate_schema(&self, workspace: &std::path::Path) -> anyhow::Result<()> {
        use anyhow::ensure;
        ensure!(
            self.format == BINDING_FORMAT && crate::native::is_digest(&self.inputs_sha256),
            "linked_worktree_binding_schema"
        );
        for root in [&self.workspace, &self.git_dir, &self.common_dir] {
            ensure!(
                super::super::normal_absolute(&root.path) && root.path != std::path::Path::new("/"),
                "linked_worktree_canonical_root_required"
            );
        }
        ensure!(
            self.workspace.path == workspace
                && !workspace.starts_with(&self.common_dir.path)
                && !self.common_dir.path.starts_with(workspace),
            "linked_worktree_overlapping_roots"
        );
        let admin = &self.git_dir.path;
        let name = admin.file_name().and_then(|s| s.to_str()).unwrap_or("");
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                && admin
                    .parent()
                    .and_then(|p| p.file_name())
                    .is_some_and(|p| p == "worktrees")
                && admin.parent().and_then(|p| p.parent()) == Some(self.common_dir.path.as_path()),
            "linked_worktree_ordinary_layout_required"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::super::super::git_local_clone::{directory_path, open};
    use super::*;
    use anyhow::{ensure, Context};
    use std::{
        ffi::CString,
        fs::{self, File},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        },
        path::{Component, Path},
    };

    pub(crate) fn open_root(root: &Root) -> anyhow::Result<File> {
        let mut directory = File::open("/")?;
        for part in root.path.components() {
            match part {
                Component::RootDir => continue,
                Component::Normal(name) => {
                    use std::os::unix::ffi::OsStrExt;
                    let name = CString::new(name.as_bytes())?;
                    let fd = unsafe {
                        libc::openat(
                            directory.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    ensure!(fd >= 0, "linked_worktree_root_unavailable");
                    directory = unsafe { File::from_raw_fd(fd) };
                }
                _ => anyhow::bail!("linked_worktree_canonical_root_required"),
            }
        }
        let m = directory.metadata()?;
        ensure!(
            m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o022 == 0
                && super::super::super::WorkspaceIdentity::from_metadata(&m) == root.identity,
            "linked_worktree_root_changed"
        );
        Ok(directory)
    }

    /// Every working-tree entry is checked by descriptor. Only the root .git
    /// file is special; nesting, links, attributes and submodules remain refused.
    fn tree(
        pin: File,
        depth: usize,
        count: &mut usize,
        watches: &mut Vec<File>,
    ) -> anyhow::Result<()> {
        ensure!(
            depth <= 32 && watches.len() < 128,
            "linked_worktree_tree_bound"
        );
        let before = pin.metadata()?;
        let path = directory_path(&pin, Path::new("/"));
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            *count += 1;
            ensure!(*count <= 32768, "linked_worktree_tree_bound");
            let name = entry.file_name();
            let m = fs::symlink_metadata(entry.path())?;
            ensure!(
                m.uid() == unsafe { libc::geteuid() }
                    && m.mode() & 0o022 == 0
                    && !m.is_symlink()
                    && (m.is_dir() || m.is_file()),
                "linked_worktree_unsafe_entry"
            );
            ensure!(
                name != ".gitattributes"
                    && name != ".gitmodules"
                    && (name != ".git" || depth == 0 && m.is_file()),
                "linked_worktree_nested_metadata_unsupported"
            );
            if m.is_dir() {
                tree(open(&entry.path(), true)?, depth + 1, count, watches)?;
            }
        }
        ensure!(
            super::super::super::git_local_clone::same(&before, &pin.metadata()?),
            "linked_worktree_source_changed"
        );
        watches.push(pin);
        Ok(())
    }

    impl Binding {
        pub(crate) fn roots(&self, workspace: &File) -> anyhow::Result<(File, File, Vec<File>)> {
            self.validate_schema(&self.workspace.path)?;
            let actual = workspace.metadata()?;
            ensure!(
                super::super::super::WorkspaceIdentity::from_metadata(&actual)
                    == self.workspace.identity,
                "linked_worktree_workspace_changed"
            );
            let selected = open_root(&self.workspace)?;
            let admin = open_root(&self.git_dir)?;
            let common = open_root(&self.common_dir)?;
            let mut watches = Vec::new();
            tree(selected, 0, &mut 0, &mut watches)?;
            let base = directory_path(&common, Path::new("/"));
            for name in ["shallow", "config.worktree", "modules"] {
                ensure!(
                    fs::symlink_metadata(base.join(name))
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                    "linked_worktree_metadata_unsupported"
                );
            }
            let admin_path = directory_path(&admin, Path::new("/"));
            let admin_names = fs::read_dir(&admin_path)?
                .map(|e| e.map(|e| e.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            ensure!(
                admin_names.len() <= 16
                    && admin_names.iter().all(|n| n.to_str().is_some_and(|v| [
                        "HEAD",
                        "index",
                        "gitdir",
                        "commondir",
                        "logs",
                        "refs",
                        "ORIG_HEAD",
                        "COMMIT_EDITMSG"
                    ]
                    .contains(&v))),
                "linked_worktree_admin_metadata_unsupported"
            );
            if admin_names.iter().any(|n| n == "COMMIT_EDITMSG") {
                // Ordinary commits create this inert per-worktree file. It is
                // neither copied nor interpreted and cannot add authority.
                let message = open(&admin_path.join("COMMIT_EDITMSG"), false)?;
                let m = message.metadata()?;
                ensure!(
                    m.uid() == unsafe { libc::geteuid() }
                        && m.mode() & 0o022 == 0
                        && m.nlink() == 1
                        && m.len() <= 65536,
                    "linked_worktree_inert_commit_message_unsafe"
                );
            }
            if admin_names.iter().any(|n| n == "refs") {
                let refs = open(&admin_path.join("refs"), true)?;
                let m = refs.metadata()?;
                ensure!(
                    m.uid() == unsafe { libc::geteuid() }
                        && m.mode() & 0o022 == 0
                        && fs::read_dir(directory_path(&refs, Path::new("/")))?
                            .next()
                            .is_none(),
                    "linked_worktree_private_refs_unsupported"
                );
                watches.push(refs);
            }
            if let Ok(hooks) = open(&base.join("hooks"), true) {
                let mut count = 0;
                for entry in fs::read_dir(directory_path(&hooks, Path::new("/")))? {
                    let entry = entry?;
                    count += 1;
                    ensure!(
                        count <= 64
                            && entry
                                .file_name()
                                .to_str()
                                .is_some_and(|s| s.ends_with(".sample"))
                            && fs::symlink_metadata(entry.path())?.is_file(),
                        "linked_worktree_hooks_unsupported"
                    );
                }
                watches.push(hooks);
            } else {
                ensure!(
                    fs::symlink_metadata(base.join("hooks"))
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                    "linked_worktree_hooks_unsupported"
                );
            }
            Ok((admin, common, watches))
        }

        pub(crate) fn revalidate_roots(&self) -> anyhow::Result<()> {
            for root in [&self.workspace, &self.git_dir, &self.common_dir] {
                open_root(root)?;
            }
            Ok(())
        }

        pub(crate) fn mount_workspace(
            &self,
            command: &mut tokio::process::Command,
            pins: &mut Vec<File>,
        ) -> anyhow::Result<()> {
            self.revalidate_roots()?;
            let workspace = open_root(&self.workspace)?;
            command.args(["--size", "67108864", "--tmpfs", "/workspace"]);
            let mut count = 0;
            for entry in fs::read_dir(directory_path(&workspace, Path::new("/")))? {
                let entry = entry?;
                if entry.file_name() == ".git" {
                    continue;
                }
                count += 1;
                ensure!(count <= 1024, "linked_worktree_mount_bound");
                let m = fs::symlink_metadata(entry.path())?;
                ensure!(
                    m.uid() == unsafe { libc::geteuid() }
                        && m.mode() & 0o022 == 0
                        && !m.is_symlink()
                        && (m.is_file() || m.is_dir()),
                    "linked_worktree_unsafe_entry"
                );
                let pin = open(&entry.path(), m.is_dir())?;
                command
                    .arg("--ro-bind-fd")
                    .arg(pin.as_raw_fd().to_string())
                    .arg(Path::new("/workspace").join(entry.file_name()));
                pins.push(pin);
            }
            Ok(())
        }

        pub(crate) fn controls(
            &self,
            workspace: &File,
            admin: &File,
        ) -> anyhow::Result<Vec<(String, File, Vec<u8>)>> {
            let w = directory_path(workspace, Path::new("/"));
            let g = directory_path(admin, Path::new("/"));
            Ok(vec![
                (
                    ".control/gitfile".into(),
                    open(&w.join(".git"), false)?,
                    format!(
                        "gitdir: {}\n",
                        self.git_dir
                            .path
                            .to_str()
                            .context("linked_worktree_path_encoding")?
                    )
                    .into_bytes(),
                ),
                (
                    ".control/gitdir".into(),
                    open(&g.join("gitdir"), false)?,
                    format!(
                        "{}\n",
                        self.workspace
                            .path
                            .join(".git")
                            .to_str()
                            .context("linked_worktree_path_encoding")?
                    )
                    .into_bytes(),
                ),
                (
                    ".control/commondir".into(),
                    open(&g.join("commondir"), false)?,
                    b"../..\n".to_vec(),
                ),
            ])
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::{
        fs::{self, File},
        process::Command,
    };

    fn git(words: &[&std::ffi::OsStr]) {
        let output = Command::new("git")
            .args(words)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(output.status.success(), "owned fixture Git failed");
    }

    fn fixture() -> (tempfile::TempDir, Binding) {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("common");
        let workspace = temp.path().join("one");
        git(&[
            "init".as_ref(),
            "-q".as_ref(),
            "-b".as_ref(),
            "main".as_ref(),
            repo.as_os_str(),
        ]);
        fs::write(repo.join("note"), "Owned linked history.\n").unwrap();
        git(&[
            "-C".as_ref(),
            repo.as_os_str(),
            "add".as_ref(),
            "note".as_ref(),
        ]);
        git(&[
            "-C".as_ref(),
            repo.as_os_str(),
            "-c".as_ref(),
            "user.name=Owned".as_ref(),
            "-c".as_ref(),
            "user.email=owned@example.invalid".as_ref(),
            "commit".as_ref(),
            "-qm".as_ref(),
            "Owned linked history".as_ref(),
        ]);
        git(&[
            "-C".as_ref(),
            repo.as_os_str(),
            "worktree".as_ref(),
            "add".as_ref(),
            "-q".as_ref(),
            "-b".as_ref(),
            "one".as_ref(),
            workspace.as_os_str(),
        ]);
        // This real worktree commit creates COMMIT_EDITMSG, unlike merely
        // adding a linked worktree at an existing commit.
        git(&[
            "-C".as_ref(),
            workspace.as_os_str(),
            "-c".as_ref(),
            "user.name=Owned".as_ref(),
            "-c".as_ref(),
            "user.email=owned@example.invalid".as_ref(),
            "commit".as_ref(),
            "--allow-empty".as_ref(),
            "-qm".as_ref(),
            "Owned linked history".as_ref(),
        ]);
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/pilot_linked_worktree.py");
        let output = Command::new("python3")
            .arg("-I")
            .arg("-B")
            .arg(script)
            .arg("--workspace")
            .arg(&workspace)
            .arg("--git-dir")
            .arg(repo.join(".git/worktrees/one"))
            .arg("--common-dir")
            .arg(repo.join(".git"))
            .output()
            .unwrap();
        assert!(output.status.success(), "owned binding fixture failed");
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        let binding: Binding = serde_json::from_value(result["binding"].clone()).unwrap();
        (temp, binding)
    }

    #[test]
    fn native_snapshot_agrees_with_explicit_python_selection_and_freezes_only_metadata() {
        let (_temp, binding) = fixture();
        let root = File::open(&binding.workspace.path).unwrap();
        let view = super::super::shallow_view::View::capture_linked(&root, &binding).unwrap();
        for (tool, args) in [
            ("git_status", json!({"repo_path":"/workspace"})),
            ("git_log", json!({"repo_path":"/workspace","max_count":2})),
            (
                "git_show",
                json!({"repo_path":"/workspace","revision":"HEAD"}),
            ),
        ] {
            view.validate_call(tool, &args).unwrap();
        }
        let images = view.object_witness_images().unwrap();
        assert!(images.contains_key(".git/HEAD") && images.contains_key(".git/index"));
        assert!(
            !images.contains_key(".git/commondir")
                && !images.contains_key(".git/gitdir")
                && !images.contains_key(".git/COMMIT_EDITMSG")
        );
        assert!(!images
            .keys()
            .any(|p| p.starts_with(".git/worktrees/") || p.starts_with(".git/hooks/")));
    }

    #[test]
    fn changed_selection_and_external_root_identity_refuse_before_execution() {
        let (temp, mut binding) = fixture();
        let root = File::open(&binding.workspace.path).unwrap();
        binding.inputs_sha256 = "0".repeat(64);
        assert!(super::super::shallow_view::View::capture_linked(&root, &binding).is_err());
        let retained = temp.path().join("retained-admin");
        fs::rename(&binding.git_dir.path, &retained).unwrap();
        fs::create_dir(&binding.git_dir.path).unwrap();
        assert!(binding.revalidate_roots().is_err());
    }

    #[test]
    fn no_redirected_common_root_or_active_repository_machinery_is_adopted() {
        let (_temp, binding) = fixture();
        let root = File::open(&binding.workspace.path).unwrap();
        fs::write(binding.git_dir.path.join("commondir"), "/never-adopt\n").unwrap();
        assert!(super::super::shallow_view::View::capture_linked(&root, &binding).is_err());
        fs::write(binding.git_dir.path.join("commondir"), "../..\n").unwrap();
        fs::write(
            binding.common_dir.path.join("hooks/pre-commit"),
            "never execute",
        )
        .unwrap();
        assert!(super::super::shallow_view::View::capture_linked(&root, &binding).is_err());
    }

    #[test]
    fn selected_view_withdraws_permanently_after_branch_or_index_write() {
        let (_temp, binding) = fixture();
        let root = File::open(&binding.workspace.path).unwrap();
        let view = super::super::shallow_view::View::capture_linked(&root, &binding).unwrap();
        let index = binding.git_dir.path.join("index");
        let raw = fs::read(&index).unwrap();
        fs::write(&index, &raw).unwrap();
        assert!(view
            .validate_call("git_status", &json!({"repo_path":"/workspace"}))
            .is_err());
        assert!(view
            .validate_call("git_status", &json!({"repo_path":"/workspace"}))
            .is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod schema_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn linked_worktree_profile_requires_exclusive_exact_root_binding() {
        let identity = json!({"device":1,"inode":2,"uid":3});
        let mut profile = json!({"format":FORMAT,"workspace":"/owned/worktree","workspaceIdentity":identity,
            "linkedWorktree":{"format":BINDING_FORMAT,
                "workspace":{"path":"/owned/worktree","identity":identity},
                "gitDir":{"path":"/owned/repo/.git/worktrees/one","identity":identity},
                "commonDir":{"path":"/owned/repo/.git","identity":identity},"inputsSha256":"a".repeat(64)},
            "runtimePath":"/owned/python","runtimeSha256":"b".repeat(64),
            "packageRoot":"/owned/package","packageTreeSha256":"c".repeat(64),
            "bwrapPath":"/owned/bwrap","bwrapSha256":"d".repeat(64),"libraries":[],
            "git":{"path":"/owned/git","sha256":"e".repeat(64)},
            "gitLauncher":{"path":"/owned/launcher","sha256":"f".repeat(64)}});
        let read = |value: &serde_json::Value| {
            super::super::super::ProfileConfig::read(&serde_json::to_vec(value).unwrap())
        };
        assert!(read(&profile).is_ok());
        profile["format"] = json!(super::super::FORMAT);
        assert!(read(&profile).is_err());
        profile["format"] = json!(FORMAT);
        profile["linkedWorktree"]["workspace"]["path"] = json!("/owned/sibling");
        assert!(read(&profile).is_err());
        profile["linkedWorktree"]["workspace"]["path"] = json!("/owned/worktree");
        profile["linkedWorktree"]["grant"] = json!("never-authority");
        assert!(read(&profile).is_err());
    }
}

/// Actual namespace/original-server compatibility control. This deliberately
/// proves no daemon admission or protection; installed host qualification below
/// must still traverse the existing independent call/result boundaries.
#[cfg(all(test, target_os = "linux"))]
mod original_mcp_probe {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

    async fn frame(
        reader: &mut BufReader<tokio::process::ChildStdout>,
    ) -> anyhow::Result<serde_json::Value> {
        let mut bytes = Vec::new();
        for _ in 0..=super::super::super::MAX_FRAME_BYTES {
            let byte = reader.read_u8().await?;
            bytes.push(byte);
            if byte == b'\n' {
                return Ok(serde_json::from_slice(&bytes)?);
            }
        }
        anyhow::bail!("linked_worktree_probe_frame_bound")
    }

    #[tokio::test]
    #[ignore = "requires owned installed profile, exact candidate owner and native bubblewrap"]
    async fn linked_worktree_original_mcp_initializes_inside_native_namespace() {
        let path =
            std::env::var_os("SOU201_TEST_PROFILE").expect("explicit owned profile required");
        let profile =
            super::super::super::ProfileConfig::read(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(profile.format, FORMAT);
        let prepared = crate::mcp::server_sandbox::prepare_explicit(&profile, None).unwrap();
        let _source = prepared.git_view();
        let (mut child, mut budget, mut owner, _) = prepared.spawn().await.unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let errors = child.stderr.take().unwrap();
        let stderr = tokio::spawn(async move {
            let mut bytes = Vec::new();
            errors
                .take(8193)
                .read_to_end(&mut bytes)
                .await
                .map(|_| bytes)
        });
        let protocol = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            input.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"owned-sou201-probe\",\"version\":\"1\"}}}\n").await?;
            let initialized=frame(&mut output).await?;
            anyhow::ensure!(initialized["id"]==1 && initialized.get("result").is_some(),"linked_worktree_probe_initialize");
            input.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n").await?;
            let tools=frame(&mut output).await?;
            anyhow::ensure!(tools["id"]==2 && tools["result"]["tools"].as_array().is_some_and(|tools|tools.iter().any(|t|t["name"]=="git_status")),"linked_worktree_probe_discovery");
            Ok::<(), anyhow::Error>(())
        }).await;
        drop(input);
        let quiesced = owner.quiesce().await;
        let budget_cleanup = if let Some(budget) = budget.as_mut() {
            budget.finish().await
        } else {
            Ok(())
        };
        let cleanup = owner.finish().await;
        let waited = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait()).await;
        let bytes = tokio::time::timeout(std::time::Duration::from_secs(5), stderr)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut diagnostic = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]).into_owned();
        for path in [
            &profile.workspace,
            &profile.package_root,
            &profile.runtime_path,
            &profile.bwrap_path,
        ] {
            if let Some(path) = path.to_str() {
                diagnostic = diagnostic.replace(path, "<owned-selected-input>");
            }
        }
        if let Some(binding) = &profile.linked_worktree {
            for path in [&binding.git_dir.path, &binding.common_dir.path] {
                if let Some(path) = path.to_str() {
                    diagnostic = diagnostic.replace(path, "<owned-selected-metadata>");
                }
            }
        }
        println!(
            "{}",
            serde_json::json!({"event":"sou201_original_mcp_namespace_probe",
            "initialized":matches!(&protocol,Ok(Ok(()))),"cleanup":quiesced.is_ok()&&cleanup.is_ok()&&waited.is_ok(),
            "owned_synthetic_stderr":diagnostic,"stderr_truncated":bytes.len()>4096})
        );
        quiesced.unwrap();
        budget_cleanup.unwrap();
        cleanup.unwrap();
        waited.unwrap().unwrap();
        protocol
            .expect("owned original MCP startup timed out")
            .expect("owned original MCP startup failed");
    }
}
