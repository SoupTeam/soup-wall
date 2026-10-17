// SPDX-License-Identifier: Apache-2.0
//! One pinned upstream Git server. Names and discovery never grant authority.
use std::collections::BTreeMap;
#[cfg(any(target_os = "linux", test))]
use std::{fs, path::Path};

use anyhow::{ensure, Context};
use serde_json::Value;

use super::ToolProfile;

pub const FORMAT: &str = "sw-mcp/git-readonly/1";
pub const PYTHON: &str = "/mcp-server/python/bin/python3.11";
const MANIFEST: &str =
    include_str!("../../../../../profiles/mcp/git-readonly-v1/upstream-tools-list.json");
const INITIALIZE: &str =
    include_str!("../../../../../profiles/mcp/git-readonly-v1/upstream-initialize.json");

pub fn original_manifest() -> Value {
    serde_json::from_str::<Value>(MANIFEST).expect("pinned Git discovery")["result"].clone()
}

pub fn validate_initialization(value: &Value) -> anyhow::Result<()> {
    let expected: Value = serde_json::from_str(INITIALIZE)?;
    ensure!(
        value == &expected["result"],
        "Git initialization differs from pin"
    );
    Ok(())
}

pub fn classify_manifest(value: &Value) -> anyhow::Result<BTreeMap<String, ToolProfile>> {
    ensure!(
        value == &original_manifest(),
        "Git discovery differs from pin"
    );
    let mut profiles = BTreeMap::new();
    for tool in value["tools"].as_array().context("Git tools absent")? {
        let name = tool["name"].as_str().context("Git tool name absent")?;
        let supported = matches!(
            name,
            "git_status"
                | "git_log"
                | "git_diff"
                | "git_diff_staged"
                | "git_diff_unstaged"
                | "git_show"
        );
        profiles.insert(
            name.to_owned(),
            ToolProfile {
                input: None,
                output: None,
                unsupported_reason: (!supported).then_some("selected_git_operation_unsupported"),
                git_tool: Some(name.to_owned()),
            },
        );
    }
    Ok(profiles)
}

pub fn validate_arguments(name: &str, value: &Value) -> anyhow::Result<()> {
    let allowed: &[&str] = match name {
        "git_status" => &["repo_path"],
        "git_log" => &["repo_path", "max_count"],
        "git_diff" => &["repo_path", "target", "context_lines"],
        "git_diff_staged" | "git_diff_unstaged" => &["repo_path", "context_lines"],
        "git_show" => &["repo_path", "revision"],
        _ => anyhow::bail!("Git operation unsupported"),
    };
    super::exact_keys(value, allowed)?;
    ensure!(
        value["repo_path"] == "/workspace",
        "Git repository must be exactly /workspace"
    );
    for (key, lower, upper) in [("max_count", 1, 20), ("context_lines", 0, 20)] {
        if let Some(bound) = value.get(key) {
            ensure!(
                bound.as_u64().is_some_and(|n| n >= lower && n <= upper),
                "invalid Git bound"
            );
        }
    }
    let reference = match name {
        "git_diff" => Some(&value["target"]),
        "git_show" => Some(&value["revision"]),
        _ => None,
    };
    if let Some(reference) = reference {
        let reference = reference.as_str().context("Git revision required")?;
        ensure!(
            reference == "HEAD"
                || (reference.len() == 40 && reference.bytes().all(|c| c.is_ascii_hexdigit())),
            "only HEAD or a full SHA-1 revision is supported"
        );
    }
    Ok(())
}

/// Refuse unsupported repository machinery without running Git or altering it.
/// All inspection is repeated at protected startup on the fd-pinned directory.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn validate_repository(root: &Path) -> anyhow::Result<()> {
    use std::io::Read;
    ensure!(
        fs::symlink_metadata(root.join(".git"))?.is_dir(),
        "Git requires a standalone non-bare repository"
    );
    ensure!(
        fs::symlink_metadata(root.join(".git/config"))?.is_file(),
        "Git config must be a regular file, not a link or special file"
    );
    for path in [
        ".gitmodules",
        ".gitattributes",
        ".git/commondir",
        ".git/gitdir",
        ".git/config.worktree",
        ".git/worktrees",
        ".git/modules",
        ".git/objects/info/alternates",
        ".git/objects/info/http-alternates",
        ".git/info/attributes",
        ".git/shallow",
    ] {
        ensure!(
            fs::symlink_metadata(root.join(path))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "unsupported Git repository indirection or attributes"
        );
    }
    let mut config = Vec::new();
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(root.join(".git/config"))?;
    ensure!(
        file.metadata()?.is_file(),
        "Git config changed to a special file"
    );
    file.take(8193).read_to_end(&mut config)?;
    ensure!(config.len() <= 8192, "Git config exceeds limit");
    let config = std::str::from_utf8(&config)?;
    let mut core = false;
    for raw in config.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            ensure!(
                line.eq_ignore_ascii_case("[core]"),
                "only the bounded core Git config is supported"
            );
            core = true;
            continue;
        }
        ensure!(core, "Git config section required");
        let (key, value) = line.split_once('=').context("invalid Git config")?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_ascii_lowercase();
        ensure!(
            match key.as_str() {
                "repositoryformatversion" => value == "0",
                "bare" => value == "false",
                "filemode" | "logallrefupdates" | "ignorecase" | "precomposeunicode" =>
                    matches!(value.as_str(), "true" | "false"),
                _ => false,
            },
            "unsupported Git configuration"
        );
    }
    fn walk(path: &Path, depth: usize, count: &mut usize) -> anyhow::Result<()> {
        ensure!(depth <= 32, "Git repository depth limit");
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            *count += 1;
            ensure!(*count <= 32768, "Git repository entry limit");
            ensure!(
                entry.file_name() != ".gitattributes" && entry.file_name() != ".gitmodules",
                "nested Git attributes and submodule declarations are unsupported"
            );
            let meta = fs::symlink_metadata(entry.path())?;
            ensure!(
                !meta.is_symlink() && (meta.is_file() || meta.is_dir()),
                "Git repository links and special files are unsupported"
            );
            if meta.is_dir() {
                walk(&entry.path(), depth + 1, count)?;
            }
        }
        Ok(())
    }
    walk(root, 0, &mut 0)?;
    if root.join(".git/hooks").exists() {
        for hook in fs::read_dir(root.join(".git/hooks"))? {
            ensure!(
                hook?
                    .file_name()
                    .to_str()
                    .is_some_and(|s| s.ends_with(".sample")),
                "active Git hooks are unsupported"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn git_keeps_upstream_tools_but_bounds_repository_and_arguments() {
        let tools = classify_manifest(&original_manifest()).unwrap();
        assert_eq!(tools.len(), 12);
        assert_eq!(
            tools
                .values()
                .filter(|p| p.unsupported_reason.is_none())
                .count(),
            6
        );
        for name in [
            "git_commit",
            "git_add",
            "git_reset",
            "git_checkout",
            "git_create_branch",
            "git_branch",
        ] {
            assert!(tools[name]
                .validate_arguments(&json!({"repo_path":"/workspace"}))
                .is_err());
        }
        assert!(tools["git_log"]
            .validate_arguments(&json!({"repo_path":"/workspace","max_count":3}))
            .is_ok());
        for value in [
            json!({"repo_path":"/etc"}),
            json!({"repo_path":"/workspace","max_count":true}),
            json!({"repo_path":"/workspace","max_count":21}),
            json!({"repo_path":"/workspace","start_timestamp":"yesterday"}),
        ] {
            assert!(tools["git_log"].validate_arguments(&value).is_err());
        }
        for target in [
            "--output=/workspace/stolen",
            "HEAD:../outside",
            "main",
            "HEAD~1",
            "",
        ] {
            assert!(tools["git_diff"]
                .validate_arguments(&json!({"repo_path":"/workspace","target":target}))
                .is_err());
        }
        assert!(tools["git_diff"]
            .validate_arguments(
                &json!({"repo_path":"/workspace","target":"HEAD","context_lines":0})
            )
            .is_ok());
        assert!(tools["git_status"]
            .validate_result(
                &json!({"result":{"content":[{"type":"text","text":"clean"}],"isError":false}})
            )
            .is_ok());
        assert!(tools["git_status"]
            .validate_result(
                &json!({"result":{"content":[],"structuredContent":{"hidden":"data"}}})
            )
            .is_err());
    }

    #[test]
    fn git_profile_requires_both_executable_and_landlock_launcher_pins() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let value = json!({"format":FORMAT,"workspace":root,"runtimePath":root.join("python"),
            "runtimeSha256":"a".repeat(64),"packageRoot":root.join("package"),
            "packageTreeSha256":"b".repeat(64),"bwrapPath":root.join("bwrap"),
            "bwrapSha256":"c".repeat(64),"libraries":[],
            "git":{"path":root.join("git"),"sha256":"d".repeat(64)},
            "gitLauncher":{"path":root.join("launcher"),"sha256":"e".repeat(64)}});
        assert!(super::super::ProfileConfig::read(value.to_string().as_bytes()).is_ok());
        for field in ["git", "gitLauncher"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(super::super::ProfileConfig::read(missing.to_string().as_bytes()).is_err());
        }
        let mut other = value;
        other["format"] = json!(super::super::FORMAT);
        assert!(super::super::ProfileConfig::read(other.to_string().as_bytes()).is_err());
    }

    #[test]
    fn repository_config_indirection_and_active_hooks_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join(".git/hooks")).unwrap();
        fs::write(
            root.join(".git/config"),
            "[core]\nbare = false\nrepositoryformatversion = 0\n",
        )
        .unwrap();
        assert!(validate_repository(root).is_ok());
        fs::write(root.join(".git/hooks/pre-commit"), "payload").unwrap();
        assert!(validate_repository(root).is_err());
        fs::remove_file(root.join(".git/hooks/pre-commit")).unwrap();
        fs::write(
            root.join(".git/config"),
            "[core]\nfsmonitor = /outside/helper\n",
        )
        .unwrap();
        assert!(validate_repository(root).is_err());
    }

    #[test]
    fn repository_rejects_alternates_worktrees_attributes_and_includes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join(".git/objects/info")).unwrap();
        let config = "[core]\nbare = false\nrepositoryformatversion = 0\n";
        fs::write(root.join(".git/config"), config).unwrap();
        for relative in [
            ".git/commondir",
            ".git/gitdir",
            ".git/config.worktree",
            ".git/objects/info/alternates",
            ".git/objects/info/http-alternates",
            ".gitmodules",
            ".gitattributes",
        ] {
            fs::write(root.join(relative), "/outside/unsupported").unwrap();
            assert!(validate_repository(root).is_err(), "{relative}");
            fs::remove_file(root.join(relative)).unwrap();
        }
        for section in [
            "include",
            "includeIf \"gitdir:/workspace\"",
            "remote \"origin\"",
            "diff",
            "filter \"custom\"",
            "credential",
        ] {
            fs::write(
                root.join(".git/config"),
                format!("{config}[{section}]\nhelper = forbidden\n"),
            )
            .unwrap();
            assert!(validate_repository(root).is_err(), "{section}");
        }
        fs::write(root.join(".git/config"), config).unwrap();
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested/.gitattributes"), "* filter=custom").unwrap();
        assert!(validate_repository(root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn repository_refuses_config_symlink_before_opening_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        fs::create_dir_all(root.join(".git")).unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, "[core]\nbare = false\n").unwrap();
        std::os::unix::fs::symlink(&outside, root.join(".git/config")).unwrap();
        assert!(validate_repository(&root)
            .unwrap_err()
            .to_string()
            .contains("regular file"));
        assert_eq!(
            fs::read_to_string(outside).unwrap(),
            "[core]\nbare = false\n"
        );
    }
}
