// SPDX-License-Identifier: Apache-2.0
//! Operator-selected, immutable compatibility profile for one upstream server.
//! Discovery is untrusted evidence. These checks never grant native authority.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{ensure, Context};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::input::InputSchema;

pub mod git;
pub mod git_local_clone;
#[cfg(test)]
mod git_local_clone_tests;

pub fn git_selected(format: &str) -> bool {
    matches!(format, git::FORMAT | git_local_clone::FORMAT)
}

pub fn selected(format: Option<&str>) -> bool {
    matches!(format, Some(FORMAT | git::FORMAT | git_local_clone::FORMAT))
}

pub const FORMAT: &str = "sw-mcp/filesystem-readonly/1";
pub const ENVIRONMENT: &str = "AGENTFW_MCP_SERVER_PROFILE";
pub const PACKAGE: &str = "@modelcontextprotocol/server-filesystem";
pub const PACKAGE_VERSION: &str = "2026.8.31";
pub const SDK_VERSION: &str = "1.32.1";
pub const PROTOCOL_VERSION: &str = "2025-11-25";
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
    "2024-10-07",
];
pub const SERVER_ENTRYPOINT: &str =
    "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js";
pub const MAX_PAGES: usize = 4;
pub const MAX_TOOLS: usize = 64;
pub const MAX_FRAME_BYTES: usize = 262_144;
pub const MAX_DISCOVERY_BYTES: usize = 262_144;
pub const MAX_PROFILE_BYTES: usize = 65_536;
const MAX_TREE_FILES: usize = 32_768;
const MAX_TREE_BYTES: u64 = 512 * 1024 * 1024;

const ORIGINAL_MANIFEST: &str =
    include_str!("../../../../profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json");
const ORIGINAL_INITIALIZATION: &str =
    include_str!("../../../../profiles/mcp/filesystem-readonly-v1/upstream-initialize.json");

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Library {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileConfig {
    pub format: String,
    pub workspace: PathBuf,
    pub runtime_path: PathBuf,
    pub runtime_sha256: String,
    pub package_root: PathBuf,
    pub package_tree_sha256: String,
    pub bwrap_path: PathBuf,
    pub bwrap_sha256: String,
    pub libraries: Vec<Library>,
    #[serde(default)]
    pub git: Option<Library>,
    #[serde(default)]
    pub git_launcher: Option<Library>,
}

impl ProfileConfig {
    pub fn load_from_env() -> anyhow::Result<Option<Self>> {
        std::env::var_os(ENVIRONMENT)
            .map(|path| {
                let mut bytes = Vec::new();
                fs::File::open(path)?
                    .take(MAX_PROFILE_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)?;
                Self::read(&bytes)
            })
            .transpose()
    }

    pub fn read(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            bytes.len() <= MAX_PROFILE_BYTES,
            "MCP server profile exceeds limit"
        );
        let super::admission::Strict(value) = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid MCP server profile JSON"))?;
        let config: Self = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("invalid MCP server profile fields"))?;
        ensure!(
            selected(Some(&config.format)),
            "unsupported MCP server profile"
        );
        ensure!(
            git_selected(&config.format) == config.git.is_some()
                && git_selected(&config.format) == config.git_launcher.is_some(),
            "Git runtime/profile mismatch"
        );
        for git in [&config.git, &config.git_launcher].into_iter().flatten() {
            ensure!(
                normal_absolute(&git.path) && crate::native::is_digest(&git.sha256),
                "invalid Git executable pin"
            );
        }
        ensure!(config.libraries.len() <= 32, "MCP runtime library limit");
        for path in [
            &config.workspace,
            &config.runtime_path,
            &config.package_root,
            &config.bwrap_path,
        ]
        .into_iter()
        .chain(config.libraries.iter().map(|l| &l.path))
        {
            ensure!(
                normal_absolute(path),
                "MCP profile path must be normalized and absolute"
            );
        }
        for digest in [
            &config.runtime_sha256,
            &config.package_tree_sha256,
            &config.bwrap_sha256,
        ]
        .into_iter()
        .chain(config.libraries.iter().map(|l| &l.sha256))
        {
            ensure!(
                crate::native::is_digest(digest),
                "invalid MCP profile SHA-256"
            );
        }
        let mut unique = std::collections::BTreeSet::new();
        for library in &config.libraries {
            ensure!(
                unique.insert(&library.path),
                "duplicate MCP runtime library"
            );
        }
        Ok(config)
    }

    /// The selected profile must describe the actual explicitly requested server.
    /// This never silently substitutes a different command or allowed directory.
    pub fn validate_command(
        &self,
        command: &str,
        args: &[String],
        workspace: &Path,
    ) -> anyhow::Result<()> {
        ensure!(
            Path::new(command) == self.runtime_path,
            "MCP command differs from selected runtime"
        );
        if git_selected(&self.format) {
            ensure!(
                args == [
                    "-I",
                    "-B",
                    "-m",
                    "mcp_server_git",
                    "--repository",
                    "/workspace"
                ],
                "MCP arguments differ from selected Git server"
            );
            ensure!(
                workspace == self.workspace,
                "Git workspace differs from selected profile"
            );
            return Ok(());
        }
        let entry = self.package_root.join(SERVER_ENTRYPOINT);
        ensure!(
            args.len() == 2
                && Path::new(&args[0]) == entry
                && Path::new(&args[1]) == Path::new("/workspace"),
            "MCP arguments differ from selected server"
        );
        ensure!(
            workspace == self.workspace,
            "MCP workspace differs from selected profile"
        );
        Ok(())
    }
}

fn normal_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|s| s.len() <= 4096 && !s.chars().any(char::is_control))
        && path.components().all(|c| {
            matches!(
                c,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

pub fn original_manifest() -> Value {
    serde_json::from_str::<Value>(ORIGINAL_MANIFEST).expect("shipped upstream manifest")["result"]
        .clone()
}

pub fn original_manifest_for(format: &str) -> anyhow::Result<Value> {
    match format {
        FORMAT => Ok(original_manifest()),
        git::FORMAT | git_local_clone::FORMAT => Ok(git::original_manifest()),
        _ => anyhow::bail!("unsupported MCP profile"),
    }
}

pub fn validate_initialization_for(format: &str, value: &Value) -> anyhow::Result<()> {
    match format {
        FORMAT => validate_initialization(value),
        git::FORMAT | git_local_clone::FORMAT => git::validate_initialization(value),
        _ => anyhow::bail!("unsupported MCP profile"),
    }
}

pub fn classify_manifest_for(
    format: &str,
    value: &Value,
) -> anyhow::Result<BTreeMap<String, ToolProfile>> {
    match format {
        FORMAT => classify_manifest(value),
        git::FORMAT | git_local_clone::FORMAT => git::classify_manifest(value),
        _ => anyhow::bail!("unsupported MCP profile"),
    }
}

pub fn validate_initialization(value: &Value) -> anyhow::Result<()> {
    let original: Value = serde_json::from_str(ORIGINAL_INITIALIZATION)?;
    ensure!(
        SUPPORTED_PROTOCOL_VERSIONS.contains(&value["protocolVersion"].as_str().unwrap_or("")),
        "unsupported selected MCP protocol version"
    );
    let mut expected = original["result"].clone();
    expected["protocolVersion"] = value["protocolVersion"].clone();
    ensure!(
        value == &expected,
        "MCP initialization differs from selected upstream pin"
    );
    Ok(())
}

#[derive(Debug)]
pub struct ToolProfile {
    pub input: Option<InputSchema>,
    pub output: Option<InputSchema>,
    pub unsupported_reason: Option<&'static str>,
    git_tool: Option<String>,
}

impl ToolProfile {
    pub fn validate_arguments(&self, value: &Value) -> anyhow::Result<()> {
        ensure!(
            self.unsupported_reason.is_none(),
            "MCP tool is unsupported by selected profile"
        );
        if let Some(name) = &self.git_tool {
            return git::validate_arguments(name, value);
        }
        self.input
            .as_ref()
            .context("MCP input schema unavailable")?
            .validate(value)?;
        if let Some(map) = value.as_object() {
            for key in ["head", "tail"] {
                if let Some(lines) = map.get(key) {
                    ensure!(
                        lines.as_u64().is_some_and(|n| n > 0 && n <= 65_536),
                        "unsupported MCP line bound"
                    );
                }
            }
            ensure!(
                !(map.contains_key("head") && map.contains_key("tail")),
                "ambiguous MCP head and tail"
            );
            for key in ["path", "paths"] {
                if let Some(v) = map.get(key) {
                    if let Some(paths) = v.as_array() {
                        for path in paths {
                            validate_workspace_path(path)?;
                        }
                    } else {
                        validate_workspace_path(v)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate both original result channels before either reaches inspection.
    /// The transport forwards the original frame only after native release.
    pub fn validate_result(&self, frame: &Value) -> anyhow::Result<&'static str> {
        ensure!(
            self.unsupported_reason.is_none(),
            "MCP tool is unsupported by selected profile"
        );
        if let Some(error) = frame.get("error") {
            ensure!(
                frame.get("result").is_none(),
                "ambiguous MCP result and error"
            );
            exact_keys(error, &["code", "message"])?;
            ensure!(
                error["code"].as_i64().is_some()
                    && error["message"]
                        .as_str()
                        .is_some_and(|s| s.len() <= MAX_FRAME_BYTES),
                "invalid MCP server error"
            );
            return Ok("error");
        }
        let result = frame.get("result").context("MCP result missing")?;
        exact_keys(result, &["content", "structuredContent", "isError"])?;
        ensure!(
            result.get("isError").is_none_or(Value::is_boolean),
            "invalid MCP isError"
        );
        let blocks = result["content"]
            .as_array()
            .context("MCP content missing")?;
        ensure!(blocks.len() <= 256, "MCP content count limit");
        for block in blocks {
            exact_keys(block, &["type", "text"])?;
            ensure!(
                block["type"] == "text"
                    && block["text"]
                        .as_str()
                        .is_some_and(|s| s.len() <= MAX_FRAME_BYTES),
                "unsupported MCP content"
            );
        }
        if let Some(structured) = result.get("structuredContent") {
            self.output
                .as_ref()
                .context("MCP output schema unavailable")?
                .validate(structured)?;
        } else if self.git_tool.is_none() {
            ensure!(result["isError"] == true, "MCP structured output missing");
        }
        Ok(if result["isError"] == true {
            "error"
        } else {
            "value"
        })
    }
}

fn validate_workspace_path(value: &Value) -> anyhow::Result<()> {
    let text = value.as_str().context("MCP path must be text")?;
    ensure!(
        !text.is_empty() && text.len() <= 4096 && !text.chars().any(char::is_control),
        "invalid MCP workspace path"
    );
    // These are paths inside the Linux sandbox, even when this parser or its
    // tests are hosted on Windows. Host Path semantics would treat `/etc` as a
    // relative Windows path and accept drive/backslash spellings incorrectly.
    ensure!(
        !text.contains(['\\', ':']) && !text.starts_with('~'),
        "unsupported MCP workspace path spelling"
    );
    let relative = text.strip_prefix('/').unwrap_or(text);
    ensure!(
        relative
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".."),
        "unsupported MCP path traversal"
    );
    ensure!(
        !text.starts_with('/') || text == "/workspace" || text.starts_with("/workspace/"),
        "MCP path is outside selected workspace"
    );
    Ok(())
}

fn exact_keys(value: &Value, allowed: &[&str]) -> anyhow::Result<()> {
    let object = value.as_object().context("MCP object required")?;
    ensure!(
        object.keys().all(|k| allowed.contains(&k.as_str())),
        "unsupported MCP fields"
    );
    Ok(())
}

/// All original advertised tools remain visible. Unsupported tools are retained
/// in discovery and refused individually, without terminating unrelated calls.
pub fn classify_manifest(value: &Value) -> anyhow::Result<BTreeMap<String, ToolProfile>> {
    ensure!(
        value.to_string().len() <= MAX_DISCOVERY_BYTES,
        "MCP discovery byte limit"
    );
    ensure!(
        value == &original_manifest(),
        "MCP manifest differs from selected upstream pin"
    );
    let tools = value["tools"].as_array().context("MCP tools missing")?;
    ensure!(tools.len() <= MAX_TOOLS, "MCP tool count limit");
    let mut profiles = BTreeMap::new();
    for tool in tools {
        let name = tool["name"].as_str().context("MCP tool name missing")?;
        let unsupported_reason = match name {
            "write_file" | "edit_file" | "create_directory" | "move_file" => {
                Some("selected_profile_mutation_unsupported")
            }
            "read_media_file" => Some("selected_profile_multimedia_unsupported"),
            "read_file"
            | "read_text_file"
            | "read_multiple_files"
            | "list_directory"
            | "list_directory_with_sizes"
            | "directory_tree"
            | "search_files"
            | "get_file_info"
            | "list_allowed_directories" => None,
            _ => Some("selected_profile_tool_unsupported"),
        };
        let input = InputSchema::read_selected(&tool["inputSchema"]).ok();
        let output = InputSchema::read_selected(&tool["outputSchema"]).ok();
        let unsupported_reason = unsupported_reason.or_else(|| {
            if input.is_none() || output.is_none() {
                Some("selected_profile_schema_unsupported")
            } else {
                None
            }
        });
        ensure!(
            profiles
                .insert(
                    name.to_owned(),
                    ToolProfile {
                        input,
                        output,
                        unsupported_reason,
                        git_tool: None
                    }
                )
                .is_none(),
            "duplicate MCP tool"
        );
    }
    Ok(profiles)
}

/// SHA-256 of a canonical complete tree manifest. Entries are UTF-8 relative
/// paths in byte order; files use F\0path\0hex-sha256\n, directories D\0path\n,
/// symlinks L\0path\0target\n. Nothing is excluded. Links must stay inside root.
pub fn package_tree_sha256(root: &Path) -> anyhow::Result<String> {
    fn walk(
        root: &Path,
        relative: &Path,
        entries: &mut BTreeMap<String, Vec<u8>>,
        bytes: &mut u64,
        depth: usize,
    ) -> anyhow::Result<()> {
        ensure!(
            depth <= 32 && entries.len() <= MAX_TREE_FILES,
            "MCP package tree count or depth limit"
        );
        for entry in fs::read_dir(root.join(relative))? {
            let entry = entry?;
            let child = relative.join(entry.file_name());
            let name = child.to_str().context("MCP package path is not UTF-8")?;
            ensure!(
                !name.chars().any(char::is_control),
                "invalid MCP package path"
            );
            let metadata = fs::symlink_metadata(entry.path())?;
            let record = if metadata.is_symlink() {
                let target = fs::read_link(entry.path())?;
                ensure!(!target.is_absolute(), "MCP package link must be relative");
                let mut level = child.parent().map_or(0, |p| p.components().count());
                for component in target.components() {
                    match component {
                        Component::Normal(_) => level += 1,
                        Component::CurDir => {}
                        Component::ParentDir => {
                            ensure!(level > 0, "MCP package link escapes root");
                            level -= 1;
                        }
                        _ => anyhow::bail!("invalid MCP package link"),
                    }
                }
                // Lexical containment alone is insufficient when a target
                // traverses another link before `..`. Resolve the entire chain
                // and require an existing target inside the retained root.
                ensure!(
                    entry
                        .path()
                        .canonicalize()?
                        .starts_with(root.canonicalize()?),
                    "MCP package link resolves outside root"
                );
                let target = target.to_str().context("MCP package link is not UTF-8")?;
                ensure!(
                    !target.chars().any(char::is_control),
                    "invalid MCP package link target"
                );
                format!("L\0{name}\0{target}\n").into_bytes()
            } else if metadata.is_dir() {
                walk(root, &child, entries, bytes, depth + 1)?;
                format!("D\0{name}\n").into_bytes()
            } else {
                ensure!(metadata.is_file(), "unsupported MCP package file type");
                *bytes = bytes
                    .checked_add(metadata.len())
                    .context("MCP package size overflow")?;
                ensure!(*bytes <= MAX_TREE_BYTES, "MCP package byte limit");
                let mut file = fs::File::open(entry.path())?;
                let mut hash = Sha256::new();
                let mut buffer = [0u8; 65_536];
                let mut read_bytes = 0u64;
                loop {
                    let n = file.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    read_bytes += n as u64;
                    ensure!(
                        read_bytes <= metadata.len(),
                        "MCP package changed during hashing"
                    );
                    hash.update(&buffer[..n]);
                }
                ensure!(
                    read_bytes == metadata.len(),
                    "MCP package changed during hashing"
                );
                format!("F\0{name}\0{:x}\n", hash.finalize()).into_bytes()
            };
            ensure!(
                entries.insert(name.to_owned(), record).is_none()
                    && entries.len() <= MAX_TREE_FILES,
                "MCP package tree entry limit"
            );
        }
        Ok(())
    }
    ensure!(
        fs::metadata(root)?.is_dir(),
        "MCP package root must be a directory"
    );
    let mut entries = BTreeMap::new();
    walk(root, Path::new(""), &mut entries, &mut 0, 0)?;
    let mut hash = Sha256::new();
    for record in entries.values() {
        hash.update(record);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn original_upstream_discovery_preserves_every_tool_and_classifies_support() {
        let original = original_manifest();
        let tools = classify_manifest(&original).unwrap();
        assert_eq!(tools.len(), 14);
        assert_eq!(
            tools
                .values()
                .filter(|p| p.unsupported_reason.is_none())
                .count(),
            9
        );
        assert!(tools["read_text_file"]
            .validate_arguments(&json!({"path":"/workspace/note.txt"}))
            .is_ok());
        assert!(tools["write_file"]
            .validate_arguments(&json!({"path":"/workspace/note.txt","content":"new"}))
            .is_err());
        assert!(tools["read_media_file"].unsupported_reason.is_some());
        assert!(tools["list_directory_with_sizes"]
            .validate_arguments(&json!({"path":"/workspace","sortBy":"size"}))
            .is_ok());
        assert!(tools["list_directory_with_sizes"]
            .validate_arguments(&json!({"path":"/workspace","sortBy":"arbitrary"}))
            .is_err());
        assert!(tools["read_multiple_files"]
            .validate_arguments(&json!({"paths":[]}))
            .is_err());
        assert!(tools["read_text_file"]
            .validate_arguments(&json!({"path":"/workspace/note.txt","head":1.5}))
            .is_err());
        assert!(tools["read_text_file"]
            .validate_arguments(&json!({"path":"/workspace/note.txt","head":-1}))
            .is_err());
        assert!(tools["read_text_file"]
            .validate_arguments(&json!({"path":"/workspace/note.txt","unknown":"ignored upstream"}))
            .is_err());
        for path in ["/etc/passwd", "../note.txt", "/workspace/../etc/passwd", ""] {
            assert!(tools["read_text_file"]
                .validate_arguments(&json!({"path":path}))
                .is_err());
        }
        assert!(
            tools["read_text_file"]
                .validate_arguments(&json!({"path":"/workspace/note.txt"}))
                .is_ok(),
            "unsupported calls do not consume unrelated schemas"
        );
    }

    #[test]
    fn selected_upstream_pins_cover_metadata_execution_and_output_schema() {
        for field in [
            "description",
            "title",
            "inputSchema",
            "outputSchema",
            "annotations",
            "execution",
        ] {
            let mut changed = original_manifest();
            changed["tools"][0][field] = Value::Null;
            assert!(classify_manifest(&changed).is_err(), "{field}");
        }
        let mut changed = original_manifest();
        changed["nextCursor"] = json!("hidden-page");
        assert!(classify_manifest(&changed).is_err());
    }

    #[test]
    fn selected_protocol_versions_are_the_frozen_original_sdk_allowlist() {
        let original: Value = serde_json::from_str(ORIGINAL_INITIALIZATION).unwrap();
        for version in SUPPORTED_PROTOCOL_VERSIONS {
            let mut response = original["result"].clone();
            response["protocolVersion"] = json!(version);
            assert!(validate_initialization(&response).is_ok());
        }
        for version in ["future", "", "2026-07-28"] {
            let mut response = original["result"].clone();
            response["protocolVersion"] = json!(version);
            assert!(validate_initialization(&response).is_err());
        }
        let mut response = original["result"].clone();
        response["capabilities"]["logging"] = json!({});
        assert!(validate_initialization(&response).is_err());
    }

    #[test]
    fn selected_original_result_requires_inspectable_structured_text() {
        let tools = classify_manifest(&original_manifest()).unwrap();
        let read = &tools["read_text_file"];
        let value = json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ordinary"}],"structuredContent":{"content":"independent text"}}});
        assert_eq!(read.validate_result(&value).unwrap(), "value");
        for result in [
            json!({"content":[],"structuredContent":{"content":"text","hidden":"payload"}}),
            json!({"content":[],"structuredContent":{"content":42}}),
            json!({"content":[],"structuredContent":{"instructions":"payload"}}),
            json!({"content":[],"structuredContent":null}),
            json!({"content":[]}),
            json!({"content":[{"type":"image","data":"payload"}],"structuredContent":{"content":"text"}}),
            json!({"content":[],"structuredContent":{"content":"text"},"_meta":{"payload":"uninspected"}}),
        ] {
            assert!(read
                .validate_result(&json!({"jsonrpc":"2.0","id":1,"result":result}))
                .is_err());
        }
        assert_eq!(read.validate_result(&json!({"result":{"content":[{"type":"text","text":"ordinary error"}],"isError":true}})).unwrap(), "error");
    }

    #[test]
    fn tree_hash_records_empty_directories_file_bytes_and_every_entry() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("file"), "first").unwrap();
        let first = package_tree_sha256(root.path()).unwrap();
        fs::create_dir(root.path().join("empty")).unwrap();
        let second = package_tree_sha256(root.path()).unwrap();
        assert_ne!(first, second);
        fs::write(root.path().join("file"), "other").unwrap();
        assert_ne!(second, package_tree_sha256(root.path()).unwrap());
        fs::write(root.path().join(".hidden"), "covered").unwrap();
        assert_ne!(first, package_tree_sha256(root.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn tree_hash_covers_internal_links_and_refuses_escape_links() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("bin")).unwrap();
        fs::write(root.path().join("entry.js"), "original").unwrap();
        std::os::unix::fs::symlink("../entry.js", root.path().join("bin/tool")).unwrap();
        assert!(package_tree_sha256(root.path()).is_ok());
        fs::remove_file(root.path().join("bin/tool")).unwrap();
        std::os::unix::fs::symlink("../../outside", root.path().join("bin/tool")).unwrap();
        assert!(package_tree_sha256(root.path()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn tree_hash_refuses_escape_hidden_by_a_chained_link_before_parent_traversal() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("package");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("dir")).unwrap();
        fs::write(parent.path().join("outside"), "must not mount").unwrap();
        std::os::unix::fs::symlink("..", root.join("dir/a")).unwrap();
        std::os::unix::fs::symlink("a/../outside", root.join("dir/tool")).unwrap();
        assert!(package_tree_sha256(&root).is_err());
    }

    #[test]
    fn explicit_profile_is_strict_and_binds_the_actual_command() {
        // Physical operator paths use the host filesystem's absolute syntax;
        // the child argument remains the fixed virtual POSIX `/workspace`.
        let owned = tempfile::tempdir().unwrap();
        let root = owned.path().canonicalize().unwrap();
        let workspace = root.join("approved");
        let runtime = root.join("runtime").join("node");
        let package = root.join("installed").join("server");
        let bwrap = root.join("runtime").join("bwrap");
        let other = root.join("other");
        let value = json!({"format":FORMAT,"workspace":workspace,"runtimePath":runtime,"runtimeSha256":"a".repeat(64),"packageRoot":package,"packageTreeSha256":"b".repeat(64),"bwrapPath":bwrap,"bwrapSha256":"c".repeat(64),"libraries":[]});
        let profile = ProfileConfig::read(value.to_string().as_bytes()).unwrap();
        let args = vec![
            package.join(SERVER_ENTRYPOINT).to_str().unwrap().to_owned(),
            "/workspace".to_owned(),
        ];
        assert!(profile
            .validate_command(runtime.to_str().unwrap(), &args, &workspace)
            .is_ok());
        assert!(profile
            .validate_command(other.to_str().unwrap(), &args, &workspace)
            .is_err());
        assert!(profile
            .validate_command(runtime.to_str().unwrap(), &args, &other)
            .is_err());
        let mut changed = value.clone();
        changed["allowNetwork"] = json!(true);
        assert!(ProfileConfig::read(changed.to_string().as_bytes()).is_err());
        let mut changed = value;
        changed["format"] = json!("unknown");
        assert!(ProfileConfig::read(changed.to_string().as_bytes()).is_err());
        #[cfg(not(target_os = "linux"))]
        assert!(
            super::super::server_sandbox::prepare(&profile)
                .unwrap_err()
                .to_string()
                .contains("requires Linux bubblewrap"),
            "a valid physical configuration must not enable an unsupported host"
        );
    }

    #[test]
    fn virtual_workspace_paths_have_posix_semantics_on_every_host() {
        for path in [
            "/workspace",
            "/workspace/file.txt",
            "/workspace/sub/file.txt",
            "file.txt",
            "sub/file.txt",
            "café.txt",
        ] {
            assert!(validate_workspace_path(&json!(path)).is_ok(), "{path}");
        }
        for path in [
            "",
            "/",
            "/etc/passwd",
            "/workspaces/file.txt",
            "../file",
            "sub/../file",
            "./file",
            "sub/./file",
            "sub//file",
            "/workspace/",
            "//workspace/file",
            "C:/workspace/file",
            "C:\\workspace\\file",
            "\\workspace\\file",
            "file:stream",
            "~/file",
        ] {
            assert!(validate_workspace_path(&json!(path)).is_err(), "{path}");
        }
    }
}
