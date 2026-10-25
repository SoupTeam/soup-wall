// SPDX-License-Identifier: Apache-2.0
//! Operator-selected, immutable compatibility profile for one upstream server.
//! Discovery is untrusted evidence. These checks never grant native authority.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::input::InputSchema;

pub mod git;
mod read_lease;
mod verified_inputs;

/// Private to one pending Ask in this collector. Neither serializable nor a
/// policy/approval result; a daemon restart is still refused on redemption.
#[derive(Clone)]
pub(crate) struct VerifiedAssets {
    profile: Value,
    profile_path: PathBuf,
    inputs: verified_inputs::Inputs,
}

pub fn selected(format: Option<&str>) -> bool {
    matches!(
        format,
        Some(FORMAT | git::FORMAT | git::LOCAL_REFS_FORMAT | git::SHALLOW_FORMAT)
    )
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
/// Reviewed result budgets, separate from argument/request validation.
/// One decoded result text (each content block and each structured string).
pub const RESULT_TEXT_BYTES: usize = super::input::RESULT_STRING_BYTES;
/// One complete server response line on the wire, newline included. Covers
/// the duplicated text and structuredContent channels of one maximal text
/// with ordinary JSON escaping. Larger frames are never buffered whole.
pub const RESULT_FRAME_BYTES: usize = 1_048_576;
/// Bytes of one oversized frame that may be validated and discarded while
/// resynchronizing to its end. Beyond this the session fails closed.
pub const RESULT_DRAIN_BYTES: usize = 16 * 1024 * 1024;
/// Wall-clock bound for draining one oversized frame.
pub const RESULT_DRAIN_TIME: std::time::Duration = std::time::Duration::from_secs(10);
pub const MAX_DISCOVERY_BYTES: usize = 262_144;
pub const MAX_PROFILE_BYTES: usize = 65_536;
const MAX_TREE_FILES: usize = 32_768;
const MAX_TREE_BYTES: u64 = 512 * 1024 * 1024;

fn open_regular(path: impl AsRef<Path>) -> anyhow::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A file swapped for a FIFO during approval must refuse, not occupy
        // an admission worker forever. Regular-file reads ignore this flag.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "selected asset is not a regular file"
    );
    Ok(file)
}

const ORIGINAL_MANIFEST: &str =
    include_str!("../../../../profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json");
const ORIGINAL_INITIALIZATION: &str =
    include_str!("../../../../profiles/mcp/filesystem-readonly-v1/upstream-initialize.json");

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Library {
    pub path: PathBuf,
    pub sha256: String,
}

/// Optional existing-project identity. Content remains mutable, untrusted data;
/// replacing the selected directory never transfers its execution authority.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceIdentity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
}

impl WorkspaceIdentity {
    #[cfg(unix)]
    pub fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileConfig {
    pub format: String,
    pub workspace: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_identity: Option<WorkspaceIdentity>,
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

fn verified_capture_failure(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        match cause.to_string().as_str() {
            "selected asset changed during identity lookup" => return "identity_lookup_changed",
            "selected asset changed during verification" => return "identity_changed",
            "selected asset identity or metadata changed during approval" => {
                return "identity_changed"
            }
            "selected asset size changed during verification" => return "size_changed",
            "selected asset changed during hashing" => return "bytes_changed",
            "selected asset read lease lost during capture" | "selected asset read lease lost" => {
                return "lease_lost"
            }
            "selected asset immutable proof unavailable" => return "verity_unavailable",
            "unsupported selected asset immutable proof" => return "verity_unsupported",
            "selected executable or library changed during approval" => {
                return "runtime_digest_mismatch"
            }
            "selected package changed during approval" => return "package_digest_mismatch",
            "selected profile changed before approval" => return "profile_changed",
            _ => {}
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::NotFound => "input_missing",
                std::io::ErrorKind::PermissionDenied => "input_permission",
                _ => "input_io",
            };
        }
    }
    "capture_failure"
}

impl ProfileConfig {
    /// Recheck immutable installed assets after an operator wait. This only
    /// observes files; it creates no sandbox, budget, process or authority.
    pub(crate) fn capture_verified_assets(&self) -> anyhow::Result<VerifiedAssets> {
        let result = self.capture_verified_assets_inner();
        if let Err(error) = &result {
            let code = verified_capture_failure(error);
            eprintln!(
                "{}",
                serde_json::json!({"event":"mcp_verified_inputs_capture_failure", "failure_code":code})
            );
        }
        result
    }

    fn capture_verified_assets_inner(&self) -> anyhow::Result<VerifiedAssets> {
        let profile_path = std::env::var_os(ENVIRONMENT)
            .map(PathBuf::from)
            .context("selected profile disappeared")?;
        let profile = serde_json::to_value(self)?;
        let mut inputs = verified_inputs::Inputs::default();
        let mut verification = verified_inputs::Verification::Capture(&mut inputs);
        verification.entry(&profile_path)?;
        ensure!(
            Self::load_from_env()?
                .map(serde_json::to_value)
                .transpose()?
                == Some(profile.clone()),
            "selected profile changed before approval"
        );
        self.verify_assets_with(&mut verification)?;
        verification.entry(&profile_path)?;
        inputs.validate_leases()?;
        // Diagnostic output cannot interrupt a completed input observation.
        // Only bounded counts/durations are reported, never paths or authority.
        {
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr().lock(), "{}", inputs.capture_cost());
        }
        Ok(VerifiedAssets {
            profile,
            profile_path,
            inputs,
        })
    }

    pub(crate) fn revalidate_assets(&self, verified: &VerifiedAssets) -> anyhow::Result<()> {
        let started = std::time::Instant::now();
        let mut verification = verified_inputs::Verification::Resume(&verified.inputs);
        ensure!(
            std::env::var_os(ENVIRONMENT).map(PathBuf::from).as_ref()
                == Some(&verified.profile_path),
            "selected profile path changed during approval"
        );
        verification.entry(&verified.profile_path)?;
        let current = Self::load_from_env()?.context("selected profile disappeared")?;
        ensure!(
            serde_json::to_value(&current)? == verified.profile
                && serde_json::to_value(self)? == verified.profile,
            "selected profile changed during approval"
        );
        eprintln!(
            "{}",
            serde_json::json!({"event":"mcp_asset_verification_timing", "profile":self.format,
            "stage":"selected_profile", "elapsed_ms":started.elapsed().as_secs_f64() * 1000.0})
        );
        self.verify_assets_with(&mut verification)?;
        verification.entry(&verified.profile_path)?;
        verified.inputs.validate_leases()?;
        let (immutable_files, leased_files, rehashed_files) = verified.inputs.counts();
        eprintln!(
            "{}",
            serde_json::json!({"event":"mcp_verified_inputs_resume",
            "profile":self.format,"immutable_files":immutable_files,"leased_files":leased_files,"rehashed_files":rehashed_files})
        );
        Ok(())
    }

    /// Verify pinned bytes without modifying process environment or launching a server.
    pub(crate) fn verify_assets(&self) -> anyhow::Result<()> {
        self.verify_assets_with(&mut verified_inputs::Verification::Full)
    }

    fn verify_assets_with(
        &self,
        verification: &mut verified_inputs::Verification<'_>,
    ) -> anyhow::Result<()> {
        let started = std::time::Instant::now();
        let mut total = 0u64;
        for (path, digest) in [
            (&self.runtime_path, &self.runtime_sha256),
            (&self.bwrap_path, &self.bwrap_sha256),
        ]
        .into_iter()
        .chain(self.libraries.iter().map(|pin| (&pin.path, &pin.sha256)))
        .chain(
            self.git
                .iter()
                .chain(self.git_launcher.iter())
                .map(|pin| (&pin.path, &pin.sha256)),
        ) {
            let size = fs::metadata(path)?.len();
            total = total
                .checked_add(size)
                .context("selected asset size overflow")?;
            ensure!(total <= MAX_TREE_BYTES, "selected asset byte limit");
            ensure!(
                verification.digest(path, size)? == *digest,
                "selected executable or library changed during approval"
            );
        }
        eprintln!(
            "{}",
            serde_json::json!({"event":"mcp_asset_verification_timing", "profile":self.format,
            "stage":"runtime_and_libraries", "elapsed_ms":started.elapsed().as_secs_f64() * 1000.0})
        );
        let started = std::time::Instant::now();
        ensure!(
            package_tree_sha256_with(&self.package_root, verification)? == self.package_tree_sha256,
            "selected package changed during approval"
        );
        eprintln!(
            "{}",
            serde_json::json!({"event":"mcp_asset_verification_timing", "profile":self.format,
            "stage":"package_tree", "elapsed_ms":started.elapsed().as_secs_f64() * 1000.0})
        );
        Ok(())
    }

    pub fn load_from_env() -> anyhow::Result<Option<Self>> {
        std::env::var_os(ENVIRONMENT)
            .map(|path| {
                let mut bytes = Vec::new();
                open_regular(PathBuf::from(path))?
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
            git::is_profile(&config.format) == config.git.is_some()
                && git::is_profile(&config.format) == config.git_launcher.is_some(),
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
        if git::is_profile(&self.format) {
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
        git::FORMAT | git::LOCAL_REFS_FORMAT | git::SHALLOW_FORMAT => Ok(git::original_manifest()),
        _ => anyhow::bail!("unsupported MCP profile"),
    }
}

pub fn validate_initialization_for(format: &str, value: &Value) -> anyhow::Result<()> {
    match format {
        FORMAT => validate_initialization(value),
        git::FORMAT | git::LOCAL_REFS_FORMAT | git::SHALLOW_FORMAT => {
            git::validate_initialization(value)
        }
        _ => anyhow::bail!("unsupported MCP profile"),
    }
}

pub fn classify_manifest_for(
    format: &str,
    value: &Value,
) -> anyhow::Result<BTreeMap<String, ToolProfile>> {
    match format {
        FORMAT => classify_manifest(value),
        git::FORMAT => git::classify_manifest(value),
        git::LOCAL_REFS_FORMAT => git::classify_manifest_with_local_refs(value, true),
        git::SHALLOW_FORMAT => git::classify_manifest(value),
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
    git_local_references: bool,
}

impl ToolProfile {
    pub fn validate_arguments(&self, value: &Value) -> anyhow::Result<()> {
        ensure!(
            self.unsupported_reason.is_none(),
            "MCP tool is unsupported by selected profile"
        );
        if let Some(name) = &self.git_tool {
            return git::validate_arguments_with_local_refs(name, value, self.git_local_references);
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
                block["type"] == "text" && block["text"].is_string(),
                "unsupported MCP content"
            );
            if block["text"]
                .as_str()
                .is_some_and(|s| s.len() > RESULT_TEXT_BYTES)
            {
                return Err(super::input::ResultBudgetExceeded {
                    limit: RESULT_TEXT_BYTES,
                }
                .into());
            }
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

/// Why a path argument was refused before dispatch. Typed so the transport can
/// tell the user which boundary applied, with fixed text that never echoes the
/// argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRefusal {
    /// Absolute path outside `/workspace`.
    Outside,
    /// Empty, overlong, control character, backslash, `~`, drive, or an
    /// empty / `.` / `..` segment.
    Spelling,
}

impl std::fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PathRefusal::Outside => "MCP path is outside selected workspace",
            PathRefusal::Spelling => "unsupported MCP workspace path spelling",
        })
    }
}

impl std::error::Error for PathRefusal {}

fn validate_workspace_path(value: &Value) -> anyhow::Result<()> {
    let text = value.as_str().context("MCP path must be text")?;
    let spelling = || anyhow::Error::new(PathRefusal::Spelling);
    if text.is_empty() || text.len() > 4096 || text.chars().any(char::is_control) {
        return Err(spelling());
    }
    // These are paths inside the Linux sandbox, even when this parser or its
    // tests are hosted on Windows. Host Path semantics would treat `/etc` as a
    // relative Windows path and accept drive/backslash spellings incorrectly.
    // A colon is an ordinary Linux name byte. It is accepted only inside an
    // absolute `/workspace/` path, which cannot be read as a drive or stream;
    // relative spellings such as `C:/x` or `file:stream` stay refused.
    let absolute = text.starts_with("/workspace/");
    if text.starts_with('/') && text != "/workspace" && !absolute {
        return Err(PathRefusal::Outside.into());
    }
    if text.contains('\\') || text.starts_with('~') || (text.contains(':') && !absolute) {
        return Err(spelling());
    }
    let relative = text.strip_prefix('/').unwrap_or(text);
    if !relative
        .split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
    {
        return Err(spelling());
    }
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
        let output =
            InputSchema::read_selected_role(&tool["outputSchema"], super::input::Role::Result).ok();
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
                        git_tool: None,
                        git_local_references: false,
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
    package_tree_sha256_with(root, &mut verified_inputs::Verification::Full)
}

fn package_tree_sha256_with(
    root: &Path,
    verification: &mut verified_inputs::Verification<'_>,
) -> anyhow::Result<String> {
    fn walk(
        root: &Path,
        relative: &Path,
        entries: &mut BTreeMap<String, Vec<u8>>,
        bytes: &mut u64,
        depth: usize,
        verification: &mut verified_inputs::Verification<'_>,
    ) -> anyhow::Result<()> {
        verification.entry(&root.join(relative))?;
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
            let descriptor_leaf = cfg!(target_os = "linux") && metadata.is_file();
            // walk() already binds directories immediately before and after
            // descent, and tree_digest() closes descriptor leaves itself. Only
            // links/other entries need the surrounding observations here.
            let observe_here = !descriptor_leaf && !metadata.is_dir();
            if observe_here {
                verification.entry(&entry.path())?;
            }
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
                walk(root, &child, entries, bytes, depth + 1, verification)?;
                format!("D\0{name}\n").into_bytes()
            } else {
                ensure!(metadata.is_file(), "unsupported MCP package file type");
                *bytes = bytes
                    .checked_add(metadata.len())
                    .context("MCP package size overflow")?;
                ensure!(*bytes <= MAX_TREE_BYTES, "MCP package byte limit");
                let digest = verification.tree_digest(&entry.path(), &metadata)?;
                format!("F\0{name}\0{digest}\n").into_bytes()
            };
            if observe_here {
                verification.entry(&entry.path())?;
            }
            ensure!(
                entries.insert(name.to_owned(), record).is_none()
                    && entries.len() <= MAX_TREE_FILES,
                "MCP package tree entry limit"
            );
        }
        verification.entry(&root.join(relative))?;
        Ok(())
    }
    ensure!(
        fs::metadata(root)?.is_dir(),
        "MCP package root must be a directory"
    );
    let mut entries = BTreeMap::new();
    walk(root, Path::new(""), &mut entries, &mut 0, 0, verification)?;
    verification.tree_entries(root, entries.len())?;
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

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly selected operator-owned installed native profile"]
    fn native_installed_profile_ask_capture_resume() {
        let profile = ProfileConfig::load_from_env()
            .expect("read selected profile")
            .expect("explicit selected profile required");
        profile
            .verify_assets()
            .expect("initial selected asset verification");
        let captured = profile
            .capture_verified_assets()
            .expect("selected input capture");
        profile
            .revalidate_assets(&captured)
            .expect("selected input resume");
        let (immutable, leased, _) = captured.inputs.counts();
        assert!(
            immutable + leased > 0,
            "actual installed input kernel reuse required"
        );
    }

    #[test]
    fn capture_failure_codes_never_export_arbitrary_error_payloads() {
        assert_eq!(
            verified_capture_failure(&anyhow::anyhow!("private payload and token")),
            "capture_failure"
        );
        assert_eq!(
            verified_capture_failure(&anyhow::anyhow!(
                "selected asset changed during identity lookup"
            )),
            "identity_lookup_changed"
        );
    }

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
    fn result_budget_is_separate_from_argument_budget_on_both_channels() {
        use super::super::input::ResultBudgetExceeded;
        let tools = classify_manifest(&original_manifest()).unwrap();
        let read = &tools["read_text_file"];
        let frame = |text: &str, structured: &str| {
            json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":text}],
                "structuredContent":{"content":structured}}})
        };
        let budget_error = |value: &Value| {
            read.validate_result(value)
                .unwrap_err()
                .downcast_ref::<ResultBudgetExceeded>()
                .copied()
        };
        // The old argument default was the result limit; it no longer is.
        for size in [16_383, 16_384, 16_385, 20 * 1024, 60 * 1024, 120 * 1024] {
            let text = "a".repeat(size);
            assert_eq!(read.validate_result(&frame(&text, &text)).unwrap(), "value");
        }
        let below = "b".repeat(RESULT_TEXT_BYTES - 1);
        let at = "b".repeat(RESULT_TEXT_BYTES);
        let above = "b".repeat(RESULT_TEXT_BYTES + 1);
        assert_eq!(
            read.validate_result(&frame(&below, &below)).unwrap(),
            "value"
        );
        assert_eq!(read.validate_result(&frame(&at, &at)).unwrap(), "value");
        let limit = Some(ResultBudgetExceeded {
            limit: RESULT_TEXT_BYTES,
        });
        assert_eq!(budget_error(&frame(&above, "small")), limit);
        assert_eq!(budget_error(&frame("small", &above)), limit);
        // Bytes, not characters: 65_536 four-byte scalars fill the budget exactly.
        let wide = "\u{1F963}".repeat(RESULT_TEXT_BYTES / 4);
        assert_eq!(read.validate_result(&frame(&wide, &wide)).unwrap(), "value");
        let wider = format!("{wide}x");
        assert_eq!(budget_error(&frame(&wider, &wider)), limit);
        // Type and shape validation are unchanged by the result role.
        let typed = json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"x"}],
            "structuredContent":{"content":7}}});
        assert!(budget_error(&typed).is_none() && read.validate_result(&typed).is_err());
        // Arguments keep the reviewed 16 KiB default string budget.
        let input = read.input.as_ref().unwrap();
        assert!(input.validate(&json!({"path":"p".repeat(16_384)})).is_ok());
        assert!(input.validate(&json!({"path":"p".repeat(16_385)})).is_err());
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
            "/workspace/back\\slash",
            "/workspace/tab\tname",
            "/workspace:extra",
            "/workspace/a/../../etc/passwd",
        ] {
            assert!(validate_workspace_path(&json!(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn path_refusals_name_their_boundary_and_accept_linux_names() {
        let refusal = |path: &str| {
            validate_workspace_path(&json!(path))
                .unwrap_err()
                .downcast_ref::<PathRefusal>()
                .copied()
        };
        for path in ["/etc/passwd", "/workspaces/file.txt", "/", "/tmp/x:y"] {
            assert_eq!(refusal(path), Some(PathRefusal::Outside), "{path}");
        }
        for path in [
            "",
            "../file",
            "/workspace/../etc/passwd",
            "sub//file",
            "/workspace/",
            "C:/workspace/file",
            "file:stream",
            "~/file",
            "/workspace/a\\b",
            "/workspace/a\nb",
        ] {
            assert_eq!(refusal(path), Some(PathRefusal::Spelling), "{path:?}");
        }
        assert_eq!(
            refusal(&format!("/workspace/{}", "a".repeat(4096))),
            Some(PathRefusal::Spelling)
        );
        // Ordinary Linux names stay exact: nothing is normalized or decoded.
        for path in [
            "/workspace/a:b.txt",
            "/workspace/dir with spaces/file name.txt",
            "/workspace/кириллица/файл.txt",
            "/workspace/-leading-dash.txt",
            "-leading-dash.txt",
            "/workspace/.hidden",
            "/workspace/$(touch pwned).txt",
            "/workspace/; ls.txt",
            "/workspace/quote\"name.txt",
            "/workspace/caf\u{e9}.txt",
            "/workspace/cafe\u{301}.txt",
            "/workspace/percent%2F.txt",
        ] {
            assert!(validate_workspace_path(&json!(path)).is_ok(), "{path}");
        }
        // A type error is not a path refusal.
        assert!(validate_workspace_path(&json!(7))
            .unwrap_err()
            .downcast_ref::<PathRefusal>()
            .is_none());
    }
}
