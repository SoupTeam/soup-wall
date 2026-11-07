// SPDX-License-Identifier: Apache-2.0
//! SOU-204 offline original-tool schema upgrade analyzer.
//!
//! Compares two exact, bounded original MCP `tools/list` snapshots against the
//! current operator-owned declarations and prepares review material. It reads
//! only the explicitly named files (and the files an identity document names),
//! writes only a new output directory, and never approves or installs a schema,
//! grants permission, edits a profile, launches a server, follows a `$ref`,
//! performs network lookups or classifies with a model. Names, descriptions and
//! annotations are untrusted data: they never create or widen permission.
//!
//! Three identities stay distinct: the raw input-file digest, the accepted exact
//! identities (`profile_author::digest` of a tool, its `inputSchema`, or the
//! discovery result), and the sorted-key representation used only to compare.
//! Any after-identity that differs from the before-identity is reported as
//! **unaccepted**; no finding, however inert, changes that.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::mcp::admission::Strict;
use crate::mcp::input::{InputSchema, Role};
use crate::mcp::{profile_author, server_profile};

mod examples;
mod render;
#[cfg(test)]
mod tests;

pub const REPORT_FORMAT: &str = "sw-mcp/schema-upgrade-report/1";
pub const PACK_FORMAT: &str = "sw-mcp/schema-upgrade-review-pack/1";
const DISCOVERY_FORMAT: &str = "sw-mcp/operator-discovery/1";
const FILESYSTEM_IDENTITY_FORMAT: &str = "sw-mcp/filesystem-readonly-upstream/1";
const DECLARATION_FORMAT: &str = "sw-mcp/operator-declaration/1";

/// Analysis completed, the two snapshots are byte-identical and there is no finding.
pub const EXIT_NO_DRIFT: i32 = 0;
/// Invalid input or bound exceeded; nothing was written. Clap usage errors also exit 2.
pub const EXIT_INVALID_INPUT: i32 = 2;
/// An input file could not be read (I/O), independent of its content.
pub const EXIT_TECHNICAL: i32 = 3;
/// The output directory could not be created as a new private directory.
pub const EXIT_OUTPUT: i32 = 4;
/// Analysis completed; the after snapshot or the declarations differ and need
/// review/re-qualification.
pub const EXIT_REVIEW_REQUIRED: i32 = 5;

/// Same bound as one selected original discovery frame.
pub const MAX_SNAPSHOT_BYTES: usize = server_profile::MAX_DISCOVERY_BYTES;
pub const MAX_DECLARATION_BYTES: usize = server_profile::MAX_DISCOVERY_BYTES;
pub const MAX_REFERENCED_FILE_BYTES: u64 = 1_048_576;
pub const MAX_REFERENCED_FILES: usize = 16;
pub const MAX_TOOLS: usize = server_profile::MAX_TOOLS;
pub const MAX_DOCUMENT_DEPTH: usize = 32;
pub const MAX_DOCUMENT_NODES: usize = 65_536;
pub const MAX_DIFF_STEPS: usize = 131_072;
pub const MAX_FINDINGS: usize = 2_048;
pub const MAX_COVERAGE_ENTRIES: usize = 1_024;
pub const MAX_LABEL_BYTES: usize = 256;
/// Larger before/after values are replaced by their digest and byte length.
pub const MAX_VALUE_EXCERPT_BYTES: usize = 1_024;
pub const MAX_OUTPUT_BYTES: usize = 16 * 1_048_576;

pub(crate) const NON_AUTHORITY: &str = "This analyzer accepts nothing. It does not approve or \
install a schema, grant runtime permission, modify an accepted profile or declaration, launch a \
server, retrieve references, perform network lookups or classify with a model. Every after-side \
identity that differs from the before side remains unaccepted until the operator completes the \
existing review, qualification and admission process.";

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Exact original tools/list snapshot currently accepted (JSON-RPC response or sw-mcp/operator-discovery/1).
    #[arg(long)]
    pub before: PathBuf,
    /// Exact original tools/list snapshot proposed by the upstream update.
    #[arg(long)]
    pub after: PathBuf,
    /// Accepted identity document for the before snapshot (profile upstream-identity.json).
    #[arg(long)]
    pub before_identity: Option<PathBuf>,
    /// Current operator-owned native registry (sw-native/1) bound to the before snapshot.
    #[arg(long, conflicts_with = "declarations")]
    pub registry: Option<PathBuf>,
    /// Compare snapshots without current declarations. Semantic review is then
    /// unavailable and reported as such; never a substitute for the declared review.
    #[arg(long, conflicts_with_all = ["registry", "declarations", "proposed_registry"])]
    pub snapshot_only: bool,
    /// Current operator declarations (sw-mcp/operator-declaration/1) bound to the before snapshot.
    #[arg(long)]
    pub declarations: Option<PathBuf>,
    /// Optional draft registry for the after snapshot; compared, never accepted.
    #[arg(long)]
    pub proposed_registry: Option<PathBuf>,
    /// Operator-asserted provenance label for the before snapshot (untrusted text).
    #[arg(long)]
    pub before_label: Option<String>,
    /// Operator-asserted provenance label for the after snapshot (untrusted text).
    #[arg(long)]
    pub after_label: Option<String>,
    /// New directory for report.json, findings.csv, report.txt, review-pack.json, REVIEW_GUIDE.md.
    #[arg(long)]
    pub out: PathBuf,
}

/// A refusal of invalid or out-of-bounds input. `code` is fixed vocabulary;
/// `detail` never repeats input content.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub code: &'static str,
    pub detail: String,
}

pub(crate) fn refuse<T>(code: &'static str, detail: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal {
        code,
        detail: detail.into(),
    })
}

type R<T> = Result<T, Refusal>;

/// One already-read input. `dir` resolves paths an identity document references.
#[derive(Clone, Debug)]
pub struct InputFile {
    pub name: String,
    pub bytes: Vec<u8>,
    pub dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub struct Request {
    pub before: Option<InputFile>,
    pub after: Option<InputFile>,
    pub before_identity: Option<InputFile>,
    pub registry: Option<InputFile>,
    pub declarations: Option<InputFile>,
    pub proposed_registry: Option<InputFile>,
    /// Explicit opt-out of the declaration-bound review (`--snapshot-only`).
    pub snapshot_only: bool,
    pub before_label: Option<String>,
    pub after_label: Option<String>,
}

/// Deterministic analysis products, rendered in memory before any write.
pub struct Outcome {
    pub report: Value,
    pub pack: Value,
    pub files: Vec<(&'static str, Vec<u8>)>,
    pub exit: i32,
}

pub(crate) fn sha_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Sorted-key compact JSON used only for comparison and stable ids. Exact
/// identities are always computed by the accepted `profile_author::digest`.
pub(crate) fn canonical_json(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let ordered: BTreeMap<&String, Value> =
                    map.iter().map(|(k, v)| (k, sorted(v))).collect();
                serde_json::to_value(ordered).unwrap_or(Value::Null)
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    sorted(value).to_string()
}

pub(crate) fn escape_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn unescape_token(token: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        if c == '~' {
            match chars.next() {
                Some('0') => out.push('~'),
                Some('1') => out.push('/'),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// RFC 6901 pointer tokens; `None` for an invalid pointer.
pub(crate) fn pointer_tokens(pointer: &str) -> Option<Vec<String>> {
    if pointer.is_empty() {
        return Some(vec![]);
    }
    let rest = pointer.strip_prefix('/')?;
    rest.split('/').map(unescape_token).collect()
}

/// Bounded excerpt: small values verbatim, larger ones by digest only. The
/// value is streamed into a hasher and byte counter; no serialization of a
/// large value is ever buffered. `Value` maps are sorted, so the stream equals
/// `canonical_json`.
pub(crate) fn excerpt(value: &Value) -> Value {
    struct Meter(usize, Sha256);
    impl std::io::Write for Meter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            self.1.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut meter = Meter(0, Sha256::new());
    if serde_json::to_writer(&mut meter, value).is_err() {
        return json!({"omitted_bytes": null});
    }
    if meter.0 <= MAX_VALUE_EXCERPT_BYTES {
        value.clone()
    } else {
        json!({"omitted_bytes": meter.0, "sha256": format!("{:x}", meter.1.finalize())})
    }
}

fn is_digest(value: &str) -> bool {
    crate::native::is_digest(value)
}

// ---------------------------------------------------------------------------
// Strict bounded input
// ---------------------------------------------------------------------------

fn parse_strict(file: &InputFile, max: usize, role: &str) -> R<Value> {
    if file.bytes.len() > max {
        return refuse(
            "input_too_large",
            format!(
                "{role}: {} bytes exceeds the {max}-byte bound",
                file.bytes.len()
            ),
        );
    }
    let value = match serde_json::from_slice::<Strict>(&file.bytes) {
        Ok(Strict(value)) => value,
        Err(error) => {
            let message = error.to_string();
            let code = if message.contains("duplicate JSON member") {
                "duplicate_json_member"
            } else if message.contains("recursion limit") {
                "depth_exceeded"
            } else {
                "malformed_json"
            };
            return refuse(
                code,
                format!(
                    "{role}: strict JSON refused at line {} column {}",
                    error.line(),
                    error.column()
                ),
            );
        }
    };
    check_document_bounds(&value, role)?;
    Ok(value)
}

fn check_document_bounds(value: &Value, role: &str) -> R<()> {
    let mut stack = vec![(value, 0usize)];
    let mut nodes = 0usize;
    while let Some((node, depth)) = stack.pop() {
        nodes += 1;
        if depth > MAX_DOCUMENT_DEPTH {
            return refuse(
                "depth_exceeded",
                format!("{role}: nesting exceeds depth {MAX_DOCUMENT_DEPTH}"),
            );
        }
        if nodes > MAX_DOCUMENT_NODES {
            return refuse(
                "traversal_exceeded",
                format!("{role}: more than {MAX_DOCUMENT_NODES} JSON values"),
            );
        }
        match node {
            Value::Object(map) => stack.extend(map.values().map(|v| (v, depth + 1))),
            Value::Array(items) => stack.extend(items.iter().map(|v| (v, depth + 1))),
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn tool_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:/".contains(&b))
}

#[derive(Clone, Debug)]
pub(crate) struct FileIdentity {
    name: String,
    raw_sha256: String,
    bytes: usize,
}

impl FileIdentity {
    fn of(file: &InputFile) -> Self {
        Self {
            name: file.name.clone(),
            raw_sha256: sha_hex(&file.bytes),
            bytes: file.bytes.len(),
        }
    }
    fn json(&self) -> Value {
        json!({"file_name": self.name, "raw_sha256": self.raw_sha256, "bytes": self.bytes})
    }
}

pub(crate) struct Snapshot {
    file: FileIdentity,
    format: &'static str,
    value: Value,
    discovery_sha256: String,
    /// Tools keyed by name; document order is kept only to report reordering.
    pub(crate) tools: BTreeMap<String, Value>,
    order: Vec<String>,
}

const TOOL_MEMBERS: [&str; 9] = [
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
    "execution",
    "icons",
    "_meta",
];

fn load_snapshot(file: &InputFile, role: &'static str) -> R<Snapshot> {
    let value = parse_strict(file, MAX_SNAPSHOT_BYTES, role)?;
    let object = match value.as_object() {
        Some(object) => object,
        None => return refuse("invalid_envelope", format!("{role}: not a JSON object")),
    };
    let (format, tools, discovery) = if object.contains_key("format") {
        if value["format"] != DISCOVERY_FORMAT
            || object.len() != 4
            || !value["server_id"].is_string()
            || !value["server_version"].is_string()
        {
            return refuse(
                "invalid_envelope",
                format!("{role}: unsupported discovery document"),
            );
        }
        (
            DISCOVERY_FORMAT,
            &value["tools"],
            profile_author::digest(&value),
        )
    } else {
        if !object
            .keys()
            .all(|k| matches!(k.as_str(), "jsonrpc" | "id" | "result"))
            || value["jsonrpc"] != "2.0"
            || !(value["id"].is_string() || value["id"].is_i64() || value["id"].is_u64())
        {
            return refuse(
                "invalid_envelope",
                format!("{role}: expected a JSON-RPC 2.0 tools/list response"),
            );
        }
        let Some(result) = value["result"].as_object() else {
            return refuse("invalid_envelope", format!("{role}: result object missing"));
        };
        if result.contains_key("nextCursor") {
            return refuse(
                "incomplete_snapshot",
                format!("{role}: paginated tools/list (nextCursor) is not a complete snapshot"),
            );
        }
        if !result.keys().all(|k| k == "tools") {
            return refuse(
                "invalid_envelope",
                format!("{role}: unsupported tools/list result member"),
            );
        }
        (
            "mcp/tools-list-response",
            &value["result"]["tools"],
            profile_author::digest(&value["result"]),
        )
    };
    let Some(list) = tools.as_array() else {
        return refuse("invalid_envelope", format!("{role}: tools array missing"));
    };
    if list.len() > MAX_TOOLS {
        return refuse(
            "too_many_tools",
            format!(
                "{role}: {} tools exceeds the {MAX_TOOLS}-tool bound",
                list.len()
            ),
        );
    }
    let mut by_name = BTreeMap::new();
    let mut order = Vec::new();
    for (index, tool) in list.iter().enumerate() {
        let Some(members) = tool.as_object() else {
            return refuse(
                "invalid_tool",
                format!("{role}: tools[{index}] is not an object"),
            );
        };
        let Some(name) = tool["name"].as_str() else {
            return refuse(
                "invalid_tool",
                format!("{role}: tools[{index}] has no name"),
            );
        };
        if !tool_name_ok(name) {
            return refuse(
                "invalid_tool_name",
                format!("{role}: tools[{index}] name outside [A-Za-z0-9_-.:/]{{1,128}}"),
            );
        }
        if !tool["inputSchema"].is_object() {
            return refuse(
                "invalid_tool",
                format!("{role}: tools[{index}] inputSchema must be an object"),
            );
        }
        let typed = [
            ("title", Value::is_string as fn(&Value) -> bool),
            ("description", Value::is_string),
            ("outputSchema", Value::is_object),
            ("annotations", Value::is_object),
            ("execution", Value::is_object),
            ("icons", Value::is_array),
            ("_meta", Value::is_object),
        ];
        for (member, check) in typed {
            if members.get(member).is_some_and(|v| !check(v)) {
                return refuse(
                    "invalid_tool",
                    format!("{role}: tools[{index}].{member} has an invalid type"),
                );
            }
        }
        if by_name.insert(name.to_owned(), tool.clone()).is_some() {
            return refuse(
                "duplicate_tool",
                format!("{role}: tools[{index}] repeats an earlier tool name"),
            );
        }
        order.push(name.to_owned());
    }
    Ok(Snapshot {
        file: FileIdentity::of(file),
        format,
        discovery_sha256: discovery,
        value,
        tools: by_name,
        order,
    })
}

// ---------------------------------------------------------------------------
// Accepted identity document (before side only)
// ---------------------------------------------------------------------------

struct IdentityCheck {
    file: FileIdentity,
    format: &'static str,
    checks: Vec<Value>,
    referenced: Vec<Value>,
    per_tool: bool,
}

fn safe_relative(path: &str) -> Option<PathBuf> {
    if path.is_empty() || path.len() > 256 || path.contains(['\\', ':', '\0']) {
        return None;
    }
    let candidate = Path::new(path);
    candidate
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
        .then(|| candidate.to_path_buf())
}

fn verify_referenced(dir: Option<&Path>, relative: &str, expected: &str) -> R<Value> {
    let Some(rel) = safe_relative(relative) else {
        return refuse(
            "invalid_referenced_path",
            "identity references a path that is not a plain relative path",
        );
    };
    if !is_digest(expected) {
        return refuse(
            "identity_incomplete",
            "identity reference digest is not 64 lowercase hex",
        );
    }
    let Some(dir) = dir else {
        return refuse(
            "invalid_referenced_path",
            "identity references files but its directory is unknown",
        );
    };
    let path = dir.join(&rel);
    let bytes = read_bounded(&path, MAX_REFERENCED_FILE_BYTES).map_err(|_| Refusal {
        code: "invalid_referenced_path",
        detail: format!("referenced file {relative:?} is missing, not regular or too large"),
    })?;
    let actual = sha_hex(&bytes);
    if actual != expected {
        return refuse(
            "referenced_digest_mismatch",
            format!("referenced file {relative:?} differs from its declared digest"),
        );
    }
    Ok(json!({"path": relative, "sha256": actual, "status": "verified"}))
}

fn verify_identity(file: &InputFile, before: &Snapshot) -> R<IdentityCheck> {
    let value = parse_strict(file, MAX_DECLARATION_BYTES, "before identity")?;
    let Some(object) = value.as_object() else {
        return refuse("invalid_identity", "identity document is not an object");
    };
    let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let mut checks = Vec::new();
    let mut referenced = Vec::new();
    let dir = file.dir.as_deref();
    if value["format"] == FILESYSTEM_IDENTITY_FORMAT {
        let expected: BTreeSet<&str> = [
            "format",
            "package",
            "sdk",
            "supportedProtocolVersions",
            "packageLockSha256",
            "discoveryResultSha256",
            "tools",
            "upstreamNotices",
        ]
        .into();
        if keys != expected {
            return refuse(
                "invalid_identity",
                "identity members differ from its format",
            );
        }
        if before.format != "mcp/tools-list-response" {
            return refuse(
                "identity_mismatch",
                "filesystem identity binds a JSON-RPC tools/list result",
            );
        }
        let declared = value["discoveryResultSha256"].as_str().unwrap_or("");
        if !is_digest(declared) {
            return refuse(
                "identity_incomplete",
                "discoveryResultSha256 missing or invalid",
            );
        }
        if declared != before.discovery_sha256 {
            return refuse(
                "identity_digest_mismatch",
                "before discovery result differs from discoveryResultSha256",
            );
        }
        checks.push(json!({"check": "discoveryResultSha256", "status": "verified"}));
        let Some(entries) = value["tools"].as_array() else {
            return refuse("identity_incomplete", "identity tools missing");
        };
        let mut seen = BTreeSet::new();
        for entry in entries {
            let complete = entry.as_object().is_some_and(|m| {
                m.len() == 3
                    && ["name", "inputSchemaSha256", "originalDefinitionSha256"]
                        .iter()
                        .all(|k| m.get(*k).is_some_and(Value::is_string))
            });
            if !complete {
                return refuse("identity_incomplete", "identity tool entry incomplete");
            }
            let name = entry["name"].as_str().unwrap_or("");
            let schema = entry["inputSchemaSha256"].as_str().unwrap_or("");
            let definition = entry["originalDefinitionSha256"].as_str().unwrap_or("");
            if !is_digest(schema) || !is_digest(definition) {
                return refuse("identity_incomplete", "identity tool digest invalid");
            }
            if !seen.insert(name.to_owned()) {
                return refuse("identity_incomplete", "identity repeats a tool");
            }
            let Some(tool) = before.tools.get(name) else {
                return refuse(
                    "identity_mismatch",
                    "identity names a tool absent from the before snapshot",
                );
            };
            if profile_author::digest(&tool["inputSchema"]) != schema
                || profile_author::digest(tool) != definition
            {
                return refuse(
                    "identity_digest_mismatch",
                    "before tool differs from its accepted identity",
                );
            }
        }
        if seen.len() != before.tools.len() {
            return refuse(
                "identity_incomplete",
                "identity does not cover every before tool",
            );
        }
        checks.push(json!({"check": "per_tool_inputSchemaSha256_and_originalDefinitionSha256", "status": "verified", "tools": seen.len()}));
        let notices = value["upstreamNotices"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if notices.len() > MAX_REFERENCED_FILES {
            return refuse("invalid_identity", "too many referenced files");
        }
        for notice in &notices {
            let (Some(path), Some(digest)) = (notice["path"].as_str(), notice["sha256"].as_str())
            else {
                return refuse("identity_incomplete", "upstream notice entry incomplete");
            };
            referenced.push(verify_referenced(dir, path, digest)?);
        }
        checks.push(json!({"check": "packageLockSha256", "status": "recorded_not_verified", "reason": "implicit reference without a declared path"}));
        Ok(IdentityCheck {
            file: FileIdentity::of(file),
            format: FILESYSTEM_IDENTITY_FORMAT,
            checks,
            referenced,
            per_tool: true,
        })
    } else if !object.contains_key("format") {
        let expected: BTreeSet<&str> = [
            "package",
            "version",
            "sdk",
            "protocol",
            "source",
            "python",
            "git_version",
            "git_source_url",
            "git_source_sha256",
            "files",
        ]
        .into();
        if keys != expected {
            return refuse("invalid_identity", "unsupported identity document");
        }
        let Some(files) = value["files"].as_object() else {
            return refuse("identity_incomplete", "identity files missing");
        };
        if files.len() > MAX_REFERENCED_FILES {
            return refuse("invalid_identity", "too many referenced files");
        }
        let Some(snapshot_digest) = files
            .get("upstream-tools-list.json")
            .and_then(Value::as_str)
        else {
            return refuse(
                "identity_incomplete",
                "identity does not pin upstream-tools-list.json",
            );
        };
        if snapshot_digest != before.file.raw_sha256 {
            return refuse(
                "identity_digest_mismatch",
                "before snapshot bytes differ from the pinned upstream-tools-list.json digest",
            );
        }
        checks.push(
            json!({"check": "files[upstream-tools-list.json] raw sha256", "status": "verified"}),
        );
        for (name, digest) in files {
            if Path::new(name).file_name().and_then(|n| n.to_str()) != Some(name.as_str()) {
                return refuse(
                    "invalid_referenced_path",
                    "identity files must be plain file names",
                );
            }
            let Some(digest) = digest.as_str() else {
                return refuse("identity_incomplete", "identity file digest missing");
            };
            if name == "upstream-tools-list.json" {
                referenced.push(json!({"path": name, "sha256": digest, "status": "verified_as_before_snapshot"}));
            } else {
                referenced.push(verify_referenced(dir, name, digest)?);
            }
        }
        Ok(IdentityCheck {
            file: FileIdentity::of(file),
            format: "git-readonly-upstream-identity (unversioned)",
            checks,
            referenced,
            per_tool: false,
        })
    } else {
        refuse("invalid_identity", "unsupported identity document format")
    }
}

// ---------------------------------------------------------------------------
// Operator-owned semantic declarations
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Sel {
    pub(crate) pointer: String,
    pub(crate) kind: String,
    pub(crate) optional: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ToolSemantics {
    pub(crate) reference: String,
    schema_sha256: String,
    action: String,
    result_provenance: Option<String>,
    capabilities: BTreeMap<String, String>,
    pub(crate) resources: BTreeSet<Sel>,
    pub(crate) destinations: BTreeSet<Sel>,
}

impl ToolSemantics {
    fn json(&self) -> Value {
        let sels = |s: &BTreeSet<Sel>| {
            s.iter()
                .map(|s| json!({"pointer": s.pointer, "kind": s.kind, "optional": s.optional}))
                .collect::<Vec<_>>()
        };
        json!({
            "reference": self.reference, "schema_sha256": self.schema_sha256,
            "action": self.action, "result_provenance": self.result_provenance,
            "capabilities": self.capabilities, "resources": sels(&self.resources),
            "destinations": sels(&self.destinations),
        })
    }
}

pub(crate) struct Declared {
    file: FileIdentity,
    format: &'static str,
    id: String,
    pub(crate) tools: BTreeMap<String, ToolSemantics>,
}

fn selector(value: &Value, reference: &str) -> R<Sel> {
    let pointer = value["pointer"].as_str().unwrap_or_default();
    if !pointer.starts_with('/') || pointer_tokens(pointer).is_none() {
        return refuse(
            "invalid_declarations",
            format!("{reference}: selector pointer is not RFC 6901"),
        );
    }
    Ok(Sel {
        pointer: pointer.to_owned(),
        kind: value["kind"].as_str().unwrap_or("unknown").to_owned(),
        optional: value["optional"].as_bool().unwrap_or(false),
    })
}

fn load_registry(file: &InputFile, role: &str) -> R<Declared> {
    let value = parse_strict(file, MAX_DECLARATION_BYTES, role)?;
    if serde_json::from_value::<crate::native::Registry>(value.clone()).is_err()
        || value["contract_version"] != crate::native::CONTRACT
    {
        return refuse(
            "invalid_declarations",
            format!("{role}: not a {} native registry", crate::native::CONTRACT),
        );
    }
    let id = value["registry_id"].as_str().unwrap_or_default().to_owned();
    let mut tools = BTreeMap::new();
    let entries = value["tools"].as_array().cloned().unwrap_or_default();
    if entries.len() > 256 {
        return refuse("invalid_declarations", format!("{role}: too many tools"));
    }
    for (index, tool) in entries.iter().enumerate() {
        let reference = format!("{role}:tools[{index}]");
        let name = tool["name"].as_str().unwrap_or_default().to_owned();
        let schema = tool["schema_sha256"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if !tool_name_ok(&name) || !is_digest(&schema) {
            return refuse(
                "invalid_declarations",
                format!("{reference}: invalid tool name or schema_sha256"),
            );
        }
        let mut resources = BTreeSet::new();
        let mut destinations = BTreeSet::new();
        for egress in tool["egress"].as_array().into_iter().flatten() {
            destinations.insert(selector(egress, &reference)?);
        }
        let mut capabilities = BTreeMap::new();
        for key in ["mcp_result_profile", "workspace_profile"] {
            if let Some(v) = tool[key].as_str() {
                capabilities.insert(key.to_owned(), v.to_owned());
            }
        }
        let policy = &tool["resource_policy"];
        if policy.is_object() {
            for sel in policy["profile"]["selectors"]
                .as_array()
                .into_iter()
                .flatten()
            {
                let sel = selector(sel, &reference)?;
                if sel.kind == "path" {
                    resources.insert(sel);
                } else {
                    destinations.insert(sel);
                }
            }
            let binding = &policy["binding"];
            for key in ["path_selector", "content_selector"] {
                if let Some(pointer) = binding[key].as_str() {
                    resources.insert(selector(
                        &json!({"pointer": pointer, "kind": key}),
                        &reference,
                    )?);
                }
            }
            if let Some(operation) = policy["execution"]["operation"].as_str() {
                capabilities.insert("execution_operation".into(), operation.to_owned());
            }
            if let Some(operation) = binding["operation"].as_str() {
                capabilities.insert("binding_operation".into(), operation.to_owned());
            }
            for key in ["network", "post", "windows_read", "macos_read"] {
                if !policy[key].is_null() {
                    capabilities.insert(format!("resource_policy.{key}"), "present".into());
                }
            }
        }
        let semantics = ToolSemantics {
            reference,
            schema_sha256: schema,
            action: tool["action_class"].as_str().unwrap_or_default().to_owned(),
            result_provenance: tool["result_provenance"].as_str().map(str::to_owned),
            capabilities,
            resources,
            destinations,
        };
        if tools.insert(name, semantics).is_some() {
            return refuse("invalid_declarations", format!("{role}: duplicate tool"));
        }
    }
    Ok(Declared {
        file: FileIdentity::of(file),
        format: crate::native::CONTRACT,
        id,
        tools,
    })
}

fn load_operator_declarations(file: &InputFile, before: &Snapshot) -> R<Declared> {
    let value = parse_strict(file, MAX_DECLARATION_BYTES, "declarations")?;
    if profile_author::validate_declaration_document(&value).is_err() {
        return refuse(
            "invalid_declarations",
            format!("declarations: not a {DECLARATION_FORMAT} document"),
        );
    }
    if value["snapshot_sha256"].as_str() != Some(before.discovery_sha256.as_str())
        || before.format != DISCOVERY_FORMAT
        || value["server_id"] != before.value["server_id"]
        || value["server_version"] != before.value["server_version"]
    {
        return refuse(
            "declaration_binding_mismatch",
            "declarations are not bound to this exact before discovery snapshot",
        );
    }
    let mut tools = BTreeMap::new();
    for (index, tool) in value["tools"].as_array().into_iter().flatten().enumerate() {
        let reference = format!("declarations:tools[{index}]");
        let name = tool["name"].as_str().unwrap_or_default().to_owned();
        let kind = tool["authority"]["kind"].as_str().unwrap_or("");
        let reviewed = tool["reviewed"] == true;
        let mut resources = BTreeSet::new();
        let mut destinations = BTreeSet::new();
        // Mirrors the selectors `profile_author::policy_for` derives per authority.
        match kind {
            "create_file" | "read_document" => {
                resources.insert(Sel {
                    pointer: "/path".into(),
                    kind: "path".into(),
                    optional: false,
                });
            }
            "https_get" => {
                destinations.insert(Sel {
                    pointer: "/url".into(),
                    kind: "url".into(),
                    optional: false,
                });
            }
            _ => {}
        }
        let semantics = ToolSemantics {
            reference,
            schema_sha256: tool["schema_sha256"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            action: if reviewed {
                format!("authority:{kind}")
            } else {
                "unreviewed".into()
            },
            result_provenance: None,
            capabilities: BTreeMap::new(),
            resources,
            destinations,
        };
        if tools.insert(name, semantics).is_some() {
            return refuse("invalid_declarations", "declarations repeat a tool");
        }
    }
    Ok(Declared {
        file: FileIdentity::of(file),
        format: DECLARATION_FORMAT,
        id: value["registry_id"].as_str().unwrap_or_default().to_owned(),
        tools,
    })
}

fn bind_declarations(declared: &Declared, snapshot: &Snapshot, role: &str) -> R<()> {
    for (name, semantics) in &declared.tools {
        let Some(tool) = snapshot.tools.get(name) else {
            return refuse(
                "declaration_unknown_tool",
                format!(
                    "{role}: {} names a tool absent from its snapshot",
                    semantics.reference
                ),
            );
        };
        if profile_author::digest(&tool["inputSchema"]) != semantics.schema_sha256 {
            return refuse(
                "declaration_binding_mismatch",
                format!(
                    "{role}: {} is bound to a different schema identity",
                    semantics.reference
                ),
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Findings and diff
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Nature {
    InertMetadata,
    ReviewRequired,
    Unsupported,
    /// Not a property of the change itself: a current declaration is bound to
    /// the before identity and must be re-reviewed for the new one.
    Requalification,
}

impl Nature {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Nature::InertMetadata => "inert_metadata",
            Nature::ReviewRequired => "review_required",
            Nature::Unsupported => "unsupported",
            Nature::Requalification => "requalification_required",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Finding {
    pub(crate) id: String,
    pub(crate) tool: String,
    pub(crate) area: &'static str,
    pub(crate) pointer: String,
    pub(crate) argument_pointer: Option<String>,
    pub(crate) kind: &'static str,
    pub(crate) nature: Nature,
    pub(crate) before: Option<Value>,
    pub(crate) after: Option<Value>,
    pub(crate) detail: Value,
    pub(crate) reasons: Vec<String>,
    pub(crate) declaration_refs: Vec<String>,
    pub(crate) example_ids: Vec<String>,
}

impl Finding {
    pub(crate) fn json(&self) -> Value {
        json!({
            "id": self.id, "tool": self.tool, "area": self.area, "pointer": self.pointer,
            "argument_pointer": self.argument_pointer, "kind": self.kind,
            "nature": self.nature.as_str(),
            "before": self.before, "after": self.after,
            "detail": self.detail, "review_reasons": self.reasons,
            "declaration_refs": self.declaration_refs, "example_ids": self.example_ids,
        })
    }
}

#[derive(Clone, Copy)]
struct Place<'a> {
    tool: &'a str,
    area: &'static str,
    pointer: &'a str,
    argument: Option<&'a str>,
}

impl<'a> Place<'a> {
    fn child(&self, pointer: &'a str, argument: Option<&'a str>) -> Place<'a> {
        Place {
            tool: self.tool,
            area: self.area,
            pointer,
            argument,
        }
    }
}

struct Diff {
    findings: Vec<Finding>,
    steps: usize,
    truncated: usize,
}

const SUPPORTED_GENERIC: [&str; 6] = ["type", "title", "description", "default", "enum", "const"];

fn reason(kind: &str) -> &'static str {
    match kind {
        "tool_metadata_changed" | "schema_metadata_changed" | "enum_order_changed" => {
            "Model-visible metadata changed. It is untrusted text and does not change validation \
or permission, but the new exact identity is unaccepted."
        }
        "behavior_hint_changed" => {
            "Untrusted server behavior hint changed. Hints never grant, widen or prove permission; \
verify actual behavior in the implementation."
        }
        "capability_changed" => {
            "Tool execution capability metadata changed; confirm the runtime and host handle it."
        }
        "result_shape_added" | "result_shape_removed" => {
            "Result shape contract changed; result inspection and output budgets must be re-qualified."
        }
        "field_added" => {
            "New argument accepted by the original schema; its semantics are unknown to the analyzer."
        }
        "field_removed" | "required_field_removed" => {
            "Argument removed; callers, declarations and selectors referencing it must be reviewed."
        }
        "required_added" => "Argument became required; previously valid invocations are now refused.",
        "required_removed" => {
            "Argument is no longer required; the server may apply an implicit value when omitted."
        }
        "type_changed" | "nullable_added" | "nullable_removed" => {
            "Accepted value type changed; enforcement and declared selectors assume the old type."
        }
        "enum_values_added" | "enum_added" | "enum_removed" | "const_changed" => {
            "Set of admitted literal values changed; new values may select new behavior."
        }
        "enum_values_removed" => "Literal values were withdrawn; previously valid calls are refused.",
        "default_changed" => {
            "Server-applied default changed. Runtime validation never applies defaults, so the \
effective behavior of an omitted argument changed without any visible argument."
        }
        "constraint_changed" => "Length or item bounds changed.",
        "additional_properties_changed" => {
            "Object openness changed; undeclared arguments may be admitted by the original schema."
        }
        "items_changed" => "Array item schema was added or removed.",
        "dialect_changed" => "JSON Schema dialect changed; keyword semantics may differ.",
        "unsupported_construct_changed"
        | "unsupported_construct_added"
        | "unsupported_construct_removed"
        | "unsupported_schema_form"
        | "unsupported_member_changed" => {
            "Change is outside the supported analysis subset; its effect is unknown and requires \
manual semantic review."
        }
        "schema_outside_runtime_subset" => {
            "After schema is outside the runtime-supported input subset; examples cannot be verified."
        }
        "tool_added" => {
            "New tool. It has no accepted identity, no declaration and no permission; permission is \
never inferred from its name or description."
        }
        "tool_removed" => "Tool removed; declarations, policies and qualifications referencing it are stale.",
        "tool_order_changed" => {
            "Tool list order changed. No per-tool finding results, but the discovery identity and \
raw digest are new and unaccepted."
        }
        "declaration_binding_stale" => {
            "The current declaration is bound to the before schema identity. The after identity is \
unaccepted until a new declaration is reviewed and the profile re-qualified."
        }
        "declared_tool_removed" => "A declared tool disappeared; its declaration must be withdrawn.",
        "undeclared_tool_added" => {
            "No current declaration covers this new tool; it has no action, resource or destination \
semantics and no permission."
        }
        "declared_selector_unbound" => {
            "A declared resource/destination selector no longer addresses a schema field."
        }
        "declared_selector_target_changed" => {
            "The schema addressed by a declared resource/destination selector changed."
        }
        "declared_selector_requirement_relaxed" => {
            "A declared non-optional resource/destination selector addresses a field that may now be omitted; the declaration assumes it is always present."
        }
        _ => "Declared semantics differ between the current and proposed declarations.",
    }
}

impl Diff {
    fn step(&mut self, depth: usize) -> R<()> {
        self.steps += 1;
        if self.steps > MAX_DIFF_STEPS || depth > MAX_DOCUMENT_DEPTH {
            return refuse(
                "traversal_exceeded",
                format!("diff exceeds {MAX_DIFF_STEPS} steps or depth {MAX_DOCUMENT_DEPTH}"),
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        place: Place<'_>,
        kind: &'static str,
        nature: Nature,
        before: Option<&Value>,
        after: Option<&Value>,
        detail: Value,
    ) {
        if self.findings.len() >= MAX_FINDINGS {
            self.truncated += 1;
            return;
        }
        self.findings.push(Finding {
            id: String::new(),
            tool: place.tool.to_owned(),
            area: place.area,
            pointer: place.pointer.to_owned(),
            argument_pointer: place.argument.map(str::to_owned),
            kind,
            nature,
            // Only bounded excerpts are retained, never whole subtrees.
            before: before.map(excerpt),
            after: after.map(excerpt),
            detail,
            reasons: vec![reason(kind).to_owned()],
            declaration_refs: vec![],
            example_ids: vec![],
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn push_refs(
        &mut self,
        place: Place<'_>,
        kind: &'static str,
        nature: Nature,
        before: Option<&Value>,
        after: Option<&Value>,
        detail: Value,
        refs: &[String],
    ) {
        let count = self.findings.len();
        self.push(place, kind, nature, before, after, detail);
        if self.findings.len() > count {
            self.findings.last_mut().expect("pushed").declaration_refs = refs.to_vec();
        }
    }

    /// Unsupported constructs inside a whole added or removed subtree are
    /// findings of their own, never hidden behind the add/remove finding.
    fn flag_subtree(&mut self, place: Place<'_>, node: &Value, added: bool, root: bool) {
        let mut found = Vec::new();
        scan_unsupported(node, place.pointer, 0, root, &mut found);
        for (pointer, keyword) in found {
            self.push(
                place.child(&pointer, None),
                if added {
                    "unsupported_construct_added"
                } else {
                    "unsupported_construct_removed"
                },
                Nature::Unsupported,
                None,
                None,
                json!({"keyword": keyword, "subtree": place.pointer, "reference_resolved": false}),
            );
        }
    }

    fn flag_tool(&mut self, name: &str, tool: &Value, added: bool) {
        let input = Place {
            tool: name,
            area: "input",
            pointer: "/inputSchema",
            argument: None,
        };
        self.flag_subtree(input, &tool["inputSchema"], added, true);
        if let Some(output) = tool.get("outputSchema") {
            self.flag_subtree(result_place(name), output, added, true);
        }
    }

    fn diff_tool(&mut self, name: &str, before: &Value, after: &Value) -> R<()> {
        let (b, a) = (before.as_object(), after.as_object());
        let (Some(b), Some(a)) = (b, a) else {
            return Ok(());
        };
        let keys: BTreeSet<&String> = b.keys().chain(a.keys()).collect();
        let tool = Place {
            tool: name,
            area: "tool",
            pointer: "",
            argument: None,
        };
        for key in keys {
            let (bv, av) = (b.get(key), a.get(key));
            if bv == av {
                continue;
            }
            let pointer = format!("/{}", escape_token(key));
            match key.as_str() {
                "title" | "description" => self.push(
                    tool.child(&pointer, None),
                    "tool_metadata_changed",
                    Nature::InertMetadata,
                    bv,
                    av,
                    json!({"member": key, "untrusted_text": true}),
                ),
                "inputSchema" => {
                    let place = Place {
                        tool: name,
                        area: "input",
                        pointer: "/inputSchema",
                        argument: Some(""),
                    };
                    self.diff_node(place, &b[key], &a[key], 1)?;
                }
                "outputSchema" => match (bv, av) {
                    (Some(bv), Some(av)) => {
                        let place = Place {
                            tool: name,
                            area: "result",
                            pointer: "/outputSchema",
                            argument: None,
                        };
                        self.diff_node(place, bv, av, 1)?;
                    }
                    (None, Some(added)) => {
                        self.push(
                            tool.child(&pointer, None),
                            "result_shape_added",
                            Nature::ReviewRequired,
                            None,
                            av,
                            json!({}),
                        );
                        self.flag_subtree(result_place(name), added, true, true);
                    }
                    (Some(removed), _) => {
                        self.push(
                            tool.child(&pointer, None),
                            "result_shape_removed",
                            Nature::ReviewRequired,
                            bv,
                            None,
                            json!({}),
                        );
                        self.flag_subtree(result_place(name), removed, false, true);
                    }
                    (None, None) => {}
                },
                "annotations" | "execution" => {
                    let empty = Map::new();
                    let bm = bv.and_then(Value::as_object).unwrap_or(&empty);
                    let am = av.and_then(Value::as_object).unwrap_or(&empty);
                    let inner: BTreeSet<&String> = bm.keys().chain(am.keys()).collect();
                    for k in inner {
                        if bm.get(k) == am.get(k) {
                            continue;
                        }
                        let p = format!("{pointer}/{}", escape_token(k));
                        let (kind, nature) = match (key.as_str(), k.as_str()) {
                            ("annotations", "title") => {
                                ("tool_metadata_changed", Nature::InertMetadata)
                            }
                            ("annotations", _) => ("behavior_hint_changed", Nature::ReviewRequired),
                            _ => ("capability_changed", Nature::ReviewRequired),
                        };
                        self.push(
                            tool.child(&p, None),
                            kind,
                            nature,
                            bm.get(k),
                            am.get(k),
                            json!({"member": key, "key": k, "grants_permission": false}),
                        );
                    }
                }
                _ => self.push(
                    tool.child(&pointer, None),
                    "unsupported_member_changed",
                    Nature::Unsupported,
                    bv,
                    av,
                    json!({"member": key, "known_member": TOOL_MEMBERS.contains(&key.as_str())}),
                ),
            }
        }
        Ok(())
    }

    fn diff_node(
        &mut self,
        place: Place<'_>,
        before: &Value,
        after: &Value,
        depth: usize,
    ) -> R<()> {
        self.step(depth)?;
        if before == after {
            return Ok(());
        }
        let (Some(b), Some(a)) = (before.as_object(), after.as_object()) else {
            self.push(
                place,
                "unsupported_schema_form",
                Nature::Unsupported,
                Some(before),
                Some(after),
                json!({"reason": "non-object schema"}),
            );
            return Ok(());
        };
        let keys: BTreeSet<&String> = b.keys().chain(a.keys()).collect();
        for key in keys {
            let (bv, av) = (b.get(key), a.get(key));
            if bv == av {
                continue;
            }
            let pointer = format!("{}/{}", place.pointer, escape_token(key));
            let here = place.child(&pointer, place.argument);
            match key.as_str() {
                "type" => self.diff_type(here, bv, av),
                "properties" => self.diff_properties(place, b, a, depth)?,
                "required" => self.diff_required(place, b, a),
                "additionalProperties" => {
                    let open = |v: Option<&Value>| match v {
                        None | Some(Value::Bool(true)) => Some(true),
                        Some(Value::Bool(false)) => Some(false),
                        _ => None,
                    };
                    match (open(bv), open(av)) {
                        (Some(bo), Some(ao)) => self.push(
                            here,
                            "additional_properties_changed",
                            Nature::ReviewRequired,
                            bv,
                            av,
                            json!({"before_open": bo, "after_open": ao,
                                   "direction": if ao { "opened" } else { "closed" }}),
                        ),
                        _ => self.push(
                            here,
                            "unsupported_construct_changed",
                            Nature::Unsupported,
                            bv,
                            av,
                            json!({"keyword": key, "reason": "schema-valued additionalProperties"}),
                        ),
                    }
                }
                "items" => match (bv, av) {
                    (Some(bi), Some(ai)) if bi.is_object() && ai.is_object() => {
                        let argument = place.argument.map(|p| format!("{p}/0"));
                        self.diff_node(
                            place.child(&pointer, argument.as_deref()),
                            bi,
                            ai,
                            depth + 1,
                        )?;
                    }
                    (Some(bi), Some(ai)) if bi.is_array() || ai.is_array() => self.push(
                        here,
                        "unsupported_construct_changed",
                        Nature::Unsupported,
                        bv,
                        av,
                        json!({"keyword": key, "reason": "tuple-form items are positional"}),
                    ),
                    _ => {
                        self.push(
                            here,
                            "items_changed",
                            Nature::ReviewRequired,
                            bv,
                            av,
                            json!({}),
                        );
                        if let Some(node) = av.or(bv) {
                            self.flag_subtree(here, node, av.is_some(), false);
                        }
                    }
                },
                "enum" => self.diff_enum(here, bv, av),
                "const" => self.push(
                    here,
                    "const_changed",
                    Nature::ReviewRequired,
                    bv,
                    av,
                    json!({}),
                ),
                "default" => self.push(
                    here,
                    "default_changed",
                    Nature::ReviewRequired,
                    bv,
                    av,
                    json!({"applied_by_runtime": false}),
                ),
                "minLength" | "maxLength" | "minItems" | "maxItems" => {
                    let n = |v: Option<&Value>| v.map(|v| v.as_u64());
                    let (bn, an) = (n(bv), n(av));
                    if matches!(bn, Some(None)) || matches!(an, Some(None)) {
                        self.push(
                            here,
                            "unsupported_construct_changed",
                            Nature::Unsupported,
                            bv,
                            av,
                            json!({"keyword": key, "reason": "non-integer bound"}),
                        );
                        continue;
                    }
                    let (bn, an) = (bn.flatten(), an.flatten());
                    let is_min = key.starts_with("min");
                    let tightened = match (bn, an) {
                        (Some(x), Some(y)) => (y > x) == is_min,
                        (None, Some(_)) => true,
                        _ => false,
                    };
                    self.push(
                        here,
                        "constraint_changed",
                        Nature::ReviewRequired,
                        bv,
                        av,
                        json!({"keyword": key,
                               "direction": if tightened { "tightened" } else { "loosened" }}),
                    );
                }
                "title" | "description" => self.push(
                    here,
                    "schema_metadata_changed",
                    Nature::InertMetadata,
                    bv,
                    av,
                    json!({"keyword": key, "untrusted_text": true}),
                ),
                "$schema" if depth == 1 => self.push(
                    here,
                    "dialect_changed",
                    Nature::ReviewRequired,
                    bv,
                    av,
                    json!({}),
                ),
                other => {
                    let reference = matches!(other, "$ref" | "$defs" | "definitions" | "$id");
                    self.push(
                        here,
                        "unsupported_construct_changed",
                        Nature::Unsupported,
                        bv,
                        av,
                        json!({"keyword": other, "reference_resolved": false,
                        "reason": if reference {
                            "references are never resolved or retrieved"
                        } else {
                            "keyword outside the supported subset"
                        }}),
                    );
                }
            }
        }
        Ok(())
    }

    fn diff_type(&mut self, place: Place<'_>, before: Option<&Value>, after: Option<&Value>) {
        let set = |v: Option<&Value>| -> Option<BTreeSet<String>> {
            match v {
                None => Some(BTreeSet::new()),
                Some(Value::String(s)) => Some([s.clone()].into()),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|i| i.as_str().map(str::to_owned))
                    .collect(),
                _ => None,
            }
        };
        let (Some(b), Some(a)) = (set(before), set(after)) else {
            self.push(
                place,
                "unsupported_construct_changed",
                Nature::Unsupported,
                before,
                after,
                json!({"keyword": "type", "reason": "non-string type"}),
            );
            return;
        };
        if b == a {
            // Only the representation of the same type set changed.
            self.push(
                place,
                "schema_metadata_changed",
                Nature::InertMetadata,
                before,
                after,
                json!({"keyword": "type", "same_type_set": true}),
            );
            return;
        }
        let without_null = |s: &BTreeSet<String>| {
            s.iter()
                .filter(|t| *t != "null")
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        let kind = if without_null(&b) == without_null(&a) {
            if a.contains("null") {
                "nullable_added"
            } else {
                "nullable_removed"
            }
        } else {
            "type_changed"
        };
        self.push(
            place,
            kind,
            Nature::ReviewRequired,
            before,
            after,
            json!({"before_types": b, "after_types": a}),
        );
    }

    fn diff_properties(
        &mut self,
        place: Place<'_>,
        b: &Map<String, Value>,
        a: &Map<String, Value>,
        depth: usize,
    ) -> R<()> {
        let empty = Map::new();
        let (bp, ap) = (&b.get("properties"), &a.get("properties"));
        let pointer = format!("{}/properties", place.pointer);
        let (Some(bp), Some(ap)) = (
            bp.map_or(Some(&empty), Value::as_object),
            ap.map_or(Some(&empty), Value::as_object),
        ) else {
            self.push(
                place.child(&pointer, place.argument),
                "unsupported_construct_changed",
                Nature::Unsupported,
                b.get("properties"),
                a.get("properties"),
                json!({"keyword": "properties", "reason": "non-object properties"}),
            );
            return Ok(());
        };
        let required = |m: &Map<String, Value>| -> BTreeSet<String> {
            m.get("required")
                .and_then(Value::as_array)
                .map(|r| {
                    r.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let (breq, areq) = (required(b), required(a));
        let names: BTreeSet<&String> = bp.keys().chain(ap.keys()).collect();
        for name in names {
            let child = format!("{pointer}/{}", escape_token(name));
            let argument = place
                .argument
                .map(|p| format!("{p}/{}", escape_token(name)));
            let here = place.child(&child, argument.as_deref());
            match (bp.get(name), ap.get(name)) {
                (None, Some(av)) => {
                    self.push(
                        here,
                        "field_added",
                        Nature::ReviewRequired,
                        None,
                        Some(av),
                        json!({"field": name, "required_in_after": areq.contains(name),
                            "added_leaf_pointers": leaf_pointers(av, argument.as_deref().unwrap_or(""))}),
                    );
                    self.flag_subtree(here, av, true, false);
                }
                (Some(bv), None) => {
                    let was_required = breq.contains(name);
                    self.push(
                        here,
                        if was_required {
                            "required_field_removed"
                        } else {
                            "field_removed"
                        },
                        Nature::ReviewRequired,
                        Some(bv),
                        None,
                        json!({"field": name, "required_in_before": was_required}),
                    );
                    self.flag_subtree(here, bv, false, false);
                }
                (Some(bv), Some(av)) => self.diff_node(here, bv, av, depth + 1)?,
                (None, None) => {}
            }
        }
        Ok(())
    }

    fn diff_required(&mut self, place: Place<'_>, b: &Map<String, Value>, a: &Map<String, Value>) {
        let pointer = format!("{}/required", place.pointer);
        let list = |m: &Map<String, Value>| -> Option<Vec<String>> {
            match m.get("required") {
                None => Some(vec![]),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|v| v.as_str().map(str::to_owned))
                    .collect(),
                _ => None,
            }
        };
        let (Some(bl), Some(al)) = (list(b), list(a)) else {
            self.push(
                place.child(&pointer, place.argument),
                "unsupported_construct_changed",
                Nature::Unsupported,
                b.get("required"),
                a.get("required"),
                json!({"keyword": "required", "reason": "non-string required entries"}),
            );
            return;
        };
        let (bs, as_): (BTreeSet<_>, BTreeSet<_>) =
            (bl.iter().cloned().collect(), al.iter().cloned().collect());
        let after_props = a.get("properties").and_then(Value::as_object);
        for name in as_.difference(&bs) {
            let argument = place
                .argument
                .map(|p| format!("{p}/{}", escape_token(name)));
            self.push(
                place.child(&pointer, argument.as_deref()),
                "required_added",
                Nature::ReviewRequired,
                None,
                Some(&json!(name)),
                json!({"field": name}),
            );
        }
        for name in bs.difference(&as_) {
            // Removal of the property itself is reported as required_field_removed.
            if after_props.is_some_and(|p| p.contains_key(name)) {
                let argument = place
                    .argument
                    .map(|p| format!("{p}/{}", escape_token(name)));
                self.push(
                    place.child(&pointer, argument.as_deref()),
                    "required_removed",
                    Nature::ReviewRequired,
                    Some(&json!(name)),
                    None,
                    json!({"field": name}),
                );
            }
        }
        if bs == as_ && bl != al {
            // `required` is a set; order and duplicates carry no validation meaning.
            self.push(
                place.child(&pointer, place.argument),
                "schema_metadata_changed",
                Nature::InertMetadata,
                b.get("required"),
                a.get("required"),
                json!({"keyword": "required", "same_set": true}),
            );
        }
    }

    fn diff_enum(&mut self, place: Place<'_>, before: Option<&Value>, after: Option<&Value>) {
        let set = |v: Option<&Value>| -> Option<Option<BTreeMap<String, Value>>> {
            match v {
                None => Some(None),
                Some(Value::Array(items)) => Some(Some(
                    items
                        .iter()
                        .map(|i| (canonical_json(i), i.clone()))
                        .collect(),
                )),
                _ => None,
            }
        };
        let (Some(b), Some(a)) = (set(before), set(after)) else {
            self.push(
                place,
                "unsupported_construct_changed",
                Nature::Unsupported,
                before,
                after,
                json!({"keyword": "enum", "reason": "non-array enum"}),
            );
            return;
        };
        match (b, a) {
            (None, Some(_)) => self.push(
                place,
                "enum_added",
                Nature::ReviewRequired,
                before,
                after,
                json!({"direction": "restricted"}),
            ),
            (Some(_), None) => self.push(
                place,
                "enum_removed",
                Nature::ReviewRequired,
                before,
                after,
                json!({"direction": "unrestricted"}),
            ),
            (Some(b), Some(a)) => {
                let added: Vec<&Value> = a
                    .iter()
                    .filter(|(k, _)| !b.contains_key(*k))
                    .map(|(_, v)| v)
                    .collect();
                let removed: Vec<&Value> = b
                    .iter()
                    .filter(|(k, _)| !a.contains_key(*k))
                    .map(|(_, v)| v)
                    .collect();
                if !added.is_empty() {
                    self.push(
                        place,
                        "enum_values_added",
                        Nature::ReviewRequired,
                        before,
                        after,
                        json!({"values": added}),
                    );
                }
                if !removed.is_empty() {
                    self.push(
                        place,
                        "enum_values_removed",
                        Nature::ReviewRequired,
                        before,
                        after,
                        json!({"values": removed}),
                    );
                }
                if added.is_empty() && removed.is_empty() {
                    self.push(
                        place,
                        "enum_order_changed",
                        Nature::InertMetadata,
                        before,
                        after,
                        json!({"same_set": true}),
                    );
                }
            }
            (None, None) => {}
        }
    }
}

/// Argument pointers of every leaf in an added subtree (bounded), so nested
/// additions such as a new nested destination field are individually visible.
fn leaf_pointers(schema: &Value, prefix: &str) -> Vec<String> {
    fn walk(node: &Value, pointer: String, depth: usize, out: &mut Vec<String>) {
        if out.len() >= 32 || depth > MAX_DOCUMENT_DEPTH {
            return;
        }
        if let Some(props) = node.get("properties").and_then(Value::as_object) {
            for (name, child) in props {
                walk(
                    child,
                    format!("{pointer}/{}", escape_token(name)),
                    depth + 1,
                    out,
                );
            }
        } else if let Some(items) = node.get("items").filter(|i| i.is_object()) {
            walk(items, format!("{pointer}/0"), depth + 1, out);
        } else {
            out.push(pointer);
        }
    }
    let mut out = Vec::new();
    walk(schema, prefix.to_owned(), 0, &mut out);
    out
}

/// Keywords outside the supported subset, with exact pointers. Bounded and
/// non-resolving: a `$ref` is reported, never followed.
pub(crate) fn scan_unsupported(
    node: &Value,
    pointer: &str,
    depth: usize,
    root: bool,
    out: &mut Vec<(String, String)>,
) {
    if depth > MAX_DOCUMENT_DEPTH || out.len() >= MAX_COVERAGE_ENTRIES {
        return;
    }
    let Some(map) = node.as_object() else {
        out.push((pointer.to_owned(), "<non-object schema>".into()));
        return;
    };
    let kinds: BTreeSet<&str> = match &map.get("type") {
        Some(Value::String(s)) => [s.as_str()].into(),
        Some(Value::Array(items)) => {
            out.push((format!("{pointer}/type"), "type (union array)".into()));
            items.iter().filter_map(Value::as_str).collect()
        }
        Some(_) => {
            out.push((format!("{pointer}/type"), "type (non-string)".into()));
            BTreeSet::new()
        }
        None => {
            out.push((pointer.to_owned(), "missing type".into()));
            BTreeSet::new()
        }
    };
    for key in map.keys() {
        let supported = SUPPORTED_GENERIC.contains(&key.as_str())
            || (kinds.contains("object")
                && matches!(
                    key.as_str(),
                    "properties" | "required" | "additionalProperties"
                ))
            || (root && key == "$schema")
            || (kinds.contains("array")
                && matches!(key.as_str(), "items" | "minItems" | "maxItems"))
            || (kinds.contains("string") && matches!(key.as_str(), "minLength" | "maxLength"));
        if !supported {
            out.push((format!("{pointer}/{}", escape_token(key)), key.clone()));
        }
    }
    if let Some(props) = map.get("properties").and_then(Value::as_object) {
        for (name, child) in props {
            scan_unsupported(
                child,
                &format!("{pointer}/properties/{}", escape_token(name)),
                depth + 1,
                false,
                out,
            );
        }
    }
    if let Some(items) = map.get("items").filter(|v| v.is_object()) {
        scan_unsupported(items, &format!("{pointer}/items"), depth + 1, false, out);
    }
}

fn result_place(tool: &str) -> Place<'_> {
    Place {
        tool,
        area: "result",
        pointer: "/outputSchema",
        argument: None,
    }
}

/// Whether the field an argument pointer addresses is listed in its parent's `required`.
pub(crate) fn required_at(schema: &Value, pointer: &str) -> bool {
    let Some(tokens) = pointer_tokens(pointer) else {
        return false;
    };
    let Some((last, parents)) = tokens.split_last() else {
        return false;
    };
    let parent: String = parents
        .iter()
        .map(|t| format!("/{}", escape_token(t)))
        .collect();
    schema_at(schema, &parent)
        .and_then(|p| p["required"].as_array())
        .is_some_and(|r| r.iter().any(|v| v == last.as_str()))
}

/// Schema node addressed by an argument pointer, walking `properties`/`items`.
pub(crate) fn schema_at<'a>(schema: &'a Value, argument_pointer: &str) -> Option<&'a Value> {
    let mut node = schema;
    for token in pointer_tokens(argument_pointer)? {
        let is_array = node["type"] == "array"
            || node["type"]
                .as_array()
                .is_some_and(|t| t.iter().any(|v| v == "array"));
        node = if is_array {
            node.get("items")?
        } else {
            node.get("properties")?.get(&token)?
        };
    }
    Some(node)
}

fn subset(schema: Option<&Value>, role: Role) -> Value {
    match schema {
        None => json!({"status": "absent"}),
        Some(schema) => {
            let result = match role {
                Role::Arguments => InputSchema::read_selected(schema),
                Role::Result => InputSchema::read_selected_role(schema, role),
            };
            match result {
                Ok(_) => json!({"status": "supported"}),
                // Fixed validator vocabulary; never input content.
                Err(error) => json!({"status": "unsupported", "reason": error.to_string()}),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

pub(crate) struct Analysis<'a> {
    pub(crate) before: &'a Snapshot,
    pub(crate) after: &'a Snapshot,
    pub(crate) current: Option<&'a Declared>,
    pub(crate) findings: Vec<Finding>,
}

fn label(text: &Option<String>) -> R<Option<String>> {
    match text {
        Some(t) if t.len() > MAX_LABEL_BYTES => refuse(
            "invalid_label",
            format!("label exceeds {MAX_LABEL_BYTES} bytes"),
        ),
        other => Ok(other.clone()),
    }
}

fn need(file: &Option<InputFile>, role: &str) -> R<InputFile> {
    file.clone().ok_or_else(|| Refusal {
        code: "missing_input",
        detail: format!("{role} snapshot is required"),
    })
}

pub fn analyze(request: &Request) -> Result<Outcome, Refusal> {
    let before = load_snapshot(&need(&request.before, "before")?, "before")?;
    let after = load_snapshot(&need(&request.after, "after")?, "after")?;
    let before_label = label(&request.before_label)?;
    let after_label = label(&request.after_label)?;
    let identity = request
        .before_identity
        .as_ref()
        .map(|f| verify_identity(f, &before))
        .transpose()?;
    let declared_inputs = request.registry.is_some() || request.declarations.is_some();
    if !declared_inputs && !request.snapshot_only {
        return refuse(
            "missing_declarations",
            "the current operator-owned declarations are required (--registry or --declarations); --snapshot-only compares snapshots without semantic review",
        );
    }
    if request.snapshot_only && (declared_inputs || request.proposed_registry.is_some()) {
        return refuse(
            "invalid_arguments",
            "--snapshot-only excludes current and proposed declarations",
        );
    }
    let current = match (&request.registry, &request.declarations) {
        (Some(_), Some(_)) => {
            return refuse(
                "invalid_arguments",
                "supply either --registry or --declarations, not both",
            )
        }
        (Some(file), None) => Some(load_registry(file, "registry")?),
        (None, Some(file)) => Some(load_operator_declarations(file, &before)?),
        (None, None) => None,
    };
    if let Some(declared) = &current {
        bind_declarations(declared, &before, "current declarations")?;
    }
    let proposed = request
        .proposed_registry
        .as_ref()
        .map(|f| load_registry(f, "proposed registry"))
        .transpose()?;
    if let Some(declared) = &proposed {
        bind_declarations(declared, &after, "proposed registry")?;
    }

    let byte_identical =
        request.before.as_ref().map(|f| &f.bytes) == request.after.as_ref().map(|f| &f.bytes);
    let mut diff = Diff {
        findings: vec![],
        steps: 0,
        truncated: 0,
    };
    let names: BTreeSet<&String> = before.tools.keys().chain(after.tools.keys()).collect();
    for name in &names {
        let place = Place {
            tool: name,
            area: "tool",
            pointer: "",
            argument: None,
        };
        match (before.tools.get(*name), after.tools.get(*name)) {
            (None, Some(a)) => {
                diff.push(
                    place,
                    "tool_added",
                    Nature::ReviewRequired,
                    None,
                    Some(a),
                    json!({}),
                );
                diff.flag_tool(name, a, true);
            }
            (Some(b), None) => {
                diff.push(
                    place,
                    "tool_removed",
                    Nature::ReviewRequired,
                    Some(b),
                    None,
                    json!({}),
                );
                diff.flag_tool(name, b, false);
            }
            (Some(b), Some(a)) => diff.diff_tool(name, b, a)?,
            (None, None) => {}
        }
    }
    let shared_before: Vec<&String> = before
        .order
        .iter()
        .filter(|n| after.tools.contains_key(*n))
        .collect();
    let shared_after: Vec<&String> = after
        .order
        .iter()
        .filter(|n| before.tools.contains_key(*n))
        .collect();
    let reordered = shared_before != shared_after;
    if reordered {
        diff.push(
            Place {
                tool: "",
                area: "discovery",
                pointer: "/result/tools",
                argument: None,
            },
            "tool_order_changed",
            Nature::InertMetadata,
            None,
            None,
            json!({"order_semantic": false}),
        );
    }

    // Runtime subset and unsupported coverage, per tool and side.
    let mut tools_json = Vec::new();
    let mut coverage = Vec::new();
    let mut coverage_truncated = false;
    let mut unaccepted = Vec::new();
    for name in &names {
        let (b, a) = (before.tools.get(*name), after.tools.get(*name));
        let ids = |t: Option<&Value>| {
            t.map(|t| {
                json!({
                    "schema_sha256": profile_author::digest(&t["inputSchema"]),
                    "definition_sha256": profile_author::digest(t),
                    "output_schema_sha256": t.get("outputSchema").map(profile_author::digest),
                })
            })
        };
        let changed = b != a;
        let status = match (b, a) {
            (None, _) => "added",
            (_, None) => "removed",
            _ if changed => "changed",
            _ => "unchanged",
        };
        if a.is_some() && changed {
            unaccepted.push((*name).clone());
        }
        let after_status = match (b, a) {
            (_, None) => "absent",
            _ if !changed => "unchanged_from_before",
            _ => "new_unaccepted",
        };
        for (side, tool) in [("before", b), ("after", a)] {
            let Some(tool) = tool else { continue };
            for (area, key) in [("input", "inputSchema"), ("result", "outputSchema")] {
                let Some(schema) = tool.get(key) else {
                    continue;
                };
                let mut found = Vec::new();
                scan_unsupported(schema, &format!("/{key}"), 0, true, &mut found);
                for (pointer, keyword) in found {
                    if coverage.len() >= MAX_COVERAGE_ENTRIES {
                        coverage_truncated = true;
                        break;
                    }
                    coverage.push(json!({"tool": name, "side": side, "area": area,
                        "pointer": pointer, "construct": keyword,
                        "handling": "reported_not_analyzed"}));
                }
            }
            for key in tool
                .as_object()
                .map(|m| m.keys().collect::<Vec<_>>())
                .unwrap_or_default()
            {
                if !matches!(
                    key.as_str(),
                    "name"
                        | "title"
                        | "description"
                        | "inputSchema"
                        | "outputSchema"
                        | "annotations"
                        | "execution"
                ) {
                    if coverage.len() >= MAX_COVERAGE_ENTRIES {
                        coverage_truncated = true;
                        break;
                    }
                    coverage.push(json!({"tool": name, "side": side, "area": "tool",
                        "pointer": format!("/{}", escape_token(key)), "construct": key,
                        "handling": "compared_by_identity_only"}));
                }
            }
        }
        let input_subset = subset(a.map(|t| &t["inputSchema"]), Role::Arguments);
        if changed && a.is_some() && input_subset["status"] == "unsupported" {
            diff.push(
                Place {
                    tool: name,
                    area: "input",
                    pointer: "/inputSchema",
                    argument: None,
                },
                "schema_outside_runtime_subset",
                Nature::Unsupported,
                None,
                None,
                json!({"validator": "agentfw::mcp::input::InputSchema::read_selected",
                       "reason": input_subset["reason"]}),
            );
        }
        tools_json.push(json!({
            "name": name, "status": status,
            "before": ids(b), "after": ids(a),
            "after_identity_status": after_status,
            "accepted_by_analyzer": false,
            "runtime_subset": {
                "before_input": subset(b.map(|t| &t["inputSchema"]), Role::Arguments),
                "after_input": input_subset,
                "after_result": subset(a.and_then(|t| t.get("outputSchema")), Role::Result),
            },
            "current_declaration": current.as_ref().and_then(|d| d.tools.get(*name)).map(ToolSemantics::json),
            "proposed_declaration": proposed.as_ref().and_then(|d| d.tools.get(*name)).map(ToolSemantics::json),
        }));
    }

    declaration_findings(
        &mut diff,
        &before,
        &after,
        current.as_ref(),
        proposed.as_ref(),
    );

    let mut findings = diff.findings;
    for f in &mut findings {
        let key = format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}",
            f.tool,
            f.area,
            f.pointer,
            f.kind,
            canonical_json(&f.detail),
            f.before.as_ref().map(canonical_json).unwrap_or_default(),
            f.after.as_ref().map(canonical_json).unwrap_or_default()
        );
        f.id = format!("F-{}", &sha_hex(key.as_bytes())[..16]);
    }
    findings.sort_by(|x, y| {
        (&x.tool, &x.pointer, x.kind, &x.id).cmp(&(&y.tool, &y.pointer, y.kind, &y.id))
    });
    findings.dedup_by(|x, y| x.id == y.id);

    let mut analysis = Analysis {
        before: &before,
        after: &after,
        current: current.as_ref(),
        findings,
    };
    let generation = examples::generate(&mut analysis);
    let findings = analysis.findings;

    let count = |n: Nature| findings.iter().filter(|f| f.nature == n).count();
    let (inert, review, unsupported, requalification) = (
        count(Nature::InertMetadata),
        count(Nature::ReviewRequired),
        count(Nature::Unsupported),
        count(Nature::Requalification),
    );
    let discovery_changed = before.discovery_sha256 != after.discovery_sha256;
    // `byte_identical` is a snapshot fact. The aggregate outcome also counts
    // declaration-only findings (e.g. a proposed registry that changes an
    // action class for unchanged schemas), so identical snapshots with
    // substantive findings still require review.
    let declaration_findings = findings.iter().filter(|f| f.area == "declaration").count();
    let no_drift = byte_identical && findings.is_empty();
    let classification = if no_drift {
        "byte_identical"
    } else if unsupported > 0 {
        "unsupported_present"
    } else if review > 0 {
        "review_required"
    } else if inert > 0 {
        "inert_metadata_only"
    } else {
        "raw_bytes_differ_identities_equal"
    };
    let exit = if no_drift {
        EXIT_NO_DRIFT
    } else {
        EXIT_REVIEW_REQUIRED
    };
    let analysis_complete = diff.truncated == 0 && !coverage_truncated && generation.complete;
    let current_declared: Option<&Declared> = current.as_ref();
    let undeclared: Vec<&String> = match current_declared {
        Some(d) => before
            .tools
            .keys()
            .filter(|n| !d.tools.contains_key(*n))
            .collect(),
        None => vec![],
    };
    let mut gaps = vec![];
    if current_declared.is_none() {
        gaps.push(json!({"gap": "no_current_declarations", "mode": "snapshot_only",
            "effect": "semantic review unavailable: action/resource/destination semantics unknown; no declared-selector findings or declaration-grounded examples"}));
    }
    if !undeclared.is_empty() {
        gaps.push(json!({"gap": "tools_without_current_declaration", "tools": undeclared}));
    }
    if identity.is_none() {
        gaps.push(json!({"gap": "before_identity_not_verified", "effect": "the before snapshot was not checked against an accepted identity document"}));
    }
    if !coverage.is_empty() {
        gaps.push(json!({"gap": "unsupported_constructs_present", "entries": coverage.len()}));
    }
    if diff.truncated > 0 {
        gaps.push(json!({"gap": "findings_truncated", "omitted": diff.truncated}));
    }
    if coverage_truncated {
        gaps.push(json!({"gap": "coverage_list_truncated"}));
    }
    gaps.extend(generation.gaps.iter().cloned());
    // Coverage is complete only without any gap; truncation alone is not the test.
    let complete = gaps.is_empty();

    let input = |f: &FileIdentity, s: &Snapshot, l: &Option<String>| {
        let mut v = f.json();
        v["format"] = json!(s.format);
        v["discovery_sha256"] = json!(s.discovery_sha256);
        v["tool_count"] = json!(s.tools.len());
        v["operator_label_untrusted"] = json!(l);
        v
    };
    let declared_json = |d: &Option<Declared>| {
        d.as_ref().map(|d| {
            let mut v = d.file.json();
            v["format"] = json!(d.format);
            v["registry_id"] = json!(d.id);
            v["tools"] = json!(d.tools.len());
            v
        })
    };
    let report = json!({
        "format": REPORT_FORMAT,
        "analyzer": {"command": "agentfw mcp-schema-upgrade", "version": env!("CARGO_PKG_VERSION")},
        "non_authority": {
            "accepts_schema": false, "installs": false, "grants_permission": false,
            "modifies_profile_or_declarations": false, "launches_server": false,
            "network_or_reference_retrieval": false, "model_classification": false,
            "statement": NON_AUTHORITY,
        },
        "inputs": {
            "before": input(&before.file, &before, &before_label),
            "after": input(&after.file, &after, &after_label),
            "before_identity": identity.as_ref().map(|i| {
                let mut v = i.file.json();
                v["format"] = json!(i.format);
                v["checks"] = json!(i.checks);
                v["referenced_files"] = json!(i.referenced);
                v["per_tool_identities"] = json!(i.per_tool);
                v
            }),
            "current_declarations": declared_json(&current),
            "proposed_registry": declared_json(&proposed),
        },
        "identity_rules": {
            "raw_file": "sha256 of the exact input bytes",
            "schema_identity": "profile_author::digest(inputSchema): sha256 of sorted-key compact JSON",
            "definition_identity": "profile_author::digest(tool)",
            "discovery_identity": "profile_author::digest(result) for JSON-RPC, of the whole document for sw-mcp/operator-discovery/1",
            "analysis_normalization": "sorted object keys; required/enum/type compared as sets; used only to compare, never as identity",
        },
        "limits": limits_json(),
        "summary": {
            "classification": classification,
            "outcome": if exit == EXIT_NO_DRIFT { "no_drift" } else { "review_required" },
            "exit_code": exit,
            "byte_identical": byte_identical,
            "declaration_findings": declaration_findings,
            "discovery_identity_changed": discovery_changed,
            "tool_order_changed": reordered,
            "tools_before": before.tools.len(), "tools_after": after.tools.len(),
            "tools_added": tools_json.iter().filter(|t| t["status"] == "added").count(),
            "tools_removed": tools_json.iter().filter(|t| t["status"] == "removed").count(),
            "tools_changed": tools_json.iter().filter(|t| t["status"] == "changed").count(),
            "tools_unchanged": tools_json.iter().filter(|t| t["status"] == "unchanged").count(),
            "findings": {"total": findings.len(), "inert_metadata": inert,
                         "review_required": review, "unsupported": unsupported,
                         "requalification_required": requalification},
            "new_unaccepted_identities": unaccepted,
            "coverage_complete": complete,
            "analysis_truncated": !analysis_complete,
            "analysis_mode": if current.is_some() { "declaration_bound" } else { "snapshot_only" },
            "semantic_review": if current.is_some() {
                "available_for_supported_subset"
            } else {
                "unavailable_snapshot_only"
            },
        },
        "acceptance": {
            "analyzer_accepts": false,
            "after_discovery_identity": if discovery_changed { "new_unaccepted" } else { "unchanged_from_before" },
            "after_raw_artifact": if byte_identical { "unchanged_from_before" } else { "new_unaccepted" },
            "statement": NON_AUTHORITY,
        },
        "tools": tools_json,
        "findings": findings.iter().map(Finding::json).collect::<Vec<_>>(),
        "coverage": {"complete": complete, "gaps": gaps, "unsupported_constructs": coverage},
        "review_pack": {"file": "review-pack.json", "records": generation.records.len(),
                        "truncated": generation.omitted, "complete": generation.complete},
    });
    let pack = json!({
        "format": PACK_FORMAT,
        "report_format": REPORT_FORMAT,
        "before_raw_sha256": before.file.raw_sha256,
        "after_raw_sha256": after.file.raw_sha256,
        "status": "proposal_for_human_review",
        "these_records_are_not": ["gold_labels", "training_data", "human_approvals",
            "runtime_permission", "evidence_of_observed_runtime_enforcement",
            "semantic_safety_determinations"],
        "label_definitions": {
            "schema_validity": "observed verdict of the runtime input validator on the after schema",
            "semantic_expectation": "proposal: adverse_under_current_declaration (only with a stated contradiction of the cited declaration), behavior_change_vs_before_schema (concrete schema change), unknown_requires_manual_review (meaning not established by declarations), exercise_only, rejected_by_schema, unknown (unsupported/unconstructible), not_applicable",
            "contradiction": "the identified contradiction with the cited declaration, or null",
            "declaration_refs": "relevance and traceability only; a reference alone never makes a record adverse",
            "runtime_enforcement": "never observed by this analyzer",
            "semantic_safety": "never established by schema validity",
            "human_approval": "none; records require operator review",
        },
        "analysis_mode": if current.is_some() { "declaration_bound" } else { "snapshot_only" },
        "schema_validity_basis": "agentfw::mcp::input::InputSchema::read_selected(after inputSchema).validate(arguments); selected-profile objects are closed",
        "limits": examples::limits_json(),
        "generation": {"records": generation.records.len(), "omitted": generation.omitted,
                       "complete": generation.complete},
        "records": generation.records,
    });
    let files = render::render(&report, &pack)?;
    Ok(Outcome {
        report,
        pack,
        files,
        exit,
    })
}

fn limits_json() -> Value {
    json!({
        "max_snapshot_bytes": MAX_SNAPSHOT_BYTES,
        "max_declaration_bytes": MAX_DECLARATION_BYTES,
        "max_referenced_file_bytes": MAX_REFERENCED_FILE_BYTES,
        "max_referenced_files": MAX_REFERENCED_FILES,
        "max_tools": MAX_TOOLS,
        "max_document_depth": MAX_DOCUMENT_DEPTH,
        "max_document_nodes": MAX_DOCUMENT_NODES,
        "max_diff_steps": MAX_DIFF_STEPS,
        "max_findings": MAX_FINDINGS,
        "max_coverage_entries": MAX_COVERAGE_ENTRIES,
        "max_value_excerpt_bytes": MAX_VALUE_EXCERPT_BYTES,
        "max_label_bytes": MAX_LABEL_BYTES,
        "max_output_bytes": MAX_OUTPUT_BYTES,
        "runtime_subset": {"max_depth": crate::mcp::input::MAX_DEPTH,
            "max_items": crate::mcp::input::MAX_ITEMS,
            "max_schema_nodes": crate::mcp::input::MAX_SCHEMA_NODES},
    })
}

fn declaration_findings(
    diff: &mut Diff,
    before: &Snapshot,
    after: &Snapshot,
    current: Option<&Declared>,
    proposed: Option<&Declared>,
) {
    if let Some(current) = current {
        for (name, sem) in &current.tools {
            let place = Place {
                tool: name,
                area: "declaration",
                pointer: "",
                argument: None,
            };
            let refs = [sem.reference.clone()];
            let Some(after_tool) = after.tools.get(name) else {
                diff.push_refs(
                    place,
                    "declared_tool_removed",
                    Nature::ReviewRequired,
                    None,
                    None,
                    json!({"declaration": sem.reference}),
                    &refs,
                );
                continue;
            };
            let after_schema = &after_tool["inputSchema"];
            let before_schema = &before.tools[name]["inputSchema"];
            let after_identity = profile_author::digest(after_schema);
            if after_identity != sem.schema_sha256 {
                diff.push_refs(
                    place.child("/inputSchema", None),
                    "declaration_binding_stale",
                    Nature::Requalification,
                    Some(&json!(sem.schema_sha256)),
                    Some(&json!(after_identity)),
                    json!({"declaration": sem.reference, "after_identity_status": "new_unaccepted"}),
                    &refs,
                );
            }
            for (role, sels) in [
                ("resource", &sem.resources),
                ("destination", &sem.destinations),
            ] {
                for sel in sels {
                    let b = schema_at(before_schema, &sel.pointer);
                    let a = schema_at(after_schema, &sel.pointer);
                    let schema_pointer = format!(
                        "/inputSchema{}",
                        argument_to_schema(before_schema, after_schema, &sel.pointer)
                    );
                    // A declared non-optional selector whose field may now be omitted.
                    if a.is_some()
                        && !sel.optional
                        && required_at(before_schema, &sel.pointer)
                        && !required_at(after_schema, &sel.pointer)
                    {
                        diff.push_refs(
                            place.child(&schema_pointer, Some(&sel.pointer)),
                            "declared_selector_requirement_relaxed",
                            Nature::ReviewRequired,
                            None,
                            None,
                            json!({"declaration": sem.reference, "role": role,
                                   "selector_kind": sel.kind, "declared_optional": false}),
                            &refs,
                        );
                    }
                    if b == a {
                        continue;
                    }
                    let became_array = a.is_some_and(|a| a["type"] == "array")
                        && !b.is_some_and(|b| b["type"] == "array");
                    let kind = if a.is_none() {
                        "declared_selector_unbound"
                    } else {
                        "declared_selector_target_changed"
                    };
                    diff.push_refs(
                        place.child(&schema_pointer, Some(&sel.pointer)),
                        kind,
                        Nature::ReviewRequired,
                        b,
                        a,
                        json!({"declaration": sem.reference, "role": role,
                               "selector_kind": sel.kind, "became_array": became_array}),
                        &refs,
                    );
                }
            }
        }
        for name in after.tools.keys() {
            if !before.tools.contains_key(name) {
                diff.push(
                    Place {
                        tool: name,
                        area: "declaration",
                        pointer: "",
                        argument: None,
                    },
                    "undeclared_tool_added",
                    Nature::ReviewRequired,
                    None,
                    None,
                    json!({"declared_action": null, "permission": "none"}),
                );
            }
        }
        // Input findings at or under a declared selector cite that declaration;
        // fields added to a tool with declared selectors are not covered by them.
        for f in &mut diff.findings {
            if f.area != "input" {
                continue;
            }
            let Some(sem) = current.tools.get(&f.tool) else {
                continue;
            };
            let at_selector = f.argument_pointer.as_deref().is_some_and(|arg| {
                sem.resources
                    .iter()
                    .chain(&sem.destinations)
                    .any(|sel| arg == sel.pointer || arg.starts_with(&format!("{}/", sel.pointer)))
            });
            let added_outside = f.kind == "field_added"
                && !(sem.resources.is_empty() && sem.destinations.is_empty());
            if at_selector {
                f.reasons.push(
                    "This path is addressed by a current declared resource/destination selector."
                        .into(),
                );
            } else if added_outside {
                f.reasons.push(
                    "This tool has declared resource/destination selectors; the new field is \
not addressed by any of them. The analyzer does not infer destination or resource semantics from \
field names."
                        .into(),
                );
            }
            if (at_selector || added_outside) && !f.declaration_refs.contains(&sem.reference) {
                f.declaration_refs.push(sem.reference.clone());
            }
        }
    }
    if let (Some(current), Some(proposed)) = (current, proposed) {
        let names: BTreeSet<&String> = current.tools.keys().chain(proposed.tools.keys()).collect();
        for name in names {
            let (c, p) = (current.tools.get(name), proposed.tools.get(name));
            let place = Place {
                tool: name,
                area: "declaration",
                pointer: "",
                argument: None,
            };
            let action = |s: Option<&ToolSemantics>| s.map(|s| json!(s.action));
            let prov = |s: Option<&ToolSemantics>| {
                s.and_then(|s| s.result_provenance.clone()).map(Value::from)
            };
            let res = |s: Option<&ToolSemantics>| s.map(|s| s.json()["resources"].clone());
            let dst = |s: Option<&ToolSemantics>| s.map(|s| s.json()["destinations"].clone());
            let cap = |s: Option<&ToolSemantics>| s.map(|s| json!(s.capabilities));
            for (kind, b, a) in [
                ("declared_action_changed", action(c), action(p)),
                ("declared_result_provenance_changed", prov(c), prov(p)),
                ("declared_resource_changed", res(c), res(p)),
                ("declared_destination_changed", dst(c), dst(p)),
                ("declared_capability_changed", cap(c), cap(p)),
            ] {
                if b != a {
                    diff.push(
                        place,
                        kind,
                        Nature::ReviewRequired,
                        b.as_ref(),
                        a.as_ref(),
                        json!({"proposed_status": "draft_not_accepted",
                               "current": c.map(|s| s.reference.clone()),
                               "proposed": p.map(|s| s.reference.clone())}),
                    );
                }
            }
        }
    }
}

/// Schema pointer for an argument pointer, using whichever side still has it.
fn argument_to_schema(before: &Value, after: &Value, argument_pointer: &str) -> String {
    let mut out = String::new();
    let mut nodes = (Some(before), Some(after));
    for token in pointer_tokens(argument_pointer).unwrap_or_default() {
        let is_array = |n: Option<&Value>| n.is_some_and(|n| n["type"] == "array");
        if is_array(nodes.1) || (nodes.1.is_none() && is_array(nodes.0)) {
            out.push_str("/items");
            nodes = (
                nodes.0.and_then(|n| n.get("items")),
                nodes.1.and_then(|n| n.get("items")),
            );
        } else {
            out.push_str(&format!("/properties/{}", escape_token(&token)));
            nodes = (
                nodes
                    .0
                    .and_then(|n| n.get("properties"))
                    .and_then(|p| p.get(&token)),
                nodes
                    .1
                    .and_then(|n| n.get("properties"))
                    .and_then(|p| p.get(&token)),
            );
        }
    }
    out
}

// ---------------------------------------------------------------------------
// File I/O and CLI
// ---------------------------------------------------------------------------

pub(crate) fn read_bounded(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() || meta.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a bounded regular file",
        ));
    }
    let mut out = Vec::new();
    fs::File::open(path)?.take(max + 1).read_to_end(&mut out)?;
    if out.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "file grew beyond bound",
        ));
    }
    Ok(out)
}

fn read_input(path: &Path, max: usize, role: &str) -> Result<InputFile, (i32, String)> {
    let meta = fs::symlink_metadata(path)
        .map_err(|_| (EXIT_TECHNICAL, format!("{role}: input unavailable")))?;
    if !meta.file_type().is_file() {
        return Err((
            EXIT_INVALID_INPUT,
            format!("{role}: input must be a regular file (symlinks are refused)"),
        ));
    }
    if meta.len() > max as u64 {
        return Err((
            EXIT_INVALID_INPUT,
            format!("input_too_large: {role}: exceeds the {max}-byte bound"),
        ));
    }
    let bytes = read_bounded(path, max as u64)
        .map_err(|_| (EXIT_TECHNICAL, format!("{role}: input could not be read")))?;
    Ok(InputFile {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        bytes,
        dir: path.parent().map(|p| {
            if p.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                p.to_path_buf()
            }
        }),
    })
}

/// Writes only a new directory. Refuses an existing path and the Agent home.
pub fn publish(out: &Path, files: &[(&'static str, Vec<u8>)]) -> Result<(), String> {
    let absolute = std::path::absolute(out).map_err(|_| "output path unusable".to_owned())?;
    if let Ok(home) = crate::config::Config::home_path() {
        // Compare literal and resolved forms (case, `..`, links) of both paths.
        let resolve = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        let parent = absolute.parent().map(resolve).unwrap_or_default();
        let homes = [home.clone(), resolve(&home)];
        if homes
            .iter()
            .any(|h| absolute.starts_with(h) || parent.starts_with(h) || &parent == h)
        {
            return Err("output must not be inside the Agent home".into());
        }
    }
    let total: usize = files.iter().map(|(_, b)| b.len()).sum();
    if total > MAX_OUTPUT_BYTES {
        return Err(format!("output exceeds the {MAX_OUTPUT_BYTES}-byte bound"));
    }
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(out)
        .map_err(|_| "output directory must be new and its parent must exist".to_owned())?;
    for (name, bytes) in files {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(out.join(name))
            .map_err(|_| format!("could not create {name}"))?;
        std::io::Write::write_all(&mut file, bytes)
            .map_err(|_| format!("could not write {name}"))?;
        file.sync_all()
            .map_err(|_| format!("could not sync {name}"))?;
    }
    Ok(())
}

pub fn run_cli(args: Args) -> i32 {
    let load = |path: &Option<PathBuf>, max: usize, role: &str| {
        path.as_ref().map(|p| read_input(p, max, role)).transpose()
    };
    let request = (|| -> Result<Request, (i32, String)> {
        Ok(Request {
            before: Some(read_input(&args.before, MAX_SNAPSHOT_BYTES, "before")?),
            after: Some(read_input(&args.after, MAX_SNAPSHOT_BYTES, "after")?),
            before_identity: load(
                &args.before_identity,
                MAX_DECLARATION_BYTES,
                "before identity",
            )?,
            registry: load(&args.registry, MAX_DECLARATION_BYTES, "registry")?,
            declarations: load(&args.declarations, MAX_DECLARATION_BYTES, "declarations")?,
            proposed_registry: load(
                &args.proposed_registry,
                MAX_DECLARATION_BYTES,
                "proposed registry",
            )?,
            snapshot_only: args.snapshot_only,
            before_label: args.before_label.clone(),
            after_label: args.after_label.clone(),
        })
    })();
    let request = match request {
        Ok(r) => r,
        Err((code, message)) => {
            eprintln!("mcp-schema-upgrade refused: {message}");
            return code;
        }
    };
    let outcome = match analyze(&request) {
        Ok(outcome) => outcome,
        Err(refusal) => {
            eprintln!(
                "mcp-schema-upgrade refused: {}: {}",
                refusal.code, refusal.detail
            );
            return EXIT_INVALID_INPUT;
        }
    };
    if let Err(message) = publish(&args.out, &outcome.files) {
        eprintln!("mcp-schema-upgrade output refused: {message}");
        return EXIT_OUTPUT;
    }
    let summary = &outcome.report["summary"];
    println!(
        "mcp-schema-upgrade: {} (exit {}); findings {} (inert {}, review {}, unsupported {}, \
requalification {}); coverage_complete={}; nothing was accepted or installed.",
        summary["classification"].as_str().unwrap_or(""),
        outcome.exit,
        summary["findings"]["total"],
        summary["findings"]["inert_metadata"],
        summary["findings"]["review_required"],
        summary["findings"]["unsupported"],
        summary["findings"]["requalification_required"],
        summary["coverage_complete"],
    );
    outcome.exit
}
