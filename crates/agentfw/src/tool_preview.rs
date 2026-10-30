// SPDX-License-Identifier: Apache-2.0
//! Installed, non-executing tool-call preview.
//!
//! One explicit, bounded original-tool JSON frame is validated against the selected
//! original profile and described by the installed, verified classifier package through
//! the existing bounded worker. Nothing here discovers host configuration, starts an MCP
//! server, calls a provider, invokes the tool, downloads a model, or touches policy,
//! selection, caches, audit/risk history or host settings.
//!
//! The result is a non-authoritative description. It never names a policy verdict.
//! Output is bounded and built only from fixed vocabulary, validated tokens and short
//! digests: raw arguments, path/secret values and arbitrary exception text never reach it.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Value};
use soup_wall_agent::ActionClass;

use crate::classifier_runtime::package::{sha, Store, Verified, WORKER_PROTOCOL};
use crate::classifier_runtime::worker::{PackagedClassifier, MAX_INPUT, REQUEST_DEADLINE};
use crate::mcp::admission::{parse_classifier_reply, Invocation};
use crate::mcp::server_profile::{self, ToolProfile};

pub const SCHEMA: &str = "sw-tool-preview/1";
pub const SOURCE: &str = "rule-baseline/packaged-worker";
/// One original tool-call frame. Same bound as one reviewed MCP frame.
pub const MAX_FRAME_BYTES: usize = server_profile::MAX_FRAME_BYTES;
const MAX_NAME_CHARS: usize = 256;
const MAX_DESCRIPTION_BYTES: usize = 16 * 1024;
const MAX_ENTRIES: usize = 16;
const MAX_CODES: usize = 24;
/// Exported/printed JSON is always below this.
pub const MAX_REPORT_BYTES: usize = 128 * 1024;

pub const EXIT_OK: i32 = 0;
pub const EXIT_REFUSED: i32 = 2;
pub const EXIT_TECHNICAL: i32 = 3;
pub const EXIT_EXPORT: i32 = 4;

pub const NOTICE: &str =
    "Non-authoritative preview of one supplied tool-call frame. It states how \
the installed classifier describes the call; it is not a policy decision and does not predict \
Allow, Ask or Deny. No live session, taint state, native receipt, operator approval, execution \
or active protection is behind it.";

const CATEGORIES: [&str; 5] = ["read", "write", "delete", "send_data", "change_permissions"];
const FLAG_KEYS: [&str; 8] = [
    "description_conflict",
    "description_suspicious",
    "name_conflict",
    "schema_mismatch",
    "args_schema_violation",
    "dry_run_declared",
    "truncated",
    "definition_invocation_diff",
];
/// Closed, reviewed vocabulary of reason codes the preview may print. The worker's codes are
/// worker-controlled strings; only members of this list are ever shown, everything else is
/// counted in `reason_codes_dropped`. Mirrors the codes emitted by the packaged classifiers.
const REASON_CODES: &[&str] = &[
    "args:read",
    "args:write",
    "args:delete",
    "args:send_data",
    "args:change_permissions",
    "name:read",
    "name:write",
    "name:delete",
    "name:send_data",
    "name:change_permissions",
    "schema:read",
    "schema:write",
    "schema:delete",
    "schema:send_data",
    "schema:change_permissions",
    "shell:read",
    "shell:write",
    "shell:delete",
    "shell:send_data",
    "shell:change_permissions",
    "proven_noop",
    "pure_computation",
    "no_rule_matched",
    "partial_unknown",
    "description_conflict",
    "description_suspicious",
    "name_conflict",
    "schema_mismatch",
    "args_schema_violation",
    "dry_run_declared",
    "truncated",
    "invalid_input",
    "classifier_timeout",
    "classifier_internal_error",
    "classifier_invalid",
];
const MISSING_CONTEXT: [&str; 6] = [
    "live_session_state",
    "taint_state",
    "native_receipt",
    "operator_approval",
    "policy_decision",
    "execution_and_active_protection",
];
/// Argument-role vocabulary used only to summarize resources for display. It carries no
/// decision: it never turns a tool name or argument into a permission.
const PATH_KEYS: [&str; 6] = [
    "path",
    "paths",
    "source",
    "destination",
    "repo_path",
    "files",
];
const REF_KEYS: [&str; 6] = [
    "revision",
    "target",
    "branch_name",
    "base_branch",
    "contains",
    "not_contains",
];

/// Fixed technical failure code. Never derived from argument values.
pub type Code = &'static str;

/// The only worker capability the preview needs. The production implementation is the
/// existing bounded `PackagedClassifier`.
pub trait Classify {
    fn classify_raw(&self, input: &str) -> Result<String, Code>;
}

impl Classify for PackagedClassifier {
    fn classify_raw(&self, input: &str) -> Result<String, Code> {
        PackagedClassifier::classify_raw(self, input).map_err(|error| technical_code(&error))
    }
}

struct Unavailable(Code);

impl Classify for Unavailable {
    fn classify_raw(&self, _: &str) -> Result<String, Code> {
        Err(self.0)
    }
}

fn chain(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(" | ")
        .to_ascii_lowercase()
}

/// Map any worker/package failure to a fixed code. Free-form text is dropped.
fn technical_code(error: &anyhow::Error) -> Code {
    let text = chain(error);
    let has = |needle: &str| text.contains(needle);
    if has("no classifier package is installed") {
        "package_not_installed"
    } else if has("interrupted install") {
        "package_install_interrupted"
    } else if has("timed out") {
        "worker_timeout"
    } else if has("did not become ready") {
        "worker_start_timeout"
    } else if has("exited") {
        "worker_exited"
    } else if has("input exceeds limit") {
        "classifier_input_too_large"
    } else if has("frame rejected")
        || has("invalid worker reply")
        || has("invalid ready frame")
        || has("protocol mismatch")
        || has("does not match")
        || has("different input")
    {
        "worker_protocol_violation"
    } else if has("verif")
        || has("digest")
        || has("sha")
        || has("permission")
        || has("pin")
        || has("interpreter")
        || has("package")
    {
        "package_verification_failed"
    } else {
        "worker_failure"
    }
}

fn package_code(error: &anyhow::Error) -> Code {
    match technical_code(error) {
        "package_not_installed" => "package_not_installed",
        "package_install_interrupted" => "package_install_interrupted",
        _ => "package_verification_failed",
    }
}

// ---------------------------------------------------------------- strict JSON

/// JSON value that refuses duplicate object keys at any depth.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Value;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
                Ok(Value::from(v))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
                Ok(Value::from(v))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
                serde_json::Number::from_f64(v)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_str<E>(self, v: &str) -> Result<Value, E> {
                Ok(Value::String(v.to_owned()))
            }
            fn visit_string<E>(self, v: String) -> Result<Value, E> {
                Ok(Value::String(v))
            }
            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut items = Vec::new();
                while let Some(Strict(item)) = seq.next_element::<Strict>()? {
                    items.push(item);
                }
                Ok(Value::Array(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut object = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if object.contains_key(&key) {
                        return Err(de::Error::custom("duplicate_key"));
                    }
                    let Strict(value) = map.next_value::<Strict>()?;
                    object.insert(key, value);
                }
                Ok(Value::Object(object))
            }
        }
        deserializer.deserialize_any(V).map(Strict)
    }
}

// ---------------------------------------------------------------- frame

#[derive(Debug)]
pub struct Frame {
    form: &'static str,
    tool: String,
    arguments: Map<String, Value>,
    description: Option<String>,
    schema: Option<Value>,
}

/// Read one frame source, bounded. `-` is standard input. A path must be a regular file.
pub fn read_frame(source: &str) -> Result<Vec<u8>, Code> {
    let mut bytes = Vec::new();
    let limit = (MAX_FRAME_BYTES + 1) as u64;
    if source == "-" {
        std::io::stdin()
            .lock()
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|_| "frame_unreadable")?;
    } else {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // A FIFO must refuse, not block the preview.
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = options.open(source).map_err(|_| "frame_unreadable")?;
        if !file.metadata().map_err(|_| "frame_unreadable")?.is_file() {
            return Err("frame_not_regular_file");
        }
        file.take(limit)
            .read_to_end(&mut bytes)
            .map_err(|_| "frame_unreadable")?;
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err("frame_too_large");
    }
    Ok(bytes)
}

fn only_keys(object: &Map<String, Value>, allowed: &[&str]) -> bool {
    object.keys().all(|key| allowed.contains(&key.as_str()))
}

/// Parse exactly one original tool-call frame: either `{tool, arguments, description?,
/// inputSchema?}` or a single MCP `tools/call` request. Unknown keys, duplicate keys,
/// trailing data and non-object arguments are refused.
pub fn parse_frame(bytes: &[u8]) -> Result<Frame, Code> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err("frame_too_large");
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err("frame_empty");
    }
    let value = match serde_json::from_slice::<Strict>(bytes) {
        Ok(Strict(value)) => value,
        Err(error) => {
            let text = error.to_string();
            return Err(if text.starts_with("duplicate_key") {
                "frame_duplicate_key"
            } else if text.contains("trailing characters") {
                "frame_not_a_single_json_value"
            } else {
                "frame_invalid_json"
            });
        }
    };
    let top = value.as_object().ok_or("frame_not_an_object")?;
    let (form, name, arguments, description, schema) = if top.contains_key("method") {
        if !only_keys(top, &["jsonrpc", "id", "method", "params"])
            || top.get("jsonrpc") != Some(&json!("2.0"))
            || top.get("method") != Some(&json!("tools/call"))
        {
            return Err("frame_shape_unsupported");
        }
        let params = top
            .get("params")
            .and_then(Value::as_object)
            .ok_or("frame_shape_unsupported")?;
        if !only_keys(params, &["name", "arguments", "_meta"]) {
            return Err("frame_shape_unsupported");
        }
        (
            "mcp_tools_call",
            params.get("name"),
            params.get("arguments"),
            None,
            None,
        )
    } else {
        if !only_keys(top, &["tool", "arguments", "description", "inputSchema"]) {
            return Err("frame_shape_unsupported");
        }
        (
            "tool_frame",
            top.get("tool"),
            top.get("arguments"),
            top.get("description"),
            top.get("inputSchema"),
        )
    };
    let tool = name.and_then(Value::as_str).ok_or("tool_name_missing")?;
    if tool.trim().is_empty() || tool.chars().count() > MAX_NAME_CHARS {
        return Err("tool_name_invalid");
    }
    let arguments = match arguments {
        None => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => return Err("arguments_not_an_object"),
    };
    let description = match description {
        None => None,
        Some(Value::String(text)) if text.len() <= MAX_DESCRIPTION_BYTES => Some(text.clone()),
        Some(_) => return Err("supplied_metadata_malformed"),
    };
    let schema = match schema {
        None => None,
        Some(object @ Value::Object(_)) => Some(object.clone()),
        Some(_) => return Err("supplied_metadata_malformed"),
    };
    Ok(Frame {
        form,
        tool: tool.to_owned(),
        arguments,
        description,
        schema,
    })
}

// ---------------------------------------------------------------- profile

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileChoice {
    format: &'static str,
    server_id: &'static str,
}

/// `filesystem` and `git` select the original read-only profiles; any other accepted
/// value must be the exact format string of a shipped profile.
pub fn parse_profile(value: &str) -> Result<ProfileChoice, Code> {
    let format: &'static str = match value {
        "filesystem" => server_profile::FORMAT,
        "git" => server_profile::git::FORMAT,
        other => [
            server_profile::FORMAT,
            server_profile::filesystem_create::FORMAT,
            server_profile::git::FORMAT,
            server_profile::git::LOCAL_REFS_FORMAT,
            server_profile::git::FILE_READS_FORMAT,
            server_profile::git::SHALLOW_FORMAT,
            server_profile::git_local_clone::FORMAT,
            server_profile::git_tracked_symlinks::FORMAT,
        ]
        .into_iter()
        .find(|format| *format == other)
        .ok_or("profile_unsupported")?,
    };
    let server_id = if server_profile::git_selected(format) {
        "git"
    } else {
        "filesystem"
    };
    Ok(ProfileChoice { format, server_id })
}

struct Reviewed {
    manifest: Value,
    profiles: std::collections::BTreeMap<String, ToolProfile>,
}

fn load_reviewed(choice: ProfileChoice) -> Result<Reviewed, Code> {
    let manifest =
        server_profile::original_manifest_for(choice.format).map_err(|_| "profile_unavailable")?;
    let profiles = server_profile::classify_manifest_for(choice.format, &manifest)
        .map_err(|_| "profile_unavailable")?;
    Ok(Reviewed { manifest, profiles })
}

fn reviewed_definition<'a>(reviewed: &'a Reviewed, tool: &str) -> Option<&'a Value> {
    reviewed.manifest["tools"]
        .as_array()?
        .iter()
        .find(|definition| definition["name"] == tool)
}

fn validation_code(error: &anyhow::Error) -> Code {
    let text = chain(error);
    let has = |needle: &str| text.contains(needle);
    if has("required argument missing") {
        "required_argument_missing"
    } else if has("outside enum or const") {
        "value_outside_enum"
    } else if has("too many mcp arguments") {
        "too_many_arguments"
    } else if has("exceed profile limits") {
        "argument_limits_exceeded"
    } else if has("line bound") {
        "line_bound_unsupported"
    } else if has("head and tail") {
        "head_tail_ambiguous"
    } else if has("path") {
        "path_refused"
    } else if has("must match") || has("type") {
        "argument_type_mismatch"
    } else {
        "arguments_rejected_by_profile"
    }
}

// ---------------------------------------------------------------- redaction helpers

fn digest8(domain: &str, value: &str) -> String {
    sha(format!("{domain}\0{value}").as_bytes())[..8].to_owned()
}

/// A tool name is shown only when it is one of the reviewed profile's own names; any other
/// name is supplied content and appears as a digest and length only.
fn printable_tool(name: &str, reviewed: bool) -> Value {
    let digest = digest8("tool-preview/tool/v1", name);
    if reviewed {
        json!({"name": name, "name_printable": true, "name_digest8": digest, "name_bytes": name.len()})
    } else {
        json!({"name": null, "name_printable": false, "name_digest8": digest, "name_bytes": name.len()})
    }
}

fn entry(domain: &str, value: &str) -> Value {
    json!({"id": digest8(domain, value), "bytes": value.len()})
}

/// Typed resource summary derived from validated arguments. Values are never printed.
fn summarize_resources(arguments: &Map<String, Value>, declared_properties: usize) -> Value {
    let mut items = Vec::new();
    let mut recognized_keys = BTreeSet::new();
    for (key, value) in arguments {
        let (class, domain) = if PATH_KEYS.contains(&key.as_str()) {
            ("workspace_path", "tool-preview/path/v1")
        } else if REF_KEYS.contains(&key.as_str()) {
            ("git_reference", "tool-preview/ref/v1")
        } else {
            continue;
        };
        let strings: Vec<&str> = match value {
            Value::String(text) => vec![text.as_str()],
            Value::Array(values) => values.iter().filter_map(Value::as_str).collect(),
            _ => continue,
        };
        recognized_keys.insert(key.clone());
        items.push(json!({
            "argument": key, "class": class, "count": strings.len(),
            "entries": strings.iter().take(MAX_ENTRIES).map(|s| entry(domain, s)).collect::<Vec<_>>(),
            "entries_truncated": strings.len() > MAX_ENTRIES,
        }));
    }
    let extraction = if !items.is_empty() {
        "extracted"
    } else if declared_properties == 0 && arguments.is_empty() {
        "none_declared"
    } else {
        "missing"
    };
    json!({
        "extraction": extraction,
        "items": items,
        "unrecognized_argument_count": arguments.len() - recognized_keys.len(),
    })
}

// ---------------------------------------------------------------- classification

struct Described {
    actions: Vec<String>,
    unknown: bool,
    confidence: f64,
    uncertainty: f64,
    flags: Vec<&'static str>,
    reason_codes: Vec<String>,
    reason_codes_dropped: usize,
}

fn describe_reply(raw: &str) -> Result<Described, Code> {
    let core = parse_classifier_reply(raw.as_bytes()).map_err(|error| {
        if chain(&error).contains("technical error") {
            "classifier_reported_error"
        } else {
            "classifier_reply_invalid"
        }
    })?;
    let mut seen = BTreeSet::new();
    for label in &core.actions {
        if !CATEGORIES.contains(&label.as_str()) || !seen.insert(label.clone()) {
            return Err("classifier_reply_invalid");
        }
    }
    let unit = |x: f64| x.is_finite() && (0.0..=1.0).contains(&x);
    if !unit(core.confidence) || !unit(core.uncertainty) {
        return Err("classifier_reply_invalid");
    }
    let extras: Value = serde_json::from_str(raw).map_err(|_| "classifier_reply_invalid")?;
    let flags = FLAG_KEYS
        .iter()
        .copied()
        .filter(|key| extras[*key] == Value::Bool(true))
        .collect();
    let mut reason_codes = Vec::new();
    let mut dropped = 0;
    if let Some(codes) = extras["reason_codes"].as_array() {
        for code in codes {
            match code.as_str() {
                Some(text) if REASON_CODES.contains(&text) && reason_codes.len() < MAX_CODES => {
                    reason_codes.push(text.to_owned())
                }
                _ => dropped += 1,
            }
        }
    }
    let mut actions: Vec<String> = CATEGORIES
        .iter()
        .filter(|label| seen.contains(**label))
        .map(|label| (*label).to_owned())
        .collect();
    actions.dedup();
    Ok(Described {
        actions,
        unknown: core.unknown,
        confidence: core.confidence,
        uncertainty: core.uncertainty,
        flags,
        reason_codes,
        reason_codes_dropped: dropped,
    })
}

// ---------------------------------------------------------------- report

pub struct Preview {
    pub report: Value,
    pub exit: i32,
}

fn base(identity: Result<&Value, Code>, choice: ProfileChoice) -> Map<String, Value> {
    let mut report = Map::new();
    report.insert("schema".into(), json!(SCHEMA));
    report.insert("non_authoritative".into(), json!(true));
    report.insert("notice".into(), json!(NOTICE));
    report.insert("policy_verdict".into(), json!(null));
    report.insert("missing_context".into(), json!(MISSING_CONTEXT));
    report.insert(
        "limits".into(),
        json!({"max_frame_bytes": MAX_FRAME_BYTES, "max_classifier_input_bytes": MAX_INPUT,
            "request_deadline_ms": REQUEST_DEADLINE.as_millis() as u64}),
    );
    report.insert(
        "profile".into(),
        json!({"format": choice.format, "server_id": choice.server_id}),
    );
    match identity {
        Ok(value) => {
            report.insert("identity".into(), value.clone());
        }
        Err(code) => {
            report.insert("identity".into(), json!(null));
            report.insert("identity_unavailable".into(), json!(code));
        }
    }
    report
}

fn finish(mut report: Map<String, Value>, outcome: &str, exit: i32) -> Preview {
    report.insert("outcome".into(), json!(outcome));
    report.insert("exit".into(), json!(exit));
    Preview {
        report: Value::Object(report),
        exit,
    }
}

/// Core of the preview, independent of how the classifier is reached.
pub fn preview_with(
    choice: ProfileChoice,
    frame: Result<Vec<u8>, Code>,
    identity: Result<Value, Code>,
    classifier: &dyn Classify,
) -> Preview {
    let mut report = base(identity.as_ref().map_err(|code| *code), choice);
    let refused = |mut report: Map<String, Value>, code: Code| {
        report.insert("refusal".into(), json!({"stage": "input", "code": code}));
        finish(report, "refused", EXIT_REFUSED)
    };
    let frame = match frame.and_then(|bytes| parse_frame(&bytes)) {
        Ok(frame) => frame,
        Err(code) => return refused(report, code),
    };
    let reviewed = match load_reviewed(choice) {
        Ok(reviewed) => reviewed,
        Err(code) => {
            report.insert(
                "technical_error".into(),
                json!({"stage": "profile", "code": code}),
            );
            return finish(report, "technical_error", EXIT_TECHNICAL);
        }
    };
    report.insert("frame".into(), json!({"form": frame.form}));
    // Reviewed semantics (operator-pinned original definition) vs supplied metadata.
    let definition = reviewed_definition(&reviewed, &frame.tool);
    report.insert(
        "tool".into(),
        printable_tool(&frame.tool, definition.is_some()),
    );
    let profile = reviewed.profiles.get(&frame.tool);
    let reviewed_description = definition
        .and_then(|d| d["description"].as_str())
        .map(str::to_owned);
    let reviewed_schema = definition.map(|d| d["inputSchema"].clone());
    let supplied_schema_digest = frame
        .schema
        .as_ref()
        .map(|s| sha(&serde_json::to_vec(s).unwrap_or_default()));
    let supplied_description_digest = frame.description.as_ref().map(|d| sha(d.as_bytes()));
    let differs = definition.is_some()
        && (frame
            .description
            .as_ref()
            .is_some_and(|d| Some(d) != reviewed_description.as_ref())
            || frame
                .schema
                .as_ref()
                .is_some_and(|s| Some(s) != reviewed_schema.as_ref()));
    let supplied_present = frame.description.is_some() || frame.schema.is_some();
    report.insert(
        "metadata".into(),
        json!({
            "reviewed": definition.is_some(),
            "reviewed_description_sha256": reviewed_description.as_ref().map(|d| sha(d.as_bytes())),
            "reviewed_schema_sha256": reviewed_schema.as_ref().map(|s| sha(&serde_json::to_vec(s).unwrap_or_default())),
            "supplied_description_sha256": supplied_description_digest,
            "supplied_schema_sha256": supplied_schema_digest,
            "supplied_differs_from_reviewed": if definition.is_some() && supplied_present { json!(differs) } else { json!(null) },
            "classifier_saw": if definition.is_some() { "reviewed_definition" }
                else if supplied_present { "supplied_untrusted" } else { "name_and_arguments_only" },
            "note": "Supplied description and schema are untrusted evidence; for a tool in the \
reviewed profile the reviewed definition is used and supplied metadata is ignored.",
        }),
    );

    // Validation through the original selected profile validator.
    let declared_properties = reviewed_schema
        .as_ref()
        .and_then(|s| s["properties"].as_object())
        .map_or(0, Map::len);
    let arguments_value = Value::Object(frame.arguments.clone());
    let (validation, accepted, rejected) = match profile {
        None => (
            json!({"status": "not_in_reviewed_profile", "code": "tool_not_in_reviewed_profile"}),
            false,
            false,
        ),
        Some(profile) => match profile.unsupported_reason {
            Some(reason) => (
                json!({"status": "unsupported_by_profile", "code": reason}),
                false,
                false,
            ),
            None => match profile.validate_arguments(&arguments_value) {
                Ok(()) => (json!({"status": "accepted", "code": null}), true, false),
                Err(error) => (
                    json!({"status": "rejected", "code": validation_code(&error)}),
                    false,
                    true,
                ),
            },
        },
    };
    report.insert("validation".into(), validation);
    report.insert(
        "resources".into(),
        if accepted {
            summarize_resources(&frame.arguments, declared_properties)
        } else {
            json!({"extraction": "not_extracted_arguments_not_accepted", "items": [],
                "unrecognized_argument_count": frame.arguments.len()})
        },
    );

    // Classifier input is the production semantic input, built by `Invocation` itself.
    let (description, schema) = match definition {
        Some(definition) => (
            reviewed_description.clone().unwrap_or_default(),
            definition["inputSchema"].clone(),
        ),
        None => (
            frame.description.clone().unwrap_or_default(),
            frame.schema.clone().unwrap_or_else(|| json!({})),
        ),
    };
    let invocation = Invocation {
        server_id: choice.server_id.to_owned(),
        host_call_id: Value::Null,
        registry_sha256: String::new(),
        snapshot_sha256: String::new(),
        schema_sha256: String::new(),
        tool: frame.tool.clone(),
        description,
        schema,
        definition: Value::Null,
        server_info: Value::Null,
        definition_sha256: String::new(),
        input_sha256: String::new(),
        classifier_revision: None,
        args: arguments_value,
        baseline: ActionClass::ReadOnly,
    };
    let input = match serde_json::to_string(&invocation.semantic_input()) {
        Ok(input) if input.len() <= MAX_INPUT => input,
        _ => {
            report.insert(
                "technical_error".into(),
                json!({"stage": "classifier", "code": "classifier_input_too_large"}),
            );
            return finish(report, "technical_error", EXIT_TECHNICAL);
        }
    };
    let described = match classifier
        .classify_raw(&input)
        .and_then(|raw| describe_reply(&raw))
    {
        Ok(described) => described,
        Err(code) => {
            report.insert(
                "technical_error".into(),
                json!({"stage": "classifier", "code": code,
                "note": "A technical failure is not a classification and not an unknown result."}),
            );
            return finish(report, "technical_error", EXIT_TECHNICAL);
        }
    };

    // Conservative effective unknown: unreviewed tool or non-accepted arguments can never
    // read as fully known, while known risky labels are kept.
    let mut reasons = Vec::new();
    if described.unknown {
        reasons.push("classifier_unknown");
    }
    if definition.is_none() {
        reasons.push("tool_not_in_reviewed_profile");
    }
    if rejected {
        reasons.push("arguments_rejected_by_profile");
    }
    let effective_unknown = !reasons.is_empty();
    let mixed = described.actions.len() > 1;
    let send_data = described.actions.iter().any(|a| a == "send_data");
    let resource_missing =
        report["resources"]["extraction"] == "missing" && !described.actions.is_empty();
    report.insert(
        "classification".into(),
        json!({
            "labels": described.actions,
            "unknown": described.unknown,
            "effective_unknown": effective_unknown,
            "effective_unknown_reasons": reasons,
            "mixed_actions": mixed,
            "confidence": described.confidence,
            "uncertainty": described.uncertainty,
            "flags": described.flags,
            "reason_codes": described.reason_codes,
            "reason_codes_dropped": described.reason_codes_dropped,
            "free_text_reason": "omitted",
        }),
    );
    report.insert(
        "destinations".into(),
        json!({"extraction": if send_data { "missing" } else { "none_indicated" },
            "note": if send_data { "send_data was labelled but this preview extracts no destination" } else { "" }}),
    );
    let mut missing = Vec::new();
    if resource_missing {
        missing.push("resource_extraction_missing");
    }
    if send_data {
        missing.push("destination_extraction_missing");
    }
    report.insert("missing_extraction".into(), json!(missing));

    let outcome = match (rejected, effective_unknown, described.actions.is_empty()) {
        (true, _, _) => "refused",
        (false, true, true) => "unknown",
        (false, true, false) => "partial_unknown",
        (false, false, false) => "classified",
        (false, false, true) => "no_effects_recognized",
    };
    if outcome == "refused" {
        // The selected profile's validator rejects these arguments; the description above
        // is still shown so known risky labels are not hidden.
        let code = report["validation"]["code"].clone();
        report.insert("refusal".into(), json!({"stage": "profile", "code": code}));
        return finish(report, "refused", EXIT_REFUSED);
    }
    finish(report, outcome, EXIT_OK)
}

/// Identity of the installed package, verified now. Altered pins fail here.
pub fn identity(home: &Path, choice: ProfileChoice) -> Result<Value, Code> {
    let verified: Verified = Store::new(home)
        .current()
        .map_err(|error| package_code(&error))?;
    let manifest_digest = load_reviewed(choice)
        .map(|r| sha(&serde_json::to_vec(&r.manifest).unwrap_or_default()))
        .ok();
    Ok(json!({
        "source": SOURCE,
        "package_id": verified.id,
        "classifier_name": verified.classifier_name,
        "classifier_sha256": verified.classifier_sha256,
        "worker_sha256": verified.worker_sha256,
        "worker_protocol": WORKER_PROTOCOL,
        "interpreter_sha256": verified.python.sha256,
        "interpreter_version": verified.python.version,
        "profile_format": choice.format,
        "reviewed_manifest_sha256": manifest_digest,
    }))
}

/// Production entry: installed package under `home`, bounded worker, no fallback.
pub fn run(home: &Path, profile: &str, frame: &str) -> Preview {
    let choice = match parse_profile(profile) {
        Ok(choice) => choice,
        Err(code) => {
            let choice = ProfileChoice {
                format: "unsupported",
                server_id: "unsupported",
            };
            let mut report = base(Err("not_evaluated"), choice);
            report.insert("refusal".into(), json!({"stage": "input", "code": code}));
            return finish(report, "refused", EXIT_REFUSED);
        }
    };
    let frame = read_frame(frame);
    let identity = identity(home, choice);
    // The worker is only constructed (never started) here; refused frames start nothing.
    // `PackagedClassifier` kills and reaps its owned child when dropped at the end of
    // this function, on every path including technical failure.
    match &identity {
        Ok(_) => match PackagedClassifier::from_home(home) {
            Ok(classifier) => preview_with(choice, frame, identity, &classifier),
            Err(error) => {
                let code = package_code(&error);
                preview_with(choice, frame, identity, &Unavailable(code))
            }
        },
        Err(code) => {
            let unavailable = Unavailable(code);
            preview_with(choice, frame, identity, &unavailable)
        }
    }
}

// ---------------------------------------------------------------- rendering

fn text_list(value: &Value) -> String {
    let items: Vec<&str> = value
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if items.is_empty() {
        "-".into()
    } else {
        items.join(", ")
    }
}

/// Human text derived from the same sanitized report as the JSON output.
pub fn render_text(report: &Value) -> String {
    let mut out = String::new();
    let mut line = |text: String| {
        out.push_str(&text);
        out.push('\n');
    };
    line("TOOL-CALL PREVIEW (non-authoritative, non-executing)".into());
    line(format!(
        "outcome: {}",
        report["outcome"].as_str().unwrap_or("?")
    ));
    line(format!(
        "notice: {}",
        report["notice"].as_str().unwrap_or("")
    ));
    let id = &report["identity"];
    if id.is_object() {
        line(format!("source: {}", id["source"].as_str().unwrap_or("?")));
        line(format!(
            "package: {}",
            id["package_id"].as_str().unwrap_or("?")
        ));
        line(format!(
            "classifier sha256: {}",
            id["classifier_sha256"].as_str().unwrap_or("?")
        ));
        line(format!(
            "interpreter: {} sha256 {}",
            id["interpreter_version"].as_str().unwrap_or("?"),
            id["interpreter_sha256"].as_str().unwrap_or("?")
        ));
    } else {
        line(format!(
            "identity: unavailable ({})",
            report["identity_unavailable"].as_str().unwrap_or("?")
        ));
    }
    line(format!(
        "profile: {} (server {})",
        report["profile"]["format"].as_str().unwrap_or("?"),
        report["profile"]["server_id"].as_str().unwrap_or("?")
    ));
    if report["tool"].is_object() {
        let t = &report["tool"];
        line(format!(
            "tool: {} (digest8 {})",
            t["name"].as_str().unwrap_or("<redacted>"),
            t["name_digest8"].as_str().unwrap_or("?")
        ));
    }
    if report["metadata"].is_object() {
        let m = &report["metadata"];
        line(format!(
            "metadata: reviewed={} classifier_saw={} supplied_differs_from_reviewed={}",
            m["reviewed"],
            m["classifier_saw"].as_str().unwrap_or("?"),
            m["supplied_differs_from_reviewed"]
        ));
    }
    if report["validation"].is_object() {
        line(format!(
            "validation: {} {}",
            report["validation"]["status"].as_str().unwrap_or("?"),
            report["validation"]["code"].as_str().unwrap_or("")
        ));
    }
    if report["classification"].is_object() {
        let c = &report["classification"];
        line(format!("labels: {}", text_list(&c["labels"])));
        line(format!(
            "unknown: {} (effective {}; {})",
            c["unknown"],
            c["effective_unknown"],
            text_list(&c["effective_unknown_reasons"])
        ));
        line(format!("mixed actions: {}", c["mixed_actions"]));
        line(format!(
            "confidence: {} uncertainty: {}",
            c["confidence"], c["uncertainty"]
        ));
        line(format!("flags: {}", text_list(&c["flags"])));
        line(format!("reason codes: {}", text_list(&c["reason_codes"])));
    }
    if report["resources"].is_object() {
        let r = &report["resources"];
        line(format!(
            "resource extraction: {}",
            r["extraction"].as_str().unwrap_or("?")
        ));
        for item in r["items"].as_array().into_iter().flatten() {
            let ids: Vec<&str> = item["entries"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|e| e["id"].as_str())
                .collect();
            line(format!(
                "  {} {} x{} ids(digest8): {}",
                item["argument"].as_str().unwrap_or("?"),
                item["class"].as_str().unwrap_or("?"),
                item["count"],
                ids.join(",")
            ));
        }
        line(format!(
            "  other arguments (values not shown): {}",
            r["unrecognized_argument_count"]
        ));
    }
    if report["destinations"].is_object() {
        line(format!(
            "destination extraction: {}",
            report["destinations"]["extraction"].as_str().unwrap_or("?")
        ));
    }
    if report["refusal"].is_object() {
        line(format!(
            "refused at {}: {}",
            report["refusal"]["stage"].as_str().unwrap_or("?"),
            report["refusal"]["code"].as_str().unwrap_or("?")
        ));
    }
    if report["technical_error"].is_object() {
        line(format!(
            "TECHNICAL ERROR at {}: {} (not a classification, not an unknown result)",
            report["technical_error"]["stage"].as_str().unwrap_or("?"),
            report["technical_error"]["code"].as_str().unwrap_or("?")
        ));
    }
    line(format!(
        "missing context: {}",
        text_list(&report["missing_context"])
    ));
    line("raw arguments, path/secret values and free-text reasons are not shown".into());
    out
}

pub fn report_json(report: &Value) -> anyhow::Result<String> {
    let text = serde_json::to_string_pretty(report)?;
    anyhow::ensure!(text.len() <= MAX_REPORT_BYTES, "preview report exceeds cap");
    Ok(text)
}

// ---------------------------------------------------------------- export

/// Explicit private create-new export of the sanitized JSON report (Linux): absolute
/// destination, owner-only parent opened without following links, `O_EXCL|O_NOFOLLOW`,
/// mode 0600, bounded, removed again if the write fails. An existing path is never replaced.
#[cfg(target_os = "linux")]
pub fn export(report: &Value, destination: &Path) -> Result<(), Code> {
    export_inner(report, destination, &mut |_| Ok(()))
}

/// Test seam: `after_create` runs with the export directory's path once the exporter's unnamed
/// file exists and before it is written; an `Err` is handled exactly like a failed write.
/// Production passes a no-op.
#[cfg(target_os = "linux")]
fn export_inner(
    report: &Value,
    destination: &Path,
    after_create: &mut dyn FnMut(&Path) -> Result<(), ()>,
) -> Result<(), Code> {
    use std::ffi::CString;
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    let bytes = report_json(report).map_err(|_| "export_too_large")?;
    if !destination.is_absolute() {
        return Err("export_path_not_absolute");
    }
    let parent_path = destination.parent().ok_or("export_path_invalid")?;
    let name = destination.file_name().ok_or("export_path_invalid")?;
    let name = CString::new(name.as_bytes()).map_err(|_| "export_path_invalid")?;
    let mut dir = File::open("/").map_err(|_| "export_parent_unsafe")?;
    for part in parent_path.components() {
        match part {
            Component::RootDir => (),
            Component::Normal(segment) => {
                let segment =
                    CString::new(segment.as_bytes()).map_err(|_| "export_path_invalid")?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        segment.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err("export_parent_unsafe");
                }
                dir = unsafe { File::from_raw_fd(fd) };
            }
            _ => return Err("export_path_invalid"),
        }
    }
    let owner = dir.metadata().map_err(|_| "export_parent_unsafe")?;
    if !owner.is_dir() || owner.uid() != unsafe { libc::geteuid() } || owner.mode() & 0o077 != 0 {
        return Err("export_parent_not_private");
    }
    // Publish by identity, not by name. The report is written to an unnamed regular file
    // (O_TMPFILE) inside the validated, pinned directory and linked into place from that exact
    // descriptor. No temporary name exists for another process to substitute, an object at the
    // destination is never replaced (linkat does not replace), and nothing is ever unlinked:
    // an unnamed inode disappears with its descriptor. A filesystem without unnamed files is
    // refused instead of falling back to a named temporary file.
    let euid = unsafe { libc::geteuid() };
    let here = CString::new(".").map_err(|_| "export_path_invalid")?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            here.as_ptr(),
            libc::O_TMPFILE | libc::O_WRONLY | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EOPNOTSUPP) | Some(libc::EISDIR) | Some(libc::EINVAL) => {
                "export_filesystem_unsupported"
            }
            _ => "export_destination_exists_or_unwritable",
        });
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let created = file.metadata().map_err(|_| "export_write_failed")?;
    if !created.is_file()
        || created.uid() != euid
        || created.mode() & 0o077 != 0
        || created.nlink() != 0
        || created.dev() != owner.dev()
    {
        return Err("export_write_failed");
    }
    if after_create(parent_path).is_err()
        || file
            .write_all(bytes.as_bytes())
            .and_then(|_| file.sync_all())
            .is_err()
    {
        return Err("export_write_failed");
    }
    // The pinned directory must still be the same private directory when the link is made.
    let pinned = dir.metadata().map_err(|_| "export_parent_unsafe")?;
    if !pinned.is_dir()
        || pinned.uid() != euid
        || pinned.mode() & 0o077 != 0
        || pinned.dev() != owner.dev()
        || pinned.ino() != owner.ino()
    {
        return Err("export_parent_unsafe");
    }
    let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| "export_path_invalid")?;
    let linked = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if linked != 0 {
        return Err(
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
                "export_destination_exists_or_unwritable"
            } else {
                "export_write_failed"
            },
        );
    }
    // Confirm the name now refers to the object this call created; never remove anything.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    let mine = file.metadata().map_err(|_| "export_write_failed")?;
    if rc != 0 || st.st_dev != mine.dev() || st.st_ino != mine.ino() {
        return Err("export_write_failed");
    }
    dir.sync_all().map_err(|_| "export_write_failed")?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn export(_report: &Value, _destination: &Path) -> Result<(), Code> {
    Err("export_requires_linux")
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests;
