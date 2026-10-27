// SPDX-License-Identifier: Apache-2.0
//! Bounded SOU-11 input profile. Validation never applies defaults, coerces
//! arguments, follows references, launches commands or grants permissions.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, ensure, Context};
use serde::Serialize;
use serde_json::Value;

pub const MAX_DEPTH: usize = 8;
pub const MAX_ITEMS: usize = 256;
pub const MAX_SCHEMA_NODES: usize = 1024;
const DEFAULT_STRING_BYTES: usize = 16 * 1024;
const MAX_STRING_CHARACTERS: usize = 65_536;
/// Reviewed budget for one decoded result string (a text content block or a
/// structured string) of a selected original server. It is deliberately
/// separate from argument validation, which keeps `DEFAULT_STRING_BYTES`.
/// Equal to the default native record cap and provenance input limit, so a
/// supported result never relies on raising either of them.
pub const RESULT_STRING_BYTES: usize = 262_144;

/// Which side of a call a schema validates. The role only selects the default
/// byte budget of strings without an explicit `maxLength`; explicit original
/// constraints and type checks are identical for both roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Arguments,
    Result,
}

impl Role {
    fn default_string_bytes(self) -> usize {
        match self {
            Role::Arguments => DEFAULT_STRING_BYTES,
            Role::Result => RESULT_STRING_BYTES,
        }
    }
}

/// A result string exceeded its byte budget. Typed so the transport can
/// report the specific limit instead of a generic shape refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultBudgetExceeded {
    pub limit: usize,
}

impl std::fmt::Display for ResultBudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MCP result string exceeds the {}-byte budget",
            self.limit
        )
    }
}

impl std::error::Error for ResultBudgetExceeded {}

#[derive(Debug)]
enum Shape {
    Object(BTreeMap<String, InputSchema>, BTreeSet<String>),
    Array {
        items: Box<InputSchema>,
        min_items: usize,
        max_items: usize,
    },
    String {
        min_chars: usize,
        max_chars: Option<usize>,
        max_bytes: usize,
        role: Role,
    },
    Integer,
    Number,
    Boolean,
    Null,
}

/// Deliberately smaller than general JSON Schema. Unknown keywords are errors.
/// The original schema remains in the discovery snapshot, not in this validator.
#[derive(Debug)]
pub struct InputSchema {
    shape: Shape,
    choices: Option<Vec<Value>>,
}

impl InputSchema {
    pub fn read(value: &Value) -> anyhow::Result<Self> {
        ensure!(
            value["type"] == "object",
            "MCP input profile requires an object"
        );
        Self::node(value, 0, &mut 0, false, Role::Arguments)
    }

    /// The selected real-server profile preserves its original open schemas,
    /// but deliberately accepts only declared fields. Unknown arguments are
    /// refused rather than stripped by the upstream SDK.
    pub fn read_selected(value: &Value) -> anyhow::Result<Self> {
        Self::read_selected_role(value, Role::Arguments)
    }

    /// Selected original schema in an explicit validation role. Use
    /// `Role::Result` only for a server's `outputSchema`.
    pub fn read_selected_role(value: &Value, role: Role) -> anyhow::Result<Self> {
        ensure!(
            value["type"] == "object",
            "MCP input profile requires an object"
        );
        Self::node(value, 0, &mut 0, true, role)
    }

    fn node(
        value: &Value,
        depth: usize,
        nodes: &mut usize,
        selected: bool,
        role: Role,
    ) -> anyhow::Result<Self> {
        *nodes += 1;
        ensure!(
            depth <= MAX_DEPTH && *nodes <= MAX_SCHEMA_NODES,
            "MCP schema exceeds profile limits"
        );
        let map = value.as_object().context("MCP schema must be an object")?;
        let kind = value["type"].as_str().context("MCP schema type missing")?;
        for key in map.keys() {
            let supported = matches!(
                key.as_str(),
                "type" | "title" | "description" | "default" | "enum" | "const"
            ) || (kind == "object"
                && matches!(
                    key.as_str(),
                    "properties" | "required" | "additionalProperties"
                ))
                || (selected && depth == 0 && key == "$schema")
                || (kind == "array" && matches!(key.as_str(), "items" | "minItems" | "maxItems"))
                || (kind == "string" && matches!(key.as_str(), "minLength" | "maxLength"));
            ensure!(supported, "unsupported MCP schema keyword");
        }
        for key in ["title", "description"] {
            ensure!(
                map.get(key)
                    .is_none_or(|v| v.as_str().is_some_and(|s| s.len() <= DEFAULT_STRING_BYTES)),
                "invalid MCP schema annotation"
            );
        }
        if let Some(dialect) = map.get("$schema") {
            ensure!(
                matches!(
                    dialect.as_str(),
                    Some(
                        "http://json-schema.org/draft-07/schema#"
                            | "https://json-schema.org/draft/2020-12/schema"
                    )
                ),
                "unsupported MCP schema dialect"
            );
        }
        let shape = match kind {
            "object" => {
                ensure!(
                    value["additionalProperties"] == false
                        || (selected && !map.contains_key("additionalProperties")),
                    "MCP objects must explicitly be closed"
                );
                let properties = value["properties"]
                    .as_object()
                    .context("MCP properties missing")?;
                ensure!(properties.len() <= MAX_ITEMS, "too many MCP properties");
                let mut fields = BTreeMap::new();
                for (name, schema) in properties {
                    fields.insert(
                        name.clone(),
                        Self::node(schema, depth + 1, nodes, selected, role)?,
                    );
                }
                let mut required = BTreeSet::new();
                if let Some(value) = map.get("required") {
                    for field in value.as_array().context("invalid MCP required fields")? {
                        let name = field.as_str().context("invalid MCP required field")?;
                        ensure!(
                            fields.contains_key(name) && required.insert(name.to_owned()),
                            "unknown or duplicate MCP required field"
                        );
                    }
                }
                Shape::Object(fields, required)
            }
            "array" => {
                let bound = |key: &str| -> anyhow::Result<Option<usize>> {
                    map.get(key)
                        .map(|v| {
                            let n = v.as_u64().context("invalid MCP array bound")?;
                            ensure!(
                                n <= MAX_ITEMS as u64,
                                "MCP array bound exceeds profile limits"
                            );
                            Ok(n as usize)
                        })
                        .transpose()
                };
                let min_items = bound("minItems")?.unwrap_or(0);
                let max_items = bound("maxItems")?.unwrap_or(MAX_ITEMS);
                ensure!(min_items <= max_items, "inconsistent MCP array bounds");
                Shape::Array {
                    items: Box::new(Self::node(
                        value.get("items").context("MCP array items missing")?,
                        depth + 1,
                        nodes,
                        selected,
                        role,
                    )?),
                    min_items,
                    max_items,
                }
            }
            "string" => {
                let bound = |key: &str| -> anyhow::Result<Option<usize>> {
                    map.get(key)
                        .map(|value| {
                            let number = value
                                .as_u64()
                                .context("MCP string bound must be a nonnegative integer")?;
                            ensure!(
                                number <= MAX_STRING_CHARACTERS as u64,
                                "MCP string bound exceeds profile limits"
                            );
                            Ok(number as usize)
                        })
                        .transpose()
                };
                let min_chars = bound("minLength")?.unwrap_or(0);
                let max_chars = bound("maxLength")?;
                ensure!(
                    max_chars.is_none_or(|max| min_chars <= max),
                    "MCP string bounds are inconsistent"
                );
                // JSON Schema lengths count Unicode scalar values. An explicit
                // bound permits at most four UTF-8 bytes per scalar; operation
                // authority independently applies its tighter byte limit.
                // An explicit original bound keeps its own byte limit in
                // either role; the role budget applies only without one.
                let max_bytes = max_chars.map_or(role.default_string_bytes(), |max| max * 4);
                Shape::String {
                    min_chars,
                    max_chars,
                    max_bytes,
                    role,
                }
            }
            "integer" => Shape::Integer,
            "number" => Shape::Number,
            "boolean" => Shape::Boolean,
            "null" => Shape::Null,
            _ => bail!("unsupported MCP schema type"),
        };
        // `default` is preserved as metadata only. It never fills an absent
        // field; resource defaults require separately reviewed semantics.
        ensure!(
            !(map.contains_key("enum") && map.contains_key("const")),
            "ambiguous MCP enum and const"
        );
        let choices = if let Some(v) = map.get("enum") {
            let entries = v.as_array().context("MCP enum must be an array")?;
            ensure!(
                !entries.is_empty() && entries.len() <= MAX_ITEMS,
                "MCP enum exceeds profile limits"
            );
            let mut unique = BTreeSet::new();
            for v in entries {
                ensure!(
                    v.is_null() || v.is_string() || v.is_boolean() || v.is_number(),
                    "MCP enum only supports scalar values"
                );
                ensure!(
                    v.to_string().len() <= DEFAULT_STRING_BYTES && unique.insert(v.to_string()),
                    "invalid MCP enum value"
                );
            }
            Some(entries.clone())
        } else if let Some(v) = map.get("const") {
            ensure!(
                v.is_null() || v.is_string() || v.is_boolean() || v.is_number(),
                "MCP const only supports scalar values"
            );
            ensure!(
                v.to_string().len() <= DEFAULT_STRING_BYTES,
                "MCP const exceeds profile limits"
            );
            Some(vec![v.clone()])
        } else {
            None
        };
        let schema = Self { shape, choices };
        if let Some(choices) = &schema.choices {
            for choice in choices {
                schema.check(choice, 0, &mut 0)?;
            }
        }
        Ok(schema)
    }

    pub fn validate(&self, value: &Value) -> anyhow::Result<()> {
        self.check(value, 0, &mut 0)
    }

    fn check(&self, value: &Value, depth: usize, nodes: &mut usize) -> anyhow::Result<()> {
        *nodes += 1;
        ensure!(
            depth <= MAX_DEPTH && *nodes <= 4096,
            "MCP arguments exceed profile limits"
        );
        ensure!(
            self.choices
                .as_ref()
                .is_none_or(|choices| choices.contains(value)),
            "MCP argument is outside enum or const"
        );
        let valid = match &self.shape {
            Shape::Object(fields, required) => {
                let args = value
                    .as_object()
                    .context("MCP arguments must match object schema")?;
                ensure!(
                    required.iter().all(|key| args.contains_key(key)),
                    "MCP required argument missing"
                );
                ensure!(args.len() <= MAX_ITEMS, "too many MCP arguments");
                for (key, value) in args {
                    fields.get(key).context("unknown MCP argument")?.check(
                        value,
                        depth + 1,
                        nodes,
                    )?;
                }
                true
            }
            Shape::Array {
                items,
                min_items,
                max_items,
            } => {
                let args = value
                    .as_array()
                    .context("MCP arguments must match array schema")?;
                ensure!(
                    args.len() >= *min_items && args.len() <= *max_items,
                    "MCP array length mismatch"
                );
                for value in args {
                    items.check(value, depth + 1, nodes)?;
                }
                true
            }
            Shape::String {
                min_chars,
                max_chars,
                max_bytes,
                role: _,
            } => value.as_str().is_some_and(|text| {
                if text.len() > *max_bytes {
                    return false;
                }
                let characters = text.chars().count();
                characters >= *min_chars && max_chars.is_none_or(|max| characters <= max)
            }),
            Shape::Integer => value.is_i64() || value.is_u64(),
            Shape::Number => value.as_f64().is_some_and(f64::is_finite),
            Shape::Boolean => value.is_boolean(),
            Shape::Null => value.is_null(),
        };
        if !valid {
            if let (
                Shape::String {
                    max_bytes,
                    role: Role::Result,
                    ..
                },
                Some(text),
            ) = (&self.shape, value.as_str())
            {
                if text.len() > *max_bytes {
                    return Err(ResultBudgetExceeded { limit: *max_bytes }.into());
                }
            }
            bail!("MCP argument type or size mismatch");
        }
        Ok(())
    }
}

/// Redacted inventory only. No command, argument, environment value, URL or
/// header is exported; configuration inspection never starts a connection.
#[derive(Debug, Serialize)]
pub struct HostServerSummary {
    pub name: String,
    pub transport: &'static str,
    pub supported: bool,
    pub requires_explicit_selection: bool,
}

/// Supports a selected Claude-style JSON file's `mcpServers` map. Other host
/// formats are explicitly outside this profile. Errors omit source contents.
pub fn inspect_host_config(bytes: &[u8]) -> anyhow::Result<Vec<HostServerSummary>> {
    ensure!(
        bytes.len() <= 1024 * 1024,
        "MCP host configuration exceeds limit"
    );
    let super::admission::Strict(value) = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid MCP host configuration JSON"))?;
    let servers = value
        .get("mcpServers")
        .and_then(Value::as_object)
        .context("unsupported MCP host configuration format")?;
    ensure!(
        servers.len() <= MAX_ITEMS,
        "too many configured MCP servers"
    );
    servers
        .iter()
        .map(|(name, entry)| {
            ensure!(
                !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control),
                "invalid configured MCP server name"
            );
            let map = entry
                .as_object()
                .context("invalid MCP server configuration")?;
            let local = map.get("type").is_none_or(|kind| kind == "stdio")
                && !map.contains_key("url")
                && map
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
                && map.get("args").is_none_or(|args| {
                    args.as_array()
                        .is_some_and(|a| a.iter().all(Value::is_string))
                });
            Ok(HostServerSummary {
                name: name.clone(),
                transport: if local { "stdio" } else { "unsupported" },
                supported: local,
                requires_explicit_selection: true,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn string_schema(extra: Value) -> Value {
        let mut string = json!({"type":"string"});
        string
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        json!({"type":"object","properties":{"text":string},"required":["text"],
            "additionalProperties":false})
    }

    #[test]
    fn explicit_create_string_bound_accepts_4_kib_and_authority_checks_bytes() {
        let schema = InputSchema::read(&crate::native::resource::create_file_schema()).unwrap();
        let bound = crate::native::resource::CREATE_FILE_MAX_CONTENT;
        assert!(schema
            .validate(&json!({"path":"new.txt","content":"a".repeat(bound)}))
            .is_ok());
        assert!(schema
            .validate(&json!({"path":"new.txt","content":"a".repeat(bound + 1)}))
            .is_err());
        // Character-valid non-ASCII input still needs the separate create-file
        // authority's 4 KiB UTF-8 byte check before admission or any effect.
        assert!(schema
            .validate(&json!({"path":"new.txt","content":"☃".repeat(3_000)}))
            .is_ok());
        assert!(schema.validate(&json!({"path":"","content":""})).is_err());
        assert!(schema
            .validate(&json!({"path":"new.txt","content":"","append":true}))
            .is_err());
    }

    #[test]
    fn string_lengths_count_unicode_scalars_without_changing_unbounded_profile() {
        let schema =
            InputSchema::read(&string_schema(json!({"minLength":2,"maxLength":2}))).unwrap();
        assert!(schema.validate(&json!({"text":"☃😀"})).is_ok());
        assert!(schema.validate(&json!({"text":"☃"})).is_err());
        assert!(schema.validate(&json!({"text":"☃😀a"})).is_err());
        let empty = InputSchema::read(&string_schema(json!({"maxLength":0}))).unwrap();
        assert!(empty.validate(&json!({"text":""})).is_ok());
        assert!(empty.validate(&json!({"text":"a"})).is_err());
        let bounded = InputSchema::read(&string_schema(json!({"maxLength":65_536}))).unwrap();
        assert!(bounded
            .validate(&json!({"text":"a".repeat(65_536)}))
            .is_ok());
        assert!(bounded
            .validate(&json!({"text":"a".repeat(65_537)}))
            .is_err());
        let legacy = InputSchema::read(&string_schema(json!({}))).unwrap();
        assert!(legacy
            .validate(&json!({"text":"a".repeat(16*1024)}))
            .is_ok());
        assert!(legacy
            .validate(&json!({"text":"a".repeat(16*1024+1)}))
            .is_err());
        assert!(legacy.validate(&json!({"text":"☃".repeat(6_000)})).is_err());
    }

    #[test]
    fn malformed_inconsistent_or_unbounded_string_constraints_are_refused() {
        for extra in [
            json!({"minLength":-1}),
            json!({"maxLength":1.5}),
            json!({"minLength":true}),
            json!({"maxLength":null}),
            json!({"maxLength":65_537}),
            json!({"minLength":65_537}),
            json!({"minLength":3,"maxLength":2}),
            json!({"pattern":".*"}),
        ] {
            assert!(
                InputSchema::read(&string_schema(extra.clone())).is_err(),
                "{extra}"
            );
        }
        // A string-only keyword cannot silently change a numeric schema.
        assert!(InputSchema::read(&json!({"type":"object","properties":{
            "number":{"type":"integer","maxLength":10}},"required":[],
            "additionalProperties":false}))
        .is_err());
    }
    #[test]
    fn selected_schema_enforces_enum_array_bounds_without_defaults_or_coercion() {
        let schema = InputSchema::read_selected(&json!({"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{
            "sort":{"type":"string","enum":["name","size"],"default":"name"},
            "paths":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":2}},"required":["paths"]})).unwrap();
        assert!(schema
            .validate(&json!({"paths":["a"],"sort":"size"}))
            .is_ok());
        assert!(schema.validate(&json!({"paths":["a"]})).is_ok());
        assert!(schema
            .validate(&json!({"paths":["a"],"sort":"unknown"}))
            .is_err());
        assert!(schema.validate(&json!({"paths":["a"],"sort":1})).is_err());
        assert!(schema.validate(&json!({"paths":[]})).is_err());
        assert!(schema.validate(&json!({"paths":["a","b","c"]})).is_err());
        assert!(schema
            .validate(&json!({"paths":["a"],"unlisted":true}))
            .is_err());
        assert!(schema.validate(&json!({})).is_err());
    }

    #[test]
    fn selected_schema_refuses_unimplemented_constraints_and_malformed_enum() {
        for constraint in [
            json!({"pattern":".*"}),
            json!({"format":"uri"}),
            json!({"enum":[]}),
            json!({"enum":["a","a"]}),
            json!({"enum":[{}]}),
            json!({"enum":[1]}),
            json!({"enum":["a"],"const":"a"}),
        ] {
            let mut field = json!({"type":"string"});
            field
                .as_object_mut()
                .unwrap()
                .extend(constraint.as_object().unwrap().clone());
            assert!(
                InputSchema::read_selected(&json!({"type":"object","properties":{"s":field}}))
                    .is_err()
            );
        }
        let open = json!({"type":"object","properties":{}});
        assert!(
            InputSchema::read(&open).is_err(),
            "legacy still requires explicit closed objects"
        );
        assert!(InputSchema::read_selected(&open).is_ok());
        assert!(InputSchema::read_selected(
            &json!({"type":"object","properties":{},"additionalProperties":true})
        )
        .is_err());
        assert!(InputSchema::read_selected(
            &json!({"$schema":"https://unreviewed.invalid/schema","type":"object","properties":{}})
        )
        .is_err());
    }
}
