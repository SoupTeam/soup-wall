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

#[derive(Debug)]
enum Shape {
    Object(BTreeMap<String, InputSchema>, BTreeSet<String>),
    Array(Box<InputSchema>),
    String {
        min_chars: usize,
        max_chars: Option<usize>,
        max_bytes: usize,
    },
    Integer,
    Number,
    Boolean,
    Null,
}

/// Deliberately smaller than general JSON Schema. Unknown keywords are errors.
/// The original schema remains in the discovery snapshot, not in this validator.
#[derive(Debug)]
pub struct InputSchema(Shape);

impl InputSchema {
    pub fn read(value: &Value) -> anyhow::Result<Self> {
        ensure!(
            value["type"] == "object",
            "MCP input profile requires an object"
        );
        Self::node(value, 0, &mut 0)
    }

    fn node(value: &Value, depth: usize, nodes: &mut usize) -> anyhow::Result<Self> {
        *nodes += 1;
        ensure!(
            depth <= MAX_DEPTH && *nodes <= MAX_SCHEMA_NODES,
            "MCP schema exceeds profile limits"
        );
        let map = value.as_object().context("MCP schema must be an object")?;
        let kind = value["type"].as_str().context("MCP schema type missing")?;
        for key in map.keys() {
            let supported = matches!(key.as_str(), "type" | "title" | "description" | "default")
                || (kind == "object"
                    && matches!(
                        key.as_str(),
                        "properties" | "required" | "additionalProperties"
                    ))
                || (kind == "array" && key == "items")
                || (kind == "string" && matches!(key.as_str(), "minLength" | "maxLength"));
            ensure!(supported, "unsupported MCP schema keyword");
        }
        for key in ["title", "description"] {
            ensure!(
                map.get(key).is_none_or(Value::is_string),
                "invalid MCP schema annotation"
            );
        }
        let shape = match kind {
            "object" => {
                ensure!(
                    value["additionalProperties"] == false,
                    "MCP objects must explicitly be closed"
                );
                let properties = value["properties"]
                    .as_object()
                    .context("MCP properties missing")?;
                ensure!(properties.len() <= MAX_ITEMS, "too many MCP properties");
                let mut fields = BTreeMap::new();
                for (name, schema) in properties {
                    fields.insert(name.clone(), Self::node(schema, depth + 1, nodes)?);
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
            "array" => Shape::Array(Box::new(Self::node(
                value.get("items").context("MCP array items missing")?,
                depth + 1,
                nodes,
            )?)),
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
                let max_bytes = max_chars.map_or(DEFAULT_STRING_BYTES, |max| max * 4);
                Shape::String {
                    min_chars,
                    max_chars,
                    max_bytes,
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
        Ok(Self(shape))
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
        let valid = match &self.0 {
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
            Shape::Array(items) => {
                let args = value
                    .as_array()
                    .context("MCP arguments must match array schema")?;
                ensure!(args.len() <= MAX_ITEMS, "too many MCP array elements");
                for value in args {
                    items.check(value, depth + 1, nodes)?;
                }
                true
            }
            Shape::String {
                min_chars,
                max_chars,
                max_bytes,
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
        ensure!(valid, "MCP argument type or size mismatch");
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
}
