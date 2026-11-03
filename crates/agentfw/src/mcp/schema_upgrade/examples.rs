// SPDX-License-Identifier: Apache-2.0
//! Bounded, deterministic review-pack proposals for supported changes.
//!
//! Every invocation example is checked against the accepted runtime validator
//! (`InputSchema::read_selected` of the *after* schema), so the
//! `schema_valid`/`schema_invalid` label is observed, not assumed. Values are
//! schema-shaped placeholders, enum/const members or values copied from the
//! snapshots; nothing is inferred from names or descriptions. Records are
//! proposals for human review, never labels, approvals or permission.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::{canonical_json, pointer_tokens, schema_at, sha_hex, Analysis, Finding, Nature};
use crate::mcp::input::InputSchema;

pub const MAX_RECORDS: usize = 512;
pub const MAX_RECORDS_PER_FINDING: usize = 4;
pub const MAX_STRING_CHARS: usize = 64;
pub const MAX_ARRAY_ITEMS: usize = 4;
pub const MAX_EXAMPLE_BYTES: usize = 4_096;
const MAX_BUILD_DEPTH: usize = crate::mcp::input::MAX_DEPTH;
const PLACEHOLDER: &str = "sw-review-placeholder";

pub(super) fn limits_json() -> Value {
    json!({
        "max_records": MAX_RECORDS,
        "max_records_per_finding": MAX_RECORDS_PER_FINDING,
        "max_string_chars": MAX_STRING_CHARS,
        "max_array_items": MAX_ARRAY_ITEMS,
        "max_example_bytes": MAX_EXAMPLE_BYTES,
        "max_build_depth": MAX_BUILD_DEPTH,
    })
}

pub(super) struct Generation {
    pub(super) records: Vec<Value>,
    pub(super) omitted: usize,
    pub(super) complete: bool,
    pub(super) gaps: Vec<Value>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    Valid,
    Invalid,
    /// Label taken from the validator without a prior expectation.
    Observe,
}

fn text(n: usize) -> String {
    format!("{PLACEHOLDER}-").chars().cycle().take(n).collect()
}

fn kinds(node: &Value) -> BTreeSet<&str> {
    match &node["type"] {
        Value::String(s) => [s.as_str()].into(),
        Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
        _ => BTreeSet::new(),
    }
}

/// A nonnegative integer bound as `usize`, saturating when it does not fit;
/// every caller compares the result against a small example bound.
fn bound(node: &Value, key: &str) -> Option<usize> {
    node[key]
        .as_u64()
        .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
}

/// Smallest schema-valid value inside the example bounds.
fn minimal(node: &Value, depth: usize) -> Result<Value, &'static str> {
    if depth > MAX_BUILD_DEPTH {
        return Err("schema deeper than the example build bound");
    }
    if let Some(choices) = node["enum"].as_array() {
        return choices
            .iter()
            .min_by_key(|v| canonical_json(v))
            .cloned()
            .ok_or("empty enum");
    }
    if let Some(value) = node.get("const") {
        return Ok(value.clone());
    }
    let ty = node["type"]
        .as_str()
        .ok_or("type is not a single supported type")?;
    match ty {
        "object" => {
            let props = node["properties"]
                .as_object()
                .ok_or("object without properties")?;
            let mut out = Map::new();
            let mut required: Vec<&str> = node["required"]
                .as_array()
                .map(|r| r.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            required.sort_unstable();
            for name in required {
                let child = props.get(name).ok_or("required field without schema")?;
                out.insert(name.to_owned(), minimal(child, depth + 1)?);
            }
            Ok(Value::Object(out))
        }
        "array" => {
            let n = bound(node, "minItems").unwrap_or(0);
            if n > MAX_ARRAY_ITEMS {
                return Err("minItems exceeds the example array bound");
            }
            let item = minimal(node.get("items").ok_or("array without items")?, depth + 1)?;
            Ok(Value::Array(vec![item; n]))
        }
        "string" => {
            let min = bound(node, "minLength").unwrap_or(0);
            let max = bound(node, "maxLength").unwrap_or(usize::MAX);
            if min > MAX_STRING_CHARS {
                return Err("minLength exceeds the example string bound");
            }
            Ok(json!(text(PLACEHOLDER.len().clamp(min, max.max(min)))))
        }
        "integer" | "number" => Ok(json!(0)),
        "boolean" => Ok(json!(false)),
        "null" => Ok(Value::Null),
        _ => Err("unsupported type"),
    }
}

/// Like `minimal`, but also populates optional properties and one array item,
/// so nested additions (for example a new nested destination) are exercised.
fn full(node: &Value, depth: usize) -> Result<Value, &'static str> {
    if depth > MAX_BUILD_DEPTH || node.get("enum").is_some() || node.get("const").is_some() {
        return minimal(node, depth);
    }
    match node["type"].as_str() {
        Some("object") => {
            let props = node["properties"]
                .as_object()
                .ok_or("object without properties")?;
            let mut out = Map::new();
            for (name, child) in props {
                out.insert(name.clone(), full(child, depth + 1)?);
            }
            Ok(Value::Object(out))
        }
        Some("array") => {
            let mut value = minimal(node, depth)?;
            let max = node["maxItems"].as_u64().unwrap_or(1);
            if let (Some(items), true) = (value.as_array_mut(), max >= 1) {
                if items.is_empty() {
                    items.push(full(
                        node.get("items").ok_or("array without items")?,
                        depth + 1,
                    )?);
                }
            }
            Ok(value)
        }
        _ => minimal(node, depth),
    }
}

fn wrong_type(node: &Value) -> Value {
    if kinds(node).contains("string") {
        json!(12345)
    } else {
        json!("sw-review-wrong-type")
    }
}

/// Set a value at an argument pointer, materializing absent parents from the
/// schema. Returns false when the path cannot be built within the schema.
fn set_at(args: &mut Value, schema: &Value, pointer: &str, value: Value) -> bool {
    let Some(tokens) = pointer_tokens(pointer) else {
        return false;
    };
    let Some((last, parents)) = tokens.split_last() else {
        *args = value;
        return true;
    };
    let mut node = args;
    let mut sch = Some(schema);
    for token in parents {
        let is_array = sch.is_some_and(|s| kinds(s).contains("array"));
        let child_schema = sch.and_then(|s| {
            if is_array {
                s.get("items")
            } else {
                s.get("properties").and_then(|p| p.get(token))
            }
        });
        if is_array {
            let Some(items) = node.as_array_mut() else {
                return false;
            };
            if items.is_empty() {
                match child_schema.map(|c| minimal(c, 0)) {
                    Some(Ok(v)) => items.push(v),
                    _ => return false,
                }
            }
            node = &mut items[0];
        } else {
            let Some(map) = node.as_object_mut() else {
                return false;
            };
            if !map.contains_key(token) {
                match child_schema.map(|c| minimal(c, 0)) {
                    Some(Ok(v)) => {
                        map.insert(token.clone(), v);
                    }
                    _ => return false,
                }
            }
            node = map.get_mut(token).expect("inserted");
        }
        sch = child_schema;
    }
    match node {
        Value::Object(map) => {
            map.insert(last.clone(), value);
            true
        }
        Value::Array(items) if !items.is_empty() => {
            items[0] = value;
            true
        }
        _ => false,
    }
}

fn remove_at(args: &mut Value, pointer: &str) -> bool {
    let Some(tokens) = pointer_tokens(pointer) else {
        return false;
    };
    let Some((last, parents)) = tokens.split_last() else {
        return false;
    };
    let mut node = args;
    for token in parents {
        node = match node {
            Value::Object(map) => match map.get_mut(token) {
                Some(n) => n,
                None => return false,
            },
            Value::Array(items) if !items.is_empty() => &mut items[0],
            _ => return false,
        };
    }
    node.as_object_mut()
        .is_some_and(|m| m.remove(last).is_some())
}

fn sized(node: &Value, length: usize) -> Result<Value, &'static str> {
    if length > MAX_STRING_CHARS.max(MAX_ARRAY_ITEMS) {
        return Err("bound edge exceeds example bounds");
    }
    if kinds(node).contains("string") {
        if length > MAX_STRING_CHARS {
            return Err("bound edge exceeds the example string bound");
        }
        return Ok(json!(text(length)));
    }
    if length > MAX_ARRAY_ITEMS {
        return Err("bound edge exceeds the example array bound");
    }
    let item = minimal(node.get("items").ok_or("array without items")?, 1)?;
    Ok(Value::Array(vec![item; length]))
}

struct Pack {
    records: Vec<Value>,
    omitted: usize,
}

/// Per-finding generation context; all borrows end with the finding.
struct Cx<'a> {
    pack: &'a mut Pack,
    finding: &'a Finding,
    validator: Option<&'a InputSchema>,
    selectors: Vec<String>,
    per_finding: usize,
    ids: Vec<String>,
}

const LIMITATIONS: [&str; 4] = [
    "Proposal for human review only: not a gold label, training data, approval, permission or \
evidence of observed runtime enforcement.",
    "String values derived from 'sw-review-placeholder' are schema-shaped placeholders without \
meaning; numbers default to 0 and booleans to false.",
    "schema_valid/schema_invalid is the observed result of the selected-profile runtime validator \
on the after schema; it says nothing about server behavior or policy outcome.",
    "Semantic review must use the actual upstream implementation and the operator's declarations.",
];

impl Cx<'_> {
    fn admit(&mut self) -> bool {
        if self.pack.records.len() >= MAX_RECORDS || self.per_finding >= MAX_RECORDS_PER_FINDING {
            self.pack.omitted += 1;
            return false;
        }
        self.per_finding += 1;
        true
    }

    fn base(&self, finding: &Finding, record_type: &str, category: &str) -> Value {
        json!({
            "record_type": record_type,
            "tool": finding.tool,
            "finding_ids": [finding.id],
            "finding_kind": finding.kind,
            "finding_pointer": finding.pointer,
            "argument_pointer": finding.argument_pointer,
            "check_category": category,
            "source_rule": format!("sw-mcp/schema-upgrade-rule/1#{}/{}", finding.kind, category),
            "declaration_refs": finding.declaration_refs,
            "status": "proposal_for_human_review",
        })
    }

    fn finish(&mut self, mut record: Value) {
        let key = format!(
            "{}\0{}\0{}\0{}",
            record["tool"],
            record["finding_ids"],
            record["check_category"],
            canonical_json(&record["arguments"])
        );
        let id = format!("E-{}", &sha_hex(key.as_bytes())[..16]);
        record["id"] = json!(id);
        self.ids.push(id);
        self.pack.records.push(record);
    }

    fn note(&mut self, record_type: &str, category: &str, rationale: &str) {
        let finding = self.finding;
        if !self.admit() {
            return;
        }
        let mut record = self.base(finding, record_type, category);
        record["arguments"] = Value::Null;
        record["schema_validity"] = json!("not_applicable");
        record["semantic_expectation"] = json!(match record_type {
            "unsupported_case" | "unconstructible" => "unknown",
            _ => "not_applicable",
        });
        record["semantic_basis"] = basis(finding, false);
        separated(&mut record);
        record["rationale"] = json!(rationale);
        record["limitations"] = json!(LIMITATIONS[..1]);
        self.finish(record);
    }

    fn invocation(&mut self, args: Value, expect: Expect, category: &str, rationale: &str) {
        let finding = self.finding;
        let Some(validator) = self.validator else {
            return self.note(
                "unsupported_case",
                category,
                "After input schema is outside the supported subset; no example validity can be \
established.",
            );
        };
        let valid = validator.validate(&args).is_ok();
        let mismatch = match expect {
            Expect::Valid => !valid,
            Expect::Invalid => valid,
            Expect::Observe => false,
        };
        if mismatch {
            return self.note(
                "unconstructible",
                category,
                "A bounded example with the intended schema validity could not be constructed; \
manual review required.",
            );
        }
        if canonical_json(&args).len() > MAX_EXAMPLE_BYTES {
            return self.note(
                "unconstructible",
                category,
                "Example would exceed the per-example byte bound.",
            );
        }
        if !self.admit() {
            return;
        }
        let mut record = self.base(finding, "invocation_example", category);
        record["arguments"] = args;
        record["schema_validity"] = json!(if valid {
            "schema_valid"
        } else {
            "schema_invalid"
        });
        // Schema validity is observed; the semantic expectation is a proposal
        // taken from the category table. A declaration reference only marks
        // relevance; adversity under a declaration needs a named contradiction.
        let (expectation, contradiction) = if valid {
            match intent(category) {
                Intent::Exercise => ("exercise_only", None),
                Intent::Unknown => ("unknown_requires_manual_review", None),
                Intent::Drift => ("behavior_change_vs_before_schema", None),
                Intent::Contradiction => match contradiction(finding, category) {
                    Some(text) => ("adverse_under_current_declaration", Some(text)),
                    None => ("unknown_requires_manual_review", None),
                },
            }
        } else {
            ("rejected_by_schema", None)
        };
        record["semantic_expectation"] = json!(expectation);
        record["contradiction"] = json!(contradiction);
        record["semantic_basis"] = basis(finding, contradiction.is_some());
        separated(&mut record);
        record["rationale"] = json!(rationale);
        record["value_notes"] = json!(self
            .selectors
            .iter()
            .map(|p| json!({"argument_pointer": p,
                "note": "declared selector: operator must substitute an in-scope value; the analyzer knows no valid resource or destination"}))
            .collect::<Vec<_>>());
        record["limitations"] = json!(LIMITATIONS);
        self.finish(record);
    }
}

#[derive(Clone, Copy)]
enum Intent {
    /// Exercises behavior the operator already accepted (e.g. pinning a previous default).
    Exercise,
    /// Meaning cannot be established from explicit declarations; manual review.
    Unknown,
    /// A concrete schema-level change relative to the before schema.
    Drift,
    /// A concrete contradiction with a cited declaration (see `contradiction`).
    Contradiction,
}

/// The single source of truth for semantic intent per review category.
fn intent(category: &str) -> Intent {
    match category {
        "explicit_previous_default" => Intent::Exercise,
        "undeclared_tool_exercise"
        | "new_field_exercise"
        | "field_outside_declared_selectors"
        | "declared_selector_shape_change" => Intent::Unknown,
        "multiple_values_through_declared_selector" | "declared_selector_omitted" => {
            Intent::Contradiction
        }
        _ => Intent::Drift,
    }
}

/// The identified contradiction with the cited declaration, or `None` when
/// none can be stated from the finding's own declared facts.
fn contradiction(finding: &Finding, category: &str) -> Option<String> {
    let reference = finding.declaration_refs.first()?;
    let pointer = finding.argument_pointer.as_deref()?;
    match category {
        "multiple_values_through_declared_selector" if finding.detail["became_array"] == true => {
            Some(format!(
                "{reference} declares the {} selector {pointer} against a single value in the \
before schema; the after schema admits several values through that one selector",
                finding.detail["role"].as_str().unwrap_or("declared")
            ))
        }
        "declared_selector_omitted" if finding.detail["declared_optional"] == false => {
            Some(format!(
                "{reference} declares the {} selector {pointer} as non-optional; the after \
schema no longer requires the field",
                finding.detail["role"].as_str().unwrap_or("declared")
            ))
        }
        _ => None,
    }
}

fn basis(finding: &Finding, contradiction: bool) -> Value {
    if finding.declaration_refs.is_empty() {
        json!({"declarations": [], "note": "this finding cites no current declaration"})
    } else if contradiction {
        json!({"declarations": finding.declaration_refs,
               "note": "the stated contradiction is with the cited current declaration, not with names or descriptions"})
    } else {
        json!({"declarations": finding.declaration_refs,
               "note": "declaration cited for relevance and traceability; no contradiction with it was identified"})
    }
}

/// Fixed statements every record carries so validity is never read as safety.
fn separated(record: &mut Value) {
    record["runtime_enforcement"] = json!("not_observed");
    record["semantic_safety"] = json!("not_established");
    record["human_approval"] = json!("none");
}

pub(super) fn generate(analysis: &mut Analysis<'_>) -> Generation {
    let mut pack = Pack {
        records: vec![],
        omitted: 0,
    };
    let mut findings = std::mem::take(&mut analysis.findings);
    for finding in &mut findings {
        let after_schema = analysis
            .after
            .tools
            .get(&finding.tool)
            .map(|t| &t["inputSchema"]);
        let before_schema = analysis
            .before
            .tools
            .get(&finding.tool)
            .map(|t| &t["inputSchema"]);
        let validator = after_schema.and_then(|s| InputSchema::read_selected(s).ok());
        let selectors = analysis
            .current
            .and_then(|d| d.tools.get(&finding.tool))
            .map(|s| {
                s.resources
                    .iter()
                    .chain(&s.destinations)
                    .map(|s| s.pointer.clone())
                    .collect()
            })
            .unwrap_or_default();
        let mut cx = Cx {
            pack: &mut pack,
            finding,
            validator: validator.as_ref(),
            selectors,
            per_finding: 0,
            ids: vec![],
        };
        one(&mut cx, before_schema, after_schema);
        let ids = cx.ids;
        finding.example_ids = ids;
    }
    analysis.findings = findings;
    let mut gaps = vec![];
    if pack.omitted > 0 {
        gaps.push(json!({"gap": "review_pack_truncated", "omitted_records": pack.omitted}));
    }
    let not_constructed = pack
        .records
        .iter()
        .filter(|r| r["record_type"] == "unconstructible" || r["record_type"] == "unsupported_case")
        .count();
    if not_constructed > 0 {
        gaps.push(json!({"gap": "examples_not_constructed", "records": not_constructed}));
    }
    pack.records.sort_by(|a, b| {
        let key = |r: &Value| {
            (
                r["tool"].as_str().unwrap_or("").to_owned(),
                r["finding_pointer"].as_str().unwrap_or("").to_owned(),
                r["check_category"].as_str().unwrap_or("").to_owned(),
                r["id"].as_str().unwrap_or("").to_owned(),
            )
        };
        key(a).cmp(&key(b))
    });
    Generation {
        complete: pack.omitted == 0,
        omitted: pack.omitted,
        records: pack.records,
        gaps,
    }
}

fn one(out: &mut Cx<'_>, before: Option<&Value>, after: Option<&Value>) {
    let f = out.finding;
    if f.nature == Nature::InertMetadata {
        return;
    }
    if f.nature == Nature::Unsupported {
        return out.note(
            "unsupported_case",
            "manual_semantic_review",
            "Construct outside the supported analysis subset; the analyzer neither interprets nor \
exercises it.",
        );
    }
    if f.area == "result" || f.kind.starts_with("result_shape") {
        return out.note(
            "review_item",
            "result_shape_requalification",
            "Results are produced by the server; an output-schema change cannot be exercised by \
one invocation. Re-qualify result inspection with the actual server.",
        );
    }
    match f.kind {
        "behavior_hint_changed" | "capability_changed" => {
            return out.note(
                "review_item",
                "verify_behavior_not_hint",
                "Hints and capability metadata are untrusted; verify behavior in the implementation.",
            )
        }
        "tool_removed" | "declared_tool_removed" => {
            return out.note(
                "review_item",
                "withdraw_declarations",
                "Withdraw declarations, policies and qualifications that reference the removed tool.",
            )
        }
        "declaration_binding_stale" => {
            return out.note(
                "review_item",
                "re_review_declaration",
                "A new declaration must be reviewed for the new exact identity before any admission.",
            )
        }
        "undeclared_tool_added" | "tool_order_changed" | "dialect_changed" | "items_changed" => {
            return out.note(
                "review_item",
                "manual_semantic_review",
                "No bounded invocation exercises this change in isolation.",
            )
        }
        k if k.starts_with("declared_") && k.ends_with("_changed") && k != "declared_selector_target_changed" => {
            return out.note(
                "review_item",
                "proposed_declaration_review",
                "Proposed declaration differs from the current one; it is a draft and grants nothing.",
            )
        }
        "declared_selector_unbound" => {
            return out.note(
                "unconstructible",
                "declared_selector_unbound",
                "The declared selector no longer addresses a schema field; no example can exercise it.",
            )
        }
        _ => {}
    }
    let Some(after) = after else { return };
    let base = match minimal(after, 0) {
        Ok(base) => base,
        Err(reason) => {
            return out.note(
                "unconstructible",
                "base_invocation",
                &format!("No minimal valid invocation within bounds: {reason}."),
            )
        }
    };
    if f.kind == "tool_added" {
        return out.invocation(
            base,
            Expect::Valid,
            "undeclared_tool_exercise",
            "Minimal schema-valid invocation of a new tool. The tool has no declaration and no \
permission; this only supports qualification planning.",
        );
    }
    let Some(pointer) = f.argument_pointer.clone() else {
        return out.note(
            "review_item",
            "manual_semantic_review",
            "Finding has no argument location.",
        );
    };
    let node_after = schema_at(after, &pointer);
    let node_before = before.and_then(|b| schema_at(b, &pointer));
    let with = |value: Value| {
        let mut args = base.clone();
        set_at(&mut args, after, &pointer, value).then_some(args)
    };
    match f.kind {
        "field_added" => {
            let Some(node) = node_after else { return };
            // Relevance only: the category records that selectors exist.
            let declared = !out.selectors.is_empty();
            if let Some(args) = full(node, 1).ok().and_then(with) {
                out.invocation(
                    args,
                    Expect::Valid,
                    if declared {
                        "field_outside_declared_selectors"
                    } else {
                        "new_field_exercise"
                    },
                    "Populates the new field with a schema-shaped value. Its meaning is unknown to the \
analyzer and must be reviewed against the implementation.",
                );
            }
            if let Some(args) = with(wrong_type(node)) {
                out.invocation(
                    args,
                    Expect::Invalid,
                    "new_field_type_rejection",
                    "Supplies a value of the wrong JSON type for the new field.",
                );
            }
        }
        "field_removed" | "required_field_removed" => {
            let value = node_before
                .and_then(|n| minimal(n, 1).ok())
                .unwrap_or_else(|| json!(PLACEHOLDER));
            let mut args = base.clone();
            if insert_raw(&mut args, &pointer, value) {
                out.invocation(
                    args,
                    Expect::Invalid,
                    "removed_field_rejection",
                    "Supplies the removed field; the selected-profile validator refuses unknown \
arguments.",
                );
            }
            if f.kind == "required_field_removed" {
                out.invocation(
                    base.clone(),
                    Expect::Valid,
                    "relaxed_requirement",
                    "An invocation without the formerly required argument is now schema-valid; the \
server may apply implicit behavior.",
                );
            }
        }
        "required_added" => {
            let mut args = base.clone();
            if remove_at(&mut args, &pointer) {
                out.invocation(
                    args,
                    Expect::Invalid,
                    "missing_new_required",
                    "Omits the newly required argument; previously valid calls are now refused.",
                );
            }
        }
        "required_removed" => {
            let mut args = base.clone();
            remove_at(&mut args, &pointer);
            out.invocation(
                args,
                Expect::Valid,
                "relaxed_requirement",
                "Omits the argument that is no longer required; the server may apply an implicit \
value.",
            );
        }
        "enum_values_added" | "enum_values_removed" => {
            let added = f.kind == "enum_values_added";
            for value in f.detail["values"].as_array().cloned().unwrap_or_default() {
                if let Some(args) = with(value) {
                    out.invocation(
                        args,
                        if added {
                            Expect::Valid
                        } else {
                            Expect::Invalid
                        },
                        if added {
                            "newly_admitted_value"
                        } else {
                            "withdrawn_value_rejection"
                        },
                        if added {
                            "Uses a literal value admitted only by the after schema."
                        } else {
                            "Uses a literal value withdrawn by the after schema."
                        },
                    );
                }
            }
        }
        "enum_added" | "enum_removed" | "const_changed" | "type_changed" | "nullable_added"
        | "nullable_removed" => {
            if let Some(args) = node_after.and_then(|n| minimal(n, 1).ok()).and_then(with) {
                out.invocation(
                    args,
                    Expect::Valid,
                    "changed_value_domain",
                    "Uses a value admitted by the changed after schema.",
                );
            }
            let old = match f.kind {
                "enum_added" => node_after.map(|n| {
                    if kinds(n).contains("string") {
                        json!("sw-review-outside-enum")
                    } else {
                        json!(-1)
                    }
                }),
                _ => node_before.and_then(|n| minimal(n, 1).ok()),
            };
            if let Some(args) = old.and_then(with) {
                out.invocation(
                    args,
                    Expect::Observe,
                    "previous_value_domain",
                    "Uses a value shaped by the before schema; the observed validity shows whether \
it is still admitted.",
                );
            }
        }
        "default_changed" => {
            let required = super::required_at(after, &pointer);
            if required {
                out.note(
                    "review_item",
                    "default_on_required_field",
                    "The field is required in the after schema; the changed default affects no \
omitted call but may change documentation or server behavior.",
                );
            } else {
                let mut args = base.clone();
                remove_at(&mut args, &pointer);
                out.invocation(
                    args,
                    Expect::Valid,
                    "implicit_default_changed",
                    "Omits the argument; the upstream server now applies a different default that \
runtime validation never sees.",
                );
                let previous = f
                    .before
                    .clone()
                    .filter(|v| v.get("omitted_bytes").is_none());
                if let Some(args) = previous.and_then(with) {
                    out.invocation(
                        args,
                        Expect::Observe,
                        "explicit_previous_default",
                        "Pins the previous default explicitly to preserve prior behavior.",
                    );
                }
            }
        }
        "constraint_changed" => {
            let Some(node) = node_after else { return };
            let keyword = f.detail["keyword"].as_str().unwrap_or("");
            let loosened = f.detail["direction"] == "loosened";
            // Bounds are untrusted u64 values (the before schema is never
            // runtime-validated): checked arithmetic, lazy fallback, checked
            // conversion. An unrepresentable edge becomes an explicit record.
            let (b, a) = (
                f.before.as_ref().and_then(Value::as_u64),
                f.after.as_ref().and_then(Value::as_u64),
            );
            let is_max = keyword.starts_with("max");
            let target: Option<u64> = match (is_max, loosened) {
                (true, true) => a.or_else(|| b.and_then(|b| b.checked_add(1))),
                (true, false) => a.and_then(|a| a.checked_add(1)),
                (false, true) => Some(a.unwrap_or(0)),
                (false, false) => a.and_then(|a| a.checked_sub(1)),
            };
            let target = match target.map(usize::try_from) {
                Some(Ok(n)) => Some(n),
                Some(Err(_)) => {
                    return out.note(
                        "unconstructible",
                        "bound_edge",
                        "bound edge is not representable on this platform",
                    )
                }
                None => None,
            };
            match target.map(|n| sized(node, n)) {
                Some(Ok(value)) => {
                    if let Some(args) = with(value) {
                        out.invocation(
                            args,
                            if loosened {
                                Expect::Valid
                            } else {
                                Expect::Invalid
                            },
                            if loosened {
                                "loosened_bound_edge"
                            } else {
                                "tightened_bound_edge"
                            },
                            "Value at the changed bound edge.",
                        );
                    }
                }
                Some(Err(reason)) => out.note("unconstructible", "bound_edge", reason),
                None => out.note(
                    "unconstructible",
                    "bound_edge",
                    "No finite bound edge exists for this change.",
                ),
            }
        }
        "additional_properties_changed" => {
            let mut args = base.clone();
            let extra = if pointer.is_empty() {
                "/sw_review_extra".to_owned()
            } else {
                format!("{pointer}/sw_review_extra")
            };
            if insert_raw(&mut args, &extra, json!(PLACEHOLDER)) {
                out.invocation(
                    args,
                    Expect::Observe,
                    "undeclared_argument",
                    "Supplies an argument the schema does not declare.",
                );
            }
        }
        "declared_selector_target_changed" => {
            let Some(node) = node_after else { return };
            if f.detail["became_array"] == true {
                let max = node["maxItems"].as_u64().unwrap_or(2).min(2) as usize;
                let item = node.get("items").cloned().unwrap_or(Value::Null);
                let values: Vec<Value> = (1..=max.max(1))
                    .map(|i| {
                        if kinds(&item).contains("string") {
                            json!(format!("sw-review-destination-{i}"))
                        } else {
                            minimal(&item, 1).unwrap_or(Value::Null)
                        }
                    })
                    .collect();
                if let Some(args) = with(Value::Array(values)) {
                    out.invocation(
                        args,
                        Expect::Observe,
                        "multiple_values_through_declared_selector",
                        "The declared selector now addresses an array; several distinct values can \
travel through one declared resource/destination.",
                    );
                }
            } else if let Some(args) = minimal(node, 1).ok().and_then(with) {
                out.invocation(
                    args,
                    Expect::Observe,
                    "declared_selector_shape_change",
                    "Exercises the changed schema at a declared selector.",
                );
            }
            if let Some(args) = node_before.and_then(|n| minimal(n, 1).ok()).and_then(with) {
                out.invocation(
                    args,
                    Expect::Observe,
                    "previous_shape_at_declared_selector",
                    "Supplies the declared selector in its before-schema shape; the observed validity shows whether the declared form is still admitted.",
                );
            }
        }
        "declared_selector_requirement_relaxed" => {
            let mut args = base.clone();
            remove_at(&mut args, &pointer);
            out.invocation(
                args,
                Expect::Valid,
                "declared_selector_omitted",
                "Omits the field a non-optional declared selector expects; the declaration assumes the resource/destination is always present.",
            );
        }
        _ => out.note(
            "review_item",
            "manual_semantic_review",
            "No bounded example rule exists for this finding kind.",
        ),
    }
}

/// Insert a key at a pointer whose parent already exists in `args`.
fn insert_raw(args: &mut Value, pointer: &str, value: Value) -> bool {
    let Some(tokens) = pointer_tokens(pointer) else {
        return false;
    };
    let Some((last, parents)) = tokens.split_last() else {
        return false;
    };
    let mut node = args;
    for token in parents {
        node = match node {
            Value::Object(map) => match map.get_mut(token) {
                Some(n) => n,
                None => return false,
            },
            Value::Array(items) if !items.is_empty() => &mut items[0],
            _ => return false,
        };
    }
    match node.as_object_mut() {
        Some(map) => {
            map.insert(last.clone(), value);
            true
        }
        None => false,
    }
}
