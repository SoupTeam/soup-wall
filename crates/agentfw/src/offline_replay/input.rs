// SPDX-License-Identifier: Apache-2.0
//! Raw, strict, bounded validation precedes AgentEvent's permissive decoder.

use super::{Failure, Result};
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use soup_wall_agent::AgentEvent;
use std::collections::BTreeSet;
use std::fmt;

pub(super) const TOOLS: &[&str] = &[
    "Read",
    "Grep",
    "Glob",
    "NotebookRead",
    "TodoRead",
    "WebFetch",
    "WebSearch",
    "Bash",
    "Write",
    "Edit",
    "MultiEdit",
];

pub(super) struct Prepared {
    pub seq: Option<u64>,
    pub kind: Option<&'static str>,
    pub event: Option<AgentEvent>,
    pub status: Option<&'static str>,
    pub reasons: Vec<&'static str>,
}

pub(super) struct Input {
    pub events: Vec<Prepared>,
    pub incomplete: bool,
}

struct Seed<'a> {
    remaining: &'a mut usize,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Value, D::Error> {
        if self.depth > 32 || *self.remaining == 0 {
            return Err(D::Error::custom("offline_json_bounds"));
        }
        *self.remaining -= 1;
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_i64<E: Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: Error>(self, v: f64) -> std::result::Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("offline_invalid_number"))
    }
    fn visit_str<E: Error>(self, v: &str) -> std::result::Result<Value, E> {
        if v.len() > 32768 {
            return Err(E::custom("offline_string_bounds"));
        }
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: Error>(self, v: String) -> std::result::Result<Value, E> {
        if v.len() > 32768 {
            return Err(E::custom("offline_string_bounds"));
        }
        Ok(Value::String(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            remaining: self.remaining,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 128 || values.contains_key(&key) {
                return Err(A::Error::custom("offline_duplicate_or_oversized_key"));
            }
            let value = map.next_value_seed(Seed {
                remaining: self.remaining,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn keys(value: &Value, allowed: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.keys().all(|key| allowed.contains(&key.as_str())))
}
fn identifier(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
}
fn measure(value: &Value, nodes: &mut usize, content: &mut usize) {
    *nodes += 1;
    match value {
        Value::String(s) => *content += s.len(),
        Value::Array(values) => values.iter().for_each(|v| measure(v, nodes, content)),
        Value::Object(values) => values.values().for_each(|v| measure(v, nodes, content)),
        _ => {}
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Input> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Seed {
        remaining: &mut 65536,
        depth: 0,
    }
    .deserialize(&mut decoder)
    .map_err(|_| Failure("offline_input_json_or_bounds"))?;
    decoder
        .end()
        .map_err(|_| Failure("offline_input_partial_or_trailing"))?;
    if !keys(&value, &["format", "context", "events"])
        || value["format"] != "sw-policy-offline-input/1"
    {
        return Err(Failure("offline_input_format_or_fields"));
    }
    let rows = value["events"]
        .as_array()
        .ok_or(Failure("offline_events_missing"))?;
    if rows.is_empty() || rows.len() > 64 {
        return Err(Failure("offline_event_count"));
    }
    // Validate every event's budget before evaluating any event, including ones
    // that will be classified unsupported. Identity still hashes original bytes.
    let mut total = 0;
    for row in rows {
        let mut nodes = 0;
        measure(row, &mut nodes, &mut total);
        if nodes > 8192 || total > 512 * 1024 || super::encoded_len(row, 32768).is_err() {
            return Err(Failure("offline_event_bounds"));
        }
    }
    let context = &value["context"];
    let mut common = Vec::new();
    let mut common_status = "insufficient_context";
    if !context.is_object() {
        common.push("missing_context");
    } else if !keys(context, &["history", "judge"]) {
        common.push("unsupported_context_fields");
        common_status = "unsupported";
    } else {
        match context["history"].as_str() {
            Some("complete_from_start" | "incomplete") => {}
            None if context.get("history").is_none() => common.push("missing_history_context"),
            _ => {
                common.push("unsupported_history_context");
                common_status = "unsupported";
            }
        }
        match context["judge"].as_str() {
            Some("disabled") => {}
            None if context.get("judge").is_none() => common.push("missing_judge_context"),
            _ => {
                common.push("unsupported_judge_context");
                common_status = "unsupported";
            }
        }
    }
    let mut session = None;
    let mut agent = None;
    let mut last_seq = None;
    let mut events = Vec::new();
    for row in rows {
        let raw = &row["event"];
        let kind = match raw["kind"].as_str() {
            Some("tool_call") => Some("tool_call"),
            Some("tool_result") => Some("tool_result"),
            _ => None,
        };
        let mut out = Prepared {
            seq: raw["seq"].as_u64(),
            kind,
            event: None,
            status: None,
            reasons: common.clone(),
        };
        if !common.is_empty() {
            out.status = Some(common_status);
        }
        let mut reject = |status, reason| {
            out.status = Some(status);
            out.reasons.push(reason);
        };
        if !keys(row, &["complete", "event"]) {
            reject("unsupported", "unsupported_record_fields");
        }
        if row["complete"] != true {
            reject("insufficient_context", "event_not_declared_complete");
        }
        if kind.is_none() {
            if raw["kind"].is_string() {
                reject("unsupported", "unsupported_event_kind");
            } else {
                reject("insufficient_context", "missing_event_kind");
            }
        }
        let allowed = if kind == Some("tool_call") {
            &[
                "session", "agent", "parent", "seq", "at_ms", "kind", "tool", "args",
            ][..]
        } else {
            &[
                "session", "agent", "parent", "seq", "at_ms", "kind", "tool", "content", "source",
            ][..]
        };
        if raw.is_object() && !keys(raw, allowed) {
            reject("unsupported", "unsupported_event_fields");
        }
        if !raw.is_object()
            || !identifier(&raw["session"])
            || !identifier(&raw["agent"])
            || out.seq.is_none()
            || raw["at_ms"].as_u64().is_none()
        {
            reject("insufficient_context", "missing_or_invalid_event_identity");
        }
        if !raw["parent"].is_null() {
            reject("unsupported", "unsupported_parent_context");
        }
        match raw["tool"].as_str() {
            Some(tool) if TOOLS.contains(&tool) => {}
            None => reject("insufficient_context", "missing_tool"),
            _ => reject("unsupported", "unsupported_tool"),
        }
        if kind == Some("tool_call") && !raw["args"].is_object() {
            reject("insufficient_context", "missing_or_invalid_arguments");
        }
        if kind == Some("tool_result") {
            if !raw["content"].is_string() {
                reject("insufficient_context", "missing_result_content");
            }
            let source = &raw["source"];
            match source["origin"].as_str() {
                Some("user_prompt" | "local_project" | "local_system")
                    if keys(source, &["origin"]) => {}
                Some("network")
                    if keys(source, &["origin", "host"]) && identifier(&source["host"]) => {}
                None => reject("insufficient_context", "missing_result_source"),
                _ => reject("unsupported", "unsupported_result_source"),
            }
        }
        // Keep array order and reject changing identities or replayed sequence
        // numbers before AgentEvent defaults/unknown-kind handling can run.
        if let Some(seq) = out.seq {
            if last_seq.is_some_and(|previous| seq <= previous) {
                reject("unsupported", "event_order_invalid");
            }
            last_seq = Some(last_seq.map_or(seq, |previous: u64| previous.max(seq)));
        }
        for (current, selected) in [(&raw["session"], &mut session), (&raw["agent"], &mut agent)] {
            if identifier(current) {
                if selected
                    .as_ref()
                    .is_some_and(|old| old != current.as_str().unwrap())
                {
                    reject("unsupported", "event_context_identity_changed");
                } else if selected.is_none() {
                    *selected = current.as_str().map(String::from);
                }
            }
        }
        if out.status.is_none() {
            match serde_json::from_value::<AgentEvent>(raw.clone()) {
                Ok(event) => out.event = Some(event),
                Err(_) => {
                    out.status = Some("insufficient_context");
                    out.reasons.push("event_fields_invalid");
                }
            }
        }
        out.reasons = out
            .reasons
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        events.push(out);
    }
    Ok(Input {
        events,
        incomplete: context["history"] == "incomplete",
    })
}
