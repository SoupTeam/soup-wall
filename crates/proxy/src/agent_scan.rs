// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Agent-layer inspection of the tool blocks in proxied API traffic. Stateless per
//! request/response cycle: request `tool_result`s build taint; the response's
//! `tool_use`s are the actions checked against it.

use soup_wall_adapter::{DecisionResponse, Verdict as AdapterVerdict, CONTRACT_VERSION};
use soup_wall_agent::{AgentEvent, AgentFirewall, EventKind, Provenance, Verdict};

use crate::events::{EventDirection, EventKind as SecurityEventKind, SecurityEvent};

/// A tool the model wants to run, with its arguments as JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub id: Option<String>,
    pub name: String,
    pub args: serde_json::Value,
}

/// The worst verdict over a response's tool calls, plus a human reason.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanVerdict {
    pub verdict: Verdict,
    pub fallback: Option<Verdict>,
    pub reason: Option<String>,
}

impl ScanVerdict {
    /// Return the resolved authoritative verdict under local proxy rules.
    pub fn resolved_verdict(&self) -> Verdict {
        soup_wall_agent::resolution::resolve(self.verdict, self.fallback, false)
    }

    /// Project a provider-cycle result onto the shared adapter contract.
    ///
    /// The proxy currently has no remote adapter configured, so this is a local
    /// response with no expiry/signature. An unexpected `Escalate` is tightened to
    /// its declared fallback, or to `Ask` when no fallback exists.
    pub fn adapter_response(&self, policy_version: impl Into<String>) -> DecisionResponse {
        let verdict = match self.resolved_verdict() {
            Verdict::Allow => AdapterVerdict::Allow,
            Verdict::Ask => AdapterVerdict::Ask,
            Verdict::Deny => AdapterVerdict::Deny,
            Verdict::Escalate => unreachable!("resolution always returns a concrete verdict"),
        };
        DecisionResponse {
            contract_version: CONTRACT_VERSION.into(),
            verdict,
            policy_version: policy_version.into(),
            policy_bundle_id: None,
            // `reason` is human-readable and may contain operator policy text;
            // keep it out of the machine contract until a stable reason-code field
            // is carried separately.
            reason_codes: Vec::new(),
            remediation_hint: None,
            expires_at: None,
            signature: None,
            replay: None,
        }
    }
}

/// Strict inspection boundary for tool content.
#[derive(Debug, Clone, PartialEq)]
pub enum ContentStatus<T> {
    /// Completely inspected and supported text/JSON parts.
    Supported(T),
    /// Explicit refusal for unknown, image, document, or audio payloads.
    Unsupported(&'static str),
    /// Explicit refusal for broken JSON, empty arrays, or violated type boundaries.
    Malformed(&'static str),
}

impl<T> ContentStatus<T> {
    pub fn into_result(self) -> Result<T, &'static str> {
        match self {
            ContentStatus::Supported(data) => Ok(data),
            ContentStatus::Unsupported(err) => Err(err),
            ContentStatus::Malformed(err) => Err(err),
        }
    }
}

/// Tool outputs in an OpenAI request: `role:"tool"` messages' string content.
pub fn openai_tool_results_strict(
    request: &crate::openai::ChatRequest,
) -> ContentStatus<Vec<String>> {
    let mut results = Vec::new();
    for msg in &request.messages {
        if msg.role == "tool" {
            if let Some(text) = &msg.content {
                results.push(text.clone());
            } else {
                return ContentStatus::Malformed("tool message missing content string");
            }
        }
    }
    ContentStatus::Supported(results)
}

pub fn openai_tool_results(request: &crate::openai::ChatRequest) -> Vec<String> {
    openai_tool_results_strict(request)
        .into_result()
        .unwrap_or_default()
}

pub fn openai_tool_calls_strict(response: &serde_json::Value) -> ContentStatus<Vec<ToolCall>> {
    let mut calls = Vec::new();
    let choices = match response.get("choices").and_then(|v| v.as_array()) {
        Some(c) => c,
        None => return ContentStatus::Supported(calls),
    };

    for choice in choices {
        let msg = match choice.get("message") {
            Some(m) => m,
            None => continue,
        };

        if msg.get("function_call").is_some() {
            return ContentStatus::Unsupported(
                "legacy function_call is not supported; use tool_calls",
            );
        }

        if let Some(tool_calls) = msg.get("tool_calls").and_then(|v| v.as_array()) {
            for tc in tool_calls {
                let tool_type = tc
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("function");
                if tool_type != "function" {
                    return ContentStatus::Unsupported(
                        "unsupported tool type in OpenAI response (only 'function' allowed)",
                    );
                }

                if let Some(func) = tc.get("function") {
                    let id = tc.get("id").and_then(|v| v.as_str()).map(String::from);
                    let name = func
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let args_str = func
                        .get("arguments")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();

                    if name.is_empty() {
                        return ContentStatus::Malformed("tool_call missing name");
                    }
                    let args = serde_json::from_str(&args_str)
                        .unwrap_or(serde_json::Value::String(args_str));
                    calls.push(ToolCall { id, name, args });
                } else {
                    return ContentStatus::Malformed("tool_call missing function block");
                }
            }
        }
    }
    ContentStatus::Supported(calls)
}

pub fn openai_tool_calls(response: &serde_json::Value) -> Vec<ToolCall> {
    openai_tool_calls_strict(response)
        .into_result()
        .unwrap_or_default()
}

pub fn responses_tool_results_strict(
    request: &crate::responses::ResponsesRequest,
) -> ContentStatus<Vec<String>> {
    let mut results = Vec::new();
    let items = match request.input.as_ref().and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return ContentStatus::Supported(results),
    };

    for item in items {
        let t = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if t == "function_call_output" {
            match item.get("output") {
                Some(serde_json::Value::String(text)) => results.push(text.clone()),
                Some(serde_json::Value::Array(arr)) => {
                    for block in arr {
                        if block.get("type").and_then(|v| v.as_str()) == Some("input_text") {
                            if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                                results.push(text.to_string());
                            } else {
                                return ContentStatus::Malformed(
                                    "input_text block missing text field",
                                );
                            }
                        } else {
                            return ContentStatus::Unsupported("multimedia or non-string tool results are not supported in Responses");
                        }
                    }
                }
                Some(_) => {
                    return ContentStatus::Unsupported(
                        "multimedia or non-string tool results are not supported in Responses",
                    )
                }
                None => {
                    return ContentStatus::Malformed("function_call_output missing output field")
                }
            }
        } else if matches!(
            t,
            "custom_tool_call_output"
                | "local_shell_call_output"
                | "computer_call_output"
                | "mcp_call_output"
        ) || t.contains("tool")
        {
            return ContentStatus::Unsupported("unsupported tool-result type in Responses");
        }
    }
    ContentStatus::Supported(results)
}

pub fn responses_tool_results(request: &crate::responses::ResponsesRequest) -> Vec<String> {
    responses_tool_results_strict(request)
        .into_result()
        .unwrap_or_default()
}

pub fn responses_tool_calls_strict(response: &serde_json::Value) -> ContentStatus<Vec<ToolCall>> {
    let mut calls = Vec::new();
    let outputs = match response.get("output").and_then(|v| v.as_array()) {
        Some(out) => out,
        None => return ContentStatus::Supported(calls),
    };

    for item in outputs {
        let t = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if t == "function_call" {
            let id = item
                .get("call_id")
                .and_then(|v| v.as_str())
                .map(String::from);
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let args_str = item
                .get("arguments")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if name.is_empty() {
                return ContentStatus::Malformed("Responses function_call missing name");
            }

            let args =
                serde_json::from_str(&args_str).unwrap_or(serde_json::Value::String(args_str));
            calls.push(ToolCall { id, name, args });
        } else if matches!(
            t,
            "custom_tool_call" | "local_shell_call" | "computer_call" | "mcp_call"
        ) || t.ends_with("_call")
        {
            return ContentStatus::Unsupported("unsupported tool-bearing type in Responses");
        }
    }
    ContentStatus::Supported(calls)
}

pub fn responses_tool_calls(response: &serde_json::Value) -> Vec<ToolCall> {
    responses_tool_calls_strict(response)
        .into_result()
        .unwrap_or_default()
}

/// Convert a single Responses output item into a ToolCall if it is a function_call.
/// Used by the SSE stream frame parser in handlers.rs.
pub fn responses_tool_call(item: &serde_json::Value) -> Option<ToolCall> {
    if item.get("type").and_then(|v| v.as_str()) == Some("function_call") {
        let id = item
            .get("call_id")
            .and_then(|v| v.as_str())
            .map(String::from);
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let args_str = item
            .get("arguments")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        if name.is_empty() {
            return None;
        }

        let args = serde_json::from_str(&args_str).unwrap_or(serde_json::Value::String(args_str));
        Some(ToolCall { id, name, args })
    } else {
        None
    }
}

pub fn responses_stream_tool_call_strict(
    item: &serde_json::Value,
) -> Result<Option<ToolCall>, &'static str> {
    let t = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if t == "function_call" {
        let id = item
            .get("call_id")
            .and_then(|v| v.as_str())
            .map(String::from);
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let args_str = item
            .get("arguments")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        if name.is_empty() {
            return Ok(None);
        }

        let args = serde_json::from_str(&args_str).unwrap_or(serde_json::Value::String(args_str));
        Ok(Some(ToolCall { id, name, args }))
    } else if matches!(
        t,
        "custom_tool_call" | "local_shell_call" | "computer_call" | "mcp_call"
    ) || t.ends_with("_call")
    {
        Err("unsupported tool-bearing type in Responses streaming")
    } else {
        Ok(None)
    }
}

/// Feed the tool results as taint, then each tool call as an action; return the worst
/// verdict. A fresh `session` per cycle means no cross-request state.
pub fn inspect_cycle(
    fw: &mut AgentFirewall,
    session: &str,
    tool_results: &[String],
    tool_calls: &[ToolCall],
) -> ScanVerdict {
    let mut seq = 0u64;
    for content in tool_results {
        seq += 1;
        fw.inspect(&AgentEvent {
            session: session.to_string(),
            agent: "api".into(),
            parent: None,
            seq,
            at_ms: 0,
            kind: EventKind::ToolResult {
                tool: "tool".into(),
                content: content.clone(),
                source: Provenance::McpServer {
                    name: "api-tool".into(),
                },
            },
        });
    }
    let mut worst = ScanVerdict {
        verdict: Verdict::Allow,
        fallback: None,
        reason: None,
    };
    for call in tool_calls {
        seq += 1;
        let out = fw.inspect(&AgentEvent {
            session: session.to_string(),
            agent: "api".into(),
            parent: None,
            seq,
            at_ms: 0,
            kind: EventKind::ToolCall {
                tool: call.name.clone(),
                args: call.args.clone(),
            },
        });
        let out_resolved = soup_wall_agent::resolution::resolve(out.verdict, out.fallback, false);
        if verdict_rank(out_resolved) > verdict_rank(worst.resolved_verdict()) {
            worst = ScanVerdict {
                verdict: out.verdict,
                fallback: out.fallback,
                reason: out.rule.map(|r| match out.message {
                    Some(m) => format!("[{r}] {m}"),
                    None => format!("[{r}]"),
                }),
            };
        }
    }
    worst
}

/// Run the agent firewall over provider-neutral events. Tool results are always
/// ingested before tool calls, regardless of their wire representation.
pub fn inspect_normalized_cycle(
    fw: &mut AgentFirewall,
    session: &str,
    events: &[SecurityEvent],
) -> ScanVerdict {
    let results = events
        .iter()
        .filter_map(|event| match (&event.direction, &event.kind) {
            (EventDirection::Input, SecurityEventKind::ToolResult { content, .. }) => {
                Some(content.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let calls = events
        .iter()
        .filter_map(|event| match (&event.direction, &event.kind) {
            (
                EventDirection::Output,
                SecurityEventKind::ToolCall {
                    call_id,
                    name,
                    args,
                },
            ) => Some(ToolCall {
                id: call_id.clone(),
                name: name.clone(),
                args: args.clone(),
            }),
            _ => None,
        })
        .collect::<Vec<_>>();
    inspect_cycle(fw, session, &results, &calls)
}

/// Tool outputs in an Anthropic request: `tool_result` content blocks inside user
/// messages. A block's `content` may be a string or an array of text blocks.
/// Strict extraction of Anthropic tool results. Refuses unsupported multimodal blocks.
pub fn anthropic_tool_results_strict(request: &serde_json::Value) -> ContentStatus<Vec<String>> {
    let mut out = Vec::new();
    let Some(msgs) = request.get("messages").and_then(|m| m.as_array()) else {
        return ContentStatus::Supported(out);
    };

    for m in msgs {
        let Some(blocks) = m.get("content").and_then(|c| c.as_array()) else {
            continue;
        };
        for b in blocks {
            let t = b.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if t == "tool_result" {
                // ... (оставь внутреннюю обработку tool_result без изменений, начиная с match b.get("content"))
                match b.get("content") {
                    Some(serde_json::Value::String(s)) => {
                        if !s.is_empty() {
                            out.push(s.clone());
                        }
                    }
                    Some(serde_json::Value::Array(inner)) => {
                        if inner.is_empty() {
                            return ContentStatus::Malformed(
                                "empty array in tool_result is not valid",
                            );
                        }
                        for ib in inner {
                            match ib.get("type").and_then(|t| t.as_str()) {
                                Some("text") => {
                                    if let Some(t) = ib.get("text").and_then(|t| t.as_str()) {
                                        if !t.is_empty() {
                                            out.push(t.to_string());
                                        }
                                    } else {
                                        return ContentStatus::Malformed(
                                            "missing text field in text block",
                                        );
                                    }
                                }
                                Some("image") | Some("document") => {
                                    return ContentStatus::Unsupported(
                                        "multimodal tool results are strictly prohibited",
                                    );
                                }
                                _ => {
                                    return ContentStatus::Unsupported(
                                        "unrecognized block type inside tool_result",
                                    )
                                }
                            }
                        }
                    }
                    _ => {
                        return ContentStatus::Malformed(
                            "tool_result content must be a string or typed array",
                        )
                    }
                }
            } else if matches!(
                t,
                "server_tool_result" | "mcp_tool_result" | "computer_result"
            ) || t.contains("tool_result")
            {
                return ContentStatus::Unsupported("unsupported Anthropic tool_result type");
            }
        }
    }
    ContentStatus::Supported(out)
}

/// Tool calls in an Anthropic response: top-level `content[]` blocks of `tool_use`.
/// Strict extraction of Anthropic tool calls.
pub fn anthropic_tool_calls_strict(response: &serde_json::Value) -> ContentStatus<Vec<ToolCall>> {
    let mut out = Vec::new();
    let Some(blocks) = response.get("content").and_then(|c| c.as_array()) else {
        return ContentStatus::Supported(out);
    };
    for b in blocks {
        let t = b.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if t == "tool_use" {
            let id = b.get("id").and_then(|v| v.as_str()).map(String::from);
            let Some(name) = b.get("name").and_then(|n| n.as_str()) else {
                return ContentStatus::Malformed("tool_use block missing 'name' field");
            };
            let args = b.get("input").cloned().unwrap_or(serde_json::Value::Null);
            out.push(ToolCall {
                id,
                name: name.to_string(),
                args,
            });
        } else if matches!(t, "server_tool_use" | "mcp_tool_use" | "computer_use")
            || t.contains("tool_use")
        {
            return ContentStatus::Unsupported("unsupported Anthropic tool_use type");
        }
    }
    ContentStatus::Supported(out)
}

/// Which streaming wire format tool calls arrive in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamProtocol {
    /// OpenAI Chat Completions: `choices[].delta.tool_calls[]` fragments keyed by
    /// `index`. There is no per-call stop event; the call is complete when the
    /// choice carries a non-null `finish_reason`.
    OpenAiChat,
    /// Anthropic Messages: `content_block_start` opens a `tool_use` block,
    /// `input_json_delta` appends argument fragments, and `content_block_stop`
    /// closes exactly that block.
    AnthropicMessages,
}

/// Cap on the reassembled argument text held for one streamed response. A call
/// larger than this cannot be inspected; that is a fail-closed condition for the
/// caller to decide on, never something to silently truncate and then judge.
pub const MAX_STREAM_TOOL_CALL_BYTES: usize = 256 * 1024;

const TOOL_CALL_TOO_LARGE: &str = "streamed tool call exceeded the inspection size limit";

#[derive(Debug, Default)]
struct PartialToolCall {
    id: Option<String>,
    name: Option<String>,
    args: String,
    initial_input: Option<serde_json::Value>,
}

impl PartialToolCall {
    fn finish(self) -> Option<ToolCall> {
        let name = self.name?;
        let args = if self.args.is_empty() {
            self.initial_input.unwrap_or(serde_json::Value::Null)
        } else {
            serde_json::from_str(&self.args).unwrap_or(serde_json::Value::String(self.args))
        };
        Some(ToolCall {
            id: self.id,
            name,
            args,
        })
    }
}

/// Reassembles tool calls that arrive split across SSE frames.
///
/// Only *completed* calls are ever returned: half of an `arguments` string is not
/// valid JSON, and judging a fragment would both miss payloads that straddle a
/// frame boundary and invent findings inside truncated text. This is the same
/// boundary the Responses adapter already uses (`response.output_item.done`).
#[derive(Debug)]
pub struct StreamingToolCalls {
    protocol: StreamProtocol,
    partial: std::collections::BTreeMap<u64, PartialToolCall>,
    budget: usize,
}

impl StreamingToolCalls {
    pub fn new(protocol: StreamProtocol) -> Self {
        Self::with_limit(protocol, MAX_STREAM_TOOL_CALL_BYTES)
    }

    pub fn with_limit(protocol: StreamProtocol, max_bytes: usize) -> Self {
        Self {
            protocol,
            partial: std::collections::BTreeMap::new(),
            budget: max_bytes,
        }
    }

    /// Feed one decoded SSE payload; returns the calls this event completed.
    pub fn push(&mut self, event: &serde_json::Value) -> Result<Vec<ToolCall>, &'static str> {
        match self.protocol {
            StreamProtocol::OpenAiChat => self.push_openai(event),
            StreamProtocol::AnthropicMessages => self.push_anthropic(event),
        }
    }

    /// Return whether any tool call is currently in-flight / partially accumulated.
    pub fn is_holding(&self) -> bool {
        !self.partial.is_empty()
    }

    /// Complete whatever is still open, so a call whose terminal marker never
    /// arrived is still surfaced rather than silently dropped.
    pub fn flush(&mut self) -> Vec<ToolCall> {
        std::mem::take(&mut self.partial)
            .into_values()
            .filter_map(PartialToolCall::finish)
            .collect()
    }

    fn charge(&mut self, len: usize) -> Result<(), &'static str> {
        self.budget = self.budget.checked_sub(len).ok_or(TOOL_CALL_TOO_LARGE)?;
        Ok(())
    }

    fn push_openai(&mut self, event: &serde_json::Value) -> Result<Vec<ToolCall>, &'static str> {
        let Some(choices) = event.get("choices").and_then(serde_json::Value::as_array) else {
            return Ok(Vec::new());
        };
        let mut completed = false;
        for choice in choices {
            if choice.pointer("/delta/function_call").is_some() {
                return Err("legacy function_call is not supported in streaming; use tool_calls");
            }

            if let Some(calls) = choice
                .pointer("/delta/tool_calls")
                .and_then(serde_json::Value::as_array)
            {
                for call in calls {
                    if let Some(t) = call.get("type").and_then(serde_json::Value::as_str) {
                        if t != "function" {
                            return Err("unsupported tool type in streamed OpenAI call");
                        }
                    }

                    let index = call
                        .get("index")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    let id = call
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .map(String::from);
                    let name = call
                        .pointer("/function/name")
                        .and_then(serde_json::Value::as_str)
                        .filter(|name| !name.is_empty())
                        .map(str::to_string);
                    let fragment = call
                        .pointer("/function/arguments")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();

                    if !fragment.is_empty() {
                        self.charge(fragment.len())?;
                    }
                    let entry = self.partial.entry(index).or_default();
                    if id.is_some() {
                        entry.id = id;
                    }
                    if let Some(name) = name {
                        entry.name = Some(name);
                    }
                    entry.args.push_str(fragment);
                }
            }
            if choice
                .get("finish_reason")
                .is_some_and(|reason| !reason.is_null())
            {
                completed = true;
            }
        }
        if completed {
            Ok(self.flush())
        } else {
            Ok(Vec::new())
        }
    }

    fn push_anthropic(&mut self, event: &serde_json::Value) -> Result<Vec<ToolCall>, &'static str> {
        let index = event
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        match event.get("type").and_then(serde_json::Value::as_str) {
            Some("content_block_start") => {
                let Some(block) = event.get("content_block") else {
                    return Ok(Vec::new());
                };
                let t = block
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if t == "tool_use" {
                    let id = block
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .map(String::from);
                    let Some(name) = block.get("name").and_then(serde_json::Value::as_str) else {
                        return Ok(Vec::new());
                    };
                    self.partial.insert(
                        index,
                        PartialToolCall {
                            id,
                            name: Some(name.to_string()),
                            args: String::new(),
                            initial_input: block.get("input").cloned(),
                        },
                    );
                    Ok(Vec::new())
                } else if matches!(t, "server_tool_use" | "mcp_tool_use" | "computer_use")
                    || t.contains("tool_use")
                {
                    Err("unsupported Anthropic tool type in stream")
                } else {
                    Ok(Vec::new())
                }
            }
            Some("content_block_delta") => {
                if event
                    .pointer("/delta/type")
                    .and_then(serde_json::Value::as_str)
                    != Some("input_json_delta")
                {
                    return Ok(Vec::new());
                }
                let Some(fragment) = event
                    .pointer("/delta/partial_json")
                    .and_then(serde_json::Value::as_str)
                else {
                    return Ok(Vec::new());
                };
                // Only accumulate for a block we opened as `tool_use`; a delta for
                // any other index belongs to text and is not ours to reassemble.
                if !self.partial.contains_key(&index) {
                    return Ok(Vec::new());
                }
                self.charge(fragment.len())?;
                if let Some(entry) = self.partial.get_mut(&index) {
                    entry.args.push_str(fragment);
                }
                Ok(Vec::new())
            }
            Some("content_block_stop") => Ok(self
                .partial
                .remove(&index)
                .and_then(PartialToolCall::finish)
                .into_iter()
                .collect()),
            Some("message_stop") => Ok(self.flush()),
            _ => Ok(Vec::new()),
        }
    }
}

/// Severity ordering so the worst verdict across calls wins. `Escalate` should not
/// reach here (no judge in the proxy), but rank it above `Ask` defensively.
fn verdict_rank(v: Verdict) -> u8 {
    match v {
        Verdict::Allow => 0,
        Verdict::Ask => 1,
        Verdict::Escalate => 2,
        Verdict::Deny => 3,
    }
}

// Wrappers to satisfy existing tests and internal calls
pub fn anthropic_tool_results(request: &serde_json::Value) -> Vec<String> {
    anthropic_tool_results_strict(request)
        .into_result()
        .unwrap_or_default()
}

pub fn anthropic_tool_calls(response: &serde_json::Value) -> Vec<ToolCall> {
    anthropic_tool_calls_strict(response)
        .into_result()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
