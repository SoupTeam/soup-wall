// SPDX-License-Identifier: Apache-2.0
//! Pinned OpenCode 1.19.6 plugin callbacks. Host IDs never confer authority.
use crate::gemini_hook::{bounded, strict, Args, Binding};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

fn exact(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|m| m.len() == keys.len() && keys.iter().all(|k| m.contains_key(*k)))
}

fn translate(bytes: &[u8], binding: &Binding) -> Result<(Value, &'static str)> {
    ensure!(
        binding.contract_version == "sw-opencode-plugin-binding/1"
            && bounded(&binding.host_session, 128)
            && bounded(&binding.host_server, 128)
            && bounded(&binding.native_server, 128)
            && !binding.native_server.contains("__")
            && bounded(&binding.child_authority, 16384),
        "invalid plugin binding"
    );
    let value = strict(bytes)?;
    ensure!(
        exact(&value, &["phase", "input", "output", "cwd"]),
        "unsupported plugin envelope"
    );
    ensure!(
        value["cwd"].as_str().is_some_and(|s| bounded(s, 4096)),
        "invalid plugin directory"
    );
    let (phase, event) = match value["phase"].as_str() {
        Some("before") => ("before", "PreToolUse"),
        Some("after") => ("after", "PostToolUse"),
        _ => anyhow::bail!("unsupported plugin event"),
    };
    let input = &value["input"];
    ensure!(
        exact(
            input,
            if phase == "before" {
                &["tool", "sessionID", "callID"]
            } else {
                &["tool", "sessionID", "callID", "args"]
            }
        ),
        "unsupported plugin input"
    );
    for key in ["tool", "sessionID", "callID"] {
        ensure!(
            input[key].as_str().is_some_and(|s| bounded(s, 256)),
            "invalid plugin correlation field"
        );
    }
    let tool = input["tool"]
        .as_str()
        .unwrap()
        .strip_prefix(&format!("{}_", binding.host_server))
        .context("only the bound MCP server is supported")?;
    ensure!(
        bounded(tool, 128) && !tool.contains("__"),
        "unsupported plugin tool"
    );
    let output = &value["output"];
    let args = if phase == "before" {
        ensure!(exact(output, &["args"]), "unsupported before output");
        &output["args"]
    } else {
        // The real MCP callback carries a CallToolResult, unlike the plugin SDK's
        // title/output declaration for built-in tools. Preserve the entire value.
        ensure!(
            output
                .as_object()
                .is_some_and(|m| m.contains_key("content"))
                && output["content"].is_array(),
            "incomplete MCP plugin result"
        );
        &input["args"]
    };
    ensure!(args.is_object(), "invalid plugin arguments");
    let mut payload = json!({"session_id":binding.host_session,"hook_event_name":event,
        "tool_name":format!("mcp__{}__{}",binding.native_server,tool),"tool_input":args,"cwd":value["cwd"]});
    if phase == "after" {
        payload["tool_response"] = output.clone();
    }
    Ok((payload, phase))
}

pub fn run(args: Args) -> Result<()> {
    crate::gemini_hook::run_adapter(args, translate)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_mcp_result_and_arguments_survive_without_host_authority() {
        let binding = Binding {
            contract_version: "sw-opencode-plugin-binding/1".into(),
            host_session: "issued".into(),
            host_server: "demo".into(),
            native_server: "native".into(),
            child_authority: "proof".into(),
        };
        let mut v = json!({"phase":"after","cwd":"/owned","input":{"tool":"demo_read_document","sessionID":"untrusted","callID":"also-untrusted","args":{"name":"inventory"}},"output":{"content":[{"type":"text","text":"original"}],"structuredContent":{"a":1},"isError":false}});
        let (mapped, phase) = translate(&serde_json::to_vec(&v).unwrap(), &binding).unwrap();
        assert_eq!(phase, "after");
        assert_eq!(mapped["session_id"], "issued");
        assert_eq!(mapped["tool_name"], "mcp__native__read_document");
        assert_eq!(mapped["tool_response"], v["output"]);
        assert_eq!(mapped["tool_input"], v["input"]["args"]);
        v["input"]["agent_id"] = json!("forged");
        assert!(translate(&serde_json::to_vec(&v).unwrap(), &binding).is_err());
        v["input"].as_object_mut().unwrap().remove("agent_id");
        for tool in ["bash", "other_read_document", "demo___unknown"] {
            v["input"]["tool"] = json!(tool);
            assert!(translate(&serde_json::to_vec(&v).unwrap(), &binding).is_err());
        }
        assert!(translate(b"{\"phase\":1,\"phase\":2}", &binding).is_err());
    }
}
