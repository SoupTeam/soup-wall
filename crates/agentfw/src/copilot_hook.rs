// SPDX-License-Identifier: Apache-2.0
//! Copilot CLI 1.0.112 callbacks for one private signed native MCP binding.
use crate::gemini_hook::{bounded, strict, Binding};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Phase {
    Before,
    After,
}

#[derive(clap::Args)]
#[group(id = "CopilotHookArgs")]
pub struct Args {
    #[command(flatten)]
    pub connection: crate::gemini_hook::Args,
    /// Trusted hook configuration must select the matching callback phase.
    #[arg(long, value_enum)]
    pub phase: Phase,
}

fn translate(bytes: &[u8], binding: &Binding, after: bool) -> Result<(Value, &'static str)> {
    ensure!(
        binding.contract_version == "sw-copilot-hook-binding/1"
            && bounded(&binding.host_session, 128)
            && bounded(&binding.host_server, 128)
            && bounded(&binding.native_server, 128)
            && !binding.native_server.contains("__")
            && bounded(&binding.child_authority, 16384),
        "invalid Copilot binding"
    );
    let value = strict(bytes)?;
    let map = value.as_object().context("callback must be an object")?;
    ensure!(
        map.len() == if after { 7 } else { 6 }
            && map.keys().all(|k| [
                "sessionId",
                "timestamp",
                "cwd",
                "toolCallId",
                "toolName",
                "toolArgs",
                "toolResult"
            ]
            .contains(&k.as_str()))
            && map.contains_key("toolResult") == after,
        "unsupported Copilot callback fields"
    );
    for (name, max) in [
        ("sessionId", 128),
        ("toolCallId", 128),
        ("cwd", 4096),
        ("toolName", 256),
    ] {
        ensure!(
            value[name].as_str().is_some_and(|s| bounded(s, max)),
            "invalid callback correlation field"
        );
    }
    ensure!(
        value["timestamp"]
            .as_u64()
            .is_some_and(|n| n <= 9_007_199_254_740_991)
            && value["toolArgs"].is_object(),
        "invalid callback timestamp or arguments"
    );
    let tool = value["toolName"]
        .as_str()
        .unwrap()
        .strip_prefix(&format!("{}-", binding.host_server))
        .context("only the bound MCP server is supported")?;
    ensure!(
        bounded(tool, 128) && !tool.contains("__"),
        "unsupported Copilot tool"
    );
    let mut payload = json!({"session_id":binding.host_session,"hook_event_name":if after {"PostToolUse"} else {"PreToolUse"},
        "tool_name":format!("mcp__{}__{}",binding.native_server,tool),"tool_input":value["toolArgs"],"cwd":value["cwd"]});
    if after {
        ensure!(
            value["toolResult"].is_object()
                && value["toolResult"]["textResultForLlm"].is_string()
                && value["toolResult"]["resultType"] == "success",
            "unsupported or incomplete Copilot result"
        );
        payload["tool_response"] = value["toolResult"].clone();
    }
    Ok((payload, if after { "after" } else { "before" }))
}
fn before(bytes: &[u8], binding: &Binding) -> Result<(Value, &'static str)> {
    translate(bytes, binding, false)
}
fn after(bytes: &[u8], binding: &Binding) -> Result<(Value, &'static str)> {
    translate(bytes, binding, true)
}

fn render(receipt: Value, phase: Phase) -> Value {
    if receipt.as_object().is_some_and(|m| m.is_empty()) {
        return json!({});
    }
    let reason = receipt["reason"]
        .as_str()
        .unwrap_or("Soup Wall callback unavailable; the call/result is withheld.");
    match phase {
        Phase::Before => json!({"permissionDecision":"deny","permissionDecisionReason":reason}),
        // Explicit failure withholding, never a sanitized success result or an
        // attempt to undo an effect that already happened before this callback.
        Phase::After => {
            json!({"modifiedResult":{"resultType":"failure","textResultForLlm":reason}})
        }
    }
}

pub fn run(args: Args) -> Result<()> {
    let receipt = crate::gemini_hook::decide_adapter(
        &args.connection,
        match args.phase {
            Phase::Before => before,
            Phase::After => after,
        },
    );
    println!("{}", serde_json::to_string(&render(receipt, args.phase))?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn callback_cli_has_unique_argument_groups() {
        <Args as clap::Args>::augment_args(clap::Command::new("copilot-hook")).debug_assert();
    }
    #[test]
    fn captured_callbacks_preserve_values_without_accepting_host_authority() {
        let binding = Binding {
            contract_version: "sw-copilot-hook-binding/1".into(),
            host_session: "issued".into(),
            host_server: "demo".into(),
            native_server: "native".into(),
            child_authority: "proof".into(),
        };
        let frames: Vec<Value> = serde_json::from_str(include_str!(
            "../../../scripts/fixtures/copilot-1.0.112-hooks.json"
        ))
        .unwrap();
        for (i, frame) in frames.iter().enumerate() {
            let (mapped, phase) = translate(
                &serde_json::to_vec(&frame["value"]).unwrap(),
                &binding,
                i == 1,
            )
            .unwrap();
            assert_eq!(phase, if i == 1 { "after" } else { "before" });
            assert_eq!(mapped["session_id"], "issued");
            assert_eq!(mapped["tool_name"], "mcp__native__read_document");
            assert_eq!(mapped["tool_input"], frame["value"]["toolArgs"]);
            if i == 1 {
                assert_eq!(mapped["tool_response"], frame["value"]["toolResult"]);
            }
        }
        let mut bad = frames[0]["value"].clone();
        bad["agent_id"] = json!("forged");
        assert!(before(&serde_json::to_vec(&bad).unwrap(), &binding).is_err());
        bad.as_object_mut().unwrap().remove("agent_id");
        bad["toolName"] = json!("bash");
        assert!(before(&serde_json::to_vec(&bad).unwrap(), &binding).is_err());
        assert!(after(&serde_json::to_vec(&frames[0]["value"]).unwrap(), &binding).is_err());
        assert_eq!(render(json!({}), Phase::Before), json!({}));
        assert_eq!(
            render(json!({"decision":"deny","reason":"held"}), Phase::Before)["permissionDecision"],
            "deny"
        );
        assert_eq!(
            render(json!({"decision":"deny","reason":"held"}), Phase::After)["modifiedResult"]
                ["resultType"],
            "failure"
        );
    }
}
