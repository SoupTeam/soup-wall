// SPDX-License-Identifier: Apache-2.0
//! Gemini 0.68.0 callback bridge for one explicitly bound native MCP collector.
//! Host identifiers are correlation only. The daemon verifies the private signed
//! binding against an active collector; callbacks never mint native authority.
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

const MAX_INPUT: usize = 1024 * 1024;

#[derive(clap::Args)]
pub struct Args {
    /// Existing owner-private Agent profile directory.
    #[arg(long)]
    pub home: PathBuf,
    /// Owner-private binding issued for the same active native MCP collector.
    #[arg(long)]
    pub binding: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub(crate) contract_version: String,
    pub(crate) host_session: String,
    pub(crate) host_server: String,
    pub(crate) native_server: String,
    pub(crate) child_authority: String,
}

pub(crate) fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

pub(crate) fn strict(bytes: &[u8]) -> Result<Value> {
    let crate::mcp::admission::Strict(value) = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid or duplicate callback fields"))?;
    Ok(value)
}

fn translate(bytes: &[u8], binding: &Binding) -> Result<(Value, &'static str)> {
    ensure!(bytes.len() <= MAX_INPUT, "callback too large");
    ensure!(
        binding.contract_version == "sw-gemini-hook-binding/1"
            && bounded(&binding.host_session, 128)
            && bounded(&binding.host_server, 128)
            && bounded(&binding.native_server, 128)
            && !binding.native_server.contains("__")
            && bounded(&binding.child_authority, 16384),
        "invalid callback binding"
    );
    let value = strict(bytes)?;
    let map = value.as_object().context("callback must be an object")?;
    ensure!(
        map.keys().all(|k| [
            "session_id",
            "transcript_path",
            "cwd",
            "hook_event_name",
            "timestamp",
            "tool_name",
            "tool_input",
            "tool_response",
            "mcp_context",
            "original_request_name"
        ]
        .contains(&k.as_str())),
        "unsupported callback field"
    );
    for (name, max) in [
        ("session_id", 128),
        ("transcript_path", 4096),
        ("cwd", 4096),
        ("timestamp", 64),
        ("tool_name", 256),
    ] {
        ensure!(
            value[name].as_str().is_some_and(|s| bounded(s, max)),
            "invalid callback correlation field"
        );
    }
    let (event, phase) = match value["hook_event_name"].as_str() {
        Some("BeforeTool") => ("PreToolUse", "before"),
        Some("AfterTool") => ("PostToolUse", "after"),
        _ => anyhow::bail!("unsupported callback event"),
    };
    ensure!(
        value["tool_input"].is_object(),
        "invalid callback arguments"
    );
    ensure!(
        (phase == "after") == map.contains_key("tool_response"),
        "incomplete callback result"
    );
    let context = value["mcp_context"]
        .as_object()
        .context("only the bound MCP server is supported")?;
    ensure!(
        context
            .keys()
            .all(|k| ["server_name", "tool_name", "command", "args", "cwd"].contains(&k.as_str())),
        "unsupported MCP callback transport"
    );
    let tool = context
        .get("tool_name")
        .and_then(Value::as_str)
        .context("missing MCP tool name")?;
    ensure!(
        bounded(tool, 128)
            && !tool.contains("__")
            && context.get("server_name").and_then(Value::as_str)
                == Some(binding.host_server.as_str())
            && value["tool_name"] == format!("mcp_{}_{}", binding.host_server, tool),
        "MCP callback identity mismatch"
    );
    if let Some(original) = map.get("original_request_name") {
        ensure!(
            original == &value["tool_name"],
            "MCP callback alias is unsupported"
        );
    }
    // No host-supplied agent, parent, session or provenance claim crosses here.
    // Arguments and the entire original result Value are retained unchanged.
    let mut payload = json!({"session_id":binding.host_session,"hook_event_name":event,
        "tool_name":format!("mcp__{}__{}", binding.native_server, tool),
        "tool_input":value["tool_input"], "cwd":value["cwd"]});
    if phase == "after" {
        payload["tool_response"] = value["tool_response"].clone();
    }
    Ok((payload, phase))
}

fn render(receipt: &Value, phase: &str) -> Result<Value> {
    let map = receipt.as_object().context("invalid callback receipt")?;
    ensure!(
        map.len() == 4
            && ["decision", "reason", "phase", "shadow"]
                .iter()
                .all(|k| map.contains_key(*k))
            && receipt["phase"] == phase
            && receipt["shadow"].is_boolean()
            && (receipt["reason"].is_null()
                || receipt["reason"].as_str().is_some_and(|s| bounded(s, 8192))),
        "invalid callback receipt"
    );
    let reason = receipt["reason"]
        .as_str()
        .unwrap_or("Soup Wall policy requires confirmation.");
    match receipt["decision"].as_str() {
        Some("defer") => Ok(json!({})),
        Some("deny") => Ok(json!({"decision":"deny","reason":reason})),
        // The pinned headless host waits indefinitely on MCP `ask`. Keep the
        // policy Ask visible while withholding execution/result; never turn it
        // into Allow or claim that a host prompt is a native single-use grant.
        Some("ask") => Ok(
            json!({"decision":"deny","reason":format!("Soup Wall Ask is pending explicit confirmation: {reason}")}),
        ),
        _ => anyhow::bail!("invalid callback disposition"),
    }
}

type Translator = fn(&[u8], &Binding) -> Result<(Value, &'static str)>;

async fn exchange(args: &Args, input: &[u8], translate: Translator) -> Result<Value> {
    ensure!(cfg!(target_os = "linux"), "Host callback requires Linux");
    let config = crate::doctor::read_private(&args.home.join("config.yaml"), MAX_INPUT as u64)?;
    let config = crate::Config::from_yaml(std::str::from_utf8(&config)?)?;
    let token = crate::doctor::read_private(&args.home.join("token"), 4096)?;
    let token = std::str::from_utf8(&token)?.trim();
    ensure!(
        bounded(token, 4096),
        "invalid callback transport credential"
    );
    let bytes = crate::doctor::read_private(&args.binding, 32768)?;
    let binding: Binding = serde_json::from_value(strict(&bytes)?)?;
    let (payload, phase) = translate(input, &binding)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(1500))
        .build()?;
    let mut response = client
        .post(config.endpoint_url("/hook/decision/v1"))
        .bearer_auth(token)
        .header("X-Agentfw-Child-Authority", &binding.child_authority)
        .json(&payload)
        .send()
        .await?
        .error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 65536,
            "callback receipt too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    render(&strict(&bytes)?, phase)
}

/// Explicit deny on every handled I/O, parse or transport failure. Gemini can
/// still fail open if this executable cannot start, is killed, or its host-side
/// timeout expires. The native MCP collector remains the execution boundary.
pub fn run(args: Args) -> Result<()> {
    run_adapter(args, translate)
}

pub(crate) fn run_adapter(args: Args, translate: Translator) -> Result<()> {
    let result = (|| {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take((MAX_INPUT + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_INPUT, "callback too large");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(exchange(&args, &bytes, translate))
    })();
    let output = result.unwrap_or_else(|_: anyhow::Error| json!({"decision":"deny", "reason":"Soup Wall callback is unavailable, unsupported or unverified; the call/result is withheld."}));
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding {
            contract_version: "sw-gemini-hook-binding/1".into(),
            host_session: "trusted-session".into(),
            host_server: "demo".into(),
            native_server: "gemini-native".into(),
            child_authority: "opaque-proof".into(),
        }
    }
    fn frame() -> Value {
        json!({"session_id":"untrusted-session", "transcript_path":"/owned/transcript", "cwd":"/owned", "timestamp":"2026-11-17T12:36:35.920Z",
            "hook_event_name":"BeforeTool", "tool_name":"mcp_demo_read_document", "tool_input":{"name":"inventory"},
            "mcp_context":{"server_name":"demo", "tool_name":"read_document", "command":"/usr/bin/env", "args":[]}})
    }
    #[test]
    fn binding_replaces_identity_but_preserves_arguments_and_results() {
        let mut input = frame();
        let (payload, phase) = translate(&serde_json::to_vec(&input).unwrap(), &binding()).unwrap();
        assert_eq!(phase, "before");
        assert_eq!(payload["session_id"], "trusted-session");
        assert_eq!(payload["tool_name"], "mcp__gemini-native__read_document");
        assert_eq!(payload["tool_input"], input["tool_input"]);
        input["hook_event_name"] = json!("AfterTool");
        input["tool_response"] =
            json!({"llmContent":[{"text":"original"}],"returnDisplay":"display"});
        let (payload, phase) = translate(&serde_json::to_vec(&input).unwrap(), &binding()).unwrap();
        assert_eq!(phase, "after");
        assert_eq!(payload["tool_response"], input["tool_response"]);
    }
    #[test]
    fn unsupported_identity_and_callback_shapes_are_refused() {
        for (pointer, value) in [
            ("/tool_name", json!("run_shell_command")),
            ("/tool_input", json!(null)),
            ("/mcp_context/server_name", json!("other")),
            ("/hook_event_name", json!("SessionStart")),
        ] {
            let mut frame = frame();
            *frame.pointer_mut(pointer).unwrap() = value;
            assert!(translate(&serde_json::to_vec(&frame).unwrap(), &binding()).is_err());
        }
        let mut frame = frame();
        frame["agent_id"] = json!("claimed-authority");
        assert!(translate(&serde_json::to_vec(&frame).unwrap(), &binding()).is_err());
        assert!(translate(b"{\"tool_name\":1,\"tool_name\":2}", &binding()).is_err());
    }
    #[test]
    fn defer_never_approves_and_strong_decisions_remain_strong() {
        for phase in ["before", "after"] {
            let mut receipt =
                json!({"decision":"defer","reason":null,"phase":phase,"shadow":false});
            assert_eq!(render(&receipt, phase).unwrap(), json!({}));
            receipt["decision"] = json!("deny");
            assert_eq!(render(&receipt, phase).unwrap()["decision"], "deny");
            receipt["decision"] = json!("ask");
            assert_eq!(render(&receipt, phase).unwrap()["decision"], "deny");
        }
        assert!(render(&json!({}), "before").is_err());
    }
}
