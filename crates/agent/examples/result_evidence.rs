// SPDX-License-Identifier: Apache-2.0
//! Offline diagnostic, never dispatches a tool. One JSON request per line.
use serde_json::{json, Value};
use soup_wall_agent::{AgentEvent, AgentFirewall, AgentPolicySet, EventKind, Provenance};
use soup_wall_core::{Context, Detector, InjectionDetector};
use std::io::{self, BufRead, Read, Write};

struct BoundedOutput(Vec<u8>, usize);

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.1.saturating_sub(self.0.len()) {
            return Err(io::Error::other("diagnostic_output_limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn inspect(v: Value) -> Result<Value, String> {
    let texts: Vec<String> =
        serde_json::from_value(v["channels"].clone()).map_err(|e| e.to_string())?;
    if texts.len() > 1024 {
        return Err("diagnostic_channel_limit".into());
    }
    let policy = AgentPolicySet::from_yaml(v["policy"].as_str().ok_or("missing_policy")?)
        .map_err(|e| e.to_string())?;
    let cross = InjectionDetector::cross_block_signatures(&texts);
    let mut core = Vec::new();
    let mut outcomes = Vec::new();
    for (i, text) in texts.iter().enumerate() {
        core.push(InjectionDetector::default().inspect(&Context::input(text)));
        let mut firewall = AgentFirewall::new(policy.clone(), 1024);
        let ev = AgentEvent {
            session: "ledger-replay".into(),
            agent: "pilot".into(),
            parent: None,
            seq: i as u64 + 1,
            at_ms: 0,
            kind: EventKind::ToolResult {
                tool: "untrusted_tool".into(),
                content: text.clone(),
                source: Provenance::McpServer {
                    name: "untrusted_server".into(),
                },
            },
        };
        outcomes.push(format!(
            "{:?}",
            firewall.preview_native_mcp_result_with_evidence(&ev, &cross)
        ));
    }
    let mut result = json!({"core_findings":core,"cross_findings":cross,"outcomes":outcomes});
    // BEGIN LEDGER: removed only in the external baseline build, never production.
    let cap = v
        .get("observation_cap")
        .and_then(Value::as_u64)
        .unwrap_or(65_536)
        .min(65_536) as usize;
    let ledger = InjectionDetector::mcp_result_evidence(&texts, cap);
    if !ledger.validate_sources(&texts) {
        return Err("diagnostic_invalid_sources".into());
    }
    result["ledger"] = serde_json::to_value(ledger).map_err(|e| e.to_string())?;
    // END LEDGER
    Ok(result)
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    loop {
        // The external supervisor owns deadline, process memory and termination.
        let mut bytes = Vec::new();
        let n = input
            .by_ref()
            .take(8 * 1024 * 1024 + 1)
            .read_until(b'\n', &mut bytes)?;
        if n == 0 {
            break;
        }
        if n > 8 * 1024 * 1024 {
            return Err(io::Error::other("diagnostic_input_limit"));
        }
        let response = serde_json::from_slice(&bytes)
            .map_err(|e| e.to_string())
            .and_then(inspect);
        let mut encoded = BoundedOutput(Vec::new(), 64 * 1024 * 1024);
        serde_json::to_writer(
            &mut encoded,
            &match response {
                Ok(v) => v,
                Err(reason) => json!({"diagnostic_incomplete":true,"reason":reason}),
            },
        )?;
        output.write_all(&encoded.0)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serialized_output_is_bounded_before_retention() {
        let mut out = BoundedOutput(Vec::new(), 8);
        assert!(serde_json::to_writer(&mut out, &json!("abcdefghijk")).is_err());
        assert!(out.0.len() <= 8);
    }
}
