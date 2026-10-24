// SPDX-License-Identifier: Apache-2.0
//! Bounded offline adapter for the SOU-123 result-inspection corpus.
//!
//! Runs each retained original-server payload through the existing production entry point,
//! `AgentFirewall::preview_native_result`, with a policy file. It adds no detector and does
//! not decide expected labels; `eval/sou123/run_corpus.py` scores the output.
use agentfw::native::MAX_CONTENT;
use serde_json::{json, Value};
use soup_wall_agent::{AgentEvent, AgentFirewall, AgentPolicySet, EventKind, Provenance};
use std::{fs, path::PathBuf, time::Instant};

fn arg(name: &str) -> String {
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == name {
            return it
                .next()
                .unwrap_or_else(|| fail(&format!("{name} needs a value")));
        }
    }
    fail(&format!("missing {name}"))
}

fn fail(msg: &str) -> ! {
    eprintln!("result_inspection_corpus: {msg}");
    std::process::exit(2)
}

fn main() {
    let manifest: Value = serde_json::from_slice(
        &fs::read(arg("--manifest")).unwrap_or_else(|e| fail(&format!("manifest: {e}"))),
    )
    .unwrap_or_else(|e| fail(&format!("manifest json: {e}")));
    let dir = PathBuf::from(arg("--payload-dir"));
    let policy_yaml =
        fs::read_to_string(arg("--policy")).unwrap_or_else(|e| fail(&format!("policy: {e}")));
    let cases = manifest["cases"]
        .as_array()
        .unwrap_or_else(|| fail("manifest has no cases"));
    let mut out = Vec::new();
    for case in cases {
        let id = case["case_id"]
            .as_str()
            .unwrap_or_else(|| fail("case without id"));
        let tool = case["tool"]
            .as_str()
            .unwrap_or_else(|| fail("case without tool"));
        let bytes =
            fs::read(dir.join(format!("{id}.txt"))).unwrap_or_else(|e| fail(&format!("{id}: {e}")));
        if bytes.len() > MAX_CONTENT {
            out.push(
                json!({"case_id": id, "status": "over_budget_not_inspected", "bytes": bytes.len()}),
            );
            continue;
        }
        let Ok(text) = String::from_utf8(bytes.clone()) else {
            out.push(
                json!({"case_id": id, "status": "technical_error", "reason": "payload_not_utf8"}),
            );
            continue;
        };
        let policy = AgentPolicySet::from_yaml(&policy_yaml)
            .unwrap_or_else(|e| fail(&format!("policy parse: {e:?}")));
        let mut firewall = AgentFirewall::new(policy, 1024);
        let event = AgentEvent {
            session: format!("corpus-{id}"),
            agent: "corpus".into(),
            parent: None,
            seq: 1,
            at_ms: 0,
            kind: EventKind::ToolResult {
                tool: tool.into(),
                content: text,
                source: Provenance::McpServer {
                    name: "original-pinned".into(),
                },
            },
        };
        let started = Instant::now();
        let outcome = firewall.preview_native_result(&event);
        let micros = started.elapsed().as_micros() as u64;
        let findings: Vec<Value> = outcome
            .findings
            .iter()
            .map(|(facet, f)| json!({"facet": format!("{facet:?}"), "detector": f.detector, "severity": format!("{:?}", f.severity), "confidence": f.confidence}))
            .collect();
        out.push(json!({
            "case_id": id, "status": "inspected", "verdict": format!("{:?}", outcome.verdict),
            "rule": outcome.rule, "findings": findings, "latency_micros": micros,
        }));
    }
    println!(
        "{}",
        serde_json::to_string(&json!({"results": out})).unwrap()
    );
}
