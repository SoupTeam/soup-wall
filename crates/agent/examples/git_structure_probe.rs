// SPDX-License-Identifier: Apache-2.0
//! Counterfactual policy projection only. Never dispatches or releases a result.
use serde_json::{json, Value};
use soup_wall_agent::{AgentEvent, AgentFirewall, AgentPolicySet, EventKind, Provenance, Signals};
use soup_wall_core::{detectors::injection::EvidenceKind, Finding, InjectionDetector, Severity};
use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = String::new();
    io::stdin().take(8 * 1024 * 1024).read_to_string(&mut raw)?;
    let request: Value = serde_json::from_str(&raw)?;
    let texts: Vec<String> = serde_json::from_value(request["channels"].clone())?;
    let policy = AgentPolicySet::from_yaml(request["policy"].as_str().ok_or("policy")?)?;
    let ledger = InjectionDetector::mcp_result_evidence(&texts, 65_536);
    let parsed = request["complete_parse"].as_bool() == Some(true) && ledger.complete;
    let cross = InjectionDetector::cross_block_signatures(&texts);
    let mut baselines = Vec::new();
    let mut projected = Vec::new();
    let mut attribution = Vec::new();
    for (channel, text) in texts.iter().enumerate() {
        let mut firewall = AgentFirewall::new(policy.clone(), 1024);
        let ev = AgentEvent {
            session: "git-structure-shadow".into(),
            agent: "pilot".into(),
            seq: 1,
            at_ms: 0,
            parent: None,
            kind: EventKind::ToolResult {
                tool: "untrusted_tool".into(),
                content: text.clone(),
                source: Provenance::McpServer {
                    name: "untrusted_server".into(),
                },
            },
        };
        let original = firewall.preview_native_mcp_result_with_evidence(&ev, &cross);
        baselines.push(format!("{:?}", original.verdict));
        let mut summary = ledger.channels[channel].heuristic.clone();
        let mut components = Vec::new();
        for e in ledger
            .observations
            .iter()
            .filter(|e| e.join.is_none() && e.sources.len() == 1 && e.sources[0].channel == channel)
        {
            let span = &e.sources[0].bytes;
            let owner = request["parsed"][channel].as_array().and_then(|ranges| {
                ranges.iter().find(|r| {
                    r["start"]
                        .as_u64()
                        .is_some_and(|a| a as usize <= span.start)
                        && r["end"].as_u64().is_some_and(|b| b as usize >= span.end)
                })
            });
            let eligible = parsed && owner.is_some() && e.active;
            if eligible && e.kind == EvidenceKind::EncodedLookingToken {
                summary.encoded_tokens -= 1;
            }
            if eligible && e.kind == EvidenceKind::Delimiter {
                summary.delimiters -= 1;
            }
            components.push(json!({"kind":e.kind,"span":span,"owner":owner.map(|r|r["kind"].clone()),
                                  "weak_discount_candidate":eligible && matches!(e.kind,EvidenceKind::EncodedLookingToken|EvidenceKind::Delimiter),
                                  "finding":e.finding}));
        }
        let score = summary.score();
        let mut findings = original.findings.clone();
        if parsed {
            for (_, finding) in &mut findings {
                if finding.detector == "injection"
                    && finding
                        .label
                        .starts_with("heuristic injection signals (score ")
                {
                    *finding = Finding::new(
                        "injection",
                        if score >= 0.75 {
                            Severity::High
                        } else if score >= 0.5 {
                            Severity::Medium
                        } else {
                            Severity::Low
                        },
                        score,
                        format!("heuristic injection signals (score {score:.2})"),
                    );
                }
            }
            findings.retain(|(_, f)| {
                !(f.detector == "injection"
                    && f.label.starts_with("heuristic injection signals (score ")
                    && score < 0.30)
            });
        }
        // Retain original risk conservatively. For a fresh ToolResult preview
        // the other event signals are default; no tool effects or session state.
        let candidate = policy.evaluate(&Signals {
            findings: findings.clone(),
            risk_score: original.risk_score,
            ..Default::default()
        });
        projected.push(format!("{:?}", candidate.verdict));
        attribution.push(
            json!({"channel":channel,"before":ledger.channels[channel].heuristic,
            "after_weak_discount":summary,"before_score":ledger.channels[channel].heuristic.score(),
            "after_score":score,"components":components,"retained_findings":findings}),
        );
    }
    println!(
        "{}",
        json!({"production_authority":false,"parsed":parsed,
        "baseline_verdicts":baselines,"counterfactual_verdicts":projected,"attribution":attribution})
    );
    Ok(())
}
