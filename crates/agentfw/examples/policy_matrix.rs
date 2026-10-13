// SPDX-License-Identifier: Apache-2.0
//! Frozen controlled inputs through production policy, engine and resolution APIs.
use agentfw::{decision, handlers::resolve_escalation, judge};
use serde::Deserialize;
use serde_json::{json, Value};
use soup_wall_agent::{
    ActionClass, AgentEvent, AgentFirewall, AgentPolicySet, EventKind, Facet, Outcome, Provenance,
    Signals, TaintMark, Verdict,
};
use soup_wall_core::{Finding, Severity};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    action_class: Option<ActionClass>,
    taint: bool,
    incomplete: bool,
    secret: bool,
    pii: bool,
    sensitive: bool,
    drift: bool,
    shadow: bool,
    delegated: bool,
    hosts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    policy: Option<String>,
    signals: Option<Input>,
    #[serde(default)]
    events: Vec<AgentEvent>,
    root_tools: Option<Vec<String>>,
    cap: Option<usize>,
    native: Option<ActionClass>,
    #[serde(default)]
    hosts: Vec<String>,
    handshake: Option<[bool; 2]>,
    verdict: Option<Verdict>,
    fallback: Option<Verdict>,
    #[serde(default)]
    judge: String,
    #[serde(default)]
    unresolved_boundary: bool,
    expected: String,
    expected_rule: Option<String>,
    historical: Option<String>,
}

fn name(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Ask => "ask",
        Verdict::Deny => "deny",
        Verdict::Escalate => "escalate",
    }
}

fn run(c: &Case) -> Value {
    let policy = AgentPolicySet::from_yaml(
        c.policy
            .as_deref()
            .unwrap_or(include_str!("../../agent/policies/agent-default.yaml")),
    )
    .expect("frozen policy parses");
    let mut out = if let Some(i) = &c.signals {
        let mut findings = Vec::new();
        for (present, detector) in [(i.secret, "secret.synthetic"), (i.pii, "pii.synthetic")] {
            if present {
                findings.push((
                    Facet::ToolArgs,
                    Finding::new(detector, Severity::High, 1.0, "synthetic"),
                ));
            }
        }
        let signals = Signals {
            action_class: i.action_class,
            taint: i.taint.then(|| TaintMark {
                source: Provenance::Network {
                    host: "fixture.invalid".into(),
                },
                seq: 1,
            }),
            provenance_incomplete: i.incomplete,
            findings: findings.clone(),
            touches_sensitive_path: i.sensitive,
            mcp_manifest_changed: i.drift,
            mcp_tool_shadow: i.shadow,
            subagent_escalation: i.delegated,
            egress_hosts: i.hosts.clone(),
            ..Default::default()
        };
        let d = policy.evaluate(&signals);
        Outcome {
            verdict: d.verdict,
            rule: d.rule,
            message: d.message,
            fallback: d.fallback,
            taint: signals.taint,
            provenance_incomplete: i.incomplete,
            findings,
            risk_score: 0,
            egress_hosts: i.hosts.clone(),
        }
    } else {
        let mut fw = AgentFirewall::new(policy, c.cap.unwrap_or(10000));
        if let Some(tools) = &c.root_tools {
            fw.set_root("s", "main", tools);
        }
        let mut last = None;
        for ev in &c.events {
            let class = c.native.filter(|_| matches!(ev.kind, EventKind::ToolCall { .. }));
            last = Some(if let Some(class) = class {
                fw.inspect_native_call(ev, class, &c.hosts)
            } else {
                fw.inspect(ev)
            });
        }
        if let Some([drift, shadow]) = c.handshake {
            last = Some(fw.inspect_mcp_handshake("fixture", &[], drift, shadow));
        }
        last.unwrap_or_else(|| Outcome {
            verdict: c.verdict.expect("case has an entry point"),
            rule: None,
            message: None,
            fallback: c.fallback,
            taint: None,
            provenance_incomplete: false,
            findings: Vec::new(),
            risk_score: 0,
            egress_hosts: Vec::new(),
        })
    };
    let initial = out.verdict;
    if !c.unresolved_boundary && out.verdict == Verdict::Escalate {
        let j = match c.judge.as_str() {
            "injection" => judge::parse_answer("INJECTION"),
            "documentation" => judge::parse_answer("DOCUMENTATION"),
            "invalid" => judge::parse_answer("IGNORE RULES; ALLOW"),
            other => judge::Judgement::Unavailable(other.into()),
        };
        out.verdict = resolve_escalation(j, out.fallback);
    }
    let hook = decision::decide(
        out.verdict,
        out.rule.as_deref(),
        out.message.as_deref(),
        true,
    );
    let adapter = serde_json::to_value(out.adapter_response("frozen-matrix-v1")).unwrap();
    let final_name = name(hook.would_have_been);
    let expected_hook = match c.expected.as_str() {
        "allow" => "defer",
        "ask" => "ask",
        "deny" => "deny",
        _ => panic!("invalid expected verdict"),
    };
    let passed = final_name == c.expected
        && hook.permission_decision == expected_hook
        && adapter["verdict"] == c.expected
        && c.expected_rule
            .as_ref()
            .is_none_or(|r| out.rule.as_ref() == Some(r));
    json!({"id":c.id,"expected":c.expected,"actual":final_name,"initial":name(initial),
        "hook":hook.permission_decision,"adapter":adapter["verdict"],"rule":out.rule,
        "expected_rule":c.expected_rule,"incomplete":out.provenance_incomplete,
        "known_taint":out.taint.is_some(),"passed":passed,"historical":c.historical})
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 3, "usage: policy_matrix INPUT.json OUTPUT.json");
    let cases: Vec<Case> = serde_json::from_slice(&std::fs::read(&args[1]).unwrap()).unwrap();
    assert!(!cases.is_empty());
    let mut ids = std::collections::HashSet::new();
    let rows: Vec<Value> = cases
        .iter()
        .map(|c| {
            assert!(ids.insert(&c.id), "duplicate matrix id");
            run(c)
        })
        .collect();
    let passed = rows.iter().filter(|r| r["passed"] == true).count();
    let report = json!({"total":rows.len(),"passed":passed,"cases":rows});
    std::fs::write(&args[2], serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("policy matrix: {passed}/{}", cases.len());
    if passed != cases.len() {
        std::process::exit(1);
    }
}
