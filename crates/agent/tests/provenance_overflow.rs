// SPDX-License-Identifier: Apache-2.0
//! Synthetic component regressions; no tool or network operation is executed.

use serde_json::json;
use soup_wall_agent::{
    ActionClass, AgentEvent, AgentFirewall, AgentPolicySet, EventKind, Provenance, Verdict,
};

const PROSE: &str = "The archival checklist describes the sequence of ordinary document reviews and the regional reporting schedule for the coming quarter.";

fn event(session: &str, seq: u64, kind: EventKind) -> AgentEvent {
    AgentEvent {
        session: session.into(),
        agent: "main".into(),
        parent: None,
        seq,
        at_ms: seq,
        kind,
    }
}

fn result(session: &str, seq: u64, content: &str) -> AgentEvent {
    event(
        session,
        seq,
        EventKind::ToolResult {
            tool: "WebFetch".into(),
            content: content.into(),
            source: Provenance::Network {
                host: "docs.example".into(),
            },
        },
    )
}

fn call(session: &str, tool: &str, text: &str) -> AgentEvent {
    event(
        session,
        2000,
        EventKind::ToolCall {
            tool: tool.into(),
            args: json!({"text": text}),
        },
    )
}

fn firewall(cap: usize) -> AgentFirewall {
    AgentFirewall::new(AgentPolicySet::from_yaml("default: allow").unwrap(), cap)
}

#[test]
fn evicted_early_prose_url_and_path_cannot_become_clean_effectful_calls() {
    for early in [PROSE, "https://old.io/x", "/tmp/early-document.txt"] {
        let mut fw = firewall(8);
        fw.admit_native_result(&result("s", 1, early));
        for seq in 2..80 {
            let filler = format!(
                "https://new{seq}.io/x Orchards contain apple trees beside winding rivers. \
                 Mountain climbers follow rocky trails through snowy valleys while \
                 migrating birds cross distant oceans beneath shimmering stars."
            );
            fw.admit_native_result(&result("s", seq, &filler));
        }
        assert!(fw.provenance_incomplete("s"));
        for class in [
            ActionClass::SideEffecting,
            ActionClass::Network,
            ActionClass::PrivilegeChanging,
            ActionClass::Destructive,
        ] {
            let out = fw.inspect_native_call(&call("s", "opaque", early), class, &[]);
            assert_eq!(out.verdict, Verdict::Ask);
            assert_eq!(out.rule.as_deref(), Some("taint-history-incomplete"));
            assert!(out.provenance_incomplete);
            assert!(
                out.taint.is_none(),
                "discarded source must not be fabricated"
            );
            assert_eq!(out.fallback, None);
            assert_eq!(
                out.adapter_response("p").reason_codes,
                vec!["taint-history-incomplete".to_string()]
            );
        }
    }
}

#[test]
fn zero_capacity_covers_hook_sensitive_reads_and_native_effects() {
    let mut fw = firewall(0);
    fw.inspect(&result("s", 1, "short"));
    assert_eq!(
        fw.inspect(&call("s", "Write", "ordinary")).verdict,
        Verdict::Ask
    );
    assert_eq!(
        fw.inspect(&call("s", "Read", "/etc/passwd")).verdict,
        Verdict::Ask
    );
    assert_eq!(
        fw.inspect(&call("s", "Read", "src/main.rs")).verdict,
        Verdict::Allow
    );
    assert_eq!(
        fw.inspect(&call("peer", "Write", "ordinary")).verdict,
        Verdict::Allow
    );
    assert!(fw.provenance_incomplete("s"));
    assert!(!fw.provenance_incomplete("peer"));
}

#[test]
fn benign_below_capacity_and_unadmitted_preview_remain_unaffected() {
    let mut fw = firewall(1000);
    fw.inspect(&result("s", 1, PROSE));
    assert!(!fw.provenance_incomplete("s"));
    assert_eq!(
        fw.inspect(&call("s", "Write", "ordinary")).verdict,
        Verdict::Allow
    );
    let mut disabled = firewall(0);
    disabled.preview_native_result(&result("s", 1, PROSE));
    assert!(!disabled.provenance_incomplete("s"));
    disabled.admit_native_result(&result("s", 1, PROSE));
    assert!(disabled.provenance_incomplete("s"));
}

#[test]
fn trusted_input_peer_activity_and_duplicate_start_cannot_reset_loss() {
    let mut fw = firewall(0);
    fw.inspect(&result("s", 1, PROSE));
    fw.inspect(&event(
        "s",
        2,
        EventKind::ToolResult {
            tool: "Read".into(),
            content: "trusted".into(),
            source: Provenance::UserPrompt,
        },
    ));
    fw.inspect(&result("peer", 1, PROSE));
    fw.inspect(&event("peer", 2, EventKind::SessionEnd));
    assert!(
        fw.inspect(&event("s", 3, EventKind::SessionStart))
            .provenance_incomplete
    );
    assert_eq!(
        fw.inspect(&call("s", "Write", "ordinary")).verdict,
        Verdict::Ask
    );
    fw.inspect(&event("s", 4, EventKind::SessionEnd));
    assert!(!fw.provenance_incomplete("s"));
    fw.inspect(&event("s", 5, EventKind::SessionStart));
    assert_eq!(
        fw.inspect(&call("s", "Write", "ordinary")).verdict,
        Verdict::Allow
    );
    assert_eq!(
        fw.inspect(&call("new", "Write", "ordinary")).verdict,
        Verdict::Allow
    );
}

#[test]
fn retained_hard_deny_survives_incomplete_history() {
    let policy = AgentPolicySet::from_yaml(include_str!("../policies/agent-default.yaml")).unwrap();
    let mut fw = AgentFirewall::new(policy, 1);
    fw.inspect(&result("s", 1, "https://old.io/x"));
    fw.inspect(&result("s", 2, "https://last.io/x"));
    let out = fw.inspect_native_call(
        &call("s", "opaque", "https://last.io/x"),
        ActionClass::Destructive,
        &[],
    );
    assert!(out.provenance_incomplete);
    assert!(out.taint.is_some());
    assert_eq!(out.verdict, Verdict::Deny);
    assert_eq!(out.rule.as_deref(), Some("deny-tainted-destructive"));
}

#[test]
fn explicit_allow_and_judge_fallback_cannot_bypass_loss_floor() {
    for action in [
        "allow",
        "escalate\n    fallback: allow",
        "escalate\n    fallback: ask",
    ] {
        let policy = AgentPolicySet::from_yaml(&format!(
            "agent_policies:\n  - name: candidate\n    when: {{}}\n    action: {action}\ndefault: allow"
        )).unwrap();
        let mut fw = AgentFirewall::new(policy, 0);
        fw.admit_native_result(&result("s", 1, PROSE));
        let out = fw.inspect_native_call(
            &call("s", "opaque", "ordinary"),
            ActionClass::Network,
            &["approved.example".into()],
        );
        assert_eq!(out.verdict, Verdict::Ask);
        assert_eq!(out.fallback, None);
    }
    for action in ["ask", "deny"] {
        let mut fw = AgentFirewall::new(
            AgentPolicySet::from_yaml(&format!("default: {action}")).unwrap(),
            0,
        );
        fw.admit_native_result(&result("s", 1, PROSE));
        let out = fw.inspect(&call("s", "Write", "ordinary"));
        assert_eq!(
            out.verdict,
            if action == "deny" {
                Verdict::Deny
            } else {
                Verdict::Ask
            }
        );
        assert_eq!(out.rule, None);
    }
}
