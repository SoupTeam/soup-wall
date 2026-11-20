// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)
use super::*;
use crate::action::ActionClass;
use crate::event::Provenance;
use crate::taint::TaintMark;
use soup_wall_core::{Finding, Severity};

const YAML: &str = r#"
agent_policies:
  - name: deny-tainted-destructive
    when: { taint: [network, mcp], action_class: destructive }
    action: deny
    message: "Blocked: destructive action derived from untrusted content"
  - name: ask-tainted-side-effect
    when: { taint: [network, mcp], min_action_class: side_effecting }
    action: ask
  - name: deny-secret-egress
    when: { detector: secret, facet: tool_args, min_action_class: network }
    action: deny
  - name: ask-unknown-host
    when: { egress_not_allowlisted: true }
    action: ask
  - name: deny-subagent-escalation
    when: { subagent_escalation: true }
    action: deny
egress_allowlist: [github.com, crates.io]
default: allow
"#;

fn signals() -> Signals {
    Signals::default()
}

#[test]
fn parses_the_shipped_shape() {
    let p = AgentPolicySet::from_yaml(YAML).expect("parse");
    assert_eq!(p.agent_policies.len(), 5);
    assert_eq!(p.default, Verdict::Allow);
    assert_eq!(p.egress_allowlist, vec!["github.com", "crates.io"]);
}

#[test]
fn clean_signals_fall_through_to_the_default() {
    let p = AgentPolicySet::from_yaml(YAML).unwrap();
    assert_eq!(p.evaluate(&signals()).verdict, Verdict::Allow);
}

#[test]
fn tainted_destructive_is_denied() {
    let p = AgentPolicySet::from_yaml(YAML).unwrap();
    let mut s = signals();
    s.action_class = Some(ActionClass::Destructive);
    s.taint = Some(TaintMark {
        source: Provenance::Network {
            host: "evil.com".into(),
        },
        seq: 2,
    });
    let d = p.evaluate(&s);
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rule.as_deref(), Some("deny-tainted-destructive"));
}

#[test]
fn tainted_write_is_asked_not_denied() {
    let p = AgentPolicySet::from_yaml(YAML).unwrap();
    let mut s = signals();
    s.action_class = Some(ActionClass::SideEffecting);
    s.taint = Some(TaintMark {
        source: Provenance::McpServer {
            name: "rogue".into(),
        },
        seq: 1,
    });
    assert_eq!(p.evaluate(&s).verdict, Verdict::Ask);
}

#[test]
fn tainted_read_only_is_allowed() {
    let p = AgentPolicySet::from_yaml(YAML).unwrap();
    let mut s = signals();
    s.action_class = Some(ActionClass::ReadOnly);
    s.taint = Some(TaintMark {
        source: Provenance::Network {
            host: "evil.com".into(),
        },
        seq: 1,
    });
    assert_eq!(p.evaluate(&s).verdict, Verdict::Allow);
}

#[test]
fn a_secret_in_a_network_call_is_denied() {
    let p = AgentPolicySet::from_yaml(YAML).unwrap();
    let mut s = signals();
    s.action_class = Some(ActionClass::Network);
    s.findings = vec![(
        crate::facet::Facet::ToolArgs,
        Finding::new("secret.aws_key", Severity::Critical, 0.99, "AWS key"),
    )];
    let d = p.evaluate(&s);
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rule.as_deref(), Some("deny-secret-egress"));
}

#[test]
fn an_unlisted_egress_host_is_asked() {
    let p = AgentPolicySet::from_yaml(YAML).unwrap();
    let mut s = signals();
    s.egress_hosts = vec!["evil.com".into()];
    assert_eq!(p.evaluate(&s).verdict, Verdict::Ask);
}

#[test]
fn an_allowlisted_egress_host_is_not_asked() {
    let p = AgentPolicySet::from_yaml(YAML).unwrap();
    let mut s = signals();
    s.egress_hosts = vec!["api.github.com".into()];
    assert_eq!(p.evaluate(&s).verdict, Verdict::Allow);
}

#[test]
fn subagent_escalation_is_denied() {
    let p = AgentPolicySet::from_yaml(YAML).unwrap();
    let mut s = signals();
    s.subagent_escalation = true;
    assert_eq!(p.evaluate(&s).verdict, Verdict::Deny);
}

#[test]
fn first_matching_rule_wins() {
    let p = AgentPolicySet::from_yaml(YAML).unwrap();
    let mut s = signals();
    // Matches both deny-tainted-destructive and ask-tainted-side-effect.
    s.action_class = Some(ActionClass::Destructive);
    s.taint = Some(TaintMark {
        source: Provenance::Network {
            host: "e.com".into(),
        },
        seq: 1,
    });
    assert_eq!(
        p.evaluate(&s).rule.as_deref(),
        Some("deny-tainted-destructive")
    );
}

#[test]
fn the_shipped_default_policy_parses() {
    let yaml = include_str!("../../policies/agent-default.yaml");
    let p = AgentPolicySet::from_yaml(yaml).expect("shipped policy must parse");
    assert!(!p.agent_policies.is_empty());
}

#[test]
fn a_detected_secret_over_the_network_denies_even_with_a_sensitive_path() {
    // Regression pin: deny-secret-egress must win over ask-sensitive-path-egress
    // when a single event matches both. A network send that both touches a
    // credential-shaped path AND carries a detected Critical secret finding is
    // the strongest signal the system can produce; it must never be downgraded
    // to a prompt by a weaker rule that happens to be evaluated first.
    let yaml = include_str!("../../policies/agent-default.yaml");
    let p = AgentPolicySet::from_yaml(yaml).expect("shipped policy must parse");
    let mut s = signals();
    s.action_class = Some(ActionClass::Network);
    s.touches_sensitive_path = true;
    s.findings = vec![(
        crate::facet::Facet::ToolArgs,
        Finding::new("secret.aws_key", Severity::Critical, 0.99, "AWS key"),
    )];
    let d = p.evaluate(&s);
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rule.as_deref(), Some("deny-secret-egress"));
}

#[test]
fn a_typo_d_condition_key_is_a_parse_error_not_a_silent_catch_all() {
    // Before `deny_unknown_fields`: `detecter` (typo for `detector`) parsed
    // successfully, leaving `when: {}` in effect, which matches every event of
    // the rule's action-class shape. A fat-fingered narrow rule silently became
    // a catch-all. This must now be a hard parse error with no valid policy.
    let bad_yaml = r#"
agent_policies:
  - name: typo-rule
    when: { detecter: secret, min_action_class: network }
    action: deny
default: allow
"#;
    let err = AgentPolicySet::from_yaml(bad_yaml)
        .expect_err("a typo'd condition key must fail to parse, not silently match everything");
    let msg = err.to_string();
    assert!(
        msg.contains("detecter") || msg.contains("unknown field"),
        "expected the error to name the bad field, got: {msg}"
    );
}

// The escalate action and its declared fallback.

const ESCALATE_YAML: &str = r#"
agent_policies:
  - name: escalate-tainted-side-effect
    when: { taint: [network], min_action_class: side_effecting }
    action: escalate
    fallback: allow
    message: "uses fetched content"
default: allow
"#;

#[test]
fn an_escalate_rule_parses_and_carries_its_fallback() {
    let p = AgentPolicySet::from_yaml(ESCALATE_YAML).expect("should parse");
    assert_eq!(p.agent_policies[0].action, Verdict::Escalate);
    assert_eq!(p.agent_policies[0].fallback, Some(Verdict::Allow));
}

#[test]
fn a_fallback_of_deny_is_a_parse_error() {
    // Everything in this project fails OPEN: an unreachable daemon proceeds, a
    // malformed payload proceeds, a poisoned mutex proceeds. `fallback: deny`
    // would be the one path where a MISSING optional dependency produces a hard
    // block — the tool getting more restrictive the less of it you have
    // installed. That inverts the failure posture, so reject it at parse time
    // rather than leave it as a footgun. A rule confident enough to deny should
    // say `action: deny`.
    let yaml = "agent_policies:\n  - name: r\n    when: { taint: [network] }\n    action: escalate\n    fallback: deny\ndefault: allow\n";
    let err = AgentPolicySet::from_yaml(yaml).unwrap_err().to_string();
    assert!(
        err.contains("deny"),
        "the error should explain why deny is not a valid fallback, got: {err}"
    );
}

#[test]
fn an_escalate_rule_without_a_fallback_is_a_parse_error() {
    // The judge is OFF by default, so the fallback path is the NORMAL path.
    // A security tool must not have a hidden default for "the thing I depend
    // on is absent".
    let yaml = "agent_policies:\n  - name: r\n    when: { taint: [network] }\n    action: escalate\ndefault: allow\n";
    let err = AgentPolicySet::from_yaml(yaml).unwrap_err().to_string();
    assert!(
        err.contains("fallback"),
        "error should name the missing field, got: {err}"
    );
}

#[test]
fn a_fallback_on_a_non_escalate_rule_is_a_parse_error() {
    // Silently ignoring it would let an operator believe a deny had a fallback.
    let yaml = "agent_policies:\n  - name: r\n    when: { taint: [network] }\n    action: deny\n    fallback: allow\ndefault: allow\n";
    let err = AgentPolicySet::from_yaml(yaml).unwrap_err().to_string();
    assert!(err.contains("fallback"), "got: {err}");
}

#[test]
fn escalate_is_not_a_valid_fallback() {
    // A fallback that escalates again would loop.
    let yaml = "agent_policies:\n  - name: r\n    when: { taint: [network] }\n    action: escalate\n    fallback: escalate\ndefault: allow\n";
    assert!(AgentPolicySet::from_yaml(yaml).is_err());
}

#[test]
fn escalate_is_not_a_valid_policy_default() {
    // There is no rule to take a fallback from, so this cannot be resolved.
    let yaml = "agent_policies: []\ndefault: escalate\n";
    assert!(AgentPolicySet::from_yaml(yaml).is_err());
}

#[test]
fn evaluate_returns_the_fallback_alongside_an_escalate_verdict() {
    let p = AgentPolicySet::from_yaml(ESCALATE_YAML).unwrap();
    let mut s = signals();
    s.action_class = Some(ActionClass::SideEffecting);
    s.taint = Some(TaintMark {
        source: Provenance::Network {
            host: "e.com".into(),
        },
        seq: 1,
    });
    let d = p.evaluate(&s);
    assert_eq!(d.verdict, Verdict::Escalate);
    assert_eq!(d.fallback, Some(Verdict::Allow));
    assert_eq!(d.rule.as_deref(), Some("escalate-tainted-side-effect"));
}

#[test]
fn a_non_escalate_decision_carries_no_fallback() {
    let p = AgentPolicySet::from_yaml(YAML).unwrap();
    let mut s = signals();
    s.subagent_escalation = true;
    let d = p.evaluate(&s);
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.fallback, None);
}

#[test]
fn the_shipped_default_policy_still_parses_with_escalate_support() {
    let yaml = include_str!("../../policies/agent-default.yaml");
    AgentPolicySet::from_yaml(yaml).expect("shipped policy must parse");
}

#[test]
fn a_manifest_drift_rule_matches_only_when_the_signal_is_set() {
    let yaml = "agent_policies:\n  - name: ask-manifest-drift\n    when: { mcp_manifest_changed: true }\n    action: ask\ndefault: allow\n";
    let p = AgentPolicySet::from_yaml(yaml).unwrap();

    let mut s = Signals::default();
    assert_eq!(
        p.evaluate(&s).verdict,
        Verdict::Allow,
        "no drift -> default"
    );

    s.mcp_manifest_changed = true;
    assert_eq!(p.evaluate(&s).verdict, Verdict::Ask, "drift -> ask");
}

#[test]
fn a_tool_shadow_rule_matches_only_when_the_signal_is_set() {
    let yaml = "agent_policies:\n  - name: ask-tool-shadow\n    when: { mcp_tool_shadow: true }\n    action: ask\ndefault: allow\n";
    let p = AgentPolicySet::from_yaml(yaml).unwrap();

    let mut s = Signals::default();
    assert_eq!(p.evaluate(&s).verdict, Verdict::Allow);
    s.mcp_tool_shadow = true;
    assert_eq!(p.evaluate(&s).verdict, Verdict::Ask);
}

#[test]
fn a_typo_in_an_mcp_condition_is_still_a_parse_error() {
    // deny_unknown_fields must keep protecting the new keys too.
    let yaml = "agent_policies:\n  - name: r\n    when: { mcp_manifest_changd: true }\n    action: ask\ndefault: allow\n";
    assert!(AgentPolicySet::from_yaml(yaml).is_err());
}
