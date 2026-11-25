// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Flat, first-match YAML policy over agent signals. Mirrors `core::policy` in shape
//! so operators only learn one format.

use serde::{Deserialize, Serialize};
use soup_wall_core::{Finding, Severity};
use std::sync::OnceLock;

use crate::action::ActionClass;
use crate::egress::is_allowed;
use crate::event::Provenance;
use crate::facet::Facet;
use crate::taint::TaintMark;

/// What to do about an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    /// Pause and put the decision to the human.
    Ask,
    Deny,
    /// The rule is not confident. Ask the optional local judge; if none is
    /// available, apply the rule's declared `fallback`. Never appears in a final
    /// decision handed to a collector — it is always resolved first.
    Escalate,
}

/// Which untrusted source classes a rule cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TaintSource {
    Network,
    Mcp,
    Subagent,
    Native,
}

impl TaintSource {
    fn matches(self, p: &Provenance) -> bool {
        matches!(
            (self, p),
            (TaintSource::Network, Provenance::Network { .. })
                | (TaintSource::Mcp, Provenance::McpServer { .. })
                | (TaintSource::Subagent, Provenance::Subagent { .. })
                | (TaintSource::Native, Provenance::Native { .. })
        )
    }
}

/// Everything the engine derived about one event. All fields optional; a rule matches
/// only if every condition it states holds.
#[derive(Debug, Clone, Default)]
pub struct Signals {
    pub action_class: Option<ActionClass>,
    pub taint: Option<TaintMark>,
    /// Retained provenance was lost; no source attribution is implied.
    pub provenance_incomplete: bool,
    pub findings: Vec<(Facet, Finding)>,
    pub risk_score: u8,
    pub egress_hosts: Vec<String>,
    pub subagent_escalation: bool,
    /// The call touches a credential-shaped path. Never dangerous alone.
    pub touches_sensitive_path: bool,
    /// The MCP server's tool manifest changed vs. its stored pin (rug-pull).
    pub mcp_manifest_changed: bool,
    /// A tool name in this handshake collides with another server's or a builtin.
    pub mcp_tool_shadow: bool,
}

/// All present sub-conditions are ANDed. Absent fields are ignored.
///
/// `deny_unknown_fields`: a typo'd condition key (`detecter` for `detector`) must be a
/// parse error, not a silently-ignored field. Silently ignoring it would leave `when: {}`
/// in effect, which matches every event of the rule's shape — a fat-fingered narrow rule
/// becomes a catch-all, and if its action is `allow` it disables every rule below it. A
/// security policy failing open on a typo, with no diagnostic, is worse than a hard error.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCondition {
    #[serde(default)]
    pub taint: Option<Vec<TaintSource>>,
    /// Exact action class.
    #[serde(default)]
    pub action_class: Option<ActionClass>,
    /// Action class at or above this severity.
    #[serde(default)]
    pub min_action_class: Option<ActionClass>,
    #[serde(default)]
    pub detector: Option<String>,
    #[serde(default)]
    pub facet: Option<Facet>,
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default)]
    pub risk_score_gte: Option<u8>,
    #[serde(default)]
    pub egress_not_allowlisted: Option<bool>,
    #[serde(default)]
    pub subagent_escalation: Option<bool>,
    /// True when the call touches a path that commonly holds credentials. Reported
    /// separately from `action_class` because reading such a file is ordinary — use
    /// it only in combination with taint or egress, never alone.
    #[serde(default)]
    pub touches_sensitive_path: Option<bool>,
    #[serde(default)]
    pub mcp_manifest_changed: Option<bool>,
    #[serde(default)]
    pub mcp_tool_shadow: Option<bool>,
}

/// Wire form of a rule, before validation. Only `AgentRule` is used elsewhere.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentRule {
    name: String,
    when: AgentCondition,
    action: Verdict,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    fallback: Option<Verdict>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(try_from = "RawAgentRule")]
pub struct AgentRule {
    pub name: String,
    pub when: AgentCondition,
    pub action: Verdict,
    pub message: Option<String>,
    /// Verdict to apply when `action` is `Escalate` and no judge is available.
    /// Required for `Escalate`, forbidden otherwise — enforced at parse time.
    pub fallback: Option<Verdict>,
}

impl TryFrom<RawAgentRule> for AgentRule {
    type Error = String;

    fn try_from(r: RawAgentRule) -> Result<Self, Self::Error> {
        match (r.action, r.fallback) {
            (Verdict::Escalate, None) => {
                return Err(format!(
                    "rule {:?}: action 'escalate' requires a 'fallback' of allow or ask. \
                     The judge is optional and off by default, so the fallback is the \
                     normal path and must be stated explicitly.",
                    r.name
                ))
            }
            (Verdict::Escalate, Some(Verdict::Escalate)) => {
                return Err(format!(
                    "rule {:?}: 'fallback' cannot be 'escalate'",
                    r.name
                ))
            }
            (Verdict::Escalate, Some(Verdict::Deny)) => {
                // Permitted but pointless: a rule confident enough to deny should
                // just deny. Rejected to keep intent unambiguous.
                return Err(format!(
                    "rule {:?}: 'fallback' of 'deny' is not allowed — a rule confident \
                     enough to deny should use 'action: deny' directly",
                    r.name
                ));
            }
            (Verdict::Escalate, Some(Verdict::Allow | Verdict::Ask)) => {}
            (_, Some(_)) => {
                return Err(format!(
                    "rule {:?}: 'fallback' is only valid with 'action: escalate'",
                    r.name
                ))
            }
            _ => {}
        }
        Ok(AgentRule {
            name: r.name,
            when: r.when,
            action: r.action,
            message: r.message,
            fallback: r.fallback,
        })
    }
}

fn default_verdict() -> Verdict {
    Verdict::Allow
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicySet {
    #[serde(default)]
    pub agent_policies: Vec<AgentRule>,
    #[serde(default)]
    pub egress_allowlist: Vec<String>,
    #[serde(default = "default_verdict")]
    pub default: Verdict,
}

/// The outcome for one event.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentDecision {
    pub verdict: Verdict,
    pub rule: Option<String>,
    pub message: Option<String>,
    /// Set only when `verdict` is `Escalate`.
    pub fallback: Option<Verdict>,
}

/// Trace captured by the same first-match/floor evaluation that returns the verdict.
/// Rule ordinals refer to the supplied operator policy or the shipped floor policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyTrace {
    pub operator_rule: Option<usize>,
    pub operator_verdict: Verdict,
    pub operator_fallback: Option<Verdict>,
    pub applied_floor: Option<SafetyFloor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SafetyFloor {
    ShippedDeny { rule: usize },
    IncompleteProvenance,
}

impl AgentPolicySet {
    pub fn from_yaml(s: &str) -> Result<Self, serde_yaml::Error> {
        use serde::de::Error as _;
        let p: AgentPolicySet = serde_yaml::from_str(s)?;
        if p.default == Verdict::Escalate {
            // Produce a real serde error rather than a panic or a silent fix.
            return Err(serde_yaml::Error::custom(
                "policy 'default' cannot be 'escalate': there is no rule to take a fallback from",
            ));
        }
        Ok(p)
    }

    /// First matching operator rule/default, then mandatory safety floors.
    pub fn evaluate(&self, s: &Signals) -> AgentDecision {
        self.evaluate_with_trace(s).0
    }

    /// Additive observation of the actual evaluator, not a second rule match.
    pub fn evaluate_with_trace(&self, s: &Signals) -> (AgentDecision, PolicyTrace) {
        let (decision, operator_rule) = self.evaluate_rules(s);
        let mut trace = PolicyTrace {
            operator_rule,
            operator_verdict: decision.verdict,
            operator_fallback: decision.fallback,
            applied_floor: None,
        };
        if decision.verdict == Verdict::Deny {
            return (decision, trace);
        }
        // Reuse the shipped hard-refusal predicates rather than duplicating them.
        // Operator ordering remains first-match within its configurable layer.
        static SHIPPED: OnceLock<AgentPolicySet> = OnceLock::new();
        let shipped = SHIPPED.get_or_init(|| {
            Self::from_yaml(include_str!("../policies/agent-default.yaml"))
                .expect("shipped policy must parse")
        });
        for (index, rule) in shipped.agent_policies.iter().enumerate() {
            if rule.action == Verdict::Deny && self.matches(&rule.when, s) {
                trace.applied_floor = Some(SafetyFloor::ShippedDeny { rule: index });
                return (
                    AgentDecision {
                        verdict: Verdict::Deny,
                        rule: Some(rule.name.clone()),
                        message: rule.message.clone(),
                        fallback: None,
                    },
                    trace,
                );
            }
        }
        let protected = s
            .action_class
            .is_some_and(|a| a >= ActionClass::SideEffecting || s.touches_sensitive_path);
        if s.provenance_incomplete
            && protected
            && matches!(decision.verdict, Verdict::Allow | Verdict::Escalate)
        {
            trace.applied_floor = Some(SafetyFloor::IncompleteProvenance);
            return (AgentDecision {
                verdict: Verdict::Ask,
                rule: Some("taint-history-incomplete".into()),
                message: Some("Session provenance was discarded; review this action or start a fresh context.".into()),
                fallback: None,
            }, trace);
        }
        (decision, trace)
    }

    /// Eligibility gate for the opt-in formatter correction only. This does not
    /// alter the ordinary first-match evaluator. A hidden independent restrictive
    /// predicate is still evidence that the raw refusal was not formatter-only.
    pub(crate) fn formatter_only_denial(
        &self,
        trace: &PolicyTrace,
        original: &Signals,
        corrected: &Signals,
    ) -> bool {
        if self.default != Verdict::Allow
            || trace.applied_floor.is_some()
            || !trace
                .operator_rule
                .and_then(|index| self.agent_policies.get(index))
                .is_some_and(Self::formatter_deny_condition)
        {
            return false;
        }
        if self.agent_policies.iter().any(|rule| {
            if rule.action == Verdict::Allow {
                return false;
            }
            let before = self.matches(&rule.when, original);
            let after = self.matches(&rule.when, corrected);
            // Discharge only a formatter-specific predicate that actually
            // stopped matching. A hidden Low Deny that still matches stays.
            if after {
                return true;
            }
            before && !Self::formatter_deny_condition(rule)
        }) {
            return false;
        }
        let floors = Self {
            agent_policies: Vec::new(),
            egress_allowlist: self.egress_allowlist.clone(),
            default: Verdict::Allow,
        };
        floors
            .evaluate_with_trace(original)
            .1
            .applied_floor
            .is_none()
            && floors
                .evaluate_with_trace(corrected)
                .1
                .applied_floor
                .is_none()
    }

    fn formatter_deny_condition(rule: &AgentRule) -> bool {
        rule.action == Verdict::Deny
            && rule.when.detector.as_deref() == Some("injection")
            && rule.when.facet == Some(Facet::ToolResult)
            && serde_json::to_value(&rule.when)
                .ok()
                .and_then(|value| value.as_object().cloned())
                .is_some_and(|fields| {
                    fields.iter().all(|(key, value)| {
                        value.is_null()
                            || matches!(key.as_str(), "detector" | "facet" | "min_severity")
                    })
                })
    }

    fn evaluate_rules(&self, s: &Signals) -> (AgentDecision, Option<usize>) {
        for (index, rule) in self.agent_policies.iter().enumerate() {
            if self.matches(&rule.when, s) {
                return (
                    AgentDecision {
                        verdict: rule.action,
                        rule: Some(rule.name.clone()),
                        message: rule.message.clone(),
                        fallback: rule.fallback,
                    },
                    Some(index),
                );
            }
        }
        (
            AgentDecision {
                verdict: self.default,
                rule: None,
                message: None,
                fallback: None,
            },
            None,
        )
    }

    fn matches(&self, c: &AgentCondition, s: &Signals) -> bool {
        if let Some(sources) = &c.taint {
            match &s.taint {
                None => return false,
                Some(mark) => {
                    if !sources.iter().any(|t| t.matches(&mark.source)) {
                        return false;
                    }
                }
            }
        }
        if let Some(exact) = c.action_class {
            if s.action_class != Some(exact) {
                return false;
            }
        }
        if let Some(min) = c.min_action_class {
            match s.action_class {
                Some(a) if a >= min => {}
                _ => return false,
            }
        }
        if let Some(min) = c.risk_score_gte {
            if s.risk_score < min {
                return false;
            }
        }
        if c.detector.is_some() || c.min_severity.is_some() || c.facet.is_some() {
            let any = s.findings.iter().any(|(facet, f)| {
                let facet_ok = c.facet.is_none_or(|want| want == *facet);
                // Segment-bounded prefix, matching core's scheme: "secret" matches
                // "secret" and "secret.aws_key" but not "secretsauce".
                let det_ok = c
                    .detector
                    .as_ref()
                    .is_none_or(|d| f.detector == *d || f.detector.starts_with(&format!("{d}.")));
                let sev_ok = c.min_severity.is_none_or(|m| f.severity >= m);
                facet_ok && det_ok && sev_ok
            });
            if !any {
                return false;
            }
        }
        if let Some(want_unlisted) = c.egress_not_allowlisted {
            let any_unlisted = s
                .egress_hosts
                .iter()
                .any(|h| !is_allowed(h, &self.egress_allowlist));
            // A positive assertion that destinations are allowlisted requires
            // actual evidence; an empty list cannot match that assertion.
            if any_unlisted != want_unlisted || (!want_unlisted && s.egress_hosts.is_empty()) {
                return false;
            }
        }
        if let Some(want) = c.subagent_escalation {
            if s.subagent_escalation != want {
                return false;
            }
        }
        if let Some(want) = c.touches_sensitive_path {
            if s.touches_sensitive_path != want {
                return false;
            }
        }
        if let Some(want) = c.mcp_manifest_changed {
            if s.mcp_manifest_changed != want {
                return false;
            }
        }
        if let Some(want) = c.mcp_tool_shadow {
            if s.mcp_tool_shadow != want {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests;
