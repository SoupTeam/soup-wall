// SPDX-License-Identifier: Apache-2.0
//! PR #92: final decisions and child grants must agree before continuation.
use soup_wall_agent::{AgentEvent, AgentFirewall, AgentPolicySet, Verdict};

fn event(kind: serde_json::Value) -> AgentEvent {
    let mut value = serde_json::json!({
        "session": "s", "agent": "main", "parent": null, "seq": 1, "at_ms": 1
    });
    value
        .as_object_mut()
        .unwrap()
        .extend(kind.as_object().unwrap().clone());
    serde_json::from_value(value).unwrap()
}

fn spawn() -> AgentEvent {
    event(serde_json::json!({"kind":"subagent_spawn", "name":"worker",
        "instructions":"Review documentation", "granted_tools":["Read"]}))
}

fn read() -> AgentEvent {
    let mut ev = event(serde_json::json!({"kind":"tool_call", "tool":"Read",
        "args":{"path":"README.md"}}));
    ev.agent = "worker".into();
    ev.parent = Some("main".into());
    ev.seq = 2;
    ev
}

fn firewall(action: &str, fallback: &str) -> AgentFirewall {
    let yaml = format!(
        "agent_policies:\n  - name: spawn-policy\n    when: {{}}\n    action: {action}\n{fallback}default: allow\n"
    );
    let mut fw = AgentFirewall::new(AgentPolicySet::from_yaml(&yaml).unwrap(), 100);
    fw.set_root("s", "main", &["Read".into()]);
    fw
}

#[test]
fn documentation_and_unavailable_allow_commit_before_the_child_read() {
    // Both replies map to no injection; production resolution applies fallback.
    for _reply in ["documentation", "unavailable", "invalid", "timeout"] {
        let mut fw = firewall("escalate", "    fallback: allow\n");
        let out = fw.inspect_resolved(&spawn(), |initial| {
            assert_eq!(initial.verdict, Verdict::Escalate);
            assert!(initial.authority_pending);
            false
        });
        assert_eq!(out.verdict, Verdict::Allow);
        assert!(!out.authority_pending);
        assert_eq!(
            out.adapter_response("test").verdict,
            soup_wall_adapter::Verdict::Allow
        );
        assert_eq!(
            fw.inspect_resolved(&read(), |_| false).verdict,
            Verdict::Allow
        );
    }
}

#[test]
fn direct_allow_is_a_passing_control_and_does_not_call_the_judge() {
    let mut fw = firewall("allow", "");
    assert_eq!(
        fw.inspect_resolved(&spawn(), |_| panic!("unexpected judge"))
            .verdict,
        Verdict::Allow
    );
    assert_eq!(fw.inspect(&read()).verdict, Verdict::Allow);
}

#[test]
fn injection_and_ask_fallback_create_no_child_grant() {
    for (fallback, injection) in [("allow", true), ("ask", false), ("ask", true)] {
        let mut fw = firewall("escalate", &format!("    fallback: {fallback}\n"));
        assert_eq!(
            fw.inspect_resolved(&spawn(), |_| injection).verdict,
            Verdict::Ask
        );
        assert_eq!(fw.inspect(&read()).verdict, Verdict::Deny);
    }
}

#[test]
fn concrete_ask_and_deny_create_no_grant() {
    for action in ["ask", "deny"] {
        let mut fw = firewall(action, "");
        let out = fw.inspect_resolved(&spawn(), |_| panic!("unexpected judge"));
        assert!(matches!(out.verdict, Verdict::Ask | Verdict::Deny));
        assert_eq!(fw.inspect(&read()).verdict, Verdict::Deny);
    }
}

#[test]
fn unresolved_projection_does_not_claim_a_committed_allow() {
    let mut fw = firewall("escalate", "    fallback: allow\n");
    let mut out = fw.inspect(&spawn());
    assert_eq!(out.verdict, Verdict::Escalate);
    assert_eq!(
        out.adapter_response("test").verdict,
        soup_wall_adapter::Verdict::Ask
    );
    // A standalone verdict resolver cannot commit this firewall's authority.
    out.verdict = soup_wall_agent::resolution::resolve(out.verdict, out.fallback, false);
    assert_eq!(
        out.adapter_response("test").verdict,
        soup_wall_adapter::Verdict::Ask
    );
    assert_eq!(fw.inspect(&read()).verdict, Verdict::Deny);
}

#[test]
fn parent_revocation_after_an_unresolved_inspection_is_rechecked() {
    let mut fw = firewall("escalate", "    fallback: allow\n");
    let old = fw.inspect(&spawn());
    fw.set_root("s", "main", &[]);
    let out = fw.inspect_resolved(&spawn(), |_| panic!("hard denial bypasses judge"));
    assert_eq!(out.verdict, Verdict::Deny);
    assert_eq!(
        old.adapter_response("test").verdict,
        soup_wall_adapter::Verdict::Ask
    );
    assert_eq!(fw.inspect(&read()).verdict, Verdict::Deny);
}

#[test]
fn finalization_is_bound_to_the_exact_child_and_requested_tools() {
    let mut fw = firewall("escalate", "    fallback: allow\n");
    assert_eq!(
        fw.inspect_resolved(&spawn(), |_| false).verdict,
        Verdict::Allow
    );
    let mut other = read();
    other.agent = "other-child".into();
    assert_eq!(fw.inspect(&other).verdict, Verdict::Deny);
    let mut extra = read();
    if let soup_wall_agent::EventKind::ToolCall { tool, .. } = &mut extra.kind {
        *tool = "Write".into();
    }
    assert_eq!(fw.inspect(&extra).verdict, Verdict::Deny);
    assert_eq!(
        fw.inspect_resolved(&read(), |_| false).verdict,
        Verdict::Allow
    );
}

#[test]
fn peer_session_and_session_end_cannot_reuse_committed_grants() {
    let mut fw = firewall("escalate", "    fallback: allow\n");
    fw.inspect_resolved(&spawn(), |_| false);
    let mut peer = read();
    peer.session = "peer".into();
    assert_eq!(fw.inspect(&peer).verdict, Verdict::Deny);
    fw.inspect(&event(serde_json::json!({"kind":"session_end"})));
    assert_eq!(
        fw.inspect_resolved(&spawn(), |_| panic!("parent grant ended"))
            .verdict,
        Verdict::Deny
    );
    assert_eq!(fw.inspect(&read()).verdict, Verdict::Deny);
}
