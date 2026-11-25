// SPDX-License-Identifier: Apache-2.0
//! What the hook endpoint answers, and what it audits, for requests it settles
//! before policy inspection: unreadable bodies, unparsable payloads, malformed
//! tool calls, missing sessions, unknown events and unsupported identities.
//!
//! Enforce mode must deny a protected `PreToolUse` it cannot inspect. Shadow
//! mode, and events that are not a `PreToolUse`, never receive a decision.

use std::sync::{Arc, Mutex};

use agentfw::audit::AuditSink;
use agentfw::handlers::{AppState, Sessions};
use agentfw::{app, Config};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use soup_wall_agent::AgentFirewall;
use tower::ServiceExt;

const TOKEN: &str = "test-token-abcdefghijklmnopqrstuvwxyz012345";

struct Daemon {
    dir: tempfile::TempDir,
    state: agentfw::Shared,
}

impl Daemon {
    fn new(config: Config) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(AppState {
            native: None,
            firewall: Mutex::new(AgentFirewall::with_default_policy()),
            sessions: Sessions::default(),
            audit: AuditSink::open(&dir.path().join("audit.jsonl")).unwrap(),
            spans: agentfw::spans::SpanCache::new(64, 4096),
            judge: agentfw::judge::Judge::new(Default::default()),
            manifests: agentfw::mcp::store::ManifestStore::new(&dir.path().join("manifests")),
            tools: agentfw::mcp::store::ToolRegistry::with_builtins(),
            grants: agentfw::grant::GrantStore::new(&dir.path().join("grants")),
            grant_ledger: agentfw::grant::GrantLedger::open(&dir.path().join("grants-spent.json")),
            grant_key: agentfw::grant::derive_key(TOKEN),
            config,
            token: TOKEN.into(),
        });
        Self { dir, state }
    }

    fn enforcing() -> Self {
        Self::new(Config {
            enforce: true,
            ..Config::default()
        })
    }

    fn shadow() -> Self {
        Self::new(Config {
            enforce: false,
            ..Config::default()
        })
    }

    async fn hook(&self, body: impl Into<Vec<u8>>) -> Value {
        let request = Request::builder()
            .method("POST")
            .uri("/hook")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::from(body.into()))
            .unwrap();
        let response = app(self.state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn denied_with(reply: &Value, reason: &str) {
    let output = &reply["hookSpecificOutput"];
    assert_eq!(output["hookEventName"], "PreToolUse", "reply: {reply}");
    assert_eq!(output["permissionDecision"], "deny", "reply: {reply}");
    assert_eq!(output["permissionDecisionReason"], reason, "reply: {reply}");
}

fn undecided(reply: &Value) {
    assert_eq!(reply, &json!({}));
}

fn bash(session: &str, command: &str) -> String {
    json!({"session_id": session, "hook_event_name": "PreToolUse",
           "tool_name": "Bash", "tool_input": {"command": command}})
    .to_string()
}

#[tokio::test]
async fn a_body_over_the_cap_is_denied_when_enforcing_and_passed_in_shadow_mode() {
    let oversized = bash("s", &"x".repeat(4096));
    let capped = |enforce| Config {
        enforce,
        max_body_bytes: 1024,
        ..Config::default()
    };

    let enforcing = Daemon::new(capped(true));
    denied_with(
        &enforcing.hook(oversized.clone()).await,
        "hook body exceeds configured max_body_bytes",
    );
    assert!(enforcing.audit().is_empty());

    let shadow = Daemon::new(capped(false));
    undecided(&shadow.hook(oversized).await);
}

#[tokio::test]
async fn a_body_that_is_not_utf8_is_denied_when_enforcing() {
    let mut body = bash("s", "ls").into_bytes();
    body.push(0xff);

    let enforcing = Daemon::enforcing();
    denied_with(
        &enforcing.hook(body.clone()).await,
        "invalid UTF-8 in hook body; refused by policy",
    );

    undecided(&Daemon::shadow().hook(body).await);
}

#[tokio::test]
async fn an_unparsable_payload_is_denied_only_when_it_may_be_a_protected_pre_tool_use() {
    // `session_id` has the wrong type, so the payload does not deserialize.
    let unparsable = |event: &str, tool: &str| {
        json!({"session_id": 5, "hook_event_name": event,
               "tool_name": tool, "tool_input": {"command": "ls"}})
        .to_string()
    };

    let enforcing = Daemon::enforcing();
    denied_with(
        &enforcing.hook(unparsable("PreToolUse", "Bash")).await,
        "unparsable hook payload; refused by policy",
    );
    undecided(&enforcing.hook(unparsable("PostToolUse", "Bash")).await);
    assert!(enforcing.audit().is_empty());

    undecided(
        &Daemon::shadow()
            .hook(unparsable("PreToolUse", "Bash"))
            .await,
    );
}

#[tokio::test]
async fn a_malformed_pre_tool_use_is_denied_and_audited_without_its_body() {
    let no_command = json!({"session_id": "s", "hook_event_name": "PreToolUse",
                            "tool_name": "Bash", "tool_input": {"note": "MARKER"}})
    .to_string();
    let no_tool = json!({"session_id": "s", "hook_event_name": "PreToolUse",
                         "tool_input": {"command": "ls"}})
    .to_string();

    let enforcing = Daemon::enforcing();
    for body in [&no_command, &no_tool] {
        denied_with(
            &enforcing.hook(body.clone()).await,
            "unsupported PreToolUse shape; refused by policy",
        );
    }
    let audit = enforcing.audit();
    assert_eq!(audit.len(), 2);
    for line in &audit {
        assert_eq!(line["verdict"], "deny");
        assert_eq!(line["rule"], "unsupported-pre-tool-use-shape");
        assert_eq!(line["shadow"], false);
        assert_eq!(line["event"], "pre_tool_use");
        assert_eq!(line["session"], "s");
        assert_eq!(line["seq"], 0);
        assert!(line.get("raw").is_none());
    }
    assert_eq!(audit[0]["tool"], "Bash");
    assert!(audit[1].get("tool").is_none());

    let shadow = Daemon::shadow();
    undecided(&shadow.hook(no_command.clone()).await);
    assert!(shadow.audit().is_empty());

    let capturing = Daemon::new(Config {
        enforce: true,
        capture_unknown_raw: true,
        ..Config::default()
    });
    capturing.hook(no_command).await;
    assert!(capturing.audit()[0]["raw"]
        .as_str()
        .unwrap()
        .contains("MARKER"));
}

#[tokio::test]
async fn a_protected_pre_tool_use_without_a_session_is_denied_and_audited() {
    let enforcing = Daemon::enforcing();
    denied_with(
        &enforcing.hook(bash("", "ls")).await,
        "protected PreToolUse missing valid session_id",
    );
    let audit = enforcing.audit();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["verdict"], "deny");
    assert_eq!(audit[0]["rule"], "invalid-session");
    assert_eq!(audit[0]["session"], "");
    assert_eq!(audit[0]["shadow"], false);
    assert_eq!(audit[0]["seq"], 0);

    // A read-only tool is not protected: no decision and no audit line.
    let read = json!({"session_id": "", "hook_event_name": "PreToolUse",
                      "tool_name": "Read", "tool_input": {"file_path": "/tmp/a"}})
    .to_string();
    undecided(&enforcing.hook(read).await);
    assert_eq!(enforcing.audit().len(), 1);

    let shadow = Daemon::shadow();
    undecided(&shadow.hook(bash("", "ls")).await);
    assert!(shadow.audit().is_empty());
}

#[tokio::test]
async fn an_unknown_event_is_passed_and_audited_as_allowed() {
    let body = json!({"session_id": "s", "hook_event_name": "SomeFutureEvent"}).to_string();

    let enforcing = Daemon::enforcing();
    undecided(&enforcing.hook(body.clone()).await);
    let audit = enforcing.audit();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["verdict"], "allow");
    assert_eq!(audit[0]["event"], "unknown");
    assert_eq!(audit[0]["shadow"], false);
    assert_eq!(audit[0]["seq"], 1);
    assert!(audit[0].get("rule").is_none());

    let shadow = Daemon::shadow();
    undecided(&shadow.hook(body).await);
    assert_eq!(shadow.audit()[0]["shadow"], true);
}

#[tokio::test]
async fn a_claimed_agent_identity_is_refused_without_native_admission() {
    let claim = |event: &str| {
        json!({"session_id": "s", "hook_event_name": event, "agent_id": "child",
               "tool_name": "Bash", "tool_input": {"command": "ls"}})
        .to_string()
    };

    let enforcing = Daemon::enforcing();
    denied_with(
        &enforcing.hook(claim("PreToolUse")).await,
        "native_hook_identity_unsupported",
    );
    undecided(&enforcing.hook(claim("PostToolUse")).await);
    let audit = enforcing.audit();
    assert_eq!(audit.len(), 2);
    for line in &audit {
        assert_eq!(line["verdict"], "deny");
        assert_eq!(line["rule"], "native_hook_identity_unsupported");
        assert_eq!(line["shadow"], false);
        assert_eq!(line["agent_id"], "child");
        assert_eq!(line["seq"], 0);
    }
    assert_eq!(audit[0]["event"], "pre_tool_use");
    assert_eq!(audit[1]["event"], "post_tool_use");

    let shadow = Daemon::shadow();
    undecided(&shadow.hook(claim("PreToolUse")).await);
    let audit = shadow.audit();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["verdict"], "deny");
    assert_eq!(audit[0]["shadow"], true);
}
