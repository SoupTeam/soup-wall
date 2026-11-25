// SPDX-License-Identifier: Apache-2.0
use super::super::{inspect, parse, NativeState, Response};
use super::*;
use crate::{
    audit::AuditSink,
    handlers::{AppState, Sessions as HookSessions},
    Config,
};
use soup_wall_agent::{AgentFirewall, AgentPolicySet, DEFAULT_TAINT_CAP};
use std::sync::Arc;

const HOOK: &str = "hook-unit-key";

#[test]
fn edit_diagnostics_include_resource_ask_without_mutating_or_reading_authority() {
    let home = tempfile::tempdir().unwrap();
    let approval = ApprovalState::new(home.path(), b"private-key-canary", 120).unwrap();
    let make = |session: &str, epoch: &str, state: State| Record {
        session_id: session.into(),
        epoch: epoch.into(),
        tool: "create_output_0".into(),
        schema_sha256: "a".repeat(64),
        binding_sha256: "b".repeat(64),
        args_sha256: "c".repeat(64),
        expires_at_ms: now_ms() + 120_000,
        source: Source::Classifier,
        policy_epoch: 0,
        selected: false,
        expires: Instant::now() + Duration::from_secs(120),
        state,
    };
    {
        let mut rows = approval.records.lock().unwrap();
        rows.insert("pending".into(), make("edit", "epoch", State::Pending));
        rows.insert(
            "rejected".into(),
            make("edit", "epoch", State::Closed("rejected")),
        );
        rows.insert("foreign".into(), make("foreign", "epoch", State::Pending));
        rows.insert("stale".into(), make("edit", "stale", State::Pending));
    }
    // An attacker-controlled authority marker must never be followed by
    // a diagnostic query. Its observation cannot mutate the in-memory Ask.
    let marker = pending_dir(home.path()).join("pending.rejected");
    std::fs::write(&marker, "raw-arguments-secret-canary").unwrap();
    let inspect = || {
        approval
            .edit_bindings(|session, epoch, tool| {
                session == "edit" && epoch == "epoch" && tool == "create_output_0"
            })
            .unwrap()
    };
    let first = inspect();
    assert_eq!(first, inspect());
    assert_eq!(first.0.len(), 1);
    assert_eq!(first.1.len(), 1);
    assert_eq!(first.0[0]["state"], "pending");
    assert_eq!(first.1[0]["state"], "rejected");
    assert!(approval.operator_bindings().unwrap().is_empty());
    let observed = serde_json::to_string(&first).unwrap();
    for canary in [
        "private-key-canary",
        "raw-arguments-secret-canary",
        "foreign",
        "stale",
    ] {
        assert!(!observed.contains(canary));
    }
    assert_eq!(
        std::fs::read_to_string(marker).unwrap(),
        "raw-arguments-secret-canary"
    );
    assert_eq!(approval.records.lock().unwrap().len(), 4);
    assert_eq!(
        approval.records.lock().unwrap()["pending"].state,
        State::Pending
    );
}

#[test]
fn edit_diagnostic_expiry_is_observed_without_closing_or_removing_records() {
    let home = tempfile::tempdir().unwrap();
    let approval = ApprovalState::new(home.path(), b"unit", 120).unwrap();
    approval.records.lock().unwrap().insert(
        "expired".into(),
        Record {
            session_id: "edit".into(),
            epoch: "epoch".into(),
            tool: "replace_output_0".into(),
            schema_sha256: "a".repeat(64),
            binding_sha256: "b".repeat(64),
            args_sha256: "c".repeat(64),
            expires_at_ms: 1,
            source: Source::Daemon,
            policy_epoch: 0,
            selected: false,
            expires: Instant::now() - Duration::from_secs(1),
            state: State::Pending,
        },
    );
    let (pending, decisions) = approval.edit_bindings(|_, _, _| true).unwrap();
    assert!(pending.is_empty());
    assert_eq!(decisions[0]["state"], "expired");
    assert_eq!(
        approval.records.lock().unwrap()["expired"].state,
        State::Pending
    );
}

#[test]
fn operator_errors_have_producer_codes_without_parsing_messages() {
    use crate::pilot_approval::result::{reason, Reason};
    let home = tempfile::tempdir().unwrap();
    let missing = read_pending(home.path(), "missing").unwrap_err();
    assert!(matches!(reason(&missing), Reason::PendingUnavailable));
    let invalid = read_pending(home.path(), "../foreign").unwrap_err();
    assert!(matches!(reason(&invalid), Reason::InvalidInput));
    std::fs::create_dir(pending_dir(home.path())).unwrap();
    let pending_id = format!("{:032x}", rand::random::<u128>());
    let path = pending_dir(home.path()).join(format!("{pending_id}.json"));
    std::fs::write(
        &path,
        json!({"pending_id":pending_id, "scope":"native-mcp/approval/v1",
        "expires_at_ms":0})
        .to_string(),
    )
    .unwrap();
    let expired = operator_approve(home.path(), HOOK, &pending_id, &"a".repeat(64)).unwrap_err();
    assert!(matches!(reason(&expired), Reason::PendingExpired));
    let missing_claim = claim(home.path(), "missing").unwrap_err();
    assert!(matches!(reason(&missing_claim), Reason::DecisionConflict));
}

#[test]
fn interrupted_submission_remains_unknown_without_changing_legacy_exit() {
    use crate::pilot_approval::result::{reason, Reason};
    for structured in [false, true] {
        let home = tempfile::tempdir().unwrap();
        let directory = pending_dir(home.path());
        std::fs::create_dir(&directory).unwrap();
        let pending_id = format!("{:032x}", rand::random::<u128>());
        std::fs::create_dir(directory.join(format!("{pending_id}.approved"))).unwrap();
        let binding = "a".repeat(64);
        std::fs::write(
            directory.join(format!("{pending_id}.json")),
            json!({"pending_id":pending_id,
            "scope":"native-mcp/approval/v1", "session_id":"owned", "session_epoch":"epoch",
            "tool":"read_text_file", "binding_sha256":binding,
            "expires_at_ms":now_ms() + 30_000})
            .to_string(),
        )
        .unwrap();
        let result = if structured {
            operator_submit_for_session(home.path(), HOOK, &pending_id, &binding, "owned", "epoch")
        } else {
            operator_approve_for_session(home.path(), HOOK, &pending_id, &binding, "owned", "epoch")
        };
        if structured {
            assert!(matches!(reason(&result.unwrap_err()), Reason::Unknown));
        } else {
            assert!(result.is_ok());
        }
        assert!(GrantStore::new(&grants_dir(home.path()))
            .pending()
            .is_empty());
    }
}

#[test]
fn structured_submission_does_not_claim_a_grant_that_expired_during_issuance() {
    use crate::pilot_approval::result::{reason, Reason};
    let home = tempfile::tempdir().unwrap();
    let directory = pending_dir(home.path());
    std::fs::create_dir(&directory).unwrap();
    let lock = std::fs::File::create(home.path().join("approval-policy-epoch.lock")).unwrap();
    lock.lock().unwrap();
    let pending_id = format!("{:032x}", rand::random::<u128>());
    let expiry = now_ms() + 500;
    let binding = "a".repeat(64);
    std::fs::write(
        directory.join(format!("{pending_id}.json")),
        json!({"pending_id":pending_id,
        "scope":"native-mcp/approval/v1", "session_id":"owned", "session_epoch":"epoch",
        "tool":"read_text_file", "binding_sha256":binding, "expires_at_ms":expiry})
        .to_string(),
    )
    .unwrap();
    let selected = home.path().to_path_buf();
    let worker_id = pending_id.clone();
    let worker = std::thread::spawn(move || {
        operator_submit_for_session(&selected, HOOK, &worker_id, &binding, "owned", "epoch")
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while !directory.join(format!("{pending_id}.deciding")).exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let claimed = directory.join(format!("{pending_id}.deciding")).exists();
    while now_ms() <= expiry {
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(lock);
    let result = worker.join().unwrap();
    assert!(
        claimed,
        "submission did not reach the controlled issuance barrier"
    );
    assert!(matches!(reason(&result.unwrap_err()), Reason::Unknown));
    assert!(GrantStore::new(&grants_dir(home.path()))
        .pending()
        .is_empty());
}
const POLICY: &str = "agent_policies:\n  - name: unit-destructive-ask\n    when: { action_class: destructive }\n    action: ask\n  - name: unit-side-effecting-ask\n    when: { action_class: side_effecting }\n    action: ask\n  - name: unit-privilege-deny\n    when: { action_class: privilege_changing }\n    action: deny\ndefault: allow\n";

struct Env {
    dir: tempfile::TempDir,
    st: Shared,
}

fn env(approval: Option<u64>) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let schema = "a".repeat(64);
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut tools = vec![
        json!({"name": "delete_note", "schema_sha256": schema, "action_class": "destructive",
         "result_provenance": "untrusted", "egress": []}),
        json!({"name": "read_note", "schema_sha256": schema, "action_class": "read_only",
         "result_provenance": "untrusted", "egress": []}),
        json!({"name": "grant_admin", "schema_sha256": schema, "action_class": "privilege_changing",
         "result_provenance": "untrusted", "egress": []}),
    ];
    #[cfg(unix)]
    {
        let create_schema =
            super::super::canonical_digest(&crate::native::resource::create_file_schema());
        let ws = dir.path().canonicalize().unwrap();
        let ws_str = ws.to_str().unwrap();
        let target_file = ws.join("test.txt").to_str().unwrap().to_string();
        tools.push(json!({"name": "create_file", "schema_sha256": create_schema, "action_class": "side_effecting",
             "result_provenance": "untrusted", "egress": [], "resource_policy": {
                 "profile": {"server_id": "test-fs", "tool_name": "create_file", "schema_sha256": create_schema, "selectors": [{"pointer": "/path", "kind": "path", "allow_missing_leaf": true}]},
                 "workspace": ws_str, "cwd": ws_str,
                 "executor_sha256": crate::native::resource::create_file_executor_sha256(),
                 "classifier_sha256": "c".repeat(64),
                 "allowed_resources": [{"kind": "path", "canonical": target_file}],
                 "execution": {
                     "operation": "create_file", "action": "write", "max_content_bytes": 4096,
                     "executor_profile": "sw-native/create-file/linux-root-child/1",
                     "path_selector": "/path", "content_selector": "/content"
                 }
             }}));
    }
    let bytes =
        json!({"contract_version": CONTRACT, "registry_id": "unit-approval", "tools": tools})
            .to_string()
            .into_bytes();
    let digest = super::super::sha256_hex(&bytes);
    let mut native = NativeState::from_bytes(&bytes, &digest, "native-unit-key".into()).unwrap();
    if let Some(ttl) = approval {
        native = native
            .with_approval(dir.path(), &grant::derive_key(HOOK), ttl)
            .unwrap();
    }
    let dirp = dir.path();
    let st = Arc::new(AppState {
        native: Some(native),
        firewall: std::sync::Mutex::new(AgentFirewall::new(
            AgentPolicySet::from_yaml(POLICY).unwrap(),
            DEFAULT_TAINT_CAP,
        )),
        sessions: HookSessions::default(),
        audit: AuditSink::open(&dirp.join("audit.jsonl")).unwrap(),
        spans: crate::spans::SpanCache::new(64, 4096),
        judge: crate::judge::Judge::new(Default::default()),
        manifests: crate::mcp::store::ManifestStore::new(&dirp.join("manifests")),
        tools: crate::mcp::store::ToolRegistry::with_builtins(),
        grants: GrantStore::new(&dirp.join("grants")),
        grant_ledger: GrantLedger::open(&dirp.join("grants-spent.json")),
        grant_key: grant::derive_key(HOOK),
        config: Config {
            enforce: true,
            ..Config::default()
        },
        token: HOOK.into(),
    });
    Env { dir, st }
}

impl Env {
    fn native(&self) -> &NativeState {
        self.st.native.as_ref().unwrap()
    }
    fn home(&self) -> &Path {
        self.dir.path()
    }
    fn start(&self, session: &str) {
        let fields = json!({"event": "session_start"});
        self.send(session, fields).unwrap();
    }
    fn send(&self, session: &str, fields: Value) -> Result<Response, &'static str> {
        let mut value = json!({"contract_version": CONTRACT,
            "registry_sha256": self.native().registry_sha256, "session_id": session});
        for (k, v) in fields.as_object().unwrap() {
            value[k] = v.clone();
        }
        inspect(&self.st, self.native(), parse(&value.to_string()).unwrap())
    }
    fn call(
        &self,
        session: &str,
        tool: &str,
        args: Value,
        approval: Option<&str>,
    ) -> Result<Response, &'static str> {
        let mut fields = json!({"event": "call", "tool": tool, "args": args,
            "schema_sha256": "a".repeat(64)});
        if let Some(id) = approval {
            fields["approval_id"] = json!(id);
        }
        self.send(session, fields)
    }
    fn open(
        &self,
        session: &str,
        tool: &str,
        args: Value,
        source: &str,
    ) -> Result<Value, &'static str> {
        let schema = self
            .native()
            .registry
            .tools
            .iter()
            .find(|t| t.name == tool)
            .map(|t| t.schema_sha256.clone())
            .unwrap_or_else(|| "a".repeat(64));
        let request = ApprovalRequest {
            contract_version: CONTRACT.into(),
            registry_sha256: self.native().registry_sha256.clone(),
            session_id: session.into(),
            action: "request".into(),
            source: Some(source.into()),
            tool: Some(tool.into()),
            args: Some(args),
            schema_sha256: Some(schema),
            pending_id: None,
            resource_admission: None,
            selected_invocation: None,
        };
        super::open(
            &self.st,
            self.native(),
            self.native()
                .approval
                .as_ref()
                .ok_or("native_approval_disabled")?,
            &request,
        )
    }
    fn state(&self, session: &str, id: &str) -> String {
        self.native()
            .approval
            .as_ref()
            .unwrap()
            .status(id, session)
            .map(|s| s.0.to_string())
            .unwrap_or_else(|e| e.to_string())
    }
    fn approve(&self, reply: &Value) {
        operator_approve(
            self.home(),
            HOOK,
            reply["pending_id"].as_str().unwrap(),
            reply["binding_sha256"].as_str().unwrap(),
        )
        .unwrap();
    }
}

fn id(reply: &Value) -> String {
    reply["pending_id"].as_str().unwrap().to_string()
}

fn codes(response: &Response) -> String {
    response.reason_codes.join(",")
}

#[test]
fn default_config_keeps_the_refusal_and_has_no_approval_route() {
    let env = env(None);
    env.start("s1");
    let refused = env
        .call("s1", "delete_note", json!({"name": "a"}), None)
        .unwrap();
    assert!(!refused.release && refused.verdict == "ask");
    assert_eq!(
        env.call("s1", "delete_note", json!({"name": "a"}), Some("anything"))
            .err(),
        Some("native_approval_disabled")
    );
    assert!(env
        .open("s1", "delete_note", json!({"name": "a"}), "daemon")
        .is_err());
}

#[test]
fn exact_approval_releases_the_original_call_exactly_once() {
    let env = env(Some(60));
    env.start("s1");
    let args = json!({"name": "inventory"});
    assert!(
        !env.call("s1", "delete_note", args.clone(), None)
            .unwrap()
            .release
    );
    let reply = env
        .open("s1", "delete_note", args.clone(), "daemon")
        .unwrap();
    let pending = id(&reply);
    assert_eq!(env.state("s1", &pending), "pending");
    // Not approved yet: presenting the id is refused and burns it.
    let early = env
        .call("s1", "delete_note", args.clone(), Some(&pending))
        .unwrap();
    assert!(!early.release, "{}", codes(&early));
    let reply = env
        .open("s1", "delete_note", args.clone(), "daemon")
        .unwrap();
    let pending = id(&reply);
    assert_eq!(operator_list(env.home()).len(), 1);
    env.approve(&reply);
    assert_eq!(env.state("s1", &pending), "approved");
    let released = env
        .call("s1", "delete_note", args.clone(), Some(&pending))
        .unwrap();
    assert!(
        released.release && released.call_id.is_some(),
        "{}",
        codes(&released)
    );
    assert_eq!(released.verdict, "allow");
    assert_eq!(env.state("s1", &pending), "redeemed");
    // Replay of the same approval never releases again.
    let replay = env.call("s1", "delete_note", args, Some(&pending)).unwrap();
    assert!(!replay.release && replay.call_id.is_none());
    assert!(operator_list(env.home()).is_empty());
}

#[test]
fn reject_and_expiry_cannot_be_rescued() {
    let env = env(Some(1));
    env.start("s1");
    let args = json!({"name": "a"});
    let reply = env
        .open("s1", "delete_note", args.clone(), "daemon")
        .unwrap();
    let pending = id(&reply);
    operator_reject(env.home(), &pending).unwrap();
    assert_eq!(env.state("s1", &pending), "rejected");
    assert!(operator_approve(
        env.home(),
        HOOK,
        &pending,
        reply["binding_sha256"].as_str().unwrap()
    )
    .is_err());
    assert!(
        !env.call("s1", "delete_note", args.clone(), Some(&pending))
            .unwrap()
            .release
    );
    let reply = env
        .open("s1", "delete_note", args.clone(), "daemon")
        .unwrap();
    env.approve(&reply);
    std::thread::sleep(Duration::from_millis(1200));
    let pending = id(&reply);
    assert_eq!(env.state("s1", &pending), "expired");
    assert!(
        !env.call("s1", "delete_note", args, Some(&pending))
            .unwrap()
            .release
    );
}

#[test]
fn changed_arguments_and_other_sessions_get_no_release() {
    let env = env(Some(60));
    env.start("s1");
    env.start("s2");
    let args = json!({"name": "inventory"});
    let reply = env
        .open("s1", "delete_note", args.clone(), "daemon")
        .unwrap();
    env.approve(&reply);
    let pending = id(&reply);
    let changed = env
        .call(
            "s1",
            "delete_note",
            json!({"name": "other"}),
            Some(&pending),
        )
        .unwrap();
    assert!(!changed.release, "{}", codes(&changed));
    // The refusal closed the approval: the original arguments are no longer rescued.
    assert!(
        !env.call("s1", "delete_note", args.clone(), Some(&pending))
            .unwrap()
            .release
    );

    let reply = env
        .open("s1", "delete_note", args.clone(), "daemon")
        .unwrap();
    env.approve(&reply);
    let pending = id(&reply);
    let other = env
        .call("s2", "delete_note", args.clone(), Some(&pending))
        .unwrap();
    assert!(!other.release, "{}", codes(&other));
    assert!(
        !env.call("s1", "delete_note", args, Some(&pending))
            .unwrap()
            .release
    );
}

#[test]
fn policy_switch_hard_deny_and_unsupported_cannot_be_rescued() {
    let env = env(Some(60));
    env.start("s1");
    let args = json!({"name": "inventory"});
    let reply = env
        .open("s1", "delete_note", args.clone(), "daemon")
        .unwrap();
    env.approve(&reply);
    env.st.grants.invalidate_all_for_policy_switch().unwrap();
    let stale = env
        .call("s1", "delete_note", args.clone(), Some(&id(&reply)))
        .unwrap();
    assert!(
        !stale.release && codes(&stale).contains("stale_policy"),
        "{}",
        codes(&stale)
    );

    assert_eq!(
        env.open("s1", "grant_admin", json!({"name": "x"}), "daemon")
            .err(),
        Some("native_approval_hard_deny")
    );
    assert_eq!(
        env.open("s1", "grant_admin", json!({"name": "x"}), "classifier")
            .err(),
        Some("native_approval_hard_deny")
    );
    assert_eq!(
        env.open("s1", "read_note", json!({"name": "x"}), "daemon")
            .err(),
        Some("native_approval_not_required")
    );
    // An approval id attached to a hard-Deny call never releases it.
    let denied = env
        .call("s1", "grant_admin", json!({"name": "x"}), Some(&id(&reply)))
        .unwrap();
    assert!(!denied.release && denied.verdict == "deny");
}

#[test]
fn concurrent_redemption_releases_exactly_one() {
    let env = Arc::new(env(Some(60)));
    env.start("s1");
    let args = json!({"name": "inventory"});
    let reply = env
        .open("s1", "delete_note", args.clone(), "daemon")
        .unwrap();
    env.approve(&reply);
    let pending = id(&reply);
    let mut threads = Vec::new();
    for _ in 0..8 {
        let (env, args, pending) = (env.clone(), args.clone(), pending.clone());
        threads.push(std::thread::spawn(move || {
            env.call("s1", "delete_note", args, Some(&pending))
                .map(|r| r.release)
                .unwrap_or(false)
        }));
    }
    let released = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .filter(|r| *r)
        .count();
    assert_eq!(released, 1);
}

#[test]
fn restart_session_end_and_second_pending_close_or_refuse() {
    let env = env(Some(60));
    env.start("s1");
    let args = json!({"name": "inventory"});
    let reply = env
        .open("s1", "delete_note", args.clone(), "daemon")
        .unwrap();
    assert_eq!(
        env.open("s1", "delete_note", args.clone(), "daemon").err(),
        Some("native_approval_already_pending")
    );
    env.approve(&reply);
    let pending = id(&reply);
    env.send("s1", json!({"event": "session_end"})).unwrap();
    assert_eq!(env.state("s1", &pending), "closed");
    assert!(operator_list(env.home()).is_empty());
    assert!(!env
        .home()
        .join("native-grants")
        .join(format!("{pending}.json"))
        .exists());

    env.start("s2");
    let reply = env.open("s2", "delete_note", args, "daemon").unwrap();
    assert_eq!(operator_list(env.home()).len(), 1);
    let restarted = ApprovalState::new(env.home(), &grant::derive_key(HOOK), 60).unwrap();
    assert!(
        operator_list(env.home()).is_empty(),
        "a restart removes pending files"
    );
    assert!(restarted.records.lock().unwrap().is_empty());
    assert!(operator_inspect(env.home(), &id(&reply)).is_err());
}

#[test]
fn hook_key_and_hook_grants_cannot_authorize_native_calls() {
    let env = env(Some(60));
    env.start("s1");
    let args = json!({"name": "inventory"});
    let reply = env
        .open("s1", "delete_note", args.clone(), "daemon")
        .unwrap();
    let pending = id(&reply);
    let epoch = env.native().sessions.lock().unwrap().entries["s1"]
        .epoch
        .clone();
    // A grant signed with the HOOK key, even with the matching scope, is not accepted.
    GrantStore::new(&grants_dir(env.home()))
        .issue(
            &grant::derive_key(HOOK),
            &ActionRef {
                session: epoch.clone(),
                tool: scope_tool("delete_note"),
                args_fingerprint: reply["binding_sha256"].as_str().unwrap().into(),
            },
            now_ms(),
            60_000,
            pending.clone(),
        )
        .unwrap();
    let forged = env
        .call("s1", "delete_note", args.clone(), Some(&pending))
        .unwrap();
    assert!(!forged.release, "{}", codes(&forged));
    // An old-style hook approval for the same tool and arguments does not release it either.
    let hook_style = ActionRef {
        session: epoch,
        tool: "delete_note".into(),
        args_fingerprint: grant::action_fingerprint("delete_note", &args),
    };
    env.st
        .grants
        .issue(
            &env.st.grant_key,
            &hook_style,
            now_ms(),
            60_000,
            crate::token::generate(),
        )
        .unwrap();
    assert!(!env.call("s1", "delete_note", args, None).unwrap().release);
}

#[test]
fn classifier_source_requires_the_same_exact_approval() {
    let env = env(Some(60));
    env.start("s1");
    let args = json!({"name": "inventory"});
    let reply = env
        .open("s1", "read_note", args.clone(), "classifier")
        .unwrap();
    // Unapproved: the daemon's own Allow does not accept an unapproved id.
    let pending = id(&reply);
    env.approve(&reply);
    let released = env
        .call("s1", "read_note", args.clone(), Some(&pending))
        .unwrap();
    assert!(released.release, "{}", codes(&released));
    let again = env.call("s1", "read_note", args, Some(&pending)).unwrap();
    assert!(!again.release);
}

#[test]
#[cfg(unix)]
fn resource_tool_can_be_approved_and_inspected() {
    let env = env(Some(60));
    env.start("s1");
    let ws_path = env.home().join("test.txt").to_str().unwrap().to_string();
    let args = json!({"path": ws_path, "content": "approved content bytes"});
    if !cfg!(target_os = "linux") {
        assert_eq!(
            env.open("s1", "create_file", args, "daemon").unwrap_err(),
            "native_approval_resource_tool_unsupported"
        );
        assert!(operator_list(env.home()).is_empty());
        return;
    }
    let reply = env
        .open("s1", "create_file", args.clone(), "daemon")
        .unwrap();
    let pending = id(&reply);
    let inspected = operator_inspect(env.home(), &pending).unwrap();
    assert_eq!(inspected["tool"], "create_file");
    assert_eq!(inspected["resource_details"]["operation"], "create_file");
    assert_eq!(inspected["resource_details"]["content_length"], 22);
    assert_eq!(inspected["binding_sha256"], reply["binding_sha256"]);

    assert_eq!(env.state("s1", &pending), "pending");
    env.approve(&reply);
    assert_eq!(env.state("s1", &pending), "approved");
}

#[test]
#[cfg(unix)]
fn unsupported_resource_tool_with_ask_is_refused() {
    let env = env(Some(60));
    env.start("s1");
    let mut tool = env
        .native()
        .registry
        .tools
        .iter()
        .find(|t| t.name == "create_file")
        .unwrap()
        .clone();
    if let Some(ref mut policy) = tool.resource_policy {
        policy.executor_sha256 = "0".repeat(64);
    }
    assert!(!crate::native::resource_approval::is_supported_linux_resource_tool(&tool));
}
#[tokio::test]
async fn sou89_collector_guard_binds_approval_open_status_and_cancel_to_the_owner() {
    let env = env(Some(60));
    let start = env
        .send(
            "s1",
            json!({"event":"session_start", "liveness":"sw-native-liveness/1"}),
        )
        .unwrap();
    let epoch = env.native().sessions.lock().unwrap().entries["s1"]
        .epoch
        .clone();
    let identity = json!({"contract_version":"sw-native-liveness/1", "instance_id":env.native().instance_id(),
        "epoch":epoch, "owner_token":start.owner_token.unwrap()});
    let headers = |identity: &Value| {
        let mut h = HeaderMap::new();
        h.insert(
            "authorization",
            format!("Bearer {}", env.native().token).parse().unwrap(),
        );
        h.insert(
            super::super::liveness::COLLECTOR_IDENTITY_HEADER,
            identity.to_string().parse().unwrap(),
        );
        h
    };
    let request = json!({"contract_version":CONTRACT,"registry_sha256":env.native().registry_sha256,
        "session_id":"s1","action":"request","source":"daemon","tool":"delete_note",
        "schema_sha256":"a".repeat(64),"args":{"name":"inventory"}});
    let mut forged = identity.clone();
    forged["owner_token"] = json!("peer-owner");
    let (status, _) = handler(
        AxState(env.st.clone()),
        headers(&forged),
        request.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(operator_list(env.home()).is_empty());
    let (status, Json(opened)) = handler(
        AxState(env.st.clone()),
        headers(&identity),
        request.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let pending = opened["pending_id"].as_str().unwrap();
    for action in ["status", "cancel"] {
        let body = json!({"contract_version":CONTRACT,"registry_sha256":env.native().registry_sha256,
            "session_id":"s1","action":action,"pending_id":pending});
        let (status, _) =
            handler(AxState(env.st.clone()), headers(&forged), body.to_string()).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(env.state("s1", pending), "pending");
        let (status, Json(reply)) = handler(
            AxState(env.st.clone()),
            headers(&identity),
            body.to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            reply["state"],
            if action == "status" {
                "pending"
            } else {
                "cancelled"
            }
        );
    }
}
mod selected_tests;
