// SPDX-License-Identifier: Apache-2.0
//! Real native inspection / signed operator grants; no upstream execution claim.
use super::*;
use crate::native::{canonical_digest, child_authority, hash};

fn fixture(format: &str) -> (Env, String, Value, String, SelectedInvocation) {
    let mut env = env(Some(60));
    let name = if format == crate::mcp::server_profile::FORMAT {
        "read_text_file"
    } else {
        "git_show"
    };
    let manifest = crate::mcp::server_profile::original_manifest_for(format).unwrap();
    let definition = manifest["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap();
    let schema = canonical_digest(&definition["inputSchema"]);
    let bytes = json!({"contract_version":CONTRACT,"registry_id":"selected-approval-unit","tools":[{
        "name":name,"schema_sha256":schema,"action_class":"read_only","result_provenance":"untrusted",
        "egress":[],"mcp_result_profile":format}]}).to_string();
    let native = NativeState::from_bytes(
        bytes.as_bytes(),
        &hash(bytes.as_bytes()),
        "native-unit-key".into(),
    )
    .unwrap()
    .with_approval(env.home(), &grant::derive_key(HOOK), 60)
    .unwrap();
    let st = Arc::get_mut(&mut env.st).unwrap();
    st.native = Some(native);
    st.firewall = Mutex::new(AgentFirewall::new(AgentPolicySet::from_yaml(
        "agent_policies:\n  - name: selected-read-ask\n    when: { action_class: read_only }\n    action: ask\ndefault: allow\n"
    ).unwrap(), DEFAULT_TAINT_CAP));
    let args = if name == "read_text_file" {
        json!({"path":"/workspace/notes.txt"})
    } else {
        json!({"repo_path":"/workspace","revision":"HEAD"})
    };
    let context = SelectedInvocation {
        host_call_id: json!(71),
        request_sha256: "a".repeat(64),
        server_id: "selected-unit".into(),
        profile: format.into(),
        profile_sha256: "b".repeat(64),
        classifier_sha256: "c".repeat(64),
        snapshot_sha256: "d".repeat(64),
        definition_sha256: canonical_digest(definition),
        input_sha256: "e".repeat(64),
    };
    start(&env, "selected-owner", &[name.into()]);
    (env, name.into(), args, schema, context)
}

fn start(env: &Env, session: &str, tools: &[String]) {
    let native = env.native();
    let grant = child_authority::mint_scoped(
        &child_authority::derive_key(&native.token),
        "selected-host",
        "selected-unit",
        tools,
        now_ms(),
        60_000,
        format!("{}.{}", native.instance_id(), crate::token::generate()),
        Some(format!("agent-{session}")),
        None,
        None,
    );
    env.send(
        session,
        json!({"event":"session_start","host_session":"selected-host",
        "server_id":"selected-unit","child_authority":child_authority::encode_token(&grant)}),
    )
    .unwrap();
}

fn open_selected(
    env: &Env,
    name: &str,
    args: &Value,
    schema: &str,
    context: &SelectedInvocation,
) -> Result<Value, &'static str> {
    let request: ApprovalRequest = serde_json::from_value(json!({"contract_version":CONTRACT,
        "registry_sha256":env.native().registry_sha256,"session_id":"selected-owner","action":"request",
        "source":"daemon","tool":name,"args":args,"schema_sha256":schema,"selected_invocation":context})).unwrap();
    super::super::open_bound(
        &env.st,
        env.native(),
        env.native().approval.as_ref().unwrap(),
        &request,
        Some(&identity(env, "selected-owner")),
    )
}

fn call_selected(
    env: &Env,
    session: &str,
    name: &str,
    args: &Value,
    schema: &str,
    context: &SelectedInvocation,
    pending: &str,
) -> Result<Response, &'static str> {
    let request = json!({"contract_version":CONTRACT,"registry_sha256":env.native().registry_sha256,
        "session_id":session,"event":"call","tool":name,"args":args,"schema_sha256":schema,
        "mcp_host_call_id":context.host_call_id,"approval_id":pending,"selected_invocation":context});
    crate::native::inspect_bound(
        &env.st,
        env.native(),
        crate::native::parse(&request.to_string()).unwrap(),
        Some(&identity(env, session)),
    )
}

fn identity(env: &Env, id: &str) -> crate::native::liveness::CollectorIdentity {
    let sessions = env.native().sessions.lock().unwrap();
    let session = &sessions.entries[id];
    serde_json::from_value(json!({"contract_version":"sw-native-liveness/1",
        "instance_id":env.native().instance_id(),"epoch":session.epoch,"owner_token":session.owner_token})).unwrap()
}

#[tokio::test]
async fn selected_status_cancel_require_the_private_owner_even_when_header_is_absent() {
    for format in FORMATS {
        let (env, name, args, schema, context) = fixture(format);
        let pending = open_selected(&env, &name, &args, &schema, &context).unwrap();
        for action in ["status", "cancel"] {
            let body = json!({"contract_version":CONTRACT,"registry_sha256":env.native().registry_sha256,
                "session_id":"selected-owner","action":action,"pending_id":id(&pending)});
            let mut headers = HeaderMap::new();
            headers.insert(
                "authorization",
                format!("Bearer {}", env.native().token).parse().unwrap(),
            );
            let (status, _) =
                handler(AxState(env.st.clone()), headers.clone(), body.to_string()).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(env.state("selected-owner", &id(&pending)), "pending");
            let mut owner = serde_json::to_value(identity(&env, "selected-owner")).unwrap();
            owner["owner_token"] = json!("foreign-owner");
            headers.insert(
                crate::native::liveness::COLLECTOR_IDENTITY_HEADER,
                owner.to_string().parse().unwrap(),
            );
            let (status, _) = handler(AxState(env.st.clone()), headers, body.to_string()).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(env.state("selected-owner", &id(&pending)), "pending");
        }
    }
}

const FORMATS: [&str; 2] = [
    crate::mcp::server_profile::FORMAT,
    crate::mcp::server_profile::git::FORMAT,
];

#[test]
fn selected_approval_is_single_use_and_host_request_scoped() {
    for format in FORMATS {
        let (env, name, args, schema, context) = fixture(format);
        let pending = open_selected(&env, &name, &args, &schema, &context).unwrap();
        let record = operator_inspect(env.home(), &id(&pending)).unwrap();
        assert_eq!(record["selected_invocation"], json!(context));
        assert_eq!(record["args"], args);
        assert!(
            env.native().sessions.lock().unwrap().entries["selected-owner"]
                .calls
                .is_empty()
        );
        env.approve(&pending);
        assert!(
            call_selected(
                &env,
                "selected-owner",
                &name,
                &args,
                &schema,
                &context,
                &id(&pending)
            )
            .unwrap()
            .release
        );
        let replay = call_selected(
            &env,
            "selected-owner",
            &name,
            &args,
            &schema,
            &context,
            &id(&pending),
        )
        .unwrap();
        assert!(!replay.release && codes(&replay).contains("native_approval_spent"));
        assert!(operator_list(env.home()).is_empty());
    }
}

#[test]
fn selected_approval_changed_identity_is_terminal_and_never_rescued() {
    for format in FORMATS {
        for field in [
            "host_call_id",
            "request_sha256",
            "classifier_sha256",
            "profile_sha256",
            "snapshot_sha256",
            "input_sha256",
        ] {
            let (env, name, args, schema, context) = fixture(format);
            let pending = open_selected(&env, &name, &args, &schema, &context).unwrap();
            env.approve(&pending);
            let mut changed = json!(context);
            changed[field] = if field == "host_call_id" {
                json!("71")
            } else {
                json!("f".repeat(64))
            };
            let changed: SelectedInvocation = serde_json::from_value(changed).unwrap();
            let denied = call_selected(
                &env,
                "selected-owner",
                &name,
                &args,
                &schema,
                &changed,
                &id(&pending),
            )
            .unwrap();
            assert!(!denied.release, "changed {field}");
            assert!(
                !call_selected(
                    &env,
                    "selected-owner",
                    &name,
                    &args,
                    &schema,
                    &context,
                    &id(&pending)
                )
                .unwrap()
                .release
            );
            assert!(
                env.native().sessions.lock().unwrap().entries["selected-owner"]
                    .calls
                    .is_empty()
            );
        }
    }
}

#[test]
fn selected_approval_foreign_session_cancellation_and_policy_switch_release_nothing() {
    for format in FORMATS {
        for control in ["foreign", "cancel", "policy", "reject"] {
            let (env, name, args, schema, context) = fixture(format);
            let pending = open_selected(&env, &name, &args, &schema, &context).unwrap();
            if control == "reject" {
                operator_reject(env.home(), &id(&pending)).unwrap();
            } else {
                env.approve(&pending);
            }
            let session = if control == "foreign" {
                start(&env, "other-owner", std::slice::from_ref(&name));
                "other-owner"
            } else {
                "selected-owner"
            };
            if control == "cancel" {
                cancel(
                    &env.st,
                    env.native().approval.as_ref().unwrap(),
                    &id(&pending),
                    session,
                )
                .unwrap();
            }
            if control == "policy" {
                env.native()
                    .approval
                    .as_ref()
                    .unwrap()
                    .store
                    .invalidate_all_for_policy_switch()
                    .unwrap();
            }
            assert!(
                !call_selected(
                    &env,
                    session,
                    &name,
                    &args,
                    &schema,
                    &context,
                    &id(&pending)
                )
                .unwrap()
                .release,
                "{control}"
            );
            assert!(env.native().sessions.lock().unwrap().entries[session]
                .calls
                .is_empty());
        }
    }
}

#[test]
fn selected_approval_rejects_invalid_arguments_context_and_missing_tool_authority() {
    for format in FORMATS {
        let (env, name, args, schema, context) = fixture(format);
        let mut invalid = args.clone();
        invalid["unadvertised"] = json!(true);
        assert!(open_selected(&env, &name, &invalid, &schema, &context).is_err());
        let mut wrong = context.clone();
        wrong.definition_sha256 = "0".repeat(64);
        assert!(open_selected(&env, &name, &args, &schema, &wrong).is_err());
        wrong = context.clone();
        wrong.profile = "unsupported/mutator/1".into();
        assert!(open_selected(&env, &name, &args, &schema, &wrong).is_err());
        env.native()
            .sessions
            .lock()
            .unwrap()
            .entries
            .get_mut("selected-owner")
            .unwrap()
            .granted_tools
            .clear();
        assert_eq!(
            open_selected(&env, &name, &args, &schema, &context).unwrap_err(),
            "native_child_authority_escalation"
        );
        assert!(operator_list(env.home()).is_empty());
    }
}

#[test]
fn selected_changed_arguments_expiry_and_hard_deny_cannot_redeem() {
    for format in FORMATS {
        for control in ["args", "expiry", "deny"] {
            let (env, name, args, schema, context) = fixture(format);
            let pending = open_selected(&env, &name, &args, &schema, &context).unwrap();
            env.approve(&pending);
            let mut presented = args.clone();
            if control == "args" {
                if name == "read_text_file" {
                    presented["path"] = json!("/workspace/other.txt");
                } else {
                    presented["revision"] = json!("a".repeat(40));
                }
            } else if control == "expiry" {
                env.native()
                    .approval
                    .as_ref()
                    .unwrap()
                    .records
                    .lock()
                    .unwrap()
                    .get_mut(&id(&pending))
                    .unwrap()
                    .expires = Instant::now();
            } else {
                *env.st.firewall.lock().unwrap() = AgentFirewall::new(
                    AgentPolicySet::from_yaml("agent_policies: []\ndefault: deny\n").unwrap(),
                    DEFAULT_TAINT_CAP,
                );
            }
            assert!(
                !call_selected(
                    &env,
                    "selected-owner",
                    &name,
                    &presented,
                    &schema,
                    &context,
                    &id(&pending)
                )
                .unwrap()
                .release
            );
            assert!(
                env.native().sessions.lock().unwrap().entries["selected-owner"]
                    .calls
                    .is_empty()
            );
        }
    }
}

#[test]
fn approval_expiry_pruning_removes_files_without_evicting_live_sibling() {
    let env = env(Some(60));
    env.start("live");
    env.start("cycling");
    let args = json!({"name":"synthetic"});
    let live = env
        .open("live", "delete_note", args.clone(), "daemon")
        .unwrap();
    for _ in 0..100 {
        let transient = env
            .open("cycling", "delete_note", args.clone(), "daemon")
            .unwrap();
        let approval = env.native().approval.as_ref().unwrap();
        approval
            .records
            .lock()
            .unwrap()
            .get_mut(&id(&transient))
            .unwrap()
            .expires = Instant::now();
        assert!(
            matches!(
                env.state("cycling", &id(&transient)).as_str(),
                "expired" | "native_approval_unknown"
            ),
            "terminal history may be pruned; live siblings may not"
        );
        assert!(operator_inspect(env.home(), &id(&transient)).is_err());
        assert!(approval.records.lock().unwrap().len() <= KEEP_TERMINAL + 1);
        assert_eq!(operator_list(env.home()).len(), 1);
    }
    env.approve(&live);
    assert!(
        env.call("live", "delete_note", args, Some(&id(&live)))
            .unwrap()
            .release
    );
}
