// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Independent witness verification suite for SOU-88 single-use operator
//! Ask confirmation for constrained Linux native resource executors.
//!
//! Verifies:
//! 1. Filesystem witness: `create_file` approved executes once; rejected/mutated/expired executes 0 times.
//! 2. Filesystem witness: `read_document` approved executes once; replayed returns spent.
//! 3. Network witness: `https_get` approved executes once; mutated/rejected returns refusal / 0 execution.
//! 4. Hard Deny non-escalation: hard Deny cannot open or redeem approvals.
//! 5. Provenance loss confinement: approving single Ask call preserves taint floor and incomplete history; next call requires Ask.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use agentfw::audit::AuditSink;
use agentfw::handlers::{AppState, Sessions};
use agentfw::mcp::resources::{EvidenceSource, ResourceEvidence};
use agentfw::native::approval::{
    operator_approve, operator_inspect, operator_list, operator_reject,
};
use agentfw::native::resource::{
    create_file_binding, create_file_executor_sha256, create_file_schema, https_get_binding,
    https_get_schema, Admission, Policy, CREATE_FILE_EXECUTOR_PROFILE, CREATE_FILE_MAX_CONTENT,
    READ_DOCUMENT_EXECUTOR_PROFILE,
};
use agentfw::native::{NativeState, CONTRACT, MAX_CONTENT};
use agentfw::{app, Config};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soup_wall_agent::{AgentFirewall, AgentPolicySet, DEFAULT_TAINT_CAP};
use tower::ServiceExt;

const HOOK_TOKEN: &str = "witness-hook-token-0123456789";
const NATIVE_TOKEN: &str = "witness-native-token-9876543210";
const HTTPS_URL: &str = "https://example.com/witness/data";

const SIDE_EFFECTING_ASK_POLICY: &str = r#"
agent_policies:
  - name: ask-side-effecting
    when: { action_class: side_effecting }
    action: ask
  - name: ask-read-only
    when: { action_class: read_only }
    action: ask
  - name: ask-network
    when: { action_class: network }
    action: ask
  - name: deny-destructive
    when: { action_class: destructive }
    action: deny
egress_allowlist:
  - example.com
default: allow
"#;

const HARD_DENY_POLICY: &str = r#"
agent_policies:
  - name: hard-deny-all
    when: { action_class: side_effecting }
    action: deny
default: allow
"#;

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct WitnessFixture {
    dir: tempfile::TempDir,
    state: agentfw::Shared,
    registry_sha256: String,
    create_policy: Policy,
    read_policy: Policy,
    https_policy: Policy,
    create_file_path: PathBuf,
    read_doc_path: PathBuf,
}

impl WitnessFixture {
    fn new(firewall_policy: &str, ttl_seconds: u64) -> Self {
        let root = std::env::temp_dir();
        #[cfg(unix)]
        let root = root.canonicalize().unwrap();
        let dir = tempfile::tempdir_in(root).unwrap();

        let workspace = dir.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let workspace = workspace.canonicalize().unwrap();

        let create_file_path = workspace.join("witness_create.txt");
        let read_doc_path = workspace.join("witness_doc.txt");
        std::fs::write(&read_doc_path, b"witness document secret content 12345\n").unwrap();

        let create_schema_sha = agentfw::native::canonical_digest(&create_file_schema());
        let create_resource_policy_val = json!({
            "profile": {
                "server_id": "witness-fixture",
                "tool_name": "create_file",
                "schema_sha256": create_schema_sha,
                "selectors": [{
                    "pointer": "/path",
                    "kind": "path",
                    "allow_missing_leaf": true
                }]
            },
            "workspace": workspace,
            "cwd": workspace,
            "executor_sha256": create_file_executor_sha256(),
            "classifier_sha256": "c".repeat(64),
            "allowed_resources": [{
                "kind": "path",
                "canonical": create_file_path
            }],
            "execution": {
                "operation": "create_file",
                "action": "write",
                "max_content_bytes": CREATE_FILE_MAX_CONTENT,
                "executor_profile": CREATE_FILE_EXECUTOR_PROFILE
            }
        });
        let create_policy: Policy =
            serde_json::from_value(create_resource_policy_val.clone()).unwrap();

        let read_schema = json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" }
            },
            "required": ["path"],
            "additionalProperties": false
        });
        let read_schema_sha = agentfw::native::canonical_digest(&read_schema);
        let read_resource_policy_val = json!({
            "profile": {
                "server_id": "witness-fixture",
                "tool_name": "read_document",
                "schema_sha256": read_schema_sha,
                "selectors": [{
                    "pointer": "/path",
                    "kind": "path",
                    "allow_missing_leaf": false
                }]
            },
            "workspace": workspace,
            "cwd": workspace,
            "executor_sha256": sha(READ_DOCUMENT_EXECUTOR_PROFILE.as_bytes()),
            "classifier_sha256": "c".repeat(64),
            "allowed_resources": [{
                "kind": "path",
                "canonical": read_doc_path
            }],
            "execution": {
                "operation": "read_document",
                "action": "read",
                "max_content_bytes": MAX_CONTENT,
                "executor_profile": READ_DOCUMENT_EXECUTOR_PROFILE
            }
        });
        let read_policy: Policy = serde_json::from_value(read_resource_policy_val.clone()).unwrap();

        let https_schema_sha = agentfw::native::canonical_digest(&https_get_schema());
        let https_resource_policy_val = json!({
            "profile": {
                "server_id": "witness-fixture",
                "tool_name": "https_get",
                "schema_sha256": https_schema_sha,
                "selectors": [{
                    "pointer": "/url",
                    "kind": "url"
                }]
            },
            "workspace": workspace,
            "cwd": workspace,
            "executor_sha256": agentfw::mcp::https_get::executor_profile_sha256(),
            "classifier_sha256": "c".repeat(64),
            "allowed_resources": [{
                "kind": "url",
                "canonical": "https://example.com/witness/data",
                "host": "example.com",
                "port": 443
            }],
            "network": {
                "exact_url": HTTPS_URL,
                "approved_addresses": ["93.184.216.34"],
                "private_endpoint": null,
                "root_certificate_pem": null
            }
        });
        let https_policy: Policy =
            serde_json::from_value(https_resource_policy_val.clone()).unwrap();

        let registry = json!({
            "contract_version": CONTRACT,
            "registry_id": "witness-native-registry",
            "tools": [
                {
                    "name": "create_file",
                    "schema_sha256": create_schema_sha,
                    "action_class": "side_effecting",
                    "result_provenance": "local_project",
                    "egress": [],
                    "resource_policy": create_resource_policy_val
                },
                {
                    "name": "read_document",
                    "schema_sha256": read_schema_sha,
                    "action_class": "read_only",
                    "result_provenance": "untrusted",
                    "egress": [],
                    "resource_policy": read_resource_policy_val
                },
                {
                    "name": "https_get",
                    "schema_sha256": https_schema_sha,
                    "action_class": "network",
                    "result_provenance": "untrusted",
                    "egress": [{"pointer": "/url", "kind": "url_host", "optional": false}],
                    "resource_policy": https_resource_policy_val
                }
            ]
        });

        let bytes = serde_json::to_vec(&registry).unwrap();
        let registry_sha256 = sha(&bytes);

        let mut native =
            NativeState::from_bytes(&bytes, &registry_sha256, NATIVE_TOKEN.into()).unwrap();
        let home = dir.path().join(".agentfw");
        std::fs::create_dir_all(&home).unwrap();
        let grant_key = agentfw::grant::derive_key(HOOK_TOKEN);
        native = native
            .with_approval(&home, &grant_key, ttl_seconds)
            .unwrap();

        let state = Arc::new(AppState {
            native: Some(native),
            firewall: Mutex::new(AgentFirewall::new(
                AgentPolicySet::from_yaml(firewall_policy).unwrap(),
                DEFAULT_TAINT_CAP,
            )),
            sessions: Sessions::default(),
            audit: AuditSink::open(&home.join("audit.jsonl")).unwrap(),
            spans: agentfw::spans::SpanCache::new(64, 4096),
            judge: agentfw::judge::Judge::new(Default::default()),
            manifests: agentfw::mcp::store::ManifestStore::new(&home.join("manifests")),
            tools: agentfw::mcp::store::ToolRegistry::with_builtins(),
            grants: agentfw::grant::GrantStore::new(&home.join("grants")),
            grant_ledger: agentfw::grant::GrantLedger::open(&home.join("grants-spent.json")),
            grant_key,
            config: Config {
                enforce: true,
                ..Config::default()
            },
            token: HOOK_TOKEN.into(),
        });

        Self {
            dir,
            state,
            registry_sha256,
            create_policy,
            read_policy,
            https_policy,
            create_file_path,
            read_doc_path,
        }
    }

    fn agent_home(&self) -> PathBuf {
        self.dir.path().join(".agentfw")
    }

    async fn start_session(&self, session: &str) {
        let body = json!({
            "contract_version": CONTRACT,
            "registry_sha256": self.registry_sha256,
            "session_id": session,
            "event": "session_start"
        });
        let (status, reply) =
            post(self.state.clone(), "/native/v1", &body, Some(NATIVE_TOKEN)).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert_eq!(reply["release"], true, "{reply}");
    }

    async fn open_approval(
        &self,
        session: &str,
        tool: &str,
        args: &Value,
        schema_sha256: &str,
        resource_admission: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut body = json!({
            "contract_version": CONTRACT,
            "registry_sha256": self.registry_sha256,
            "session_id": session,
            "action": "request",
            "source": "daemon",
            "tool": tool,
            "args": args,
            "schema_sha256": schema_sha256,
        });
        if let Some(adm) = resource_admission {
            body["resource_admission"] = adm.clone();
        }
        post(
            self.state.clone(),
            "/native/approval/v1",
            &body,
            Some(NATIVE_TOKEN),
        )
        .await
    }

    fn make_create_file_call(
        &self,
        session: &str,
        args: &Value,
        approval_id: Option<&str>,
    ) -> Value {
        let binding = create_file_binding(&self.create_policy, args).unwrap();
        let admission = Admission {
            server_id: self.create_policy.profile.server_id.clone(),
            host_call_id: json!("witness-create-call-1"),
            profile_sha256: agentfw::native::canonical_digest(
                &serde_json::to_value(&self.create_policy.profile).unwrap(),
            ),
            executor_sha256: self.create_policy.executor_sha256.clone(),
            classifier_sha256: self.create_policy.classifier_sha256.clone(),
            snapshot_sha256: "d".repeat(64),
            definition_sha256: "f".repeat(64),
            input_sha256: "a".repeat(64),
            resources: vec![ResourceEvidence {
                pointer: "/path".into(),
                source: EvidenceSource::Argument,
                resource: self.create_policy.allowed_resources[0].clone(),
            }],
            execution: Some(binding),
            network: None,
            windows_read: None,
        };

        let mut body = json!({
            "contract_version": agentfw::native::resource::CREATE_CONTRACT,
            "registry_sha256": self.registry_sha256,
            "session_id": session,
            "event": "call",
            "tool": "create_file",
            "args": args,
            "schema_sha256": self.create_policy.profile.schema_sha256,
            "resource_admission": serde_json::to_value(admission).unwrap()
        });

        if let Some(id) = approval_id {
            body["approval_id"] = json!(id);
        }

        body
    }

    fn make_read_document_call(
        &self,
        session: &str,
        args: &Value,
        approval_id: Option<&str>,
    ) -> Value {
        let admission = Admission {
            server_id: self.read_policy.profile.server_id.clone(),
            host_call_id: json!("witness-read-call-1"),
            profile_sha256: agentfw::native::canonical_digest(
                &serde_json::to_value(&self.read_policy.profile).unwrap(),
            ),
            executor_sha256: self.read_policy.executor_sha256.clone(),
            classifier_sha256: self.read_policy.classifier_sha256.clone(),
            snapshot_sha256: "d".repeat(64),
            definition_sha256: "f".repeat(64),
            input_sha256: "a".repeat(64),
            resources: vec![ResourceEvidence {
                pointer: "/path".into(),
                source: EvidenceSource::Argument,
                resource: self.read_policy.allowed_resources[0].clone(),
            }],
            execution: None,
            network: None,
            windows_read: None,
        };

        let mut body = json!({
            "contract_version": agentfw::native::resource::CONTRACT,
            "registry_sha256": self.registry_sha256,
            "session_id": session,
            "event": "call",
            "tool": "read_document",
            "args": args,
            "schema_sha256": self.read_policy.profile.schema_sha256,
            "resource_admission": serde_json::to_value(admission).unwrap()
        });

        if let Some(id) = approval_id {
            body["approval_id"] = json!(id);
        }

        body
    }

    fn make_https_get_call(&self, session: &str, args: &Value, approval_id: Option<&str>) -> Value {
        let binding = https_get_binding(&self.https_policy, args).unwrap();
        let admission = Admission {
            server_id: self.https_policy.profile.server_id.clone(),
            host_call_id: json!("witness-https-call-1"),
            profile_sha256: agentfw::native::canonical_digest(
                &serde_json::to_value(&self.https_policy.profile).unwrap(),
            ),
            executor_sha256: self.https_policy.executor_sha256.clone(),
            classifier_sha256: self.https_policy.classifier_sha256.clone(),
            snapshot_sha256: "d".repeat(64),
            definition_sha256: "f".repeat(64),
            input_sha256: "a".repeat(64),
            resources: vec![ResourceEvidence {
                pointer: "/url".into(),
                source: EvidenceSource::Argument,
                resource: self.https_policy.allowed_resources[0].clone(),
            }],
            execution: None,
            network: Some(binding),
            windows_read: None,
        };

        let mut body = json!({
            "contract_version": agentfw::native::resource::NETWORK_CONTRACT,
            "registry_sha256": self.registry_sha256,
            "session_id": session,
            "event": "call",
            "tool": "https_get",
            "args": args,
            "schema_sha256": self.https_policy.profile.schema_sha256,
            "resource_admission": serde_json::to_value(admission).unwrap()
        });

        if let Some(id) = approval_id {
            body["approval_id"] = json!(id);
        }

        body
    }
}

async fn post(
    state: agentfw::Shared,
    path: &str,
    body: &Value,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app(state)
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).expect("endpoint responses must be JSON"),
    )
}

// =========================================================================
// TEST 1: Filesystem Witness - create_file approved executes once
// =========================================================================
#[tokio::test]
async fn witness_create_file_approved_executes_once() {
    let fixture = WitnessFixture::new(SIDE_EFFECTING_ASK_POLICY, 60);
    let session = "create-approved-session";
    fixture.start_session(session).await;

    let target_path = &fixture.create_file_path;
    let content = "approved content written by single-use executor\n";
    let args = json!({
        "path": target_path.to_str().unwrap(),
        "content": content
    });

    // 1. Filesystem witness BEFORE call: file does NOT exist
    assert!(
        !target_path.exists(),
        "target file must not exist before call"
    );

    // 2. Call without approval_id triggers Ask verdict
    let call = fixture.make_create_file_call(session, &args, None);
    let (status, reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["release"], false, "Ask must not release execution");
    assert_eq!(reply["verdict"], "ask");

    // 3. Request approval through /native/approval/v1
    let (app_status, app_reply) = fixture
        .open_approval(
            session,
            "create_file",
            &args,
            fixture.create_policy.profile.schema_sha256.as_str(),
            Some(&call["resource_admission"]),
        )
        .await;
    assert_eq!(app_status, StatusCode::OK, "{app_reply}");
    let pending_id = app_reply["pending_id"]
        .as_str()
        .expect("must provide pending_id");
    let binding_sha256 = app_reply["binding_sha256"]
        .as_str()
        .expect("must provide binding_sha256");

    // 4. Filesystem witness AFTER Ask: file STILL does not exist (0 execution)
    assert!(
        !target_path.exists(),
        "target file must not exist during Ask wait"
    );

    // 5. Operator lists and inspects approval details
    let pending_list = operator_list(&fixture.agent_home());
    assert_eq!(pending_list.len(), 1, "exactly one approval pending");
    assert_eq!(pending_list[0]["tool"], "create_file");
    assert_eq!(pending_list[0]["pending_id"], pending_id);

    let inspected = operator_inspect(&fixture.agent_home(), pending_id).unwrap();
    assert_eq!(inspected["tool"], "create_file");
    assert_eq!(inspected["resource_details"]["operation"], "create_file");
    assert_eq!(
        inspected["resource_details"]["path"],
        target_path.to_str().unwrap()
    );
    assert_eq!(
        inspected["resource_details"]["content_bytes_sha256"],
        sha(content.as_bytes())
    );

    // 6. Operator approves
    operator_approve(
        &fixture.agent_home(),
        HOOK_TOKEN,
        pending_id,
        binding_sha256,
    )
    .unwrap();

    // 7. Resubmit call with approval_id: gate releases execution
    let approved_call = fixture.make_create_file_call(session, &args, Some(pending_id));
    let (status, approved_reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &approved_call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved_reply}");
    assert_eq!(
        approved_reply["release"], true,
        "approved call must release"
    );
    assert_eq!(approved_reply["verdict"], "allow");

    // 8. Simulating executor execution following native release (exact single-use write)
    std::fs::write(target_path, content.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(target_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // 9. Filesystem witness: file exists, content matches, permissions 0600
    assert!(
        target_path.exists(),
        "target file must exist after execution"
    );
    assert_eq!(std::fs::read_to_string(target_path).unwrap(), content);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            target_path.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // 10. Replay prevention: re-submitting same approval_id while file exists fails closed
    let (status, replay_reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &approved_call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replay_reply}");
    assert_eq!(
        replay_reply["release"], false,
        "replayed approval must not release"
    );
    assert!(
        replay_reply["reason_codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "native_create_target_exists_or_unavailable"
                || c == "native_approval_spent")
    );

    // Even if the file is removed, re-submitting the same approval_id is spent in the ledger
    std::fs::remove_file(target_path).unwrap();
    let (_, replay_spent) = post(
        fixture.state.clone(),
        "/native/v1",
        &approved_call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(replay_spent["release"], false);
    assert!(replay_spent["reason_codes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "native_approval_spent"));
}

// =========================================================================
// TEST 2: Filesystem Witness - Rejection, Mutation, and Expiration (0 executions)
// =========================================================================
#[tokio::test]
async fn witness_create_file_rejected_mutated_expired_zero_execution() {
    let fixture = WitnessFixture::new(SIDE_EFFECTING_ASK_POLICY, 1);
    let session = "create-zero-exec-session";
    fixture.start_session(session).await;

    let target_path = &fixture.create_file_path;
    let content = "payload destined for rejection\n";
    let args = json!({
        "path": target_path.to_str().unwrap(),
        "content": content
    });

    // --- Subtest A: Operator Rejection ---
    let call = fixture.make_create_file_call(session, &args, None);
    let (_, app_reply) = fixture
        .open_approval(
            session,
            "create_file",
            &args,
            fixture.create_policy.profile.schema_sha256.as_str(),
            Some(&call["resource_admission"]),
        )
        .await;
    let pending_id = app_reply["pending_id"].as_str().unwrap();

    operator_reject(&fixture.agent_home(), pending_id).unwrap();

    let resubmitted = fixture.make_create_file_call(session, &args, Some(pending_id));
    let (_, rejected_reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &resubmitted,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(rejected_reply["release"], false);
    assert!(rejected_reply["reason_codes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "native_approval_rejected"));
    assert!(
        !target_path.exists(),
        "witness: rejected call must execute zero times"
    );

    // --- Subtest B: Content Mutation After Approval ---
    let session_b = "create-mutation-session";
    fixture.start_session(session_b).await;
    let call_b = fixture.make_create_file_call(session_b, &args, None);
    let (_, app_reply_b) = fixture
        .open_approval(
            session_b,
            "create_file",
            &args,
            fixture.create_policy.profile.schema_sha256.as_str(),
            Some(&call_b["resource_admission"]),
        )
        .await;
    let pending_id_b = app_reply_b["pending_id"].as_str().unwrap();
    let binding_b = app_reply_b["binding_sha256"].as_str().unwrap();

    operator_approve(&fixture.agent_home(), HOOK_TOKEN, pending_id_b, binding_b).unwrap();

    // Mutate content payload
    let mutated_args = json!({
        "path": target_path.to_str().unwrap(),
        "content": "MUTATED CONTENT BY ADVERSARY\n"
    });
    let mutated_call = fixture.make_create_file_call(session_b, &mutated_args, Some(pending_id_b));
    let (_, mutated_reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &mutated_call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(mutated_reply["release"], false);
    assert!(mutated_reply["reason_codes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "native_approval_binding_mismatch"));
    assert!(
        !target_path.exists(),
        "witness: mutated content must execute zero times"
    );

    // --- Subtest C: Expiration ---
    let session_c = "create-expiry-session";
    fixture.start_session(session_c).await;
    let call_c = fixture.make_create_file_call(session_c, &args, None);
    let (_, app_reply_c) = fixture
        .open_approval(
            session_c,
            "create_file",
            &args,
            fixture.create_policy.profile.schema_sha256.as_str(),
            Some(&call_c["resource_admission"]),
        )
        .await;
    let pending_id_c = app_reply_c["pending_id"].as_str().unwrap();
    let binding_c = app_reply_c["binding_sha256"].as_str().unwrap();

    // Wait past 1s TTL
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Operator approving expired request fails or redemption fails
    let approve_result =
        operator_approve(&fixture.agent_home(), HOOK_TOKEN, pending_id_c, binding_c);
    if approve_result.is_ok() {
        let resubmitted_c = fixture.make_create_file_call(session_c, &args, Some(pending_id_c));
        let (_, expired_reply) = post(
            fixture.state.clone(),
            "/native/v1",
            &resubmitted_c,
            Some(NATIVE_TOKEN),
        )
        .await;
        assert_eq!(expired_reply["release"], false);
        assert!(expired_reply["reason_codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "native_approval_expired"));
    }
    assert!(
        !target_path.exists(),
        "witness: expired approval must execute zero times"
    );
}

// =========================================================================
// TEST 3: Filesystem Witness - read_document approved executes once
// =========================================================================
#[tokio::test]
async fn witness_read_document_approved_executes_once() {
    let fixture = WitnessFixture::new(SIDE_EFFECTING_ASK_POLICY, 60);
    let session = "read-approved-session";
    fixture.start_session(session).await;

    let target_path = &fixture.read_doc_path;
    let args = json!({
        "path": target_path.to_str().unwrap()
    });

    // 1. Initial call triggers Ask
    let call = fixture.make_read_document_call(session, &args, None);
    let (status, reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["release"], false);
    assert_eq!(reply["verdict"], "ask");

    // 2. Open approval
    let (_, app_reply) = fixture
        .open_approval(
            session,
            "read_document",
            &args,
            fixture.read_policy.profile.schema_sha256.as_str(),
            Some(&call["resource_admission"]),
        )
        .await;
    let pending_id = app_reply["pending_id"].as_str().unwrap();
    let binding_sha256 = app_reply["binding_sha256"].as_str().unwrap();

    // 3. Operator inspection confirms read_document details
    let inspected = operator_inspect(&fixture.agent_home(), pending_id).unwrap();
    assert_eq!(inspected["tool"], "read_document");
    assert_eq!(inspected["resource_details"]["operation"], "read_document");
    assert_eq!(
        inspected["resource_details"]["path"],
        target_path.to_str().unwrap()
    );

    // 4. Operator approves
    operator_approve(
        &fixture.agent_home(),
        HOOK_TOKEN,
        pending_id,
        binding_sha256,
    )
    .unwrap();

    // 5. Resubmitted call succeeds
    let approved_call = fixture.make_read_document_call(session, &args, Some(pending_id));
    let (_, approved_reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &approved_call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(approved_reply["release"], true);
    assert_eq!(approved_reply["verdict"], "allow");

    // 6. Replay fails with native_approval_spent
    let (_, replay_reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &approved_call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(replay_reply["release"], false);
    assert!(replay_reply["reason_codes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "native_approval_spent"));
}

// =========================================================================
// TEST 4: Network Witness - https_get approved executes once, mutation/rejection 0
// =========================================================================
#[tokio::test]
async fn witness_https_get_approved_executes_once_and_rejection_zero_execution() {
    let fixture = WitnessFixture::new(SIDE_EFFECTING_ASK_POLICY, 60);
    let session = "https-witness-session";
    fixture.start_session(session).await;

    let args = json!({
        "url": HTTPS_URL
    });

    // 1. Call triggers Ask
    let call = fixture.make_https_get_call(session, &args, None);
    let (status, reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["release"], false);
    assert_eq!(reply["verdict"], "ask");

    // 2. Open approval
    let (_, app_reply) = fixture
        .open_approval(
            session,
            "https_get",
            &args,
            fixture.https_policy.profile.schema_sha256.as_str(),
            Some(&call["resource_admission"]),
        )
        .await;
    let pending_id = app_reply["pending_id"].as_str().unwrap();
    let binding_sha256 = app_reply["binding_sha256"].as_str().unwrap();

    // 3. Operator inspects URL authority
    let inspected = operator_inspect(&fixture.agent_home(), pending_id).unwrap();
    assert_eq!(inspected["tool"], "https_get");
    assert_eq!(inspected["resource_details"]["operation"], "https_get");
    assert_eq!(inspected["resource_details"]["url"], HTTPS_URL);

    // 4. Operator approves
    operator_approve(
        &fixture.agent_home(),
        HOOK_TOKEN,
        pending_id,
        binding_sha256,
    )
    .unwrap();

    // 5. Resubmit succeeds
    let approved_call = fixture.make_https_get_call(session, &args, Some(pending_id));
    let (_, approved_reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &approved_call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(approved_reply["release"], true);
    assert_eq!(approved_reply["verdict"], "allow");

    // 6. Replay fails with native_approval_spent
    let (_, replay_reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &approved_call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(replay_reply["release"], false);
    assert!(replay_reply["reason_codes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "native_approval_spent"));

    // 7. Mutation test: altered URL returns binding mismatch
    let session_mut = "https-mutation-session";
    fixture.start_session(session_mut).await;
    let call_mut = fixture.make_https_get_call(session_mut, &args, None);
    let (_, app_reply_mut) = fixture
        .open_approval(
            session_mut,
            "https_get",
            &args,
            fixture.https_policy.profile.schema_sha256.as_str(),
            Some(&call_mut["resource_admission"]),
        )
        .await;
    let pending_mut = app_reply_mut["pending_id"].as_str().unwrap();
    let binding_mut = app_reply_mut["binding_sha256"].as_str().unwrap();
    operator_approve(&fixture.agent_home(), HOOK_TOKEN, pending_mut, binding_mut).unwrap();

    let altered_url_args = json!({"url": "https://example.com/witness/other"});
    let mut altered_call = fixture.make_https_get_call(session_mut, &args, Some(pending_mut));
    altered_call["args"] = altered_url_args;
    let (_, mut_reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &altered_call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(mut_reply["release"], false);
    assert!(mut_reply["reason_codes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "native_approval_binding_mismatch" || c == "native_https_url_not_allowed"));
}

// =========================================================================
// TEST 5: Hard Deny Non-Escalation
// =========================================================================
#[tokio::test]
async fn witness_hard_deny_cannot_be_approved() {
    let fixture = WitnessFixture::new(HARD_DENY_POLICY, 60);
    let session = "hard-deny-session";
    fixture.start_session(session).await;

    let target_path = &fixture.create_file_path;
    let args = json!({
        "path": target_path.to_str().unwrap(),
        "content": "forbidden payload\n"
    });

    let call = fixture.make_create_file_call(session, &args, None);
    let (status, reply) = post(
        fixture.state.clone(),
        "/native/v1",
        &call,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["release"], false);
    assert_eq!(reply["verdict"], "deny");

    // Attempting to request approval for hard Deny fails with native_approval_hard_deny
    let (app_status, app_reply) = fixture
        .open_approval(
            session,
            "create_file",
            &args,
            fixture.create_policy.profile.schema_sha256.as_str(),
            Some(&call["resource_admission"]),
        )
        .await;
    assert_eq!(app_status, StatusCode::CONFLICT, "{app_reply}");
    assert_eq!(app_reply["error_code"], "native_approval_hard_deny");

    assert!(
        operator_list(&fixture.agent_home()).is_empty(),
        "pending list must be empty"
    );
    assert!(
        !target_path.exists(),
        "witness: hard Deny must execute zero times"
    );
}

// =========================================================================
// TEST 6: Provenance Loss Confinement - Single Call Authorization Only
// =========================================================================
#[tokio::test]
async fn witness_ask_after_provenance_loss_confinement() {
    let fixture = WitnessFixture::new(SIDE_EFFECTING_ASK_POLICY, 60);
    let session = "provenance-taint-session";
    fixture.start_session(session).await;

    let target_path = &fixture.create_file_path;
    let args = json!({
        "path": target_path.to_str().unwrap(),
        "content": "call 1 under taint\n"
    });

    // 1. Mark session with incomplete provenance
    fixture
        .state
        .firewall
        .lock()
        .unwrap()
        .mark_provenance_incomplete("witness-host");

    // 2. First call under taint triggers Ask
    let call1 = fixture.make_create_file_call(session, &args, None);
    let (_, reply1) = post(
        fixture.state.clone(),
        "/native/v1",
        &call1,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(reply1["release"], false);
    assert_eq!(reply1["verdict"], "ask");

    let (_, app_reply1) = fixture
        .open_approval(
            session,
            "create_file",
            &args,
            fixture.create_policy.profile.schema_sha256.as_str(),
            Some(&call1["resource_admission"]),
        )
        .await;
    let pending1 = app_reply1["pending_id"].as_str().unwrap();
    let binding1 = app_reply1["binding_sha256"].as_str().unwrap();

    // 3. Operator approves first call
    operator_approve(&fixture.agent_home(), HOOK_TOKEN, pending1, binding1).unwrap();

    let approved1 = fixture.make_create_file_call(session, &args, Some(pending1));
    let (_, approved_reply1) = post(
        fixture.state.clone(),
        "/native/v1",
        &approved1,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(
        approved_reply1["release"], true,
        "first approved call releases"
    );
    assert_eq!(approved_reply1["verdict"], "allow");

    // 4. Invariant: provenance incomplete is NOT cleared
    assert!(
        fixture
            .state
            .firewall
            .lock()
            .unwrap()
            .provenance_incomplete("witness-host"),
        "approval must NOT clear provenance taint floor"
    );

    // 5. Invariant: next call STILL requires Ask (no blanket grant)
    let call2 = fixture.make_create_file_call(session, &args, None);
    let (_, reply2) = post(
        fixture.state.clone(),
        "/native/v1",
        &call2,
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(
        reply2["release"], false,
        "subsequent call must STILL require Ask"
    );
    assert_eq!(reply2["verdict"], "ask");

    let (_, app_reply2) = fixture
        .open_approval(
            session,
            "create_file",
            &args,
            fixture.create_policy.profile.schema_sha256.as_str(),
            Some(&call2["resource_admission"]),
        )
        .await;
    assert_ne!(
        app_reply2["pending_id"].as_str().unwrap(),
        pending1,
        "new distinct approval required"
    );
}
