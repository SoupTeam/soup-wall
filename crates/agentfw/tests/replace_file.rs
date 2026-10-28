// SPDX-License-Identifier: Apache-2.0
#![cfg(target_os = "linux")]
//! Real router/native authorization controls; filesystem publication witnesses
//! additionally exercise the production stdio broker on native Ubuntu.
use agentfw::handlers::{AppState, Sessions};
use agentfw::mcp::replace_file;
use agentfw::mcp::resources::{EvidenceSource, ResourceEvidence};
use agentfw::native::resource::{self, Admission, Policy};
use agentfw::native::{canonical_digest, NativeState, CONTRACT};
use agentfw::{app, Config};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use soup_wall_agent::{AgentFirewall, AgentPolicySet, DEFAULT_TAINT_CAP};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    target: PathBuf,
    state: agentfw::Shared,
    registry: String,
    policy: Policy,
    args: Value,
    native_token: String,
    hook_token: String,
}
impl Fixture {
    fn new(action: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("output");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = root.join("result.txt");
        std::fs::write(&target, "old useful bytes\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let plan = replace_file::preview(&root, &target, "new useful bytes\n").unwrap();
        let args = json!({"path":"result.txt","content":"new useful bytes\n","old_sha256":plan.old_sha256,"old_identity":plan.old_identity});
        let policy_value = json!({"profile":{"server_id":"replacement-fixture","tool_name":"replace_result",
            "schema_sha256":"a".repeat(64),"selectors":[{"pointer":"/path","kind":"path"}]},
            "workspace":root,"cwd":root,"executor_sha256":replace_file::content_sha256(replace_file::PROFILE.as_bytes()),
            "classifier_sha256":"c".repeat(64),"allowed_resources":[{"kind":"path","canonical":target}],
            "execution":{"operation":"replace_file","action":"write","max_content_bytes":4096,
                "executor_profile":replace_file::PROFILE,"path_selector":"/path","content_selector":"/content",
                "response_contract":"sw-native/response/text/1","replacement":{
                    "contract_version":resource::replacement::POLICY_CONTRACT,"root":plan.root,
                    "writer_exclusion":replace_file::EXCLUSION,"old_sha256_selector":"/old_sha256","old_identity_selector":"/old_identity"}}});
        let policy: Policy = serde_json::from_value(policy_value.clone()).unwrap();
        let registry = json!({"contract_version":CONTRACT,"registry_id":"sou159-fixture","tools":[{
            "name":"replace_result","schema_sha256":"a".repeat(64),"action_class":"destructive",
            "result_provenance":"untrusted","egress":[],"resource_policy":policy_value}]});
        let bytes = serde_json::to_vec(&registry).unwrap();
        let registry = replace_file::content_sha256(&bytes);
        let home = dir.path().join(agentfw::token::generate());
        std::fs::create_dir(&home).unwrap();
        let native_token = agentfw::token::generate();
        let hook_token = agentfw::token::generate();
        let key = agentfw::grant::derive_key(&hook_token);
        let native = NativeState::from_bytes(&bytes, &registry, native_token.clone())
            .unwrap()
            .with_approval(&home, &key, 60)
            .unwrap();
        let yaml=format!("agent_policies:\n  - name: replacement-policy\n    when: {{ action_class: destructive }}\n    action: {action}\ndefault: allow\n");
        let state = Arc::new(AppState {
            native: Some(native),
            firewall: Mutex::new(AgentFirewall::new(
                AgentPolicySet::from_yaml(&yaml).unwrap(),
                DEFAULT_TAINT_CAP,
            )),
            sessions: Sessions::default(),
            audit: agentfw::audit::AuditSink::open(&home.join("audit.jsonl")).unwrap(),
            spans: agentfw::spans::SpanCache::new(64, 4096),
            judge: agentfw::judge::Judge::new(Default::default()),
            manifests: agentfw::mcp::store::ManifestStore::new(&home.join("manifests")),
            tools: agentfw::mcp::store::ToolRegistry::with_builtins(),
            grants: agentfw::grant::GrantStore::new(&home.join("grants")),
            grant_ledger: agentfw::grant::GrantLedger::open(&home.join("grants-spent.json")),
            grant_key: key,
            config: Config {
                enforce: true,
                ..Config::default()
            },
            token: hook_token.clone(),
        });
        Self {
            _dir: dir,
            home,
            target,
            state,
            registry,
            policy,
            args,
            native_token,
            hook_token,
        }
    }
    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let response = app(self.state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("authorization", format!("Bearer {}", self.native_token))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    async fn start(&self) {
        let (status,v)=self.post("/native/v1",json!({"contract_version":CONTRACT,"registry_sha256":self.registry,"session_id":"s1","event":"session_start"})).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert_eq!(v["release"], true);
    }
    fn admission(&self) -> Admission {
        Admission {
            server_id: self.policy.profile.server_id.clone(),
            host_call_id: json!(1),
            profile_sha256: canonical_digest(&serde_json::to_value(&self.policy.profile).unwrap()),
            executor_sha256: self.policy.executor_sha256.clone(),
            classifier_sha256: self.policy.classifier_sha256.clone(),
            snapshot_sha256: "d".repeat(64),
            definition_sha256: "e".repeat(64),
            input_sha256: "f".repeat(64),
            resources: vec![ResourceEvidence {
                pointer: "/path".into(),
                source: EvidenceSource::Argument,
                resource: self.policy.allowed_resources[0].clone(),
            }],
            execution: Some(resource::replacement::binding(&self.policy, &self.args).unwrap()),
            network: None,
            post: None,
            windows_read: None,
            macos_read: None,
        }
    }
    fn call(&self) -> Value {
        json!({"contract_version":resource::replacement::CONTRACT,"registry_sha256":self.registry,"session_id":"s1","event":"call",
        "tool":"replace_result","schema_sha256":"a".repeat(64),"args":self.args,"resource_admission":self.admission()})
    }
    fn publish(&self, id: &Value) -> Value {
        json!({"contract_version":resource::replacement::CONTRACT,"registry_sha256":self.registry,"session_id":"s1","event":"publish",
        "tool":"replace_result","args":self.args,"call_id":id})
    }
}

#[tokio::test]
async fn replacement_publication_is_live_bound_single_use_and_not_a_write() {
    let f = Fixture::new("allow");
    f.start().await;
    let (_, call) = f.post("/native/v1", f.call()).await;
    assert_eq!(call["release"], true, "{call}");
    let (_, gate) = f.post("/native/v1", f.publish(&call["call_id"])).await;
    assert_eq!(gate["release"], true, "{gate}");
    let (status, again) = f.post("/native/v1", f.publish(&call["call_id"])).await;
    assert_ne!(status, StatusCode::OK, "{again}");
    assert_eq!(
        std::fs::read_to_string(f.target).unwrap(),
        "old useful bytes\n"
    );
}
#[tokio::test]
async fn replacement_mismatched_publication_spends_the_call() {
    let f = Fixture::new("allow");
    f.start().await;
    let (_, call) = f.post("/native/v1", f.call()).await;
    let mut request = f.publish(&call["call_id"]);
    request["args"]["content"] = json!("different bytes");
    assert_ne!(f.post("/native/v1", request).await.0, StatusCode::OK);
    assert_ne!(
        f.post("/native/v1", f.publish(&call["call_id"])).await.0,
        StatusCode::OK
    );
}
#[tokio::test]
async fn replacement_session_end_revokes_publication() {
    let f = Fixture::new("allow");
    f.start().await;
    let (_, call) = f.post("/native/v1", f.call()).await;
    f.post("/native/v1",json!({"contract_version":CONTRACT,"registry_sha256":f.registry,"session_id":"s1","event":"session_end"})).await;
    assert_ne!(
        f.post("/native/v1", f.publish(&call["call_id"])).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn replacement_new_hard_deny_revokes_already_admitted_publication() {
    let f = Fixture::new("allow");
    f.start().await;
    let (_, call) = f.post("/native/v1", f.call()).await;
    assert_eq!(call["release"], true);
    *f.state.firewall.lock().unwrap()=AgentFirewall::new(AgentPolicySet::from_yaml(
        "agent_policies:\n  - name: changed-hard-deny\n    when: { action_class: destructive }\n    action: deny\ndefault: allow\n").unwrap(),DEFAULT_TAINT_CAP);
    assert_ne!(
        f.post("/native/v1", f.publish(&call["call_id"])).await.0,
        StatusCode::OK
    );
    assert_ne!(
        f.post("/native/v1", f.publish(&call["call_id"])).await.0,
        StatusCode::OK
    );
    assert_eq!(
        std::fs::read_to_string(&f.target).unwrap(),
        "old useful bytes\n"
    );
}
#[tokio::test]
async fn replacement_ask_freezes_digests_redacts_content_and_cannot_rescue_deny() {
    for action in ["ask", "deny"] {
        let f = Fixture::new(action);
        f.start().await;
        let (_, call) = f.post("/native/v1", f.call()).await;
        assert_eq!(call["release"], false, "{call}");
        let (status,pending)=f.post("/native/approval/v1",json!({"contract_version":CONTRACT,"registry_sha256":f.registry,"session_id":"s1",
            "action":"request","source":"daemon","tool":"replace_result","schema_sha256":"a".repeat(64),"args":f.args,"resource_admission":f.admission()})).await;
        if action == "deny" {
            assert_ne!(status, StatusCode::OK);
            continue;
        }
        assert_eq!(status, StatusCode::OK, "{pending}");
        let id = pending["pending_id"].as_str().unwrap();
        let inspected = agentfw::native::approval::operator_inspect(&f.home, id).unwrap();
        assert!(inspected.get("args").is_none());
        assert_eq!(
            inspected["resource_details"]["old_content_sha256"],
            f.args["old_sha256"]
        );
        assert_eq!(
            inspected["resource_details"]["new_content_sha256"],
            replace_file::content_sha256(b"new useful bytes\n")
        );
        agentfw::native::approval::operator_approve(
            &f.home,
            &f.hook_token,
            id,
            pending["binding_sha256"].as_str().unwrap(),
        )
        .unwrap();
        let mut request = f.call();
        request["approval_id"] = json!(id);
        let (_, call) = f.post("/native/v1", request.clone()).await;
        assert_eq!(call["release"], true, "{call}");
        let (_, gate) = f.post("/native/v1", f.publish(&call["call_id"])).await;
        assert_eq!(gate["release"], true, "{gate}");
        assert_ne!(f.post("/native/v1", request).await.1["release"], true);
    }
}
