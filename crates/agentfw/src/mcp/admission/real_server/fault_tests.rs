// SPDX-License-Identifier: Apache-2.0
//! Controlled protocol faults against the real relay, not server acceptance.
//! Actual upstream execution and Linux containment are separate required tests.

use super::*;
use crate::mcp::admission::{AdmissionCfg, ReadTestDouble};
use crate::native::NativeState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, Request, ResponseTemplate,
};

type Reader = BufReader<ReadHalf<DuplexStream>>;
type Writer = WriteHalf<DuplexStream>;

#[tokio::test]
async fn selected_admission_errors_stay_bounded_without_echoing_private_bodies() {
    for (body, expected) in [
        (
            json!({"error_code":"native_fixture_refused","private":"private fixture payload"})
                .to_string(),
            "code=native_fixture_refused",
        ),
        (
            json!({"error_code":"private fixture payload"}).to_string(),
            "code=unavailable",
        ),
        (
            "private fixture payload".repeat(1024),
            "MCP admission response exceeds limit",
        ),
    ] {
        let daemon = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(409).set_body_string(body))
            .mount(&daemon)
            .await;
        let config =
            installed_registry_config(installed_registry_entries(server_profile::FORMAT)).unwrap();
        let collector = Collector::new(&config).unwrap();
        let error = collector
            .post(&daemon.uri(), "fixture-token", &json!({}))
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains("private fixture payload"));
    }
}

// Only unit-test builds have this task-local producer/completion seam. The
// real relay, native receipt transport, policy boundary and Linux publisher
// run unchanged; this is deterministic phase coverage, not upstream evidence.
#[cfg(target_os = "linux")]
struct CreateDriver {
    phase: &'static str,
    paused: AtomicBool,
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

#[cfg(target_os = "linux")]
tokio::task_local! { static CREATE_DRIVER: Arc<CreateDriver>; }

#[cfg(target_os = "linux")]
pub(super) fn controlled_create_output(
    args: &Value,
) -> Option<anyhow::Result<(Vec<u8>, Option<VerifiedOutput>)>> {
    CREATE_DRIVER
        .try_with(|_| {
            let output = crate::mcp::original_create::verified_test_output(args)?;
            let text = format!("Successfully wrote to {}", args["path"].as_str().unwrap());
            Ok((
                frame(&json!({"jsonrpc":"2.0","id":3,"result":{
            "content":[{"type":"text","text":text}],"structuredContent":{"content":text}}})),
                Some(output),
            ))
        })
        .ok()
}

#[cfg(target_os = "linux")]
pub(super) async fn pause_create_completion(phase: &str) {
    if let Ok(driver) = CREATE_DRIVER.try_with(Arc::clone) {
        if driver.phase == phase && !driver.paused.swap(true, Ordering::SeqCst) {
            driver.reached.notify_one();
            driver.resume.notified().await;
        }
    }
}

#[cfg(target_os = "linux")]
async fn create_phase_fixture(phase: &'static str) -> (Harness, Arc<CreateDriver>) {
    create_phase_fixture_with_fault(phase, "normal").await
}

#[cfg(target_os = "linux")]
async fn create_phase_fixture_with_fault(
    phase: &'static str,
    fault: &'static str,
) -> (Harness, Arc<CreateDriver>) {
    let driver = Arc::new(CreateDriver {
        phase,
        paused: AtomicBool::new(false),
        reached: tokio::sync::Notify::new(),
        resume: tokio::sync::Notify::new(),
    });
    let fixture = CREATE_DRIVER
        .scope(
            driver.clone(),
            Harness::for_format(fault, server_profile::filesystem_create::FORMAT),
        )
        .await;
    (fixture, driver)
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn original_create_daemon_size_refusal_cannot_authorize_publication() {
    let (mut fixture, _) = create_phase_fixture_with_fault("none", "create-result-cap").await;
    fixture.ready().await;
    fixture.host(json!({"jsonrpc":"2.0","id":"capped-create","method":"tools/call",
        "params":{"name":"write_file","arguments":{"path":"/workspace/refused.txt","content":"private"}}})).await;
    let refusal = fixture.host_reply().await;
    assert_eq!(refusal["id"], "capped-create");
    assert_eq!(
        refusal["error"]["message"],
        DaemonSizeLimit("native_record_over_cap").message()
    );
    assert_eq!(
        std::fs::read_dir(fixture.boundary_home.path().join("workspace"))
            .unwrap()
            .count(),
        0
    );
    fixture.useful(json!("useful-after-create-cap")).await;
    fixture.host(json!({"jsonrpc":"2.0","id":"capped-create","method":"tools/call",
        "params":{"name":"write_file","arguments":{"path":"/workspace/replay.txt","content":"private"}}})).await;
    assert_eq!(fixture.host_reply().await["error"]["code"], -32600);
    let inspected = completions(&fixture).await;
    assert_eq!(inspected.len(), 3);
    assert_eq!(inspected[0]["result_kind"], "value");
    assert_eq!(inspected[1]["result_kind"], "error");
    assert_eq!(inspected[0]["call_id"], inspected[1]["call_id"]);
    assert_eq!(
        std::fs::read_dir(fixture.boundary_home.path().join("workspace"))
            .unwrap()
            .count(),
        0
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn original_create_cancel_after_inspection_or_staging_never_publishes_and_continues() {
    for phase in ["inspected", "staged"] {
        let (mut fixture, driver) = create_phase_fixture(phase).await;
        fixture.ready().await;
        fixture.host(json!({"jsonrpc":"2.0","id":"cancel-write","method":"tools/call",
            "params":{"name":"write_file","arguments":{"path":"/workspace/cancelled.txt","content":"private"}}})).await;
        tokio::time::timeout(Duration::from_secs(5), driver.reached.notified())
            .await
            .unwrap();
        let workspace = fixture.boundary_home.path().join("workspace");
        let barrier = crate::policy_transition::Barrier::new(fixture.boundary_home.path()).unwrap();
        assert!(
            barrier.try_activation().unwrap().is_none(),
            "policy activation overtook the original-create {phase} boundary"
        );
        assert_eq!(std::fs::read_dir(&workspace).unwrap().count(), 0);
        fixture
            .host(json!({"jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":"cancel-write"}}))
            .await;
        assert_eq!(fixture.host_reply().await["error"]["code"], -32800);
        driver.resume.notify_one();
        fixture.useful(json!("useful-after-cancel")).await;
        // A spent ID cannot regain publication authority even for a different
        // leaf after the cancelled result has already spent its native grant.
        fixture.host(json!({"jsonrpc":"2.0","id":"cancel-write","method":"tools/call",
            "params":{"name":"write_file","arguments":{"path":"/workspace/replayed.txt","content":"private"}}})).await;
        assert_eq!(fixture.host_reply().await["error"]["code"], -32600);
        fixture.host(json!({"jsonrpc":"2.0","id":"fresh-write","method":"tools/call",
            "params":{"name":"write_file","arguments":{"path":"/workspace/fresh.txt","content":"continued"}}})).await;
        let reply = fixture.host_reply().await;
        assert!(reply.get("result").is_some(), "{phase}: {reply}");
        assert_eq!(
            std::fs::read_to_string(workspace.join("fresh.txt")).unwrap(),
            "continued"
        );
        assert!(!workspace.join("cancelled.txt").exists());
        assert!(!workspace.join("replayed.txt").exists());
        assert_eq!(std::fs::read_dir(workspace).unwrap().count(), 1);
        assert!(
            barrier.try_activation().unwrap().is_some(),
            "completed original creates leaked their policy boundary"
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn original_create_eof_after_inspection_or_staging_discards_output() {
    for phase in ["inspected", "staged"] {
        let (mut fixture, driver) = create_phase_fixture(phase).await;
        fixture.ready().await;
        fixture.host(json!({"jsonrpc":"2.0","id":"eof-write","method":"tools/call",
            "params":{"name":"write_file","arguments":{"path":"/workspace/eof.txt","content":"private"}}})).await;
        tokio::time::timeout(Duration::from_secs(5), driver.reached.notified())
            .await
            .unwrap();
        fixture.host_input.shutdown().await.unwrap();
        driver.resume.notify_one();
        tokio::time::timeout(Duration::from_secs(5), &mut fixture.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            std::fs::read_dir(fixture.boundary_home.path().join("workspace"))
                .unwrap()
                .count(),
            0
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn original_create_ask_requires_authenticated_owner_not_readonly_approval() {
    let mut fixture = Harness::for_format(
        "create-daemon-ask",
        server_profile::filesystem_create::FORMAT,
    )
    .await;
    fixture.ready().await;
    fixture.host(json!({"jsonrpc":"2.0","id":"write-ask","method":"tools/call",
        "params":{"name":"write_file","arguments":{"path":"/workspace/ask.txt","content":"private"}}})).await;
    let response = fixture.host_reply().await;
    assert_eq!(response["id"], "write-ask");
    assert!(
        response
            .to_string()
            .contains("native_approval_bound_owner_required"),
        "{response}"
    );
    assert!(!fixture
        .boundary_home
        .path()
        .join("workspace/ask.txt")
        .exists());
    assert!(!fixture
        .daemon
        .received_requests()
        .await
        .unwrap()
        .iter()
        .any(|request| request.url.path() == "/approval"));
    fixture.useful(json!("read-after-create-ask")).await;
}

#[tokio::test]
async fn selected_approval_never_rescues_empty_partial_unknown_or_failed_classification() {
    struct Evidence {
        actions: Vec<String>,
        unknown: bool,
        fail: bool,
    }
    impl super::super::InvocationClassifier for Evidence {
        fn source(&self) -> &'static str {
            "controlled-classification-evidence"
        }
        fn classify(
            &self,
            _: &super::super::Invocation,
        ) -> anyhow::Result<super::super::Classification> {
            ensure!(!self.fail, "controlled classifier failure");
            Ok(super::super::Classification {
                actions: self.actions.clone(),
                unknown: self.unknown,
                confidence: 1.0,
                uncertainty: 0.0,
                reason: "controlled boundary regression".into(),
            })
        }
    }
    for (actions, unknown, fail, approval) in [
        (vec![], false, false, true),
        (vec!["read".into()], true, false, true),
        (vec![], false, true, true),
        (vec![], false, false, false),
        (vec!["read".into()], true, false, false),
        (vec![], false, true, false),
    ] {
        let mut config =
            installed_registry_config(installed_registry_entries(server_profile::FORMAT)).unwrap();
        config.classifier = Some(Arc::new(Evidence {
            actions,
            unknown,
            fail,
        }));
        config.approval = approval.then(|| super::super::ApprovalWait {
            url: "http://127.0.0.1:1/never-reached".into(),
            wait: Duration::from_secs(1),
        });
        let collector = Collector::new(&config).unwrap();
        let definition = server_profile::original_manifest()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "read_text_file")
            .unwrap()
            .clone();
        let snapshot = Arc::new(Snapshot {
            sha256: "a".repeat(64),
            server_info: json!({}),
            tools: BTreeMap::from([(
                "read_text_file".into(),
                AdmittedTool {
                    description: definition["description"].as_str().unwrap().into(),
                    schema: definition["inputSchema"].clone(),
                    schema_sha256: sha(canonical(&definition["inputSchema"])
                        .to_string()
                        .as_bytes()),
                    definition_sha256: sha(canonical(&definition).to_string().as_bytes()),
                    definition,
                },
            )]),
        });
        let call = Call {
            profile: server_profile::FORMAT.into(),
            id: json!(81),
            tool: "read_text_file".into(),
            args: json!({"path":"/workspace/notes.txt"}),
            raw: vec![],
            request_sha256: "a".repeat(64),
            phase: Phase::Admitting,
            cancelled: false,
            cancel: tokio::sync::watch::channel(false).0,
            dispatched: false,
            deadline: Instant::now() + Duration::from_secs(2),
            progress: None,
            progress_count: 0,
            last_progress: 0.0,
            create_lease: None,
            #[cfg(target_os = "linux")]
            pinned_workspace: None,
        };
        let profile = server_profile::ProfileConfig {
            workspace_identity: None,
            format: call.profile.clone(),
            workspace: "/workspace".into(),
            runtime_path: "/never-spawned".into(),
            runtime_sha256: "a".repeat(64),
            package_root: "/never-spawned".into(),
            package_tree_sha256: "b".repeat(64),
            bwrap_path: "/never-spawned".into(),
            bwrap_sha256: "c".repeat(64),
            libraries: vec![],
            git: None,
            git_launcher: None,
        };
        let Decision::Refused(raw) = admit(&collector, snapshot, &call, &profile).await.unwrap()
        else {
            panic!("incomplete classification acquired a dispatch grant");
        };
        let text = String::from_utf8(raw).unwrap();
        assert!(
            text.contains(if fail {
                "classifier_error"
            } else if approval {
                "classifier_unknown_approval_unsupported"
            } else {
                "classifier_ask"
            }),
            "{text}"
        );
    }
}

#[tokio::test]
async fn selected_pending_approval_cancellation_rejection_and_timeout_close_exact_record() {
    for control in ["cancel", "reject", "timeout", "identity"] {
        let daemon = MockServer::start().await;
        Mock::given(method("POST")).and(path("/approval"))
            .respond_with(move |request: &Request| {
                let value: Value = serde_json::from_slice(&request.body).unwrap();
                let action = value["action"].as_str().unwrap();
                ResponseTemplate::new(200).set_body_json(json!({
                    "contract_version":crate::native::approval::APPROVAL_CONTRACT,
                    "action":action,"pending_id":if control == "identity" && action == "status" {"foreign"} else {"owned-pending"},
                    "state":if action == "status" && control == "reject" {"rejected"} else {"pending"},
                    "expires_in_ms":5000,"binding_sha256":"b".repeat(64)}))
            }).mount(&daemon).await;
        let mut config =
            installed_registry_config(installed_registry_entries(server_profile::FORMAT)).unwrap();
        config.approval = Some(super::super::ApprovalWait {
            url: format!("{}/approval", daemon.uri()),
            wait: Duration::from_millis(300),
        });
        let collector = Collector::new(&config).unwrap();
        let cancel = tokio::sync::watch::channel(false).0;
        let call = Call {
            profile: server_profile::FORMAT.into(),
            id: json!(81),
            tool: "read_text_file".into(),
            args: json!({"path":"/workspace/notes.txt"}),
            raw: vec![],
            request_sha256: "a".repeat(64),
            phase: Phase::Admitting,
            cancelled: false,
            cancel: cancel.clone(),
            dispatched: false,
            deadline: Instant::now() + Duration::from_secs(2),
            progress: None,
            progress_count: 0,
            last_progress: 0.0,
            create_lease: None,
            #[cfg(target_os = "linux")]
            pinned_workspace: None,
        };
        let context = crate::native::approval::SelectedInvocation {
            host_call_id: call.id.clone(),
            request_sha256: call.request_sha256.clone(),
            server_id: config.server_id.clone(),
            profile: call.profile.clone(),
            profile_sha256: "a".repeat(64),
            classifier_sha256: "b".repeat(64),
            snapshot_sha256: "c".repeat(64),
            definition_sha256: "d".repeat(64),
            input_sha256: "e".repeat(64),
            original_create: None,
        };
        let pending = wait_approval(&collector, &call, "daemon", "schema", &context);
        let cancelling = async {
            if control == "cancel" {
                tokio::time::sleep(Duration::from_millis(50)).await;
                cancel.send_replace(true);
            }
        };
        let (result, _) = tokio::join!(pending, cancelling);
        if control == "identity" {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        let requests = daemon.received_requests().await.unwrap();
        let bodies: Vec<Value> = requests
            .iter()
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect();
        assert_eq!(
            bodies
                .iter()
                .filter(|r| r["action"] == "cancel" && r["pending_id"] == "owned-pending")
                .count(),
            1
        );
        assert_eq!(bodies[0]["selected_invocation"], json!(context));
        assert_eq!(bodies[0]["args"], call.args);
    }
}

fn installed_registry_entries(format: &str) -> Vec<Value> {
    let manifest = server_profile::original_manifest_for(format).unwrap();
    let profiles = server_profile::classify_manifest_for(format, &manifest).unwrap();
    manifest["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| {
            let name = tool["name"].as_str().unwrap();
            let supported = profiles[name].unsupported_reason.is_none();
            let action = match name {
                "write_file" | "edit_file" | "create_directory" => "side_effecting",
                "move_file" => "destructive",
                _ if format == server_profile::git::FORMAT && !supported => "destructive",
                _ => "read_only",
            };
            let mut entry = json!({"name":name,
                "schema_sha256":sha(canonical(&tool["inputSchema"]).to_string().as_bytes()),
                "action_class":action,"result_provenance":"untrusted","egress":[]});
            if supported {
                entry["mcp_result_profile"] = json!(format);
            }
            entry
        })
        .collect()
}

fn installed_registry_config(tools: Vec<Value>) -> anyhow::Result<AdmissionCfg> {
    installed_registry_config_with_id(tools, "installed-shared-regression")
}

fn installed_registry_config_with_id(
    tools: Vec<Value>,
    registry_id: &str,
) -> anyhow::Result<AdmissionCfg> {
    let registry =
        json!({"contract_version":CONTRACT,"registry_id":registry_id,"tools":tools}).to_string();
    Ok(AdmissionCfg {
        host_session: None,
        child_authority: None,
        daemon_url: "http://127.0.0.1:1/native".into(),
        manifest_url: "http://127.0.0.1:1/manifest".into(),
        manifest_token: "never-used-test-token".into(),
        server_id: "installed-shared-regression".into(),
        native: NativeState::from_bytes(
            registry.as_bytes(),
            &sha(registry.as_bytes()),
            "test-token".into(),
        )?,
        command: "never-spawned".into(),
        args: vec![],
        classifier: None,
        resource_profiles: BTreeMap::new(),
        approval: None,
        liveness_url: None,
        liveness_lease_seconds: None,
    })
}

#[tokio::test]
async fn selected_registry_shared_daemon_accepts_both_exact_original_profiles() {
    for git_format in [
        server_profile::git::FORMAT,
        server_profile::git::LOCAL_REFS_FORMAT,
        server_profile::git::SHALLOW_FORMAT,
        server_profile::git_local_clone::FORMAT,
    ] {
        let formats = [server_profile::FORMAT, git_format];
        let tools = formats
            .into_iter()
            .flat_map(installed_registry_entries)
            .collect();
        let config = installed_registry_config(tools).unwrap();
        let collector = Collector::new(&config).unwrap();
        for format in formats {
            let manifest = server_profile::original_manifest_for(format).unwrap();
            let profiles = server_profile::classify_manifest_for(format, &manifest).unwrap();
            validate_registry(
                &collector,
                &profiles,
                manifest["tools"].as_array().unwrap(),
                format,
            )
            .expect(
                "a daemon registry may explicitly install both original read-only server families",
            );
        }
    }
}

#[tokio::test]
async fn selected_registry_shared_daemon_preserves_each_family_authority_and_schema_pins() {
    for (format, local_read, foreign_read) in [
        (server_profile::FORMAT, "read_text_file", "git_show"),
        (server_profile::git::FORMAT, "git_show", "read_text_file"),
    ] {
        let original: Vec<_> = [server_profile::FORMAT, server_profile::git::FORMAT]
            .into_iter()
            .flat_map(installed_registry_entries)
            .collect();
        let manifest = server_profile::original_manifest_for(format).unwrap();
        let profiles = server_profile::classify_manifest_for(format, &manifest).unwrap();
        for name in [local_read, foreign_read] {
            for (field, value) in [
                ("schema_sha256", json!("0".repeat(64))),
                ("action_class", json!("destructive")),
                ("result_provenance", json!("trusted")),
                ("mcp_result_profile", Value::Null),
                (
                    "mcp_result_profile",
                    json!(if name == "git_show" {
                        server_profile::FORMAT
                    } else {
                        server_profile::git::FORMAT
                    }),
                ),
                ("egress", json!(["https://owned.invalid"])),
            ] {
                let mut tools = original.clone();
                tools.iter_mut().find(|tool| tool["name"] == name).unwrap()[field] = value;
                if let Ok(config) = installed_registry_config(tools) {
                    let collector = Collector::new(&config).unwrap();
                    assert!(
                        validate_registry(
                            &collector,
                            &profiles,
                            manifest["tools"].as_array().unwrap(),
                            format
                        )
                        .is_err(),
                        "{format} accepted weakened {field} for {name}"
                    );
                }
            }
        }
        let mut missing = original.clone();
        missing.retain(|tool| tool["name"] != local_read);
        let config = installed_registry_config(missing).unwrap();
        assert!(validate_registry(
            &Collector::new(&config).unwrap(),
            &profiles,
            manifest["tools"].as_array().unwrap(),
            format
        )
        .is_err());
        let mut unknown = original;
        unknown.push(
            json!({"name":"not_an_installed_original_tool","schema_sha256":"a".repeat(64),
            "action_class":"read_only","result_provenance":"untrusted","egress":[]}),
        );
        let config = installed_registry_config(unknown).unwrap();
        assert!(validate_registry(
            &Collector::new(&config).unwrap(),
            &profiles,
            manifest["tools"].as_array().unwrap(),
            format
        )
        .is_err());
    }
}

#[tokio::test]
async fn selected_registry_create_only_does_not_inherit_shared_daemon_peer_authority() {
    let format = server_profile::filesystem_create::FORMAT;
    let manifest = server_profile::original_manifest_for(format).unwrap();
    let profiles = server_profile::classify_manifest_for(format, &manifest).unwrap();
    let own = installed_registry_entries(format);
    for peer_format in [
        None,
        Some(server_profile::git::FORMAT),
        Some(server_profile::git::LOCAL_REFS_FORMAT),
        Some(server_profile::git::SHALLOW_FORMAT),
        Some(server_profile::git_local_clone::FORMAT),
    ] {
        let mut tools = own.clone();
        if let Some(peer_format) = peer_format {
            let peer = installed_registry_entries(peer_format)
                .into_iter()
                .find(|tool| tool["name"] == "git_show")
                .unwrap();
            tools.push(peer);
        }
        let config = installed_registry_config_with_id(tools, "filesystem-create-only-v1")
            .expect("native loader must accept these individually pinned tool entries");
        let collector = Collector::new(&config).unwrap();
        let result = validate_registry(
            &collector,
            &profiles,
            manifest["tools"].as_array().unwrap(),
            format,
        );
        if peer_format.is_some() {
            assert_eq!(
                result.unwrap_err().to_string(),
                "selected registry contains an unadvertised tool"
            );
        } else {
            result.expect("exact original create-only registry must remain supported");
        }
    }
}

#[derive(Default)]
struct WriteGate {
    blocked: AtomicBool,
    reached: AtomicBool,
    waker: futures_util::task::AtomicWaker,
}

impl WriteGate {
    fn block(&self) {
        self.reached.store(false, Ordering::SeqCst);
        self.blocked.store(true, Ordering::SeqCst);
    }
    fn release(&self) {
        self.blocked.store(false, Ordering::SeqCst);
        self.waker.wake();
    }
    async fn wait(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !self.reached.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("relay reached the physical write boundary");
    }
}

struct GatedWriter(Writer, Arc<WriteGate>);

impl AsyncWrite for GatedWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.1.waker.register(cx.waker());
        if self.1.blocked.load(Ordering::SeqCst) {
            self.1.reached.store(true, Ordering::SeqCst);
            return Poll::Pending;
        }
        Pin::new(&mut self.0).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

struct Harness {
    format: &'static str,
    host_input: Writer,
    host_output: Reader,
    server_input: Reader,
    server_output: Writer,
    task: JoinHandle<anyhow::Result<()>>,
    daemon: MockServer,
    boundary_home: tempfile::TempDir,
    dispatch_gate: Arc<WriteGate>,
    release_gate: Arc<WriteGate>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Harness {
    async fn new(fault: &'static str) -> Self {
        Self::for_format(fault, server_profile::FORMAT).await
    }
    async fn for_format(fault: &'static str, format: &'static str) -> Self {
        let boundary_home = tempfile::tempdir().unwrap();
        let daemon = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/manifest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"verdict":"allow","enforce":true,"reason":null})),
            )
            .mount(&daemon)
            .await;
        let grants = Arc::new(Mutex::new(BTreeMap::<String, String>::new()));
        Mock::given(method("POST")).and(path("/native"))
            .respond_with(move |request:&Request| {
                let value:Value=serde_json::from_slice(&request.body).unwrap();
                if fault=="daemon-loss" && value["event"]=="call" { return ResponseTemplate::new(503); }
                if fault == "create-daemon-ask" && value["event"] == "call" && value["tool"] == "write_file" {
                    return ResponseTemplate::new(200).set_body_json(json!({
                        "contract_version":CONTRACT,"registry_sha256":value["registry_sha256"],
                        "session_id":value["session_id"],"event":"call","verdict":"ask",
                        "enforced":true,"release":false,"call_id":null,"binding_sha256":null,
                        "content_sha256":null,"reason_codes":["fixture_native_ask"]}));
                }
                let allowed=value["args"]["path"]!="/workspace/deny";
                let mut receipt=json!({"contract_version":CONTRACT,"registry_sha256":value["registry_sha256"],
                    "session_id":value["session_id"],"event":value["event"],"verdict":if allowed{"allow"}else{"deny"},
                    "enforced":true,"release":allowed,"call_id":null,"binding_sha256":null,"content_sha256":null,
                    "reason_codes":if allowed{json!([])}else{json!(["fixture_native_deny"])}});
                if value["event"]=="call" && allowed {
                    let binding=sha(canonical(&value).to_string().as_bytes());
                    let call_id=format!("fault-{}",&binding[..24]);
                    grants.lock().unwrap().insert(call_id.clone(),binding.clone());
                    receipt["call_id"]=json!(call_id);receipt["binding_sha256"]=json!(binding);
                } else if value["event"]=="result" {
                    if (fault=="record-cap" && value["content"].as_str().unwrap().contains("OVER_DAEMON_RECORD"))
                        || (fault=="create-result-cap" && value["tool"]=="write_file" && value["result_kind"]=="value") {
                        // Refused before any state change; the grant stays unspent.
                        return ResponseTemplate::new(413).set_body_json(json!({"contract_version":CONTRACT,"release":false,"error_code":"native_record_over_cap"}));
                    }
                    let call_id=value["call_id"].as_str().unwrap();
                    let binding=grants.lock().unwrap().remove(call_id).expect("one independently correlated grant per result");
                    receipt["call_id"]=value["call_id"].clone();receipt["binding_sha256"]=json!(binding);
                    receipt["content_sha256"]=json!(sha(value["content"].as_str().unwrap().as_bytes()));
                }
                let response=ResponseTemplate::new(200).set_body_json(receipt);
                if fault=="stalled-admission" && value["event"]=="call" {response.set_delay(Duration::from_secs(60))} else {response}
            }).mount(&daemon).await;
        let manifest = server_profile::original_manifest();
        let mut tools=manifest["tools"].as_array().unwrap().iter().map(|tool| {
            let unsupported=matches!(tool["name"].as_str().unwrap(),"write_file"|"edit_file"|"create_directory"|"move_file"|"read_media_file");
            let mut entry=json!({"name":tool["name"],"schema_sha256":sha(canonical(&tool["inputSchema"]).to_string().as_bytes()),"action_class":"read_only","result_provenance":"untrusted","egress":[]});
            if !unsupported {entry["mcp_result_profile"]=json!(server_profile::FORMAT);}
            entry
        }).collect::<Vec<_>>();
        if format == server_profile::git::FORMAT
            || format == server_profile::filesystem_create::FORMAT
        {
            tools = installed_registry_entries(format);
        }
        if fault == "shared-registry" {
            tools.extend(installed_registry_entries(server_profile::git::FORMAT));
        }
        let registry_id = if format == server_profile::filesystem_create::FORMAT {
            "filesystem-create-only-v1"
        } else {
            "selected-relay-faults"
        };
        let registry = json!({"contract_version":CONTRACT,"registry_id":registry_id,"tools":tools})
            .to_string();
        let native = NativeState::from_bytes(
            registry.as_bytes(),
            &sha(registry.as_bytes()),
            "fault-test-token".into(),
        )
        .unwrap()
        .with_policy_barrier(boundary_home.path())
        .unwrap();
        let config = AdmissionCfg {
            host_session: None,
            child_authority: None,
            daemon_url: format!("{}/native", daemon.uri()),
            manifest_url: format!("{}/manifest", daemon.uri()),
            manifest_token: "fault-manifest-token".into(),
            server_id: "selected-relay-faults".into(),
            native,
            command: "never-spawned".into(),
            args: vec![],
            classifier: Some(if format == server_profile::filesystem_create::FORMAT {
                Arc::new(crate::mcp::admission::FixtureTestDouble)
            } else {
                Arc::new(ReadTestDouble)
            }),
            resource_profiles: BTreeMap::new(),
            approval: (fault == "create-daemon-ask").then(|| super::super::ApprovalWait {
                url: format!("{}/approval", daemon.uri()),
                wait: Duration::from_millis(300),
            }),
            liveness_url: None,
            liveness_lease_seconds: None,
        };
        let (host, relay_host) = tokio::io::duplex(1024 * 1024);
        let (server, relay_server) = tokio::io::duplex(1024 * 1024);
        let (host_read, host_input) = tokio::io::split(host);
        let (server_read, server_output) = tokio::io::split(server);
        let (relay_client, relay_host) = tokio::io::split(relay_host);
        let (relay_server, relay_child) = tokio::io::split(relay_server);
        let dispatch_gate = Arc::new(WriteGate::default());
        let release_gate = Arc::new(WriteGate::default());
        let mut relay_child = GatedWriter(relay_child, dispatch_gate.clone());
        let mut relay_host = GatedWriter(relay_host, release_gate.clone());
        let workspace = boundary_home.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        #[cfg(target_os = "linux")]
        let create_driver = CREATE_DRIVER.try_with(Arc::clone).ok();
        let run = async move {
            let collector = Collector::new(&config)?;
            // Protocol-only fixture: this profile is never spawned or used to
            // qualify approval resumption / Linux filesystem confinement.
            let profile = server_profile::ProfileConfig {
                workspace_identity: None,
                format: format.into(),
                workspace,
                runtime_path: "/never-spawned/runtime".into(),
                runtime_sha256: "0".repeat(64),
                package_root: "/never-spawned/package".into(),
                package_tree_sha256: "0".repeat(64),
                bwrap_path: "/never-spawned/bwrap".into(),
                bwrap_sha256: "0".repeat(64),
                libraries: vec![],
                git: None,
                git_launcher: None,
            };
            relay(
                &collector,
                &mut BufReader::new(relay_client),
                &mut relay_host,
                &mut BufReader::new(relay_server),
                &mut relay_child,
                &profile,
                None,
            )
            .await
        };
        #[cfg(target_os = "linux")]
        let task = tokio::spawn(async move {
            if let Some(driver) = create_driver {
                return CREATE_DRIVER.scope(driver, run).await;
            }
            run.await
        });
        #[cfg(not(target_os = "linux"))]
        let task = tokio::spawn(run);
        Self {
            format,
            host_input,
            host_output: BufReader::new(host_read),
            server_input: BufReader::new(server_read),
            server_output,
            task,
            daemon,
            boundary_home,
            dispatch_gate,
            release_gate,
        }
    }
    async fn host(&mut self, value: Value) {
        self.host_input.write_all(&frame(&value)).await.unwrap();
    }
    async fn server(&mut self, value: Value) {
        self.server_output.write_all(&frame(&value)).await.unwrap();
    }
    async fn read(reader: &mut Reader) -> Option<Value> {
        let mut line = String::new();
        let read = tokio::time::timeout(Duration::from_secs(8), reader.read_line(&mut line))
            .await
            .expect("bounded relay exchange")
            .unwrap();
        if read == 0 {
            None
        } else {
            Some(serde_json::from_str(&line).unwrap())
        }
    }
    async fn host_reply(&mut self) -> Value {
        Self::read(&mut self.host_output).await.expect("host reply")
    }
    async fn dispatched(&mut self) -> Value {
        Self::read(&mut self.server_input)
            .await
            .expect("server dispatch")
    }
    async fn ready(&mut self) {
        self.host(json!({"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fault-test","version":"1"}}})).await;
        assert_eq!(self.dispatched().await["id"], "init");
        let initialization = if self.format == server_profile::git::FORMAT {
            serde_json::from_str::<Value>(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../profiles/mcp/git-readonly-v1/upstream-initialize.json"
            )))
            .unwrap()["result"]
                .clone()
        } else {
            json!({"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"secure-filesystem-server","version":"0.2.0"}})
        };
        self.server(json!({"jsonrpc":"2.0","id":"init","result":initialization}))
            .await;
        assert_eq!(self.host_reply().await["id"], "init");
        self.host(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        assert_eq!(
            self.dispatched().await["method"],
            "notifications/initialized"
        );
        self.host(json!({"jsonrpc":"2.0","id":"list","method":"tools/list","params":{}}))
            .await;
        assert_eq!(self.dispatched().await["method"], "tools/list");
        self.server(
            json!({"jsonrpc":"2.0","id":"list","result":server_profile::original_manifest_for(self.format).unwrap()}),
        )
        .await;
        assert_eq!(
            self.host_reply().await["result"]["tools"]
                .as_array()
                .unwrap()
                .len(),
            if self.format == server_profile::git::FORMAT {
                12
            } else {
                14
            }
        );
    }
    async fn call(&mut self, id: Value, path: &str) {
        self.host(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":path}}})).await;
    }
    async fn useful(&mut self, id: Value) {
        self.call(id.clone(), "/workspace/useful").await;
        assert_eq!(self.dispatched().await["id"], id);
        let original = json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"useful original"}],"structuredContent":{"content":"useful original"}}});
        self.server(original.clone()).await;
        assert_eq!(self.host_reply().await, original);
    }
    async fn failed(&mut self) -> String {
        tokio::time::timeout(Duration::from_secs(8), &mut self.task)
            .await
            .expect("relay must terminate")
            .unwrap()
            .unwrap_err()
            .to_string()
    }
}

#[tokio::test]
async fn selected_registry_shared_daemon_does_not_dispatch_foreign_tools_through_filesystem() {
    let mut fixture = Harness::new("shared-registry").await;
    fixture.ready().await;
    fixture
        .host(json!({"jsonrpc":"2.0","id":"foreign","method":"tools/call",
        "params":{"name":"git_show","arguments":{"repo_path":"/workspace","revision":"HEAD"}}}))
        .await;
    let refused = fixture.host_reply().await;
    assert_eq!(refused["id"], "foreign");
    assert_eq!(refused["error"]["code"], -32601);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), fixture.server_input.fill_buf())
            .await
            .is_err(),
        "an unadvertised foreign tool reached the filesystem server"
    );
    assert!(
        !fixture
            .daemon
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| {
                request.url.path() == "/native"
                    && serde_json::from_slice::<Value>(&request.body).unwrap()["event"] == "call"
            }),
        "a foreign tool acquired native call authority through this collector"
    );
    fixture.useful(json!("useful-after-foreign-refusal")).await;
}

#[tokio::test]
async fn managed_transition_cannot_overtake_dispatch_or_host_result_write() {
    let mut fixture = Harness::new("ordinary").await;
    fixture.ready().await;
    let barrier = crate::policy_transition::Barrier::new(fixture.boundary_home.path()).unwrap();
    fixture.dispatch_gate.block();
    fixture.call(json!("transition"), "/workspace/useful").await;
    fixture.dispatch_gate.wait().await;
    assert!(
        barrier.try_activation().unwrap().is_none(),
        "activation overtook an undispatched Allow"
    );
    fixture.dispatch_gate.release();
    assert_eq!(fixture.dispatched().await["id"], "transition");
    // Once the full request was written, a switch may proceed while the
    // original server works. That dispatched read is never called undone.
    let activation = barrier
        .try_activation()
        .unwrap()
        .expect("dispatched work no longer blocks activation");
    drop(activation);
    fixture.release_gate.block();
    fixture.server(json!({"jsonrpc":"2.0","id":"transition","result":{"content":[{"type":"text","text":"useful original"}],"structuredContent":{"content":"useful original"}}})).await;
    fixture.release_gate.wait().await;
    assert!(
        barrier.try_activation().unwrap().is_none(),
        "activation overtook inspected but unreleased content"
    );
    fixture.release_gate.release();
    assert_eq!(fixture.host_reply().await["id"], "transition");
    assert!(barrier.try_activation().unwrap().is_some());
}

#[tokio::test]
async fn selected_fault_unknown_and_duplicate_response_ids_never_release_payload() {
    for duplicate in [false, true] {
        let mut fixture = Harness::new("ordinary").await;
        fixture.ready().await;
        if duplicate {
            fixture.useful(json!(1)).await;
        }
        fixture.server(json!({"jsonrpc":"2.0","id":if duplicate{json!(1)}else{json!("unknown")},"result":{"content":[{"type":"text","text":"UNADMITTED_PAYLOAD"}],"structuredContent":{"content":"UNADMITTED_PAYLOAD"}}})).await;
        assert!(fixture.failed().await.contains("unknown or duplicate"));
        assert!(Harness::read(&mut fixture.host_output).await.is_none());
    }
}

#[tokio::test]
async fn selected_fault_progress_logging_and_reverse_callbacks_have_no_release_channel() {
    let mut fixture = Harness::new("ordinary").await;
    fixture.ready().await;
    fixture.server(json!({"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"UNINSPECTED_LOG_PAYLOAD"}})).await;
    fixture.server(json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"unknown","progress":1,"message":"UNINSPECTED_PROGRESS_PAYLOAD"}})).await;
    fixture.server(json!({"jsonrpc":"2.0","id":"callback","method":"sampling/createMessage","params":{"messages":[{"content":"UNINSPECTED_CALLBACK_PAYLOAD"}]}})).await;
    let refusal = fixture.dispatched().await;
    assert_eq!(refusal["id"], "callback");
    assert_eq!(refusal["error"]["code"], -32601);
    fixture.useful(json!("followup")).await;
}

#[tokio::test]
async fn selected_fault_unsupported_output_tool_and_native_refusal_preserve_useful_peer() {
    let mut fixture = Harness::new("ordinary").await;
    fixture.ready().await;
    fixture.host(json!({"jsonrpc":"2.0","id":"unsupported","method":"tools/call","params":{"name":"read_media_file","arguments":{"path":"/workspace/picture"}}})).await;
    assert_eq!(fixture.host_reply().await["error"]["code"], -32601);
    fixture.call(json!("denied"), "/workspace/deny").await;
    assert_eq!(fixture.host_reply().await["result"]["isError"], true);
    fixture.call(json!("bad-output"), "/workspace/read").await;
    assert_eq!(fixture.dispatched().await["id"], "bad-output");
    fixture.server(json!({"jsonrpc":"2.0","id":"bad-output","result":{"content":[{"type":"text","text":"PARTIAL_PAYLOAD"}],"structuredContent":{"hidden":"UNINSPECTED_PAYLOAD"}}})).await;
    let refusal = fixture.host_reply().await;
    assert_eq!(refusal["error"]["code"], -32603);
    assert!(!refusal.to_string().contains("PAYLOAD"));
    fixture.useful(json!("followup")).await;
}

#[tokio::test]
async fn selected_fault_daemon_loss_never_dispatches_the_call() {
    let mut fixture = Harness::new("daemon-loss").await;
    fixture.ready().await;
    fixture.call(json!("lost"), "/workspace/read").await;
    assert!(fixture.failed().await.contains("rejected"));
    assert!(Harness::read(&mut fixture.server_input).await.is_none());
    assert!(Harness::read(&mut fixture.host_output).await.is_none());
}

#[tokio::test]
async fn selected_fault_overload_and_queued_cancellation_are_correlated_without_execution() {
    let mut fixture = Harness::new("stalled-admission").await;
    fixture.ready().await;
    for n in 0..ACTIVE_LIMIT {
        fixture.call(json!(n), "/workspace/read").await;
    }
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let requests = fixture.daemon.received_requests().await.unwrap();
            let calls = requests
                .iter()
                .filter(|r| {
                    serde_json::from_slice::<Value>(&r.body).is_ok_and(|v| v["event"] == "call")
                })
                .count();
            if calls == ACTIVE_LIMIT {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("all active native admissions must be independently observed");
    for n in 0..QUEUE_LIMIT {
        fixture.call(json!(100 + n), "/workspace/read").await;
    }
    fixture.call(json!("overload"), "/workspace/read").await;
    let refusal = fixture.host_reply().await;
    assert_eq!(refusal["id"], "overload");
    assert_eq!(refusal["error"]["code"], -32003);
    fixture
        .host(
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":100}}),
        )
        .await;
    let cancellation = fixture.host_reply().await;
    assert_eq!(cancellation["id"], 100);
    assert_eq!(cancellation["error"]["code"], -32800);
    let requests = fixture.daemon.received_requests().await.unwrap();
    assert_eq!(requests.iter().filter(|r|serde_json::from_slice::<Value>(&r.body).is_ok_and(|v|v["event"]=="call")).count(),ACTIVE_LIMIT);
    fixture.task.abort();
    let _ = (&mut fixture.task).await;
    assert!(
        Harness::read(&mut fixture.server_input).await.is_none(),
        "no call executed while native admissions were pending"
    );
}

#[tokio::test]
async fn selected_fault_actual_call_deadline_reclaims_grant_and_discards_late_reply() {
    let mut fixture = Harness::new("ordinary").await;
    fixture.ready().await;
    fixture.call(json!("timed-out"), "/workspace/read").await;
    assert_eq!(fixture.dispatched().await["id"], "timed-out");
    let mut line = String::new();
    tokio::time::timeout(
        crate::mcp::admission::IO_TIMEOUT + Duration::from_secs(3),
        fixture.host_output.read_line(&mut line),
    )
    .await
    .expect("the actual production call deadline must finish")
    .unwrap();
    let refusal: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(refusal["id"], "timed-out");
    assert_eq!(refusal["error"]["code"], -32001);
    let cancellation = fixture.dispatched().await;
    assert_eq!(cancellation["method"], "notifications/cancelled");
    assert_eq!(cancellation["params"]["requestId"], "timed-out");
    // The late original frame is independently supplied after the host has
    // observed timeout. It must not become a second response/release channel.
    fixture.server(json!({"jsonrpc":"2.0","id":"timed-out","result":{"content":[{"type":"text","text":"LATE_UNADMITTED_PAYLOAD"}],"structuredContent":{"content":"LATE_UNADMITTED_PAYLOAD"}}})).await;
    fixture.useful(json!("after-timeout")).await;
    let requests = fixture.daemon.received_requests().await.unwrap();
    let completions = requests
        .iter()
        .filter_map(|request| serde_json::from_slice::<Value>(&request.body).ok())
        .filter(|request| request["event"] == "result")
        .collect::<Vec<_>>();
    assert_eq!(
        completions.len(),
        2,
        "timeout spends its grant, independently of the useful peer"
    );
    assert!(completions.iter().all(|request| !request["content"]
        .as_str()
        .unwrap()
        .contains("LATE_UNADMITTED_PAYLOAD")));
}

#[tokio::test]
async fn selected_git_cancellation_drains_without_aborting_siblings_or_freeing_physical_slots() {
    let mut fixture = Harness::for_format("ordinary", server_profile::git::FORMAT).await;
    fixture.ready().await;
    for id in 0..WIRE_LIMIT {
        fixture
            .host(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":"git_show","arguments":{"repo_path":"/workspace","revision":"HEAD"}}}))
            .await;
        assert_eq!(fixture.dispatched().await["id"], id);
        fixture
            .host(json!({"jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":id}}))
            .await;
        let reply = fixture.host_reply().await;
        assert_eq!(reply["id"], id);
        assert_eq!(reply["error"]["code"], -32800);
    }
    fixture
        .host(json!({"jsonrpc":"2.0","id":"full","method":"tools/call",
        "params":{"name":"git_show","arguments":{"repo_path":"/workspace","revision":"HEAD"}}}))
        .await;
    let refused = fixture.host_reply().await;
    assert_eq!(refused["id"], "full");
    assert_eq!(refused["error"]["code"], -32003);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), fixture.server_input.fill_buf())
            .await
            .is_err(),
        "no cancellation or seventeenth physical request may reach the original Git server"
    );
    for id in 0..WIRE_LIMIT {
        fixture.server(json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"LATE_CANCELLED_GIT_PAYLOAD"}]}})).await;
    }
    // The useful peer can proceed only after actual original completions return
    // the physical capacity. A dropped local grant alone cannot free a slot.
    tokio::time::sleep(Duration::from_millis(100)).await;
    fixture
        .host(json!({"jsonrpc":"2.0","id":"peer","method":"tools/call",
        "params":{"name":"git_show","arguments":{"repo_path":"/workspace","revision":"HEAD"}}}))
        .await;
    assert_eq!(fixture.dispatched().await["id"], "peer");
    let result = json!({"jsonrpc":"2.0","id":"peer","result":{"content":[{"type":"text","text":"useful original Git peer"}]}});
    fixture.server(result.clone()).await;
    assert_eq!(
        fixture.host_reply().await,
        result,
        "late cancelled results must never reach the host"
    );
    let requests = fixture.daemon.received_requests().await.unwrap();
    let completions: Vec<Value> = requests
        .iter()
        .filter_map(|request| serde_json::from_slice(&request.body).ok())
        .filter(|request: &Value| request["event"] == "result")
        .collect();
    assert_eq!(
        completions.len(),
        WIRE_LIMIT + 2,
        "all cancelled/refused grants and the useful peer complete exactly once"
    );
    assert!(completions.iter().all(|request| !request["content"]
        .as_str()
        .unwrap()
        .contains("LATE_CANCELLED_GIT_PAYLOAD")));
}

#[tokio::test]
async fn selected_git_withdrawn_nonresponding_request_keeps_its_original_deadline() {
    let mut fixture = Harness::for_format("ordinary", server_profile::git::FORMAT).await;
    fixture.ready().await;
    fixture
        .host(json!({"jsonrpc":"2.0","id":"hung","method":"tools/call",
        "params":{"name":"git_show","arguments":{"repo_path":"/workspace","revision":"HEAD"}}}))
        .await;
    assert_eq!(fixture.dispatched().await["id"], "hung");
    fixture.host(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"hung"}})).await;
    assert_eq!(fixture.host_reply().await["error"]["code"], -32800);
    let error = tokio::time::timeout(
        crate::mcp::admission::IO_TIMEOUT + Duration::from_secs(3),
        &mut fixture.task,
    )
    .await
    .expect("withdrawal must not remove the physical work deadline")
    .unwrap()
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "MCP server did not finish a withdrawn request within its bound"
    );
    assert!(
        Harness::read(&mut fixture.server_input).await.is_none(),
        "no abort notification reached the pinned Git SDK"
    );
}

#[tokio::test]
async fn selected_fault_original_call_and_result_bytes_remain_untouched() {
    let mut fixture = Harness::new("ordinary").await;
    fixture.ready().await;
    let original_call = concat!(
        r#"{ "jsonrpc" : "2.0", "id" : "bytes", "method" : "tools/call", "params" : { "name" : "read_text_file", "arguments" : { "path" : "/workspace/café.txt" } } }"#,
        "\n"
    );
    fixture
        .host_input
        .write_all(original_call.as_bytes())
        .await
        .unwrap();
    let mut observed_call = String::new();
    tokio::time::timeout(
        Duration::from_secs(8),
        fixture.server_input.read_line(&mut observed_call),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(observed_call.as_bytes(), original_call.as_bytes());
    let original_result = concat!(
        r#"{ "id" : "bytes", "result" : { "structuredContent" : { "content" : "original caf\u00e9\n" }, "content" : [ { "text" : "original caf\u00e9\n", "type" : "text" } ] }, "jsonrpc" : "2.0" }"#,
        "\n"
    );
    fixture
        .server_output
        .write_all(original_result.as_bytes())
        .await
        .unwrap();
    let mut observed_result = String::new();
    tokio::time::timeout(
        Duration::from_secs(8),
        fixture.host_output.read_line(&mut observed_result),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(observed_result.as_bytes(), original_result.as_bytes());
    let requests = fixture.daemon.received_requests().await.unwrap();
    let result = requests
        .iter()
        .filter_map(|request| serde_json::from_slice::<Value>(&request.body).ok())
        .find(|request| request["event"] == "result")
        .unwrap();
    assert_eq!(
        result["content"], original_result,
        "native receipt binds the same original complete frame"
    );
}

#[tokio::test]
async fn selected_fault_exact_manifest_cannot_release_an_extra_error_channel() {
    let mut fixture = Harness::new("ordinary").await;
    fixture.ready().await;
    fixture
        .host(json!({"jsonrpc":"2.0","id":"refresh","method":"tools/list","params":{}}))
        .await;
    assert_eq!(fixture.dispatched().await["id"], "refresh");
    fixture.server(json!({"jsonrpc":"2.0","id":"refresh","result":server_profile::original_manifest(),"error":{"code":-1,"message":"UNINSPECTED_ERROR_PAYLOAD","data":{"instructions":"UNINSPECTED_ERROR_DATA"}}})).await;
    assert!(fixture
        .failed()
        .await
        .contains("exactly one result or error"));
    assert!(
        Harness::read(&mut fixture.host_output).await.is_none(),
        "the valid pinned manifest must not carry an uninspected parallel error channel"
    );
}

fn original_result(id: &Value, text: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":text}],"structuredContent":{"content":text}}})
}

/// Every native completion carried by the daemon, in order.
async fn completions(fixture: &Harness) -> Vec<Value> {
    fixture
        .daemon
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter_map(|request| serde_json::from_slice::<Value>(&request.body).ok())
        .filter(|request| request["event"] == "result")
        .collect()
}

#[tokio::test]
async fn large_results_within_budget_are_released_exactly_on_both_channels() {
    let mut fixture = Harness::new("ordinary").await;
    fixture.ready().await;
    let escaped = "quote \" back \\ tab \t nl \n ctl \u{1} кириллица 日本語 \u{1F963}\n";
    let mut texts = vec![
        "a".repeat(16_383),
        "a".repeat(16_384),
        "a".repeat(16_385),
        "b".repeat(20 * 1024),
        "c".repeat(60 * 1024),
        "d".repeat(120 * 1024),
        "e".repeat(server_profile::RESULT_TEXT_BYTES - 1),
        "f".repeat(server_profile::RESULT_TEXT_BYTES),
    ];
    let mut utf8 = escaped.repeat(120 * 1024 / escaped.len());
    utf8.truncate(utf8.floor_char_boundary(120 * 1024));
    texts.push(utf8);
    for (index, text) in texts.iter().enumerate() {
        let id = json!(format!("large-{index}"));
        fixture.call(id.clone(), "/workspace/large").await;
        assert_eq!(fixture.dispatched().await["id"], id);
        let original = original_result(&id, text);
        fixture.server(original.clone()).await;
        let released = fixture.host_reply().await;
        assert_eq!(released, original, "result {index} changed");
        assert_eq!(
            released["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .len(),
            text.len()
        );
    }
    let inspected = completions(&fixture).await;
    assert_eq!(inspected.len(), texts.len());
    for (request, text) in inspected.iter().zip(&texts) {
        // The complete original frame, both channels, reached inspection.
        let frame: Value = serde_json::from_str(request["content"].as_str().unwrap()).unwrap();
        assert_eq!(frame["result"]["structuredContent"]["content"], json!(text));
        assert_eq!(request["result_kind"], "value");
    }
    fixture.useful(json!("after-large")).await;
}

#[tokio::test]
async fn result_text_over_budget_is_withheld_correlated_and_the_session_continues() {
    let mut fixture = Harness::new("ordinary").await;
    fixture.ready().await;
    let over = "OVER_TEXT_PAYLOAD".repeat(server_profile::RESULT_TEXT_BYTES / 17 + 1);
    assert!(over.len() > server_profile::RESULT_TEXT_BYTES);
    for (index, (content, structured)) in [(over.as_str(), "small"), ("small", over.as_str())]
        .into_iter()
        .enumerate()
    {
        let id = json!(index);
        fixture.call(id.clone(), "/workspace/large").await;
        assert_eq!(fixture.dispatched().await["id"], id);
        fixture
            .server(
                json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":content}],
                "structuredContent":{"content":structured}}}),
            )
            .await;
        let refusal = fixture.host_reply().await;
        assert_eq!(refusal["id"], id);
        assert_eq!(refusal["error"]["code"], -32603);
        assert_eq!(refusal["error"]["message"], TEXT_BUDGET_MESSAGE);
        assert!(!refusal.to_string().contains("OVER_TEXT_PAYLOAD"));
        fixture.useful(json!(format!("after-text-{index}"))).await;
    }
    assert!(TEXT_BUDGET_MESSAGE.contains(&server_profile::RESULT_TEXT_BYTES.to_string()));
    let inspected = completions(&fixture).await;
    // Each refusal spent its own grant with a local error; nothing leaked.
    assert_eq!(inspected.len(), 4);
    assert!(inspected.iter().all(|request| !request["content"]
        .as_str()
        .unwrap()
        .contains("OVER_TEXT_PAYLOAD")));
}

#[tokio::test]
async fn oversized_frames_are_drained_withheld_and_later_calls_still_work() {
    let mut fixture = Harness::new("ordinary").await;
    fixture.ready().await;
    // Each text is within its budget, but JSON escaping of the duplicated
    // channels exceeds the envelope; then a 2 MiB file and a huge error.
    let quotes = "\"".repeat(server_profile::RESULT_TEXT_BYTES - 18) + "OVER_FRAME_PAYLOAD";
    assert_eq!(quotes.len(), server_profile::RESULT_TEXT_BYTES);
    let cases = [
        original_result(&json!("escaped"), &quotes),
        original_result(
            &json!(7),
            &"OVER_FRAME_PAYLOAD".repeat(2 * 1024 * 1024 / 18),
        ),
        json!({"jsonrpc":"2.0","id":"error","error":{"code":-32000,"message":"OVER_FRAME_PAYLOAD".repeat(70_000)}}),
    ];
    for (index, frame_value) in cases.iter().enumerate() {
        assert!(frame(frame_value).len() > server_profile::RESULT_FRAME_BYTES);
        let id = frame_value["id"].clone();
        fixture.call(id.clone(), "/workspace/huge").await;
        assert_eq!(fixture.dispatched().await["id"], id);
        fixture.server(frame_value.clone()).await;
        let refusal = fixture.host_reply().await;
        assert_eq!(refusal["id"], id);
        assert_eq!(refusal["error"]["message"], FRAME_BUDGET_MESSAGE);
        assert!(!refusal.to_string().contains("OVER_FRAME_PAYLOAD"));
        fixture.useful(json!(format!("after-frame-{index}"))).await;
    }
    assert!(FRAME_BUDGET_MESSAGE.contains(&server_profile::RESULT_FRAME_BYTES.to_string()));
    let inspected = completions(&fixture).await;
    assert_eq!(inspected.len(), 6);
    assert!(inspected
        .iter()
        .all(|request| request["content"].as_str().unwrap().len() < 1024
            || !request["content"]
                .as_str()
                .unwrap()
                .contains("OVER_FRAME_PAYLOAD")));
}

#[tokio::test]
async fn oversized_frame_correlates_among_concurrent_calls_and_late_cancelled_ones() {
    let mut fixture = Harness::new("ordinary").await;
    fixture.ready().await;
    for id in ["a", "b", "c"] {
        fixture.call(json!(id), "/workspace/large").await;
        assert_eq!(fixture.dispatched().await["id"], id);
    }
    // Cancel "c" first: its later oversized result is a late frame.
    fixture
        .host(
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"c"}}),
        )
        .await;
    let cancelled = fixture.host_reply().await;
    assert_eq!(cancelled["id"], "c");
    assert_eq!(cancelled["error"]["code"], -32800);
    assert_eq!(
        fixture.dispatched().await["method"],
        "notifications/cancelled"
    );
    let huge = "OVER_FRAME_PAYLOAD".repeat(1024 * 1024 / 18 + 1);
    fixture.server(original_result(&json!("c"), &huge)).await;
    fixture.server(original_result(&json!("b"), &huge)).await;
    let ordinary = original_result(&json!("a"), &"x".repeat(60 * 1024));
    fixture.server(ordinary.clone()).await;
    let mut replies = [fixture.host_reply().await, fixture.host_reply().await];
    replies.sort_by_key(|reply| reply["id"].as_str().unwrap().to_owned());
    assert_eq!(replies[0], ordinary);
    assert_eq!(replies[1]["id"], "b");
    assert_eq!(replies[1]["error"]["message"], FRAME_BUDGET_MESSAGE);
    fixture.useful(json!("after-concurrent")).await;
    // No second reply for the cancelled call ever reaches the host.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), fixture.host_output.fill_buf())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn oversized_frames_that_cannot_be_proven_fail_closed() {
    let huge = "q".repeat(server_profile::RESULT_FRAME_BYTES);
    let cases: Vec<(Vec<u8>, &str)> = vec![
        // Malformed inside the drained part.
        (
            {
                let mut raw = frame(&original_result(&json!("m"), &huge));
                let at = server_profile::RESULT_FRAME_BYTES + 100;
                raw[at] = b'"';
                raw
            },
            frames::MALFORMED_ERROR,
        ),
        // Unknown ID: valid framing but no admitted call.
        (
            frame(&original_result(&json!("nobody"), &huge)),
            "unknown or duplicate MCP response ID",
        ),
        // Not a response.
        (
            frame(
                &json!({"jsonrpc":"2.0","method":"notifications/message","params":{"data":huge}}),
            ),
            frames::MALFORMED_ERROR,
        ),
        // A response with no ID.
        (
            frame(&json!({"jsonrpc":"2.0","result":{"content":[{"type":"text","text":huge}]}})),
            frames::UNCORRELATED_ERROR,
        ),
        // Unterminated at EOF.
        (
            {
                let mut raw = frame(&original_result(&json!("m"), &huge));
                raw.pop();
                raw
            },
            frames::UNTERMINATED_ERROR,
        ),
    ];
    for (raw, expected) in cases {
        let mut fixture = Harness::new("ordinary").await;
        fixture.ready().await;
        fixture.call(json!("m"), "/workspace/large").await;
        assert_eq!(fixture.dispatched().await["id"], "m");
        let unterminated = !raw.ends_with(b"\n");
        // The relay may stop reading as soon as it refuses the frame.
        let _ = fixture.server_output.write_all(&raw).await;
        if unterminated {
            let _ = fixture.server_output.shutdown().await;
        }
        let failure = fixture.failed().await;
        assert!(
            failure.contains(expected),
            "expected {expected:?}, got {failure:?}"
        );
        // No payload byte reached the host on any failure.
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(
            Duration::from_millis(200),
            fixture.host_output.read_to_end(&mut rest),
        )
        .await;
        assert!(!String::from_utf8_lossy(&rest).contains("qqqq"));
    }
}

#[tokio::test]
async fn daemon_size_refusal_spends_the_grant_with_a_correlated_error() {
    let mut fixture = Harness::new("record-cap").await;
    fixture.ready().await;
    fixture.call(json!("capped"), "/workspace/large").await;
    assert_eq!(fixture.dispatched().await["id"], "capped");
    fixture
        .server(original_result(
            &json!("capped"),
            "OVER_DAEMON_RECORD payload",
        ))
        .await;
    let refusal = fixture.host_reply().await;
    assert_eq!(refusal["id"], "capped");
    assert_eq!(
        refusal["error"]["message"],
        DaemonSizeLimit("native_record_over_cap").message()
    );
    assert!(!refusal.to_string().contains("OVER_DAEMON_RECORD"));
    fixture.useful(json!("after-daemon-limit")).await;
    let inspected = completions(&fixture).await;
    // The refused original, its correlated replacement, then the peer.
    assert_eq!(inspected.len(), 3);
    assert_eq!(inspected[1]["result_kind"], "error");
    assert_eq!(inspected[0]["call_id"], inspected[1]["call_id"]);
}

#[tokio::test]
async fn path_refusals_name_their_boundary_without_dispatch_or_echo() {
    let mut fixture = Harness::new("ordinary").await;
    fixture.ready().await;
    for (index, (arguments, message)) in [
        (json!({"path":"/etc/passwd"}), PATH_OUTSIDE_MESSAGE),
        (
            json!({"path":"/workspace/../etc/passwd"}),
            PATH_SPELLING_MESSAGE,
        ),
        (json!({"path":"/workspace/a\\b"}), PATH_SPELLING_MESSAGE),
        (json!({"path":"C:/workspace/file"}), PATH_SPELLING_MESSAGE),
        (
            json!({"path":"/workspace/notes.txt","head":-1}),
            "MCP arguments violate the selected input profile",
        ),
        (
            json!({"path":7}),
            "MCP arguments violate the selected input profile",
        ),
        (
            json!({"path":"/workspace/notes.txt","command":"rm -rf /workspace"}),
            "MCP arguments violate the selected input profile",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let id = json!(format!("refused-{index}"));
        fixture
            .host(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"read_text_file","arguments":arguments}}))
            .await;
        let refusal = fixture.host_reply().await;
        assert_eq!(refusal["id"], id);
        assert_eq!(refusal["error"]["code"], -32602);
        assert_eq!(refusal["error"]["message"], message);
        for secret in ["passwd", "rm -rf", "a\\b"] {
            assert!(!refusal.to_string().contains(secret), "argument echoed");
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), fixture.server_input.fill_buf())
                .await
                .is_err(),
            "a refused path reached the original server"
        );
        fixture
            .useful(json!(format!("after-refused-{index}")))
            .await;
    }
    // A colon is an ordinary Linux name inside /workspace: dispatched exactly.
    fixture.call(json!("colon"), "/workspace/a:b.txt").await;
    let dispatched = fixture.dispatched().await;
    assert_eq!(dispatched["id"], "colon");
    assert_eq!(
        dispatched["params"]["arguments"]["path"],
        "/workspace/a:b.txt"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn original_create_approval_cannot_rescue_unknown_mixed_or_understated_classifier() {
    for marker in ["unknown", "mixed", "understate", "duplicate", "invalid"] {
        let mut fixture =
            Harness::for_format("normal", server_profile::filesystem_create::FORMAT).await;
        fixture.ready().await;
        fixture
            .host(
                json!({"jsonrpc":"2.0","id":"unclassified-write","method":"tools/call",
            "params":{"name":"write_file","arguments":{"path":"/workspace/refused.txt",
                "content":format!("classifier-fault-{marker}")}}}),
            )
            .await;
        let refused = fixture.host_reply().await;
        assert_eq!(refused["id"], "unclassified-write");
        let reason = if matches!(marker, "duplicate" | "invalid") {
            assert_eq!(refused["error"]["code"], -32603, "{marker}: {refused}");
            "classifier_invalid"
        } else if marker == "mixed" {
            "classifier_deny"
        } else {
            "classifier_ask"
        };
        if !matches!(marker, "duplicate" | "invalid") {
            assert_eq!(refused["result"]["isError"], true, "{marker}: {refused}");
        }
        assert!(refused.to_string().contains(reason), "{marker}: {refused}");
        assert_eq!(
            std::fs::read_dir(fixture.boundary_home.path().join("workspace"))
                .unwrap()
                .count(),
            0
        );
        let requests = fixture.daemon.received_requests().await.unwrap();
        assert!(
            !requests.iter().any(|request| {
                let value: Value = serde_json::from_slice(&request.body).unwrap();
                request.url.path() == "/approval"
                    || (value["event"] == "call" && value["tool"] == "write_file")
            }),
            "classification {marker} reached native write authority"
        );
        fixture.useful(json!("read-after-classifier-refusal")).await;
    }
}
