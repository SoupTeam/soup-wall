// SPDX-License-Identifier: Apache-2.0
//! Controlled protocol faults against the real relay, not server acceptance.
//! Actual upstream execution and Linux containment are separate required tests.

use super::*;
use crate::mcp::admission::{AdmissionCfg, ReadTestDouble};
use crate::native::NativeState;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, Request, ResponseTemplate,
};

type Reader = BufReader<ReadHalf<DuplexStream>>;
type Writer = WriteHalf<DuplexStream>;

struct Harness {
    host_input: Writer,
    host_output: Reader,
    server_input: Reader,
    server_output: Writer,
    task: JoinHandle<anyhow::Result<()>>,
    daemon: MockServer,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Harness {
    async fn new(fault: &'static str) -> Self {
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
                    let call_id=value["call_id"].as_str().unwrap();
                    let binding=grants.lock().unwrap().remove(call_id).expect("one independently correlated grant per result");
                    receipt["call_id"]=value["call_id"].clone();receipt["binding_sha256"]=json!(binding);
                    receipt["content_sha256"]=json!(sha(value["content"].as_str().unwrap().as_bytes()));
                }
                let response=ResponseTemplate::new(200).set_body_json(receipt);
                if fault=="stalled-admission" && value["event"]=="call" {response.set_delay(Duration::from_secs(60))} else {response}
            }).mount(&daemon).await;
        let manifest = server_profile::original_manifest();
        let tools=manifest["tools"].as_array().unwrap().iter().map(|tool| {
            let unsupported=matches!(tool["name"].as_str().unwrap(),"write_file"|"edit_file"|"create_directory"|"move_file"|"read_media_file");
            let mut entry=json!({"name":tool["name"],"schema_sha256":sha(canonical(&tool["inputSchema"]).to_string().as_bytes()),"action_class":"read_only","result_provenance":"untrusted","egress":[]});
            if !unsupported {entry["mcp_result_profile"]=json!(server_profile::FORMAT);}
            entry
        }).collect::<Vec<_>>();
        let registry=json!({"contract_version":CONTRACT,"registry_id":"selected-relay-faults","tools":tools}).to_string();
        let native = NativeState::from_bytes(
            registry.as_bytes(),
            &sha(registry.as_bytes()),
            "fault-test-token".into(),
        )
        .unwrap();
        let config = AdmissionCfg {
            daemon_url: format!("{}/native", daemon.uri()),
            manifest_url: format!("{}/manifest", daemon.uri()),
            manifest_token: "fault-manifest-token".into(),
            server_id: "selected-relay-faults".into(),
            native,
            command: "never-spawned".into(),
            args: vec![],
            classifier: Some(Arc::new(ReadTestDouble)),
            resource_profiles: BTreeMap::new(),
            approval: None,
        };
        let (host, relay_host) = tokio::io::duplex(1024 * 1024);
        let (server, relay_server) = tokio::io::duplex(1024 * 1024);
        let (host_read, host_input) = tokio::io::split(host);
        let (server_read, server_output) = tokio::io::split(server);
        let (relay_client, mut relay_host) = tokio::io::split(relay_host);
        let (relay_server, mut relay_child) = tokio::io::split(relay_server);
        let task = tokio::spawn(async move {
            let collector = Collector::new(&config)?;
            relay(
                &collector,
                &mut BufReader::new(relay_client),
                &mut relay_host,
                &mut BufReader::new(relay_server),
                &mut relay_child,
            )
            .await
        });
        Self {
            host_input,
            host_output: BufReader::new(host_read),
            server_input: BufReader::new(server_read),
            server_output,
            task,
            daemon,
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
        self.server(json!({"jsonrpc":"2.0","id":"init","result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"secure-filesystem-server","version":"0.2.0"}}})).await;
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
            json!({"jsonrpc":"2.0","id":"list","result":server_profile::original_manifest()}),
        )
        .await;
        assert_eq!(
            self.host_reply().await["result"]["tools"]
                .as_array()
                .unwrap()
                .len(),
            14
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
