// SPDX-License-Identifier: Apache-2.0
//! Production collector -> native router -> constrained executor acceptance.
//! Linux-only behavior is never enabled by environment variables.
use super::*;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

const ASK: &str = "egress_allowlist: [127.0.0.1]\nagent_policies:\n  - name: ask-read\n    when: { action_class: read_only }\n    action: ask\n  - name: ask-get\n    when: { action_class: network }\n    action: ask\ndefault: allow\n";
const DOCUMENT: &str = "SOU-88 protected document: 19 blue widgets.\n";

/// Observe actual reads without opening the protected file ourselves. Metadata
/// and O_PATH pinning do not produce IN_ACCESS; production read(2) does.
struct ReadWatch(OwnedFd);
impl ReadWatch {
    fn new(path: &Path) -> Self {
        // SAFETY: owns a fresh nonblocking fd; path is a live NUL-terminated leaf.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(fd >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert!(
            unsafe { libc::inotify_add_watch(fd.as_raw_fd(), path.as_ptr(), libc::IN_ACCESS) } >= 0
        );
        Self(fd)
    }
    fn accessed(&self) -> bool {
        let mut bytes = [0u8; 4096];
        // SAFETY: valid writable buffer and owned nonblocking descriptor.
        let count =
            unsafe { libc::read(self.0.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
        if count < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            false
        } else {
            assert!(count > 0);
            true
        }
    }
}

/// Separate receiver process owns the socket and append-only request ledger.
/// Uses the existing SOU-56 TLS fixture with normal CA and hostname validation.
struct Receiver {
    _dir: tempfile::TempDir,
    child: Child,
    ledger: std::path::PathBuf,
    port: u16,
    ca: String,
}
impl Receiver {
    async fn start() -> Self {
        let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let output = Command::new("python3").args(["-B", "-c",
            "import importlib.util,sys; from pathlib import Path; s=importlib.util.spec_from_file_location('tls',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.certificates(Path(sys.argv[2]))"])
            .arg(repo.join("scripts/verify-sou56-https-get.py"))
            .arg(dir.path().join("certs")).output().await.unwrap();
        assert!(
            output.status.success(),
            "TLS fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let ledger = dir.path().join("receiver.jsonl");
        let ready = dir.path().join("ready.json");
        let child = Command::new("python3")
            .arg("-B")
            .arg(repo.join("scripts/fixtures/mcp_https_get_probe_server.py"))
            .arg("--https")
            .arg("--ledger")
            .arg(&ledger)
            .arg("--ready")
            .arg(&ready)
            .arg("--cert")
            .arg(dir.path().join("certs/valid.pem"))
            .arg("--key")
            .arg(dir.path().join("certs/server.key"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let value: Value = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(bytes) = std::fs::read(&ready) {
                    break serde_json::from_slice(&bytes).unwrap();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let ca = std::fs::read_to_string(dir.path().join("certs/ca.pem")).unwrap();
        Self {
            _dir: dir,
            child,
            ledger,
            port: value["port"].as_u64().unwrap() as u16,
            ca,
        }
    }
    fn connections(&self) -> usize {
        executed(&self.ledger)
            .iter()
            .filter(|row| row["event"] == "connection")
            .count()
    }
    fn requests(&self) -> Vec<Value> {
        executed(&self.ledger)
            .into_iter()
            .filter(|row| row["event"] == "request")
            .collect()
    }
}

async fn fixture(receiver: Option<&Receiver>, ttl: u64) -> Fixture {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("rule_baseline/rule_baseline.py");
    let classifier = sha(&std::fs::read(script).unwrap());
    Fixture::with_resource_policy_custom_approval(
        if receiver.is_some() { "sou88-https" } else { "classified-read" }, true,
        Some("rule-baseline"), Some(ASK), Some((ttl, 10)), |dir, registry| {
            let workspace = dir.canonicalize().unwrap();
            let (name, schema, selector, kind, resource, network, executor) = if let Some(r) = receiver {
                let url = format!("https://127.0.0.1:{}/document?item=7", r.port);
                ("https_get", agentfw::native::resource::https_get_schema(), "/url", "url",
                    json!({"kind":"url","canonical":url,"host":"127.0.0.1","port":r.port}),
                    json!({"exact_url":url,"approved_addresses":["127.0.0.1"],
                        "private_endpoint":{"host":"127.0.0.1","port":r.port,"address":"127.0.0.1"},
                        "root_certificate_pem":r.ca}), agentfw::mcp::https_get::executor_profile_sha256())
            } else {
                let path = workspace.join("protected.txt");
                std::fs::write(&path, DOCUMENT).unwrap();
                ("read_document", json!({"type":"object","properties":{"path":{"type":"string"}},
                    "required":["path"],"additionalProperties":false}), "/path", "path",
                    json!({"kind":"path","canonical":path}), Value::Null,
                    sha(agentfw::native::resource::READ_DOCUMENT_EXECUTOR_PROFILE.as_bytes()))
            };
            let digest = sha(schema.to_string().as_bytes());
            registry["tools"][0] = json!({"name":name,"schema_sha256":digest,
                "action_class":if receiver.is_some() {"network"} else {"read_only"},
                "result_provenance":"untrusted",
                "egress":if receiver.is_some() {json!([{"pointer":"/url","kind":"url_host","optional":false}])} else {json!([])},
                "resource_policy":{"profile":{"server_id":"fixture","tool_name":name,"schema_sha256":digest,
                    "selectors":[{"pointer":selector,"kind":kind}]},"workspace":workspace,"cwd":workspace,
                    "executor_sha256":executor,"classifier_sha256":classifier,"network":network,
                    "allowed_resources":[resource]}});
        }).await
}

async fn acceptance(network: bool) {
    let mut receiver = if network {
        Some(Receiver::start().await)
    } else {
        None
    };
    for scenario in [
        "reject",
        "expired",
        "mutated",
        "cancelled",
        "duplicate-pending",
        "approved",
    ] {
        let mut f = fixture(
            receiver.as_ref(),
            if scenario == "expired" { 1 } else { 60 },
        )
        .await;
        f.ready().await;
        let path = f._dir.path().join("protected.txt");
        let watch = if network {
            None
        } else {
            Some(ReadWatch::new(&path))
        };
        let call = json!({"jsonrpc":"2.0","id":"protected-call","method":"tools/call",
            "params":{"name":if network {"https_get"} else {"read_document"},
                "arguments":if let Some(r) = receiver.as_ref() {
                    json!({"url":format!("https://127.0.0.1:{}/document?item=7",r.port)})
                } else {json!({"path":path})}}});
        let before = receiver.as_ref().map_or(0, |r| r.connections());
        let requests_before = receiver.as_ref().map_or(0, |r| r.requests().len());
        f.send_only(&call.to_string()).await;
        let row = f.wait_pending().await;
        let inspected = agentfw::native::approval::operator_inspect(
            &f.agent_home(),
            row["pending_id"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            inspected["resource_details"]["operation"],
            if network {
                "https_get"
            } else {
                "read_document"
            }
        );
        assert_eq!(
            receiver.as_ref().map_or(0, |r| r.connections()),
            before,
            "no preapproval socket"
        );
        if let Some(w) = &watch {
            assert!(!w.accessed(), "no preapproval protected read");
        }
        match scenario {
            "reject" => agentfw::native::approval::operator_reject(
                &f.agent_home(),
                row["pending_id"].as_str().unwrap(),
            )
            .unwrap(),
            "expired" => {
                // Hold the real redemption in transport until the *approved*
                // grant expires. No forged clock, status, or Allow response.
                f.daemon_faults
                    .stall_call_admission
                    .store(true, Ordering::SeqCst);
                operator_approve(&f, &row).unwrap();
                tokio::time::timeout(Duration::from_secs(2), async {
                    while f.daemon_faults.call_requests_started.load(Ordering::SeqCst) == 0 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("approved redemption reached transport hold");
                tokio::time::sleep(Duration::from_millis(1100)).await;
                f.daemon_faults
                    .stall_call_admission
                    .store(false, Ordering::SeqCst);
                f.daemon_faults.release_stalled_calls.notify_one();
            }
            "mutated" => {
                f.daemon_faults
                    .mutate_approved_args
                    .store(true, Ordering::SeqCst);
                operator_approve(&f, &row).unwrap();
            }
            "cancelled" => {
                f.send_only(
                    &json!({"jsonrpc":"2.0","method":"notifications/cancelled",
                "params":{"requestId":"protected-call","reason":"owned control"}})
                    .to_string(),
                )
                .await
            }
            "duplicate-pending" => f.send_only(&call.to_string()).await,
            "approved" => {
                operator_approve(&f, &row).unwrap();
                assert!(operator_approve(&f, &row).is_err());
            }
            _ => unreachable!(),
        }
        if matches!(scenario, "cancelled" | "duplicate-pending") {
            assert!(f.receive().await.is_none());
            f.assert_gateway_failed().await;
            assert!(
                operator_approve(&f, &row).is_err(),
                "closed session must invalidate pending authority"
            );
        } else {
            let reply: Value = serde_json::from_str(&f.receive().await.unwrap()).unwrap();
            assert_eq!(reply["id"], "protected-call");
            if scenario == "approved" {
                assert_ne!(reply["result"]["isError"], true, "{reply}");
                let text = reply["result"]["content"][0]["text"].as_str().unwrap();
                if network {
                    assert!(text.contains("SOU-56 owned HTTPS receiver"), "{reply}");
                } else {
                    assert_eq!(text, DOCUMENT);
                }
            } else {
                assert_eq!(reply["result"]["isError"], true, "{scenario}: {reply}");
                assert!(!reply.to_string().contains(DOCUMENT));
                let expected = match scenario {
                    "reject" => "native_approval_rejected",
                    "expired" => "native_approval_expired",
                    _ => "native_",
                };
                assert!(reply.to_string().contains(expected), "{scenario}: {reply}");
            }
        }
        let success = scenario == "approved";
        if let Some(w) = &watch {
            assert_eq!(w.accessed(), success, "{scenario}: protected byte access");
        }
        if let Some(r) = &receiver {
            assert_eq!(
                r.connections(),
                before + usize::from(success),
                "{scenario}: socket ledger"
            );
            let requests = r.requests();
            assert_eq!(
                requests.len(),
                requests_before + usize::from(success),
                "{scenario}: GET ledger"
            );
            if success {
                assert_eq!(requests.last().unwrap()["method"], "GET");
                assert_eq!(requests.last().unwrap()["target"], "/document?item=7");
            }
        }
        assert!(
            executed(&f.ledger).is_empty(),
            "child tool call dispatch forbidden"
        );
        if scenario == "mutated" {
            let original = f
                .daemon_faults
                .captured_calls
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|v| v["approval_id"].is_string())
                .unwrap()
                .clone();
            let response: Value = reqwest::Client::new()
                .post(format!("http://127.0.0.1:{}/native/v1", f.port))
                .bearer_auth(TOKEN)
                .json(&original)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(
                response["release"], false,
                "mutation must be terminal: {response}"
            );
            assert!(
                response.to_string().contains("native_approval_closed"),
                "{response}"
            );
            if let Some(w) = &watch {
                assert!(!w.accessed());
            }
            if let Some(r) = &receiver {
                assert_eq!(r.connections(), before);
            }
        }
        if success {
            // Replay the actual signed-approval request against the real router.
            let replay = f
                .daemon_faults
                .captured_calls
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|v| v["approval_id"].is_string())
                .unwrap()
                .clone();
            let reply: Value = reqwest::Client::new()
                .post(format!("http://127.0.0.1:{}/native/v1", f.port))
                .bearer_auth(TOKEN)
                .json(&replay)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(reply["release"], false, "{reply}");
            assert!(
                reply.to_string().contains("native_approval_spent"),
                "{reply}"
            );
            // A duplicate host request ID is fail-closed, not another execution.
            assert!(f.exchange(&call.to_string()).await.is_none());
            f.assert_gateway_failed().await;
            if let Some(w) = &watch {
                assert!(!w.accessed(), "replay read");
            }
            if let Some(r) = &receiver {
                assert_eq!(r.requests().len(), requests_before + 1);
                assert_eq!(r.connections(), before + 1);
            }
        } else if !matches!(scenario, "cancelled" | "duplicate-pending") {
            // Refusal must leave useful work possible, but never grant a blanket Allow.
            let mut next = call.clone();
            next["id"] = json!("useful-continuation");
            f.send_only(&next.to_string()).await;
            let next_row = f.wait_pending().await;
            assert_ne!(next_row["pending_id"], row["pending_id"]);
            operator_approve(&f, &next_row).unwrap();
            let reply: Value = serde_json::from_str(&f.receive().await.unwrap()).unwrap();
            assert_ne!(
                reply["result"]["isError"], true,
                "continuation after {scenario}: {reply}"
            );
            if let Some(w) = &watch {
                assert!(w.accessed());
            }
            if let Some(r) = &receiver {
                assert_eq!(r.requests().len(), requests_before + 1);
            }
        }
        assert!(executed(&f.ledger).is_empty());
        f.child.kill().await.ok();
        f.child.wait().await.unwrap();
        eprintln!(
            "SOU88_EXECUTION operation={} scenario={scenario} passed=true",
            if network {
                "https_get"
            } else {
                "read_document"
            }
        );
    }
    if let Some(r) = receiver.as_mut() {
        eprintln!(
            "SOU88_TLS_LEDGER {}",
            serde_json::to_string(&executed(&r.ledger)).unwrap()
        );
        r.child.kill().await.unwrap();
        r.child.wait().await.unwrap();
    }
}

#[tokio::test]
async fn sou88_read_document_real_executor_approval_controls() {
    acceptance(false).await;
}

#[tokio::test]
async fn sou88_https_get_real_tls_receiver_approval_controls() {
    acceptance(true).await;
}
