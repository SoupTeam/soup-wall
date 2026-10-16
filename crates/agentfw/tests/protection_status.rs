// SPDX-License-Identifier: Apache-2.0
//! Runtime diagnostics through the real router and CLI; no provider or tool execution.
use agentfw::handlers::{AppState, Sessions};
use agentfw::protection_status::{
    self as status, Evidence, Expectations, Mode, Runtime, Snapshot, ENDPOINT, NONCE_HEADER,
};
use agentfw::{app_with_diagnostics, Config};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soup_wall_agent::{AgentFirewall, AgentPolicySet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;

const TOKEN: &str = "status-test-token-do-not-print";
const NATIVE_TOKEN: &str = "native-test-token-do-not-print";
static NONCE: std::sync::LazyLock<String> = std::sync::LazyLock::new(agentfw::token::generate);
const ALLOW: &str = "agent_policies: []\ndefault: allow\n";
const DENY: &str = "agent_policies: []\ndefault: deny\n";

struct Fixture {
    dir: tempfile::TempDir,
    state: agentfw::Shared,
    app: axum::Router,
}
impl Fixture {
    fn new(enforce: bool, native: bool) -> Self {
        Self::with_port(enforce, native, 8787)
    }
    fn with_port(enforce: bool, native: bool, port: u16) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let registry = serde_json::to_vec(
            &json!({"contract_version":"sw-native/1", "registry_id":"status-fixture",
            "tools":[{"name":"read_note","schema_sha256":"1".repeat(64),"action_class":"read_only",
            "result_provenance":"local_project","egress":[]}]}),
        )
        .unwrap();
        let sha = format!("{:x}", Sha256::digest(&registry));
        let registry_path = dir.path().join("registry.json");
        std::fs::write(&registry_path, &registry).unwrap();
        let policy_path = dir.path().join("policy.yaml");
        std::fs::write(&policy_path, ALLOW).unwrap();
        let config = Config {
            enforce,
            port,
            policy: Some(policy_path),
            native: native.then(|| agentfw::config::NativeCfg {
                registry_path,
                registry_sha256: sha.clone(),
                approval: None,
            }),
            ..Config::default()
        };
        let state = Arc::new(AppState {
            native: native.then(|| {
                agentfw::native::NativeState::from_bytes(&registry, &sha, NATIVE_TOKEN.into())
                    .unwrap()
            }),
            firewall: Mutex::new(AgentFirewall::new(
                AgentPolicySet::from_yaml(ALLOW).unwrap(),
                10,
            )),
            sessions: Sessions::default(),
            audit: agentfw::audit::AuditSink::open(&dir.path().join("audit.jsonl")).unwrap(),
            spans: agentfw::spans::SpanCache::new(64, 4096),
            judge: agentfw::judge::Judge::new(config.judge.clone()),
            manifests: agentfw::mcp::store::ManifestStore::new(&dir.path().join("manifests")),
            tools: agentfw::mcp::store::ToolRegistry::with_builtins(),
            grants: agentfw::grant::GrantStore::new(&dir.path().join("grants")),
            grant_ledger: agentfw::grant::GrantLedger::open(&dir.path().join("spent.json")),
            grant_key: agentfw::grant::derive_key(TOKEN),
            token: TOKEN.into(),
            config,
        });
        let runtime = Arc::new(Runtime::new(&state.config));
        let app = app_with_diagnostics(state.clone(), runtime.clone());
        Self { dir, state, app }
    }
    async fn get(&self) -> Snapshot {
        let (code, value) =
            request(self.app.clone(), ENDPOINT, Some(TOKEN), Some(&NONCE), None).await;
        assert_eq!(code, StatusCode::OK, "{value}");
        serde_json::from_value(value).unwrap()
    }
}
async fn request(
    app: axum::Router,
    path: &str,
    token: Option<&str>,
    nonce: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .uri(path)
        .method(if body.is_some() { "POST" } else { "GET" });
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    if let Some(nonce) = nonce {
        req = req.header(NONCE_HEADER, nonce);
    }
    let response = app
        .oneshot(
            req.body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    if path == ENDPOINT {
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    let bytes = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn status_requires_hook_auth_and_fresh_challenge() {
    let f = Fixture::new(true, true);
    for token in [None, Some("incorrect"), Some(NATIVE_TOKEN)] {
        let (code, body) = request(f.app.clone(), ENDPOINT, token, Some(&NONCE), None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert!(!body.to_string().contains(TOKEN));
        assert!(body.get("policy").is_none());
    }
    let (code, _) = request(f.app.clone(), ENDPOINT, Some(TOKEN), None, None).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    let s = f.get().await;
    status::validate(&s, &NONCE, status::now_ms(), &Expectations::default()).unwrap();
}

#[tokio::test]
async fn disk_policy_registry_and_config_changes_do_not_replace_runtime_evidence() {
    let f = Fixture::new(true, true);
    let before = f.get().await;
    std::fs::write(f.state.config.policy.as_ref().unwrap(), DENY).unwrap();
    std::fs::write(f.dir.path().join("config.yaml"), "enforce: false\n").unwrap();
    std::fs::remove_file(&f.state.config.native.as_ref().unwrap().registry_path).unwrap();
    let after = f.get().await;
    assert_eq!(before.policy.sha256, after.policy.sha256);
    assert_eq!(before.registry.sha256, after.registry.sha256);
    assert_eq!(
        before.runtime.loaded_config_sha256,
        after.runtime.loaded_config_sha256
    );
    assert_eq!(after.mode, Mode::Enforcing);
    f.state
        .firewall
        .lock()
        .unwrap()
        .replace_policy_preserving_provenance(AgentPolicySet::from_yaml(DENY).unwrap());
    assert_ne!(f.get().await.policy.sha256, before.policy.sha256);
}

#[tokio::test]
async fn managed_metadata_and_live_policy_share_one_snapshot() {
    let f = Fixture::new(true, false);
    let old = f.get().await.policy.sha256;
    f.state.firewall.lock().unwrap().activate_managed_policy(
        AgentPolicySet::from_yaml(DENY).unwrap(),
        "revision-two".into(),
        2,
        "a".repeat(64),
    );
    let current = f.get().await;
    assert_ne!(old, current.policy.sha256);
    assert_eq!(
        current.policy.managed_revision.as_deref(),
        Some("revision-two")
    );
    assert_eq!(current.policy.managed_source_sha256, Some("a".repeat(64)));
    assert_eq!(current.policy.managed_sequence, Some(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_policy_switches_never_mix_digest_and_managed_revision() {
    let f = Fixture::new(true, false);
    let allow = f.get().await.policy.sha256;
    f.state.firewall.lock().unwrap().activate_managed_policy(
        AgentPolicySet::from_yaml(DENY).unwrap(),
        "deny".into(),
        2,
        "d".repeat(64),
    );
    let deny = f.get().await.policy.sha256;
    let state = f.state.clone();
    let writer = std::thread::spawn(move || {
        for i in 0..200 {
            let (policy, revision) = if i % 2 == 0 {
                (ALLOW, "allow")
            } else {
                (DENY, "deny")
            };
            state.firewall.lock().unwrap().activate_managed_policy(
                AgentPolicySet::from_yaml(policy).unwrap(),
                revision.into(),
                i,
                "d".repeat(64),
            );
            std::thread::yield_now();
        }
    });
    for _ in 0..50 {
        let s = f.get().await;
        assert_eq!(
            s.policy.sha256,
            if s.policy.managed_revision.as_deref() == Some("allow") {
                allow.clone()
            } else {
                deny.clone()
            }
        );
    }
    writer.join().unwrap();
}

#[tokio::test]
async fn native_contact_does_not_prove_execution_or_model_consumption() {
    let f = Fixture::new(true, true);
    let before = f.get().await;
    assert_eq!(
        before.paths[2]
            .activity
            .as_ref()
            .unwrap()
            .authenticated_requests,
        0
    );
    let body = json!({"contract_version":"sw-native/1", "registry_sha256": before.registry.sha256.unwrap(), "session_id":"fixture", "event":"session_start"});
    let (code, _) = request(
        f.app.clone(),
        "/native/v1",
        Some(NATIVE_TOKEN),
        None,
        Some(body),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let after = f.get().await;
    assert_eq!(
        after.paths[2]
            .activity
            .as_ref()
            .unwrap()
            .authenticated_requests,
        1
    );
    assert!(after
        .paths
        .iter()
        .all(|p| p.execution_coverage == Evidence::Unknown));
    assert_eq!(after.paths[3].reason, "resource_executor_unsupported");
    assert_eq!(after.paths[4].capability, Evidence::Unsupported);
    assert_eq!(after.paths[5].capability, Evidence::Unknown);
}

#[tokio::test]
async fn legacy_fail_open_contact_and_unauthorized_requests_are_distinguished() {
    let f = Fixture::new(true, false);
    let raw = json!({"private_raw_call":"do-not-echo-secret"});
    request(
        f.app.clone(),
        "/hook",
        Some("wrong"),
        None,
        Some(raw.clone()),
    )
    .await;
    assert_eq!(
        f.get().await.paths[0]
            .activity
            .as_ref()
            .unwrap()
            .authenticated_requests,
        0
    );
    request(f.app.clone(), "/hook", Some(TOKEN), None, Some(raw)).await;
    let s = f.get().await;
    assert_eq!(
        s.paths[0].activity.as_ref().unwrap().authenticated_requests,
        1
    );
    assert_eq!(s.paths[0].execution_coverage, Evidence::Unknown);
    assert_eq!(s.paths[0].configured, None);
    let text = serde_json::to_string(&s).unwrap();
    assert!(!text.contains("do-not-echo-secret"));
    assert!(!text.contains(TOKEN));
}

#[tokio::test]
async fn shadow_and_absent_registry_remain_explicit() {
    let f = Fixture::new(false, false);
    let s = f.get().await;
    assert_eq!(s.mode, Mode::Shadow);
    assert_eq!(s.registry.state, Evidence::Unknown);
    assert!(s.registry.sha256.is_none());
    assert_eq!(s.paths[2].capability, Evidence::Unsupported);
    assert!(s.runtime.binary_sha256.is_none());
}

#[tokio::test]
async fn lifecycle_identity_is_reused_and_health_remains_compatible() {
    let f = Fixture::new(true, false);
    let health_before = request(f.app.clone(), "/health", None, None, None).await.1;
    let identity = agentfw::lifecycle::ManagedHealth {
        pid: std::process::id(),
        instance: "managed-instance-123456".into(),
        binary_digest: "b".repeat(64),
        config_digest: "c".repeat(64),
    };
    let runtime = Arc::new(Runtime::new(&f.state.config).with_lifecycle(identity.clone()));
    let app = app_with_diagnostics(f.state.clone(), runtime);
    let value = request(app.clone(), ENDPOINT, Some(TOKEN), Some(&NONCE), None)
        .await
        .1;
    let s: Snapshot = serde_json::from_value(value).unwrap();
    assert_eq!(s.runtime.lifecycle, Some(identity));
    status::validate(&s, &NONCE, status::now_ms(), &Expectations::default()).unwrap();
    assert_eq!(
        request(app, "/health", None, None, None).await.1,
        health_before
    );
}

#[tokio::test]
async fn poisoned_engine_reports_unavailable_without_claiming_coverage() {
    let f = Fixture::new(true, false);
    let st = f.state.clone();
    let _ = std::thread::spawn(move || {
        let _guard = st.firewall.lock().unwrap();
        panic!("fixture poison");
    })
    .join();
    let (code, body) = request(f.app.clone(), ENDPOINT, Some(TOKEN), Some(&NONCE), None).await;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["mode"], "unavailable");
    assert!(body.get("paths").is_none());
}

#[tokio::test]
async fn stale_nonce_digest_instance_and_overclaimed_coverage_are_rejected() {
    let f = Fixture::new(true, true);
    let s = f.get().await;
    let now = status::now_ms();
    assert!(status::validate(
        &s,
        &agentfw::token::generate(),
        now,
        &Expectations::default()
    )
    .is_err());
    assert!(status::validate(&s, &NONCE, now + 20_000, &Expectations::default()).is_err());
    for expected in [
        Expectations {
            instance: Some("other-instance".into()),
            ..Default::default()
        },
        Expectations {
            policy_sha256: Some("0".repeat(64)),
            ..Default::default()
        },
        Expectations {
            registry_sha256: Some("0".repeat(64)),
            ..Default::default()
        },
        Expectations {
            config_sha256: Some("0".repeat(64)),
            ..Default::default()
        },
        Expectations {
            binary_sha256: Some("0".repeat(64)),
            ..Default::default()
        },
    ] {
        assert_eq!(
            status::validate(&s, &NONCE, now, &expected),
            Err("status_identity_mismatch")
        );
    }
    let mut bad = s.clone();
    bad.paths[3].capability = Evidence::Supported;
    assert!(status::validate(&bad, &NONCE, now, &Expectations::default()).is_err());
    let mut bad = s.clone();
    bad.paths[2].execution_coverage = Evidence::Supported;
    assert!(status::validate(&bad, &NONCE, now, &Expectations::default()).is_err());
    let mut bad = s.clone();
    bad.mode = Mode::Unavailable;
    assert!(status::validate(&bad, &NONCE, now, &Expectations::default()).is_err());
}

#[tokio::test]
async fn request_client_rejects_unavailable_and_wrong_auth() {
    let f = Fixture::new(true, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cfg = f.state.config.clone();
    cfg.port = listener.local_addr().unwrap().port();
    let app = f.app.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    assert_eq!(
        status::query(
            &cfg,
            "wrong",
            &Expectations::default(),
            Duration::from_secs(1)
        )
        .await
        .unwrap_err(),
        "status_query_rejected"
    );
    assert!(status::query(
        &cfg,
        TOKEN,
        &Expectations::default(),
        Duration::from_secs(1)
    )
    .await
    .is_ok());
    task.abort();
    let _ = task.await;
    assert_eq!(
        status::query(
            &cfg,
            TOKEN,
            &Expectations::default(),
            Duration::from_secs(1)
        )
        .await
        .unwrap_err(),
        "status_unavailable"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_is_read_only_and_unknown_is_nonzero_unless_query_only() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = Fixture::with_port(true, false, listener.local_addr().unwrap().port());
    let mut cfg = f.state.config.clone();
    let app = f.app.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    std::fs::write(
        f.dir.path().join("config.yaml"),
        serde_yaml::to_string(&cfg).unwrap(),
    )
    .unwrap();
    std::fs::write(f.dir.path().join("token"), TOKEN).unwrap();
    let before = std::fs::read(f.dir.path().join("config.yaml")).unwrap();
    for (flags, exit) in [
        (vec![], 2),
        (vec!["--query-only"], 0),
        (
            vec!["--query-only", "--expect-instance", "wrong-instance"],
            1,
        ),
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_agentfw"))
            .arg("protection-status")
            .arg("--home")
            .arg(f.dir.path())
            .args(flags)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(exit),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(!text.contains(TOKEN));
        assert!(!String::from_utf8_lossy(&out.stderr).contains(TOKEN));
        assert!(text.contains("unknown"));
    }
    assert_eq!(
        std::fs::read(f.dir.path().join("config.yaml")).unwrap(),
        before
    );
    assert_eq!(
        std::fs::read_to_string(f.dir.path().join("token")).unwrap(),
        TOKEN
    );
    // Loaded config is unchanged; a disk edit is not silently treated as active.
    cfg.enforce = false;
    std::fs::write(
        f.dir.path().join("config.yaml"),
        serde_yaml::to_string(&cfg).unwrap(),
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .arg("protection-status")
        .arg("--home")
        .arg(f.dir.path())
        .arg("--query-only")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("status_identity_mismatch"));
    task.abort();
}

#[test]
fn missing_token_is_not_created_and_parse_errors_are_sanitized() {
    let dir = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .arg("protection-status")
        .arg("--home")
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(!dir.path().join("token").exists());
    std::fs::write(
        dir.path().join("config.yaml"),
        "private_call_content: token-secret\n",
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .arg("protection-status")
        .arg("--home")
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("token-secret"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("token-secret"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_cli_cannot_satisfy_require_enforce() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = Fixture::with_port(false, false, listener.local_addr().unwrap().port());
    let app = f.app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    std::fs::write(
        f.dir.path().join("config.yaml"),
        serde_yaml::to_string(&f.state.config).unwrap(),
    )
    .unwrap();
    std::fs::write(f.dir.path().join("token"), TOKEN).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .arg("protection-status")
        .arg("--home")
        .arg(f.dir.path())
        .args(["--query-only", "--require-enforce"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("shadow"));
    server.abort();
}

#[tokio::test]
async fn runtime_instances_are_distinct_and_cannot_be_substituted() {
    let f = Fixture::new(true, false);
    let first = f.get().await;
    let other = app_with_diagnostics(f.state.clone(), Arc::new(Runtime::new(&f.state.config)));
    let s: Snapshot = serde_json::from_value(
        request(other, ENDPOINT, Some(TOKEN), Some(&NONCE), None)
            .await
            .1,
    )
    .unwrap();
    assert_ne!(s.runtime.instance, first.runtime.instance);
    assert_eq!(
        status::validate(
            &s,
            &NONCE,
            status::now_ms(),
            &Expectations {
                instance: Some(first.runtime.instance),
                ..Default::default()
            }
        ),
        Err("status_identity_mismatch")
    );
}

#[tokio::test]
async fn client_rejects_redirect_raw_error_bodies_and_oversized_replies() {
    use wiremock::{matchers::path, Mock, MockServer, ResponseTemplate};
    for response in [
        ResponseTemplate::new(302).insert_header("location", "http://127.0.0.1:1/private"),
        ResponseTemplate::new(500).set_body_string("raw-call-and-secret"),
        ResponseTemplate::new(200).set_body_string("raw-call-and-secret"),
        ResponseTemplate::new(200).set_body_string("x".repeat(40_000)),
    ] {
        let server = MockServer::start().await;
        Mock::given(path(ENDPOINT))
            .respond_with(response)
            .mount(&server)
            .await;
        let config = Config {
            port: server.address().port(),
            ..Default::default()
        };
        let error = status::query(
            &config,
            TOKEN,
            &Expectations::default(),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(!error.contains("secret"));
        assert!(!error.contains(TOKEN));
        assert!(error.starts_with("status_"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[test]
fn default_home_query_does_not_create_a_profile() {
    let dir = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .env("HOME", dir.path())
        .env("USERPROFILE", dir.path())
        .arg("protection-status")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(!dir.path().join(".agentfw").exists());
}

struct Daemon(std::process::Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn real_daemon_reports_loaded_identity_and_survives_disk_drift() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join(".agentfw");
    let install = std::process::Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .arg("install")
        .env("HOME", dir.path())
        .env("USERPROFILE", dir.path())
        .output()
        .unwrap();
    assert!(install.status.success(), "fixture profile setup failed");
    let token = std::fs::read_to_string(home.join("token")).unwrap();
    let port = {
        let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    let cfg = Config {
        port,
        enforce: true,
        ..Default::default()
    };
    std::fs::write(
        home.join("config.yaml"),
        serde_yaml::to_string(&cfg).unwrap(),
    )
    .unwrap();
    let stderr_path = dir.path().join("daemon-stderr.txt");
    let stderr = std::fs::File::create(&stderr_path).unwrap();
    let mut daemon = Daemon(
        std::process::Command::new(env!("CARGO_BIN_EXE_agentfw"))
            .arg("serve")
            .env("HOME", dir.path())
            .env("USERPROFILE", dir.path())
            .env_remove("SOUP_MANAGED_AGENT_CONSOLE")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(stderr)
            .spawn()
            .unwrap(),
    );
    let mut observed = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "fixture daemon exited: {}",
            std::fs::read_to_string(&stderr_path).unwrap_or_default()
        );
        if let Ok(s) = status::query(
            &cfg,
            token.trim(),
            &Expectations::default(),
            Duration::from_millis(200),
        )
        .await
        {
            observed = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let first = observed.expect("daemon diagnostics available");
    assert_eq!(first.runtime.pid, daemon.0.id());
    assert_eq!(
        first.runtime.loaded_config_sha256,
        status::config_digest(&cfg)
    );
    let binary =
        agentfw::lifecycle::sha256_file(std::path::Path::new(env!("CARGO_BIN_EXE_agentfw")))
            .unwrap();
    assert_eq!(first.runtime.binary_sha256, Some(binary.clone()));
    let changed = Config {
        enforce: false,
        ..cfg.clone()
    };
    std::fs::write(
        home.join("config.yaml"),
        serde_yaml::to_string(&changed).unwrap(),
    )
    .unwrap();
    let second = status::query(
        &cfg,
        token.trim(),
        &Expectations::default(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(first.runtime, second.runtime);
    assert_eq!(second.mode, Mode::Enforcing);
    assert_eq!(first.policy.sha256, second.policy.sha256);
    assert!(second
        .paths
        .iter()
        .all(|p| p.execution_coverage == Evidence::Unknown));
    if let Some(path) = std::env::var_os("AGENTFW_STATUS_EVIDENCE") {
        let evidence = json!({
            "before": first, "after_disk_edit": second,
            "expected_pid": daemon.0.id(), "expected_binary_sha256": binary,
        });
        std::fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn cli_refuses_fifo_config_and_token_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    for (name, expected) in [
        ("config.yaml", "status_config_unavailable"),
        ("token", "status_token_unavailable"),
    ] {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(name);
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_agentfw"));
        command
            .args(["protection-status", "--home"])
            .arg(home.path())
            .args(["--timeout-seconds", "1"])
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(5), command.output())
            .await
            .expect("status query blocked on a FIFO before its network deadline")
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["error_code"], expected);
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 1);
    }
}
