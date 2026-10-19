// SPDX-License-Identifier: Apache-2.0
//! `agentfw onboard` refusal, read-only and undo ownership checks against the built binary.
//! The full apply/retry/interrupt/rollback/undo matrix runs in
//! `scripts/onboarding-acceptance.py` (see docs/operations/ONBOARDING.md).
#![cfg(target_os = "linux")]

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const AGENT: &str = env!("CARGO_BIN_EXE_agentfw");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The debug binary is large; hash it once per test process.
fn agent_sha() -> &'static str {
    static DIGEST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DIGEST.get_or_init(|| sha(&std::fs::read(AGENT).unwrap()))
}

fn python() -> Option<PathBuf> {
    ["/usr/bin/python3", "/usr/local/bin/python3"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .and_then(|p| p.canonicalize().ok())
}

struct Home {
    _dir: tempfile::TempDir,
    root: PathBuf,
    python: PathBuf,
    port: u16,
}

impl Home {
    fn new() -> Option<Self> {
        let python = python()?;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for sub in ["user/work/notes", "user/.claude", "opt"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        for private in ["user", "user/.claude"] {
            std::fs::set_permissions(root.join(private), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let server = root.join("opt/server.py");
        std::fs::copy(
            repo().join("scripts/fixtures/mcp_admission_demo_server.py"),
            &server,
        )
        .unwrap();
        // The reviewed registry pins the accepted fixture's own schemas.
        let registry = Command::new(&python).arg("-I").arg("-c").arg(
            "import importlib.util,json,hashlib,sys\n\
             s=importlib.util.spec_from_file_location('s',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n\
             c=lambda v: json.dumps(v,sort_keys=True,separators=(',',':')).encode()\n\
             k={'read_document':'read_only','send_http':'network','publish_report':'network','delete_note':'destructive'}\n\
             t=[{'name':x['name'],'schema_sha256':hashlib.sha256(c(x['inputSchema'])).hexdigest(),'action_class':k[x['name']],\n\
                 'result_provenance':'untrusted' if k[x['name']]=='read_only' else 'local_system',\n\
                 'egress':[{'pointer':'/url','kind':'url_host','optional':False}] if k[x['name']]=='network' else []} for x in m.TOOLS]\n\
             print(json.dumps({'contract_version':'sw-native/1','registry_id':'notes-fixture-v1','tools':t}))",
        ).arg(&server).output().unwrap();
        std::fs::write(root.join("opt/registry.json"), &registry.stdout).unwrap();
        let config = json!({"theme": "dark", "mcpServers": {
            "notes": {"command": python, "args": ["-I", "-u", server, "--notes", root.join("user/work/notes"),
                      "--ledger", root.join("user/work/ledger.jsonl"), "--recipient", "http://127.0.0.1:9/capture"]},
            "unrelated": {"command": "/bin/true", "args": ["sentinel"]}}});
        let host = root.join("user/.claude/mcp.json");
        std::fs::write(&host, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o600)).unwrap();
        let port = TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        Some(Self {
            _dir: dir,
            root,
            python,
            port,
        })
    }

    fn inputs(&self, overrides: &[(&str, String)]) -> Vec<String> {
        let classifier = repo().join("rule_baseline/rule_baseline.py");
        let registry = self.root.join("opt/registry.json");
        let mut values: Vec<(String, String)> = vec![
            ("--agent".into(), AGENT.into()),
            ("--agent-sha256".into(), agent_sha().to_string()),
            ("--classifier".into(), "rule-baseline".into()),
            (
                "--classifier-script".into(),
                classifier.display().to_string(),
            ),
            (
                "--classifier-sha256".into(),
                sha(&std::fs::read(&classifier).unwrap()),
            ),
            (
                "--classifier-python".into(),
                self.python.display().to_string(),
            ),
            ("--registry".into(), registry.display().to_string()),
            (
                "--registry-sha256".into(),
                sha(&std::fs::read(&registry).unwrap()),
            ),
            (
                "--workspace".into(),
                self.root.join("user/work").display().to_string(),
            ),
            (
                "--agent-home".into(),
                self.root.join("user/.agentfw").display().to_string(),
            ),
            (
                "--host-config".into(),
                self.root
                    .join("user/.claude/mcp.json")
                    .display()
                    .to_string(),
            ),
            ("--server".into(), "notes".into()),
            ("--port".into(), self.port.to_string()),
        ];
        for (key, value) in overrides {
            if let Some(slot) = values.iter_mut().find(|(k, _)| k == key) {
                slot.1 = value.clone();
            } else {
                values.push((key.to_string(), value.clone()));
            }
        }
        values.into_iter().flat_map(|(k, v)| [k, v]).collect()
    }

    fn onboard(
        &self,
        operation: &str,
        args: Vec<String>,
        report: &str,
    ) -> (Option<i32>, Option<Value>, String) {
        let path = self.root.join(report);
        let output = Command::new(AGENT)
            .current_dir(self.root.join("user"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("onboard")
            .arg(operation)
            .args(args)
            .arg("--report")
            .arg(&path)
            .output()
            .unwrap();
        let value = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        (
            output.status.code(),
            value,
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    }

    fn untouched(&self) -> bool {
        !self.root.join("user/.agentfw").exists()
            && !self.root.join("user/.soup-wall-onboarding").exists()
            && std::fs::read_dir(self.root.join("user/.claude"))
                .unwrap()
                .count()
                == 1
    }
}

fn check<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
}

#[test]
fn preview_is_read_only_and_binds_a_plan_digest() {
    let Some(home) = Home::new() else { return };
    let host_before = std::fs::read(home.root.join("user/.claude/mcp.json")).unwrap();
    let (code, report, stdout) = home.onboard("preview", home.inputs(&[]), "preview.json");
    let report = report.unwrap();
    assert_eq!(code, Some(0), "{stdout}");
    assert_eq!(report["result"], "plan_ready");
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["status"] == "ok"));
    assert_eq!(report["plan_sha256"].as_str().unwrap().len(), 64);
    assert!(stdout.contains("Planned changes:") && stdout.contains("Not changed:"));
    assert_eq!(
        std::fs::read(home.root.join("user/.claude/mcp.json")).unwrap(),
        host_before
    );
    assert!(home.untouched());
    let raw = std::fs::read_to_string(home.root.join("preview.json")).unwrap();
    assert!(
        !raw.contains(home.root.to_str().unwrap()),
        "report must not contain raw paths"
    );
    // Same inputs, same digest; a different port is a different plan.
    let (_, again, _) = home.onboard("preview", home.inputs(&[]), "preview-2.json");
    assert_eq!(again.unwrap()["plan_sha256"], report["plan_sha256"]);
    let (_, other, _) = home.onboard(
        "preview",
        home.inputs(&[("--port", (home.port ^ 1).to_string())]),
        "preview-3.json",
    );
    assert_ne!(other.unwrap()["plan_sha256"], report["plan_sha256"]);
}

#[test]
fn missing_or_wrong_assets_are_refused_with_actions() {
    let Some(home) = Home::new() else { return };
    let missing = home.root.join("missing.py").display().to_string();
    let (code, report, _) = home.onboard(
        "preview",
        home.inputs(&[("--classifier-script", missing)]),
        "a.json",
    );
    let report = report.unwrap();
    assert_eq!(
        (code, report["result"].as_str()),
        (Some(4), Some("refused"))
    );
    assert_eq!(check(&report, "classifier")["status"], "refused");
    assert!(check(&report, "classifier")["action"].is_string());
    let (_, report, _) = home.onboard(
        "preview",
        home.inputs(&[("--classifier-sha256", "0".repeat(64))]),
        "b.json",
    );
    assert!(check(&report.unwrap(), "classifier")["detail"]
        .as_str()
        .unwrap()
        .contains("wrong revision"));
    let (_, report, _) = home.onboard(
        "preview",
        home.inputs(&[("--registry-sha256", "1".repeat(64))]),
        "c.json",
    );
    assert_eq!(check(&report.unwrap(), "registry")["status"], "refused");
    let (_, report, _) = home.onboard(
        "preview",
        home.inputs(&[("--server", "absent".into())]),
        "d.json",
    );
    assert_eq!(check(&report.unwrap(), "server")["status"], "refused");
    assert!(home.untouched());
}

#[test]
fn existing_agent_home_and_foreign_listener_are_conflicts() {
    let Some(home) = Home::new() else { return };
    let existing = home.root.join("user/.agentfw");
    std::fs::create_dir(&existing).unwrap();
    std::fs::write(existing.join("config.yaml"), b"enforce: true\n").unwrap();
    let listener = TcpListener::bind(("127.0.0.1", home.port)).unwrap();
    let (code, report, _) = home.onboard("preview", home.inputs(&[]), "p.json");
    let report = report.unwrap();
    assert_eq!(code, Some(4));
    assert_eq!(check(&report, "agent_home")["status"], "conflict");
    assert_eq!(check(&report, "port")["status"], "conflict");
    let (code, report, _) = home.onboard(
        "apply",
        [
            home.inputs(&[]),
            vec!["--plan-sha256".into(), "0".repeat(64)],
        ]
        .concat(),
        "a.json",
    );
    assert_eq!(
        (code, report.unwrap()["result"].as_str()),
        (Some(4), Some("refused"))
    );
    assert_eq!(
        std::fs::read(existing.join("config.yaml")).unwrap(),
        b"enforce: true\n"
    );
    assert!(!home.root.join("user/.soup-wall-onboarding").exists());
    drop(listener);
}

#[test]
fn apply_requires_the_reviewed_digest_and_unsafe_host_files_are_refused() {
    let Some(home) = Home::new() else { return };
    let (code, report, _) = home.onboard(
        "apply",
        [
            home.inputs(&[]),
            vec!["--plan-sha256".into(), "a".repeat(64)],
        ]
        .concat(),
        "a.json",
    );
    let report = report.unwrap();
    assert_eq!(code, Some(4));
    assert!(report["explanation"]
        .as_str()
        .unwrap()
        .contains("differ from the reviewed preview"));
    assert!(home.untouched());
    let host = home.root.join("user/.claude/mcp.json");
    std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (_, report, _) = home.onboard("preview", home.inputs(&[]), "p.json");
    assert_eq!(check(&report.unwrap(), "host_config")["status"], "refused");
    assert_eq!(
        std::fs::metadata(&host).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[test]
fn undo_without_a_recorded_onboarding_changes_nothing_and_reports_are_never_replaced() {
    let Some(home) = Home::new() else { return };
    let args = vec![
        "--agent".into(),
        AGENT.into(),
        "--agent-home".into(),
        home.root.join("user/.agentfw").display().to_string(),
        "--host-config".into(),
        home.root
            .join("user/.claude/mcp.json")
            .display()
            .to_string(),
        "--server".into(),
        "notes".into(),
    ];
    let (code, report, _) = home.onboard("undo", args, "u.json");
    assert_eq!(
        (code, report.unwrap()["result"].as_str()),
        (Some(4), Some("refused"))
    );
    assert!(home.untouched());
    std::fs::write(home.root.join("taken.json"), b"operator").unwrap();
    let (code, _, _) = home.onboard("preview", home.inputs(&[]), "taken.json");
    assert_eq!(code, Some(4));
    assert_eq!(
        std::fs::read(home.root.join("taken.json")).unwrap(),
        b"operator"
    );
}

fn journal(home: &Home) -> Option<Value> {
    std::fs::read(home.root.join("user/.soup-wall-onboarding/journal.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// The journal and home a stopped onboarding leaves behind after its files were
/// written and the Agent created runtime entries (no connection or lifecycle yet).
fn recorded_onboarding(home: &Home) -> PathBuf {
    let user = home.root.join("user");
    let agent_home = user.join(".agentfw");
    let state = user.join(".soup-wall-onboarding");
    for dir in [
        agent_home.join("grants"),
        agent_home.join("onboarding"),
        state.clone(),
    ] {
        std::fs::create_dir_all(&dir).unwrap();
    }
    let files = [
        ("config.yaml", b"enforce: true\n".as_slice()),
        ("onboarding/registry.json", b"{}"),
        ("grants/g1.json", b"{\"grant\":1}"),
        ("audit.jsonl", b"{\"event\":1}\n"),
    ];
    let mut inventory = serde_json::Map::new();
    for dir in ["grants", "onboarding"] {
        inventory.insert(dir.into(), json!({"kind": "dir", "sha256": null}));
    }
    for (rel, bytes) in files {
        std::fs::write(agent_home.join(rel), bytes).unwrap();
        inventory.insert(rel.into(), json!({"kind": "file", "sha256": sha(bytes)}));
    }
    let journal = json!({
        "schema": "sw-onboarding/1", "plan_sha256": "0".repeat(64), "core_sha256": "0".repeat(64),
        "agent_home": agent_home, "host_config": user.join(".claude/mcp.json"), "server": "notes",
        "agent": AGENT, "agent_sha256": agent_sha(), "port": home.port, "created_home": true,
        "files": {"config": sha(b"enforce: true\n")},
        "steps": {"create_agent_home": "done", "write_owned_files": "done", "create_token": "done"},
        "phase": "interrupted", "inventory": inventory,
    });
    std::fs::write(
        state.join("journal.json"),
        serde_json::to_vec_pretty(&journal).unwrap(),
    )
    .unwrap();
    for dir in [&state, &agent_home] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    agent_home
}

fn undo_args(home: &Home, purge: bool) -> Vec<String> {
    let user = home.root.join("user");
    let mut args = vec![
        "--agent".into(),
        AGENT.into(),
        "--agent-home".into(),
        user.join(".agentfw").display().to_string(),
        "--host-config".into(),
        user.join(".claude/mcp.json").display().to_string(),
        "--server".into(),
        "notes".into(),
    ];
    if purge {
        args.push("--purge-agent-home".into());
    }
    args
}

#[test]
fn undo_preserves_foreign_files_inside_recognized_directories() {
    let Some(home) = Home::new() else { return };
    let agent_home = recorded_onboarding(&home);
    std::fs::write(
        agent_home.join("grants/operator-notes.txt"),
        b"operator bytes",
    )
    .unwrap();
    std::fs::write(agent_home.join("onboarding/operator.txt"), b"more").unwrap();
    for (purge, name) in [(false, "u1.json"), (true, "u2.json")] {
        let (code, report, _) = home.onboard("undo", undo_args(&home, purge), name);
        let report = report.unwrap();
        assert_eq!(
            (code, report["result"].as_str()),
            (Some(4), Some("incomplete")),
            "{report}"
        );
        let line = report["rollback"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["step"] == "agent_home")
            .unwrap();
        assert_eq!(line["outcome"], "conflict");
        assert!(!report.to_string().contains(&*home.root.to_string_lossy()));
        assert_eq!(
            std::fs::read(agent_home.join("grants/operator-notes.txt")).unwrap(),
            b"operator bytes"
        );
        assert_eq!(
            std::fs::read(agent_home.join("onboarding/operator.txt")).unwrap(),
            b"more"
        );
        assert_eq!(journal(&home).unwrap()["phase"], "rollback_conflict");
    }
    // Recorded entries were removed; the audit log only by the explicit purge.
    assert!(!agent_home.join("grants/g1.json").exists());
    assert!(!agent_home.join("config.yaml").exists());
    assert!(!agent_home.join("audit.jsonl").exists());
    std::fs::remove_file(agent_home.join("grants/operator-notes.txt")).unwrap();
    std::fs::remove_file(agent_home.join("onboarding/operator.txt")).unwrap();
    let (code, report, _) = home.onboard("undo", undo_args(&home, false), "u3.json");
    assert_eq!(
        (code, report.unwrap()["result"].as_str()),
        (Some(0), Some("undone"))
    );
    assert!(!agent_home.exists());
    assert!(journal(&home).is_none());
}

#[test]
fn ordinary_undo_keeps_the_audit_log_and_a_changed_runtime_file() {
    let Some(home) = Home::new() else { return };
    let agent_home = recorded_onboarding(&home);
    std::fs::write(agent_home.join("grants/g1.json"), b"{\"changed\":true}").unwrap();
    let (code, report, _) = home.onboard("undo", undo_args(&home, false), "u1.json");
    assert_eq!(
        (code, report.unwrap()["result"].as_str()),
        (Some(4), Some("incomplete"))
    );
    assert_eq!(
        std::fs::read(agent_home.join("grants/g1.json")).unwrap(),
        b"{\"changed\":true}"
    );
    assert!(agent_home.join("audit.jsonl").exists());
    std::fs::remove_file(agent_home.join("grants/g1.json")).unwrap();
    let (code, report, _) = home.onboard("undo", undo_args(&home, false), "u2.json");
    assert_eq!(
        (code, report.unwrap()["result"].as_str()),
        (Some(0), Some("undone"))
    );
    assert_eq!(
        std::fs::read(agent_home.join("audit.jsonl")).unwrap(),
        b"{\"event\":1}\n"
    );
    assert_eq!(journal(&home).unwrap()["phase"], "undone_audit_retained");
    let (code, _, _) = home.onboard("undo", undo_args(&home, true), "u3.json");
    assert_eq!(code, Some(0));
    assert!(!agent_home.exists());
    assert!(journal(&home).is_none());
}
