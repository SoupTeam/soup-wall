// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::self_test::{fixture, windows_safety as safety};
use std::io::Write;
use std::process::{Command as ProcessCommand, Stdio};

struct Fixture {
    root: tempfile::TempDir,
    selection: Selection,
}

fn write(path: &Path, bytes: &[u8]) {
    let mut file = safety::new_file(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

impl Fixture {
    fn new() -> Self {
        let temporary = std::env::temp_dir().canonicalize().unwrap();
        let temporary = temporary.to_str().unwrap();
        let root =
            tempfile::tempdir_in(temporary.strip_prefix(r"\\?\").unwrap_or(temporary)).unwrap();
        std::fs::remove_dir(root.path()).unwrap();
        safety::new_directory(root.path()).unwrap();
        let path = |name| root.path().join(name);
        let agent = path("agentfw.exe");
        let python = path("python.exe");
        let classifier = path("rule_baseline.py");
        let registry = path("registry.json");
        let policy = path("policy.yaml");
        let host_config = path("host.json");
        let state_directory = path("state");
        safety::new_directory(&state_directory).unwrap();
        let agent_bytes = b"controlled preview fixture; never executed";
        let python_bytes = b"controlled Python preview fixture; never executed";
        let classifier_bytes = b"raise RuntimeError('preview must not execute this source')";
        let registry_bytes = fixture::registry();
        for (path, bytes) in [
            (&agent, agent_bytes.as_slice()),
            (&python, python_bytes.as_slice()),
            (&classifier, classifier_bytes.as_slice()),
            (&registry, registry_bytes.as_slice()),
            (&policy, fixture::SHIPPED_POLICY.as_bytes()),
        ] {
            write(path, bytes);
        }
        let config = json!({"mcpServers": {
            "notes": {"command": agent, "args": ["original-server"]},
            "other": {"command": "untouched", "env": {"TOKEN": "operator-sentinel"}}
        }, "settings": {"theme": "operator-sentinel"}});
        write(&host_config, &serde_json::to_vec(&config).unwrap());
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let selection = Selection {
            agent,
            agent_sha256: sha(agent_bytes),
            python,
            python_sha256: sha(python_bytes),
            classifier,
            classifier_sha256: sha(classifier_bytes),
            registry,
            registry_sha256: sha(&registry_bytes),
            policy,
            policy_sha256: sha(fixture::SHIPPED_POLICY.as_bytes()),
            host_config,
            server: "notes".into(),
            home: path(".agentfw"),
            state_directory,
            report: path("report.json"),
            workspace: root.path().to_path_buf(),
            port,
        };
        Self { root, selection }
    }

    fn names(&self) -> Vec<String> {
        let mut names = std::fs::read_dir(self.root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    }
}

#[tokio::test]
async fn preview_is_read_only_and_does_not_execute_selected_programs() {
    let fixture = Fixture::new();
    let names = fixture.names();
    let host = std::fs::read(&fixture.selection.host_config).unwrap();
    let result = preview_selected(&fixture.selection).await.unwrap();
    assert_eq!(result.status, "preview");
    assert_eq!(result.synthetic_protection, "not_witnessed");
    assert_eq!(result.host_reload, "pending_explicit_host_reload");
    assert_eq!(result.confirmation.len(), 64);
    assert_eq!(fixture.names(), names);
    assert_eq!(std::fs::read(&fixture.selection.host_config).unwrap(), host);
    assert!(!fixture.selection.home.exists());
    assert!(!fixture.selection.report.exists());
    assert_eq!(
        std::fs::read_dir(&fixture.selection.state_directory)
            .unwrap()
            .count(),
        0
    );
    let printed = serde_json::to_string(&result).unwrap();
    assert!(!printed.contains("operator-sentinel"));
    assert!(!printed.contains(&fixture.root.path().display().to_string()));
}

#[tokio::test]
async fn confirmation_changes_with_host_edits_and_exact_destinations() {
    let fixture = Fixture::new();
    let original = preview_selected(&fixture.selection).await.unwrap();
    let repeated = preview_selected(&fixture.selection).await.unwrap();
    assert_eq!(original.confirmation, repeated.confirmation);
    let mut changed = fixture.selection.clone();
    changed.report = fixture.root.path().join("different-report.json");
    assert_ne!(
        original.confirmation,
        preview_selected(&changed).await.unwrap().confirmation
    );
    let mut value: Value =
        serde_json::from_slice(&std::fs::read(&changed.host_config).unwrap()).unwrap();
    value["settings"]["theme"] = json!("operator edit");
    std::fs::write(&changed.host_config, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_ne!(
        repeated.confirmation,
        preview_selected(&fixture.selection)
            .await
            .unwrap()
            .confirmation
    );
}

#[tokio::test]
async fn every_asset_requires_the_expected_digest() {
    let fixture = Fixture::new();
    for index in 0..5 {
        let mut selection = fixture.selection.clone();
        let digest = match index {
            0 => &mut selection.agent_sha256,
            1 => &mut selection.python_sha256,
            2 => &mut selection.classifier_sha256,
            3 => &mut selection.registry_sha256,
            _ => &mut selection.policy_sha256,
        };
        *digest = "0".repeat(64);
        assert!(preview_selected(&selection).await.is_err());
        assert!(!selection.home.exists());
    }
}

#[tokio::test]
async fn existing_home_report_and_journal_are_preserved() {
    for target in 0..3 {
        let fixture = Fixture::new();
        let path = match target {
            0 => fixture.selection.home.clone(),
            1 => fixture.selection.report.clone(),
            _ => fixture.selection.state_directory.join("onboarding.json"),
        };
        write(&path, b"operator-sentinel");
        assert!(preview_selected(&fixture.selection).await.is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"operator-sentinel");
    }
}

#[tokio::test]
async fn occupied_foreign_port_receives_no_preview_traffic() {
    let mut fixture = Fixture::new();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    fixture.selection.port = listener.local_addr().unwrap().port();
    assert!(preview_selected(&fixture.selection).await.is_err());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(!fixture.selection.home.exists());
}

#[tokio::test]
async fn invalid_registry_and_policy_fail_even_with_matching_hashes() {
    let mut fixture = Fixture::new();
    std::fs::write(&fixture.selection.registry, b"{}").unwrap();
    fixture.selection.registry_sha256 = sha(b"{}");
    assert!(preview_selected(&fixture.selection).await.is_err());
    let bytes = fixture::registry();
    std::fs::write(&fixture.selection.registry, &bytes).unwrap();
    fixture.selection.registry_sha256 = sha(&bytes);
    std::fs::write(&fixture.selection.policy, b"invalid: [").unwrap();
    fixture.selection.policy_sha256 = sha(b"invalid: [");
    assert!(preview_selected(&fixture.selection).await.is_err());
}

#[tokio::test]
async fn unknown_server_and_duplicate_host_fields_are_refused() {
    let mut fixture = Fixture::new();
    fixture.selection.server = "missing".into();
    assert!(preview_selected(&fixture.selection).await.is_err());
    fixture.selection.server = "notes".into();
    std::fs::write(
        &fixture.selection.host_config,
        br#"{"mcpServers":{},"mcpServers":{}}"#,
    )
    .unwrap();
    assert!(preview_selected(&fixture.selection).await.is_err());
}

#[tokio::test]
async fn hardlinked_host_configuration_is_refused_without_changes() {
    let fixture = Fixture::new();
    let alias = fixture.root.path().join("host-alias.json");
    std::fs::hard_link(&fixture.selection.host_config, &alias).unwrap();
    let before = std::fs::read(&alias).unwrap();
    assert!(preview_selected(&fixture.selection).await.is_err());
    assert_eq!(std::fs::read(&alias).unwrap(), before);
}

#[tokio::test]
async fn connection_confirmation_is_checked_before_daemon_access() {
    let fixture = Fixture::new();
    let selection = &fixture.selection;
    let before = std::fs::read(&selection.host_config).unwrap();
    let options = Options {
        path: selection.host_config.clone(),
        server: selection.server.clone(),
        home: selection.home.clone(),
        agent: selection.agent.clone(),
        runtime: None,
        probe_tool: None,
        probe_args: None,
        server_profile: None,
        classifier_script: None,
        classifier_python: None,
    };
    let error = connection::run_confirmed("connect", &options, Some(&"0".repeat(64)), None, None)
        .await
        .err()
        .unwrap();
    assert!(error
        .to_string()
        .contains("host changed since onboarding preview"));
    assert_eq!(std::fs::read(&selection.host_config).unwrap(), before);
    assert!(!selection.home.exists());
}

#[test]
fn removal_checks_contents_and_keeps_the_verified_handle_exclusive() {
    use std::os::windows::fs::OpenOptionsExt;
    let fixture = Fixture::new();
    let file = fixture.root.path().join("owned.txt");
    write(&file, b"owned bytes");
    assert!(connection::remove_confirmed(&file, b"different bytes").is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"owned bytes");
    let retained = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&file)
        .unwrap();
    assert!(connection::remove_confirmed(&file, b"owned bytes").is_err());
    drop(retained);
    connection::remove_confirmed(&file, b"owned bytes").unwrap();
    assert!(!file.exists());
}

#[test]
fn narrowed_owned_directory_acl_is_refused_without_repair() {
    let fixture = Fixture::new();
    let directory = &fixture.selection.state_directory;
    connection::verify_full_directory(&safety::check_private(directory, true).unwrap()).unwrap();
    crate::private_file_windows::ensure_private_directory(directory).unwrap();
    crate::private_file_windows::ensure_private_directory(directory).unwrap();
    connection::verify_full_directory(&safety::check_private(directory, true).unwrap()).unwrap();
    let sid = crate::private_file_windows::current_user_sid().unwrap();
    assert!(ProcessCommand::new("icacls")
        .arg(directory)
        .args(["/remove:g", &format!("*{sid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
    assert!(ProcessCommand::new("icacls")
        .arg(directory)
        .args(["/grant:r", &format!("*{sid}:(OI)(CI)R")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
    let observed = safety::check_private(directory, true).unwrap();
    assert!(connection::verify_full_directory(&observed).is_err());
    drop(observed);
    assert!(std::fs::write(
        directory.join("operator-rights-check"),
        b"must remain refused"
    )
    .is_err());
}

#[tokio::test]
async fn real_ntfs_junction_and_broad_acl_are_refused() {
    let mut fixture = Fixture::new();
    let original = fixture.selection.state_directory.clone();
    let junction = fixture.root.path().join("state-alias");
    assert!(ProcessCommand::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&original)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
    fixture.selection.state_directory = junction.clone();
    assert!(preview_selected(&fixture.selection).await.is_err());
    std::fs::remove_dir(&junction).unwrap();
    fixture.selection.state_directory = original.clone();
    assert!(ProcessCommand::new("icacls")
        .arg(&original)
        .args(["/grant", "*S-1-5-32-545:(OI)(CI)F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
    assert!(preview_selected(&fixture.selection).await.is_err());
    assert!(original.exists());
    assert!(!fixture.selection.home.exists());
}
