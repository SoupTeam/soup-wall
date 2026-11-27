// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

#[cfg(target_os = "linux")]
#[test]
fn selected_workspace_validation_keeps_default_and_refuses_capability_union() {
    use super::validate_selected_git_workspace;
    use crate::mcp::server_profile::git;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
    let config = b"[core]\nbare = false\nrepositoryformatversion = 0\n";
    std::fs::write(root.join(".git/config"), config).unwrap();
    for format in [git::FORMAT, git::FILE_READS_FORMAT, git::LOCAL_REFS_FORMAT] {
        assert!(validate_selected_git_workspace(root, format).is_ok());
    }
    assert!(validate_selected_git_workspace(root, "sw-mcp/git-readonly/1+file-revisions").is_err());
    std::fs::write(root.join(".git/shallow"), b"a\n").unwrap();
    assert!(validate_selected_git_workspace(root, git::FORMAT).is_err());
    assert!(validate_selected_git_workspace(root, git::FILE_READS_FORMAT).is_err());
    assert_eq!(std::fs::read(root.join(".git/config")).unwrap(), config);
    assert_eq!(std::fs::read(root.join(".git/shallow")).unwrap(), b"a\n");
}

#[cfg(target_os = "macos")]
#[test]
fn mac_group_observation_refuses_live_unknown_or_malformed_members() {
    assert!(!super::mac_group_has_running_processes("10 S\n20 Z+\n", 20).unwrap());
    assert!(super::mac_group_has_running_processes("20 Z\n20 S\n", 20).unwrap());
    assert!(super::mac_group_has_running_processes("20 ?\n", 20).unwrap());
    for value in ["", "unreadable", "20 Z extra", "20"] {
        assert!(super::mac_group_has_running_processes(value, 20).is_err());
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn mac_zombie_only_group_does_not_fake_a_signal_permission_failure() {
    use std::os::unix::process::CommandExt;
    let mut child = std::process::Command::new("/usr/bin/true")
        .process_group(0)
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if super::owned_host_exited(&mut child).unwrap() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(super::owned_host_exited(&mut child).unwrap());
    let result =
        super::terminate_process_group(child.id(), std::time::Duration::from_millis(5)).await;
    assert!(child.wait().unwrap().success());
    result.unwrap();
}
use super::*;

#[test]
#[cfg(unix)]
fn intentional_stop_requires_authenticated_terminal_disposition() {
    use std::os::unix::process::ExitStatusExt;
    let interrupted = || Err(anyhow::anyhow!("pilot host terminated by SIGTERM"));
    assert_eq!(terminal_exit_code(interrupted(), true, true).unwrap(), 0);
    assert!(terminal_exit_code(interrupted(), true, false).is_err());
    // An authenticated receipt cannot turn cancellation, timeout or daemon
    // loss into a successful terminal outcome.
    assert!(terminal_exit_code(interrupted(), false, true).is_err());
    assert!(terminal_exit_code(interrupted(), false, false).is_err());
    assert!(terminal_exit_code(Ok(std::process::ExitStatus::from_raw(9)), false, true).is_err());
    assert_eq!(
        terminal_exit_code(Ok(std::process::ExitStatus::from_raw(0)), false, true).unwrap(),
        0
    );
    assert_eq!(
        terminal_exit_code(
            Ok(std::process::ExitStatus::from_raw(17 << 8)),
            false,
            false
        )
        .unwrap(),
        17
    );
}

fn dummy_script(path: &Path) {
    fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn private_state_parent_cannot_alias_either_selected_workspace() {
    let root = tempfile::tempdir().unwrap();
    let filesystem = root.path().join("filesystem");
    let git = root.path().join("git");
    fs::create_dir(&filesystem).unwrap();
    fs::create_dir(&git).unwrap();
    for (i, workspace) in [&filesystem, &git].iter().enumerate() {
        let alias = root.path().join(format!("alias-{i}"));
        std::os::unix::fs::symlink(workspace, &alias).unwrap();
        assert!(PrivateDirGuard::in_parent(&[&filesystem, &git], &alias).is_err());
        assert!(fs::read_dir(workspace).unwrap().next().is_none());
    }
    let guard = PrivateDirGuard::in_parent(&[&filesystem, &git], root.path()).unwrap();
    let path = guard.path.clone();
    drop(guard);
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn completed_host_remains_waitable_until_owned_group_cleanup() {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 17"])
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !owned_host_exited(&mut child).unwrap() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    // A second observation must still see the same waitable child.
    assert!(owned_host_exited(&mut child).unwrap());
    assert_eq!(child.wait().unwrap().code(), Some(17));
}

#[test]
fn test_missing_claude_executable_fails() {
    let temp = tempfile::tempdir().unwrap();
    let args = PilotLaunchArgs {
        git_workspace: None,
        claude: temp.path().join("nonexistent_claude"),
        workspace: temp.path().to_path_buf(),
        home: None,
        fs_profile: temp.path().join("fs.json"),
        git_profile: temp.path().join("git.json"),
        classifier: None,
        policy: None,
        host_session: None,
        agent_bin: None,
        dry_run: true,
        timeout_seconds: 10,
        ask_wait_seconds: 0,
        json: false,
        prompt: None,
        model: "claude-sonnet-4-20250514".into(),
        effort: None,
        mock_daemon_token: Some(crate::token::generate()),
        mock_instance_id: Some(crate::token::generate()),
        provider_env_fd: None,
        maintenance_home: None,
        maintenance_component_home: None,
        maintenance_run: None,
        provider_ca_fd: None,
        provider_ca_sha256: None,
        linux_budget: None,
        linux_budget_sha256: None,
        allow_command_fixtures: false,
    };
    assert!(args.validate().is_err());
}

#[test]
fn test_instance_prefixed_nonces_and_mismatch_negative_control() {
    let instance_id = format!("inst-live-{}", random_uuid_v4());
    let nonce = format!("{instance_id}.{}", random_uuid_v4());
    assert_eq!(
        nonce.split_once('.').map(|(inst, _)| inst),
        Some(instance_id.as_str())
    );

    // Negative control: foreign or restarted daemon instance mismatch
    let restarted_instance = format!("inst-restarted-{}", random_uuid_v4());
    assert_ne!(
        nonce.split_once('.').map(|(inst, _)| inst),
        Some(restarted_instance.as_str())
    );
}

#[test]
fn test_valid_args_dry_run_generates_correct_plan() {
    let temp = tempfile::tempdir().unwrap();
    let claude = temp.path().join("claude");
    dummy_script(&claude);

    let workspace = temp.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();

    let fs_profile = temp.path().join("fs.json");
    fs::write(
        &fs_profile,
        r#"{"runtimePath":"/usr/bin/node","packageRoot":"/pkg/fs","tools":[{"name":"read_text_file"}]}"#,
    )
    .unwrap();

    let git_profile = temp.path().join("git.json");
    fs::write(
        &git_profile,
        r#"{"runtimePath":"/usr/bin/python3","tools":[{"name":"git_status"}]}"#,
    )
    .unwrap();

    let test_token = crate::token::generate();
    let test_instance_id = crate::token::generate();

    let git_workspace = temp.path().join("separate-git");
    fs::create_dir(&git_workspace).unwrap();
    let args = PilotLaunchArgs {
        git_workspace: Some(git_workspace.clone()),
        claude,
        workspace: workspace.clone(),
        home: Some(temp.path().to_path_buf()),
        fs_profile,
        git_profile,
        classifier: None,
        policy: None,
        host_session: Some("test-session-123".into()),
        agent_bin: None,
        dry_run: true,
        timeout_seconds: 60,
        ask_wait_seconds: 0,
        json: true,
        prompt: None,
        model: "claude-sonnet-4-20250514".into(),
        effort: None,
        mock_daemon_token: Some(test_token.clone()),
        mock_instance_id: Some(test_instance_id.clone()),
        provider_env_fd: None,
        maintenance_home: None,
        maintenance_component_home: None,
        maintenance_run: None,
        provider_ca_fd: None,
        provider_ca_sha256: None,
        linux_budget: None,
        linux_budget_sha256: None,
        allow_command_fixtures: false,
    };

    let mut config = args.validate().expect("validation should succeed");
    assert_eq!(config.host_session, "test-session-123");
    assert_eq!(config.fs_tools, vec!["read_text_file"]);
    assert_eq!(config.git_tools, vec!["git_status"]);
    assert_eq!(config.fs_runtime_cmd[0], "/usr/bin/node");
    assert_eq!(config.git_runtime_cmd[0], "/usr/bin/python3");

    let guard = PrivateDirGuard::new(&workspace).expect("guard creation");
    assert!(!guard.path.starts_with(&workspace));

    let grants = mint_grants(&config, 1_000_000, &test_instance_id).expect("grants mint");
    assert!(grants.contains_key("filesystem"));
    assert!(grants.contains_key("git"));

    // Verify that the grant verifies with derived key and has instance-prefixed nonce
    let key = child_authority::derive_key(&test_token);
    let fs_grant = &grants["filesystem"];
    assert!(fs_grant.nonce.starts_with(&format!("{test_instance_id}.")));
    assert!(
        child_authority::verify(&key, fs_grant, "test-session-123", "filesystem", 1_000_050,)
            .is_ok()
    );

    let (mcp_config, plans) =
        write_per_process_mcp_config(&guard.path, &config, &grants, None).expect("write config");
    assert!(mcp_config.exists());
    let actual: serde_json::Value =
        serde_json::from_slice(&fs::read(&mcp_config).unwrap()).unwrap();
    for server in actual["mcpServers"].as_object().unwrap().values() {
        assert_eq!(server["command"], "/usr/bin/env");
        assert_eq!(server["args"][0], "-i");
        assert_eq!(server["args"][1], "--");
        for key in crate::pilot_host::PROVIDER_ENV {
            assert_eq!(server["env"][key], "");
        }
        let words = server["args"].as_array().unwrap();
        assert!(words
            .iter()
            .any(|word| word == config.agent_bin_path.to_str().unwrap()));
        assert!(words.iter().any(|word| word
            .as_str()
            .is_some_and(|w| w.starts_with("AGENTFW_HOST_SESSION="))));
    }

    // Verify tokens are redacted in plans
    assert!(plans["filesystem"].token_redacted);
    assert_eq!(plans["filesystem"].args[7], "[REDACTED]");

    // Verify real server command after --
    assert_eq!(plans["filesystem"].args[10], "--");
    assert_eq!(plans["filesystem"].args[11], "/usr/bin/node");
    assert_eq!(plans["git"].args[10], "--");
    assert_eq!(plans["git"].args[11], "/usr/bin/python3");

    // Verify mcp.json contains environment variables
    let mcp_data: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&mcp_config).unwrap()).unwrap();
    let env_for = |server: &str| {
        mcp_data["mcpServers"][server]["args"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|word| word.as_str().and_then(|word| word.split_once('=')))
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<BTreeMap<_, _>>()
    };
    let fs_env = env_for("filesystem");
    let git_env = env_for("git");
    assert_eq!(
        git_env["AGENTFW_WORKSPACE"],
        git_workspace.canonicalize().unwrap().display().to_string()
    );
    assert_eq!(fs_env["AGENTFW_CLASSIFIER_PYTHON"], "/usr/bin/python3");
    assert_eq!(git_env["AGENTFW_CLASSIFIER_PYTHON"], "/usr/bin/python3");
    assert_eq!(fs_env["AGENTFW_HOST_SESSION"], "test-session-123");
    assert_eq!(fs_env["AGENTFW_NATIVE_LIVENESS"], "true");
    assert_eq!(
        fs_env["AGENTFW_WORKSPACE"],
        workspace.canonicalize().unwrap().display().to_string()
    );

    // The credential scrubber must preserve explicitly selected budget
    // authority in each collector's finite environment and launch arguments.
    let budget_path = temp.path().join("selected-budget.json");
    config.linux_budget = Some(budget_path.clone());
    config.linux_budget_sha256 = Some("b".repeat(64));
    let (budget_mcp, _) =
        write_per_process_mcp_config(&guard.path, &config, &grants, None).unwrap();
    let budget_mcp: serde_json::Value =
        serde_json::from_slice(&fs::read(budget_mcp).unwrap()).unwrap();
    for server in budget_mcp["mcpServers"].as_object().unwrap().values() {
        assert_eq!(server["command"], "/usr/bin/env");
        let words = server["args"].as_array().unwrap();
        assert!(words.iter().any(|word| word
            == &serde_json::json!(format!(
                "{}={}",
                crate::mcp::linux_budget::ENVIRONMENT,
                budget_path.display()
            ))));
        assert!(words.iter().any(|word| word
            .as_str()
            .is_some_and(|word| word.starts_with("AGENTFW_PILOT_BUDGET_BINDING="))));
        assert!(words.iter().any(|word| word == "--pilot-budget-binding"));
        assert!(words.iter().any(|word| word == "--pilot-budget-sha256"));
        for key in crate::pilot_host::PROVIDER_ENV {
            assert_eq!(server["env"][key], "");
            assert!(!words.iter().any(|word| word
                .as_str()
                .is_some_and(|word| word.starts_with(&format!("{key}=")))));
        }
    }
}

#[test]
fn test_colliding_tools_between_servers_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let claude = temp.path().join("claude");
    dummy_script(&claude);

    let workspace = temp.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();

    let fs_profile = temp.path().join("fs.json");
    fs::write(&fs_profile, r#"{"tools":[{"name":"shared_tool"}]}"#).unwrap();

    let git_profile = temp.path().join("git.json");
    fs::write(&git_profile, r#"{"tools":[{"name":"shared_tool"}]}"#).unwrap();

    let args = PilotLaunchArgs {
        git_workspace: None,
        claude,
        workspace,
        home: None,
        fs_profile,
        git_profile,
        classifier: None,
        policy: None,
        host_session: None,
        agent_bin: None,
        dry_run: true,
        timeout_seconds: 60,
        ask_wait_seconds: 0,
        json: false,
        prompt: None,
        model: "claude-sonnet-4-20250514".into(),
        effort: None,
        mock_daemon_token: Some(crate::token::generate()),
        mock_instance_id: Some(crate::token::generate()),
        provider_env_fd: None,
        maintenance_home: None,
        maintenance_component_home: None,
        maintenance_run: None,
        provider_ca_fd: None,
        provider_ca_sha256: None,
        linux_budget: None,
        linux_budget_sha256: None,
        allow_command_fixtures: false,
    };

    assert!(args.validate().is_err());
}

#[test]
fn test_unverified_command_json_rejected_outside_mock_mode() {
    let temp = tempfile::tempdir().unwrap();
    let claude = temp.path().join("claude");
    dummy_script(&claude);

    let workspace = temp.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();

    let fs_profile = temp.path().join("fs.json");
    fs::write(&fs_profile, r#"{"command":"/bin/echo","args":["hello"]}"#).unwrap();

    let git_profile = temp.path().join("git.json");
    fs::write(&git_profile, r#"{"command":"/bin/echo","args":["world"]}"#).unwrap();

    let args = PilotLaunchArgs {
        git_workspace: None,
        claude,
        workspace,
        home: None,
        fs_profile,
        git_profile,
        classifier: None,
        policy: None,
        host_session: None,
        agent_bin: None,
        dry_run: true,
        timeout_seconds: 60,
        ask_wait_seconds: 0,
        json: false,
        prompt: None,
        model: "claude-sonnet-4-20250514".into(),
        effort: None,
        mock_daemon_token: None,
        mock_instance_id: None,
        provider_env_fd: None,
        maintenance_home: None,
        maintenance_component_home: None,
        maintenance_run: None,
        provider_ca_fd: None,
        provider_ca_sha256: None,
        linux_budget: None,
        linux_budget_sha256: None,
        allow_command_fixtures: false,
    };

    let err = args.validate().unwrap_err();
    assert!(err
        .to_string()
        .contains("real pilot requires validated ProfileConfig"));
}

#[test]
fn test_missing_profile_rejected_outside_mock_mode() {
    let temp = tempfile::tempdir().unwrap();
    let claude = temp.path().join("claude");
    dummy_script(&claude);

    let workspace = temp.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();

    let fs_dir = temp.path().join("fs_empty");
    fs::create_dir_all(&fs_dir).unwrap();

    let git_dir = temp.path().join("git_empty");
    fs::create_dir_all(&git_dir).unwrap();

    let args = PilotLaunchArgs {
        git_workspace: None,
        claude,
        workspace,
        home: None,
        fs_profile: fs_dir,
        git_profile: git_dir,
        classifier: None,
        policy: None,
        host_session: None,
        agent_bin: None,
        dry_run: true,
        timeout_seconds: 60,
        ask_wait_seconds: 0,
        json: false,
        prompt: None,
        model: "claude-sonnet-4-20250514".into(),
        effort: None,
        mock_daemon_token: None,
        mock_instance_id: None,
        provider_env_fd: None,
        maintenance_home: None,
        maintenance_component_home: None,
        maintenance_run: None,
        provider_ca_fd: None,
        provider_ca_sha256: None,
        linux_budget: None,
        linux_budget_sha256: None,
        allow_command_fixtures: false,
    };

    let err = args.validate().unwrap_err();
    assert!(err
        .to_string()
        .contains("installed MCP server profile not found"));
}

#[test]
fn test_command_fixtures_allowed_with_flag() {
    let temp = tempfile::tempdir().unwrap();
    let claude = temp.path().join("claude");
    dummy_script(&claude);

    let workspace = temp.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();

    let fs_profile = temp.path().join("fs.json");
    fs::write(&fs_profile, r#"{"command":"/bin/echo","args":["hello"]}"#).unwrap();

    let git_profile = temp.path().join("git.json");
    fs::write(&git_profile, r#"{"command":"/bin/echo","args":["world"]}"#).unwrap();

    let args = PilotLaunchArgs {
        git_workspace: None,
        claude,
        workspace,
        home: None,
        fs_profile,
        git_profile,
        classifier: None,
        policy: None,
        host_session: None,
        agent_bin: None,
        dry_run: true,
        timeout_seconds: 60,
        ask_wait_seconds: 0,
        json: false,
        prompt: None,
        model: "claude-sonnet-4-20250514".into(),
        effort: None,
        mock_daemon_token: None,
        mock_instance_id: None,
        provider_env_fd: None,
        maintenance_home: None,
        maintenance_component_home: None,
        maintenance_run: None,
        provider_ca_fd: None,
        provider_ca_sha256: None,
        linux_budget: None,
        linux_budget_sha256: None,
        allow_command_fixtures: true,
    };

    let cfg = args
        .validate()
        .expect("should succeed with allow_command_fixtures");
    assert_eq!(cfg.fs_runtime_cmd, vec!["/bin/echo", "hello"]);
    assert_eq!(cfg.git_runtime_cmd, vec!["/bin/echo", "world"]);
}
