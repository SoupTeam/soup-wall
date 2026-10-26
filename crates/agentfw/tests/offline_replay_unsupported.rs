// SPDX-License-Identifier: Apache-2.0
//! Explicit refusal on platforms without the Unix private-file contract.
#![cfg(not(unix))]

use std::fs;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn offline_cli_refuses_unsupported_platform_without_discovery_or_output() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let home = root.join("absent-agent-home");
    let input = root.join("input.json");
    let policy = root.join("policy.yaml");
    let output = root.join("report.json");
    let events = include_bytes!("fixtures/offline-replay/sequence.json");
    let rules = include_bytes!("../../agent/policies/agent-default.yaml");
    fs::write(&input, events).unwrap();
    fs::write(&policy, rules).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentfw"));
    command
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join("config"));
    // Keep only the OS loader path needed by a native Windows process.
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    let mut child = command
        .args(["replay", "--offline", "--input"])
        .arg(&input)
        .arg("--policy")
        .arg(&policy)
        .arg("--output")
        .arg(&output)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("bounded unsupported-platform CLI timed out");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert_eq!(
        String::from_utf8(result.stderr).unwrap().trim(),
        "Offline replay failed: offline_platform_unsupported"
    );
    assert!(!home.exists());
    assert!(!output.exists());
    assert_eq!(fs::read(&input).unwrap().as_slice(), events.as_slice());
    assert_eq!(fs::read(&policy).unwrap().as_slice(), rules.as_slice());
}
