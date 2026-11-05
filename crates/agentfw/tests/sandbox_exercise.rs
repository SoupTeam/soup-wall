// SPDX-License-Identifier: Apache-2.0
//! Public sandbox exercises refuse special-file assets before calibration.
#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn fifo_assets_refuse_within_a_separate_process_deadline() {
    let owned = tempfile::tempdir().unwrap();
    let fifo = owned.path().join("asset.fifo");
    let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_agentfw"));
    let digest = format!("{:x}", Sha256::digest(std::fs::read(binary).unwrap()));
    let regular = json!({"path": binary, "sha256": digest});

    for asset in [
        "runtimePath",
        "bwrapPath",
        "libraries",
        "git",
        "gitLauncher",
    ] {
        let git = matches!(asset, "git" | "gitLauncher");
        let mut profile = json!({
            "format": if git { "sw-mcp/git-readonly/1" } else { "sw-mcp/filesystem-readonly/1" },
            "workspace": owned.path(), "packageRoot": owned.path(),
            "packageTreeSha256": "0".repeat(64),
            "runtimePath": binary, "runtimeSha256": digest,
            "bwrapPath": binary, "bwrapSha256": digest, "libraries": []
        });
        if git {
            profile["git"] = regular.clone();
            profile["gitLauncher"] = regular.clone();
        }
        profile[asset] = match asset {
            "libraries" => json!([{"path": fifo, "sha256": digest}]),
            "git" | "gitLauncher" => json!({"path": fifo, "sha256": digest}),
            _ => json!(fifo),
        };
        let bytes = serde_json::to_vec(&profile).unwrap();
        let path = owned.path().join("profile.json");
        std::fs::write(&path, &bytes).unwrap();
        let mut child = Command::new(binary)
            .args(["sandbox-exercise", "--execute", "--kind"])
            .arg(if git { "git" } else { "filesystem" })
            .arg("--profile")
            .arg(&path)
            .arg("--profile-sha256")
            .arg(format!("{:x}", Sha256::digest(&bytes)))
            .env_clear()
            .env("HOME", owned.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("sandbox exercise blocked on FIFO {asset}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(3), "{asset}");
        assert!(output.stderr.is_empty(), "{asset}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["status"], "failed", "{asset}");
        assert_eq!(report["reason"], "input_identity_mismatch", "{asset}");
    }
}
