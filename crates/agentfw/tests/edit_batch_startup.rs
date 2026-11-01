// SPDX-License-Identifier: Apache-2.0
use std::process::Command;
#[test]
fn installed_batch_help_respects_compiled_platform() {
    let binary = env!("CARGO_BIN_EXE_agentfw");
    if cfg!(target_os = "linux") {
        for action in [
            "preview",
            "apply",
            "status",
            "recover-preview",
            "recover",
            "revert-preview",
            "revert",
        ] {
            let out = Command::new(binary)
                .args(["edit-session", "batch", action, "--help"])
                .output()
                .unwrap();
            assert!(out.status.success(), "{action}");
        }
    } else {
        let out = Command::new(binary)
            .args(["edit-session", "batch", "--help"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("batch"));
        assert!(Command::new(binary)
            .args(["edit-session", "--help"])
            .output()
            .unwrap()
            .status
            .success());
    }
}
