// SPDX-License-Identifier: Apache-2.0
//! The Linux-only grammar and its implementation must share the cfg boundary.
use std::process::Command;

#[test]
fn installed_edit_cli_starts_on_the_compiled_platform() {
    let binary = env!("CARGO_BIN_EXE_agentfw");
    for args in [
        vec!["--help"],
        vec!["edit-session", "--help"],
        vec!["edit-session", "status", "--help"],
    ] {
        let result = Command::new(binary).args(&args).output().unwrap();
        assert!(
            result.status.success(),
            "startup {:?}: {}",
            args,
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let result = Command::new(binary)
        .args(["edit-session", "apply", "--help"])
        .output()
        .unwrap();
    #[cfg(target_os = "linux")]
    {
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let help = String::from_utf8(result.stdout).unwrap();
        for command in ["preview", "commit", "status", "revert-preview", "revert"] {
            assert!(help.contains(command), "missing {command}");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(result.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&result.stderr).contains("unrecognized subcommand"));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn operator_application_subcommands_parse_without_booting_runtime() {
    let binary = env!("CARGO_BIN_EXE_agentfw");
    for command in [
        "preview",
        "commit",
        "status",
        "recover",
        "revert-preview",
        "revert",
    ] {
        let result = Command::new(binary)
            .args(["edit-session", "apply", command, "--help"])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}: {}",
            command,
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
