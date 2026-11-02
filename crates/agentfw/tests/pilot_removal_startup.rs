// SPDX-License-Identifier: Apache-2.0
use std::process::Command;

#[test]
fn configuration_projection_remains_available_with_installed_removal() {
    let output = Command::new(env!("CARGO_BIN_EXE_agentfw"))
        .args(["configuration-project", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("--policy"));
}

#[test]
fn removal_cli_and_types_share_linux_boundary_and_remain_installed() {
    let binary = env!("CARGO_BIN_EXE_agentfw");
    let output = Command::new(binary)
        .args(["pilot-removal", "--help"])
        .output()
        .unwrap();
    #[cfg(target_os = "linux")]
    {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for action in ["preview", "apply", "status", "resume"] {
            let output = Command::new(binary)
                .args(["pilot-removal", action, "--help"])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
    }
}
