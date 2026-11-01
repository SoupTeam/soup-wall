// SPDX-License-Identifier: Apache-2.0
//! CLI parsing and dispatch must not require a larger process stack.
#![cfg(any(target_os = "linux", windows))]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn ordinary_cli_startup_fits_a_standard_stack_before_execution() {
    let probes = vec![
        (&["--help"][..], 0, None),
        (&["install"][..], 0, None),
        (
            &[
                "mcp",
                "--native-admission",
                "--id",
                "stack-probe",
                "--",
                "unused-server",
            ][..],
            1,
            Some("operator-installed registry"),
        ),
    ];
    #[cfg(target_os = "linux")]
    let probes = {
        let mut probes = probes;
        probes.extend([
            (&["policy-candidate", "preview", "--help"][..], 0, None),
            (&["edit-session", "inventory", "--help"][..], 0, None),
            (&["edit-session", "with-run", "--help"][..], 0, None),
            (&["edit-session", "export-set", "--help"][..], 0, None),
            (&["edit-session", "apply", "--help"][..], 0, None),
            (&["edit-session", "archive", "--help"][..], 0, None),
        ]);
        probes
    };
    for (arguments, expected, refusal) in probes {
        let home = tempfile::tempdir().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_agentfw"));
        command.args(arguments).env_clear();
        for key in [
            "PATH",
            "SystemRoot",
            "WINDIR",
            "COMSPEC",
            "SYSTEMDRIVE",
            "PATHEXT",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("APPDATA", home.path().join("appdata"))
            .env("LOCALAPPDATA", home.path().join("localappdata"))
            .current_dir(home.path())
            .stdin(Stdio::null())
            // Install prints token-bearing instructions; never retain them.
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            // Lower only this disposable child to Windows' ordinary 1 MiB
            // startup envelope. Windows uses its actual default stack.
            // SAFETY: after fork, only getrlimit/setrlimit OS calls and errno
            // reads run here; no allocation, locks or parent state is used.
            unsafe {
                command.pre_exec(|| {
                    let mut inherited = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::getrlimit(libc::RLIMIT_STACK, &mut inherited) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let cap = inherited.rlim_cur.min(inherited.rlim_max).min(1024 * 1024);
                    let limit = libc::rlimit {
                        rlim_cur: cap,
                        rlim_max: cap,
                    };
                    if libc::setrlimit(libc::RLIMIT_STACK, &limit) == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                });
            }
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("CLI startup did not finish for {arguments:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(expected), "{arguments:?}");
        assert!(!stderr.contains("overflowed its stack"));
        if let Some(reason) = refusal {
            assert!(
                stderr.contains(reason),
                "missing expected refusal: {arguments:?}"
            );
        }
    }
}
