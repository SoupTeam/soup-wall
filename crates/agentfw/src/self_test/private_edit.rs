// SPDX-License-Identifier: Apache-2.0
//! Fixed installed helper dispatch; all mutations use accepted edit-session APIs.
use std::path::PathBuf;

pub(crate) fn unexecuted(status: &str, reason: &str) -> i32 {
    let names = [
        "create-read",
        "replace-read",
        "ask-reject-replay",
        "aggregate-quota",
        "exact-run-stop",
        "stopped-authority",
        "daemon-loss",
        "fresh-run-recovery",
    ];
    let unsupported = status == "unsupported";
    let rows: Vec<_> = names
        .iter()
        .map(|name| {
            serde_json::json!({"id":name,"attempted":false,"status":if unsupported {"unsupported"} else {"incomplete"}})
        })
        .collect();
    println!(
        "{}",
        serde_json::json!({"format":"sw-private-edit-self-test/1", "status":status,
            "executed":false,"reason":reason,"paid_inference":false,
            "expected":names,"cases":rows,
            "inventory":{"expected":8,"attempted":0,"passed":0,"failed":0,
                "incomplete":if unsupported {0} else {8},"unsupported":if unsupported {8} else {0}}})
    );
    if unsupported {
        super::EXIT_UNSUPPORTED
    } else {
        super::EXIT_INCOMPLETE
    }
}

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Existing private Agent home containing the verified pilot component.
    #[arg(long)]
    home: PathBuf,
    /// Current prepared pilot selection; never discovered from PATH.
    #[arg(long)]
    selection: PathBuf,
    /// Explicit consent to start owned processes and edit disposable outputs.
    #[arg(long, requires = "output")]
    run: bool,
    /// Fresh absolute directory for the report and disposable owned workspace.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Upper bound for the complete execution, including cleanup.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(10..=600))]
    timeout_seconds: u64,
    /// Retain only the owned synthetic workspace for private inspection.
    #[arg(long, requires = "run")]
    keep_workspace: bool,
}

pub fn run(args: Args) -> i32 {
    #[cfg(target_os = "linux")]
    {
        let agent = match std::env::current_exe() {
            Ok(path) => path,
            Err(_) => {
                return unexecuted("incomplete", "installed_agent_unavailable");
            }
        };
        let mut words = vec![
            "--home".into(),
            args.home.as_os_str().to_owned(),
            "--selection".into(),
            args.selection.into_os_string(),
            "--agent".into(),
            agent.into_os_string(),
            "--timeout-seconds".into(),
            args.timeout_seconds.to_string().into(),
        ];
        if args.run {
            words.push("--run".into());
        }
        if let Some(path) = args.output {
            words.extend(["--output".into(), path.into_os_string()]);
        }
        if args.keep_workspace {
            words.push("--keep-workspace".into());
        }
        crate::pilot_component::exec_private_edit_self_test(&args.home, &words)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        unexecuted("unsupported", "private_edit_requires_linux_x86_64")
    }
}
