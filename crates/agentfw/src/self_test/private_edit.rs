// SPDX-License-Identifier: Apache-2.0
//! Fixed installed helper dispatch; all mutations use accepted edit-session APIs.
use std::path::PathBuf;

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
                eprintln!("private edit self-test: installed_agent_unavailable");
                return super::EXIT_INCOMPLETE;
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
        println!(
            "{}",
            serde_json::json!({"format":"sw-private-edit-self-test/1", "status":"unsupported",
                "executed":false,"reason":"private_edit_requires_linux_x86_64",
                "inventory":{"attempted":0,"passed":0,"failed":0,"incomplete":0,"unsupported":1}})
        );
        super::EXIT_UNSUPPORTED
    }
}
