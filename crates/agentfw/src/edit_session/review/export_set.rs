// SPDX-License-Identifier: Apache-2.0
//! Explicit, source-bound result-set confirmation over the accepted review path.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

const FORMAT: &str = "sw-installed-edit-export-set/1";
static CANCELLED: AtomicBool = AtomicBool::new(false);

#[derive(ClapArgs, Debug)]
pub(in crate::edit_session) struct Args {
    #[arg(long)]
    run: PathBuf,
    #[arg(long)]
    sha256: String,
    /// Two to eight exact declared mutation-output names, each selected once.
    #[arg(long = "include", required = true)]
    include: Vec<String>,
    /// Exact new absolute private directory, outside all selected state.
    #[arg(long)]
    out: PathBuf,
    /// Allow local review and copying of these selected private file contents.
    #[arg(long)]
    consent_private_content: bool,
    #[arg(long, requires_all = ["confirm", "consent_private_content"])]
    apply: bool,
    /// Exact confirmation_sha256 from a fresh preview of this set and destination.
    #[arg(long, requires = "apply")]
    confirm: Option<String>,
}

extern "C" fn cancelled(_: libc::c_int) {
    CANCELLED.store(true, Ordering::Relaxed);
}
/// Temporary CLI-only handlers. No signal handler performs filesystem work.
struct Cancellation {
    interrupt: libc::sigaction,
    terminate: libc::sigaction,
}
impl Cancellation {
    fn install() -> Result<Self> {
        CANCELLED.store(false, Ordering::Relaxed);
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut interrupt = unsafe { std::mem::zeroed() };
        let mut terminate = unsafe { std::mem::zeroed() };
        action.sa_sigaction = cancelled as *const () as libc::sighandler_t;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        ensure!(
            unsafe { libc::sigaction(libc::SIGINT, &action, &mut interrupt) } == 0,
            "edit_export_cancel_handler_unavailable"
        );
        if unsafe { libc::sigaction(libc::SIGTERM, &action, &mut terminate) } != 0 {
            unsafe { libc::sigaction(libc::SIGINT, &interrupt, std::ptr::null_mut()) };
            anyhow::bail!("edit_export_cancel_handler_unavailable");
        }
        Ok(Self {
            interrupt,
            terminate,
        })
    }
    fn check(&self) -> Result<()> {
        ensure!(!CANCELLED.load(Ordering::Relaxed), "edit_export_cancelled");
        Ok(())
    }
}
impl Drop for Cancellation {
    fn drop(&mut self) {
        unsafe {
            libc::sigaction(libc::SIGINT, &self.interrupt, std::ptr::null_mut());
            libc::sigaction(libc::SIGTERM, &self.terminate, std::ptr::null_mut());
        }
    }
}

fn chosen<'a>(names: &[String], review: &'a Reviewed) -> Result<Vec<&'a Output>> {
    ensure!(
        (2..=profile::MAX_TARGETS).contains(&names.len()),
        "edit_export_set_count"
    );
    let selected = selected(names, &review.observation.outputs)?;
    selected
        .into_iter()
        .map(|name| {
            ensure!(name != "manifest.json", "edit_export_reserved_name");
            let output = review
                .observation
                .outputs
                .iter()
                .find(|o| o.name == name)
                .unwrap();
            ensure!(
                output.content.is_some()
                    && output.identity.is_some()
                    && output.sha256.is_some()
                    && output.bytes.is_some(),
                "edit_export_selected_file_missing"
            );
            Ok(output)
        })
        .collect()
}

fn run(args: &Args, cancel: &Cancellation) -> Result<serde_json::Value> {
    ensure!(
        args.consent_private_content,
        "edit_export_private_content_consent_required"
    );
    cancel.check()?;
    let read = super::Args {
        run: args.run.clone(),
        sha256: args.sha256.clone(),
        show: vec![],
        baseline: vec![],
        consent_private_content: true,
        export: None,
        include: vec![],
        expect_observation: None,
    };
    let mut budget = Budget::new();
    let reviewed = observe(&read, &mut budget)?;
    let files = chosen(&args.include, &reviewed)?;
    for protected in [
        &args.run,
        &reviewed.selection.profile.root,
        &reviewed.selection.profile.component.home,
    ] {
        ensure!(
            !args.out.starts_with(protected) && !protected.starts_with(&args.out),
            "edit_export_destination_overlaps_state"
        );
    }
    let destination = crate::private_export::Destination::select(&args.out)?;
    let entries: Vec<_> = files
        .iter()
        .map(|o| {
            serde_json::json!({
                "name":o.name, "bytes":o.bytes, "sha256":o.sha256, "identity":o.identity
            })
        })
        .collect();
    // The entire selected set, exact destination and retained run/profile/
    // terminal/cleanup binding are one finite confirmation. No raw receipts.
    let preview = serde_json::json!({"format":FORMAT,
        "run_sha256":reviewed.observation.run_sha256,
        "profile_sha256":reviewed.observation.profile_sha256,
        "binding_sha256":reviewed.observation.binding_sha256,
        "observation_sha256":profile::digest(&reviewed.observation)?,
        "destination":destination.binding(), "files":entries});
    let confirmation = profile::digest(&preview)?;
    recheck(&read, &reviewed, &mut budget)?;
    cancel.check()?;
    if args.apply {
        ensure!(
            args.confirm.as_deref() == Some(confirmation.as_str()),
            "edit_export_confirmation_mismatch"
        );
        let manifest = serde_json::to_vec(&serde_json::json!({
            "format":"sw-installed-edit-private-result-set/1",
            "privacy":"explicitly_selected_private_content_local_only",
            "confirmation_sha256":confirmation,
            "run_sha256":reviewed.observation.run_sha256,
            "profile_sha256":reviewed.observation.profile_sha256,
            "files":entries
        }))?;
        ensure!(manifest.len() <= 32 * 1024, "edit_export_manifest_cap");
        let mut copies: Vec<_> = files
            .iter()
            .map(|o| (o.name.as_str(), o.content.as_ref().unwrap().as_slice()))
            .collect();
        copies.push(("manifest.json", &manifest));
        destination.publish(&copies, || {
            cancel.check()?;
            recheck(&read, &reviewed, &mut budget)?;
            cancel.check()
        })?;
        cancel.check()?;
    }
    let display: Vec<_> = files.iter().map(|o| -> Result<_> {
        Ok(if o.text {
            serde_json::json!({"name":o.name,"encoding":"rust_ascii_escaped_untrusted_text",
                "text":escaped(o.content.as_ref().unwrap())?})
        } else {
            serde_json::json!({"name":o.name,"encoding":"binary_not_rendered","sha256":o.sha256,"bytes":o.bytes})
        })
    }).collect::<Result<_>>()?;
    let value = serde_json::json!({"format":FORMAT,"status":if args.apply {"published"} else {"preview"},
        "confirmation_sha256":confirmation,"selection":preview,"display":display,
        "private_content":true,"executed":false,"authority":false});
    ensure!(
        serde_json::to_vec(&value)?.len() <= 384 * 1024,
        "edit_export_response_cap"
    );
    Ok(value)
}

pub(in crate::edit_session) fn command(args: Args) -> Result<()> {
    let result = Cancellation::install().and_then(|cancel| run(&args, &cancel));
    match result {
        Ok(value) => {
            println!("{}", serde_json::to_string(&value)?);
            Ok(())
        }
        Err(error) => {
            let reason = error
                .chain()
                .filter_map(|e| {
                    let code = e.to_string();
                    (code.len() <= 128
                        && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                        && [
                            "export_",
                            "edit_",
                            "selected_",
                            "current_",
                            "terminal_",
                            "retained_",
                        ]
                        .iter()
                        .any(|p| code.starts_with(p)))
                    .then_some(code)
                })
                .next()
                .unwrap_or_else(|| "edit_export_selected_state_or_io_unavailable".into());
            println!(
                "{}",
                serde_json::json!({"format":FORMAT,"status":"incomplete","reason":reason,
                "publication":"not_confirmed_destination_may_be_absent_or_complete",
                "cleanup":"verified_owned_stage_objects_only_changed_or_unavailable_objects_may_remain",
                "executed":false,"authority":false})
            );
            anyhow::bail!("edit_export_set_incomplete")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct Grammar {
        #[command(flatten)]
        args: Args,
    }
    #[test]
    fn apply_requires_exact_confirmation_and_private_consent() {
        let words = [
            "export-set",
            "--run",
            "/private/run",
            "--sha256",
            &"a".repeat(64),
            "--include",
            "a.txt",
            "--include",
            "b.txt",
            "--out",
            "/private/export",
        ];
        assert!(Grammar::try_parse_from(words.iter().copied().chain(["--apply"])).is_err());
        assert!(Grammar::try_parse_from(words.iter().copied().chain([
            "--apply",
            "--confirm",
            &"b".repeat(64)
        ]))
        .is_err());
        assert!(Grammar::try_parse_from(
            words.iter().copied().chain(["--consent-private-content"])
        )
        .is_ok());
    }
}
