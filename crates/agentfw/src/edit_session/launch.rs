// SPDX-License-Identifier: Apache-2.0
//! Operator consent, immutable installed selection and read-only preflight.
use super::{
    profile::{self, Baseline, Component, Pin, Profile, Target},
    Action, Ask, Selection, FORMAT,
};
use crate::mcp::replace_file;
use anyhow::{ensure, Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

pub(super) const POLICY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../profiles/pilot/linux-private-edit-v1/policy.yaml"
));
pub(super) const MAX_PLAN: u64 = 128 * 1024;

pub(super) fn policy() -> Result<soup_wall_agent::AgentPolicySet> {
    Ok(soup_wall_agent::AgentPolicySet::from_yaml(POLICY)?)
}

pub(super) fn private_dir(path: &Path) -> Result<()> {
    replace_file::inspect_workspace(path)
        .map(|_| ())
        .map_err(anyhow::Error::new)
}
fn file(path: &Path, cap: u64) -> Result<File> {
    ensure!(
        path.is_absolute() && path.as_os_str().len() <= 4096,
        "edit_absolute_path_required"
    );
    for p in path.ancestors() {
        let metadata = fs::symlink_metadata(p)?;
        ensure!(!metadata.is_symlink(), "edit_linked_input");
        if p != path {
            // A protected leaf inside a replaceable directory is not a pin.
            // Sticky owned ancestors (e.g. /tmp) protect the already owned next
            // entry; otherwise no group/other writer may redirect the path.
            ensure!(
                metadata.is_dir()
                    && (metadata.uid() == 0 || metadata.uid() == unsafe { libc::geteuid() })
                    && (metadata.mode() & 0o022 == 0 || metadata.mode() & libc::S_ISVTX != 0),
                "edit_input_ancestry"
            );
        }
    }
    ensure!(
        path.canonicalize()?.as_os_str() == path.as_os_str(),
        "edit_input_alias"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.len() <= cap
            && m.mode() & 0o022 == 0
            && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() }),
        "edit_input_metadata"
    );
    Ok(file)
}

pub(super) fn bytes(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let file = file(path, cap)?;
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= cap, "edit_input_cap");
    Ok(bytes)
}
fn pin(path: &Path, cap: u64) -> Result<Pin> {
    let mut file = file(path, cap)?;
    let before = file.metadata()?;
    let mut h = Sha256::new();
    let mut buffer = [0; 65536];
    let mut total = 0;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(total <= cap, "edit_runtime_cap");
        h.update(&buffer[..n]);
    }
    let after = file.metadata()?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
            m.mode(),
        )
    };
    ensure!(
        identity(&before) == identity(&after),
        "edit_runtime_changed"
    );
    Ok(Pin {
        path: path.into(),
        sha256: format!("{:x}", h.finalize()),
    })
}
pub(super) fn write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}
fn component(home: &Path) -> Result<Component> {
    let c = crate::pilot_component::Store::new(home)
        .current()
        .map_err(|e| anyhow::anyhow!("edit_component_unavailable: {}", e.reason))?;
    let classifier = c.tree.join("rule_baseline/rule_baseline.py");
    Ok(Component {
        home: home.into(),
        id: c.id,
        source_commit: c.manifest.source.commit,
        source_tree: c.manifest.source.tree,
        python: Pin {
            path: c.python.path.into(),
            sha256: c.python.sha256,
        },
        python_version: c.python.version,
        classifier: pin(&classifier, 1024 * 1024)?,
    })
}
fn selected(args: Selection) -> Result<Profile> {
    let mutation_quota = match (args.max_mutations, args.max_write_bytes) {
        (None, None) => None,
        (Some(operations), Some(bytes)) => Some(super::quota::Limits::new(operations, bytes)?),
        _ => anyhow::bail!("edit_quota_both_limits_required"),
    };
    ensure!(
        cfg!(target_arch = "x86_64"),
        "installed_edit_requires_native_linux_x86_64"
    );
    ensure!(
        args.private_sole_writer,
        "edit_explicit_private_sole_writer_required"
    );
    let root_identity = replace_file::inspect_workspace(&args.root)?;
    let mut targets = BTreeMap::<String, Target>::new();
    for (kind, names) in [
        ("read", args.read),
        ("create", args.create),
        ("replace", args.replace),
    ] {
        for name in names {
            ensure!(profile::leaf(&name), "edit_direct_child_required");
            let t = targets.entry(name.clone()).or_insert(Target {
                name,
                read: false,
                create: false,
                replacement: None,
            });
            match kind {
                "read" => {
                    ensure!(!t.read, "edit_duplicate_target");
                    t.read = true;
                }
                "create" => {
                    ensure!(
                        !t.create && t.replacement.is_none(),
                        "edit_conflicting_target"
                    );
                    t.create = true;
                }
                _ => {
                    ensure!(
                        !t.create && t.replacement.is_none(),
                        "edit_conflicting_target"
                    );
                    let p = replace_file::preview(&args.root, &args.root.join(&t.name), "")?;
                    t.replacement = Some(Baseline {
                        identity: p.old_identity,
                        sha256: p.old_sha256,
                    });
                }
            }
        }
    }
    ensure!(
        targets
            .values()
            .any(|t| t.create || t.replacement.is_some()),
        "edit_mutation_selection_required"
    );
    let component = component(&args.home)?;
    let claude = pin(&args.claude, 512 * 1024 * 1024)?;
    crate::pilot_host::validate(&args.claude, false)?;
    let p = Profile {
        format: if mutation_quota.is_some() {
            super::QUOTA_PROFILE
        } else {
            FORMAT
        }
        .into(),
        mutation_quota,
        refreshed_from_sha256: None,
        exclusion: replace_file::EXCLUSION.into(),
        root: args.root,
        root_identity,
        agent: pin(&std::env::current_exe()?.canonicalize()?, 512 * 1024 * 1024)?,
        claude,
        component,
        policy_sha256: profile::digest(&policy()?)?,
        targets: targets.into_values().collect(),
    };
    verify(&p)?;
    Ok(p)
}
pub(super) fn verify(p: &Profile) -> Result<()> {
    verify_anchors(p)?;
    verify_targets(p)
}
pub(super) fn verify_anchors(p: &Profile) -> Result<()> {
    p.validate()?;
    ensure!(
        replace_file::inspect_workspace(&p.root)? == p.root_identity,
        "edit_root_changed"
    );
    ensure!(
        p.agent == pin(&std::env::current_exe()?.canonicalize()?, 512 * 1024 * 1024)?
            && p.claude == pin(&p.claude.path, 512 * 1024 * 1024)?,
        "edit_runtime_changed"
    );
    crate::pilot_host::validate(&p.claude.path, false)?;
    ensure!(
        component(&p.component.home)? == p.component,
        "edit_component_changed"
    );
    ensure!(
        p.policy_sha256 == profile::digest(&policy()?)?,
        "edit_policy_changed"
    );
    Ok(())
}
pub(super) fn verify_targets(p: &Profile) -> Result<()> {
    for target in &p.targets {
        let path = p.root.join(&target.name);
        if target.create {
            ensure!(
                fs::symlink_metadata(&path)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "edit_create_target_exists"
            );
            crate::mcp::create_file::PreparedCreate::prepare(
                &crate::sandbox::PinnedWorkspace::open(&p.root)?,
                &path,
                "",
            )
            .map_err(anyhow::Error::new)?;
        } else {
            let live = replace_file::preview(&p.root, &path, "")?;
            if let Some(old) = &target.replacement {
                ensure!(
                    old.identity == live.old_identity && old.sha256 == live.old_sha256,
                    "edit_baseline_changed"
                );
            }
        }
    }
    // Startup validates all generated bindings, supported operations and floors.
    let raw = profile::canonical(&p.registry()?)?;
    crate::native::NativeState::from_bytes(
        &raw,
        &replace_file::content_sha256(&raw),
        crate::token::generate(),
    )?;
    Ok(())
}
struct Stage(std::path::PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        // A private sole-writer state directory; only these two owned entries
        // are ever removed. Publication moves the directory away atomically.
        for name in ["profile.json", "profile.sha256"] {
            let _ = fs::remove_file(self.0.join(name));
        }
        let _ = fs::remove_dir(&self.0);
    }
}
fn publish(out: &Path, p: &Profile) -> Result<()> {
    publish_checked(out, p, || Ok(()))
}
/// Shared create-new staging and atomic no-clobber publication. Refresh checks
/// its exact input again after staging, before the only publication point.
pub(super) fn publish_checked(
    out: &Path,
    p: &Profile,
    revalidate: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let parent = out.parent().context("edit_plan_parent")?;
    private_dir(parent)?;
    let name = out
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| profile::leaf(s))
        .context("edit_plan_name")?;
    ensure!(
        !out.starts_with(&p.root) && !p.root.starts_with(out),
        "edit_state_overlaps_output"
    );
    let stage = Stage(parent.join(format!("edit-stage-{}", crate::token::generate())));
    fs::DirBuilder::new().mode(0o700).create(&stage.0)?;
    write(
        &stage.0.as_path().join("profile.json"),
        &profile::canonical(p)?,
        0o400,
    )?;
    write(
        &stage.0.as_path().join("profile.sha256"),
        profile::digest(p)?.as_bytes(),
        0o400,
    )?;
    File::open(stage.0.as_path())?.sync_all()?;
    revalidate()?;
    private_dir(parent)?;
    let from = std::ffi::CString::new(stage.0.as_path().as_os_str().as_bytes())?;
    let dest = std::ffi::CString::new(parent.join(name).as_os_str().as_bytes())?;
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                dest.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "edit_plan_already_exists_or_publication_failed"
    );
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub(super) fn load(path: &Path, expected: &str) -> Result<Profile> {
    let p = read_plan(path, expected)?;
    verify(&p)?;
    Ok(p)
}
/// Exact bounded descriptor read without accepting stale target bindings for execution.
/// Only refresh may observe new targets after independently checking the anchors.
pub(super) fn read_plan(path: &Path, expected: &str) -> Result<Profile> {
    private_dir(path)?;
    ensure!(
        crate::native::is_digest(expected),
        "edit_plan_digest_invalid"
    );
    let raw = bytes(&path.join("profile.json"), MAX_PLAN)?;
    ensure!(
        replace_file::content_sha256(&raw) == expected,
        "edit_plan_changed"
    );
    ensure!(
        bytes(&path.join("profile.sha256"), 64)? == expected.as_bytes(),
        "edit_plan_receipt_changed"
    );
    let crate::mcp::admission::Strict(value) =
        serde_json::from_slice(&raw).map_err(|_| anyhow::anyhow!("edit_plan_invalid"))?;
    let p: Profile =
        serde_json::from_value(value).map_err(|_| anyhow::anyhow!("edit_plan_invalid"))?;
    ensure!(profile::canonical(&p)? == raw, "edit_plan_not_canonical");
    p.validate()?;
    Ok(p)
}
pub(super) fn command(action: Action) -> Result<()> {
    match action {
        Action::ExportSet(args) => super::review::export_set::command(args)?,
        Action::Apply { action } => super::application::command(action)?,
        Action::Batch { action } => super::batch::command(action)?,
        Action::Archive { home, action } => archive(&home, action)?,
        Action::Inventory(args) => super::inventory::command(args)?,
        Action::WithRun(args) => super::inventory::with_run(args)?,
        Action::Review(args) => super::review::command(args)?,
        Action::Status(args) => super::status(args)?,
        Action::Preview(args) => {
            let p = selected(args)?;
            println!(
                "{}",
                json!({"format":FORMAT,"executed":false,"authority":false,"profile_sha256":profile::digest(&p)?,"profile":p})
            );
        }
        Action::Prepare {
            selected: args,
            apply,
            out,
        } => {
            let p = selected(args)?;
            if apply {
                publish(&out, &p)?;
            }
            println!(
                "{}",
                json!({"format":FORMAT,"executed":apply,"authority":false,"status":if apply {"prepared-not-active"} else {"preview"},"plan":out,"profile_sha256":profile::digest(&p)?,"profile":p})
            );
        }
        Action::Run {
            plan,
            sha256,
            state,
            prompt_file,
            timeout_seconds,
            model,
        } => super::runtime::run(plan, sha256, state, prompt_file, timeout_seconds, model)?,
        Action::Stop { run, output } => super::control::stop(&run, output)?,
        Action::Refresh {
            plan,
            sha256,
            out,
            apply,
            confirm,
        } => {
            let result = super::refresh::command(&plan, &sha256, &out, apply, confirm.as_deref())?;
            println!("{result}");
        }
        Action::Ask { run, action } => {
            private_dir(&run)?;
            let record: super::runtime::RunRecord =
                serde_json::from_slice(&bytes(&run.join("run.json"), MAX_PLAN)?)
                    .map_err(|_| anyhow::anyhow!("edit_run_invalid"))?;
            ensure!(
                record.format == FORMAT && record.run == run,
                "edit_run_identity"
            );
            let home = record.home.clone();
            ensure!(
                home.parent() == Some(run.as_path())
                    && home
                        .file_name()
                        .and_then(|s| s.to_str())
                        .is_some_and(|name| name.len() == 43
                            && name
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))),
                "edit_run_home_identity"
            );
            private_dir(&home)?;
            if run.join("terminal.json").exists() {
                ensure!(matches!(action, Ask::List), "edit_run_ended");
                println!("[]");
                return Ok(());
            }
            // Private files are not live authority. A killed/restarted daemon
            // must never let an operator issue a grant into a retired epoch.
            let cfg = crate::Config::from_yaml(std::str::from_utf8(&bytes(
                &home.join("config.yaml"),
                MAX_PLAN,
            )?)?)?;
            let native_token = String::from_utf8(bytes(&home.join("native-token"), 4096)?)?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let observed = runtime
                .block_on(async {
                    let client = reqwest::Client::builder()
                        .no_proxy()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(std::time::Duration::from_secs(3))
                        .build()?;
                    let mut response = client
                        .get(cfg.endpoint_url("/native/v1/instance"))
                        .bearer_auth(native_token.trim())
                        .send()
                        .await?
                        .error_for_status()?;
                    let mut raw = Vec::new();
                    while let Some(chunk) = response.chunk().await? {
                        ensure!(
                            raw.len().saturating_add(chunk.len()) <= MAX_PLAN as usize,
                            "edit_instance_response_cap"
                        );
                        raw.extend_from_slice(&chunk);
                    }
                    let crate::mcp::admission::Strict(value) = serde_json::from_slice(&raw)?;
                    Ok::<_, anyhow::Error>(value)
                })
                .map_err(|_| anyhow::anyhow!("edit_run_not_live"))?;
            ensure!(
                observed["instance_id"].as_str() == Some(record.instance_id.as_str()),
                "edit_run_epoch_changed"
            );
            let value = match action {
                Ask::List => json!(crate::native::approval::operator_list(&home)),
                Ask::Inspect { id } => {
                    let mut v = crate::native::approval::operator_inspect(&home, &id)?;
                    v.as_object_mut()
                        .context("edit_pending_invalid")?
                        .remove("args");
                    v["arguments_redacted"] = json!(true);
                    v
                }
                Ask::Approve { id, binding } => {
                    let token = String::from_utf8(bytes(&home.join("token"), 4096)?)?;
                    crate::native::approval::operator_approve(&home, token.trim(), &id, &binding)?;
                    json!({"state":"approved","id":id})
                }
                Ask::Reject { id } => {
                    crate::native::approval::operator_reject(&home, &id)?;
                    json!({"state":"rejected","id":id})
                }
            };
            println!("{value}");
        }
        Action::Relay {
            home,
            host_session,
            child_authority,
            profile_sha256,
        } => {
            let cfg = crate::Config::from_yaml(std::str::from_utf8(&bytes(
                &home.join("config.yaml"),
                MAX_PLAN,
            )?)?)?;
            let token = String::from_utf8(bytes(&home.join("native-token"), 4096)?)?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(crate::native::execution::transport::run_edit_client(
                cfg.endpoint_url(super::ENDPOINT),
                token,
                crate::native::execution::transport::Preamble {
                    contract: FORMAT.into(),
                    catalogue_sha256: profile_sha256,
                    server_id: super::SERVER.into(),
                    host_session,
                    child_authority,
                },
            ))?;
        }
    }
    Ok(())
}

fn archive(home: &Path, action: super::Archive) -> Result<()> {
    ensure!(
        cfg!(target_arch = "x86_64"),
        "installed_edit_requires_native_linux_x86_64"
    );
    use std::ffi::OsString;
    use std::os::unix::process::CommandExt;
    let component = crate::pilot_component::Store::new(home)
        .current()
        .map_err(|_| anyhow::anyhow!("edit_archive_verified_component_required"))?;
    const HELPER: &str = "scripts/edit-run-archive.py";
    ensure!(
        component
            .manifest
            .files
            .iter()
            .any(|entry| entry.path == HELPER),
        "edit_archive_component_upgrade_required"
    );
    let mut words: Vec<OsString> = Vec::new();
    let mut bound = None;
    match action {
        super::Archive::Preview { run, destination } => {
            words.extend([
                "preview".into(),
                "--run".into(),
                run.into_os_string(),
                "--destination".into(),
                destination.into_os_string(),
            ]);
        }
        super::Archive::Apply(selected) => {
            words.push("archive".into());
            bound = Some(selected);
        }
        super::Archive::Cleanup {
            selected,
            acknowledge_evidence_loss,
        } => {
            words.push("cleanup".into());
            if acknowledge_evidence_loss {
                words.push("--acknowledge-evidence-loss".into());
            }
            bound = Some(selected);
        }
        super::Archive::Recover { selected, journal } => {
            words.extend(["recover".into(), "--journal".into(), journal.into()]);
            bound = Some(selected);
        }
    }
    if let Some(selected) = bound {
        words.extend([
            "--plan".into(),
            selected.plan.into_os_string(),
            "--confirm".into(),
            selected.confirm.into(),
        ]);
    }
    let _ = std::process::Command::new(&component.python.path)
        .args(["-I", "-B"])
        .arg(component.tree.join(HELPER))
        .args(words)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .exec();
    anyhow::bail!("edit_archive_verified_helper_start_failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn protected_runtime_leaf_cannot_borrow_authority_from_a_writable_parent() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path().canonicalize().unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let shared = dir.join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).unwrap();
        let path = shared.join("runtime");
        write(&path, b"owned runtime", 0o500).unwrap();
        file(&path, 128).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(file(&path, 128).is_err());
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(bytes(&path, 128).unwrap(), b"owned runtime");
    }
}
