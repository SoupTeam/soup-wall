// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::lifecycle::Manager;
use crate::self_test::windows_safety as safety;
use std::collections::BTreeMap;
use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;

const JOURNAL_LIMIT: usize = 256 * 1024;
const OWNER_MARKER: &str = "onboarding-owner";

#[derive(clap::Args)]
pub struct StateArgs {
    #[arg(long)]
    pub state_directory: PathBuf,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Configured,
    Installed,
    DaemonStarted,
    Publishing,
    Connected,
    Verified,
    Removing,
    Removed,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema_version: String,
    selection: Selection,
    confirmation: String,
    nonce: String,
    phase: Phase,
    files: BTreeMap<String, String>,
    expected_host_sha256: String,
    setup_ms: u128,
    verification_attempts: u8,
    verification_ms: Option<u128>,
    self_test_sha256: Option<String>,
}

fn path(directory: &Path) -> PathBuf {
    directory.join("onboarding.json")
}

fn save(state: &State) -> Result<()> {
    let file = path(&state.selection.state_directory);
    connection::recover(&file, true)?;
    let before = if file.try_exists()? {
        Some(connection::read_file(&file, JOURNAL_LIMIT)?)
    } else {
        None
    };
    let bytes = serde_json::to_vec(state)?;
    if before
        .as_ref()
        .is_some_and(|(observed, _)| *observed == bytes)
    {
        return Ok(());
    }
    ensure!(
        bytes.len() <= JOURNAL_LIMIT,
        "onboarding journal exceeds its fixed size limit"
    );
    connection::publish(
        &file,
        before.as_ref().map(|(bytes, id)| (bytes.as_slice(), *id)),
        &bytes,
    )
}

fn load(directory: &Path) -> Result<State> {
    let bytes = connection::read_file(&path(directory), JOURNAL_LIMIT)?.0;
    let state: State = serde_json::from_slice(&bytes).context("invalid onboarding journal")?;
    ensure!(
        state.schema_version == "sw-windows-onboarding/1"
            && state.selection.state_directory == directory
            && state
                .selection
                .home
                .file_name()
                .is_some_and(|name| name == ".agentfw")
            && crate::native::is_digest(&state.confirmation)
            && state.nonce.len() == 43
            && state
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
            && state.verification_attempts <= 3,
        "onboarding journal identity mismatch"
    );
    let required = [
        OWNER_MARKER,
        "config.yaml",
        "registry.json",
        "policy.yaml",
        "runtime.json",
        "token",
        "native-token",
    ];
    ensure!(
        state.files.len() == required.len()
            && required.iter().all(|name| state.files.contains_key(*name)),
        "unexpected onboarding file ownership record"
    );
    ensure!(
        state.files[OWNER_MARKER] == state.nonce,
        "onboarding ownership marker mismatch"
    );
    Ok(state)
}

fn lock(directory: &Path) -> Result<File> {
    safety::standard_user()?;
    let lock = connection::lock(&path(directory))?;
    connection::recover(&path(directory), true)?;
    Ok(lock)
}

fn owned_home(state: &State) -> Result<()> {
    connection::verify_full_directory(&safety::check_private(&state.selection.home, true)?)?;
    let observed = connection::read_file(&state.selection.home.join(OWNER_MARKER), 128)?.0;
    ensure!(
        observed == state.nonce.as_bytes(),
        "Agent home ownership changed; preserve it"
    );
    let versions = state.selection.home.join("versions");
    if versions.try_exists()? {
        let _pin = connection::parent(&versions.join("lifecycle.json"))?;
        connection::verify_full_directory(&safety::check_private(&versions, true)?)?;
    }
    Ok(())
}

fn check_files(state: &State) -> Result<()> {
    owned_home(state)?;
    for (name, expected) in &state.files {
        let observed = connection::read_file(&state.selection.home.join(name), FILE_LIMIT)?.0;
        ensure!(
            observed == expected.as_bytes(),
            "an owned configuration file changed; preserve it"
        );
    }
    Ok(())
}

fn options(state: &State, agent: PathBuf) -> Options {
    Options {
        path: state.selection.host_config.clone(),
        server: state.selection.server.clone(),
        home: state.selection.home.clone(),
        agent,
        probe_tool: None,
        probe_args: None,
        runtime: Some(state.selection.home.join("runtime.json")),
        server_profile: None,
        classifier_script: None,
        classifier_python: None,
    }
}

fn manager(state: &State) -> Manager {
    Manager::new(&state.selection.home)
}

async fn control(state: &State, operation: &'static str) -> Result<crate::lifecycle::Status> {
    let _process = endpoint_owner(state)?;
    let home = state.selection.home.clone();
    let version = format!("onboard-{}", &state.nonce[..16]);
    let candidate = state.selection.agent.clone();
    let digest = state.selection.agent_sha256.clone();
    tokio::task::spawn_blocking(move || {
        let manager = Manager::new(home);
        match operation {
            "recover" => manager.recover()?,
            "install" => {
                manager.install(&version, &candidate, &digest)?;
            }
            "start" => manager.start()?,
            "remove" => manager.remove()?,
            "status" => (),
            _ => anyhow::bail!("unsupported lifecycle operation"),
        }
        manager.status()
    })
    .await?
}

fn lifecycle_state(state: &State) -> Result<crate::lifecycle::State> {
    let bytes = connection::read_file(
        &state.selection.home.join("versions").join("lifecycle.json"),
        FILE_LIMIT,
    )?
    .0;
    serde_json::from_slice(&bytes).context("invalid owned lifecycle state")
}

fn pin_process(pid: u32, expected: &Path) -> Result<Option<OwnedHandle>> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            return Ok(None);
        }
        return Err(error.into());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_OBJECT_0 => return Ok(None),
        WAIT_TIMEOUT => (),
        _ => anyhow::bail!("cannot verify the managed process state"),
    }
    let mut image = vec![0u16; 32768];
    let mut length = image.len() as u32;
    ensure!(
        unsafe {
            QueryFullProcessImageNameW(process.as_raw_handle(), 0, image.as_mut_ptr(), &mut length)
        } != 0
            && length > 0
            && length as usize <= image.len(),
        "cannot identify the managed process image"
    );
    let observed = PathBuf::from(std::ffi::OsString::from_wide(&image[..length as usize]));
    ensure!(
        observed.canonicalize()? == expected.canonicalize()?,
        "managed PID belongs to another executable; refusing endpoint access"
    );
    Ok(Some(process))
}

fn endpoint_owner(state: &State) -> Result<Option<OwnedHandle>> {
    let record = state.selection.home.join("versions").join("lifecycle.json");
    if record.try_exists()? {
        if let Some(process) = lifecycle_state(state)?.process {
            ensure!(
                process.pid != 0,
                "managed process identity is incomplete; retain recovery evidence"
            );
            if let Some(pin) = pin_process(process.pid, &installed(state)?)? {
                ensure!(
                    process.binary_digest == state.selection.agent_sha256
                        && process.config_digest == sha(state.files["config.yaml"].as_bytes())
                        && process.port == state.selection.port
                        && process.bind == "127.0.0.1",
                    "managed process record does not match the owned setup"
                );
                return Ok(Some(pin));
            }
        }
    }
    let listener = TcpListener::bind(("127.0.0.1", state.selection.port))
        .context("foreign port occupancy preserved without sending credentials")?;
    drop(listener);
    Ok(None)
}

fn installed(state: &State) -> Result<PathBuf> {
    let manager = manager(state);
    let status = lifecycle_state(state)?;
    let selected = status
        .active
        .context("owned Agent installation is missing")?;
    ensure!(
        selected.digest == state.selection.agent_sha256
            && selected.version == format!("onboard-{}", &state.nonce[..16]),
        "installed Agent identity changed"
    );
    let path = manager.path_for(&selected)?;
    asset(&path, &state.selection.agent_sha256, true)?;
    Ok(path)
}

fn config(state: &State) -> Result<crate::Config> {
    crate::Config::from_yaml(&state.files["config.yaml"])
}

async fn daemon(state: &State) -> Result<Value> {
    check_files(state)?;
    let _process = endpoint_owner(state)?.context("owned daemon is not running")?;
    let agent = installed(state)?;
    let cfg = config(state)?;
    let policy = soup_wall_agent::AgentPolicySet::from_yaml(&state.files["policy.yaml"])?;
    let expectations = crate::protection_status::Expectations {
        config_sha256: Some(crate::protection_status::config_digest(&cfg)),
        binary_sha256: Some(state.selection.agent_sha256.clone()),
        registry_sha256: Some(state.selection.registry_sha256.clone()),
        policy_sha256: Some(sha(&serde_json::to_vec(&policy)?)),
        ..Default::default()
    };
    let snapshot = crate::protection_status::query(
        &cfg,
        &state.files["token"],
        &expectations,
        Duration::from_secs(2),
    )
    .await
    .map_err(|reason| anyhow::anyhow!(reason))?;
    ensure!(
        snapshot.mode == crate::protection_status::Mode::Enforcing,
        "owned daemon is not enforcing"
    );
    let status = lifecycle_state(state)?;
    let process = status
        .process
        .context("managed daemon ownership record is absent")?;
    ensure!(
        snapshot
            .runtime
            .lifecycle
            .as_ref()
            .is_some_and(|identity| identity.pid == process.pid
                && identity.instance == process.instance
                && identity.binary_digest == process.binary_digest
                && identity.config_digest == process.config_digest),
        "running daemon does not match managed process ownership"
    );
    asset(&agent, &state.selection.agent_sha256, true)?;
    Ok(json!({"binary_sha256": snapshot.runtime.binary_sha256,
        "config_sha256": snapshot.runtime.loaded_config_sha256,
        "policy_sha256": snapshot.policy.sha256, "registry_sha256": snapshot.registry.sha256}))
}

fn summary(state: &State, configured: bool, verified: bool) -> Value {
    json!({"schema_version": "sw-windows-onboarding/1", "phase": state.phase,
        "configured": configured, "daemon_verified": verified,
        "synthetic_protection": if state.phase == Phase::Verified {"witnessed"} else {"not_witnessed"},
        "host_reload": "pending_explicit_host_reload", "setup_ms": state.setup_ms,
        "verification_ms": state.verification_ms, "self_test_sha256": state.self_test_sha256,
        "identities": {"agent_sha256": state.selection.agent_sha256,
            "python_sha256": state.selection.python_sha256, "classifier_sha256": state.selection.classifier_sha256,
            "registry_sha256": state.selection.registry_sha256, "policy_source_sha256": state.selection.policy_sha256},
        "self_test_scope": "bundled_fixture_and_shipped_policy",
        "unsupported_scopes": ["live_model_effectiveness", "arbitrary_server_sandbox", "other_operating_systems"]})
}

pub(super) async fn apply(
    selection: Selection,
    confirmation: &str,
    pause_after: Option<&str>,
) -> Result<Value> {
    safety::standard_user()?;
    let preview = super::preview(&selection).await?;
    ensure!(
        preview.confirmation == confirmation,
        "stale or incorrect preview confirmation"
    );
    let _lock = lock(&selection.state_directory)?;
    let repeated = super::preview(&selection).await?;
    ensure!(
        repeated.confirmation == confirmation,
        "selected state changed before apply"
    );
    let cfg = crate::Config {
        port: selection.port,
        enforce: true,
        policy: Some(selection.home.join("policy.yaml")),
        native: Some(crate::config::NativeCfg {
            execution: None,
            registry_path: selection.home.join("registry.json"),
            registry_sha256: selection.registry_sha256.clone(),
            approval: None,
            liveness: None,
        }),
        ..Default::default()
    };
    let nonce = crate::token::generate();
    let mut files = BTreeMap::new();
    files.insert(OWNER_MARKER.into(), nonce.clone());
    files.insert("config.yaml".into(), serde_yaml::to_string(&cfg)?);
    files.insert(
        "registry.json".into(),
        String::from_utf8(asset(&selection.registry, &selection.registry_sha256, false)?.0)?,
    );
    files.insert(
        "policy.yaml".into(),
        String::from_utf8(asset(&selection.policy, &selection.policy_sha256, false)?.0)?,
    );
    files.insert(
        "runtime.json".into(),
        serde_json::to_string(&json!({"workspace": selection.workspace,
        "classifier_script": selection.classifier, "classifier_python": selection.python}))?,
    );
    files.insert("token".into(), crate::token::generate());
    files.insert("native-token".into(), crate::token::generate());
    let mut state = State {
        schema_version: "sw-windows-onboarding/1".into(),
        selection,
        confirmation: confirmation.into(),
        nonce,
        phase: Phase::Prepared,
        files,
        expected_host_sha256: repeated.identities["host_config_sha256"]
            .as_str()
            .context("missing host identity")?
            .into(),
        setup_ms: 0,
        verification_attempts: 0,
        verification_ms: None,
        self_test_sha256: None,
    };
    save(&state)?;
    checkpoint(pause_after, "prepared");
    resume(&mut state, pause_after).await
}

fn checkpoint(selected: Option<&str>, current: &str) {
    if selected == Some(current) {
        std::thread::sleep(Duration::from_secs(30));
    }
}

async fn resume(state: &mut State, pause_after: Option<&str>) -> Result<Value> {
    ensure!(
        !matches!(state.phase, Phase::Removing | Phase::Removed),
        "setup is being removed"
    );
    let started = Instant::now();
    if !state.selection.home.try_exists()? {
        ensure!(
            state.phase == Phase::Prepared,
            "owned Agent home disappeared"
        );
        safety::new_directory(&state.selection.home)?;
        connection::publish(
            &state.selection.home.join(OWNER_MARKER),
            None,
            state.nonce.as_bytes(),
        )?;
    }
    owned_home(state)?;
    for (name, expected) in &state.files {
        let target = state.selection.home.join(name);
        if target.try_exists()? {
            ensure!(
                connection::read_file(&target, FILE_LIMIT)?.0 == expected.as_bytes(),
                "owned file changed; preserve it"
            );
        } else {
            ensure!(
                matches!(state.phase, Phase::Prepared),
                "an owned file disappeared after setup"
            );
            connection::publish(&target, None, expected.as_bytes())?;
        }
    }
    if state.phase == Phase::Prepared {
        state.phase = Phase::Configured;
        save(state)?;
        checkpoint(pause_after, "configured");
    }
    check_files(state)?;
    asset(
        &state.selection.python,
        &state.selection.python_sha256,
        true,
    )?;
    asset(
        &state.selection.classifier,
        &state.selection.classifier_sha256,
        false,
    )?;
    let status = control(state, "recover").await?;
    if status.active.is_none() {
        ensure!(
            state.phase == Phase::Configured,
            "owned Agent installation disappeared"
        );
        asset(&state.selection.agent, &state.selection.agent_sha256, true)?;
        control(state, "install").await?;
    }
    let agent = installed(state)?;
    if state.phase == Phase::Configured {
        state.phase = Phase::Installed;
        save(state)?;
        checkpoint(pause_after, "installed");
    }
    if !control(state, "status").await?.running {
        let listener = TcpListener::bind(("127.0.0.1", state.selection.port))
            .context("foreign port occupancy preserved")?;
        drop(listener);
        control(state, "start").await?;
    }
    daemon(state).await?;
    if state.phase == Phase::Installed {
        state.phase = Phase::DaemonStarted;
        save(state)?;
        checkpoint(pause_after, "daemon_started");
    }
    if state.phase == Phase::DaemonStarted {
        ensure!(
            sha(&connection::read_file(&state.selection.host_config, FILE_LIMIT)?.0)
                == state.expected_host_sha256,
            "host configuration changed since preview; preserve it"
        );
        state.phase = Phase::Publishing;
        save(state)?;
        checkpoint(pause_after, "publishing");
    }
    let runtime_digest = sha(&serde_json::to_vec(&json!({
        "runtime": sha(state.files["runtime.json"].as_bytes()),
        "script": state.selection.classifier_sha256, "python": state.selection.python_sha256,
    }))?);
    let native_digest = sha(&serde_json::to_vec(&json!({
        "config": sha(state.files["config.yaml"].as_bytes()), "runtime": runtime_digest,
    }))?);
    connection::run_confirmed(
        "connect",
        &options(state, agent),
        Some(&state.expected_host_sha256),
        Some(&runtime_digest),
        Some(&native_digest),
    )
    .await?;
    check_files(state)?;
    asset(
        &state.selection.python,
        &state.selection.python_sha256,
        true,
    )?;
    asset(
        &state.selection.classifier,
        &state.selection.classifier_sha256,
        false,
    )?;
    if state.phase == Phase::Publishing {
        state.phase = Phase::Connected;
    }
    state.setup_ms += started.elapsed().as_millis();
    save(state)?;
    checkpoint(pause_after, "connected");
    Ok(summary(state, true, true))
}

pub(super) async fn inspect(directory: &Path) -> Result<Value> {
    safety::standard_user()?;
    let state = load(directory)?;
    if matches!(state.phase, Phase::Removed | Phase::Prepared) {
        return Ok(summary(&state, false, false));
    }
    check_files(&state)?;
    let verified = daemon(&state).await.is_ok();
    let configured = if let Ok(agent) = installed(&state) {
        connection::run("inspect", &options(&state, agent))
            .await
            .is_ok_and(|report| report.status == "configured")
    } else {
        false
    };
    Ok(summary(&state, configured, verified))
}

pub(super) async fn recover(directory: &Path) -> Result<Value> {
    let started = Instant::now();
    let mut report = recover_inner(directory).await?;
    report["recovery_ms"] = json!(started.elapsed().as_millis());
    Ok(report)
}

async fn recover_inner(directory: &Path) -> Result<Value> {
    let _lock = lock(directory)?;
    let mut state = load(directory)?;
    if state.phase == Phase::Removed {
        return Ok(summary(&state, false, false));
    }
    if state.phase == Phase::Removing {
        return remove_locked(&mut state).await;
    }
    if matches!(state.phase, Phase::Connected | Phase::Verified)
        && daemon(&state).await.is_ok()
        && connection::run("inspect", &options(&state, installed(&state)?))
            .await
            .is_ok_and(|report| report.status == "configured")
    {
        return Ok(summary(&state, true, true));
    }
    resume(&mut state, None).await
}

pub(super) async fn verify(directory: &Path) -> Result<Value> {
    let _lock = lock(directory)?;
    let mut state = load(directory)?;
    ensure!(
        matches!(state.phase, Phase::Connected | Phase::Verified),
        "complete apply or recover before verification"
    );
    let started = Instant::now();
    let running = daemon(&state).await?;
    let agent = installed(&state)?;
    ensure!(
        connection::run("inspect", &options(&state, agent.clone()))
            .await?
            .status
            == "configured",
        "owned host connection is not configured"
    );
    asset(
        &state.selection.python,
        &state.selection.python_sha256,
        true,
    )?;
    asset(
        &state.selection.classifier,
        &state.selection.classifier_sha256,
        false,
    )?;
    ensure!(
        state.verification_attempts < 3,
        "verification retry limit reached; retain reports and recover or remove"
    );
    let report_path = if state.verification_attempts == 0 {
        state.selection.report.clone()
    } else {
        state
            .selection
            .report
            .with_extension(format!("retry-{}.json", state.verification_attempts))
    };
    fresh(&report_path)?;
    state.verification_attempts += 1;
    state.phase = Phase::Connected;
    state.self_test_sha256 = None;
    save(&state)?;
    safety::install_control_handler()?;
    let mut command = ProcessCommand::new(&agent);
    command
        .args(["self-test", "--agent"])
        .arg(&agent)
        .args(["--classifier", "rule-baseline", "--classifier-script"])
        .arg(&state.selection.classifier)
        .arg("--classifier-sha256")
        .arg(&state.selection.classifier_sha256)
        .arg("--classifier-python")
        .arg(&state.selection.python)
        .arg("--report")
        .arg(&report_path)
        .arg("--work-parent")
        .arg(directory)
        .args(["--timeout-seconds", "120"])
        .env_clear()
        .env(
            "SystemRoot",
            std::env::var_os("SystemRoot").context("SystemRoot unavailable")?,
        )
        .env(
            "USERPROFILE",
            state
                .selection
                .home
                .parent()
                .context("home parent missing")?,
        )
        .env("TEMP", directory)
        .env("TMP", directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = safety::Owned::spawn(command)?;
    let exited = child.wait_exit(Duration::from_secs(130));
    let stopped = child.stop();
    ensure!(
        exited && stopped.reaped && stopped.group_empty && stopped.exit == Some(0),
        "installed self-test did not finish successfully; retain its report"
    );
    let bytes = connection::read_file(&report_path, FILE_LIMIT)?.0;
    let report: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        report["result"] == "passed"
            && report["exit_code"] == 0
            && report["identities"]["agent"]["sha256"] == state.selection.agent_sha256
            && report["identities"]["classifier"]["source_sha256"]
                == state.selection.classifier_sha256
            && report["cleanup"]["workspace"] == "removed"
            && report["cleanup"]["final_effects"]["exact_execution_ledger"] == true
            && report["cleanup"]["final_effects"]["no_unexpected_effects"] == true
            && report["scenarios"]
                .as_array()
                .is_some_and(|scenarios| scenarios.len() == 5
                    && scenarios
                        .iter()
                        .all(|scenario| scenario["status"] == "passed")),
        "independent self-test evidence is incomplete"
    );
    ensure!(
        daemon(&state).await? == running,
        "managed daemon identities changed during verification"
    );
    asset(
        &state.selection.python,
        &state.selection.python_sha256,
        true,
    )?;
    asset(
        &state.selection.classifier,
        &state.selection.classifier_sha256,
        false,
    )?;
    ensure!(
        connection::run("inspect", &options(&state, agent))
            .await?
            .status
            == "configured",
        "host connection changed during verification"
    );
    state.phase = Phase::Verified;
    state.self_test_sha256 = Some(sha(&bytes));
    state.verification_ms = Some(started.elapsed().as_millis());
    save(&state)?;
    Ok(summary(&state, true, true))
}

pub(super) async fn remove(directory: &Path) -> Result<Value> {
    let started = Instant::now();
    let _lock = lock(directory)?;
    let mut report = remove_locked(&mut load(directory)?).await?;
    report["removal_ms"] = json!(started.elapsed().as_millis());
    Ok(report)
}

async fn remove_locked(state: &mut State) -> Result<Value> {
    if state.phase == Phase::Removed {
        return Ok(summary(state, false, false));
    }
    if state.phase == Phase::Prepared && !state.selection.home.try_exists()? {
        state.phase = Phase::Removed;
        save(state)?;
        return Ok(summary(state, false, false));
    }
    owned_home(state)?;
    for (name, expected) in &state.files {
        let target = state.selection.home.join(name);
        if target.try_exists()? {
            ensure!(
                connection::read_file(&target, FILE_LIMIT)?.0 == expected.as_bytes(),
                "operator edit preserved; removal stopped"
            );
        }
    }
    let prior = state.phase;
    state.phase = Phase::Removing;
    save(state)?;
    if matches!(
        prior,
        Phase::Publishing | Phase::Connected | Phase::Verified | Phase::Removing
    ) {
        let agent = installed(state).unwrap_or_else(|_| state.selection.agent.clone());
        connection::run("disconnect", &options(state, agent)).await?;
    }
    control(state, "recover").await?;
    control(state, "remove").await?;
    for (name, expected) in &state.files {
        if name == OWNER_MARKER {
            continue;
        }
        let target = state.selection.home.join(name);
        if target.try_exists()? {
            ensure!(
                connection::read_file(&target, FILE_LIMIT)?.0 == expected.as_bytes(),
                "concurrent operator edit preserved"
            );
            connection::remove_confirmed(&target, expected.as_bytes())?;
        }
    }
    state.phase = Phase::Removed;
    state.self_test_sha256 = None;
    save(state)?;
    Ok(summary(state, false, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_pin_rejects_a_live_foreign_image_and_handles_an_exited_process() {
        let current = std::env::current_exe().unwrap();
        let process = pin_process(std::process::id(), &current).unwrap().unwrap();
        assert!(pin_process(std::process::id(), &std::env::temp_dir()).is_err());
        drop(process);
        let system = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
        let mut child = ProcessCommand::new(system.join("System32").join("cmd.exe"))
            .args(["/D", "/C", "exit", "0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.wait().unwrap();
        assert!(pin_process(child.id(), &current).unwrap().is_none());
    }
}
