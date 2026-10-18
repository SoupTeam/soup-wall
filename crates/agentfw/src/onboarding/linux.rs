// SPDX-License-Identifier: Apache-2.0
//! Linux local-user onboarding. Every mutation goes through an accepted Agent
//! command (`install`, `lifecycle`, `mcp-connection`) or writes a file this
//! operation creates with `create_new`; every step is journaled first.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command as Process, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    base_report, ApplyArgs, Command, Inputs, UndoArgs, EXIT_CONFIGURED, EXIT_FAILED,
    EXIT_INCOMPLETE, EXIT_OK,
};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    let handler = on_signal as extern "C" fn(libc::c_int) as usize;
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
        unsafe {
            libc::signal(signal, handler as libc::sighandler_t);
        }
    }
}

fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

const STATE_DIR: &str = ".soup-wall-onboarding";
const JOURNAL: &str = "journal.json";
const LOCK: &str = "lock";
const OWNED_DIR: &str = "onboarding";
const MAX_REGISTRY: u64 = 256 * 1024;
const MAX_POLICY: u64 = 1024 * 1024;
const MAX_HOST_CONFIG: u64 = 1024 * 1024;
const STEP_TIMEOUT: Duration = Duration::from_secs(150);
/// Runtime entries the Agent itself creates in a home that onboarding created.
const RUNTIME_ENTRIES: [&str; 8] = [
    "token",
    "native-token",
    "audit.jsonl",
    "grants",
    "manifests",
    "versions",
    "native-pending",
    OWNED_DIR,
];
pub(crate) const STEPS: [&str; 9] = [
    "create_agent_home",
    "write_owned_files",
    "create_token",
    "lifecycle_install",
    "lifecycle_start",
    "verify_identity",
    "connect_server",
    "verify_server",
    "self_test",
];

// ------------------------------------------------------------------ utilities

pub(crate) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_limited(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("file exceeds its size limit"));
    }
    Ok(bytes)
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// Absolute, no `..`/`.` aliases, and no symlink in any existing component.
pub(crate) fn plain_path(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute() {
        return Err("must be an absolute path");
    }
    if path
        .components()
        .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err("must not contain `.` or `..` components");
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err("must not contain symbolic links")
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    Ok(())
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Reports carry a stable digest of a path string, never the path itself.
fn path_digest(path: &Path) -> String {
    sha256(path.as_os_str().as_encoded_bytes())[..16].to_string()
}

fn canonical(value: &Value) -> String {
    crate::self_test::fixture::canonical(value)
}

fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Atomic private replacement for this operation's own journal only.
fn write_journal_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension("tmp");
    let _ = std::fs::remove_file(&temporary);
    write_new_private(&temporary, bytes)?;
    std::fs::rename(&temporary, path)?;
    File::open(path.parent().unwrap_or(Path::new("/")))?.sync_all()
}

// ------------------------------------------------------------------ subprocesses

pub(crate) struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub timed_out: bool,
}

impl Output {
    fn ok(&self) -> bool {
        self.code == Some(0)
    }
    fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.stdout).ok()
    }
}

/// Run one accepted Agent command in its own process group with a cleared environment.
pub(crate) fn run_agent(
    agent: &Path,
    args: &[OsString],
    profile: Option<&Path>,
    limit: Duration,
) -> Output {
    let mut command = Process::new(agent);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    if let Some(profile) = profile {
        command.env("HOME", profile).env("USERPROFILE", profile);
    }
    let Ok(mut child) = command.spawn() else {
        return Output {
            code: None,
            stdout: Vec::new(),
            timed_out: false,
        };
    };
    let mut stdout = child.stdout.take().expect("piped stdout");
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = (&mut stdout).take(4 * 1024 * 1024).read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + limit;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                // SAFETY: the child is unreaped, so its process-group ID is still ours.
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                timed_out = true;
                break child.wait().ok();
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => break None,
        }
    };
    Output {
        code: status.and_then(|s| s.code()),
        stdout: reader.join().unwrap_or_default(),
        timed_out,
    }
}

fn os(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn with_paths(mut base: Vec<OsString>, pairs: &[(&str, &Path)]) -> Vec<OsString> {
    for (flag, path) in pairs {
        base.push(OsString::from(flag));
        base.push(path.as_os_str().to_owned());
    }
    base
}

// ------------------------------------------------------------------ checks

#[derive(Clone, Serialize)]
pub(crate) struct Check {
    pub id: &'static str,
    pub status: &'static str,
    pub detail: String,
    pub action: Option<String>,
}

fn ok(id: &'static str, detail: impl Into<String>) -> Check {
    Check {
        id,
        status: "ok",
        detail: detail.into(),
        action: None,
    }
}

fn refused(id: &'static str, detail: impl Into<String>, action: impl Into<String>) -> Check {
    Check {
        id,
        status: "refused",
        detail: detail.into(),
        action: Some(action.into()),
    }
}

fn conflict(id: &'static str, detail: impl Into<String>, action: impl Into<String>) -> Check {
    Check {
        id,
        status: "conflict",
        detail: detail.into(),
        action: Some(action.into()),
    }
}

/// Facts established by checks and bound into the plan digest.
#[derive(Clone, Default)]
pub(crate) struct Facts {
    agent_sha256: String,
    registry_bytes: Vec<u8>,
    registry_id: String,
    policy_bytes: Vec<u8>,
    policy_source: &'static str,
    policy_rules: usize,
    expected_policy_digest: String,
    host_sha256: String,
    entry_sha256: String,
    other_servers: usize,
    other_settings: usize,
    python_version: String,
    resume: bool,
}

struct Paths {
    profile: PathBuf,
    state: PathBuf,
}

fn paths(inputs_home: &Path) -> Option<Paths> {
    let profile = inputs_home.parent()?.to_path_buf();
    Some(Paths {
        state: profile.join(STATE_DIR),
        profile,
    })
}

fn port_in_use(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(300),
    )
    .is_ok()
}

fn expected_policy_digest(text: &str) -> Option<(String, usize)> {
    let policy = soup_wall_agent::AgentPolicySet::from_yaml(text).ok()?;
    Some((
        sha256(&serde_json::to_vec(&policy).ok()?),
        policy.agent_policies.len(),
    ))
}

pub(crate) fn check_inputs(inputs: &Inputs) -> (Vec<Check>, Facts) {
    let mut checks = Vec::new();
    let mut facts = Facts::default();
    let journal = paths(&inputs.agent_home).and_then(|p| load_journal(&p.state).ok().flatten());
    facts.resume = journal
        .as_ref()
        .is_some_and(|j| j.agent_home == inputs.agent_home.to_string_lossy());
    checks.push(ok(
        "platform",
        "Linux local-user profile; service management not requested",
    ));

    // Agent executable.
    let agent = &inputs.agent;
    match plain_path(agent) {
        Err(reason) => checks.push(refused(
            "agent",
            format!("--agent {reason}"),
            "pass the real absolute path of the installed agentfw",
        )),
        Ok(()) => match std::fs::metadata(agent) {
            Ok(meta) if meta.is_file() && meta.mode() & 0o111 != 0 && meta.mode() & 0o002 == 0 => {
                match sha256_file(agent) {
                    Ok(digest) if digest == inputs.agent_sha256 => {
                        facts.agent_sha256 = digest;
                        let help =
                            run_agent(agent, &os(&["--help"]), None, Duration::from_secs(10));
                        let text = String::from_utf8_lossy(&help.stdout);
                        if help.ok()
                            && [
                                "lifecycle",
                                "mcp-connection",
                                "protection-status",
                                "self-test",
                            ]
                            .iter()
                            .all(|c| text.contains(c))
                        {
                            checks.push(ok("agent", "executable digest matches; lifecycle, mcp-connection, protection-status and self-test are available"));
                        } else {
                            checks.push(refused("agent", "the selected Agent lacks a required accepted command", "install an Agent build that includes lifecycle, mcp-connection, protection-status and self-test"));
                        }
                    }
                    Ok(_) => checks.push(refused(
                        "agent",
                        "executable digest differs from --agent-sha256",
                        "verify the installed binary and pass its reviewed SHA-256",
                    )),
                    Err(_) => checks.push(refused(
                        "agent",
                        "executable is unreadable",
                        "check the Agent installation",
                    )),
                }
            }
            _ => checks.push(refused(
                "agent",
                "not a regular executable, or writable by other users",
                "install the Agent as a private executable",
            )),
        },
    }

    // Classifier assets for the isolated self-test.
    let expected = inputs.classifier_sha256.trim();
    match read_limited(&inputs.classifier_script, 1024 * 1024) {
        Ok(bytes) if hex64(expected) && sha256(&bytes) == expected => checks.push(ok(
            "classifier",
            "rule_baseline.py digest matches the expected revision",
        )),
        Ok(_) => checks.push(refused(
            "classifier",
            "classifier source does not match --classifier-sha256 (wrong revision)",
            "install the reviewed rule_baseline.py revision or pass its reviewed digest",
        )),
        Err(_) => checks.push(refused(
            "classifier",
            "classifier source is missing or unreadable",
            "install rule_baseline.py locally and pass its absolute path",
        )),
    }
    let python = run_python_version(&inputs.classifier_python);
    match python {
        Some(version) => {
            facts.python_version = version;
            checks.push(ok("classifier_python", "Python 3 runs in isolated mode"));
        }
        None => checks.push(refused(
            "classifier_python",
            "--classifier-python did not run as Python 3",
            "pass an installed Python 3 interpreter",
        )),
    }

    // Reviewed registry (profile).
    match read_limited(&inputs.registry, MAX_REGISTRY) {
        Ok(bytes) if sha256(&bytes) == inputs.registry_sha256 => {
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(value)
                    if value["contract_version"] == "sw-native/1"
                        && value["tools"].as_array().is_some_and(|t| !t.is_empty()) =>
                {
                    let needs_profile = value["tools"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|t| t.get("resource_policy").is_some())
                        || inputs
                            .registry
                            .parent()
                            .is_some_and(|d| d.join("profile.json").exists());
                    if needs_profile {
                        checks.push(refused("registry", "this profile needs a server profile or resource executor that the accepted connection interface does not configure",
                        "use the profile's own documented launch, or a plain native-admission registry"));
                    } else {
                        facts.registry_id =
                            value["registry_id"].as_str().unwrap_or_default().to_owned();
                        facts.registry_bytes = bytes;
                        checks.push(ok(
                            "registry",
                            "reviewed sw-native/1 registry digest matches",
                        ));
                    }
                }
                _ => checks.push(refused(
                    "registry",
                    "registry is not a sw-native/1 registry with tools",
                    "select the reviewed registry for the server",
                )),
            }
        }
        Ok(_) => checks.push(refused(
            "registry",
            "registry digest differs from --registry-sha256",
            "review the registry and pass its digest",
        )),
        Err(_) => checks.push(refused(
            "registry",
            "registry is missing, unreadable or larger than 256 KiB",
            "pass the reviewed registry file",
        )),
    }

    // Policy: reviewed file or the shipped default.
    let policy = match (&inputs.policy, &inputs.policy_sha256) {
        (Some(path), Some(digest)) => match read_limited(path, MAX_POLICY) {
            Ok(bytes) if sha256(&bytes) == *digest => Some((bytes, "reviewed")),
            Ok(_) => {
                checks.push(refused(
                    "policy",
                    "policy digest differs from --policy-sha256",
                    "review the policy and pass its digest",
                ));
                None
            }
            Err(_) => {
                checks.push(refused(
                    "policy",
                    "policy is missing or unreadable",
                    "pass the reviewed policy file",
                ));
                None
            }
        },
        _ => Some((
            crate::self_test::fixture::SHIPPED_POLICY
                .as_bytes()
                .to_vec(),
            "shipped_default",
        )),
    };
    if let Some((bytes, source)) = policy {
        match std::str::from_utf8(&bytes)
            .ok()
            .and_then(expected_policy_digest)
        {
            Some((digest, rules)) => {
                facts.expected_policy_digest = digest;
                facts.policy_rules = rules;
                facts.policy_bytes = bytes;
                facts.policy_source = source;
                checks.push(ok(
                    "policy",
                    format!("{source} policy parses ({rules} rules)"),
                ));
            }
            None => checks.push(refused(
                "policy",
                "policy does not parse as an agent policy",
                "fix the policy before onboarding",
            )),
        }
    }

    // Workspace.
    match plain_path(&inputs.workspace).map(|_| std::fs::metadata(&inputs.workspace)) {
        Ok(Ok(meta)) if meta.is_dir() && meta.uid() == euid() && meta.mode() & 0o002 == 0 => {
            checks.push(ok("workspace", "reviewed workspace is an owned directory"))
        }
        _ => checks.push(refused(
            "workspace",
            "workspace must be an existing absolute directory owned by you and not world-writable",
            "create or select the reviewed workspace",
        )),
    }

    // Agent home: new, named .agentfw, under an owned private parent.
    let home = &inputs.agent_home;
    let home_ok = plain_path(home).is_ok() && home.file_name().is_some_and(|n| n == ".agentfw");
    match (home_ok, home.parent().map(std::fs::metadata)) {
        (true, Some(Ok(parent))) if parent.is_dir() && parent.uid() == euid() && parent.mode() & 0o022 == 0 => {
            if std::fs::symlink_metadata(home).is_ok() && !facts.resume {
                checks.push(conflict("agent_home", "an Agent home already exists; onboarding never adopts or overwrites an existing profile, config or policy",
                    "select a new Agent home, or remove the existing one yourself after review"));
            } else if facts.resume {
                checks.push(ok("agent_home", "a recorded onboarding of this Agent home can be resumed or undone"));
            } else {
                checks.push(ok("agent_home", "new Agent home will be created"));
            }
        }
        (true, _) => checks.push(refused("agent_home", "the Agent home parent must exist, be owned by you and not be group/world-writable",
            "use a private directory such as your home directory")),
        (false, _) => checks.push(refused("agent_home", "--agent-home must be an absolute path without links whose last component is `.agentfw`",
            "pass <private directory>/.agentfw")),
    }

    // Host configuration and the selected reviewed entry.
    check_host(inputs, &mut checks, &mut facts, journal.as_ref());

    // Port: never adopt a foreign listener.
    let ours = facts.resume
        && journal
            .as_ref()
            .is_some_and(|j| j.steps.get("lifecycle_start").map(String::as_str) == Some("done"));
    if port_in_use(inputs.port) && !ours {
        checks.push(conflict(
            "port",
            format!(
                "127.0.0.1:{} already has a listener that this onboarding does not own",
                inputs.port
            ),
            "stop that listener, or choose another --port",
        ));
    } else {
        checks.push(ok(
            "port",
            format!("127.0.0.1:{} is available for the new Agent", inputs.port),
        ));
    }

    // Optional explicit probe.
    if let (Some(tool), Some(args)) = (&inputs.probe_tool, &inputs.probe_args) {
        let valid = !tool.is_empty()
            && tool.len() <= 128
            && serde_json::from_str::<Value>(args).is_ok_and(|v| v.is_object());
        checks.push(if valid {
            ok(
                "probe",
                "an explicit harmless probe call will verify the connected server",
            )
        } else {
            refused(
                "probe",
                "probe tool must be 1..128 characters and its arguments a JSON object",
                "fix --probe-tool/--probe-args",
            )
        });
    } else {
        checks.push(ok(
            "probe",
            "no probe selected; the server connection can be configured but not verified",
        ));
    }
    let hashes_ok = [&inputs.agent_sha256, &inputs.registry_sha256]
        .iter()
        .all(|h| hex64(h));
    if !hashes_ok {
        checks.push(refused(
            "digests",
            "SHA-256 inputs must be 64 lowercase hex characters",
            "copy the digests from sha256sum",
        ));
    }
    (checks, facts)
}

fn run_python_version(python: &Path) -> Option<String> {
    let mut command = Process::new(python);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "-I",
            "-c",
            "import sys; print('%d.%d.%d' % sys.version_info[:3])",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    let output = command.output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (output.status.success() && text.starts_with("3.")).then_some(text)
}

fn check_host(
    inputs: &Inputs,
    checks: &mut Vec<Check>,
    facts: &mut Facts,
    journal: Option<&Journal>,
) {
    let path = &inputs.host_config;
    let parent_ok = path
        .parent()
        .and_then(|p| std::fs::metadata(p).ok())
        .is_some_and(|m| m.is_dir() && m.uid() == euid() && m.mode() & 0o002 == 0);
    let meta = std::fs::symlink_metadata(path);
    let private = meta
        .as_ref()
        .is_ok_and(|m| m.is_file() && m.nlink() == 1 && m.uid() == euid() && m.mode() & 0o077 == 0);
    if plain_path(path).is_err() || !parent_ok || !private {
        checks.push(refused("host_config", "host configuration must be an absolute, link-free, private (0600) regular file you own, in a directory others cannot write",
            "fix ownership/permissions yourself (onboarding never changes them)"));
        return;
    }
    let Ok(bytes) = read_limited(path, MAX_HOST_CONFIG) else {
        checks.push(refused(
            "host_config",
            "host configuration is unreadable or larger than 1 MiB",
            "select the Claude Code JSON file",
        ));
        return;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        checks.push(refused(
            "host_config",
            "host configuration is not valid JSON",
            "fix the JSON before onboarding",
        ));
        return;
    };
    let Some(servers) = value["mcpServers"].as_object() else {
        checks.push(refused(
            "host_config",
            "host configuration has no mcpServers object",
            "add the reviewed server entry first",
        ));
        return;
    };
    facts.host_sha256 = sha256(&bytes);
    facts.other_servers = servers.len().saturating_sub(1);
    facts.other_settings = value
        .as_object()
        .map(|o| o.len().saturating_sub(1))
        .unwrap_or(0);
    let Some(entry) = servers.get(&inputs.server) else {
        checks.push(refused(
            "server",
            "the selected server entry does not exist",
            "add the reviewed server entry to mcpServers, then preview again",
        ));
        return;
    };
    facts.entry_sha256 = sha256(canonical(entry).as_bytes());
    let args_ok = entry
        .get("args")
        .is_none_or(|a| a.as_array().is_some_and(|a| a.iter().all(Value::is_string)));
    let env_empty = entry
        .get("env")
        .is_none_or(|e| e.as_object().is_some_and(|o| o.is_empty()));
    let stdio = entry.get("type").is_none_or(|t| t == "stdio") && entry.get("url").is_none();
    let command = entry["command"].as_str().map(Path::new);
    let wrapped = entry["args"]
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v == "--native-admission"));
    let connected_by_us = journal.is_some_and(|j| j.steps.contains_key("connect_server"));
    if wrapped && !connected_by_us {
        checks.push(conflict(
            "server",
            "the selected entry is already wrapped by another connection",
            "disconnect it with its owner first",
        ));
        return;
    }
    if wrapped {
        checks.push(ok(
            "server",
            "the selected entry is the wrapper recorded by this onboarding",
        ));
        return;
    }
    let command_ok = command.is_some_and(|c| {
        plain_path(c).is_ok()
            && std::fs::metadata(c)
                .is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0 && m.mode() & 0o002 == 0)
    });
    if !(args_ok && env_empty && stdio && command_ok) {
        checks.push(refused("server", "the entry must be a stdio command with an absolute, link-free executable, string arguments and no environment values",
            "use the real executable path (for example from readlink -f) and move credentials out of env"));
        return;
    }
    checks.push(ok("server", format!("reviewed stdio entry found; {} other server entries and {} other settings will be preserved",
        facts.other_servers, facts.other_settings)));
}

/// Returns the full plan digest and a core digest that excludes the host file
/// bytes, so a recorded onboarding can resume after its own connection changed them.
pub(crate) fn plan(inputs: &Inputs, facts: &Facts) -> (Value, String, String) {
    let home = &inputs.agent_home;
    let identity = json!({
        "schema": super::SCHEMA, "profile": super::PROFILE,
        "agent": {"path": inputs.agent, "sha256": facts.agent_sha256},
        "classifier": {"kind": inputs.classifier, "script": inputs.classifier_script, "sha256": inputs.classifier_sha256,
                       "python": inputs.classifier_python},
        "registry": {"path": inputs.registry, "sha256": inputs.registry_sha256},
        "policy": {"source": facts.policy_source, "sha256": sha256(&facts.policy_bytes)},
        "workspace": inputs.workspace, "agent_home": home,
        "host_config": {"path": inputs.host_config, "sha256": facts.host_sha256, "server": inputs.server,
                        "entry_sha256": facts.entry_sha256},
        "port": inputs.port,
        "probe": inputs.probe_tool.as_ref().map(|t| json!({"tool": t, "args_sha256": sha256(inputs.probe_args.clone().unwrap_or_default().as_bytes())})),
        "version_label": version_label(&facts.agent_sha256),
    });
    let digest = sha256(canonical(&identity).as_bytes());
    let mut core = identity.clone();
    core["host_config"]["sha256"] = Value::Null;
    core["host_config"]["entry_sha256"] = Value::Null;
    let core_digest = sha256(canonical(&core).as_bytes());
    (identity, digest, core_digest)
}

fn version_label(agent_sha: &str) -> String {
    format!("onboard-{}", agent_sha.get(..12).unwrap_or("unknown"))
}

/// Concrete changes shown to the operator (exact paths are printed, never stored in reports).
fn changes(inputs: &Inputs, facts: &Facts) -> Vec<(String, &'static str)> {
    let home = inputs.agent_home.display();
    vec![
        (format!("create directory {home} (mode 0700)"), "agent_home"),
        (format!("write {home}/{OWNED_DIR}/registry.json and policy.yaml, and {home}/config.yaml (enforce, 127.0.0.1:{}, pinned registry)", inputs.port), "owned_files"),
        (format!("run `agentfw install` for {home} (creates its token)"), "token"),
        (format!("run `agentfw lifecycle install {}` and `lifecycle start` (no service)", version_label(&facts.agent_sha256)), "lifecycle"),
        (format!("run `agentfw mcp-connection connect` for server `{}` in {} (only that entry is rewritten; its recovery files stay beside the config)",
                 inputs.server, inputs.host_config.display()), "connection"),
        ("verify with protection-status, mcp-connection inspect (explicit probe only) and the isolated self-test".into(), "verification"),
    ]
}

// ------------------------------------------------------------------ journal

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Journal {
    pub schema: String,
    pub plan_sha256: String,
    pub core_sha256: String,
    pub agent_home: String,
    pub host_config: String,
    pub server: String,
    pub agent: String,
    pub agent_sha256: String,
    pub port: u16,
    pub created_home: bool,
    pub files: BTreeMap<String, String>,
    pub steps: BTreeMap<String, String>,
    pub phase: String,
    /// Entries of a home this operation created that its own steps created or changed,
    /// recorded around each step. Cleanup removes only entries that still match.
    #[serde(default)]
    pub inventory: BTreeMap<String, InventoryEntry>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InventoryEntry {
    pub kind: String,
    pub sha256: Option<String>,
}

const INVENTORY_DEPTH: usize = 8;
const INVENTORY_ENTRIES: usize = 4096;

fn entry_of(path: &Path) -> Option<InventoryEntry> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let file_type = meta.file_type();
    Some(if file_type.is_symlink() {
        let target = std::fs::read_link(path).ok()?;
        InventoryEntry {
            kind: "symlink".into(),
            sha256: Some(sha256(target.as_os_str().as_encoded_bytes())),
        }
    } else if file_type.is_dir() {
        InventoryEntry {
            kind: "dir".into(),
            sha256: None,
        }
    } else if file_type.is_file() {
        InventoryEntry {
            kind: "file".into(),
            sha256: sha256_file(path).ok(),
        }
    } else {
        InventoryEntry {
            kind: "other".into(),
            sha256: None,
        }
    })
}

/// Bounded, non-following inventory of a directory tree, keyed by relative path.
pub(crate) fn inventory(root: &Path) -> BTreeMap<String, InventoryEntry> {
    fn walk(dir: &Path, prefix: &str, depth: usize, out: &mut BTreeMap<String, InventoryEntry>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            if out.len() >= INVENTORY_ENTRIES {
                return;
            }
            let rel = format!("{prefix}{}", entry.file_name().to_string_lossy());
            let Some(record) = entry_of(&entry.path()) else {
                continue;
            };
            let is_dir = record.kind == "dir";
            out.insert(rel.clone(), record);
            if is_dir && depth < INVENTORY_DEPTH {
                walk(&entry.path(), &format!("{rel}/"), depth + 1, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, "", 1, &mut out);
    out
}

/// Remove, bottom-up and without following links, only entries that still match the
/// recorded inventory. Untracked or changed entries are preserved and returned.
/// A non-empty audit log is kept unless the operator explicitly purges.
pub(crate) fn clean_recorded(
    root: &Path,
    recorded: &BTreeMap<String, InventoryEntry>,
    purge_audit: bool,
) -> (Vec<String>, bool) {
    fn walk(
        dir: &Path,
        prefix: &str,
        recorded: &BTreeMap<String, InventoryEntry>,
        purge_audit: bool,
        preserved: &mut Vec<String>,
        audit_kept: &mut bool,
    ) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let rel = format!("{prefix}{}", entry.file_name().to_string_lossy());
            let Some(actual) = entry_of(&path) else {
                continue;
            };
            if actual.kind == "dir" {
                walk(
                    &path,
                    &format!("{rel}/"),
                    recorded,
                    purge_audit,
                    preserved,
                    audit_kept,
                );
                let tracked = recorded.get(&rel).is_some_and(|r| r.kind == "dir");
                if !tracked || std::fs::remove_dir(&path).is_err() {
                    // An untracked directory, or one still holding preserved entries, stays.
                    if !tracked {
                        preserved.push(rel);
                    }
                }
                continue;
            }
            if rel == "audit.jsonl" && actual.kind == "file" {
                let empty = std::fs::metadata(&path).is_ok_and(|m| m.len() == 0);
                if purge_audit || empty {
                    let _ = std::fs::remove_file(&path);
                } else {
                    *audit_kept = true;
                }
                continue;
            }
            if recorded.get(&rel) == Some(&actual) {
                let _ = std::fs::remove_file(&path);
            } else {
                preserved.push(rel);
            }
        }
    }
    let mut preserved = Vec::new();
    let mut audit_kept = false;
    walk(
        root,
        "",
        recorded,
        purge_audit,
        &mut preserved,
        &mut audit_kept,
    );
    (preserved, audit_kept)
}

fn load_journal(state: &Path) -> std::io::Result<Option<Journal>> {
    match read_limited(&state.join(JOURNAL), 1024 * 1024) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(std::io::Error::other),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn save_journal(state: &Path, journal: &Journal) -> std::io::Result<()> {
    write_journal_file(
        &state.join(JOURNAL),
        &serde_json::to_vec_pretty(journal).map_err(std::io::Error::other)?,
    )
}

struct StateLock(File);

impl Drop for StateLock {
    fn drop(&mut self) {
        // SAFETY: unlocking our own descriptor.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn lock_state(state: &Path) -> Result<StateLock, String> {
    match std::fs::symlink_metadata(state) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() && meta.uid() == euid() => {}
        Ok(_) => {
            return Err(
                "the onboarding state directory is not a private directory owned by you".into(),
            )
        }
        Err(_) => std::fs::DirBuilder::new()
            .mode(0o700)
            .create(state)
            .map_err(|_| "could not create the onboarding state directory".to_string())?,
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(state.join(LOCK))
        .map_err(|_| "could not open the onboarding lock".to_string())?;
    // SAFETY: flock on our own descriptor.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another onboarding operation is running for this Agent home".into());
    }
    Ok(StateLock(file))
}

// ------------------------------------------------------------------ report

struct Report {
    file: File,
    body: serde_json::Map<String, Value>,
}

fn reserve_report(path: &Path, operation: &str) -> Result<Report, i32> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => Ok(Report {
            file,
            body: base_report(operation, true),
        }),
        Err(_) => {
            eprintln!("onboard: --report must be a new file in an existing writable directory; nothing ran");
            Err(EXIT_INCOMPLETE)
        }
    }
}

impl Report {
    fn finish(mut self, result: &str, code: i32, explanation: &str, next: Vec<String>) -> i32 {
        self.body.insert("result".into(), json!(result));
        self.body.insert("exit_code".into(), json!(code));
        self.body.insert("explanation".into(), json!(explanation));
        self.body.insert("next_steps".into(), json!(next));
        let mut bytes = serde_json::to_vec_pretty(&Value::Object(self.body)).unwrap_or_default();
        bytes.push(b'\n');
        let written = self
            .file
            .write_all(&bytes)
            .and_then(|_| self.file.sync_all())
            .is_ok();
        println!(
            "Result: {} (exit {code}). {explanation}",
            result.to_uppercase()
        );
        for step in &next {
            println!("  next: {step}");
        }
        if !written {
            eprintln!("onboard: the report could not be written completely");
            return EXIT_INCOMPLETE;
        }
        code
    }
}

fn checks_json(checks: &[Check]) -> Value {
    json!(checks)
}

fn labels(inputs: &Inputs, facts: &Facts) -> Value {
    json!({
        "agent": {"sha256": facts.agent_sha256, "path_digest": path_digest(&inputs.agent)},
        "classifier": {"kind": inputs.classifier, "sha256": inputs.classifier_sha256, "python_version": facts.python_version},
        "registry": {"registry_id": facts.registry_id, "sha256": inputs.registry_sha256},
        "policy": {"source": facts.policy_source, "file_sha256": sha256(&facts.policy_bytes),
                   "expected_daemon_digest": facts.expected_policy_digest, "rule_count": facts.policy_rules},
        "workspace": {"path_digest": path_digest(&inputs.workspace)},
        "agent_home": {"path_digest": path_digest(&inputs.agent_home)},
        "host_config": {"path_digest": path_digest(&inputs.host_config), "sha256_at_preview": facts.host_sha256,
                        "selected_entry_sha256": facts.entry_sha256, "other_server_entries": facts.other_servers,
                        "other_settings": facts.other_settings},
        "port": inputs.port,
        "probe": inputs.probe_tool.is_some(),
    })
}

const COVERAGE: &str = "unknown";

fn coverage() -> Value {
    json!({
        "host_session": COVERAGE, "other_mcp_servers": COVERAGE, "claude_hooks": COVERAGE, "model_context": COVERAGE,
        "note": "No Claude Code session was observed by onboarding; only the configured entry, the daemon identity, an explicit probe and the isolated self-test are reported."
    })
}

// ------------------------------------------------------------------ preview

fn print_plan(inputs: &Inputs, checks: &[Check], facts: &Facts, digest: Option<&str>) {
    println!(
        "Soup Wall onboarding preview ({}); nothing has been changed.",
        super::PROFILE
    );
    println!("Inputs:");
    println!("  Agent          {}", inputs.agent.display());
    println!("  Agent home     {}", inputs.agent_home.display());
    println!(
        "  Host config    {} (server `{}`)",
        inputs.host_config.display(),
        inputs.server
    );
    println!("  Registry       {}", inputs.registry.display());
    println!(
        "  Policy         {}",
        inputs
            .policy
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "shipped default".into())
    );
    println!("  Workspace      {}", inputs.workspace.display());
    println!(
        "  Classifier     {} (Python {})",
        inputs.classifier_script.display(),
        facts.python_version
    );
    println!("Checks:");
    for check in checks {
        println!(
            "  {:<9} {:<18} {}",
            check.status.to_uppercase(),
            check.id,
            check.detail
        );
        if let Some(action) = &check.action {
            println!("            action: {action}");
        }
    }
    if let Some(digest) = digest {
        println!("Planned changes:");
        for (index, (change, _)) in changes(inputs, facts).iter().enumerate() {
            println!("  {}. {change}", index + 1);
        }
        println!("Not changed: other mcpServers entries, other settings, services, credentials and existing policies.");
        println!("Plan SHA-256: {digest}");
    }
}

fn preview(inputs: Inputs) -> i32 {
    let mut report = match reserve_report(&inputs.report, "preview") {
        Ok(report) => report,
        Err(code) => return code,
    };
    let (checks, facts) = check_inputs(&inputs);
    let blocked = checks.iter().any(|c| c.status != "ok");
    let (_, digest, _) = plan(&inputs, &facts);
    print_plan(
        &inputs,
        &checks,
        &facts,
        (!blocked).then_some(digest.as_str()),
    );
    report.body.insert("inputs".into(), labels(&inputs, &facts));
    report.body.insert("checks".into(), checks_json(&checks));
    if blocked {
        let next = checks.iter().filter_map(|c| c.action.clone()).collect();
        return report.finish(
            "refused",
            EXIT_INCOMPLETE,
            "The plan cannot be applied; resolve the refused or conflicting checks.",
            next,
        );
    }
    report.body.insert("plan_sha256".into(), json!(digest));
    report.body.insert(
        "planned_changes".into(),
        json!(changes(&inputs, &facts)
            .iter()
            .map(|(_, l)| *l)
            .collect::<Vec<_>>()),
    );
    report.finish("plan_ready", EXIT_OK, "Review the planned changes; nothing has been changed.",
        vec![format!("apply exactly this plan with: agentfw onboard apply <same inputs> --plan-sha256 {digest}")])
}

// ------------------------------------------------------------------ apply

struct Session<'a> {
    inputs: &'a Inputs,
    facts: &'a Facts,
    state: PathBuf,
    profile: PathBuf,
    journal: Journal,
    deadline: Instant,
    evidence: serde_json::Map<String, Value>,
}

enum StepError {
    /// Contradiction with an expectation: report failed.
    Failed(String),
    /// Missing, conflicting or unavailable: report incomplete.
    Incomplete(String),
}

impl Session<'_> {
    fn home(&self) -> &Path {
        &self.inputs.agent_home
    }

    fn mark(&mut self, step: &str, state: &str) -> Result<(), StepError> {
        self.journal.steps.insert(step.into(), state.into());
        save_journal(&self.state, &self.journal)
            .map_err(|_| StepError::Incomplete("the onboarding journal could not be saved".into()))
    }

    fn limit(&self) -> Duration {
        STEP_TIMEOUT.min(self.deadline.saturating_duration_since(Instant::now()))
    }

    fn agent(&self, args: Vec<OsString>, profile: bool) -> Output {
        run_agent(
            &self.inputs.agent,
            &args,
            profile.then_some(self.profile.as_path()),
            self.limit(),
        )
    }

    fn owned_files(&self) -> Vec<(String, PathBuf, Vec<u8>)> {
        let owned = self.home().join(OWNED_DIR);
        let registry = owned.join("registry.json");
        let policy = owned.join("policy.yaml");
        let config = json!({"bind": "127.0.0.1", "port": self.inputs.port, "enforce": true, "policy": policy,
            "native": {"registry_path": registry, "registry_sha256": self.inputs.registry_sha256}});
        vec![
            (
                "registry".into(),
                registry,
                self.facts.registry_bytes.clone(),
            ),
            ("policy".into(), policy, self.facts.policy_bytes.clone()),
            (
                "config".into(),
                self.home().join("config.yaml"),
                config.to_string().into_bytes(),
            ),
        ]
    }

    fn step(&mut self, name: &'static str) -> Result<(), StepError> {
        if self.journal.steps.get(name).map(String::as_str) == Some("done")
            && !matches!(name, "verify_identity" | "verify_server" | "self_test")
        {
            return Ok(());
        }
        self.mark(name, "started")?;
        let started = Instant::now();
        let before = if self.home().is_dir() {
            inventory(self.home())
        } else {
            BTreeMap::new()
        };
        let result = match name {
            "create_agent_home" => self.create_home(),
            "write_owned_files" => self.write_files(),
            "create_token" => self.create_token(),
            "lifecycle_install" => self.lifecycle_install(),
            "lifecycle_start" => self.lifecycle_start(),
            "verify_identity" => self.verify_identity(),
            "connect_server" => self.connect(),
            "verify_server" => self.verify_server(),
            "self_test" => self.self_test(),
            _ => unreachable!(),
        };
        let elapsed = started.elapsed().as_millis() as u64;
        let entry = self.evidence.entry("steps").or_insert_with(|| json!({}));
        entry[name] = json!({"outcome": if result.is_ok() { "done" } else { "stopped" }, "elapsed_ms": elapsed});
        // Attribute to this operation only what the step itself created or changed, even
        // when it stopped; entries that existed before the step and were not ours stay foreign.
        if self.journal.created_home && self.home().is_dir() {
            for (rel, entry) in inventory(self.home()) {
                if before.get(&rel) != Some(&entry) || self.journal.inventory.contains_key(&rel) {
                    self.journal.inventory.insert(rel, entry);
                }
            }
        }
        if result.is_ok() {
            self.mark(name, "done")?;
        } else {
            let _ = save_journal(&self.state, &self.journal);
        }
        result
    }

    fn create_home(&mut self) -> Result<(), StepError> {
        let home = self.home().to_path_buf();
        match std::fs::symlink_metadata(&home) {
            Err(_) => {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&home)
                    .map_err(|_| StepError::Incomplete("could not create the Agent home".into()))?;
                self.journal.created_home = true;
                Ok(())
            }
            // Resume after a crash between journaling and creation: adopt only an empty or owned-only home.
            Ok(meta)
                if self.journal.steps.contains_key("create_agent_home")
                    && meta.is_dir()
                    && only_known_entries(&home) =>
            {
                self.journal.created_home = true;
                Ok(())
            }
            Ok(_) => Err(StepError::Incomplete(
                "the Agent home appeared after preview; onboarding does not adopt it".into(),
            )),
        }
    }

    fn write_files(&mut self) -> Result<(), StepError> {
        let owned = self.home().join(OWNED_DIR);
        if std::fs::symlink_metadata(&owned).is_err() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&owned)
                .map_err(|_| {
                    StepError::Incomplete("could not create the owned onboarding directory".into())
                })?;
        }
        for (label, path, bytes) in self.owned_files() {
            match read_limited(&path, MAX_POLICY) {
                Ok(existing) if existing == bytes => {}
                Ok(_) => {
                    return Err(StepError::Incomplete(format!(
                        "{label} was changed outside onboarding; not overwritten"
                    )))
                }
                Err(_) => write_new_private(&path, &bytes).map_err(|_| {
                    StepError::Incomplete(format!("could not write the owned {label} file"))
                })?,
            }
            self.journal.files.insert(label, sha256(&bytes));
        }
        Ok(())
    }

    fn create_token(&mut self) -> Result<(), StepError> {
        let output = self.agent(os(&["install"]), true);
        let token = self.home().join("token");
        if !output.ok() || !token.is_file() {
            return Err(StepError::Incomplete(
                "`agentfw install` did not create the Agent token".into(),
            ));
        }
        let digest =
            sha256_file(&token).map_err(|_| StepError::Incomplete("token unreadable".into()))?;
        self.journal.files.insert("token".into(), digest);
        Ok(())
    }

    fn lifecycle_status(&self) -> Option<Value> {
        self.agent(os(&["lifecycle", "status"]), true).json()
    }

    fn lifecycle_install(&mut self) -> Result<(), StepError> {
        if self
            .lifecycle_status()
            .is_some_and(|s| s["active"]["digest"] == json!(self.facts.agent_sha256))
        {
            return Ok(());
        }
        let mut args = os(&[
            "lifecycle",
            "install",
            &version_label(&self.facts.agent_sha256),
        ]);
        args.push(self.inputs.agent.as_os_str().to_owned());
        args.extend(os(&["--sha256", &self.facts.agent_sha256]));
        if self.agent(args, true).ok() {
            Ok(())
        } else {
            Err(StepError::Incomplete(
                "`agentfw lifecycle install` refused the selected Agent".into(),
            ))
        }
    }

    fn lifecycle_start(&mut self) -> Result<(), StepError> {
        if self
            .lifecycle_status()
            .is_some_and(|s| s["running"] == true)
        {
            return Ok(());
        }
        if port_in_use(self.inputs.port) {
            return Err(StepError::Incomplete(format!(
                "127.0.0.1:{} gained a foreign listener after preview; it was not adopted",
                self.inputs.port
            )));
        }
        let output = self.agent(os(&["lifecycle", "start"]), true);
        if output.ok()
            && self
                .lifecycle_status()
                .is_some_and(|s| s["running"] == true)
        {
            Ok(())
        } else {
            Err(StepError::Incomplete(if output.timed_out {
                "the Agent did not become healthy in time".into()
            } else {
                "`agentfw lifecycle start` did not start an owned, verified Agent".into()
            }))
        }
    }

    fn verify_identity(&mut self) -> Result<(), StepError> {
        let pid = self
            .lifecycle_status()
            .and_then(|s| s["process"]["pid"].as_u64());
        let args = with_paths(os(&["protection-status"]), &[("--home", self.home())]);
        let mut args = args;
        args.extend(os(&[
            "--query-only",
            "--require-enforce",
            "--expect-registry-sha256",
            &self.inputs.registry_sha256,
            "--expect-binary-sha256",
            &self.facts.agent_sha256,
        ]));
        let output = self.agent(args, false);
        let Some(value) = output.json() else {
            return Err(StepError::Incomplete(
                "authenticated protection-status was unavailable".into(),
            ));
        };
        let snapshot = &value["snapshot"];
        let checks = json!({
            "query_answered": output.ok() && value["query"] == "answered",
            "mode_enforcing": snapshot["mode"] == "enforcing",
            "pid_matches_lifecycle": pid.is_some() && snapshot["runtime"]["pid"].as_u64() == pid,
            "binary_matches_agent": snapshot["runtime"]["binary_sha256"] == json!(self.facts.agent_sha256),
            "registry_matches": snapshot["registry"]["sha256"] == json!(self.inputs.registry_sha256),
            "policy_matches": snapshot["policy"]["sha256"] == json!(self.facts.expected_policy_digest),
        });
        self.evidence.insert("configured".into(), json!({
            "note": "daemon identity and configuration; not witnessed protection",
            "checks": checks,
            "policy": {"digest_format": snapshot["policy"]["digest_format"], "sha256": snapshot["policy"]["sha256"],
                       "rule_count": snapshot["policy"]["rule_count"]},
            "registry": snapshot["registry"],
        }));
        if checks
            .as_object()
            .expect("object")
            .values()
            .all(|v| v == true)
        {
            Ok(())
        } else {
            Err(StepError::Failed("the running Agent's identity, mode, policy or registry does not match the reviewed plan".into()))
        }
    }

    fn connection_args(&self, operation: &str) -> Vec<OsString> {
        with_paths(
            os(&["mcp-connection", operation]),
            &[
                ("--path", &self.inputs.host_config),
                ("--agent", &self.inputs.agent),
                ("--home", self.home()),
            ],
        )
        .into_iter()
        .chain(os(&["--server", &self.inputs.server]))
        .collect()
    }

    fn connect(&mut self) -> Result<(), StepError> {
        let output = self.agent(self.connection_args("connect"), false);
        let status = output
            .json()
            .map(|v| v["status"].clone())
            .unwrap_or(Value::Null);
        self.evidence
            .insert("connection".into(), json!({"status": status}));
        if output.ok() && status == "configured" {
            Ok(())
        } else {
            Err(StepError::Incomplete("`mcp-connection connect` did not configure the entry (conflict, race or preflight failure); see its own recovery guidance".into()))
        }
    }

    fn verify_server(&mut self) -> Result<(), StepError> {
        let mut args = self.connection_args("inspect");
        if let (Some(tool), Some(probe)) = (&self.inputs.probe_tool, &self.inputs.probe_args) {
            args.extend(os(&["--probe-tool", tool, "--probe-args", probe]));
        }
        let output = self.agent(args, false);
        let value = output.json().unwrap_or(Value::Null);
        let status = value["status"].as_str().unwrap_or("unavailable").to_owned();
        self.evidence.insert("host_probe".into(), json!({
            "status": status, "probe_requested": self.inputs.probe_tool.is_some(),
            "probe_result_sha256": value["probe_result_sha256"],
            "scope": "one explicit call through the configured entry; future calls still pass native admission"}));
        match status.as_str() {
            "verified_for_this_probe" | "configured" => Ok(()),
            _ => Err(StepError::Failed(format!(
                "the connected server did not verify ({status})"
            ))),
        }
    }

    fn self_test(&mut self) -> Result<(), StepError> {
        let report = self.state.join(format!(
            "self-test-{}.json",
            crate::self_test::now_unix_ms()
        ));
        let mut args = os(&[
            "self-test",
            "--classifier",
            &self.inputs.classifier,
            "--classifier-sha256",
            &self.inputs.classifier_sha256,
        ]);
        args = with_paths(
            args,
            &[
                ("--agent", &self.inputs.agent),
                ("--classifier-script", &self.inputs.classifier_script),
                ("--classifier-python", &self.inputs.classifier_python),
                ("--report", &report),
            ],
        );
        let output = self.agent(args, false);
        let result = read_limited(&report, 4 * 1024 * 1024)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
        let status = result
            .as_ref()
            .and_then(|r| r["result"].as_str())
            .unwrap_or("incomplete")
            .to_owned();
        self.evidence.insert("self_test".into(), json!({
            "result": status, "exit_code": output.code,
            "summary": result.as_ref().map(|r| r["summary"].clone()),
            "report_sha256": read_limited(&report, 4 * 1024 * 1024).ok().map(|b| sha256(&b)),
            "scope": "isolated temporary workspace and daemon; it does not show that the configured host is protected"}));
        match status.as_str() {
            "passed" => Ok(()),
            "failed" => Err(StepError::Failed(
                "the installed self-test witnessed a protection failure".into(),
            )),
            _ => Err(StepError::Incomplete(
                "the installed self-test did not complete".into(),
            )),
        }
    }
}

/// True when every entry is one this operation or the Agent it started creates.
fn only_known_entries(home: &Path) -> bool {
    std::fs::read_dir(home)
        .map(|entries| {
            entries.flatten().all(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name == "config.yaml"
                    || RUNTIME_ENTRIES.contains(&name.as_str())
                    || name.starts_with(".launch-")
            })
        })
        .unwrap_or(false)
}

fn apply(args: ApplyArgs) -> i32 {
    let inputs = args.inputs;
    let mut report = match reserve_report(&inputs.report, "apply") {
        Ok(report) => report,
        Err(code) => return code,
    };
    install_signal_handlers();
    let started = Instant::now();
    let (checks, facts) = check_inputs(&inputs);
    let (_, digest, core) = plan(&inputs, &facts);
    report.body.insert("inputs".into(), labels(&inputs, &facts));
    report.body.insert("checks".into(), checks_json(&checks));
    report.body.insert("coverage".into(), coverage());
    if checks.iter().any(|c| c.status != "ok") {
        let next = checks.iter().filter_map(|c| c.action.clone()).collect();
        return report.finish(
            "refused",
            EXIT_INCOMPLETE,
            "Revalidation refused the plan; nothing was changed.",
            next,
        );
    }
    let recorded = paths(&inputs.agent_home).and_then(|p| load_journal(&p.state).ok().flatten());
    if let Some(phase) = recorded
        .as_ref()
        .map(|j| j.phase.clone())
        .filter(|p| p.starts_with("undone") || p == "rollback_conflict")
    {
        return report.finish("refused", EXIT_INCOMPLETE,
            &format!("The recorded onboarding for this Agent home is `{phase}`; it is not resumed and nothing was changed."),
            vec!["run `agentfw onboard undo` (with --purge-agent-home to remove a retained audit log), then preview again".into()]);
    }
    let resumable = recorded
        .as_ref()
        .is_some_and(|j| j.plan_sha256 == args.plan_sha256 && j.core_sha256 == core);
    if digest != args.plan_sha256 && !resumable {
        return report.finish("refused", EXIT_INCOMPLETE,
            "The current inputs or host files differ from the reviewed preview; nothing was changed.",
            vec!["run `agentfw onboard preview` again, review the new plan and apply its digest".into()]);
    }
    report
        .body
        .insert("plan_sha256".into(), json!(args.plan_sha256));
    let Some(paths) = paths(&inputs.agent_home) else {
        return report.finish("refused", EXIT_INCOMPLETE, "invalid Agent home", vec![]);
    };
    let _lock = match lock_state(&paths.state) {
        Ok(lock) => lock,
        Err(reason) => {
            return report.finish(
                "refused",
                EXIT_INCOMPLETE,
                &reason,
                vec!["wait for the other operation, then retry".into()],
            )
        }
    };
    let journal = match load_journal(&paths.state) {
        Ok(Some(journal))
            if journal.plan_sha256 == args.plan_sha256 && journal.core_sha256 == core =>
        {
            journal
        }
        Ok(Some(_)) => {
            return report.finish(
                "refused",
                EXIT_INCOMPLETE,
                "A different onboarding is recorded for this Agent home; nothing was changed.",
                vec!["run `agentfw onboard undo` for the recorded onboarding first".into()],
            )
        }
        Ok(None) => Journal {
            schema: super::SCHEMA.into(),
            plan_sha256: digest.clone(),
            core_sha256: core.clone(),
            agent_home: inputs.agent_home.to_string_lossy().into(),
            host_config: inputs.host_config.to_string_lossy().into(),
            server: inputs.server.clone(),
            agent: inputs.agent.to_string_lossy().into(),
            agent_sha256: facts.agent_sha256.clone(),
            port: inputs.port,
            phase: "applying".into(),
            ..Default::default()
        },
        Err(_) => {
            return report.finish(
                "incomplete",
                EXIT_INCOMPLETE,
                "The onboarding journal is unreadable; nothing was changed.",
                vec!["inspect the onboarding state directory".into()],
            )
        }
    };
    let resumed = !journal.steps.is_empty();
    let mut session = Session {
        inputs: &inputs,
        facts: &facts,
        profile: paths.profile.clone(),
        state: paths.state.clone(),
        journal,
        deadline: started + Duration::from_secs(inputs.timeout_seconds),
        evidence: serde_json::Map::new(),
    };
    session.journal.phase = "applying".into();
    let _ = save_journal(&session.state, &session.journal);
    println!(
        "Applying plan {}{}",
        args.plan_sha256,
        if resumed {
            " (resuming a recorded onboarding)"
        } else {
            ""
        }
    );
    let mut stop: Option<StepError> = None;
    let mut interrupted_at = None;
    for name in STEPS {
        if interrupted() || Instant::now() >= session.deadline {
            interrupted_at = Some(name);
            break;
        }
        print!("  {name:<20} ");
        let _ = std::io::stdout().flush();
        match session.step(name) {
            Ok(()) => println!("done"),
            Err(error) => {
                println!("stopped");
                stop = Some(error);
                break;
            }
        }
    }
    let steps = session.journal.steps.clone();
    let mut body = std::mem::take(&mut session.evidence);
    body.insert("journal_steps".into(), json!(steps));
    body.insert("resumed".into(), json!(resumed));
    body.insert(
        "duration_ms".into(),
        json!(started.elapsed().as_millis() as u64),
    );
    let configured_done = steps.get("verify_identity").map(String::as_str) == Some("done")
        && steps.get("connect_server").map(String::as_str) == Some("done");
    let (result, code, explanation, next) = if let Some(step) = interrupted_at {
        session.journal.phase = "interrupted".into();
        let _ = save_journal(&session.state, &session.journal);
        ("incomplete", EXIT_INCOMPLETE, format!("Interrupted before {step}; completed steps are journaled and nothing was rolled back."),
         vec!["rerun the same `agentfw onboard apply` to resume".into(), "or run `agentfw onboard undo` to reverse the recorded changes".into()])
    } else {
        match stop {
            None => {
                session.journal.phase = "applied".into();
                let _ = save_journal(&session.state, &session.journal);
                let probe = body["host_probe"]["status"] == "verified_for_this_probe";
                if probe {
                    ("verified", EXIT_OK, "Configured and verified: the daemon identity matches the plan, the explicit probe returned an admitted result and the isolated self-test passed. Unobserved host sessions remain unknown.".to_string(),
                     vec!["start a new Claude Code session so it loads the updated MCP entry".into(),
                          "to reverse: agentfw onboard undo with the same Agent, Agent home, host config and server".into()])
                } else {
                    ("configured", EXIT_CONFIGURED, "Configured: daemon identity and the MCP entry match the plan and the isolated self-test passed, but no probe verified the connected server.".to_string(),
                     vec!["rerun apply with --probe-tool/--probe-args for a harmless call to verify the server".into()])
                }
            }
            Some(error) => {
                let (result, code, reason) = match error {
                    StepError::Failed(reason) => ("failed", EXIT_FAILED, reason),
                    StepError::Incomplete(reason) => ("incomplete", EXIT_INCOMPLETE, reason),
                };
                // Verification failures after configuration are reported, not silently rolled back.
                if configured_done && result == "failed" {
                    session.journal.phase = "applied_unverified".into();
                    let _ = save_journal(&session.state, &session.journal);
                    (result, code, format!("Configured, but verification failed: {reason}."),
                     vec!["review the evidence; run `agentfw onboard undo` to reverse the configuration".into()])
                } else {
                    println!("Rolling back this operation's proven changes...");
                    // Automatic rollback is never a purge: an operator decides that explicitly.
                    let rollback = rollback(
                        &mut session.journal,
                        &inputs.agent,
                        &paths,
                        false,
                        session.deadline,
                    );
                    let clean = rollback.iter().all(|r| r["outcome"] != "conflict");
                    body.insert("rollback".into(), json!(rollback));
                    if clean && rollback.iter().any(|r| r["outcome"] == "retained") {
                        // A non-empty audit log stays; keep the record so an explicit purge can finish.
                        session.journal.steps.clear();
                        session.journal.phase = "undone_audit_retained".into();
                        let _ = save_journal(&session.state, &session.journal);
                    } else if clean {
                        let _ = remove_state(&paths.state);
                    } else {
                        session.journal.phase = "rollback_conflict".into();
                        let _ = save_journal(&session.state, &session.journal);
                    }
                    (
                        result,
                        code,
                        format!(
                            "{reason}. {}",
                            if clean {
                                "This operation's changes were rolled back."
                            } else {
                                "Rollback stopped at a conflict; see rollback."
                            }
                        ),
                        vec!["resolve the reason above, then preview and apply again".into()],
                    )
                }
            }
        }
    };
    for (key, value) in body {
        report.body.insert(key, value);
    }
    report.finish(result, code, &explanation, next)
}

// ------------------------------------------------------------------ rollback / undo

fn rollback(
    journal: &mut Journal,
    agent: &Path,
    paths: &Paths,
    purge: bool,
    deadline: Instant,
) -> Vec<Value> {
    let mut results = Vec::new();
    let limit = || {
        STEP_TIMEOUT.min(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_secs(30)),
        )
    };
    let home = PathBuf::from(&journal.agent_home);
    let host = PathBuf::from(&journal.host_config);
    let mut record = |step: &str, outcome: &str, detail: &str| {
        results.push(json!({"step": step, "outcome": outcome, "detail": detail}));
    };
    if journal.steps.contains_key("connect_server") {
        let args: Vec<OsString> = with_paths(
            os(&["mcp-connection", "disconnect"]),
            &[("--path", &host), ("--agent", agent), ("--home", &home)],
        )
        .into_iter()
        .chain(os(&["--server", &journal.server]))
        .collect();
        let output = run_agent(agent, &args, None, limit());
        if output.json().is_some_and(|v| v["status"] == "disconnected") {
            journal.steps.remove("connect_server");
            record(
                "connect_server",
                "reversed",
                "only the selected entry was restored; unrelated edits preserved",
            );
        } else {
            record("connect_server", "conflict", "mcp-connection refused to restore the entry (changed or pending); nothing was overwritten");
            return results;
        }
    }
    if journal.steps.contains_key("lifecycle_install")
        || journal.steps.contains_key("lifecycle_start")
    {
        let stopped = run_agent(
            agent,
            &os(&["lifecycle", "stop"]),
            Some(&paths.profile),
            limit(),
        );
        let removed = run_agent(
            agent,
            &os(&["lifecycle", "remove"]),
            Some(&paths.profile),
            limit(),
        );
        if removed.ok() {
            journal.steps.remove("lifecycle_start");
            journal.steps.remove("lifecycle_install");
            record(
                "lifecycle",
                "reversed",
                if stopped.ok() {
                    "owned Agent stopped and managed binary removed"
                } else {
                    "managed binary removed"
                },
            );
        } else {
            record(
                "lifecycle",
                "conflict",
                "`lifecycle remove` refused (unverified process or changed binary)",
            );
            return results;
        }
    }
    // Owned files: delete only exact bytes this operation wrote.
    let owned = [
        ("config", home.join("config.yaml")),
        ("registry", home.join(OWNED_DIR).join("registry.json")),
        ("policy", home.join(OWNED_DIR).join("policy.yaml")),
        ("token", home.join("token")),
    ];
    for (label, path) in owned {
        let Some(expected) = journal.files.get(label).cloned() else {
            continue;
        };
        match sha256_file(&path) {
            Ok(actual) if actual == expected => {
                let _ = std::fs::remove_file(&path);
                journal.files.remove(label);
                record(label, "reversed", "removed exact owned bytes");
            }
            Ok(_) => {
                record(label, "conflict", "changed outside onboarding; retained");
                return results;
            }
            Err(_) => {
                journal.files.remove(label);
            }
        }
    }
    if journal.created_home {
        // Only entries recorded by this operation are removed; nothing is removed recursively.
        let (preserved, audit_kept) = clean_recorded(&home, &journal.inventory, purge);
        if !preserved.is_empty() {
            let mut areas: Vec<String> = preserved
                .iter()
                .map(|rel| rel.split('/').next().unwrap_or_default().to_string())
                .collect();
            areas.dedup();
            record(
                "agent_home",
                "conflict",
                &format!(
                    "{} untracked or changed entries were preserved (under: {}); nothing else was removed",
                    preserved.len(),
                    areas.join(", ")
                ),
            );
        } else if std::fs::remove_dir(&home).is_ok() {
            journal.created_home = false;
            record(
                "agent_home",
                "reversed",
                "the Agent home created by onboarding was removed",
            );
        } else if audit_kept {
            record(
                "agent_home",
                "retained",
                "non-empty audit log retained; remove with undo --purge-agent-home after review",
            );
        } else {
            record(
                "agent_home",
                "conflict",
                "the Agent home could not be removed; retained",
            );
        }
    }
    results
}

fn remove_state(state: &Path) -> std::io::Result<()> {
    // Only our own state files: journal, lock and self-test reports.
    for entry in std::fs::read_dir(state)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == JOURNAL
            || name == LOCK
            || name == "journal.tmp"
            || (name.starts_with("self-test-") && name.ends_with(".json"))
        {
            std::fs::remove_file(entry.path())?;
        }
    }
    std::fs::remove_dir(state)
}

fn undo(args: UndoArgs) -> i32 {
    let mut report = match reserve_report(&args.report, "undo") {
        Ok(report) => report,
        Err(code) => return code,
    };
    install_signal_handlers();
    let Some(paths) = paths(&args.agent_home).filter(|_| plain_path(&args.agent_home).is_ok())
    else {
        return report.finish(
            "refused",
            EXIT_INCOMPLETE,
            "--agent-home must be an absolute link-free path",
            vec![],
        );
    };
    let _lock = match lock_state(&paths.state) {
        Ok(lock) => lock,
        Err(reason) => return report.finish("refused", EXIT_INCOMPLETE, &reason, vec![]),
    };
    let mut journal = match load_journal(&paths.state) {
        Ok(Some(journal)) => journal,
        Ok(None) => {
            let _ = std::fs::remove_file(paths.state.join(LOCK));
            let _ = std::fs::remove_dir(&paths.state);
            return report.finish(
                "refused",
                EXIT_INCOMPLETE,
                "No onboarding is recorded for this Agent home; nothing was changed.",
                vec![],
            );
        }
        Err(_) => {
            return report.finish(
                "incomplete",
                EXIT_INCOMPLETE,
                "The onboarding journal is unreadable; nothing was changed.",
                vec![],
            )
        }
    };
    if journal.host_config != args.host_config.to_string_lossy()
        || journal.server != args.server
        || journal.agent_home != args.agent_home.to_string_lossy()
    {
        return report.finish(
            "refused",
            EXIT_INCOMPLETE,
            "The inputs do not match the recorded onboarding; nothing was changed.",
            vec!["pass the same Agent home, host config and server that were applied".into()],
        );
    }
    let deadline = Instant::now() + Duration::from_secs(args.timeout_seconds);
    let results = rollback(
        &mut journal,
        &args.agent,
        &paths,
        args.purge_agent_home,
        deadline,
    );
    let conflict = results.iter().any(|r| r["outcome"] == "conflict");
    let retained = results.iter().any(|r| r["outcome"] == "retained");
    for line in &results {
        println!(
            "  {:<16} {:<9} {}",
            line["step"].as_str().unwrap_or(""),
            line["outcome"].as_str().unwrap_or(""),
            line["detail"].as_str().unwrap_or("")
        );
    }
    report.body.insert("rollback".into(), json!(results));
    report.body.insert("retained".into(), json!({
        "connection_recovery_files": "kept beside the host config by mcp-connection by design; remove only after review",
        "audit_log": retained}));
    if conflict {
        journal.phase = "rollback_conflict".into();
        let _ = save_journal(&paths.state, &journal);
        return report.finish(
            "incomplete",
            EXIT_INCOMPLETE,
            "Undo stopped at a conflict; nothing that changed outside onboarding was removed.",
            vec!["review the conflicting item, then run undo again".into()],
        );
    }
    // Every recorded step is reversed; keep a minimal journal only while an audit log is retained.
    journal.steps.clear();
    if retained {
        journal.phase = "undone_audit_retained".into();
        let _ = save_journal(&paths.state, &journal);
    } else {
        let _ = remove_state(&paths.state);
    }
    report.finish("undone", EXIT_OK,
        if retained { "This onboarding's changes were reversed; the non-empty audit log was kept." } else { "This onboarding's changes were reversed." },
        if retained { vec!["review and remove the retained audit log yourself, or run undo again with --purge-agent-home".into()] } else { vec![] })
}

pub fn run(command: Command) -> i32 {
    match command {
        Command::Preview(inputs) => preview(*inputs),
        Command::Apply(args) => apply(*args),
        Command::Undo(args) => undo(*args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_path_refuses_relative_aliases_and_links() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().canonicalize().unwrap();
        assert!(plain_path(&real.join("missing/child")).is_ok());
        assert!(plain_path(Path::new("relative")).is_err());
        assert!(plain_path(&real.join("a/../b")).is_err());
        std::os::unix::fs::symlink(&real, real.join("link")).unwrap();
        assert!(plain_path(&real.join("link/x")).is_err());
    }

    #[test]
    fn policy_digest_matches_the_daemon_serialization() {
        let (digest, rules) =
            expected_policy_digest(crate::self_test::fixture::SHIPPED_POLICY).unwrap();
        assert!(hex64(&digest));
        assert!(rules > 0);
        assert!(expected_policy_digest("agent_policies: [").is_none());
    }

    #[test]
    fn runtime_entry_check_refuses_unknown_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.yaml"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("versions")).unwrap();
        assert!(only_known_entries(dir.path()));
        std::fs::write(dir.path().join("notes.txt"), b"operator").unwrap();
        assert!(!only_known_entries(dir.path()));
    }

    /// A created home with one owned file, Agent runtime entries and an audit log,
    /// plus the journal that onboarding would have recorded for it.
    fn recorded_home() -> (tempfile::TempDir, Paths, Journal) {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().canonicalize().unwrap();
        let home = profile.join(".agentfw");
        std::fs::create_dir_all(home.join("grants")).unwrap();
        std::fs::create_dir_all(home.join(OWNED_DIR)).unwrap();
        std::fs::write(home.join("config.yaml"), b"enforce: true\n").unwrap();
        std::fs::write(home.join("grants/g1.json"), b"{}").unwrap();
        std::fs::write(home.join("audit.jsonl"), b"{\"event\":1}\n").unwrap();
        let mut journal = Journal {
            agent_home: home.to_string_lossy().into_owned(),
            created_home: true,
            inventory: inventory(&home),
            ..Journal::default()
        };
        journal.files.insert(
            "config".into(),
            sha256_file(&home.join("config.yaml")).unwrap(),
        );
        let paths = paths(&home).unwrap();
        (dir, paths, journal)
    }

    fn home_outcome(results: &[Value]) -> (String, String) {
        let line = results.iter().find(|r| r["step"] == "agent_home").unwrap();
        (
            line["outcome"].as_str().unwrap().into(),
            line["detail"].as_str().unwrap().into(),
        )
    }

    fn run_rollback(journal: &mut Journal, paths: &Paths, purge: bool) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(60);
        rollback(
            journal,
            Path::new("/nonexistent/agentfw"),
            paths,
            purge,
            deadline,
        )
    }

    #[test]
    fn rollback_preserves_foreign_files_inside_recognized_directories() {
        // The automatic rollback after a failed apply calls this with purge = false.
        let (_dir, paths, mut journal) = recorded_home();
        let home = PathBuf::from(&journal.agent_home);
        std::fs::write(home.join("grants/operator-notes.txt"), b"operator bytes").unwrap();
        std::fs::write(home.join(OWNED_DIR).join("operator.txt"), b"more").unwrap();
        let (outcome, detail) = home_outcome(&run_rollback(&mut journal, &paths, false));
        assert_eq!(outcome, "conflict");
        assert!(detail.starts_with("2 untracked"), "{detail}");
        assert!(!detail.contains(&*paths.profile.to_string_lossy()));
        assert_eq!(
            std::fs::read(home.join("grants/operator-notes.txt")).unwrap(),
            b"operator bytes"
        );
        assert_eq!(
            std::fs::read(home.join(OWNED_DIR).join("operator.txt")).unwrap(),
            b"more"
        );
        // Recorded entries were removed; the audit log is never purged implicitly.
        assert!(!home.join("grants/g1.json").exists());
        assert!(!home.join("config.yaml").exists());
        assert!(home.join("audit.jsonl").exists());
        assert!(journal.created_home);

        // An explicit purge still never deletes untracked bytes.
        let (outcome, _) = home_outcome(&run_rollback(&mut journal, &paths, true));
        assert_eq!(outcome, "conflict");
        assert!(home.join("grants/operator-notes.txt").exists());
        assert!(!home.join("audit.jsonl").exists());

        // Once the operator removes them, the created home is removed.
        std::fs::remove_file(home.join("grants/operator-notes.txt")).unwrap();
        std::fs::remove_file(home.join(OWNED_DIR).join("operator.txt")).unwrap();
        let (outcome, _) = home_outcome(&run_rollback(&mut journal, &paths, false));
        assert_eq!(outcome, "reversed");
        assert!(!home.exists());
    }

    #[test]
    fn rollback_preserves_changed_runtime_files_and_keeps_audit_without_purge() {
        let (_dir, paths, mut journal) = recorded_home();
        let home = PathBuf::from(&journal.agent_home);
        std::fs::write(home.join("grants/g1.json"), b"{\"changed\":true}").unwrap();
        let (outcome, detail) = home_outcome(&run_rollback(&mut journal, &paths, false));
        assert_eq!(outcome, "conflict");
        assert!(detail.starts_with("1 untracked or changed"), "{detail}");
        assert_eq!(
            std::fs::read(home.join("grants/g1.json")).unwrap(),
            b"{\"changed\":true}"
        );
        std::fs::remove_file(home.join("grants/g1.json")).unwrap();
        let (outcome, _) = home_outcome(&run_rollback(&mut journal, &paths, false));
        assert_eq!(outcome, "retained");
        assert_eq!(
            std::fs::read(home.join("audit.jsonl")).unwrap(),
            b"{\"event\":1}\n"
        );
        let (outcome, _) = home_outcome(&run_rollback(&mut journal, &paths, true));
        assert_eq!(outcome, "reversed");
        assert!(!home.exists());
    }

    #[test]
    fn inventory_does_not_follow_links() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("keep.txt"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();
        let recorded = inventory(&root);
        assert_eq!(recorded["link"].kind, "symlink");
        assert!(!recorded.contains_key("link/keep.txt"));
        let (preserved, _) = clean_recorded(&root, &recorded, true);
        assert!(preserved.is_empty());
        assert!(outside.path().join("keep.txt").exists());
    }

    #[test]
    fn state_cleanup_removes_only_own_files() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(STATE_DIR);
        std::fs::create_dir(&state).unwrap();
        std::fs::write(state.join(JOURNAL), b"{}").unwrap();
        std::fs::write(state.join("other.txt"), b"keep").unwrap();
        assert!(remove_state(&state).is_err());
        assert!(state.join("other.txt").exists());
        assert!(!state.join(JOURNAL).exists());
    }
}
