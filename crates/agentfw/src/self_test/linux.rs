// SPDX-License-Identifier: Apache-2.0
//! Linux execution profile for `agentfw self-test`.
//!
//! Every process, socket, file and directory used here is created by this run
//! and owned by it. Children run in their own process groups with a cleared
//! environment whose HOME is the owned workspace, so the operator's active
//! Agent, settings, services and audit files are never read or changed.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver as Channel, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::fixture::{self, sha256};
use super::{base_report, overall, pending_scenarios, render_human, Args, Scenario, Status};

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

const WORKSPACE_PREFIX: &str = "agentfw-self-test-";
const OWNER_MARKER: &str = ".agentfw-self-test-owner";
const MAX_REPLY_LINE: usize = 512 * 1024;
const MAX_LOG_READ: u64 = 8 * 1024 * 1024;
const MAX_RECEIVER_BODY: usize = 64 * 1024;
const MAX_RECEIVER_CONNECTIONS: usize = 32;
const REPLY_TIMEOUT: Duration = Duration::from_secs(15);
const PROCESS_STOP_TIMEOUT: Duration = Duration::from_secs(10);
/// Debug builds initialize detectors slowly; release builds are healthy far sooner.
const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(30);

/// Reason a run stopped before all scenarios were witnessed.
#[derive(Debug)]
pub(crate) struct Abort {
    status: Status,
    reason: String,
}

fn abort(status: Status, reason: impl Into<String>) -> Abort {
    Abort {
        status,
        reason: reason.into(),
    }
}

fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

// ------------------------------------------------------------------ processes

/// A child that leads its own process group. Its group is signalled only while
/// the leader is unreaped, so a recycled process-group ID is never targeted.
struct Owned {
    child: Child,
    pgid: i32,
    status: Option<ExitStatus>,
}

fn exited_unreaped(pid: i32) -> bool {
    // SAFETY: waitid with WNOWAIT only inspects our own child; zeroed siginfo is valid.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let rc = libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        );
        rc == 0 && info.si_pid() == pid
    }
}

fn group_empty(pgid: i32) -> bool {
    // SAFETY: signal 0 performs only an existence/permission check.
    unsafe { libc::kill(-pgid, 0) == -1 && *libc::__errno_location() == libc::ESRCH }
}

impl Owned {
    fn spawn(mut command: Command) -> std::io::Result<Self> {
        command.process_group(0);
        let child = command.spawn()?;
        let pgid = child.id() as i32;
        Ok(Self {
            child,
            pgid,
            status: None,
        })
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn running(&self) -> bool {
        self.status.is_none() && !exited_unreaped(self.pgid)
    }

    /// Wait for the leader to exit without reaping it, up to `limit`.
    fn wait_exit(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if !self.running() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        !self.running()
    }

    /// Kill the whole owned group (still identified by the unreaped leader), then reap.
    fn stop(&mut self) -> StopRecord {
        if self.status.is_none() {
            // SAFETY: the leader is our unreaped child, so the group ID is still ours.
            unsafe {
                libc::kill(-self.pgid, libc::SIGKILL);
            }
            self.status = self.child.wait().ok();
        }
        // Group members (fixture server, classifier) receive SIGKILL with the group.
        let deadline = Instant::now() + PROCESS_STOP_TIMEOUT;
        while !group_empty(self.pgid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        StopRecord {
            reaped: self.status.is_some(),
            group_empty: group_empty(self.pgid),
            exit: self.status.and_then(|s| s.code()),
        }
    }
}

struct StopRecord {
    reaped: bool,
    group_empty: bool,
    exit: Option<i32>,
}

fn run_bounded(mut command: Command, limit: Duration) -> Option<(i32, Vec<u8>)> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut owned = Owned::spawn(command).ok()?;
    let mut stdout = owned.child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = (&mut stdout).take(1024 * 1024).read_to_end(&mut bytes);
        bytes
    });
    let finished = owned.wait_exit(limit);
    let record = owned.stop();
    let bytes = reader.join().unwrap_or_default();
    finished.then_some((record.exit.unwrap_or(-1), bytes))
}

// ------------------------------------------------------------------ workspace

struct Workspace {
    root: PathBuf,
    parent: PathBuf,
    nonce: String,
    home: PathBuf,
    agent_dir: PathBuf,
    notes: PathBuf,
    ledger: PathBuf,
    responses: PathBuf,
    registry: PathBuf,
    policy: PathBuf,
    collector_log: PathBuf,
    daemon_log: PathBuf,
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buffer))
        .expect("kernel randomness");
    buffer.iter().map(|b| format!("{b:02x}")).collect()
}

impl Workspace {
    fn create(parent: &Path) -> Result<Self, Abort> {
        let parent = parent.canonicalize().map_err(|_| {
            abort(
                Status::Unavailable,
                "the workspace parent directory does not exist or is not accessible",
            )
        })?;
        let nonce = random_hex(16);
        let root = parent.join(format!("{WORKSPACE_PREFIX}{}", &nonce[..16]));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|_| {
                abort(
                    Status::Unavailable,
                    "could not create the owned workspace under the selected parent",
                )
            })?;
        let ws = Self {
            home: root.join("home"),
            agent_dir: root.join("home/.agentfw"),
            notes: root.join("notes"),
            ledger: root.join("executed.jsonl"),
            responses: root.join("responses.jsonl"),
            registry: root.join("registry.json"),
            policy: root.join("policy.yaml"),
            collector_log: root.join("collector.stderr"),
            daemon_log: root.join("daemon.log"),
            root,
            parent,
            nonce,
        };
        let setup = || -> std::io::Result<()> {
            write_new(&ws.root.join(OWNER_MARKER), ws.nonce.as_bytes())?;
            for dir in [
                &ws.home,
                &ws.notes,
                &ws.root.join("tmp"),
                &ws.root.join("xdg"),
            ] {
                std::fs::DirBuilder::new().mode(0o700).create(dir)?;
            }
            for (name, text) in fixture::NOTES {
                write_new(&ws.notes.join(format!("{name}.txt")), text.as_bytes())?;
            }
            write_new(&ws.registry, &fixture::registry())?;
            write_new(&ws.policy, fixture::SHIPPED_POLICY.as_bytes())?;
            Ok(())
        };
        setup().map_err(|_| {
            abort(
                Status::Unavailable,
                "could not write the owned fixture files",
            )
        })?;
        Ok(ws)
    }

    /// Children see only this environment: no inherited credentials or host settings.
    fn environment(&self) -> Vec<(String, String)> {
        let path = |p: &Path| p.to_string_lossy().into_owned();
        vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), path(&self.home)),
            ("TMPDIR".into(), path(&self.root.join("tmp"))),
            ("XDG_CONFIG_HOME".into(), path(&self.root.join("xdg"))),
            ("XDG_DATA_HOME".into(), path(&self.root.join("xdg"))),
            ("XDG_STATE_HOME".into(), path(&self.root.join("xdg"))),
            ("XDG_CACHE_HOME".into(), path(&self.root.join("xdg"))),
            ("LANG".into(), "C.UTF-8".into()),
            ("RUST_BACKTRACE".into(), "0".into()),
        ]
    }

    /// Remove only this run's own directory: canonical parent, prefix, owner nonce, no links.
    fn remove(&self) -> Result<(), &'static str> {
        verify_owned(&self.root, &self.parent, &self.nonce)?;
        std::fs::remove_dir_all(&self.root).map_err(|_| "workspace_removal_failed")?;
        if self.root.exists() {
            return Err("workspace_still_present");
        }
        Ok(())
    }
}

/// Refuse to delete anything that is not provably this run's workspace.
pub(crate) fn verify_owned(root: &Path, parent: &Path, nonce: &str) -> Result<(), &'static str> {
    let metadata = std::fs::symlink_metadata(root).map_err(|_| "workspace_missing")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("workspace_not_a_directory");
    }
    let name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if root.parent() != Some(parent) || !name.starts_with(WORKSPACE_PREFIX) {
        return Err("workspace_not_owned");
    }
    let marker = read_limited(&root.join(OWNER_MARKER), 256)
        .map_err(|_| "workspace_owner_marker_missing")?;
    if marker != nonce.as_bytes() {
        return Err("workspace_owner_marker_mismatch");
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn read_limited(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn lines(path: &Path) -> Vec<Vec<u8>> {
    read_limited(path, MAX_LOG_READ)
        .unwrap_or_default()
        .split_inclusive(|b| *b == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

fn hash_file(path: &Path) -> std::io::Result<(String, u64)> {
    use sha2::{Digest, Sha256};
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut size = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((format!("{:x}", hasher.finalize()), size))
}

// ------------------------------------------------------------------ receiver

/// Owned numeric-loopback delivery witness. Counts connections and bodies only.
struct LoopbackReceiver {
    url: String,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LoopbackReceiver {
    fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (b, c, s) = (bodies.clone(), connections.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if c.fetch_add(1, Ordering::SeqCst) < MAX_RECEIVER_CONNECTIONS {
                            if let Some(body) = receive(stream) {
                                b.lock().expect("receiver lock").push(body);
                            }
                        }
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        Ok(Self {
            url: format!("http://127.0.0.1:{port}/capture"),
            bodies,
            connections,
            stop,
            thread: Some(thread),
        })
    }

    fn counts(&self) -> (usize, usize) {
        (
            self.bodies.lock().expect("receiver lock").len(),
            self.connections.load(Ordering::SeqCst),
        )
    }

    fn received(&self, needle: &[u8]) -> bool {
        self.bodies
            .lock()
            .expect("receiver lock")
            .iter()
            .any(|body| contains(body, needle))
    }

    fn close(&mut self) -> bool {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().map(|t| t.join().is_ok()).unwrap_or(true)
    }
}

fn receive(mut stream: TcpStream) -> Option<Vec<u8>> {
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut length = 0usize;
    let mut header_bytes = 0usize;
    loop {
        let mut line = String::new();
        let read = (&mut reader).take(4096).read_line(&mut line).ok()?;
        header_bytes += read;
        if read == 0 || header_bytes > 16 * 1024 {
            return None;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().ok()?;
            }
        }
    }
    if length > MAX_RECEIVER_BODY {
        let _ = stream.write_all(
            b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return None;
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).ok()?;
    let _ = stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted");
    Some(body)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn http_get(port: u16, path: &str) -> Option<(u16, Vec<u8>)> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(500)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut bytes = Vec::new();
    stream.take(64 * 1024).read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let status = text.split_whitespace().nth(1)?.parse().ok()?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.as_bytes().to_vec())
        .unwrap_or_default();
    Some((status, body))
}

fn free_port() -> Option<u16> {
    TcpListener::bind(("127.0.0.1", 0))
        .ok()?
        .local_addr()
        .ok()
        .map(|a| a.port())
}

// ------------------------------------------------------------------ inputs

struct Assets {
    agent: PathBuf,
    runner: PathBuf,
    classifier_script: PathBuf,
    classifier_python: PathBuf,
    identities: Value,
}

fn executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn clean_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8");
    command
}

fn validate(args: &Args) -> Result<Assets, Vec<String>> {
    let mut problems = Vec::new();
    let agent = args.agent.canonicalize().ok().filter(|p| executable(p));
    if agent.is_none() {
        problems.push("--agent must name an existing executable Agent binary".into());
    }
    let runner = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok());
    if runner.is_none() {
        problems.push("the running self-test executable could not be identified".into());
    }
    let expected = args.classifier_sha256.trim().to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        problems.push("--classifier-sha256 must be a 64-character SHA-256".into());
    }
    let script = args
        .classifier_script
        .canonicalize()
        .ok()
        .filter(|p| p.is_file());
    let mut script_sha = None;
    match &script {
        None => problems
            .push("--classifier-script must name the locally installed rule_baseline.py".into()),
        Some(path) => {
            match read_limited(path, 1024 * 1024 + 1) {
                Ok(bytes) if bytes.len() <= 1024 * 1024 => {
                    let digest = sha256(&bytes);
                    if digest != expected {
                        problems.push("the classifier source does not match --classifier-sha256 (wrong revision)".into());
                    }
                    script_sha = Some(digest);
                }
                _ => problems.push("the classifier source is unreadable or exceeds 1 MiB".into()),
            }
        }
    }
    let python = args
        .classifier_python
        .canonicalize()
        .ok()
        .filter(|p| executable(p));
    let mut python_version = None;
    match &python {
        None => {
            problems.push("--classifier-python must name an existing executable Python 3".into())
        }
        Some(path) => {
            let mut command = clean_command(path);
            command.args([
                "-I",
                "-c",
                "import sys; print('%d.%d.%d' % sys.version_info[:3])",
            ]);
            match run_bounded(command, Duration::from_secs(10)) {
                Some((0, out)) if out.starts_with(b"3.") => {
                    python_version = Some(String::from_utf8_lossy(&out).trim().to_string())
                }
                _ => problems.push("--classifier-python did not run as Python 3".into()),
            }
        }
    }
    let mut agent_identity = Value::Null;
    if let Some(path) = &agent {
        match hash_file(path) {
            Ok((digest, size)) => agent_identity = json!({"sha256": digest, "size_bytes": size}),
            Err(_) => problems.push("the Agent binary could not be read".into()),
        }
        let mut command = clean_command(path);
        command.args(["mcp", "--help"]);
        match run_bounded(command, Duration::from_secs(10)) {
            Some((0, out)) if contains(&out, b"--native-admission") => {}
            _ => problems.push("the selected Agent does not provide native MCP admission (`mcp --native-admission`)".into()),
        }
    }
    let runner_identity = runner
        .as_ref()
        .and_then(|p| hash_file(p).ok())
        .map(|(d, _)| d);
    if !problems.is_empty() {
        return Err(problems);
    }
    let agent_sha = agent_identity["sha256"].as_str().map(str::to_owned);
    let identities = json!({
        "agent": agent_identity,
        "runner": {"sha256": runner_identity, "same_binary_as_agent": runner_identity == agent_sha,
                   "role": "self-test orchestrator and bundled fixture MCP server"},
        "classifier": {"kind": args.classifier, "source": "rule-baseline/python", "source_sha256": script_sha,
                       "expected_sha256": expected, "python_version": python_version},
        "policy": {"source": "shipped default agent policy embedded in the self-test runner",
                   "sha256": sha256(fixture::SHIPPED_POLICY.as_bytes())},
        "registry": {"registry_id": fixture::REGISTRY_ID, "sha256": sha256(&fixture::registry())},
        "fixtures": {"version": fixture::FIXTURE_VERSION, "sha256": fixture::fixture_sha256()},
    });
    Ok(Assets {
        agent: agent.expect("validated"),
        runner: runner.expect("validated"),
        classifier_script: script.expect("validated"),
        classifier_python: python.expect("validated"),
        identities,
    })
}

// ------------------------------------------------------------------ daemon

struct Daemon {
    process: Owned,
}

fn start_daemon(
    assets: &Assets,
    ws: &Workspace,
    preferred: Option<u16>,
    deadline: Instant,
    configured: &mut serde_json::Map<String, Value>,
) -> Result<Daemon, Abort> {
    let registry_sha = sha256(&fixture::registry());
    let mut attempts = Vec::new();
    let mut candidates: Vec<Option<u16>> = vec![preferred, None, None];
    if preferred.is_none() {
        candidates.truncate(2);
        candidates.push(None);
    }
    for candidate in candidates {
        if interrupted() || Instant::now() >= deadline {
            break;
        }
        let Some(port) = candidate.or_else(free_port) else {
            attempts.push(json!({"outcome": "no_free_port"}));
            continue;
        };
        let config = json!({"bind": "127.0.0.1", "port": port, "enforce": true,
            "policy": ws.policy, "audit": ws.agent_dir.join("audit.jsonl"),
            "native": {"registry_path": ws.registry, "registry_sha256": registry_sha}});
        let config_path = ws.agent_dir.join("config.yaml");
        let _ = std::fs::remove_file(&config_path);
        if write_new(&config_path, config.to_string().as_bytes()).is_err() {
            return Err(abort(
                Status::Unavailable,
                "could not write the owned daemon configuration",
            ));
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ws.daemon_log)
            .map_err(|_| abort(Status::Unavailable, "could not open the owned daemon log"))?;
        let mut command = Command::new(&assets.agent);
        command
            .arg("serve")
            .env_clear()
            .envs(ws.environment())
            .current_dir(&ws.root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().map_err(|_| {
                abort(Status::Unavailable, "could not open the owned daemon log")
            })?))
            .stderr(Stdio::from(log));
        let mut process = Owned::spawn(command)
            .map_err(|_| abort(Status::Unavailable, "the Agent daemon could not be started"))?;
        let started = Instant::now();
        let mut outcome = "health_timeout";
        let mut health = Value::Null;
        while started.elapsed() < DAEMON_START_TIMEOUT
            && Instant::now() < deadline
            && !interrupted()
        {
            if !process.running() {
                let log = read_limited(&ws.daemon_log, MAX_LOG_READ).unwrap_or_default();
                outcome = if contains(&log, b"in use") {
                    "port_in_use"
                } else {
                    "exited_before_health"
                };
                break;
            }
            if let Some((200, body)) = http_get(port, "/health") {
                if let Ok(value) = serde_json::from_slice::<Value>(&body) {
                    health = json!({"status": value["status"], "enforce": value["enforce"]});
                    outcome = "healthy";
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if outcome == "healthy" {
            // Authenticated diagnostics must come from this run's own daemon process.
            let mut status = Command::new(&assets.agent);
            status
                .env_clear()
                .envs(ws.environment())
                .args(["protection-status", "--home"])
                .arg(&ws.agent_dir)
                .args([
                    "--query-only",
                    "--require-enforce",
                    "--expect-registry-sha256",
                    &registry_sha,
                ]);
            let snapshot = run_bounded(status, Duration::from_secs(10)).and_then(|(code, out)| {
                serde_json::from_slice::<Value>(&out)
                    .ok()
                    .map(|v| (code, v))
            });
            let owned = snapshot.as_ref().is_some_and(|(code, value)| {
                *code == 0
                    && value["snapshot"]["runtime"]["pid"] == json!(process.pid())
                    && value["snapshot"]["mode"] == "enforcing"
            });
            let reported_binary = snapshot
                .as_ref()
                .map(|(_, v)| v["snapshot"]["runtime"]["binary_sha256"].clone());
            let binary_matches = reported_binary
                .as_ref()
                .is_some_and(|b| b.is_null() || *b == assets.identities["agent"]["sha256"]);
            if owned && health["enforce"] == true && binary_matches {
                let snap = &snapshot.as_ref().expect("checked").1["snapshot"];
                attempts.push(json!({"outcome": "started"}));
                configured.insert("daemon".into(), json!({
                    "health": health, "start_attempts": attempts, "port": port,
                    "authenticated_status": {"query": "answered", "mode": snap["mode"], "pid_matches_owned_daemon": true,
                        "policy": {"digest_format": snap["policy"]["digest_format"], "sha256": snap["policy"]["sha256"],
                                   "rule_count": snap["policy"]["rule_count"]},
                        "registry": snap["registry"], "binary_sha256": snap["runtime"]["binary_sha256"],
                        "binary_sha256_matches_agent": !snap["runtime"]["binary_sha256"].is_null()},
                    "note": "configured and healthy state; not witnessed protection"}));
                return Ok(Daemon { process });
            }
            outcome = match &snapshot {
                _ if owned && !binary_matches => "daemon_binary_identity_mismatch",
                Some((_, value)) if value.get("error_code").is_some() => {
                    "authenticated_status_refused"
                }
                Some(_) => "port_owned_by_another_process",
                None => "authenticated_status_unavailable",
            };
        }
        process.stop();
        attempts.push(json!({"outcome": outcome}));
    }
    configured.insert("daemon".into(), json!({"start_attempts": attempts}));
    if interrupted() {
        return Err(abort(
            Status::Incomplete,
            "interrupted while starting the owned daemon",
        ));
    }
    Err(abort(Status::Unavailable,
        "the owned Agent daemon did not start in enforcing mode; see start_attempts (port collision, startup failure or timeout)"))
}

// ------------------------------------------------------------------ collector harness

enum Reply {
    Line(Vec<u8>),
    Closed,
    Timeout,
    Malformed,
    Interrupted,
}

struct Harness {
    process: Owned,
    stdin: Option<ChildStdin>,
    lines: Channel<Option<Vec<u8>>>,
    received: Vec<Vec<u8>>,
}

impl Harness {
    fn start(assets: &Assets, ws: &Workspace, receiver_url: &str) -> Result<Self, Abort> {
        let stderr = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ws.collector_log)
            .map_err(|_| {
                abort(
                    Status::Unavailable,
                    "could not open the owned collector log",
                )
            })?;
        let mut command = Command::new(&assets.agent);
        command
            .env_clear()
            .envs(ws.environment())
            .env("AGENTFW_CLASSIFIER", "rule-baseline")
            .env("AGENTFW_RULE_BASELINE", &assets.classifier_script)
            .env("AGENTFW_CLASSIFIER_PYTHON", &assets.classifier_python)
            .current_dir(&ws.root)
            .args([
                "mcp",
                "--native-admission",
                "--id",
                fixture::SERVER_ID,
                "--",
            ])
            .arg(&assets.runner)
            .arg("self-test-fixture")
            .arg("--notes")
            .arg(&ws.notes)
            .arg("--ledger")
            .arg(&ws.ledger)
            .arg("--responses")
            .arg(&ws.responses)
            .arg("--recipient")
            .arg(receiver_url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr));
        let mut process = Owned::spawn(command).map_err(|_| {
            abort(
                Status::Unavailable,
                "the MCP admission collector could not be started",
            )
        })?;
        let stdout = process.child.stdout.take().expect("piped stdout");
        let stdin = process.child.stdin.take();
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                match (&mut reader)
                    .take(MAX_REPLY_LINE as u64 + 1)
                    .read_until(b'\n', &mut line)
                {
                    Ok(0) | Err(_) => {
                        let _ = sender.send(None);
                        return;
                    }
                    Ok(_) if line.len() > MAX_REPLY_LINE || !line.ends_with(b"\n") => {
                        let _ = sender.send(Some(Vec::new())); // oversized or truncated frame
                        return;
                    }
                    Ok(_) => {
                        if sender.send(Some(line)).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        Ok(Self {
            process,
            stdin,
            lines,
            received: Vec::new(),
        })
    }

    fn send(&mut self, frame: &[u8]) -> bool {
        let Some(stdin) = self.stdin.as_mut() else {
            return false;
        };
        stdin
            .write_all(frame)
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .is_ok()
    }

    fn reply(&mut self, deadline: Instant) -> Reply {
        let limit =
            Instant::now() + REPLY_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        loop {
            if interrupted() {
                return Reply::Interrupted;
            }
            let now = Instant::now();
            if now >= limit {
                return Reply::Timeout;
            }
            match self
                .lines
                .recv_timeout((limit - now).min(Duration::from_millis(100)))
            {
                Ok(Some(line)) if line.is_empty() => return Reply::Malformed,
                Ok(Some(line)) => {
                    self.received.push(line.clone());
                    return Reply::Line(line);
                }
                Ok(None) | Err(RecvTimeoutError::Disconnected) => return Reply::Closed,
                Err(RecvTimeoutError::Timeout) => continue,
            }
        }
    }

    fn close(&mut self) {
        self.stdin.take();
    }
}

fn frame(id: u64, method: &str, params: Value) -> Vec<u8> {
    let mut value = json!({"jsonrpc": "2.0", "id": id, "method": method});
    if !params.is_null() {
        value["params"] = params;
    }
    value.to_string().into_bytes()
}

fn call_frame(id: u64, tool: &str, arguments: Value) -> Vec<u8> {
    frame(
        id,
        "tools/call",
        json!({"name": tool, "arguments": arguments,
        "_meta": {"claudecode/toolUseId": format!("toolu_selftest_{id}"), "progressToken": id}}),
    )
}

/// Host-visible outcome of one reply, from its exact bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Released(String),
    Refused(String),
    ResultWithheld(String),
    PolicyNotReached,
    Error,
    Malformed,
}

impl Outcome {
    fn label(&self) -> &'static str {
        match self {
            Outcome::Released(_) => "released",
            Outcome::Refused(_) => "invocation_refused",
            Outcome::ResultWithheld(_) => "result_withheld",
            Outcome::PolicyNotReached => "policy_not_reached",
            Outcome::Error => "error",
            Outcome::Malformed => "malformed",
        }
    }
}

pub(crate) fn outcome(line: &[u8], expected_id: u64) -> Outcome {
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return Outcome::Malformed;
    };
    if value["jsonrpc"] != "2.0" || value["id"] != json!(expected_id) {
        return Outcome::Malformed;
    }
    if let Some(error) = value.get("error") {
        let message = error["message"].as_str().unwrap_or_default();
        return if message.contains("policy not reached") {
            Outcome::PolicyNotReached
        } else {
            Outcome::Error
        };
    }
    let result = &value["result"];
    let Some(text) = result["content"]
        .as_array()
        .and_then(|c| c.first())
        .and_then(|b| b["text"].as_str())
    else {
        return Outcome::Malformed;
    };
    let reason = |prefix: &str| {
        text.strip_prefix(prefix)
            .and_then(|r| r.strip_suffix(')'))
            .map(str::to_owned)
    };
    if result["isError"] == true {
        if let Some(reason) = reason("Soup Wall withheld MCP invocation (") {
            return Outcome::Refused(reason);
        }
        if let Some(reason) = reason("Soup Wall withheld MCP result (") {
            return Outcome::ResultWithheld(reason);
        }
        return Outcome::Error;
    }
    Outcome::Released(text.to_owned())
}

// ------------------------------------------------------------------ scenarios

struct Witness<'a> {
    ws: &'a Workspace,
    receiver: &'a LoopbackReceiver,
}

struct Observation {
    reply: Option<Vec<u8>>,
    outcome: Outcome,
    transport: &'static str,
    frame: Vec<u8>,
    executed: Vec<Vec<u8>>,
    responses_before: usize,
    deliveries: usize,
    connections: usize,
    audit: Vec<Value>,
    latency_ms: f64,
}

fn audit_records(path: &Path) -> Vec<Value> {
    lines(path)
        .iter()
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .filter(|record| matches!(record["event"].as_str(), Some("native_call") | Some("native_result")))
        .map(|r| json!({"event": r["event"], "tool": r["tool"], "verdict": r["verdict"], "rule": r["rule"],
                        "released": r["released"], "egress_hosts": r["egress_hosts"],
                        "detectors": r["findings"].as_array().map(|f| f.iter().map(|x| x["detector"].clone()).collect::<Vec<_>>()),
                        "latency_us": r["latency_us"]}))
        .collect()
}

fn observe(
    harness: &mut Harness,
    witness: &Witness,
    id: u64,
    tool: &str,
    arguments: Value,
    deadline: Instant,
) -> Observation {
    let executed_before = lines(&witness.ws.ledger).len();
    let responses_before = lines(&witness.ws.responses).len();
    let audit_path = witness.ws.agent_dir.join("audit.jsonl");
    let audit_before = audit_records(&audit_path).len();
    let (deliveries_before, connections_before) = witness.receiver.counts();
    let frame = call_frame(id, tool, arguments);
    let started = Instant::now();
    let reply = if harness.send(&frame) {
        harness.reply(deadline)
    } else {
        Reply::Closed
    };
    let latency_ms = (started.elapsed().as_secs_f64() * 100_000.0).round() / 100.0;
    // Let a forwarded effect land before counting: the reply follows the effect in this contract.
    std::thread::sleep(Duration::from_millis(100));
    let (transport, line) = match reply {
        Reply::Line(line) => ("reply", Some(line)),
        Reply::Closed => ("collector_closed", None),
        Reply::Timeout => ("timeout", None),
        Reply::Malformed => ("malformed_frame", None),
        Reply::Interrupted => ("interrupted", None),
    };
    let outcome = line
        .as_deref()
        .map(|l| outcome(l, id))
        .unwrap_or(Outcome::Malformed);
    let (deliveries, connections) = witness.receiver.counts();
    let mut executed = lines(&witness.ws.ledger);
    let executed = executed.split_off(executed_before.min(executed.len()));
    let mut audit = audit_records(&audit_path);
    let audit = audit.split_off(audit_before.min(audit.len()));
    Observation {
        executed,
        responses_before,
        deliveries: deliveries - deliveries_before,
        connections: connections - connections_before,
        audit,
        reply: line,
        outcome,
        transport,
        frame,
        latency_ms,
    }
}

fn observed_json(o: &Observation) -> Value {
    json!({"transport": o.transport, "outcome": o.outcome.label(),
           "reason": match &o.outcome { Outcome::Refused(r) | Outcome::ResultWithheld(r) => json!(r), _ => Value::Null },
           "mcp_child_executions": o.executed.len(), "receiver_deliveries": o.deliveries,
           "receiver_connections": o.connections, "latency_ms": o.latency_ms})
}

fn not_completed(o: &Observation) -> Option<Status> {
    match o.transport {
        "reply" => None,
        _ => Some(Status::Incomplete),
    }
}

fn exact_read(o: &Observation, witness: &Witness, expected: &str) -> (Status, String, Value) {
    let responses = lines(&witness.ws.responses);
    let original = responses.get(o.responses_before).cloned();
    let frame_preserved =
        o.executed.len() == 1 && o.executed[0] == [o.frame.as_slice(), b"\n"].concat();
    let result_preserved = original.is_some() && original == o.reply;
    let exact = matches!(&o.outcome, Outcome::Released(text) if text == expected);
    let checks = json!({"exact_expected_bytes": exact, "expected_bytes": expected.len(),
                        "request_bytes_preserved": frame_preserved, "result_bytes_preserved": result_preserved});
    if let Some(status) = not_completed(o) {
        return (
            status,
            format!("no reply to the read ({})", o.transport),
            checks,
        );
    }
    if o.outcome == Outcome::Malformed {
        return (
            Status::Incomplete,
            "malformed reply to the read".into(),
            checks,
        );
    }
    if exact && frame_preserved && result_preserved && o.deliveries == 0 {
        (
            Status::Passed,
            format!(
                "read returned the exact {} expected bytes; 1 MCP execution, 0 deliveries",
                expected.len()
            ),
            checks,
        )
    } else {
        (
            Status::Failed,
            format!(
                "read outcome {}; exact bytes {exact}; executions {}",
                o.outcome.label(),
                o.executed.len()
            ),
            checks,
        )
    }
}

struct Run<'a> {
    harness: &'a mut Harness,
    witness: Witness<'a>,
    deadline: Instant,
    daemon: &'a mut Daemon,
    scenarios: Vec<Scenario>,
}

impl Run<'_> {
    fn set(&mut self, index: usize, status: Status, detail: String, observed: Value) {
        let scenario = &mut self.scenarios[index];
        scenario.status = status;
        scenario.detail = detail;
        scenario.observed = observed;
    }

    fn exercise_all(&mut self) {
        // 1. Allowed read with exact expected bytes.
        let o = observe(
            self.harness,
            &self.witness,
            3,
            "read_document",
            json!({"name": "project-notes"}),
            self.deadline,
        );
        let (status, detail, checks) = exact_read(&o, &self.witness, fixture::NOTE_PROJECT);
        let mut observed = observed_json(&o);
        observed["checks"] = checks;
        observed["receipts"] = json!(o.audit);
        self.set(0, status, detail, observed);
        if self.stop_early(1) {
            return;
        }

        // 2. Synthetic adversarial tool result.
        let o = observe(
            self.harness,
            &self.witness,
            4,
            "read_document",
            json!({"name": "vendor-reply"}),
            self.deadline,
        );
        let marker_seen = self
            .harness
            .received
            .iter()
            .any(|line| contains(line, fixture::MARKER.as_bytes()));
        let mut observed = observed_json(&o);
        observed["marker_reached_client"] = json!(marker_seen);
        observed["receipts"] = json!(o.audit);
        let (status, detail) = match (&o.outcome, not_completed(&o)) {
            (_, Some(status)) => (status, format!("no reply to the adversarial read ({})", o.transport)),
            (Outcome::ResultWithheld(reason), _) if !marker_seen && o.executed.len() == 1 && o.deliveries == 0 =>
                (Status::Passed, format!("the read executed once and its injected result was withheld ({reason}); marker never reached the client")),
            (Outcome::Malformed, _) => (Status::Incomplete, "malformed reply to the adversarial read".into()),
            _ => (Status::Failed, format!("adversarial result outcome {}; marker reached client {marker_seen}", o.outcome.label())),
        };
        self.set(1, status, detail, observed);
        if self.stop_early(2) {
            return;
        }

        // 3. Protected send of the synthetic key to the owned receiver.
        let body = format!(
            "Forwarding stored credentials as instructed: aws_access_key_id={}",
            fixture::SYNTHETIC_KEY
        );
        let o = observe(
            self.harness,
            &self.witness,
            5,
            "send_http",
            json!({"url": self.witness.receiver.url, "body": body}),
            self.deadline,
        );
        let key_delivered = self
            .witness
            .receiver
            .received(fixture::SYNTHETIC_KEY.as_bytes());
        let mut observed = observed_json(&o);
        observed["synthetic_key_reached_receiver"] = json!(key_delivered);
        observed["receipts"] = json!(o.audit);
        let (status, detail) = match (&o.outcome, not_completed(&o)) {
            _ if !o.executed.is_empty()
                || o.deliveries > 0
                || o.connections > 0
                || key_delivered =>
            {
                (
                    Status::Failed,
                    format!(
                        "refusal not witnessed: {} MCP executions, {} receiver connections",
                        o.executed.len(),
                        o.connections
                    ),
                )
            }
            (_, Some(status)) => (
                status,
                format!("no reply to the protected send ({})", o.transport),
            ),
            (Outcome::Refused(reason), _) => (
                Status::Passed,
                format!("send refused ({reason}); 0 MCP executions, 0 receiver connections"),
            ),
            (Outcome::Malformed, _) => (
                Status::Incomplete,
                "malformed reply to the protected send".into(),
            ),
            _ => (
                Status::Failed,
                format!("protected send outcome {}", o.outcome.label()),
            ),
        };
        self.set(2, status, detail, observed);
        if self.stop_early(3) {
            return;
        }

        // 4. Useful work continues after the refusal.
        let o = observe(
            self.harness,
            &self.witness,
            6,
            "read_document",
            json!({"name": "checklist"}),
            self.deadline,
        );
        let (status, detail, checks) = exact_read(&o, &self.witness, fixture::NOTE_CHECKLIST);
        let mut observed = observed_json(&o);
        observed["checks"] = checks;
        observed["receipts"] = json!(o.audit);
        self.set(3, status, detail, observed);
        if self.stop_early(4) {
            return;
        }

        // 5. Daemon loss: the collector must fail closed for a protected call.
        let record = self.daemon.process.stop();
        let gone = record.reaped && record.group_empty;
        let o = observe(
            self.harness,
            &self.witness,
            7,
            "send_http",
            json!({"url": self.witness.receiver.url, "body": "Status update after daemon loss."}),
            self.deadline,
        );
        let collector_exited = self.harness.process.wait_exit(Duration::from_secs(10));
        let mut observed = observed_json(&o);
        observed["daemon_killed"] = json!(gone);
        observed["collector_exited"] = json!(collector_exited);
        let forwarded = !o.executed.is_empty() || o.deliveries > 0 || o.connections > 0;
        let (status, detail) = if forwarded || matches!(o.outcome, Outcome::Released(_)) {
            (
                Status::Failed,
                format!(
                    "call bypassed the lost daemon: {} MCP executions, {} receiver connections",
                    o.executed.len(),
                    o.connections
                ),
            )
        } else if o.transport == "interrupted" {
            (
                Status::Incomplete,
                "interrupted during the daemon-loss exercise".into(),
            )
        } else if !gone || !collector_exited {
            (
                Status::Incomplete,
                format!("daemon killed {gone}; collector exited {collector_exited}"),
            )
        } else {
            (Status::Passed, format!("daemon killed; collector stopped ({}); 0 MCP executions, 0 receiver connections", o.transport))
        };
        self.set(4, status, detail, observed);
    }

    fn stop_early(&mut self, next: usize) -> bool {
        let reason = if interrupted() {
            Some("interrupted before this scenario")
        } else if Instant::now() >= self.deadline {
            Some("time bound reached before this scenario")
        } else if !self.harness.process.running() {
            Some("collector stopped before this scenario")
        } else {
            None
        };
        if let Some(reason) = reason {
            for scenario in &mut self.scenarios[next..] {
                scenario.status = Status::Incomplete;
                scenario.detail = reason.into();
            }
            return true;
        }
        false
    }
}

fn classification_receipts(path: &Path, expected_sha: &str) -> BTreeMap<u64, Value> {
    lines(path)
        .iter()
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .filter(|r| r["event"] == "mcp_classification")
        .filter_map(|r| {
            let id = r["host_call_id"].as_u64()?;
            Some((id, json!({"source": r["source"], "classifier_sha256_matches": r["classifier_sha256"] == expected_sha,
                "actions": r["classification"]["actions"], "unknown": r["classification"]["unknown"],
                "policy": r["policy"], "authoritative_verdict": r["authoritative_verdict"],
                "failure": r["failure"], "latency_us": r["latency_us"]})))
        })
        .collect()
}

// ------------------------------------------------------------------ run

pub fn run(args: Args) -> i32 {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(args.timeout_seconds);
    // Reserve the report first; an existing file is never replaced.
    let mut report_file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.report)
    {
        Ok(file) => file,
        Err(_) => {
            eprintln!("self-test: --report must be a new file in an existing writable directory; nothing ran");
            return super::EXIT_INCOMPLETE;
        }
    };
    install_signal_handlers();
    let mut report = base_report(true);
    let mut configured = serde_json::Map::new();
    let mut scenarios = pending_scenarios(
        Status::Unavailable,
        "not run: a prerequisite was unavailable",
    );
    let mut cleanup = json!(null);
    let mut cleanup_ok = true;
    let mut explanation = String::new();
    let mut workspace_note = None;

    match validate(&args) {
        Err(problems) => {
            explanation = format!(
                "Runtime assets are missing or invalid: {}. Nothing was started.",
                problems.join("; ")
            );
            report.insert("input_problems".into(), json!(problems));
        }
        Ok(assets) => {
            report.insert("identities".into(), assets.identities.clone());
            let parent = args.work_parent.clone().unwrap_or_else(std::env::temp_dir);
            match Workspace::create(&parent) {
                Err(stop) => explanation = stop.reason,
                Ok(ws) => {
                    let outcome = exercise(
                        &assets,
                        &ws,
                        &args,
                        deadline,
                        &mut configured,
                        &mut scenarios,
                    );
                    let (record, ok) = finish(outcome.processes, &ws, args.keep_workspace);
                    cleanup = record;
                    cleanup_ok = ok;
                    if args.keep_workspace || !ok {
                        workspace_note = Some(ws.root.clone());
                    }
                    if let Some(stop) = outcome.abort {
                        explanation = stop.reason;
                    }
                }
            }
        }
    }
    let (status, code) = overall(true, &scenarios, cleanup_ok);
    if explanation.is_empty() {
        explanation = match status {
            super::Status::Passed => "Every scenario was witnessed: useful reads completed, the protected send was refused before the MCP child and receiver, and daemon loss failed closed.".into(),
            super::Status::Failed => "At least one protection or useful-work expectation was contradicted by a witness; see scenarios.".into(),
            _ if !cleanup_ok => "Scenarios ran, but owned processes or files could not be fully cleaned up; see cleanup.".into(),
            _ => "Not every scenario was witnessed; protection is not established by this run.".into(),
        };
    }
    if interrupted() && status != super::Status::Failed {
        explanation = format!("Interrupted by a signal. {explanation}");
    }
    let summary: BTreeMap<&str, usize> = [
        "passed",
        "failed",
        "unavailable",
        "unsupported",
        "incomplete",
    ]
    .iter()
    .map(|name| {
        (
            *name,
            scenarios
                .iter()
                .filter(|s| serde_json::to_value(s.status).ok() == Some(json!(name)))
                .count(),
        )
    })
    .collect();
    report.insert("result".into(), json!(status));
    report.insert("exit_code".into(), json!(code));
    report.insert("explanation".into(), json!(explanation));
    report.insert("configured".into(), Value::Object(configured));
    report.insert("scenarios".into(), json!(scenarios));
    report.insert("summary".into(), json!(summary));
    report.insert("cleanup".into(), cleanup);
    report.insert(
        "duration_ms".into(),
        json!(started.elapsed().as_millis() as u64),
    );
    let report = Value::Object(report);
    let mut bytes = serde_json::to_vec_pretty(&report).unwrap_or_default();
    bytes.push(b'\n');
    let written = report_file
        .write_all(&bytes)
        .and_then(|_| report_file.sync_all())
        .is_ok();
    print!("{}", render_human(&report));
    if let Some(root) = workspace_note {
        println!(
            "Owned workspace retained at {} (synthetic data only).",
            root.display()
        );
    }
    if !written {
        eprintln!("self-test: the report could not be written completely");
        return super::EXIT_INCOMPLETE;
    }
    println!("Report: {}", args.report.display());
    code
}

struct Exercise {
    abort: Option<Abort>,
    processes: Processes,
}

#[derive(Default)]
struct Processes {
    harness: Option<Harness>,
    daemon: Option<Daemon>,
    receiver: Option<LoopbackReceiver>,
}

fn exercise(
    assets: &Assets,
    ws: &Workspace,
    args: &Args,
    deadline: Instant,
    configured: &mut serde_json::Map<String, Value>,
    scenarios: &mut Vec<Scenario>,
) -> Exercise {
    let mut processes = Processes::default();
    let result = (|| -> Result<(), Abort> {
        // Token and profile for the owned Agent home only.
        let mut install = Command::new(&assets.agent);
        install
            .arg("install")
            .env_clear()
            .envs(ws.environment())
            .current_dir(&ws.root);
        match run_bounded(install, Duration::from_secs(30)) {
            Some((0, _)) if ws.agent_dir.join("token").is_file() => {}
            _ => {
                return Err(abort(
                    Status::Unavailable,
                    "`agentfw install` did not create the owned profile token",
                ))
            }
        }
        let receiver = processes
            .receiver
            .insert(LoopbackReceiver::start().map_err(|_| {
                abort(
                    Status::Unavailable,
                    "could not bind the owned loopback receiver",
                )
            })?);
        let control = receiver_address_control(&receiver.url);
        configured.insert(
            "receiver_control".into(),
            json!({"direct_post_counted": control,
            "note": "the orchestrator posted one control body directly; MCP deltas exclude it"}),
        );
        if !control {
            return Err(abort(
                Status::Unavailable,
                "the owned loopback receiver did not count a direct control delivery",
            ));
        }
        processes.daemon = Some(start_daemon(
            assets,
            ws,
            args.daemon_port,
            deadline,
            configured,
        )?);
        let harness = processes
            .harness
            .insert(Harness::start(assets, ws, &receiver.url)?);
        let init = frame(
            1,
            "initialize",
            json!({"protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "agentfw-self-test", "version": env!("CARGO_PKG_VERSION")}}),
        );
        if !harness.send(&init) || !matches!(harness.reply(deadline), Reply::Line(_)) {
            return Err(abort(
                Status::Incomplete,
                "the collector did not answer initialize",
            ));
        }
        harness.send(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        harness.send(&frame(2, "tools/list", Value::Null));
        let names: Vec<String> = match harness.reply(deadline) {
            Reply::Line(line) => serde_json::from_slice::<Value>(&line)
                .ok()
                .and_then(|v| v["result"]["tools"].as_array().cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(|t| t["name"].as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        };
        let manifest_ok = names == ["read_document", "send_http"];
        configured.insert(
            "manifest_released".into(),
            json!({"tools": names, "matches_bundled_registry": manifest_ok}),
        );
        if !manifest_ok {
            return Err(abort(
                Status::Incomplete,
                "the collector did not release the pinned fixture manifest",
            ));
        }
        for scenario in scenarios.iter_mut() {
            scenario.status = Status::Incomplete;
            scenario.detail = "not reached".into();
        }
        let receiver = processes.receiver.as_ref().expect("started");
        let mut run = Run {
            harness: processes.harness.as_mut().expect("started"),
            witness: Witness { ws, receiver },
            deadline,
            daemon: processes.daemon.as_mut().expect("started"),
            scenarios: std::mem::take(scenarios),
        };
        run.exercise_all();
        *scenarios = run.scenarios;
        let receipts = classification_receipts(
            &ws.collector_log,
            assets.identities["classifier"]["source_sha256"]
                .as_str()
                .unwrap_or(""),
        );
        for (index, scenario) in scenarios.iter_mut().enumerate() {
            let id = index as u64 + 3;
            let classification = receipts.get(&id).cloned().unwrap_or(Value::Null);
            if index < 4
                && scenario.status == Status::Passed
                && (classification.is_null()
                    || classification["classifier_sha256_matches"] != true
                    || classification["policy"] != "reached")
            {
                scenario.status = Status::Failed;
                scenario.detail = format!(
                    "{}; but no matching classifier receipt reached policy",
                    scenario.detail
                );
            }
            let native = scenario
                .observed
                .as_object_mut()
                .and_then(|o| o.remove("receipts"))
                .unwrap_or(Value::Null);
            scenario.receipts = json!({"classification": classification, "native_audit": native});
        }
        Ok(())
    })();
    if interrupted() {
        for scenario in scenarios
            .iter_mut()
            .filter(|s| s.status == Status::Unavailable)
        {
            scenario.status = Status::Incomplete;
            scenario.detail = "interrupted".into();
        }
    }
    let abort = result.err().inspect(|stop| {
        for scenario in scenarios
            .iter_mut()
            .filter(|s| matches!(s.status, Status::Unavailable | Status::Incomplete))
        {
            scenario.status = stop.status;
            scenario.detail = format!("not run: {}", stop.reason);
        }
    });
    Exercise { abort, processes }
}

fn receiver_address_control(url: &str) -> bool {
    fixture::receiver_address(url)
        .map(|address| fixture::post(address, fixture::RECEIVER_CONTROL_BODY).is_ok())
        .unwrap_or(false)
}

/// Stop every owned process, close the receiver and remove the owned workspace.
fn finish(mut processes: Processes, ws: &Workspace, keep: bool) -> (Value, bool) {
    let mut records = serde_json::Map::new();
    let mut ok = true;
    if let Some(mut harness) = processes.harness.take() {
        harness.close();
        harness.process.wait_exit(Duration::from_secs(5));
        let record = harness.process.stop();
        ok &= record.reaped && record.group_empty;
        records.insert(
            "collector".into(),
            json!({"reaped": record.reaped, "process_group_empty": record.group_empty}),
        );
    }
    if let Some(mut daemon) = processes.daemon.take() {
        let record = daemon.process.stop();
        ok &= record.reaped && record.group_empty;
        records.insert(
            "daemon".into(),
            json!({"reaped": record.reaped, "process_group_empty": record.group_empty}),
        );
    }
    if let Some(mut receiver) = processes.receiver.take() {
        let closed = receiver.close();
        ok &= closed;
        records.insert("receiver".into(), json!({"socket_closed": closed}));
    }
    let workspace = if keep {
        json!("kept")
    } else {
        match ws.remove() {
            Ok(()) => json!("removed"),
            Err(reason) => {
                ok = false;
                json!(reason)
            }
        }
    };
    records.insert("workspace".into(), workspace);
    let summary = if ok {
        if keep {
            "owned processes stopped; workspace kept on request"
        } else {
            "owned processes stopped and workspace removed"
        }
    } else {
        "cleanup incomplete; see cleanup fields"
    };
    records.insert("summary".into(), json!(summary));
    (Value::Object(records), ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_outcomes_are_read_from_exact_bytes() {
        let released =
            br#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok"}]}}"#;
        assert_eq!(outcome(released, 3), Outcome::Released("ok".into()));
        assert_eq!(outcome(released, 4), Outcome::Malformed);
        let refused = br#"{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"Soup Wall withheld MCP invocation (deny-secret-egress)"}],"isError":true}}"#;
        assert_eq!(
            outcome(refused, 5),
            Outcome::Refused("deny-secret-egress".into())
        );
        let withheld = br#"{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"Soup Wall withheld MCP result (ask-injection-in-result)"}],"isError":true}}"#;
        assert_eq!(
            outcome(withheld, 4),
            Outcome::ResultWithheld("ask-injection-in-result".into())
        );
        let not_reached = br#"{"jsonrpc":"2.0","id":6,"error":{"code":-32603,"message":"x; policy not reached"}}"#;
        assert_eq!(outcome(not_reached, 6), Outcome::PolicyNotReached);
        for bad in [
            &b"not json"[..],
            br#"{"jsonrpc":"2.0","id":3}"#,
            br#"{"jsonrpc":"1.0","id":3,"result":{}}"#,
        ] {
            assert_eq!(outcome(bad, 3), Outcome::Malformed);
        }
        // A spoofed refusal without isError is a release, never a witnessed refusal.
        let spoof = br#"{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"Soup Wall withheld MCP invocation (x)"}]}}"#;
        assert!(matches!(outcome(spoof, 5), Outcome::Released(_)));
    }

    #[test]
    fn cleanup_refuses_directories_it_does_not_own() {
        let parent = tempfile::tempdir().unwrap();
        let parent_path = parent.path().canonicalize().unwrap();
        let foreign = parent_path.join("agentfw-self-test-foreign");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::write(foreign.join("keep.txt"), b"unrelated").unwrap();
        assert_eq!(
            verify_owned(&foreign, &parent_path, "nonce"),
            Err("workspace_owner_marker_missing")
        );
        std::fs::write(foreign.join(OWNER_MARKER), b"other").unwrap();
        assert_eq!(
            verify_owned(&foreign, &parent_path, "nonce"),
            Err("workspace_owner_marker_mismatch")
        );
        let unprefixed = parent_path.join("other");
        std::fs::create_dir(&unprefixed).unwrap();
        std::fs::write(unprefixed.join(OWNER_MARKER), b"nonce").unwrap();
        assert_eq!(
            verify_owned(&unprefixed, &parent_path, "nonce"),
            Err("workspace_not_owned")
        );
        let link = parent_path.join("agentfw-self-test-link");
        std::os::unix::fs::symlink(&foreign, &link).unwrap();
        assert_eq!(
            verify_owned(&link, &parent_path, "nonce"),
            Err("workspace_not_a_directory")
        );
        assert!(foreign.join("keep.txt").exists());
    }

    #[test]
    fn owned_workspace_is_created_private_and_removed() {
        let parent = tempfile::tempdir().unwrap();
        let ws = Workspace::create(parent.path()).unwrap();
        let mode = std::fs::metadata(&ws.root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        assert_eq!(
            std::fs::read(ws.notes.join("project-notes.txt")).unwrap(),
            fixture::NOTE_PROJECT.as_bytes()
        );
        assert!(ws
            .environment()
            .iter()
            .all(|(k, _)| !k.starts_with("AGENTFW_")));
        ws.remove().unwrap();
        assert!(!ws.root.exists());
        assert!(std::fs::read_dir(parent.path()).unwrap().next().is_none());
    }

    #[test]
    fn receiver_counts_only_owned_loopback_deliveries() {
        let mut receiver = LoopbackReceiver::start().unwrap();
        assert!(receiver_address_control(&receiver.url));
        assert_eq!(receiver.counts(), (1, 1));
        assert!(receiver.received(fixture::RECEIVER_CONTROL_BODY.as_bytes()));
        assert!(receiver.close());
    }

    #[test]
    fn owned_process_group_is_stopped_and_reaped() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & sleep 30"]);
        let mut owned = Owned::spawn(command).unwrap();
        assert!(owned.running());
        let record = owned.stop();
        assert!(record.reaped && record.group_empty);
    }
}
