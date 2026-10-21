// SPDX-License-Identifier: Apache-2.0
//! Bounded persistent worker behind `InvocationClassifier`.
//!
//! One Python process per collector classifier, started from the verified installed
//! package. Every request is a single framed line bound to an id and to the SHA-256
//! of the exact semantic-input bytes; the reply must echo both. Any failure
//! (timeout, malformed or oversized frame, id/digest mismatch, exit, technical
//! error) retires the process; the call fails closed and the next call starts a fresh
//! verified process. Late frames of a retired process can never reach a later call
//! because each process owns its own channels.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context};
use serde::{Deserialize, Serialize};

use super::package::{sha, Store, Verified, WORKER_PROTOCOL};
#[cfg(windows)]
use super::platform_windows as platform;
use crate::mcp::admission::{
    parse_classifier_reply, Classification, Invocation, InvocationClassifier,
};

pub const MAX_INPUT: usize = 1024 * 1024;
const MAX_REPLY_FRAME: usize = 64 * 1024;
/// Must stay below the collector's outer two-second classification timeout.
pub const REQUEST_DEADLINE: Duration = Duration::from_millis(1400);
const START_DEADLINE: Duration = Duration::from_millis(1400);

// Verifies the exact bytes of the installed files (one read each), executes the
// classifier unchanged under a non-main module name, then hands control to the framing
// loop. Nothing is imported from the package directory.
//
// Platform neutral on purpose: the files are opened as raw bytes (O_BINARY exists only
// on Windows, where the CRT would otherwise translate line endings and stop at Ctrl-Z)
// and the reply stream is fixed to UTF-8 with bare "\n" frames, so the bytes the worker
// writes are identical on every platform and independent of the console code page.
const WORKER_BOOTSTRAP: &str = r#"import hashlib, os, sys
sys.stdout.reconfigure(encoding="utf-8", newline="\n")
directory, classifier_sha, worker_sha = sys.argv[1:]
def load(name, expected):
    fd = os.open(os.path.join(directory, name), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit(78)
    return compile(data, name, "exec")
classifier = load("rule_baseline.py", classifier_sha)
worker = load("worker.py", worker_sha)
space = {"__name__": "rule_baseline_worker", "__file__": "rule_baseline.py"}
exec(classifier, space)
frame = {"__name__": "rule_baseline_framing"}
exec(worker, frame)
sys.exit(frame["run"](space, classifier_sha))
"#;

#[derive(Serialize)]
struct Request<'a> {
    v: &'static str,
    id: u64,
    input_sha256: &'a str,
    input_json: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    v: String,
    ready: bool,
    classifier_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    v: String,
    id: u64,
    input_sha256: String,
    result_json: String,
}

struct Worker {
    child: Child,
    to_worker: SyncSender<Vec<u8>>,
    from_worker: Receiver<Result<Vec<u8>, String>>,
    next_id: u64,
    /// Owns the worker and everything it starts (Windows Job Object).
    #[cfg(windows)]
    tree: platform::JobTree,
    /// Counts retirements whose job could not be proven empty.
    #[cfg(windows)]
    unclean: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        #[cfg(windows)]
        self.tree.terminate();
        let _ = self.child.kill();
        let _ = self.child.wait();
        #[cfg(windows)]
        if !self.tree.wait_empty(Duration::from_secs(2)) {
            self.unclean
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

fn read_frame<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    loop {
        let (done, used) = {
            let available = reader.fill_buf().map_err(|e| e.to_string())?;
            if available.is_empty() {
                return if line.is_empty() {
                    Ok(None)
                } else {
                    Err("truncated frame".into())
                };
            }
            match available.iter().position(|b| *b == b'\n') {
                Some(i) => {
                    line.extend_from_slice(&available[..i]);
                    (true, i + 1)
                }
                None => {
                    line.extend_from_slice(available);
                    (false, available.len())
                }
            }
        };
        reader.consume(used);
        if line.len() > MAX_REPLY_FRAME {
            return Err("oversized frame".into());
        }
        if done {
            return Ok(Some(line));
        }
    }
}

pub struct PackagedClassifier {
    store: Store,
    package: String,
    classifier_sha256: String,
    state: Mutex<Option<Worker>>,
    deadline: Duration,
    /// Number of worker processes started (identity/latency evidence and tests).
    starts: std::sync::atomic::AtomicU64,
    /// Retired workers whose process tree could not be proven empty (always 0 when sound).
    #[cfg(windows)]
    unclean: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl PackagedClassifier {
    pub fn from_home(home: &std::path::Path) -> anyhow::Result<Self> {
        let store = Store::new(home);
        let verified = store.current()?;
        Ok(Self {
            package: verified.id,
            classifier_sha256: verified.classifier_sha256,
            store,
            state: Mutex::new(None),
            deadline: REQUEST_DEADLINE,
            starts: Default::default(),
            #[cfg(windows)]
            unclean: Default::default(),
        })
    }

    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Identity of the installed package (manifest digest), distinct from `revision()`.
    pub fn package_id(&self) -> &str {
        &self.package
    }

    pub fn starts(&self) -> u64 {
        self.starts.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Retired workers whose Job Object was not verified empty (Windows evidence).
    #[cfg(windows)]
    pub fn unclean_retirements(&self) -> u64 {
        self.unclean.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn start(&self) -> anyhow::Result<Worker> {
        // Re-verify at every (re)start: files, permissions and interpreter.
        let verified: Verified = self.store.current()?;
        ensure!(
            verified.id == self.package,
            "the selected classifier package changed; restart the collector"
        );
        let mut command = Command::new(&verified.python.path);
        command
            .arg("-I")
            .arg("-u")
            .arg("-c")
            .arg(WORKER_BOOTSTRAP)
            .arg(&verified.dir)
            .arg(&verified.classifier_sha256)
            .arg(&verified.worker_sha256)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(unix)]
        command.current_dir("/");
        // Python needs SystemRoot to initialise on Windows; nothing else is passed.
        // The process starts suspended so it is inside its Job Object before it runs.
        #[cfg(windows)]
        let tree = {
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};
            let root = std::env::var_os("SystemRoot").context("SystemRoot is not set")?;
            command.env("SystemRoot", &root).current_dir(&root);
            command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
            platform::JobTree::new()?
        };
        let mut child = command
            .spawn()
            .context("classifier worker could not start")?;
        #[cfg(windows)]
        if let Err(error) = tree.assign_and_resume(&child) {
            tree.terminate();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.context("classifier worker could not be started inside its job"));
        }
        self.starts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut stdin = child.stdin.take().context("worker stdin missing")?;
        let stdout = child.stdout.take().context("worker stdout missing")?;
        let (to_worker, input) = sync_channel::<Vec<u8>>(1);
        let (output, from_worker) = sync_channel::<Result<Vec<u8>, String>>(2);
        std::thread::spawn(move || {
            for frame in input {
                if stdin.write_all(&frame).and_then(|_| stdin.flush()).is_err() {
                    return;
                }
            }
        });
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_frame(&mut reader) {
                    Ok(Some(frame)) => {
                        if output.send(Ok(frame)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        let _ = output.send(Err(error));
                        return;
                    }
                }
            }
        });
        let mut worker = Worker {
            child,
            to_worker,
            from_worker,
            next_id: 1,
            #[cfg(windows)]
            tree,
            #[cfg(windows)]
            unclean: self.unclean.clone(),
        };
        let frame = match worker.from_worker.recv_timeout(START_DEADLINE) {
            Ok(frame) => frame.map_err(|e| anyhow::anyhow!("worker start failed: {e}"))?,
            Err(RecvTimeoutError::Timeout) => {
                // The worker is still owned by its job and Drop retires it. Distinguish a
                // slow bootstrap from an early exit without changing the admission bound.
                let status = worker.child.try_wait().ok().flatten();
                bail!(
                    "classifier worker did not become ready within {:?} (child status: {:?})",
                    START_DEADLINE,
                    status
                );
            }
            Err(RecvTimeoutError::Disconnected) => {
                let status = worker.child.try_wait().ok().flatten();
                bail!(
                    "classifier worker exited before ready (child status: {:?})",
                    status
                );
            }
        };
        let ready: Ready = serde_json::from_slice(&frame).context("invalid ready frame")?;
        ensure!(
            ready.v == WORKER_PROTOCOL
                && ready.ready
                && ready.classifier_sha256 == verified.classifier_sha256,
            "worker ready frame does not match the installed package"
        );
        Ok(worker)
    }

    fn exchange(&self, worker: &mut Worker, input: &str) -> anyhow::Result<String> {
        let id = worker.next_id;
        worker.next_id += 1;
        let digest = sha(input.as_bytes());
        let mut frame = serde_json::to_vec(&Request {
            v: WORKER_PROTOCOL,
            id,
            input_sha256: &digest,
            input_json: input,
        })?;
        frame.push(b'\n');
        worker
            .to_worker
            .try_send(frame)
            .map_err(|_| anyhow::anyhow!("worker is not accepting input"))?;
        let started = Instant::now();
        let bytes = match worker.from_worker.recv_timeout(self.deadline) {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error)) => bail!("worker frame rejected: {error}"),
            Err(RecvTimeoutError::Timeout) => {
                bail!("classifier worker timed out after {:?}", started.elapsed())
            }
            Err(RecvTimeoutError::Disconnected) => bail!("classifier worker exited"),
        };
        let reply: Reply = serde_json::from_slice(&bytes).context("invalid worker reply")?;
        ensure!(reply.v == WORKER_PROTOCOL, "worker protocol mismatch");
        ensure!(reply.id == id, "worker reply id does not match the request");
        ensure!(
            reply.input_sha256 == digest,
            "worker reply is bound to different input"
        );
        Ok(reply.result_json)
    }

    /// Raw classifier output text for one exact input (same bytes the single-shot
    /// process prints), after id/digest binding. Failures retire the worker.
    pub fn classify_raw(&self, input: &str) -> anyhow::Result<String> {
        ensure!(input.len() <= MAX_INPUT, "classifier input exceeds limit");
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("classifier worker state poisoned"))?;
        let mut worker = match state.take() {
            Some(worker) => worker,
            None => self.start()?,
        };
        // On error `worker` is dropped here: killed and reaped, never reused.
        let result = self.exchange(&mut worker, input)?;
        *state = Some(worker);
        Ok(result)
    }

    /// Pid of the live worker, if any (tests and evidence).
    pub fn worker_pid(&self) -> Option<u32> {
        self.state.lock().ok()?.as_ref().map(|w| w.child.id())
    }
}

impl InvocationClassifier for PackagedClassifier {
    fn source(&self) -> &'static str {
        "rule-baseline/packaged-worker"
    }
    /// The verified classifier source digest: the semantic revision that resource policies
    /// and real-server profiles pin. Package identity is exposed separately.
    fn revision(&self) -> Option<&str> {
        Some(&self.classifier_sha256)
    }
    fn classify(&self, invocation: &Invocation) -> anyhow::Result<Classification> {
        let input = serde_json::to_string(&invocation.semantic_input())?;
        ensure!(input.len() <= MAX_INPUT, "classifier input exceeds limit");
        parse_classifier_reply(self.classify_raw(&input)?.as_bytes())
    }
}
