// SPDX-License-Identifier: Apache-2.0
//! A single owned CPU worker, on a dedicated supervisor thread. No inference,
//! Python startup or pipe I/O runs on Tokio or under native/firewall locks.

use super::*;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context};

const BOOTSTRAP: &str = include_str!("../../../../scripts/result-data-review-worker.py");
const STARTUP: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_millis(25);
const MAX_REQUEST: usize = 2 * 1024 * 1024;

struct Flags {
    ready: AtomicBool,
    busy: AtomicBool,
    stop: AtomicBool,
}

struct Job {
    id: u64,
    input_json: String,
    digest: String,
    channels: usize,
    deadline: Instant,
    reply: tokio::sync::oneshot::Sender<Option<DataPermit>>,
}

pub struct Reviewer {
    flags: Arc<Flags>,
    sender: SyncSender<Job>,
    next: AtomicU64,
    // Dropping does not join a potentially blocked startup on Tokio. The stop
    // flag makes its long-lived supervisor retire and reap the owned child.
    _supervisor: JoinHandle<()>,
}

impl Reviewer {
    pub fn start(config: Config) -> anyhow::Result<Self> {
        config.validate()?;
        let flags = Arc::new(Flags {
            ready: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        });
        let (sender, receiver) = sync_channel(1);
        let state = flags.clone();
        let supervisor = thread::Builder::new()
            .name("result-data-review".into())
            .spawn(move || {
                if supervise(&config, &state, receiver).is_err() {
                    // Stable diagnostics only. No text, paths, logits or credentials.
                    tracing::warn!(code = "result_data_review_retired");
                }
                state.ready.store(false, Ordering::Release);
                state.busy.store(false, Ordering::Release);
            })?;
        Ok(Self {
            flags,
            sender,
            next: AtomicU64::new(1),
            _supervisor: supervisor,
        })
    }

    /// Only a private, complete, bound Data result creates a permit.
    pub(crate) async fn review(&self, channels: Vec<String>) -> Option<DataPermit> {
        if !self.flags.ready.load(Ordering::Acquire)
            || self
                .flags
                .busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return None;
        }
        let deadline = Instant::now() + DEADLINE;
        let Some(input_json) = input(&channels) else {
            self.flags.busy.store(false, Ordering::Release);
            return None;
        };
        // The busy CAS above is the sole request issuer, so this cannot race
        // with another increment. Never wrap or reuse an id in this process.
        let id = self.next.load(Ordering::Acquire);
        let Some(next) = id.checked_add(1) else {
            self.flags.busy.store(false, Ordering::Release);
            return None;
        };
        self.next.store(next, Ordering::Release);
        let (reply, response) = tokio::sync::oneshot::channel();
        let job = Job {
            id,
            digest: sha(input_json.as_bytes()),
            input_json,
            channels: channels.len(),
            deadline,
            reply,
        };
        if self.sender.try_send(job).is_err() {
            self.flags.busy.store(false, Ordering::Release);
            return None;
        }
        let permit =
            tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), response)
                .await
                .ok()?
                .ok()?;
        if Instant::now() < deadline {
            permit
        } else {
            None
        }
    }

    pub(crate) fn ready(&self) -> bool {
        self.flags.ready.load(Ordering::Acquire)
    }
}

impl Drop for Reviewer {
    fn drop(&mut self) {
        self.flags.stop.store(true, Ordering::Release);
    }
}

fn private_directory(path: &Path) -> anyhow::Result<()> {
    ensure!(path.is_absolute(), "absolute directory required");
    let mut prefix = PathBuf::new();
    for part in path.components() {
        ensure!(
            !matches!(part, Component::ParentDir | Component::CurDir),
            "unsafe path component"
        );
        prefix.push(part);
        let meta = fs::symlink_metadata(&prefix)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "directory symlink forbidden"
        );
        // Sticky system parents such as /tmp cannot rename a different owner's
        // private entry. Every other ancestor must be non-writable to others.
        // SAFETY: geteuid is a read-only libc query.
        let trusted_sticky = meta.mode() & 0o1000 != 0
            && (meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() });
        ensure!(
            meta.mode() & 0o022 == 0 || trusted_sticky,
            "writable ancestor"
        );
    }
    let meta = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    ensure!(
        meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
        "owner-private directory required"
    );
    Ok(())
}

fn hash_file(path: &Path, cap: u64) -> anyhow::Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= cap && metadata.mode() & 0o022 == 0,
        "unsafe runtime file"
    );
    let mut hasher = Sha256::new();
    let mut count = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        ensure!(count <= cap, "runtime file grew");
        hasher.update(&buf[..read]);
    }
    ensure!(count == metadata.len(), "runtime file changed");
    Ok(format!("{:x}", hasher.finalize()))
}

/// Canonical runtime manifest: sorted slash-separated relative UTF-8 paths;
/// each entry contributes JSON `[path, kind, hash_or_link_target]` plus LF.
/// Directories also participate; symlinks are limited to standard venv aliases.
/// This is an operator installation pin, not authorization supplied by a tool.
pub fn runtime_digest(root: &Path) -> anyhow::Result<String> {
    private_directory(root)?;
    let mut pending = vec![root.to_path_buf()];
    let mut entries = Vec::new();
    let interpreter = fs::canonicalize(root.join("bin/python"))?;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)?
                .to_str()
                .context("non UTF-8 runtime path")?
                .to_owned();
            let metadata = fs::symlink_metadata(&path)?;
            let (kind, digest) = if metadata.file_type().is_symlink() {
                let target = fs::read_link(&path)?;
                let allowed_python = path.parent() == Some(root.join("bin").as_path())
                    && matches!(
                        entry.file_name().to_str(),
                        Some("python" | "python3" | "python3.12" | "python3.11" | "python3.13")
                    )
                    && fs::canonicalize(&path)? == interpreter;
                ensure!(
                    allowed_python || (relative == "lib64" && target == Path::new("lib")),
                    "unapproved runtime symlink"
                );
                (
                    "link",
                    target
                        .to_str()
                        .context("non UTF-8 runtime link")?
                        .to_owned(),
                )
            } else {
                ensure!(metadata.mode() & 0o022 == 0, "writable runtime entry");
                if metadata.is_dir() {
                    pending.push(path.clone());
                    ("dir", String::new())
                } else {
                    ("file", hash_file(&path, 512 * 1024 * 1024)?)
                }
            };
            entries.push((relative, kind, digest));
            ensure!(entries.len() <= 50_000, "runtime tree over cap");
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for entry in entries {
        hasher.update(serde_json::to_vec(&entry)?);
        hasher.update(b"\n");
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Compute local operator pins only. This does not enable or qualify a model.
pub fn installation_pin(runtime_dir: PathBuf, assets_dir: PathBuf) -> anyhow::Result<Config> {
    private_directory(&assets_dir)?;
    let runtime_sha256 = runtime_digest(&runtime_dir)?;
    let executable = fs::canonicalize(runtime_dir.join("bin/python"))?;
    let config = Config {
        interpreter_sha256: hash_file(&executable, 512 * 1024 * 1024)?,
        runtime_dir,
        runtime_sha256,
        assets_dir,
    };
    config.validate()?;
    Ok(config)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    v: String,
    #[serde(rename = "type")]
    kind: String,
    model_sha256: String,
    runtime: std::collections::BTreeMap<String, String>,
}

fn check_ready(frame: &[u8]) -> anyhow::Result<()> {
    let value: Ready = serde_json::from_slice(frame)?;
    ensure!(
        value.v == PROTOCOL
            && value.kind == "ready"
            && value.model_sha256 == MODEL_SHA256
            && value.runtime
                == std::collections::BTreeMap::from([
                    ("onnxruntime".into(), "1.23.2".into()),
                    ("tokenizers".into(), "0.22.1".into()),
                    ("numpy".into(), "2.3.4".into())
                ]),
        "invalid ready frame"
    );
    Ok(())
}

type Frame = Result<Vec<u8>, ()>;

struct Worker {
    child: Child,
    output: Option<Receiver<Frame>>,
    input: Option<SyncSender<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
}

impl Worker {
    fn spawn(command: &mut Command) -> anyhow::Result<Self> {
        // This supervisor thread outlives the worker. PDEATHSIG is tied to the
        // spawning Linux thread; never spawn from a transient startup thread.
        let parent = std::process::id();
        // SAFETY: the closure uses only async-signal-safe libc operations.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() as u32 != parent {
                    return Err(std::io::Error::other("parent changed"));
                }
                Ok(())
            });
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = child.stdout.take().context("missing stdout")?;
        let mut stdin = child.stdin.take().context("missing stdin")?;
        let (output_sender, output) = sync_channel(1);
        let reader = thread::spawn(move || {
            let mut source = BufReader::new(stdout);
            loop {
                let frame = read_frame(&mut source);
                let stop = frame.is_err();
                if output_sender.send(frame).is_err() || stop {
                    break;
                }
            }
        });
        let (input, input_receiver) = sync_channel::<Vec<u8>>(1);
        let writer = thread::spawn(move || {
            while let Ok(bytes) = input_receiver.recv() {
                if stdin.write_all(&bytes).and_then(|_| stdin.flush()).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            output: Some(output),
            input: Some(input),
            reader: Some(reader),
            writer: Some(writer),
        })
    }

    fn receive(&self, deadline: Instant, flags: &Flags) -> anyhow::Result<Vec<u8>> {
        loop {
            ensure!(!flags.stop.load(Ordering::Acquire), "reviewer stopping");
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure!(!remaining.is_zero(), "review deadline");
            match self
                .output
                .as_ref()
                .context("output closed")?
                .recv_timeout(remaining.min(POLL))
            {
                Ok(Ok(bytes)) => return Ok(bytes),
                Err(RecvTimeoutError::Timeout) => continue,
                _ => anyhow::bail!("review worker output failed"),
            }
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.input.take();
        self.output.take();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn read_frame(source: &mut impl BufRead) -> Frame {
    let mut frame = Vec::new();
    loop {
        let part = source.fill_buf().map_err(|_| ())?;
        if part.is_empty() {
            return Err(());
        }
        let take = part
            .iter()
            .position(|b| *b == b'\n')
            .map_or(part.len(), |end| end + 1);
        if frame.len() + take > MAX_FRAME {
            return Err(());
        }
        let complete = part[take - 1] == b'\n';
        frame.extend_from_slice(&part[..take]);
        source.consume(take);
        if complete {
            return Ok(frame);
        }
    }
}

fn supervise(config: &Config, flags: &Flags, jobs: Receiver<Job>) -> anyhow::Result<()> {
    let deadline = Instant::now() + STARTUP;
    private_directory(&config.assets_dir)?;
    ensure!(
        runtime_digest(&config.runtime_dir)? == config.runtime_sha256,
        "runtime pin mismatch"
    );
    let executable = fs::canonicalize(config.runtime_dir.join("bin/python"))?;
    ensure!(
        hash_file(&executable, 512 * 1024 * 1024)? == config.interpreter_sha256,
        "interpreter pin mismatch"
    );
    ensure!(
        Instant::now() < deadline && !flags.stop.load(Ordering::Acquire),
        "startup expired"
    );
    let mut command = Command::new(config.runtime_dir.join("bin/python"));
    command
        .args(["-I", "-B", "-u", "-c", BOOTSTRAP])
        .arg(&config.assets_dir)
        .current_dir(&config.runtime_dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("OMP_NUM_THREADS", "6")
        .env("OPENBLAS_NUM_THREADS", "6")
        .env("CUDA_VISIBLE_DEVICES", "");
    let worker = Worker::spawn(&mut command)?;
    serve_worker(worker, flags, jobs, deadline)
}

fn serve_worker(
    mut worker: Worker,
    flags: &Flags,
    jobs: Receiver<Job>,
    deadline: Instant,
) -> anyhow::Result<()> {
    check_ready(&worker.receive(deadline, flags)?)?;
    flags.ready.store(true, Ordering::Release);
    tracing::info!(
        code = "result_data_review_ready",
        model_sha256 = MODEL_SHA256
    );
    loop {
        if flags.stop.load(Ordering::Acquire) {
            break;
        }
        let job = match jobs.recv_timeout(POLL) {
            Ok(job) => job,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let data = run_job(&mut worker, &job, flags);
        match data {
            Ok(true) if Instant::now() < job.deadline => {
                let _ = job.reply.send(Some(DataPermit {
                    input_sha256: job.digest,
                }));
            }
            Ok(_) => {
                let _ = job.reply.send(None);
            }
            Err(error) => {
                let _ = job.reply.send(None);
                return Err(error); // Retire; no late reply can reach another job.
            }
        }
        flags.busy.store(false, Ordering::Release);
    }
    Ok(())
}

fn run_job(worker: &mut Worker, job: &Job, flags: &Flags) -> anyhow::Result<bool> {
    ensure!(Instant::now() < job.deadline, "expired queued job");
    let mut bytes = serde_json::to_vec(&serde_json::json!({"v": PROTOCOL,
        "id": job.id, "input_sha256": job.digest, "input_json": job.input_json}))?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= MAX_REQUEST, "request frame over cap");
    worker
        .input
        .as_ref()
        .context("input closed")?
        .try_send(bytes)
        .context("writer unavailable")?;
    let frame = worker.receive(job.deadline, flags)?;
    ensure!(Instant::now() < job.deadline, "late result review frame");
    check_reply(&frame, job.id, &job.digest, job.channels)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdout_frame_is_bounded_even_without_a_newline() {
        assert!(read_frame(&mut std::io::Cursor::new(vec![b'x'; MAX_FRAME + 1])).is_err());
        assert!(read_frame(&mut std::io::Cursor::new(b"no newline")).is_err());
        assert_eq!(
            read_frame(&mut std::io::Cursor::new(b"{}\nnext")).unwrap(),
            b"{}\n"
        );
    }

    #[test]
    fn ready_is_pinned_to_exact_model_and_runtime() {
        let mut value = serde_json::json!({"v": PROTOCOL, "type": "ready", "model_sha256": MODEL_SHA256,
            "runtime": {"onnxruntime": "1.23.2", "tokenizers": "0.22.1", "numpy": "2.3.4"}});
        assert!(check_ready(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["runtime"]["numpy"] = serde_json::json!("latest");
        assert!(check_ready(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn stalled_owned_child_is_killed_and_reaped() {
        let flags = Flags {
            ready: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        };
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-I", "-c", "import time; time.sleep(60)"]);
        let worker = Worker::spawn(&mut command).unwrap();
        let pid = worker.child.id();
        assert!(worker
            .receive(Instant::now() + Duration::from_millis(40), &flags)
            .is_err());
        drop(worker);
        // SAFETY: kill(pid, 0) only observes process existence. Child::wait has
        // already reaped our child; no signal is delivered to a reused PID.
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    }

    fn fake_reviewer(body: &str) -> (Reviewer, Arc<std::sync::atomic::AtomicU32>) {
        let ready = serde_json::json!({"v": PROTOCOL, "type": "ready", "model_sha256": MODEL_SHA256,
            "runtime": {"onnxruntime":"1.23.2", "tokenizers":"0.22.1", "numpy":"2.3.4"}});
        let code = format!("import json,sys,time\nprint({:?},flush=True)\nfor line in sys.stdin:\n r=json.loads(line)\n {}\n", ready.to_string(), body);
        let flags = Arc::new(Flags {
            ready: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        });
        let state = flags.clone();
        let (sender, receiver) = sync_channel(1);
        let pid = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let owned_pid = pid.clone();
        let supervisor = thread::spawn(move || {
            let mut command = Command::new("/usr/bin/python3");
            command.args(["-I", "-u", "-c", &code]);
            let worker = Worker::spawn(&mut command).unwrap();
            owned_pid.store(worker.child.id(), Ordering::Release);
            let _ = serve_worker(
                worker,
                &state,
                receiver,
                Instant::now() + Duration::from_secs(2),
            );
            state.ready.store(false, Ordering::Release);
            state.busy.store(false, Ordering::Release);
        });
        (
            Reviewer {
                flags,
                sender,
                next: AtomicU64::new(1),
                _supervisor: supervisor,
            },
            pid,
        )
    }

    async fn wait_ready(reviewer: &Reviewer) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !reviewer.ready() {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    const DATA_REPLY: &str = "print(json.dumps(dict(v=r['v'],type='review',id=r['id'],input_sha256=r['input_sha256'],model_sha256='5ae9f527897b1ffcb2b13440875769d0c28a25fb976b8b42465f0ad5b462b61b',assessment='data',coverage_complete=True,view_count=len(json.loads(r['input_json'])['channels'])+1,max_score=0.02)),flush=True)";

    #[tokio::test]
    async fn complete_owned_reply_is_bound_and_unknown_does_not_grant_a_permit() {
        let body = DATA_REPLY.replace(
            "assessment='data'",
            "assessment='unknown' if r['id']==1 else 'data'",
        );
        let (reviewer, _) = fake_reviewer(&body);
        wait_ready(&reviewer).await;
        assert!(reviewer.review(vec!["first".into()]).await.is_none());
        let texts = vec!["a\r\n".into(), "a\r\n".into(), "".into()];
        let permit = reviewer.review(texts.clone()).await.unwrap();
        assert!(permit.matches(&texts));
        assert!(!permit.matches(&["replacement".into()]));
    }

    #[tokio::test]
    async fn wrong_id_retires_worker_instead_of_reusing_a_late_reply() {
        let (reviewer, _) = fake_reviewer(&DATA_REPLY.replace("id=r['id']", "id=r['id']+1"));
        wait_ready(&reviewer).await;
        assert!(reviewer.review(vec!["first".into()]).await.is_none());
        assert!(reviewer.review(vec!["second".into()]).await.is_none());
    }

    #[tokio::test]
    async fn timeout_is_bounded_busy_calls_do_not_queue_and_child_is_reaped() {
        let (reviewer, pid) = fake_reviewer("time.sleep(60)");
        let reviewer = Arc::new(reviewer);
        wait_ready(&reviewer).await;
        let other = reviewer.clone();
        let started = Instant::now();
        let first = tokio::spawn(async move { other.review(vec!["first".into()]).await });
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(reviewer.review(vec!["concurrent".into()]).await.is_none());
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(first.await.unwrap().is_none());
        assert!(started.elapsed() < Duration::from_millis(1800));
        let cleanup = Instant::now() + Duration::from_secs(2);
        while reviewer.ready() {
            assert!(Instant::now() < cleanup);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // SAFETY: signal zero observes only; the supervisor reaped its own child.
        assert_eq!(
            unsafe { libc::kill(pid.load(Ordering::Acquire) as i32, 0) },
            -1
        );
        assert!(reviewer
            .review(vec!["after retirement".into()])
            .await
            .is_none());
    }
}
