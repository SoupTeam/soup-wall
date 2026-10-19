// SPDX-License-Identifier: Apache-2.0
//! Generic enforcing MCP child diagnostics and process ownership.
//!
//! This closes the child-stderr pipe, not arbitrary OS output or side effects.
//! Unix process-group cleanup does not contain a child deliberately escaping
//! with setsid/setpgid. Selected filesystem/Git namespaces retain their separate
//! accepted implementation. Raw bytes exist only in one cleared read buffer.

use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::process::{Child as TokioChild, Command};
use tokio::task::JoinHandle;
use tokio::time::{timeout_at, Instant};

pub(crate) const STDERR_CHUNK_BYTES: usize = 8192;
pub(crate) const STDERR_BYTE_LIMIT: usize = 1024 * 1024;
pub(crate) const STDERR_READ_LIMIT: usize = 4096;
pub(crate) const STDERR_LIFETIME: Duration = Duration::from_secs(3600);
pub(crate) const CHILD_GRACE: Duration = Duration::from_secs(2);
pub(crate) const CHILD_REAP: Duration = Duration::from_secs(3);
pub(crate) const DRAIN_SHUTDOWN: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DrainOutcome {
    Eof,
    ByteLimit,
    ReadLimit,
    Lifetime,
    ReadFailure,
    ShutdownTimeout,
    TaskFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct DrainReport {
    pub outcome: DrainOutcome,
    pub received_bytes: usize,
    pub read_chunks: usize,
    pub released: bool,
    #[serde(skip)]
    worker_closed: bool,
}

impl DrainReport {
    pub(crate) fn code(self) -> &'static str {
        match self.outcome {
            DrainOutcome::Eof => "eof",
            DrainOutcome::ByteLimit => "byte_limit",
            DrainOutcome::ReadLimit => "read_limit",
            DrainOutcome::Lifetime => "lifetime",
            DrainOutcome::ReadFailure => "read_failure",
            DrainOutcome::ShutdownTimeout => "shutdown_timeout",
            DrainOutcome::TaskFailure => "task_failure",
        }
    }
    pub(crate) fn cleanup_verified(self) -> bool {
        self.worker_closed
    }
    pub(crate) fn is_failure(self) -> bool {
        self.outcome != DrainOutcome::Eof
    }
}

#[derive(Default)]
struct Counters {
    bytes: AtomicUsize,
    chunks: AtomicUsize,
    failure: Arc<AtomicBool>,
}

impl Counters {
    fn report(&self, outcome: DrainOutcome) -> DrainReport {
        if outcome != DrainOutcome::Eof {
            // Publish before the worker completes. Host-write guards observe
            // this without waiting for the outer relay select to poll its Join.
            self.failure.store(true, Ordering::Release);
        }
        DrainReport {
            outcome,
            received_bytes: self.bytes.load(Ordering::Relaxed),
            read_chunks: self.chunks.load(Ordering::Relaxed),
            released: false,
            worker_closed: !matches!(
                outcome,
                DrainOutcome::ShutdownTimeout | DrainOutcome::TaskFailure
            ),
        }
    }
}

#[derive(Clone, Copy)]
struct DrainLimits {
    bytes: usize,
    reads: usize,
    lifetime: Duration,
}

impl Default for DrainLimits {
    fn default() -> Self {
        Self {
            bytes: STDERR_BYTE_LIMIT,
            reads: STDERR_READ_LIMIT,
            lifetime: STDERR_LIFETIME,
        }
    }
}

async fn discard<R: AsyncRead + Unpin>(
    mut stream: R,
    state: Arc<Counters>,
    limits: DrainLimits,
) -> DrainReport {
    let deadline = Instant::now() + limits.lifetime;
    let mut buffer = [0u8; STDERR_CHUNK_BYTES];
    let mut bytes = 0usize;
    let mut chunks = 0usize;
    loop {
        if chunks >= limits.reads {
            return state.report(DrainOutcome::ReadLimit);
        }
        // A single-byte probe distinguishes exact-quota EOF from overflow.
        // Even a flood can consume at most limit+1 bytes, never a whole excess
        // buffer. Checked subtraction is covered by the immediately prior gate.
        let available = limits
            .bytes
            .saturating_sub(bytes)
            .saturating_add(1)
            .min(STDERR_CHUNK_BYTES);
        let read = timeout_at(deadline, stream.read(&mut buffer[..available])).await;
        // No strings, samples, hashes, error Display or raw log capture. Clear
        // even an erroring reader's partially modified buffer before branching.
        buffer.fill(0);
        match read {
            Err(_) => return state.report(DrainOutcome::Lifetime),
            Ok(Err(_)) => return state.report(DrainOutcome::ReadFailure),
            Ok(Ok(0)) => return state.report(DrainOutcome::Eof),
            Ok(Ok(count)) => {
                bytes += count;
                chunks += 1;
                state.bytes.store(bytes, Ordering::Relaxed);
                state.chunks.store(chunks, Ordering::Relaxed);
                if bytes > limits.bytes {
                    return state.report(DrainOutcome::ByteLimit);
                }
            }
        }
    }
}

/// One owned worker. Cancellation does not detach its read task. Normal callers
/// must call finish() to obtain the bounded shutdown/descriptor-close outcome.
pub(crate) struct Drain {
    task: Option<JoinHandle<DrainReport>>,
    counters: Arc<Counters>,
    complete: Option<DrainReport>,
}

impl Drain {
    pub(crate) fn start<R: AsyncRead + Unpin + Send + 'static>(stream: R) -> Self {
        Self::with_limits(stream, DrainLimits::default())
    }

    fn with_limits<R: AsyncRead + Unpin + Send + 'static>(stream: R, limits: DrainLimits) -> Self {
        let counters = Arc::new(Counters::default());
        let task = tokio::spawn(discard(stream, counters.clone(), limits));
        Self {
            task: Some(task),
            counters,
            complete: None,
        }
    }

    pub(crate) fn failure_flag(&self) -> Arc<AtomicBool> {
        self.counters.failure.clone()
    }

    pub(crate) async fn wait(&mut self) -> DrainReport {
        if let Some(report) = self.complete {
            return report;
        }
        let report = match self.task.as_mut() {
            Some(task) => match task.await {
                Ok(report) => report,
                Err(_) => self.counters.report(DrainOutcome::TaskFailure),
            },
            None => self.counters.report(DrainOutcome::TaskFailure),
        };
        self.task.take();
        self.complete = Some(report);
        report
    }

    pub(crate) async fn finish(mut self) -> DrainReport {
        if let Some(report) = self.complete {
            return report;
        }
        let deadline = Instant::now() + DRAIN_SHUTDOWN;
        // Reserve half the one-second shutdown bound for abort + join. A pipe
        // held by a descendant cannot make the owner await EOF indefinitely.
        if let Ok(report) = timeout_at(deadline - DRAIN_SHUTDOWN / 2, self.wait()).await {
            return report;
        }
        let closed = if let Some(task) = self.task.as_mut() {
            task.abort();
            timeout_at(deadline, task).await.is_ok()
        } else {
            false
        };
        self.task.take();
        let mut report = self.counters.report(DrainOutcome::ShutdownTimeout);
        report.worker_closed = closed;
        self.complete = Some(report);
        report
    }
}

impl Drop for Drain {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChildFailure(&'static str);
impl std::fmt::Display for ChildFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for ChildFailure {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CleanupReport {
    pub cleaned: bool,
    pub reaped: bool,
    pub exit_success: bool,
    pub graceful_observed: bool,
    pub ownership: &'static str,
    pub failure: Option<&'static str>,
}

// One child-owner interface. The configured Windows launch supplies an atomic
// Job-list creation primitive; all paths retain the same ProcessTree cleanup.
enum ChildProcess {
    Tokio(TokioChild),
    #[cfg(windows)]
    Budgeted(super::windows_budget::launch::Process),
}

pub(crate) struct Child {
    pub(crate) stdin: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    pub(crate) stdout: Option<Box<dyn AsyncRead + Send + Unpin>>,
    pub(crate) stderr: Option<Box<dyn AsyncRead + Send + Unpin>>,
    process: ChildProcess,
}

impl Child {
    fn from_tokio(mut process: TokioChild) -> Self {
        Self {
            stdin: process.stdin.take().map(|pipe| Box::new(pipe) as _),
            stdout: process.stdout.take().map(|pipe| Box::new(pipe) as _),
            stderr: process.stderr.take().map(|pipe| Box::new(pipe) as _),
            process: ChildProcess::Tokio(process),
        }
    }
    #[cfg(windows)]
    pub(crate) fn budgeted(
        process: super::windows_budget::launch::Process,
        stdin: impl AsyncWrite + Send + Unpin + 'static,
        stdout: impl AsyncRead + Send + Unpin + 'static,
        stderr: impl AsyncRead + Send + Unpin + 'static,
    ) -> Self {
        Self {
            stdin: Some(Box::new(stdin)),
            stdout: Some(Box::new(stdout)),
            stderr: Some(Box::new(stderr)),
            process: ChildProcess::Budgeted(process),
        }
    }
    pub(crate) fn id(&self) -> Option<u32> {
        match &self.process {
            ChildProcess::Tokio(child) => child.id(),
            #[cfg(windows)]
            ChildProcess::Budgeted(child) => Some(child.id()),
        }
    }
    #[cfg(windows)]
    fn raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
        match &self.process {
            ChildProcess::Tokio(child) => child.raw_handle(),
            ChildProcess::Budgeted(child) => Some(child.raw_handle()),
        }
    }
    fn start_kill(&mut self) -> std::io::Result<()> {
        match &mut self.process {
            ChildProcess::Tokio(child) => child.start_kill(),
            #[cfg(windows)]
            ChildProcess::Budgeted(child) => child.start_kill(),
        }
    }
    async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        match &mut self.process {
            ChildProcess::Tokio(child) => child.wait().await,
            #[cfg(windows)]
            ChildProcess::Budgeted(child) => child.wait().await,
        }
    }
    #[cfg(windows)]
    fn resume_budgeted(
        &mut self,
        job: &std::os::windows::io::OwnedHandle,
    ) -> Result<(), &'static str> {
        match &mut self.process {
            ChildProcess::Budgeted(child) => child.resume(job),
            ChildProcess::Tokio(_) => Err("windows_budget_launch_type"),
        }
    }
}

/// The direct child's PID must remain unreaped until the group is signalled.
/// Callers may extract its stdio through child_mut(), but must not call wait(),
/// try_wait(), kill() or otherwise reap it independently of cleanup().
pub(crate) struct OwnedChild {
    child: Child,
    tree: ProcessTree,
    complete: Option<CleanupReport>,
    #[cfg(windows)]
    budget: Option<super::windows_budget::Budget>,
}

impl OwnedChild {
    pub(crate) async fn spawn(command: &mut Command) -> Result<Self, ChildFailure> {
        let config = super::windows_budget::Config::load_from_env()
            .map_err(|_| ChildFailure("windows_budget_configuration_refused"))?;
        Self::spawn_with_budget(command, config).await
    }

    async fn spawn_with_budget(
        command: &mut Command,
        config: Option<super::windows_budget::Config>,
    ) -> Result<Self, ChildFailure> {
        #[cfg(not(windows))]
        if config.is_some() {
            return Err(ChildFailure("windows_budget_platform_unsupported"));
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            command.process_group(0);
            let child = command
                .spawn()
                .map_err(|_| ChildFailure("native_child_spawn"))?;
            let pid = child.id().ok_or(ChildFailure("native_child_identity"))?;
            let pid = i32::try_from(pid).map_err(|_| ChildFailure("native_child_identity"))?;
            Ok(Self {
                child: Child::from_tokio(child),
                tree: ProcessTree { pid, armed: true },
                complete: None,
            })
        }
        #[cfg(windows)]
        {
            let mut tree = ProcessTree::new()?;
            let budget = config
                .map(|config| super::windows_budget::Budget::install(tree.job.clone(), config))
                .transpose()
                .map_err(ChildFailure)?;
            if let Some(budget) = budget {
                let mut child =
                    super::windows_budget::launch::spawn_suspended(command.as_std(), &tree.job)
                        .await
                        .map_err(ChildFailure)?;
                if let Err(code) = budget
                    .guard()
                    .check()
                    .and_then(|()| child.resume_budgeted(&tree.job))
                {
                    tree.terminate();
                    let _ = child.start_kill();
                    let _ = tokio::time::timeout(CHILD_REAP, child.wait()).await;
                    return Err(ChildFailure(code));
                }
                return Ok(Self {
                    child,
                    tree,
                    complete: None,
                    budget: Some(budget),
                });
            }
            command.creation_flags(
                windows_sys::Win32::System::Threading::CREATE_SUSPENDED
                    | windows_sys::Win32::System::Threading::CREATE_NO_WINDOW,
            );
            let mut child = command
                .spawn()
                .map_err(|_| ChildFailure("native_child_spawn"))?;
            if let Err(failure) = tree.assign_and_resume(&child) {
                tree.terminate();
                let _ = child.start_kill();
                let _ = tokio::time::timeout(CHILD_REAP, child.wait()).await;
                return Err(failure);
            }
            Ok(Self {
                child: Child::from_tokio(child),
                tree,
                complete: None,
                budget: None,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = command;
            Err(ChildFailure("native_child_ownership_unsupported"))
        }
    }

    pub(crate) fn ownership(&self) -> &'static str {
        ProcessTree::NAME
    }
    pub(crate) fn budget_guard(&self) -> Option<super::windows_budget::Guard> {
        #[cfg(windows)]
        {
            self.budget
                .as_ref()
                .map(super::windows_budget::Budget::guard)
        }
        #[cfg(not(windows))]
        {
            None
        }
    }
    pub(crate) fn budget_report(&self) -> Option<serde_json::Value> {
        #[cfg(windows)]
        {
            self.budget_guard().map(|guard| guard.report())
        }
        #[cfg(not(windows))]
        {
            None
        }
    }
    pub(crate) fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    pub(crate) async fn cleanup(&mut self, graceful: bool) -> CleanupReport {
        if let Some(report) = self.complete {
            return report;
        }
        let graceful_observed = if graceful {
            self.tree.observe_exit(&self.child).await
        } else {
            false
        };
        let terminated = self.tree.terminate();
        // Failure to signal a tree must never skip direct-child kill/reap.
        if !terminated {
            let _ = self.child.start_kill();
        }
        let deadline = Instant::now() + CHILD_REAP;
        let status = timeout_at(deadline, self.child.wait()).await;
        let (reaped, exit_success, mut failure) = match status {
            Ok(Ok(status)) => (true, status.success(), None),
            Ok(Err(_)) => (false, false, Some("native_child_wait")),
            Err(_) => (false, false, Some("native_child_reap_timeout")),
        };
        let empty = self.tree.finish(reaped, deadline).await;
        if !terminated {
            failure = Some("native_child_tree_termination");
        }
        if !empty {
            failure.get_or_insert("native_child_tree_unverified");
        }
        let report = CleanupReport {
            cleaned: reaped && terminated && empty,
            reaped,
            exit_success,
            graceful_observed,
            ownership: ProcessTree::NAME,
            failure,
        };
        #[cfg(windows)]
        if let Some(budget) = self.budget.as_mut() {
            budget.finish(report.cleaned);
        }
        self.complete = Some(report);
        report
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Runs before Child's kill-on-drop/reaper and before platform handles
        // close. On Unix this is the last safe point to use the unreaped pgid.
        self.tree.terminate();
    }
}

#[cfg(unix)]
struct ProcessTree {
    pid: libc::pid_t,
    armed: bool,
}

#[cfg(unix)]
impl ProcessTree {
    const NAME: &'static str = "unix_process_group";
    fn terminate(&mut self) -> bool {
        if !self.armed {
            return true;
        }
        // SAFETY: process_group(0) created this owned group before exec. The
        // direct child has never been reaped, so its numeric ID cannot be reused.
        let result = unsafe { libc::kill(-self.pid, libc::SIGKILL) };
        if result == 0 {
            return true;
        }
        let error = std::io::Error::last_os_error().raw_os_error();
        if error == Some(libc::ESRCH) {
            return true;
        }
        // Darwin returns EPERM for a process group containing only zombies.
        // Never waive EPERM merely because our direct child has exited: a live
        // descendant could still own the stderr pipe or perform side effects.
        #[cfg(target_os = "macos")]
        if error == Some(libc::EPERM) {
            return self.no_live_group_members();
        }
        false
    }

    #[cfg(target_os = "macos")]
    fn no_live_group_members(&self) -> bool {
        // sys/proc_info.h defines PROC_PGRP_ONLY=2. Keep both snapshots bounded;
        // a full/truncated list or an unreadable member is never proof of exit.
        const PROC_PGRP_ONLY: u32 = 2;
        const MEMBER_LIMIT: usize = 1024;
        let deadline = std::time::Instant::now() + Duration::from_millis(100);
        let mut before = [0 as libc::pid_t; MEMBER_LIMIT];
        let mut after = [0 as libc::pid_t; MEMBER_LIMIT];
        let snapshot = |members: &mut [libc::pid_t; MEMBER_LIMIT]| -> Option<usize> {
            // SAFETY: members is a fixed writable pid_t array. Selection is
            // only this still-pinned owned process group, never all host PIDs.
            let bytes = unsafe {
                libc::proc_listpids(
                    PROC_PGRP_ONLY,
                    self.pid as u32,
                    members.as_mut_ptr().cast(),
                    std::mem::size_of_val(members) as libc::c_int,
                )
            };
            let bytes = usize::try_from(bytes).ok()?;
            if bytes == 0
                || bytes >= std::mem::size_of_val(members)
                || bytes % std::mem::size_of::<libc::pid_t>() != 0
            {
                return None;
            }
            let count = bytes / std::mem::size_of::<libc::pid_t>();
            if members[..count].iter().any(|pid| *pid <= 0) {
                return None;
            }
            members[..count].sort_unstable();
            Some(count)
        };
        let Some(count) = snapshot(&mut before) else {
            return false;
        };
        if !before[..count].contains(&self.pid) {
            return false;
        }
        for pid in &before[..count] {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
            // SAFETY: info is writable for exactly the complete requested ABI
            // struct. No process names or other fields are exposed or logged.
            let read = unsafe {
                libc::proc_pidinfo(
                    *pid,
                    libc::PROC_PIDTBSDINFO,
                    // XNU uses nonzero arg to include zombies for this flavor.
                    1,
                    info.as_mut_ptr().cast(),
                    std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
                )
            };
            if read != std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int {
                return false;
            }
            // SAFETY: the exact complete initialized ABI struct was returned.
            let info = unsafe { info.assume_init() };
            if info.pbi_pid != *pid as u32
                || info.pbi_pgid != self.pid as u32
                || info.pbi_status != libc::SZOMB
            {
                return false;
            }
        }
        // A member could fork and exit between the first enumeration and its
        // status read. Require the same complete membership after all listed
        // members are zombies, so such an uninspected child cannot be missed.
        std::time::Instant::now() < deadline
            && snapshot(&mut after) == Some(count)
            && before[..count] == after[..count]
    }

    async fn observe_exit(&self, _child: &Child) -> bool {
        let deadline = Instant::now() + CHILD_GRACE;
        loop {
            let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: info is writable and waitid(WNOWAIT) does not reap/release
            // the child's PID, including when it is already a zombie.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    info.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == -1 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                    && Instant::now() < deadline
                {
                    continue;
                }
                return false;
            }
            // SAFETY: waitid succeeded and initialized siginfo_t.
            if unsafe { info.assume_init().si_pid() } == self.pid {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    async fn finish(&mut self, reaped: bool, _deadline: Instant) -> bool {
        if reaped {
            self.armed = false;
        }
        // This verifies owned group signalling + direct-child reaping, not an
        // OS sandbox or process-group-escape prevention. Independent acceptance
        // additionally observes every owned fixture descendant's termination.
        reaped
    }
}

#[cfg(windows)]
struct ProcessTree {
    job: Arc<std::os::windows::io::OwnedHandle>,
    armed: bool,
}

#[cfg(windows)]
impl ProcessTree {
    const NAME: &'static str = "windows_job";
    fn new() -> Result<Self, ChildFailure> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::{
            Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT},
            System::JobObjects::*,
        };
        // SAFETY: no name, no inheritable SECURITY_ATTRIBUTES, valid null inputs.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(ChildFailure("native_child_job_create"));
        }
        // SAFETY: successful CreateJobObjectW transfers an owned kernel handle.
        let job = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast()) };
        let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                ..Default::default()
            },
            ..Default::default()
        };
        // SAFETY: job is owned; limits points to its complete initialized type.
        if unsafe { SetHandleInformation(job.as_raw_handle().cast(), HANDLE_FLAG_INHERIT, 0) } == 0
            || unsafe {
                SetInformationJobObject(
                    job.as_raw_handle().cast(),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            } == 0
        {
            return Err(ChildFailure("native_child_job_configure"));
        }
        Ok(Self {
            job: Arc::new(job),
            armed: true,
        })
    }
    fn assign_and_resume(&mut self, child: &TokioChild) -> Result<(), ChildFailure> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::{
            Foundation::{GetLastError, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE},
            System::{
                Diagnostics::ToolHelp::*,
                JobObjects::{AssignProcessToJobObject, IsProcessInJob},
                Threading::*,
            },
        };
        let process = child
            .raw_handle()
            .ok_or(ChildFailure("native_child_identity"))?;
        let pid = child.id().ok_or(ChildFailure("native_child_identity"))?;
        // The primary thread is still suspended: no child instruction can run or
        // create an unowned descendant before successful job assignment.
        if unsafe { AssignProcessToJobObject(self.job.as_raw_handle().cast(), process.cast()) } == 0
        {
            return Err(ChildFailure("native_child_job_assign"));
        }
        let mut member = 0;
        if unsafe { IsProcessInJob(process.cast(), self.job.as_raw_handle().cast(), &mut member) }
            == 0
            || member == 0
        {
            return Err(ChildFailure("native_child_job_membership"));
        }
        // SAFETY: a read-only noninheritable system thread snapshot.
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if raw == INVALID_HANDLE_VALUE {
            return Err(ChildFailure("native_child_thread_snapshot"));
        }
        // SAFETY: successful snapshot is an owned kernel handle.
        let snapshot = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast()) };
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut found = None;
        let mut seen = 0usize;
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        let mut next = unsafe { Thread32First(snapshot.as_raw_handle().cast(), &mut entry) };
        while next != 0 {
            seen += 1;
            if seen > 65_536 || std::time::Instant::now() >= deadline {
                return Err(ChildFailure("native_child_thread_bound"));
            }
            if entry.th32OwnerProcessID == pid && found.replace(entry.th32ThreadID).is_some() {
                return Err(ChildFailure("native_child_thread_ambiguous"));
            }
            next = unsafe { Thread32Next(snapshot.as_raw_handle().cast(), &mut entry) };
        }
        if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
            return Err(ChildFailure("native_child_thread_snapshot"));
        }
        let id = found.ok_or(ChildFailure("native_child_thread_missing"))?;
        let raw = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                id,
            )
        };
        if raw.is_null() {
            return Err(ChildFailure("native_child_thread_open"));
        }
        // SAFETY: OpenThread succeeded and returns an owned handle.
        let thread = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast()) };
        if unsafe { GetProcessIdOfThread(thread.as_raw_handle().cast()) } != pid {
            return Err(ChildFailure("native_child_thread_identity"));
        }
        // Exactly one suspension belongs to this launch; unexpected external
        // suspension or an already-running thread is refused without fallback.
        if unsafe { ResumeThread(thread.as_raw_handle().cast()) } != 1 {
            return Err(ChildFailure("native_child_thread_resume"));
        }
        Ok(())
    }
    fn terminate(&mut self) -> bool {
        use std::os::windows::io::AsRawHandle;
        if !self.armed {
            return true;
        }
        // SAFETY: only the unnamed owned job can be affected by this handle.
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(
                self.job.as_raw_handle().cast(),
                1,
            ) != 0
        }
    }
    async fn observe_exit(&self, child: &Child) -> bool {
        use windows_sys::Win32::{
            Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::WaitForSingleObject,
        };
        let Some(handle) = child.raw_handle() else {
            return false;
        };
        let deadline = Instant::now() + CHILD_GRACE;
        loop {
            let state = unsafe { WaitForSingleObject(handle.cast(), 0) };
            if state == WAIT_OBJECT_0 {
                return true;
            }
            if state != WAIT_TIMEOUT || Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    async fn finish(&mut self, reaped: bool, deadline: Instant) -> bool {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::*;
        loop {
            let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            let ok = unsafe {
                QueryInformationJobObject(
                    self.job.as_raw_handle().cast(),
                    JobObjectBasicAccountingInformation,
                    (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    std::mem::size_of_val(&info) as u32,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return false;
            }
            if info.ActiveProcesses == 0 {
                if reaped {
                    self.armed = false;
                }
                return reaped;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[cfg(not(any(unix, windows)))]
struct ProcessTree;
#[cfg(not(any(unix, windows)))]
impl ProcessTree {
    const NAME: &'static str = "unsupported";
    fn terminate(&mut self) -> bool {
        false
    }
    async fn observe_exit(&self, _: &Child) -> bool {
        false
    }
    async fn finish(&mut self, _: bool, _: Instant) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncWriteExt, ReadBuf};

    #[tokio::test]
    async fn binary_no_newline_and_terminal_controls_produce_only_fixed_metadata() {
        let secret = b"owned-synthetic-secret\xff\0\x1b[31mno-newline";
        let (mut writer, reader) = tokio::io::duplex(128);
        writer.write_all(secret).await.unwrap();
        drop(writer);
        let mut drain = Drain::start(reader);
        let flag = drain.failure_flag();
        let report = drain.wait().await;
        assert_eq!(report.outcome, DrainOutcome::Eof);
        assert_eq!(report.received_bytes, secret.len());
        assert!(!flag.load(Ordering::Acquire));
        let public = serde_json::to_string(&report).unwrap();
        assert!(!public.contains("owned-synthetic-secret"));
        assert!(!public.contains("no-newline"));
        assert_eq!(drain.finish().await, report);
    }

    #[tokio::test]
    async fn byte_flood_stops_at_exactly_one_bounded_overflow_probe() {
        let (mut writer, reader) = tokio::io::duplex(2048);
        writer.write_all(&[0xff; 1025]).await.unwrap();
        let mut drain = Drain::with_limits(
            reader,
            DrainLimits {
                bytes: 1024,
                ..Default::default()
            },
        );
        let flag = drain.failure_flag();
        let report = drain.wait().await;
        assert_eq!(report.outcome, DrainOutcome::ByteLimit);
        assert_eq!(report.received_bytes, 1025);
        assert!(flag.load(Ordering::Acquire));
        assert!(!report.released);
    }

    struct OneByte;
    impl AsyncRead for OneByte {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            output.put_slice(b"x");
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn tiny_chunks_have_an_independent_cpu_read_bound() {
        let mut drain = Drain::with_limits(
            OneByte,
            DrainLimits {
                reads: 5,
                ..Default::default()
            },
        );
        let report = drain.wait().await;
        assert_eq!(report.outcome, DrainOutcome::ReadLimit);
        assert_eq!(report.read_chunks, 5);
        assert_eq!(report.received_bytes, 5);
        assert!(drain.failure_flag().load(Ordering::Acquire));
    }

    struct FailedReader;
    impl AsyncRead for FailedReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            output.put_slice(b"private-child-source");
            Poll::Ready(Err(io::Error::other("private-child-error")))
        }
    }
    #[tokio::test]
    async fn read_failure_does_not_copy_the_io_error_or_partial_buffer() {
        let mut drain = Drain::start(FailedReader);
        let report = drain.wait().await;
        assert_eq!(report.outcome, DrainOutcome::ReadFailure);
        assert_eq!(report.received_bytes, 0);
        let text = format!("{report:?}");
        assert!(!text.contains("private-child"));
        assert!(drain.failure_flag().load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn an_open_idle_pipe_has_an_absolute_lifetime() {
        let (_writer, reader) = tokio::io::duplex(128);
        let mut drain = Drain::with_limits(
            reader,
            DrainLimits {
                lifetime: Duration::from_millis(10),
                ..Default::default()
            },
        );
        let report = drain.wait().await;
        assert_eq!(report.outcome, DrainOutcome::Lifetime);
        assert!(drain.failure_flag().load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn a_never_closed_pipe_is_aborted_and_joined_within_shutdown_bound() {
        let (_writer, reader) = tokio::io::duplex(128);
        let drain = Drain::start(reader);
        let flag = drain.failure_flag();
        let started = Instant::now();
        let report = drain.finish().await;
        assert_eq!(report.outcome, DrainOutcome::ShutdownTimeout);
        assert!(started.elapsed() < DRAIN_SHUTDOWN + Duration::from_millis(200));
        assert!(flag.load(Ordering::Acquire));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn owned_group_cleanup_kills_and_reaps_an_executed_child() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exec sleep 60"]);
        let mut child = OwnedChild::spawn(&mut command).await.unwrap();
        let id = child.child_mut().id().unwrap();
        let report = child.cleanup(false).await;
        assert!(report.cleaned && report.reaped);
        assert!(!report.exit_success);
        assert_eq!(report.ownership, "unix_process_group");
        assert!(unsafe { libc::kill(id as libc::pid_t, 0) } == -1);
        assert_eq!(child.cleanup(false).await, report);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn graceful_observation_does_not_reap_or_release_the_owned_group_id() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        let mut child = OwnedChild::spawn(&mut command).await.unwrap();
        #[cfg(target_os = "macos")]
        {
            assert!(child.tree.observe_exit(&child.child).await);
            assert!(child.tree.no_live_group_members());
        }
        let report = child.cleanup(true).await;
        assert!(report.cleaned && report.graceful_observed && report.exit_success);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn darwin_zombie_group_proof_rejects_a_live_descendant() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 60 & printf '%s\\n' \"$!\"; exit 0"]);
        let mut child = OwnedChild::spawn(&mut command).await.unwrap();
        let stdout = child.child_mut().stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        let descendant: libc::pid_t = tokio::time::timeout(CHILD_GRACE, lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .parse()
            .unwrap();
        assert!(descendant > 0);
        assert!(child.tree.observe_exit(&child.child).await);
        assert!(!child.tree.no_live_group_members());
        let report = child.cleanup(true).await;
        assert!(report.cleaned && report.graceful_observed && report.exit_success);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn suspended_windows_launch_is_job_owned_before_the_child_can_run() {
        let mut command = Command::new("cmd.exe");
        command.args(["/d", "/c", "exit", "0"]);
        let mut child = OwnedChild::spawn(&mut command).await.unwrap();
        let report = child.cleanup(true).await;
        assert!(report.cleaned && report.reaped && report.exit_success && report.graceful_observed);
        assert_eq!(report.ownership, "windows_job");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn atomic_job_list_owns_suspended_child_even_if_owner_dies_before_resume() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        let tree = ProcessTree::new().unwrap();
        let program = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
        let mut command = std::process::Command::new(program);
        command.args(["/d", "/c", "echo", "SOU96_MUST_NOT_EXECUTE"]);
        let mut child = super::super::windows_budget::launch::spawn_suspended(&command, &tree.job)
            .await
            .unwrap();
        let mut member = 0;
        assert_ne!(
            unsafe {
                IsProcessInJob(
                    child.raw_handle().unwrap().cast(),
                    tree.job.as_raw_handle().cast(),
                    &mut member,
                )
            },
            0
        );
        assert_eq!(member, 1);
        // Drop the last Job handle without resume, TerminateJobObject or a
        // direct kill. This is exactly the pre-execution owner-death window.
        drop(tree);
        let status = tokio::time::timeout(CHILD_REAP, child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(!status.success());
        let mut bytes = Vec::new();
        tokio::time::timeout(
            DRAIN_SHUTDOWN,
            child.stdout.take().unwrap().read_to_end(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(bytes.is_empty());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn atomic_launch_refuses_non_job_without_executing_child() {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::System::Threading::CreateEventW;
        let raw = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        assert!(!raw.is_null());
        let event = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast()) };
        let mut command = std::process::Command::new(
            std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join("System32")
                .join("cmd.exe"),
        );
        command.args(["/d", "/c", "echo", "SOU96_MUST_NOT_EXECUTE"]);
        let result = super::super::windows_budget::launch::spawn_suspended(&command, &event).await;
        assert!(matches!(result, Err("windows_budget_launch_refused")));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn job_assignment_failure_never_resumes_the_real_primary_thread() {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::System::Threading::*;
        let event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        assert!(!event.is_null());
        // A real non-Job kernel handle deliberately exercises the actual
        // AssignProcessToJobObject failure path, with no production fault knob.
        let mut tree = ProcessTree {
            job: Arc::new(unsafe {
                std::os::windows::io::OwnedHandle::from_raw_handle(event.cast())
            }),
            armed: true,
        };
        let mut command = Command::new("cmd.exe");
        command
            .args(["/d", "/c", "echo", "SOU96_MUST_NOT_EXECUTE"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
        let mut child = command.spawn().unwrap();
        assert_eq!(
            tree.assign_and_resume(&child),
            Err(ChildFailure("native_child_job_assign"))
        );
        assert!(!tree.terminate());
        child.start_kill().unwrap();
        tokio::time::timeout(CHILD_REAP, child.wait())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        assert!(
            bytes.is_empty(),
            "suspended assignment failure executed server code"
        );
    }
}
