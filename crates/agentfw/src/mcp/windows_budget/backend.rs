// SPDX-License-Identifier: Apache-2.0
//! Localized extension of the existing native-child Job owner.

use super::Config;
use serde::Serialize;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
        WAIT_TIMEOUT,
    },
    System::{JobObjects::*, SystemServices::*, IO::*},
};

const POLL: Duration = Duration::from_millis(10);

fn set<T>(job: HANDLE, class: JOBOBJECTINFOCLASS, info: &T) -> Result<(), &'static str> {
    // SAFETY: callers pair SDK information classes with their complete types;
    // the owned handle remains live throughout this synchronous call.
    if unsafe {
        SetInformationJobObject(
            job,
            class,
            (info as *const T).cast(),
            std::mem::size_of::<T>() as u32,
        )
    } == 0
    {
        return Err("windows_budget_job_configure");
    }
    Ok(())
}

fn query<T: Default>(job: HANDLE, class: JOBOBJECTINFOCLASS) -> Result<T, &'static str> {
    let mut info = T::default();
    // SAFETY: see set(); every query is a fixed-size initialized SDK structure.
    if unsafe {
        QueryInformationJobObject(
            job,
            class,
            (&mut info as *mut T).cast(),
            std::mem::size_of::<T>() as u32,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err("windows_budget_observation_failed");
    }
    Ok(info)
}

#[derive(Default, Clone, Serialize)]
struct State {
    reason: Option<&'static str>,
    closed: bool,
    peak_committed_bytes: u64,
    peak_active_processes: u32,
    total_processes: u32,
    cpu_user_100ns: u64,
    cpu_kernel_100ns: u64,
    samples: u64,
}

struct Inner {
    job: Arc<OwnedHandle>,
    port: OwnedHandle,
    config: Config,
    started: Instant,
    state: Mutex<State>,
}

#[derive(Clone)]
pub(crate) struct Guard(Arc<Inner>);

impl Guard {
    fn observe(&self, state: &mut State) -> Result<(), &'static str> {
        let job = self.0.job.as_raw_handle().cast();
        let limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
            query(job, JobObjectExtendedLimitInformation)?;
        let counts: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
            query(job, JobObjectBasicAccountingInformation)?;
        let config = &self.0.config;
        if limits.BasicLimitInformation.LimitFlags != Self::flags()
            || limits.JobMemoryLimit as u64 != config.memory_max_bytes
            || limits.BasicLimitInformation.ActiveProcessLimit != config.active_process_max
            || limits.BasicLimitInformation.PerJobUserTimeLimit
                != (config.cpu_user_millis * 10_000) as i64
        {
            return Err("windows_budget_limit_drift");
        }
        state.peak_committed_bytes = state
            .peak_committed_bytes
            .max(limits.PeakJobMemoryUsed as u64);
        state.peak_active_processes = state.peak_active_processes.max(counts.ActiveProcesses);
        state.total_processes = counts.TotalProcesses;
        state.cpu_user_100ns = counts.TotalUserTime.max(0) as u64;
        state.cpu_kernel_100ns = counts.TotalKernelTime.max(0) as u64;
        state.samples = state.samples.saturating_add(1);
        if state.peak_committed_bytes >= config.memory_pressure_bytes {
            return Err("windows_budget_memory_pressure");
        }
        if counts.ActiveProcesses >= config.active_process_max {
            return Err("windows_budget_process_saturation");
        }
        if state.cpu_user_100ns >= config.cpu_user_millis * 10_000 {
            return Err("windows_budget_cpu_time");
        }
        // Drain only our private completion port. Neither PID nor message data
        // grants kill authority; termination always uses the original Job handle.
        for _ in 0..1024 {
            let (mut message, mut key, mut overlapped) = (0, 0, std::ptr::null_mut());
            let ok = unsafe {
                GetQueuedCompletionStatus(
                    self.0.port.as_raw_handle().cast(),
                    &mut message,
                    &mut key,
                    &mut overlapped,
                    0,
                )
            };
            if ok == 0 {
                if unsafe { GetLastError() } == WAIT_TIMEOUT && overlapped.is_null() {
                    return Ok(());
                }
                return Err("windows_budget_observation_failed");
            }
            if key != 1 {
                return Err("windows_budget_observation_failed");
            }
            match message {
                JOB_OBJECT_MSG_JOB_MEMORY_LIMIT | JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT => {
                    return Err("windows_budget_memory_limit")
                }
                JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT => return Err("windows_budget_process_limit"),
                JOB_OBJECT_MSG_END_OF_JOB_TIME => return Err("windows_budget_cpu_time"),
                JOB_OBJECT_MSG_NOTIFICATION_LIMIT => {
                    let violation: JOBOBJECT_LIMIT_VIOLATION_INFORMATION =
                        query(job, JobObjectLimitViolationInformation)?;
                    if violation.ViolationLimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY != 0 {
                        return Err("windows_budget_memory_pressure");
                    }
                }
                _ => {}
            }
        }
        Err("windows_budget_observation_bound")
    }

    fn flags() -> u32 {
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_TIME
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, State>, &'static str> {
        self.0.state.lock().map_err(|_| {
            unsafe {
                TerminateJobObject(self.0.job.as_raw_handle().cast(), 1);
            }
            "windows_budget_observation_failed"
        })
    }

    fn check_locked(&self, state: &mut State) -> Result<(), &'static str> {
        if let Some(reason) = state.reason {
            return Err(reason);
        }
        if state.closed {
            return Ok(());
        }
        let result = if self.0.started.elapsed() >= Duration::from_millis(self.0.config.wall_millis)
        {
            Err("windows_budget_wall_deadline")
        } else {
            self.observe(state)
        };
        if let Err(reason) = result {
            // Publish sticky terminal state while holding the same gate checked
            // at every host write/flush poll. No later response reopens the gate.
            state.reason = Some(reason);
            unsafe {
                TerminateJobObject(self.0.job.as_raw_handle().cast(), 1);
            }
        }
        result
    }

    pub(crate) fn check(&self) -> Result<(), &'static str> {
        let mut state = self.state()?;
        self.check_locked(&mut state)
    }

    pub(crate) fn with_output<T>(&self, output: impl FnOnce() -> T) -> Result<T, &'static str> {
        let mut state = self.state()?;
        self.check_locked(&mut state)?;
        // Serialize write submission with publication of terminal budget state.
        // A Pending poll releases the gate and must recheck it when repolled.
        Ok(output())
    }

    pub(crate) fn report(&self) -> serde_json::Value {
        match self.0.state.lock() {
            Ok(state) => serde_json::json!({"format":super::FORMAT,"configuration":self.0.config,
                "configuration_sha256":self.0.config.identity(),"observed":*state,
                "elapsed_millis":self.0.started.elapsed().as_millis(),"poll_millis":POLL.as_millis(),
                "scope":"aggregate_committed_memory_active_processes_user_cpu_time_wall",
                "filesystem_network_confinement":false}),
            Err(_) => {
                serde_json::json!({"format":super::FORMAT,"reason":"windows_budget_observation_failed"})
            }
        }
    }
}

pub(crate) struct Budget {
    guard: Guard,
    task: tokio::task::JoinHandle<()>,
}

impl Budget {
    /// Must complete before assigning/resuming the suspended primary thread.
    pub(crate) fn install(job: Arc<OwnedHandle>, config: Config) -> Result<Self, &'static str> {
        let handle = job.as_raw_handle().cast();
        let memory = usize::try_from(config.memory_max_bytes)
            .map_err(|_| "windows_budget_architecture_unsupported")?;
        let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: Guard::flags(),
                ActiveProcessLimit: config.active_process_max,
                PerJobUserTimeLimit: (config.cpu_user_millis * 10_000) as i64,
                ..Default::default()
            },
            JobMemoryLimit: memory,
            ..Default::default()
        };
        set(handle, JobObjectExtendedLimitInformation, &limits)?;
        set(
            handle,
            JobObjectEndOfJobTimeInformation,
            &JOBOBJECT_END_OF_JOB_TIME_INFORMATION {
                EndOfJobTimeAction: JOB_OBJECT_TERMINATE_AT_END_OF_JOB,
            },
        )?;
        let raw =
            unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 1) };
        if raw.is_null() {
            return Err("windows_budget_completion_port");
        }
        // SAFETY: a successful creation transfers a private owned kernel handle.
        let port = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        if unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err("windows_budget_completion_port");
        }
        set(
            handle,
            JobObjectAssociateCompletionPortInformation,
            &JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
                CompletionKey: std::ptr::without_provenance_mut(1),
                CompletionPort: port.as_raw_handle().cast(),
            },
        )?;
        set(
            handle,
            JobObjectNotificationLimitInformation,
            &JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION {
                LimitFlags: JOB_OBJECT_LIMIT_JOB_MEMORY,
                JobMemoryLimit: config.memory_pressure_bytes,
                ..Default::default()
            },
        )?;
        let guard = Guard(Arc::new(Inner {
            job,
            port,
            config,
            started: Instant::now(),
            state: Mutex::new(State::default()),
        }));
        guard.check()?;
        let weak = Arc::downgrade(&guard.0);
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(POLL).await;
                let Some(inner) = weak.upgrade() else { break };
                if Guard(inner).check().is_err() {
                    break;
                }
            }
        });
        Ok(Self { guard, task })
    }
    pub(crate) fn guard(&self) -> Guard {
        self.guard.clone()
    }

    pub(crate) fn finish(&mut self, cleanup_verified: bool) {
        // Capture exhaustion during graceful/reap cleanup before publishing the
        // final transport outcome. Then stop the timer of the verified empty
        // Job: later HTTP/session retirement cannot expire completed child work.
        let _ = self.guard.check();
        if let Ok(mut state) = self.guard.0.state.lock() {
            if !cleanup_verified && state.reason.is_none() {
                state.reason = Some("windows_budget_cleanup_unverified");
                unsafe {
                    TerminateJobObject(self.guard.0.job.as_raw_handle().cast(), 1);
                }
            }
            state.closed = true;
        }
        self.task.abort();
    }
}

impl Drop for Budget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn real_job_deadline_is_terminal_and_the_handle_is_private() {
        use windows_sys::Win32::Foundation::GetHandleInformation;
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        assert!(!raw.is_null());
        let job = Arc::new(unsafe { OwnedHandle::from_raw_handle(raw.cast()) });
        let config = Config::read(br#"{"format":"sw-mcp/windows-job-budget/1","memoryMaxBytes":134217728,"memoryPressureBytes":100663296,"activeProcessMax":8,"cpuUserMillis":2000,"wallMillis":1000}"#).unwrap();
        let budget = Budget::install(job.clone(), config.clone()).unwrap();
        let mut flags = 0;
        assert_ne!(
            unsafe { GetHandleInformation(job.as_raw_handle().cast(), &mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        let guard = budget.guard();
        assert!(guard.check().is_ok());
        assert_eq!(guard.report()["configuration_sha256"], config.identity());
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(guard.check(), Err("windows_budget_wall_deadline"));
        assert_eq!(guard.check(), Err("windows_budget_wall_deadline"));
        assert_eq!(
            guard.report()["observed"]["reason"],
            "windows_budget_wall_deadline"
        );
    }

    #[tokio::test]
    async fn finished_empty_job_stops_its_deadline_without_reopening_a_failure() {
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        assert!(!raw.is_null());
        let job = Arc::new(unsafe { OwnedHandle::from_raw_handle(raw.cast()) });
        let config = Config::read(br#"{"format":"sw-mcp/windows-job-budget/1","memoryMaxBytes":134217728,"memoryPressureBytes":100663296,"activeProcessMax":8,"cpuUserMillis":2000,"wallMillis":1000}"#).unwrap();
        let mut budget = Budget::install(job.clone(), config).unwrap();
        let counts: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = query(
            job.as_raw_handle().cast(),
            JobObjectBasicAccountingInformation,
        )
        .unwrap();
        assert_eq!(counts.ActiveProcesses, 0);
        budget.finish(true);
        let guard = budget.guard();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(guard.check().is_ok());
        assert_eq!(guard.report()["observed"]["closed"], true);
        assert!(guard.report()["observed"]["reason"].is_null());
    }
}
