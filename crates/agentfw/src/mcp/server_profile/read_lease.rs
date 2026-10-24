// SPDX-License-Identifier: Apache-2.0
//! Bounded, revocable local-file proofs for one pending Ask. No lease is ever
//! reacquired. A pending or forced break permanently invalidates that proof.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) use linux::{Guard, Owner};

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub(super) struct Owner;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub(super) struct Guard;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
impl Owner {
    pub(super) fn new(_file: &std::fs::File) -> Option<std::sync::Arc<Self>> {
        None
    }
    pub(super) fn acquire(
        self: &std::sync::Arc<Self>,
        _file: &std::fs::File,
    ) -> anyhow::Result<Option<std::sync::Arc<Guard>>> {
        Ok(None)
    }
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
impl Guard {
    pub(super) fn valid(&self) -> bool {
        false
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use std::{
        fs::File,
        os::fd::AsRawFd,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc, Arc, Mutex, Weak,
        },
        thread,
        time::Duration,
    };

    // A Python profile has more large extension/data files than the smaller
    // filesystem profile. Keep the per-Ask descriptor budget bounded, while
    // allowing more of those proofs to avoid rehashing large pinned inputs.
    const MAX_LEASES: usize = 256;
    // Several pending calls share a collector process. Never multiply the
    // larger per-Ask allowance into thousands of retained descriptors.
    const MAX_PROCESS_LEASES: usize = 512;
    static ACTIVE_LEASES: AtomicUsize = AtomicUsize::new(0);

    struct LeaseSlot;
    impl LeaseSlot {
        fn acquire() -> Option<Self> {
            let mut current = ACTIVE_LEASES.load(Ordering::Relaxed);
            while current < MAX_PROCESS_LEASES {
                match ACTIVE_LEASES.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return Some(Self),
                    Err(observed) => current = observed,
                }
            }
            None
        }
    }
    impl Drop for LeaseSlot {
        fn drop(&mut self) {
            ACTIVE_LEASES.fetch_sub(1, Ordering::AcqRel);
        }
    }
    const F_SETOWN_EX: libc::c_int = 15;
    const F_GETOWN_EX: libc::c_int = 16;
    const F_GETSIG: libc::c_int = 11;
    const F_OWNER_TID: libc::c_int = 0;
    #[repr(C)]
    struct SignalOwner {
        kind: libc::c_int,
        pid: libc::pid_t,
    }

    struct FileState {
        file: File,
        broken: AtomicBool,
        // Declared after file: return the slot only after closing its FD.
        _slot: LeaseSlot,
    }
    struct Shared {
        alive: AtomicBool,
        stop: AtomicBool,
        files: Mutex<Vec<Weak<FileState>>>,
    }
    pub(crate) struct Owner {
        shared: Arc<Shared>,
        tid: libc::pid_t,
        worker: Mutex<Option<thread::JoinHandle<()>>>,
    }
    // The worker upgrades only FileState, never Owner: final proof disposal
    // cannot make the worker join itself. The private FD closes before Owner.
    pub(crate) struct Guard {
        state: Arc<FileState>,
        owner: Arc<Owner>,
    }

    fn local(file: &File) -> bool {
        let mut value = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(file.as_raw_fd(), value.as_mut_ptr()) } != 0 {
            return false;
        }
        // A successful lease on CIFS locallease/FUSE need not cover remote or
        // userspace changes. Layered/remote/unknown filesystems always rehash.
        local_magic(unsafe { value.assume_init() }.f_type as u64)
    }

    fn local_magic(kind: u64) -> bool {
        matches!(kind, 0xef53 | 0x5846_5342 | 0x9123_683e | 0x0102_1994)
    }

    impl Owner {
        pub(crate) fn new(file: &File) -> Option<Arc<Self>> {
            if !local(file) {
                return None;
            }
            let shared = Arc::new(Shared {
                alive: AtomicBool::new(false),
                stop: AtomicBool::new(false),
                files: Mutex::new(Vec::new()),
            });
            let (send, receive) = mpsc::sync_channel(1);
            let state = Arc::clone(&shared);
            let worker = thread::Builder::new()
                .name("mcp-input-leases".into())
                .spawn(move || {
                    // Publish the TID only after blocking its thread-directed SIGIO.
                    // Never restore this mask: a pending signal dies with this thread.
                    let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
                    unsafe {
                        libc::sigemptyset(&mut set);
                        libc::sigaddset(&mut set, libc::SIGIO);
                    }
                    if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) }
                        != 0
                    {
                        let _ = send.send(None);
                        return;
                    }
                    struct Liveness(Arc<Shared>);
                    impl Drop for Liveness {
                        fn drop(&mut self) {
                            self.0.alive.store(false, Ordering::Release);
                        }
                    }
                    let _liveness = Liveness(Arc::clone(&state));
                    state.alive.store(true, Ordering::Release);
                    if send
                        .send(Some(
                            unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t
                        ))
                        .is_err()
                    {
                        return;
                    }
                    while !state.stop.load(Ordering::Acquire) {
                        let timeout = libc::timespec {
                            tv_sec: 0,
                            tv_nsec: 50_000_000,
                        };
                        let signal =
                            unsafe { libc::sigtimedwait(&set, std::ptr::null_mut(), &timeout) };
                        if signal < 0 {
                            if matches!(
                                std::io::Error::last_os_error().raw_os_error(),
                                Some(libc::EAGAIN | libc::EINTR)
                            ) {
                                continue;
                            }
                            return;
                        }
                        let Ok(files) = state.files.lock() else {
                            return;
                        };
                        for file in files.iter().filter_map(Weak::upgrade) {
                            if unsafe { libc::fcntl(file.file.as_raw_fd(), libc::F_GETLEASE) }
                                != libc::F_RDLCK
                            {
                                file.broken.store(true, Ordering::Release);
                                // Release writers promptly; validity is sticky before
                                // unlocking, so cancellation of their open cannot heal it.
                                unsafe {
                                    libc::fcntl(
                                        file.file.as_raw_fd(),
                                        libc::F_SETLEASE,
                                        libc::F_UNLCK,
                                    );
                                }
                            }
                        }
                    }
                })
                .ok()?;
            let tid = match receive.recv_timeout(Duration::from_secs(1)) {
                Ok(Some(tid)) => tid,
                _ => {
                    shared.stop.store(true, Ordering::Release);
                    return None;
                }
            };
            Some(Arc::new(Self {
                shared,
                tid,
                worker: Mutex::new(Some(worker)),
            }))
        }

        pub(crate) fn acquire(self: &Arc<Self>, file: &File) -> anyhow::Result<Option<Arc<Guard>>> {
            if !self.shared.alive.load(Ordering::Acquire) || !local(file) {
                return Ok(None);
            }
            let Ok(mut files) = self.shared.files.lock() else {
                return Ok(None);
            };
            if files.len() >= MAX_LEASES {
                return Ok(None);
            }
            let Some(slot) = LeaseSlot::acquire() else {
                return Ok(None);
            };
            // A private CLOEXEC duplicate of this very open file description;
            // never inherited by the server/owner or returned to another caller.
            let Ok(file) = file.try_clone() else {
                return Ok(None);
            };
            let fd = file.as_raw_fd();
            let expected = SignalOwner {
                kind: F_OWNER_TID,
                pid: self.tid,
            };
            if unsafe { libc::fcntl(fd, F_SETOWN_EX, &expected) } != 0 {
                return Ok(None);
            }
            let mut observed = SignalOwner { kind: -1, pid: -1 };
            if unsafe { libc::fcntl(fd, F_GETOWN_EX, &mut observed) } != 0
                || observed.kind != expected.kind
                || observed.pid != expected.pid
            {
                return Ok(None);
            }
            // No alternate/queued signal: default SIGIO remains thread directed.
            if unsafe { libc::fcntl(fd, F_GETSIG) } != 0 {
                return Ok(None);
            }
            if unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_RDLCK) } != 0 {
                return Ok(None);
            }
            let state = Arc::new(FileState {
                file,
                broken: AtomicBool::new(false),
                _slot: slot,
            });
            files.push(Arc::downgrade(&state));
            drop(files);
            let guard = Arc::new(Guard {
                state,
                owner: Arc::clone(self),
            });
            anyhow::ensure!(
                guard.valid(),
                "selected asset read lease lost during capture"
            );
            Ok(Some(guard))
        }
    }

    impl Drop for Owner {
        fn drop(&mut self) {
            self.shared.stop.store(true, Ordering::Release);
            if let Ok(mut worker) = self.worker.lock() {
                if let Some(worker) = worker.take() {
                    let _ = worker.join();
                }
            }
        }
    }

    impl Guard {
        pub(crate) fn valid(&self) -> bool {
            let live = || {
                self.owner.shared.alive.load(Ordering::Acquire)
                    && !self.state.broken.load(Ordering::Acquire)
            };
            let valid = live()
                && unsafe { libc::fcntl(self.state.file.as_raw_fd(), libc::F_GETLEASE) }
                    == libc::F_RDLCK
                && live();
            if !valid {
                self.state.broken.store(true, Ordering::Release);
            }
            valid
        }
    }
    #[cfg(test)]
    mod native_tests {
        include!("read_lease/native_tests.rs");
    }
}
