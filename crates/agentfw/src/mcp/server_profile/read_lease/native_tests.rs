// SPDX-License-Identifier: Apache-2.0
// Included as linux::native_tests, so these controls can inspect the private
// kernel proof without adding a production test hook or changing the protocol.

use super::*;
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    process::{Command, Stdio},
    time::Instant,
};

use super::super::super::verified_inputs::{Inputs, Verification};

const FIXTURE_BYTES: usize = 131_072;
const FIXTURE_DIRECTORY: &str = "SOU124_LEASE_FIXTURE_DIR";

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    file: File,
}

impl Fixture {
    fn new(required: bool) -> Self {
        let root = std::env::var_os(FIXTURE_DIRECTORY);
        assert!(
            !required || root.is_some(),
            "native qualification requires {FIXTURE_DIRECTORY} on an allowed local filesystem"
        );
        let directory = match root {
            Some(root) => tempfile::Builder::new()
                .prefix("sou124-read-lease-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::Builder::new()
                .prefix("sou124-read-lease-")
                .tempdir()
                .unwrap(),
        };
        let path = directory.path().join("asset");
        fs::write(&path, vec![b'A'; FIXTURE_BYTES]).unwrap();
        let file = File::open(&path).unwrap();
        Self {
            _directory: directory,
            path,
            file,
        }
    }
}

struct Leased {
    _directory: tempfile::TempDir,
    path: PathBuf,
    owner: Arc<Owner>,
    guard: Arc<Guard>,
}

fn assert_fullhash_fallback(fixture: &Fixture) {
    let mut inputs = Inputs::default();
    let digest = Verification::Capture(&mut inputs)
        .digest(&fixture.path, FIXTURE_BYTES as u64)
        .unwrap();
    assert_eq!(inputs.counts(), (0, 0, 1));
    inputs.validate_leases().unwrap();
    assert_eq!(
        Verification::Resume(&inputs)
            .digest(&fixture.path, FIXTURE_BYTES as u64)
            .unwrap(),
        digest
    );
    fs::write(&fixture.path, vec![b'B'; FIXTURE_BYTES]).unwrap();
    assert!(Verification::Resume(&inputs)
        .digest(&fixture.path, FIXTURE_BYTES as u64)
        .is_err());
}

fn leased(required: bool) -> Option<Leased> {
    let fixture = Fixture::new(required);
    let owner = Owner::new(&fixture.file);
    let proof = owner
        .as_ref()
        .and_then(|owner| owner.acquire(&fixture.file).unwrap());
    let Some(guard) = proof else {
        assert!(
            !required,
            "native qualification needs an unprivileged owner and working local read leases; local={}, uid={}, euid={}",
            local(&fixture.file),
            fixture.file.metadata().unwrap().uid(),
            unsafe { libc::geteuid() }
        );
        eprintln!(
            "sou124_native_read_lease: unsupported fixture; asserting fullhash fallback; native fast path remains unqualified"
        );
        assert_fullhash_fallback(&fixture);
        return None;
    };
    assert!(guard.valid());
    let Fixture {
        _directory,
        path,
        file,
    } = fixture;
    // acquire duplicates the open file description. Drop the caller's copy so
    // proof disposal is what closes its final descriptor in the controls below.
    drop(file);
    Some(Leased {
        _directory,
        path,
        owner: owner.unwrap(),
        guard,
    })
}

fn lease_type(guard: &Guard) -> libc::c_int {
    unsafe { libc::fcntl(guard.state.file.as_raw_fd(), libc::F_GETLEASE) }
}

fn wait_until(mut predicate: impl FnMut() -> bool, reason: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !predicate() {
        assert!(Instant::now() < deadline, "{reason}");
        thread::sleep(Duration::from_millis(1));
    }
}

fn nonblocking_writer(path: &std::path::Path) {
    let result = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path);
    assert!(
        matches!(result, Err(ref error) if error.raw_os_error() == Some(libc::EWOULDBLOCK)),
        "a live read lease must reject the nonblocking write open: {result:?}"
    );
}

fn reuse_control(required: bool) {
    let fixture = Fixture::new(required);
    let mut inputs = Inputs::default();
    let digest = Verification::Capture(&mut inputs)
        .digest(&fixture.path, FIXTURE_BYTES as u64)
        .unwrap();
    if inputs.counts() == (0, 0, 1) {
        assert!(
            !required,
            "native qualification did not establish a read lease"
        );
        eprintln!(
            "sou124_native_read_lease_reuse: fullhash fallback; native fast path remains unqualified"
        );
        assert_eq!(
            Verification::Resume(&inputs)
                .digest(&fixture.path, FIXTURE_BYTES as u64)
                .unwrap(),
            digest
        );
        fs::write(&fixture.path, vec![b'B'; FIXTURE_BYTES]).unwrap();
        assert!(Verification::Resume(&inputs)
            .digest(&fixture.path, FIXTURE_BYTES as u64)
            .is_err());
        return;
    }
    assert_eq!(inputs.counts(), (0, 1, 0));
    inputs.validate_leases().unwrap();
    for _ in 0..2 {
        assert_eq!(
            Verification::Resume(&inputs)
                .digest(&fixture.path, FIXTURE_BYTES as u64)
                .unwrap(),
            digest
        );
        assert_eq!(inputs.counts(), (0, 1, 0));
        inputs.validate_leases().unwrap();
    }
    // This open performs no write and changes no asset metadata. Losing the
    // lease alone must refuse resume rather than returning the saved SHA.
    nonblocking_writer(&fixture.path);
    assert!(inputs.validate_leases().is_err());
    assert!(Verification::Resume(&inputs)
        .digest(&fixture.path, FIXTURE_BYTES as u64)
        .is_err());
}

fn pending_break_control(required: bool) {
    let Some(lease) = leased(required) else {
        return;
    };
    // Hold the registry so the worker cannot convert the pending break into an
    // explicit unlock before the synchronous F_GETLEASE witness observes it.
    let registry = lease.owner.shared.files.lock().unwrap();
    nonblocking_writer(&lease.path);
    assert_eq!(lease_type(&lease.guard), libc::F_UNLCK);
    assert!(!lease.guard.valid());
    assert!(lease.guard.state.broken.load(Ordering::Acquire));
    drop(registry);
    // The nonblocking writer has already cancelled its open. It cannot heal
    // either the kernel's pending break or the proof's sticky failure.
    assert!(!lease.guard.valid());
}

fn lost_lease_control(required: bool) {
    let Some(lease) = leased(required) else {
        return;
    };
    let fd = lease.guard.state.file.as_raw_fd();
    // A private unlock models forced expiry without editing global sysctls or
    // making the test wait for the host's lease-break timeout.
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_UNLCK) },
        0
    );
    assert_eq!(lease_type(&lease.guard), libc::F_UNLCK);
    assert!(!lease.guard.valid());
    // Deliberately restore a kernel lease only in this adversarial control.
    // Production never reacquires; even restoration must not heal this proof.
    let owner = SignalOwner {
        kind: F_OWNER_TID,
        pid: lease.owner.tid,
    };
    assert_eq!(unsafe { libc::fcntl(fd, F_SETOWN_EX, &owner) }, 0);
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_RDLCK) },
        0
    );
    assert_eq!(lease_type(&lease.guard), libc::F_RDLCK);
    assert!(!lease.guard.valid());
}

struct WritableMapping {
    address: *mut libc::c_void,
    length: usize,
}

impl Drop for WritableMapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.address, self.length);
        }
    }
}

fn writable_mapping_control(required: bool) {
    let Some(lease) = leased(required) else {
        return;
    };
    let Leased {
        _directory,
        path,
        owner,
        guard,
    } = lease;
    drop(guard);
    let writable = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            writable.as_raw_fd(),
            0,
        )
    };
    assert_ne!(address, libc::MAP_FAILED);
    let mapping = WritableMapping {
        address,
        length: 4096,
    };
    // A writable mapping retains its write authority after the ordinary FD is
    // closed. Acquisition must still fail, and verification must rehash.
    drop(writable);
    let readonly = File::open(&path).unwrap();
    assert!(owner.acquire(&readonly).unwrap().is_none());
    let mut inputs = Inputs::default();
    Verification::Capture(&mut inputs)
        .digest(&path, FIXTURE_BYTES as u64)
        .unwrap();
    assert_eq!(inputs.counts(), (0, 0, 1));
    unsafe {
        *mapping.address.cast::<u8>() = b'B';
    }
    assert_eq!(
        unsafe { libc::msync(mapping.address, mapping.length, libc::MS_SYNC) },
        0
    );
    assert!(Verification::Resume(&inputs)
        .digest(&path, FIXTURE_BYTES as u64)
        .is_err());
}

fn independent_owners_control(required: bool) {
    let Some(first) = leased(required) else {
        return;
    };
    let second_file = File::open(&first.path).unwrap();
    let second_owner = Owner::new(&second_file).unwrap();
    let second_guard = second_owner.acquire(&second_file).unwrap().unwrap();
    drop(second_file);
    assert!(!Arc::ptr_eq(&first.owner, &second_owner));
    assert_ne!(first.owner.tid, second_owner.tid);
    for (guard, expected_tid) in [
        (&first.guard, first.owner.tid),
        (&second_guard, second_owner.tid),
    ] {
        let mut observed = SignalOwner { kind: -1, pid: -1 };
        assert_eq!(
            unsafe { libc::fcntl(guard.state.file.as_raw_fd(), F_GETOWN_EX, &mut observed) },
            0
        );
        assert_eq!((observed.kind, observed.pid), (F_OWNER_TID, expected_tid));
        assert!(guard.valid());
    }
    nonblocking_writer(&first.path);
    assert!(!first.guard.valid());
    assert!(!second_guard.valid());
}

fn disposal_control(required: bool) {
    let Some(lease) = leased(required) else {
        return;
    };
    let Leased {
        _directory,
        path,
        owner,
        guard,
    } = lease;
    let registry = owner.shared.files.lock().unwrap();
    let (send, receive) = mpsc::sync_channel(1);
    let writer = thread::spawn(move || {
        let result = OpenOptions::new().write(true).open(path).map(drop);
        let _ = send.send(result);
    });
    wait_until(
        || lease_type(&guard) == libc::F_UNLCK,
        "blocking writer did not enter the lease break",
    );
    assert!(matches!(receive.try_recv(), Err(mpsc::TryRecvError::Empty)));
    // The worker remains unable to unlock. Disposal/cancellation alone must
    // close the last proof FD and let the already blocked writer complete.
    drop(guard);
    let result = receive.recv_timeout(Duration::from_secs(3));
    drop(registry);
    result
        .expect("proof disposal did not release the blocked writer")
        .unwrap();
    writer.join().unwrap();
}

fn cloexec_control(required: bool) {
    let Some(lease) = leased(required) else {
        return;
    };
    let fd = lease.guard.state.file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    let output = Command::new("/bin/sh")
        .args([
            "-c",
            "if [ /proc/self/fd/\"$1\" -ef \"$2\" ]; then exit 91; fi",
            "sou124-lease-fd-check",
        ])
        .arg(fd.to_string())
        .arg(&lease.path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "private lease FD survived exec: {output:?}"
    );
    assert!(lease.guard.valid());
}

fn capacity_control(required: bool) {
    let Some(lease) = leased(required) else {
        return;
    };
    let Leased {
        _directory,
        path,
        owner,
        guard,
    } = lease;
    let mut guards = vec![guard];
    for _ in 1..MAX_LEASES {
        let file = File::open(&path).unwrap();
        guards.push(owner.acquire(&file).unwrap().unwrap());
    }
    assert_eq!(owner.shared.files.lock().unwrap().len(), MAX_LEASES);
    let overflow = File::open(&path).unwrap();
    assert!(owner.acquire(&overflow).unwrap().is_none());
    assert!(guards.iter().all(|guard| guard.valid()));
    drop(guards);
    // An Ask's proof slots are never evicted and reused after disposal.
    assert!(owner.acquire(&overflow).unwrap().is_none());
}

fn worker_loss_control(required: bool) {
    let Some(lease) = leased(required) else {
        return;
    };
    lease.owner.shared.stop.store(true, Ordering::Release);
    wait_until(
        || !lease.owner.shared.alive.load(Ordering::Acquire),
        "lease worker did not acknowledge shutdown",
    );
    assert_eq!(lease_type(&lease.guard), libc::F_RDLCK);
    assert!(!lease.guard.valid());
}

#[test]
fn capture_resume_reuses_a_real_lease_or_asserts_fullhash_fallback() {
    reuse_control(false);
}

#[test]
fn cancelled_nonblocking_writer_leaves_a_visible_sticky_break() {
    pending_break_control(false);
}

#[test]
fn private_forced_unlock_equivalent_cannot_heal_a_proof() {
    lost_lease_control(false);
}

#[test]
fn writable_mapping_prevents_acquisition_and_uses_fullhash() {
    writable_mapping_control(false);
}

#[test]
fn simultaneous_ask_owners_keep_independent_kernel_proofs() {
    independent_owners_control(false);
}

#[test]
fn proof_disposal_releases_an_already_blocked_writer() {
    disposal_control(false);
}

#[test]
fn private_lease_descriptor_is_absent_from_an_exec_child() {
    cloexec_control(false);
}

#[test]
fn lease_capacity_refuses_overflow_and_never_recycles_proofs() {
    capacity_control(false);
}

#[test]
fn worker_loss_refuses_even_when_the_kernel_lease_remains() {
    worker_loss_control(false);
}

#[test]
fn only_explicit_local_filesystem_types_are_eligible() {
    for kind in [0xef53, 0x5846_5342, 0x9123_683e, 0x0102_1994] {
        assert!(local_magic(kind), "allowed local filesystem {kind:#x}");
    }
    for kind in [
        0,
        u64::MAX,
        0x794c_7630, // overlay
        0x6573_5546, // FUSE
        0x6969,      // NFS
        0xff53_4d42, // CIFS
        0xfe53_4d42, // SMB2
        0x9fa0,      // procfs
    ] {
        assert!(!local_magic(kind), "unsupported filesystem {kind:#x}");
    }
    let proc_file = File::open("/proc/self/status").unwrap();
    assert!(!local(&proc_file));
    assert!(Owner::new(&proc_file).is_none());
}

#[test]
fn unprivileged_caller_cannot_lease_foreign_owned_files() {
    let file = File::open("/bin/sh").unwrap();
    assert_eq!(file.metadata().unwrap().uid(), 0);
    if unsafe { libc::geteuid() } == 0 {
        // Root is the owner here, so this fixture cannot prove foreign-owner
        // refusal. The mandatory native qualification separately forbids root.
        return;
    }
    if let Some(owner) = Owner::new(&file) {
        assert!(owner.acquire(&file).unwrap().is_none());
    }
}

#[test]
#[ignore = "native Linux qualification: set SOU124_LEASE_FIXTURE_DIR on an allowed local filesystem and run as its unprivileged owner"]
fn native_read_lease_fast_path_qualification_requires_real_proofs() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "use an unprivileged fixture owner"
    );
    reuse_control(true);
    pending_break_control(true);
    lost_lease_control(true);
    writable_mapping_control(true);
    independent_owners_control(true);
    disposal_control(true);
    cloexec_control(true);
    capacity_control(true);
    worker_loss_control(true);
}
