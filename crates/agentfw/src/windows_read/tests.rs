// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)
use super::*;
use std::fs;
use std::os::windows::fs::OpenOptionsExt;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

// A real pending FSCTL, never a production race hook. The fixture owns its
// OVERLAPPED storage until cancellation/completion has been drained.
struct ExclusiveOplock {
    file: File,
    overlapped: Box<OVERLAPPED>,
    _event: OwnedHandle,
    pending: bool,
}

impl ExclusiveOplock {
    fn acquire(path: &Path) -> Self {
        let file = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(0x4000_0000) // FILE_FLAG_OVERLAPPED
            .open(path)
            .unwrap();
        let handle = unsafe { CreateEventW(null(), 1, 0, null()) };
        assert!(!handle.is_null());
        let event = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { zeroed() });
        overlapped.hEvent = event.as_raw_handle();
        let mut lock = Self {
            file,
            overlapped,
            _event: event,
            pending: false,
        };
        let mut returned = 0;
        let ok = unsafe {
            DeviceIoControl(
                lock.file.as_raw_handle(),
                0x0009_0000, // FSCTL_REQUEST_OPLOCK_LEVEL_1
                null(),
                0,
                null_mut(),
                0,
                &mut returned,
                lock.overlapped.as_mut(),
            )
        };
        let error = io::Error::last_os_error();
        lock.pending = ok == 0 && error.raw_os_error() == Some(ERROR_IO_PENDING as i32);
        assert!(
            lock.pending,
            "exclusive oplock fixture was not granted: {error}"
        );
        lock
    }
}

impl Drop for ExclusiveOplock {
    fn drop(&mut self) {
        if self.pending {
            let mut transferred = 0;
            unsafe {
                CancelIoEx(self.file.as_raw_handle(), self.overlapped.as_ref());
                GetOverlappedResult(
                    self.file.as_raw_handle(),
                    self.overlapped.as_ref(),
                    &mut transferred,
                    1,
                );
            }
        }
    }
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::create_dir(root.join("Workspace")).unwrap();
    (temp, root.join("Workspace"))
}

fn prepare(root: &Path, path: &str) -> anyhow::Result<PreparedRead> {
    let expected = root.join(path).canonicalize()?;
    PreparedRead::prepare(root, root, path, expected.to_str().unwrap())
}

fn junction(path: &Path, target: &Path) {
    fs::create_dir(path).unwrap();
    let target = trusted_absolute(target).unwrap();
    let substitute: Vec<u16> = format!("\\??\\{target}").encode_utf16().collect();
    let print: Vec<u16> = target.encode_utf16().collect();
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&0xa000_0003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
    let data_length = 8 + (substitute.len() + print.len() + 2) * 2;
    buffer.extend_from_slice(&(data_length as u16).to_le_bytes());
    buffer.extend_from_slice(&0u16.to_le_bytes());
    buffer.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
    buffer.extend_from_slice(&((substitute.len() * 2) as u16).to_le_bytes());
    buffer.extend_from_slice(&(((substitute.len() + 1) * 2) as u16).to_le_bytes());
    buffer.extend_from_slice(&((print.len() * 2) as u16).to_le_bytes());
    for unit in substitute.into_iter().chain([0]).chain(print).chain([0]) {
        buffer.extend_from_slice(&unit.to_le_bytes());
    }
    let directory = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .unwrap();
    let mut returned = 0;
    let ok = unsafe {
        DeviceIoControl(
            directory.as_raw_handle(),
            0x0009_00a4,
            buffer.as_ptr().cast(),
            buffer.len() as u32,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    };
    assert_ne!(
        ok,
        0,
        "junction fixture failed: {}",
        io::Error::last_os_error()
    );
}

#[tokio::test]
async fn reads_exact_regular_utf8_and_binds_identity() {
    let (_temp, root) = fixture();
    fs::create_dir(root.join("Docs")).unwrap();
    fs::write(root.join("Docs\\Readme.txt"), "hello\n世界").unwrap();
    let first = prepare(&root, "Docs\\Readme.txt").unwrap();
    let second = prepare(&root, "Docs\\Readme.txt").unwrap();
    assert_eq!(first.identity(), second.identity());
    assert_eq!(first.read_bounded(64).await.unwrap(), "hello\n世界");
}

#[tokio::test]
async fn bounded_utf8_contract_refuses_binary_and_oversize() {
    let (_temp, root) = fixture();
    fs::write(root.join("Binary.txt"), [0xff]).unwrap();
    fs::write(root.join("Large.txt"), b"12345").unwrap();
    assert!(prepare(&root, "Binary.txt")
        .unwrap()
        .read_bounded(64)
        .await
        .is_err());
    assert!(prepare(&root, "Large.txt")
        .unwrap()
        .read_bounded(4)
        .await
        .is_err());
    assert_eq!(
        prepare(&root, "Large.txt")
            .unwrap()
            .read_bounded(5)
            .await
            .unwrap(),
        "12345"
    );
}

#[test]
fn refuses_original_aliases_before_opening() {
    for path in [
        "",
        ".\\File",
        "..\\File",
        "Dir\\..\\File",
        "Dir\\.\\File",
        "Dir\\\\File",
        "File.",
        "File ",
        "File:secret",
        "C:File",
        "c:\\File",
        "\\File",
        "\\\\host\\share\\File",
        "\\\\?\\C:\\File",
        "Dir/File",
        "NUL.txt",
        "COM1",
        "LPT¹",
        "READM~1.TXT",
    ] {
        assert!(
            original_target("C:\\Workspace", path).is_err(),
            "accepted {path:?}"
        );
    }
}

#[test]
fn volume_root_open_uses_validated_nt_mapping() {
    for mapping in [
        "\\\\host\\share",
        "\\??\\UNC\\host\\share",
        "\\Device\\Mup\\host\\share",
        "\\??\\C:",
        "\\Device\\HarddiskVolume1\\Other",
        "\\Device\\HarddiskVolume",
        "\\Device\\HarddiskVolume1:stream",
        "\\device\\HarddiskVolume1",
    ] {
        assert!(volume_root_name(mapping).is_err(), "accepted {mapping:?}");
    }
    let (_temp, root) = fixture();
    let root = trusted_absolute(&root).unwrap();
    let drive = &root[..3];
    let mapping = drive_mapping(drive).unwrap();
    let name = volume_root_name(&mapping).unwrap();
    assert_eq!(name, format!("{mapping}\\"));
    // The acquisition function takes this fixed NT name with no DOS root
    // handle. It has no drive-letter name left to resolve during the open.
    let direct = open_native(None, &name, true, false).unwrap();
    assert_eq!(
        check_directory(&direct).unwrap(),
        check_directory(&open_drive(drive).unwrap()).unwrap()
    );
}

#[test]
fn refuses_case_aliases_and_hard_links() {
    let (_temp, root) = fixture();
    fs::write(root.join("Readme.txt"), b"inside").unwrap();
    assert!(prepare(&root, "README.TXT").is_err());
    fs::hard_link(root.join("Readme.txt"), root.join("Alias.txt")).unwrap();
    assert!(prepare(&root, "Readme.txt").is_err());
    assert!(prepare(&root, "Alias.txt").is_err());
}

#[test]
fn refuses_nonregular_and_outside_targets() {
    let (_temp, root) = fixture();
    fs::create_dir(root.join("Directory")).unwrap();
    assert!(prepare(&root, "Directory").is_err());
    let outside = root.parent().unwrap().join("Outside.txt");
    fs::write(&outside, b"outside").unwrap();
    let raw_outside = trusted_absolute(&outside).unwrap();
    assert!(PreparedRead::prepare(&root, &root, &raw_outside, outside.to_str().unwrap()).is_err());
    assert!(
        PreparedRead::prepare(&root, &root, "..\\Outside.txt", outside.to_str().unwrap()).is_err()
    );
}

#[tokio::test]
async fn metadata_pin_prevents_root_ancestor_leaf_swap_and_writer() {
    let (_temp, root) = fixture();
    fs::create_dir(root.join("Docs")).unwrap();
    fs::write(root.join("Docs\\Readme.txt"), b"inside").unwrap();
    let prepared = prepare(&root, "Docs\\Readme.txt").unwrap();
    let outer = root.parent().unwrap();
    assert!(fs::rename(outer, outer.with_file_name("MovedFixture")).is_err());
    assert!(fs::rename(&root, root.with_file_name("MovedWorkspace")).is_err());
    assert!(fs::rename(root.join("Docs"), root.join("MovedDocs")).is_err());
    assert!(fs::rename(root.join("Docs\\Readme.txt"), root.join("Moved.txt")).is_err());
    assert!(fs::OpenOptions::new()
        .write(true)
        .open(root.join("Docs\\Readme.txt"))
        .is_err());
    // The pin's FILE_EXECUTE right permits sharing enforcement, but no
    // FILE_READ_DATA is granted. The executor never maps or executes the
    // file, and an actual ReadFile through this handle must be denied.
    let mut byte = [0];
    let mut transferred = 0;
    let ok = unsafe {
        ReadFile(
            prepared.leaf.as_raw_handle(),
            byte.as_mut_ptr(),
            1,
            &mut transferred,
            null_mut(),
        )
    };
    assert_eq!(ok, 0);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(5));
    assert_eq!(prepared.read_bounded(64).await.unwrap(), "inside");
}

#[test]
fn standard_user_junction_is_refused_as_root_and_ancestor() {
    let (_temp, root) = fixture();
    let outside = root.parent().unwrap().join("Outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("Secret.txt"), b"outside").unwrap();
    let link = root.join("Junction");
    junction(&link, &outside);
    let expected = link.join("Secret.txt");
    assert!(PreparedRead::prepare(
        &root,
        &root,
        "Junction\\Secret.txt",
        expected.to_str().unwrap()
    )
    .is_err());
    assert!(PreparedRead::prepare(&link, &link, "Secret.txt", expected.to_str().unwrap()).is_err());
}

#[test]
fn leaf_replaced_before_prepare_is_bound_to_new_identity() {
    let (_temp, root) = fixture();
    let leaf = root.join("Readme.txt");
    fs::write(&leaf, b"first").unwrap();
    let identity = prepare(&root, "Readme.txt").unwrap().identity().clone();
    fs::rename(&leaf, root.join("Retained.txt")).unwrap();
    fs::write(&leaf, b"replacement").unwrap();
    assert_ne!(prepare(&root, "Readme.txt").unwrap().identity(), &identity);
}

#[test]
fn canceled_worker_refuses_before_acquiring_data_access() {
    let (_temp, root) = fixture();
    fs::write(root.join("Readme.txt"), b"inside").unwrap();
    let prepared = prepare(&root, "Readme.txt").unwrap();
    let canceled = AtomicBool::new(true);
    assert!(prepared
        .read_on_worker(64, &canceled)
        .unwrap_err()
        .to_string()
        .contains("canceled"));
    let token = Arc::new(AtomicBool::new(false));
    drop(CancelRead(Arc::clone(&token)));
    assert!(token.load(Ordering::Acquire));
}

#[test]
fn refuses_existing_write_or_delete_handles() {
    let (_temp, root) = fixture();
    let path = root.join("Readme.txt");
    fs::write(&path, b"inside").unwrap();
    let writer = fs::OpenOptions::new()
        .write(true)
        .share_mode(7)
        .open(&path)
        .unwrap();
    assert!(prepare(&root, "Readme.txt").is_err());
    drop(writer);
    let deleter = fs::OpenOptions::new()
        .access_mode(0x0001_0000)
        .share_mode(7)
        .open(&path)
        .unwrap();
    assert!(prepare(&root, "Readme.txt").is_err());
    drop(deleter);
    assert!(prepare(&root, "Readme.txt").is_ok());
}

#[test]
fn oplock_does_not_stall_metadata_preparation_or_data_open() {
    let (_temp, root) = fixture();
    let path = root.join("Readme.txt");
    fs::write(&path, b"inside").unwrap();
    let canonical = path.canonicalize().unwrap().to_str().unwrap().to_owned();
    let lock = ExclusiveOplock::acquire(&path);
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker_root = root.clone();
    let worker = std::thread::spawn(move || {
        sender
            .send(PreparedRead::prepare(
                &worker_root,
                &worker_root,
                "Readme.txt",
                &canonical,
            ))
            .unwrap();
    });
    // A share-counted leaf pin includes FILE_EXECUTE, so an existing
    // exclusive oplock must refuse promptly before its owner acknowledges.
    let prepared = receiver.recv_timeout(Duration::from_secs(2));
    if prepared.is_err() {
        drop(lock);
        worker.join().unwrap();
        panic!("metadata preparation stalled behind an exclusive oplock");
    }
    worker.join().unwrap();
    let error = prepared.unwrap().unwrap_err().to_string();
    assert!(
        error.contains("class=leaf-metadata") && error.contains("NTSTATUS=0x00000108"),
        "{error}"
    );
    drop(lock);

    // Independently exercise the same production data-open helper with a
    // retained parent chain, while this target has no admitted leaf pin.
    // A real admitted pin would already have refused the exclusive oplock.
    fs::write(root.join("Anchor.txt"), b"anchor").unwrap();
    let pinned_parent = prepare(&root, "Anchor.txt").unwrap();
    let parent = pinned_parent
        .directories
        .last()
        .unwrap()
        .file
        .try_clone()
        .unwrap();
    let lock = ExclusiveOplock::acquire(&path);
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        sender
            .send(open_child(&parent, "Readme.txt", false, true))
            .unwrap();
    });
    let result = receiver.recv_timeout(Duration::from_secs(2));
    if result.is_err() {
        drop(lock);
        worker.join().unwrap();
        panic!("data open stalled instead of refusing an unacknowledged oplock break");
    }
    worker.join().unwrap();
    let error = result.unwrap().unwrap_err().to_string();
    assert!(
        error.contains("class=leaf-data") && error.contains("NTSTATUS=0x00000108"),
        "{error}"
    );
    drop(lock);
}

#[test]
#[ignore = "requires Windows Developer Mode or SeCreateSymbolicLinkPrivilege; junction coverage is mandatory"]
fn refuses_symlink_when_creation_is_available() {
    let (_temp, root) = fixture();
    fs::write(root.join("Readme.txt"), b"inside").unwrap();
    std::os::windows::fs::symlink_file(root.join("Readme.txt"), root.join("Link.txt")).unwrap();
    assert!(prepare(&root, "Link.txt").is_err());
}
