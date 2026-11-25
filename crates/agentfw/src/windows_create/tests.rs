// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)
use super::*;
use std::fs;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::OwnedHandle;
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let parent = temporary.path().canonicalize().unwrap();
    let workspace = parent.join("Workspace");
    fs::create_dir(&workspace).unwrap();
    (temporary, workspace)
}

fn prepare(root: &Path, leaf: &str, content: &str) -> Result<PreparedCreate, CreateFileError> {
    PreparedCreate::prepare(root, root, leaf, root.join(leaf).to_str().unwrap(), content)
}

fn entries(root: &Path) -> Vec<String> {
    let mut result: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    result.sort();
    result
}

fn junction(path: &Path, target: &Path) {
    fs::create_dir(path).unwrap();
    let target = target
        .to_str()
        .unwrap()
        .strip_prefix("\\\\?\\")
        .unwrap_or(target.to_str().unwrap());
    let substitute: Vec<u16> = format!("\\??\\{target}").encode_utf16().collect();
    let print: Vec<u16> = target.encode_utf16().collect();
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&0xa000_0003u32.to_le_bytes());
    let data_length = 8 + (substitute.len() + print.len() + 2) * 2;
    buffer.extend_from_slice(&(data_length as u16).to_le_bytes());
    buffer.extend_from_slice(&0u16.to_le_bytes());
    buffer.extend_from_slice(&0u16.to_le_bytes());
    buffer.extend_from_slice(&((substitute.len() * 2) as u16).to_le_bytes());
    buffer.extend_from_slice(&(((substitute.len() + 1) * 2) as u16).to_le_bytes());
    buffer.extend_from_slice(&((print.len() * 2) as u16).to_le_bytes());
    for unit in substitute.into_iter().chain([0]).chain(print).chain([0]) {
        buffer.extend_from_slice(&unit.to_le_bytes());
    }
    let directory = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .unwrap();
    let mut returned = 0;
    assert_ne!(
        unsafe {
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
        },
        0,
        "junction fixture: {}",
        std::io::Error::last_os_error()
    );
}

fn link_to(file: &File, parent: &File, name: &str) -> i32 {
    let target: Vec<u16> = name.encode_utf16().collect();
    let offset = offset_of!(LinkInformation, file_name);
    let length = (offset + target.len() * 2).max(size_of::<LinkInformation>());
    let mut words = vec![0usize; length.div_ceil(size_of::<usize>())];
    let information = words.as_mut_ptr().cast::<LinkInformation>();
    unsafe {
        (*information).root_directory = parent.as_raw_handle();
        (*information).file_name_length = (target.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            target.as_ptr(),
            words.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
            target.len(),
        );
    }
    let mut result = IoStatusBlock::default();
    unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut result,
            information.cast(),
            length as u32,
            FILE_LINK_INFORMATION_CLASS,
        )
    }
}

fn open_stage_with_access(staged: &StagedCreate, access: u32) -> Result<File, i32> {
    let mut name: Vec<u16> = staged.stage_name.encode_utf16().collect();
    let mut unicode = UnicodeString {
        length: (name.len() * 2) as u16,
        maximum_length: (name.len() * 2) as u16,
        buffer: name.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: staged.prepared.parent.root().as_raw_handle(),
        object_name: &mut unicode,
        attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        security_descriptor: null_mut(),
        security_quality_of_service: null_mut(),
    };
    let mut status = IoStatusBlock::default();
    let mut raw = null_mut();
    let opened = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &attributes,
            &mut status,
            null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE
                | FILE_OPEN_REPARSE_POINT
                | FILE_OPEN_NO_RECALL
                | FILE_COMPLETE_IF_OPLOCKED,
            null(),
            0,
        )
    };
    eprintln!(
        "{}",
        serde_json::json!({
            "event":"windows_create_stage_access_probe","desired_access":access,
            "open_ntstatus":opened,"partial_bytes":staged.staged_bytes
        })
    );
    if opened != 0 {
        if !raw.is_null() && raw != INVALID_HANDLE_VALUE {
            drop(unsafe { File::from_raw_handle(raw) });
        }
        return Err(opened);
    }
    assert!(!raw.is_null() && raw != INVALID_HANDLE_VALUE);
    Ok(unsafe { File::from_raw_handle(raw) })
}

fn assert_no_data_or_link(file: &File, outside: &File, access: u32, leaf: &str) {
    let mut byte = [0u8; 1];
    let mut read = 0;
    let event =
        unsafe { windows_sys::Win32::System::Threading::CreateEventW(null(), 1, 0, null()) };
    assert!(!event.is_null());
    let event = unsafe { OwnedHandle::from_raw_handle(event) };
    let mut overlapped: windows_sys::Win32::System::IO::OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.as_raw_handle();
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::ReadFile(
            file.as_raw_handle(),
            byte.as_mut_ptr(),
            1,
            &mut read,
            &mut overlapped,
        )
    };
    let read_error = std::io::Error::last_os_error().raw_os_error();
    if ok == 0 && read_error == Some(997) {
        // Even unexpected pending I/O must drain before test buffers and
        // OVERLAPPED storage are destroyed.
        unsafe {
            windows_sys::Win32::System::IO::CancelIoEx(file.as_raw_handle(), &overlapped);
            windows_sys::Win32::System::IO::GetOverlappedResult(
                file.as_raw_handle(),
                &overlapped,
                &mut read,
                1,
            );
        }
    }
    assert_eq!(ok, 0, "metadata/zero-access handle read partial data");
    assert_eq!(read_error, Some(5));
    assert_eq!(read, 0);
    let linked = link_to(file, outside, leaf);
    eprintln!(
        "{}",
        serde_json::json!({
            "event":"windows_create_stage_access_probe","desired_access":access,
            "link_ntstatus":linked,"partial_bytes":3
        })
    );
    assert_ne!(
        linked, 0,
        "metadata/zero-access source linked a partial private stage outside its authorized root"
    );
}

pub(super) fn assert_partial_stage_privacy(staged: &StagedCreate) {
    assert_eq!(staged.staged_bytes, 3);
    let outside_path = Path::new(staged.prepared.parent.canonical())
        .parent()
        .unwrap()
        .join("ForeignDirectory");
    // This independent sibling was made before preparation. It is not a
    // pinned ancestor; a control link proves target permissions and sharing
    // cannot manufacture a false-negative source-security result.
    let outside = fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&outside_path)
        .unwrap();
    let control = File::open(outside_path.join("Control.txt")).unwrap();
    assert_eq!(
        link_to(&control, &outside, "ControlLink.txt"),
        0,
        "independent target control link failed"
    );
    // Neither probe requests SYNCHRONIZE or a synchronous-I/O option.
    // DesiredAccess=0 is distinct: ACLs cannot deny an empty access mask,
    // and FileLinkInformation documents no specific source right.
    for (access, leaf) in [
        (FILE_READ_ATTRIBUTES, "ForeignAttributes.txt"),
        (0, "ForeignZero.txt"),
        (0x100, "ForeignWriteAttributes.txt"),
    ] {
        match open_stage_with_access(staged, access) {
            Ok(file) => {
                assert_no_data_or_link(&file, &outside, access, leaf);
                assert_ne!(
                    access, 0x100,
                    "private partial stage granted FILE_WRITE_ATTRIBUTES"
                );
            }
            Err(status) => {
                assert_eq!(
                    status, 0xc000_0022u32 as i32,
                    "source refusal was not the expected ACL denial"
                );
            }
        }
        assert!(!outside_path.join(leaf).exists());
    }
}

#[test]
fn partial_stage_acl_denies_data_and_foreign_link() {
    let (_temporary, root) = fixture();
    let foreign = root.parent().unwrap().join("ForeignDirectory");
    fs::create_dir(&foreign).unwrap();
    fs::write(foreign.join("Control.txt"), b"control bytes").unwrap();
    let result = prepare(&root, "New.txt", "abcdef")
        .unwrap()
        .stage_with_fault(Fault::ProbePrivacy)
        .unwrap_err();
    assert_eq!(result.code, "stage_privacy_probe_complete");
    assert_eq!(result.staged_bytes, 3);
    assert!(!result.committed);
    assert!(entries(&root).is_empty());
    assert!(!foreign.join("ForeignAttributes.txt").exists());
    assert!(!foreign.join("ForeignZero.txt").exists());
    assert!(!foreign.join("ForeignWriteAttributes.txt").exists());
}

#[test]
fn preparation_has_no_effects_and_binds_exact_root() {
    let (_temporary, root) = fixture();
    let first = prepare(&root, "New.txt", "not yet written").unwrap();
    let second = prepare(&root, "New.txt", "not yet written").unwrap();
    assert_eq!(first.identity(), second.identity());
    assert!(entries(&root).is_empty());
    drop(first);
    drop(second);
    assert!(entries(&root).is_empty());
    // Startup authority validation deliberately accepts existing targets;
    // the separate per-call prepare still refuses them without mutations.
    fs::write(root.join("Existing.txt"), b"original").unwrap();
    let (_parent, leaf) = CreateParent::prepare(
        &root,
        &root,
        "Existing.txt",
        root.join("Existing.txt").to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(leaf, "Existing.txt");
    assert!(prepare(&root, "Existing.txt", "replacement").is_err());
    assert_eq!(fs::read(root.join("Existing.txt")).unwrap(), b"original");
}

#[test]
fn publishes_complete_utf8_empty_and_bounded_bytes() {
    let (_temporary, root) = fixture();
    for (leaf, content) in [
        ("Unicode.txt", "Привет\n世界".to_owned()),
        ("Empty.txt", String::new()),
        ("Bound.txt", "x".repeat(MAX_CREATE_BYTES)),
    ] {
        let staged = prepare(&root, leaf, &content).unwrap().stage().unwrap();
        assert!(!root.join(leaf).exists());
        assert_eq!(
            entries(&root)
                .iter()
                .filter(|name| name.starts_with(".soup-wall-create-"))
                .count(),
            1
        );
        let result = staged.publish().unwrap();
        assert!(result.committed && result.file_synced);
        assert!(!result.directory_synced);
        assert_eq!(result.bytes_written, content.len());
        assert_eq!(fs::read_to_string(root.join(leaf)).unwrap(), content);
        assert!(!entries(&root)
            .iter()
            .any(|name| name.starts_with(".soup-wall-create-")));
    }
    let error = prepare(&root, "TooLarge.txt", &"é".repeat(MAX_CREATE_BYTES / 2 + 1)).unwrap_err();
    assert_eq!(error.code, "content_too_large");
    assert!(!error.committed);
    assert!(!root.join("TooLarge.txt").exists());
}

#[test]
fn prepared_content_is_immutable_and_absolute_path_is_exact() {
    let (_temporary, root) = fixture();
    let mut content = "approved original".to_owned();
    let absolute = root.join("Absolute.txt");
    let original = absolute
        .to_str()
        .unwrap()
        .strip_prefix("\\\\?\\")
        .unwrap_or(absolute.to_str().unwrap());
    let prepared =
        PreparedCreate::prepare(&root, &root, original, absolute.to_str().unwrap(), &content)
            .unwrap();
    content.clear();
    content.push_str("substitution");
    prepared.stage().unwrap().publish().unwrap();
    assert_eq!(fs::read(absolute).unwrap(), b"approved original");
    assert!(PreparedCreate::prepare(
        &root,
        &root,
        "Other.txt",
        root.join("Alias.txt").to_str().unwrap(),
        "no"
    )
    .is_err());
}

#[test]
fn refuses_namespace_aliases_nested_and_outside_paths_without_effects() {
    let (_temporary, root) = fixture();
    for leaf in [
        "",
        ".",
        "..",
        "..\\Outside.txt",
        ".\\New.txt",
        "Dir\\New.txt",
        "Dir/Name.txt",
        "New.txt.",
        "New.txt ",
        "New.txt:stream",
        "NUL.txt",
        "COM1",
        "LPT¹",
        "NEWFIL~1.TXT",
        "\\New.txt",
        "C:New.txt",
        "\\\\host\\share\\New.txt",
        "\\\\?\\C:\\New.txt",
    ] {
        assert!(prepare(&root, leaf, "no").is_err(), "accepted {leaf:?}");
        assert!(entries(&root).is_empty());
    }
    let parent = root.parent().unwrap();
    assert!(PreparedCreate::prepare(
        &root,
        parent,
        "New.txt",
        parent.join("New.txt").to_str().unwrap(),
        "no"
    )
    .is_err());
    assert!(prepare(&root, &"x".repeat(256), "no").is_err());
    assert!(entries(&root).is_empty());
}

#[test]
fn refuses_existing_case_alias_directory_hardlink_and_junction() {
    let (_temporary, root) = fixture();
    fs::write(root.join("Existing.txt"), b"preserved").unwrap();
    fs::hard_link(root.join("Existing.txt"), root.join("Hard.txt")).unwrap();
    fs::create_dir(root.join("Directory")).unwrap();
    let outside = root.parent().unwrap().join("Outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("Witness.txt"), b"outside unchanged").unwrap();
    junction(&root.join("Junction"), &outside);
    for leaf in [
        "Existing.txt",
        "EXISTING.TXT",
        "Hard.txt",
        "Directory",
        "Junction",
    ] {
        assert!(
            prepare(&root, leaf, "overwrite").is_err(),
            "accepted {leaf}"
        );
    }
    assert_eq!(fs::read(root.join("Existing.txt")).unwrap(), b"preserved");
    assert_eq!(
        fs::read(outside.join("Witness.txt")).unwrap(),
        b"outside unchanged"
    );
    assert!(!entries(&root)
        .iter()
        .any(|name| name.starts_with(".soup-wall-create-")));
}

#[test]
fn parent_and_ancestor_replacement_are_excluded_by_retained_pins() {
    let (_temporary, root) = fixture();
    let parent = root.parent().unwrap();
    let prepared = prepare(&root, "New.txt", "inside").unwrap();
    assert!(fs::rename(&root, parent.join("MovedWorkspace")).is_err());
    assert!(fs::rename(parent, parent.with_extension("moved")).is_err());
    let writer = fs::OpenOptions::new()
        .access_mode(FILE_WRITE_DATA)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&root);
    assert!(
        writer.is_err(),
        "write-sharing pin did not exclude parent writer"
    );
    prepared.stage().unwrap().publish().unwrap();
    assert_eq!(fs::read(root.join("New.txt")).unwrap(), b"inside");
}

#[test]
fn racing_creator_survives_without_partial_or_replaced_target() {
    for competitor in ["Race.txt", "RACE.TXT"] {
        let (_temporary, root) = fixture();
        let staged = prepare(&root, "Race.txt", "our complete content")
            .unwrap()
            .stage()
            .unwrap();
        fs::write(root.join(competitor), b"competing complete content").unwrap();
        let result = staged.publish().unwrap_err();
        assert_eq!(result.code, "target_exists");
        assert!(!result.committed);
        assert_eq!(result.staged_bytes, "our complete content".len());
        assert_eq!(result.committed_bytes, 0);
        assert_eq!(
            fs::read(root.join(competitor)).unwrap(),
            b"competing complete content"
        );
        assert_eq!(entries(&root), [competitor]);
    }
}

#[test]
fn concurrent_publications_have_exactly_one_complete_winner() {
    let (_temporary, root) = fixture();
    let first = prepare(&root, "Race.txt", &"a".repeat(MAX_CREATE_BYTES))
        .unwrap()
        .stage()
        .unwrap();
    let second = prepare(&root, "Race.txt", &"b".repeat(MAX_CREATE_BYTES))
        .unwrap()
        .stage()
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let waiting = Arc::clone(&barrier);
    let first = std::thread::spawn(move || {
        waiting.wait();
        first.publish()
    });
    let second = std::thread::spawn(move || {
        barrier.wait();
        second.publish()
    });
    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome
                .as_ref()
                .is_err_and(|error| error.code == "target_exists" && !error.committed))
            .count(),
        1
    );
    let bytes = fs::read(root.join("Race.txt")).unwrap();
    assert_eq!(bytes.len(), MAX_CREATE_BYTES);
    assert!(bytes.iter().all(|byte| *byte == b'a') || bytes.iter().all(|byte| *byte == b'b'));
    assert_eq!(entries(&root), ["Race.txt"]);
}

#[test]
fn partial_write_failure_accounts_real_bytes_and_removes_only_owned_stage() {
    let (_temporary, root) = fixture();
    fs::write(root.join(".soup-wall-create-foreign.tmp"), b"foreign").unwrap();
    let result = prepare(&root, "New.txt", "abcdef")
        .unwrap()
        .stage_with_fault(Fault::PartialWrite(3))
        .unwrap_err();
    assert_eq!(result.code, "stage_write_failed");
    assert_eq!(result.staged_bytes, 3);
    assert!(!result.committed);
    assert_eq!(result.committed_bytes, 0);
    assert_eq!(entries(&root), [".soup-wall-create-foreign.tmp"]);
    assert_eq!(
        fs::read(root.join(".soup-wall-create-foreign.tmp")).unwrap(),
        b"foreign"
    );
}

#[test]
fn flush_and_publication_failures_leave_no_target_and_account_staging() {
    let (_temporary, root) = fixture();
    let content = "complete but not published";
    let flush = prepare(&root, "New.txt", content)
        .unwrap()
        .stage_with_fault(Fault::Flush)
        .unwrap_err();
    assert_eq!(flush.code, "stage_sync_failed");
    assert_eq!(flush.staged_bytes, content.len());
    assert!(!flush.committed && entries(&root).is_empty());
    let publish = prepare(&root, "New.txt", content)
        .unwrap()
        .stage()
        .unwrap()
        .publish_with_fault(Fault::BeforePublish)
        .unwrap_err();
    assert_eq!(publish.code, "publish_failed");
    assert_eq!(publish.staged_bytes, content.len());
    assert!(!publish.committed && entries(&root).is_empty());
}

#[test]
fn post_publication_failure_keeps_complete_effect_and_true_accounting() {
    let (_temporary, root) = fixture();
    let result = prepare(&root, "New.txt", "actual effect")
        .unwrap()
        .stage()
        .unwrap()
        .publish_with_fault(Fault::AfterPublish)
        .unwrap_err();
    assert_eq!(result.code, "published_sync_failed");
    assert!(result.committed);
    assert_eq!(result.staged_bytes, "actual effect".len());
    assert_eq!(result.committed_bytes, "actual effect".len());
    assert_eq!(fs::read(root.join("New.txt")).unwrap(), b"actual effect");
    assert_eq!(entries(&root), ["New.txt"]);
}

#[test]
fn canceled_stage_is_exclusive_then_cleaned_and_continuation_is_useful() {
    let (_temporary, root) = fixture();
    let staged = prepare(&root, "New.txt", "canceled content")
        .unwrap()
        .stage()
        .unwrap();
    let temporary_name = entries(&root).pop().unwrap();
    assert!(fs::write(root.join(&temporary_name), b"replacement").is_err());
    assert!(fs::rename(root.join(&temporary_name), root.join("Stolen.txt")).is_err());
    assert!(!root.join("New.txt").exists());
    drop(staged);
    assert!(entries(&root).is_empty());
    // A foreign object reusing a former temporary spelling is never deleted
    // by a later operation: cleanup has no pathname deletion operation.
    fs::write(root.join(&temporary_name), b"foreign reuse").unwrap();
    prepare(&root, "New.txt", "useful continuation")
        .unwrap()
        .stage()
        .unwrap()
        .publish()
        .unwrap();
    assert_eq!(
        fs::read(root.join("New.txt")).unwrap(),
        b"useful continuation"
    );
    assert_eq!(
        fs::read(root.join(temporary_name)).unwrap(),
        b"foreign reuse"
    );
    // A real metadata-only handle can delay original-link DOC cleanup.
    // Publication still happened: the error must retain committed bytes.
    let staged = prepare(&root, "Cleanup.txt", "committed despite held metadata")
        .unwrap()
        .stage()
        .unwrap();
    let owned_name = staged.stage_name.clone();
    let held = open_stage_with_access(&staged, FILE_READ_ATTRIBUTES).unwrap();
    let result = staged.publish().unwrap_err();
    assert_eq!(result.code, "windows_create_stage_cleanup_unverified");
    assert!(result.committed);
    assert_eq!(
        result.committed_bytes,
        "committed despite held metadata".len()
    );
    drop(held);
    assert!(!root.join(owned_name).exists());
    assert_eq!(
        fs::read(root.join("Cleanup.txt")).unwrap(),
        b"committed despite held metadata"
    );
}

#[test]
fn process_interruption_cleans_stage_and_preserves_published_link() {
    // These variables exist only in this cfg(test) function, never in the
    // production executor. The same libtest entry is a real killable child.
    if let Some(root) = std::env::var_os("SOU60_CREATE_TEST_CHILD_WORKSPACE") {
        let root = std::path::PathBuf::from(root);
        let mode = std::env::var("SOU60_CREATE_TEST_CHILD_MODE").unwrap();
        let mut staged = prepare(&root, "New.txt", "complete interrupted bytes")
            .unwrap()
            .stage()
            .unwrap();
        if mode == "published" {
            staged.link().unwrap();
        }
        fs::write(root.parent().unwrap().join("Ready.txt"), mode).unwrap();
        // Hold all handles and temp link live until parent TerminateProcess.
        std::hint::black_box(&staged);
        loop {
            std::thread::park();
        }
    }
    for mode in ["stage", "published"] {
        let (_temporary, root) = fixture();
        let ready = root.parent().unwrap().join("Ready.txt");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows_create::tests::process_interruption_cleans_stage_and_preserves_published_link", "--nocapture"])
            .env("SOU60_CREATE_TEST_CHILD_WORKSPACE", &root)
            .env("SOU60_CREATE_TEST_CHILD_MODE", mode)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !ready.exists() && Instant::now() < deadline {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("native interruption child exited before witness: {status}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !ready.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("native interruption witness timed out");
        }
        assert_eq!(fs::read_to_string(&ready).unwrap(), mode);
        assert!(entries(&root)
            .iter()
            .any(|entry| entry.starts_with(".soup-wall-create-")));
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        if mode == "published" {
            assert_eq!(
                fs::read(root.join("New.txt")).unwrap(),
                b"complete interrupted bytes"
            );
            assert_eq!(entries(&root), ["New.txt"]);
        } else {
            assert!(entries(&root).is_empty());
        }
    }
}
