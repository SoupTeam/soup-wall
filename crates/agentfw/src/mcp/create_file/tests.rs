// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)
use super::*;

#[test]
fn validates_content_and_exact_direct_leaf_before_any_effects() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = PinnedWorkspace::open(directory.path()).unwrap();
    for path in [
        "",
        ".",
        "..",
        "../outside",
        "dir/file",
        "./file",
        "file/",
        "a\\b",
        "a\n",
    ] {
        assert!(
            PreparedCreate::prepare(&workspace, Path::new(path), "safe").is_err(),
            "{path:?}"
        );
    }
    assert!(PreparedCreate::prepare(
        &workspace,
        Path::new("file"),
        &"x".repeat(MAX_CREATE_BYTES + 1)
    )
    .is_err());
    assert!(directory.path().read_dir().unwrap().next().is_none());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_refuses_without_creating_any_entry() {
    let directory = tempfile::tempdir().unwrap();
    let workspace = PinnedWorkspace::open(directory.path()).unwrap();
    let error = PreparedCreate::prepare(&workspace, Path::new("safe.txt"), "text").unwrap_err();
    assert_eq!(error.code, "unsupported_platform");
    assert!(!error.committed);
    assert!(directory.path().read_dir().unwrap().next().is_none());
}

#[cfg(target_os = "linux")]
mod linux_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::{Arc, Barrier};

    #[test]
    fn creates_exact_utf8_private_file_and_accepts_empty_content() {
        let directory = tempfile::tempdir().unwrap();
        let workspace = PinnedWorkspace::open(directory.path()).unwrap();
        let request =
            PreparedCreate::prepare(&workspace, Path::new("new.txt"), "Привет\n").unwrap();
        assert!(directory.path().read_dir().unwrap().next().is_none());
        let result = request.execute().unwrap();
        assert!(result.committed && result.file_synced && result.directory_synced);
        let target = directory.path().join("new.txt");
        assert_eq!(std::fs::read(&target).unwrap(), "Привет\n".as_bytes());
        let metadata = target.metadata().unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(result.bytes_written, "Привет\n".len());
        PreparedCreate::prepare(&workspace, Path::new("empty.txt"), "")
            .unwrap()
            .execute()
            .unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("empty.txt")).unwrap(),
            b""
        );
    }

    #[test]
    fn refuses_every_existing_leaf_type_without_opening_or_changing_it() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("original"), "unchanged").unwrap();
        std::fs::write(directory.path().join("regular"), "keep").unwrap();
        std::fs::hard_link(
            outside.path().join("original"),
            directory.path().join("hardlink"),
        )
        .unwrap();
        symlink(
            outside.path().join("original"),
            directory.path().join("symlink"),
        )
        .unwrap();
        std::fs::create_dir(directory.path().join("directory")).unwrap();
        let fifo = std::ffi::CString::new(directory.path().join("fifo").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let _socket =
            std::os::unix::net::UnixListener::bind(directory.path().join("socket")).unwrap();
        let workspace = PinnedWorkspace::open(directory.path()).unwrap();
        for leaf in [
            "regular",
            "hardlink",
            "symlink",
            "directory",
            "fifo",
            "socket",
        ] {
            let error =
                PreparedCreate::prepare(&workspace, Path::new(leaf), "overwrite").unwrap_err();
            assert_eq!(error.code, "target_exists");
            assert!(!error.committed);
        }
        assert_eq!(
            std::fs::read(outside.path().join("original")).unwrap(),
            b"unchanged"
        );
        assert_eq!(
            std::fs::read(directory.path().join("regular")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn substitution_after_prepare_refuses_both_original_and_replacement_roots() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("workspace");
        let moved = parent.path().join("moved");
        std::fs::create_dir(&root).unwrap();
        let workspace = PinnedWorkspace::open(&root).unwrap();
        let request = PreparedCreate::prepare(&workspace, Path::new("new.txt"), "secret").unwrap();
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir(&root).unwrap();
        let error = request.execute().unwrap_err();
        assert_eq!(error.code, "workspace_root_substituted");
        assert!(!error.committed);
        assert!(root.read_dir().unwrap().next().is_none());
        assert!(moved.read_dir().unwrap().next().is_none());
    }

    #[test]
    fn moved_nested_parent_is_refused_instead_of_becoming_an_outside_write_handle() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        let workspace = PinnedWorkspace::open(root.path()).unwrap();
        assert!(PreparedCreate::prepare(&workspace, Path::new("nested/new.txt"), "no").is_err());
        std::fs::rename(root.path().join("nested"), outside.path().join("moved")).unwrap();
        assert!(PreparedCreate::prepare(&workspace, Path::new("nested/new.txt"), "no").is_err());
        assert!(outside
            .path()
            .join("moved")
            .read_dir()
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn target_inserted_after_prepare_is_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let workspace = PinnedWorkspace::open(root.path()).unwrap();
        let request = PreparedCreate::prepare(&workspace, Path::new("new.txt"), "ours").unwrap();
        std::fs::write(root.path().join("new.txt"), "theirs").unwrap();
        let error = request.execute().unwrap_err();
        assert_eq!(error.code, "target_exists");
        assert!(!error.committed);
        assert_eq!(
            std::fs::read(root.path().join("new.txt")).unwrap(),
            b"theirs"
        );
    }

    #[test]
    fn concurrent_same_leaf_publishes_exactly_one_complete_file() {
        let root = tempfile::tempdir().unwrap();
        let workspace = PinnedWorkspace::open(root.path()).unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        for index in 0..8 {
            let content = format!("complete payload {index}");
            let request =
                PreparedCreate::prepare(&workspace, Path::new("new.txt"), &content).unwrap();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                (content, request.execute())
            }));
        }
        let outcomes: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(
            outcomes.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        let successful = outcomes.iter().find(|(_, result)| result.is_ok()).unwrap();
        assert_eq!(
            std::fs::read(root.path().join("new.txt")).unwrap(),
            successful.0.as_bytes()
        );
        for (_, result) in outcomes {
            if let Err(error) = result {
                assert_eq!(error.code, "target_exists");
                assert!(!error.committed);
            }
        }
        assert_eq!(root.path().read_dir().unwrap().count(), 1);
    }

    #[test]
    fn anonymous_partial_write_and_prepublish_failures_leave_no_named_entry() {
        for fault in [linux::Fault::PartialWrite(3), linux::Fault::BeforePublish] {
            let root = tempfile::tempdir().unwrap();
            let workspace = PinnedWorkspace::open(root.path()).unwrap();
            let request =
                PreparedCreate::prepare(&workspace, Path::new("new.txt"), "abcdef").unwrap();
            let error = request.state.execute(fault).unwrap_err();
            assert!(!error.committed);
            assert!(error.staged_bytes > 0);
            assert_eq!(error.committed_bytes, 0);
            assert!(root.path().read_dir().unwrap().next().is_none());
        }
    }

    #[test]
    fn dropping_a_complete_anonymous_stage_cancels_without_a_named_file() {
        let root = tempfile::tempdir().unwrap();
        let workspace = PinnedWorkspace::open(root.path()).unwrap();
        let staged = PreparedCreate::prepare(&workspace, Path::new("new.txt"), "not published")
            .unwrap()
            .stage()
            .unwrap();
        assert!(root.path().read_dir().unwrap().next().is_none());
        drop(staged);
        assert!(root.path().read_dir().unwrap().next().is_none());
        PreparedCreate::prepare(&workspace, Path::new("new.txt"), "useful continuation")
            .unwrap()
            .stage()
            .unwrap()
            .publish()
            .unwrap();
        assert_eq!(
            std::fs::read(root.path().join("new.txt")).unwrap(),
            b"useful continuation"
        );
    }

    #[test]
    fn root_replacement_after_staging_refuses_publication_and_cleans_anonymous_file() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("workspace");
        let moved = parent.path().join("moved");
        std::fs::create_dir(&root).unwrap();
        let workspace = PinnedWorkspace::open(&root).unwrap();
        let staged = PreparedCreate::prepare(&workspace, Path::new("new.txt"), "not published")
            .unwrap()
            .stage()
            .unwrap();
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir(&root).unwrap();
        let error = staged.publish().unwrap_err();
        assert_eq!(error.code, "workspace_root_substituted");
        assert!(!error.committed);
        assert_eq!(error.staged_bytes, "not published".len());
        assert_eq!(error.committed_bytes, 0);
        assert!(root.read_dir().unwrap().next().is_none());
        assert!(moved.read_dir().unwrap().next().is_none());
    }

    #[test]
    fn target_inserted_after_staging_is_refused_by_atomic_publication() {
        let root = tempfile::tempdir().unwrap();
        let workspace = PinnedWorkspace::open(root.path()).unwrap();
        let staged =
            PreparedCreate::prepare(&workspace, Path::new("new.txt"), "our complete bytes")
                .unwrap()
                .stage()
                .unwrap();
        std::fs::write(root.path().join("new.txt"), "other creator").unwrap();
        let error = staged.publish().unwrap_err();
        assert_eq!(error.code, "target_exists");
        assert!(!error.committed);
        assert_eq!(error.staged_bytes, "our complete bytes".len());
        assert_eq!(
            std::fs::read(root.path().join("new.txt")).unwrap(),
            b"other creator"
        );
        assert_eq!(root.path().read_dir().unwrap().count(), 1);
    }

    #[test]
    fn directory_sync_failure_honestly_reports_already_committed_effect() {
        let root = tempfile::tempdir().unwrap();
        let workspace = PinnedWorkspace::open(root.path()).unwrap();
        let request =
            PreparedCreate::prepare(&workspace, Path::new("new.txt"), "actual effect").unwrap();
        let error = request
            .state
            .execute(linux::Fault::DirectorySync)
            .unwrap_err();
        assert!(error.committed);
        assert_eq!(error.committed_bytes, "actual effect".len());
        assert_eq!(
            std::fs::read(root.path().join("new.txt")).unwrap(),
            b"actual effect"
        );
    }

    #[test]
    fn documented_unprivileged_proc_source_preserves_atomic_no_replace() {
        let root = tempfile::tempdir().unwrap();
        let workspace = PinnedWorkspace::open(root.path()).unwrap();
        let request =
            PreparedCreate::prepare(&workspace, Path::new("new.txt"), "proc-fd source").unwrap();
        request.state.execute(linux::Fault::ProcSource).unwrap();
        assert_eq!(
            std::fs::read(root.path().join("new.txt")).unwrap(),
            b"proc-fd source"
        );
        assert_eq!(root.path().read_dir().unwrap().count(), 1);
    }
}
