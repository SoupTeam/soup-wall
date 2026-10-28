// SPDX-License-Identifier: Apache-2.0
use super::git_tracked_symlinks::*;
#[cfg(unix)]
use std::{fs, path::Path, process::Command};

#[cfg(unix)]
fn git(root: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new("git")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        // Positive fixtures require quiescence; do not let Git spawn an
        // implicit maintenance writer after an otherwise completed command.
        .args([
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            "-c",
            "user.name=Owned Synthetic",
            "-c",
            "user.email=owned@example.invalid",
        ])
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[cfg(unix)]
fn fixture() -> tempfile::TempDir {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "-b", "main"]);
    fs::write(root.path().join("data.txt"), "owned data\n").unwrap();
    fs::write(root.path().join("other.txt"), "other owned data\n").unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "-m", "Owned regular initial"]);
    fs::create_dir(root.path().join("nested")).unwrap();
    symlink("data.txt", root.path().join("link")).unwrap();
    symlink("../data.txt", root.path().join("nested/relative")).unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "-m", "Owned tracked link objects"]);
    root
}

#[cfg(unix)]
fn validate(root: &Path) -> anyhow::Result<()> {
    validate_invocation(root, |args, limit| {
        let bytes = git(root, args);
        anyhow::ensure!(bytes.len() <= limit, "test inspection bound");
        Ok(bytes)
    })
}

#[test]
fn lexical_targets_cannot_select_controls_or_escape() {
    assert_eq!(target("nested/link", b"../data.txt").unwrap(), "data.txt");
    for (path, value) in [
        ("link", &b"/outside"[..]),
        ("link", &b"../outside"[..]),
        ("nested/link", &b"../../outside"[..]),
        ("link", &b".git/config"[..]),
        ("link", &b"x/../.gitattributes"[..]),
        (".gitattributes", &b"data.txt"[..]),
        ("link", &b"a//b"[..]),
        ("link", &b"a\\b"[..]),
        ("link", &b"a b"[..]),
        ("link", &b""[..]),
        ("link", &b"."[..]),
        ("link", &b"data.txt\0"[..]),
    ] {
        assert!(target(path, value).is_err(), "{path}: {value:?}");
    }
    assert!(target("link", &vec![b'a'; 257]).is_err());
}

#[test]
fn identity_preserves_original_six_operation_and_argument_contracts() {
    assert!(super::selected(Some(FORMAT)));
    assert!(super::git_selected(FORMAT));
    let manifest = super::original_manifest_for(FORMAT).unwrap();
    assert_eq!(manifest, super::git::original_manifest());
    let profiles = super::classify_manifest_for(FORMAT, &manifest).unwrap();
    assert_eq!(
        profiles
            .values()
            .filter(|p| p.unsupported_reason.is_none())
            .count(),
        6
    );
    for old in [
        super::git::FORMAT,
        super::git::LOCAL_REFS_FORMAT,
        super::git::SHALLOW_FORMAT,
        super::git_local_clone::FORMAT,
    ] {
        assert_ne!(old, FORMAT);
        assert_ne!(
            crate::mcp::server_sandbox::profile_name(old),
            crate::mcp::server_sandbox::profile_name(FORMAT)
        );
    }
    assert!(super::git::validate_arguments(
        "git_show",
        &serde_json::json!({"repo_path":"/workspace","revision":"refs/heads/main"})
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn original_git_inspects_index_and_history_without_following_links() {
    let root = fixture();
    validate_repository(root.path()).unwrap();
    validate(root.path()).unwrap();
    assert!(super::git_local_clone::validate_repository(root.path()).is_err());
    assert!(super::git::validate_repository(root.path()).is_err());
    assert_eq!(git(root.path(), &["show", "HEAD:link"]), b"data.txt");
    assert!(
        String::from_utf8_lossy(&git(root.path(), &["ls-files", "--stage"])).contains("120000")
    );
}

#[cfg(unix)]
#[test]
fn staged_matching_link_change_is_supported_but_unstaged_and_untracked_are_not() {
    use std::os::unix::fs::symlink;
    let root = fixture();
    let link = root.path().join("link");
    fs::remove_file(&link).unwrap();
    symlink("other.txt", &link).unwrap();
    validate_repository(root.path()).unwrap();
    assert!(validate(root.path())
        .unwrap_err()
        .to_string()
        .contains("index_worktree_mismatch"));
    git(root.path(), &["add", "link"]);
    validate(root.path()).unwrap();
    symlink("data.txt", root.path().join("untracked")).unwrap();
    assert!(validate(root.path()).is_err());
    fs::remove_file(root.path().join("untracked")).unwrap();
    fs::remove_file(&link).unwrap();
    fs::write(&link, "other.txt").unwrap();
    assert!(validate(root.path()).is_err());
    fs::remove_file(&link).unwrap();
    assert!(validate(root.path()).is_err());
}

#[cfg(unix)]
#[test]
fn chains_dangling_links_metadata_and_shared_writable_targets_refuse() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = fixture();
    let link = root.path().join("link");
    for target in [
        "/outside",
        "../outside",
        "absent",
        "nested",
        "nested/relative",
        "link",
        ".git/HEAD",
    ] {
        fs::remove_file(&link).unwrap();
        symlink(target, &link).unwrap();
        assert!(validate_repository(root.path()).is_err(), "{target}");
    }
    fs::remove_file(&link).unwrap();
    symlink("data.txt", &link).unwrap();
    for control in [".git/config", ".git/index", ".git/objects"] {
        let path = root.path().join(control);
        let saved = root.path().join("saved-metadata");
        fs::rename(&path, &saved).unwrap();
        symlink(&saved, &path).unwrap();
        assert!(validate_repository(root.path()).is_err());
        fs::remove_file(path).unwrap();
        fs::rename(saved, root.path().join(control)).unwrap();
    }
    fs::set_permissions(
        root.path().join("data.txt"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(validate_repository(root.path()).is_err());
}

#[cfg(unix)]
#[test]
fn unsafe_historical_link_remains_refused_after_a_safe_current_commit() {
    use std::os::unix::fs::symlink;
    let root = fixture();
    let link = root.path().join("link");
    fs::remove_file(&link).unwrap();
    symlink("../outside", &link).unwrap();
    git(root.path(), &["add", "link"]);
    git(root.path(), &["commit", "-m", "Owned unsupported history"]);
    fs::remove_file(&link).unwrap();
    symlink("data.txt", &link).unwrap();
    git(root.path(), &["add", "link"]);
    git(root.path(), &["commit", "-m", "Owned safe current link"]);
    validate_repository(root.path()).unwrap();
    assert!(validate(root.path())
        .unwrap_err()
        .to_string()
        .contains("target_escape"));
}

#[cfg(unix)]
#[test]
fn index_and_worktree_changes_during_inspection_invalidate_the_call() {
    use std::os::unix::fs::symlink;
    for index in [true, false] {
        let root = fixture();
        let mut changed = false;
        let result = validate_invocation(root.path(), |args, _| {
            let output = git(root.path(), args);
            if !changed {
                changed = true;
                if index {
                    let path = root.path().join(".git/index");
                    fs::write(&path, fs::read(&path).unwrap()).unwrap();
                } else {
                    fs::remove_file(root.path().join("link")).unwrap();
                    symlink("other.txt", root.path().join("link")).unwrap();
                }
            }
            Ok(output)
        });
        assert!(result.unwrap_err().to_string().contains("identity_changed"));
    }
}

#[cfg(unix)]
#[test]
fn canceled_missing_regular_and_linked_components_remain_unsupported() {
    use std::os::unix::fs::symlink;
    let root = fixture();
    let link = root.path().join("link");
    for target in [
        "missing/../data.txt",
        "other.txt/../data.txt",
        "nested/relative/../data.txt",
    ] {
        fs::remove_file(&link).unwrap();
        symlink(target, &link).unwrap();
        assert!(validate_repository(root.path()).is_err(), "{target}");
    }
    fs::remove_file(&link).unwrap();
    symlink("nested/../data.txt", &link).unwrap();
    git(root.path(), &["add", "link"]);
    validate(root.path()).unwrap();
}

#[cfg(unix)]
#[test]
fn malformed_conflicted_duplicate_and_unbounded_inventories_refuse() {
    let root = fixture();
    let oid = "a".repeat(40);
    for listing in [
        format!("120000 {oid} 2\tlink\0"),
        format!("160000 {oid} 0\tsubmodule\0"),
        format!("100644 {oid} 0\tdata.txt\0").repeat(2),
        format!("100644 {oid} 0\t../outside\0"),
        format!("100644 {oid} 0\tdata.txt"),
    ] {
        let result = validate_invocation(root.path(), |_, _| Ok(listing.as_bytes().to_vec()));
        assert!(result.is_err(), "{listing:?}");
    }
    for (inventory, expected) in [
        (
            format!("{oid} commit\n").repeat(65),
            "git_links_commit_count",
        ),
        (
            format!("{oid} blob\n").repeat(32769),
            "git_links_object_count",
        ),
        ("not-an-object\n".into(), "git_links_object_record"),
    ] {
        let result = validate_invocation(root.path(), |args, _| {
            if args[0] == "cat-file" && args[1] == "--batch-all-objects" {
                Ok(inventory.as_bytes().to_vec())
            } else {
                Ok(git(root.path(), args))
            }
        });
        assert!(result.unwrap_err().to_string().contains(expected));
    }
}

#[cfg(unix)]
#[test]
fn unreachable_unsafe_history_and_link_count_are_not_skipped() {
    use std::os::unix::fs::symlink;
    let root = fixture();
    let previous = String::from_utf8(git(root.path(), &["rev-parse", "HEAD"])).unwrap();
    let link = root.path().join("link");
    fs::remove_file(&link).unwrap();
    symlink("../outside", &link).unwrap();
    git(root.path(), &["add", "link"]);
    git(
        root.path(),
        &["commit", "-m", "Owned unreachable unsupported link"],
    );
    git(root.path(), &["reset", "--hard", previous.trim()]);
    assert!(validate(root.path())
        .unwrap_err()
        .to_string()
        .contains("target_escape"));
    for n in 0..63 {
        symlink("data.txt", root.path().join(format!("extra-{n}"))).unwrap();
    }
    assert!(validate_repository(root.path())
        .unwrap_err()
        .to_string()
        .contains("git_links_count"));
}

#[cfg(unix)]
#[test]
fn owned_fixture_remains_quiescent_across_repeated_original_git_inspections() {
    let root = fixture();
    let config = fs::read(root.path().join(".git/config")).unwrap();
    let index = fs::read(root.path().join(".git/index")).unwrap();
    for _ in 0..8 {
        validate_repository(root.path()).unwrap();
        validate(root.path()).unwrap();
        assert_eq!(fs::read(root.path().join(".git/config")).unwrap(), config);
        assert_eq!(fs::read(root.path().join(".git/index")).unwrap(), index);
    }
}
