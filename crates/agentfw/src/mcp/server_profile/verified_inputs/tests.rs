// SPDX-License-Identifier: Apache-2.0
use super::*;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn userspace_or_remote_verity_claim_never_becomes_content_authority() {
    use std::cell::Cell;
    for kind in [0x6573_5546, 0x6969, 0xff53_4d42, 0x794c_7630, 0] {
        let queried = Cell::new(false);
        let forged = verity_on_filesystem(kind, || {
            queried.set(true);
            Ok(Some(vec![7; 34]))
        })
        .unwrap();
        assert!(
            !queried.get(),
            "untrusted filesystem ioctl must not be consulted"
        );
        assert!(
            forged.is_none(),
            "userspace measurement must force full hashing"
        );
    }
    assert_eq!(
        verity_on_filesystem(0xef53, || Ok(Some(vec![7; 34]))).unwrap(),
        Some(vec![7; 34])
    );
}

#[cfg(target_os = "linux")]
#[test]
fn kernel_path_identity_preserves_resolved_links_and_rejects_raced_metadata() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("actual");
    fs::create_dir(&directory).unwrap();
    let file = directory.join("asset");
    fs::write(&file, b"original").unwrap();
    let alias = root.path().join("alias");
    symlink(&directory, &alias).unwrap();
    for path in [&file, &alias.join("asset"), &directory, &alias] {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert_eq!(
            canonical_identity(path, &metadata).unwrap(),
            path.canonicalize().unwrap()
        );
    }
    let file_link = root.path().join("runtime-link");
    symlink(&file, &file_link).unwrap();
    let followed = fs::metadata(&file_link).unwrap();
    assert_eq!(
        canonical_identity(&file_link, &followed).unwrap(),
        file.canonicalize().unwrap()
    );
    let mut inputs = Inputs::default();
    let digest = Verification::Capture(&mut inputs)
        .digest(&file_link, 8)
        .unwrap();
    assert_eq!(
        Verification::Resume(&inputs).digest(&file_link, 8).unwrap(),
        digest
    );
    // Keep the old inode allocated: an unlink/recreate may immediately
    // reuse its number within the filesystem's timestamp granularity.
    fs::rename(&file_link, root.path().join("old-runtime-link")).unwrap();
    symlink(&file, &file_link).unwrap();
    assert!(Verification::Resume(&inputs).digest(&file_link, 8).is_err());
    let observed = fs::metadata(&file).unwrap();
    fs::rename(&file, directory.join("old")).unwrap();
    fs::write(&file, b"original").unwrap();
    assert!(canonical_identity(&file, &observed).is_err());
    let link_metadata = fs::symlink_metadata(&alias).unwrap();
    assert!(link_metadata.is_symlink());
    assert_eq!(
        canonical_identity(&alias, &link_metadata).unwrap(),
        directory.canonicalize().unwrap()
    );
}

#[cfg(unix)]
#[test]
fn runtime_symlink_target_is_usable_but_retargeting_never_reuses_approval() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target");
    let other = root.path().join("other");
    let runtime = root.path().join("runtime");
    fs::write(&target, b"same bytes").unwrap();
    fs::write(&other, b"same bytes").unwrap();
    symlink(&target, &runtime).unwrap();
    let mut inputs = Inputs::default();
    let digest = Verification::Capture(&mut inputs)
        .digest(&runtime, 10)
        .unwrap();
    assert_eq!(
        Verification::Resume(&inputs).digest(&runtime, 10).unwrap(),
        digest
    );
    fs::remove_file(&runtime).unwrap();
    symlink(&other, &runtime).unwrap();
    assert!(Verification::Resume(&inputs).digest(&runtime, 10).is_err());
}

#[test]
fn mutable_files_are_read_again_and_replacement_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("asset");
    fs::write(&path, b"original").unwrap();
    let mut inputs = Inputs::default();
    let original = Verification::Capture(&mut inputs).digest(&path, 8).unwrap();
    assert_eq!(
        Verification::Resume(&inputs).digest(&path, 8).unwrap(),
        original
    );
    fs::write(&path, b"tampered").unwrap();
    assert!(Verification::Resume(&inputs).digest(&path, 8).is_err());
    fs::rename(&path, dir.path().join("old-asset")).unwrap();
    fs::write(&path, b"original").unwrap();
    assert!(Verification::Resume(&inputs).digest(&path, 8).is_err());
}

#[test]
#[cfg(unix)]
fn identical_bytes_do_not_hide_mode_or_symlink_changes() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("asset");
    fs::write(&path, b"original").unwrap();
    let mut inputs = Inputs::default();
    Verification::Capture(&mut inputs).digest(&path, 8).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(Verification::Resume(&inputs).digest(&path, 8).is_err());
    fs::rename(&path, dir.path().join("other")).unwrap();
    symlink("other", &path).unwrap();
    assert!(Verification::Resume(&inputs).digest(&path, 8).is_err());
}

#[test]
fn a_missing_kernel_proof_never_uses_a_saved_sha() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("asset");
    fs::write(&path, b"original").unwrap();
    let mut inputs = Inputs::default();
    Verification::Capture(&mut inputs).digest(&path, 8).unwrap();
    inputs.files.get_mut(&path).unwrap().verity = Some(vec![0; 34]);
    assert!(Verification::Resume(&inputs).digest(&path, 8).is_err());
}

#[test]
fn matching_metadata_cannot_substitute_for_a_kernel_proof() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("asset");
    fs::write(&path, b"original").unwrap();
    let mut inputs = Inputs::default();
    Verification::Capture(&mut inputs).digest(&path, 8).unwrap();
    fs::write(&path, b"tampered").unwrap();
    // Model a write which evades a metadata-only shortcut. The byte hash
    // must still reject, independently of mtime/ctime/identity matching.
    let current = Identity::read(&path, &fs::metadata(&path).unwrap()).unwrap();
    inputs.entries.insert(path.clone(), current.clone());
    inputs.files.get_mut(&path).unwrap().identity = current;
    assert!(Verification::Resume(&inputs).digest(&path, 8).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn descriptor_tree_leaf_refuses_stale_observation_and_all_mutations() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for mutation in ["mode", "replacement", "link", "bytes"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("asset");
        fs::write(&path, b"original").unwrap();
        let mut inputs = Inputs::default();
        let metadata = fs::symlink_metadata(&path).unwrap();
        let digest = Verification::Capture(&mut inputs)
            .tree_digest(&path, &metadata)
            .unwrap();
        assert_eq!(
            Verification::Resume(&inputs)
                .tree_digest(&path, &metadata)
                .unwrap(),
            digest
        );
        match mutation {
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap(),
            "replacement" => {
                fs::rename(&path, root.path().join("old")).unwrap();
                fs::write(&path, b"original").unwrap();
            }
            "link" => {
                fs::rename(&path, root.path().join("old")).unwrap();
                symlink("old", &path).unwrap();
            }
            _ => fs::write(&path, b"tampered").unwrap(),
        }
        // Stale read_dir metadata cannot authorize a changed inode/link.
        assert!(Verification::Resume(&inputs)
            .tree_digest(&path, &metadata)
            .is_err());
        let current = fs::symlink_metadata(&path).unwrap();
        assert!(Verification::Resume(&inputs)
            .tree_digest(&path, &current)
            .is_err());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn descriptor_tree_metadata_is_never_content_authority() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("asset");
    fs::write(&path, b"original").unwrap();
    let mut inputs = Inputs::default();
    Verification::Capture(&mut inputs)
        .tree_digest(&path, &fs::symlink_metadata(&path).unwrap())
        .unwrap();
    fs::write(&path, b"tampered").unwrap();
    let file = fs::File::open(&path).unwrap();
    let current = Identity::read_open(&path, &file).unwrap();
    inputs.entries.insert(path.clone(), current.clone());
    inputs.files.get_mut(&path).unwrap().identity = current;
    assert!(Verification::Resume(&inputs)
        .tree_digest(&path, &fs::symlink_metadata(&path).unwrap())
        .is_err());
}

#[test]
fn tree_addition_removal_and_directory_replacement_are_not_reused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("package");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("asset"), b"original").unwrap();
    let mut inputs = Inputs::default();
    let original =
        super::super::package_tree_sha256_with(&root, &mut Verification::Capture(&mut inputs))
            .unwrap();
    assert_eq!(
        super::super::package_tree_sha256_with(&root, &mut Verification::Resume(&inputs)).unwrap(),
        original
    );
    fs::write(root.join("extra"), b"unverified").unwrap();
    assert!(
        super::super::package_tree_sha256_with(&root, &mut Verification::Resume(&inputs)).is_err()
    );
    fs::remove_file(root.join("extra")).unwrap();
    fs::remove_file(root.join("asset")).unwrap();
    assert!(
        super::super::package_tree_sha256_with(&root, &mut Verification::Resume(&inputs)).is_err()
    );
    fs::rename(&root, dir.path().join("old")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("asset"), b"original").unwrap();
    assert!(
        super::super::package_tree_sha256_with(&root, &mut Verification::Resume(&inputs)).is_err()
    );
}

#[test]
fn removal_refuses_even_when_directory_metadata_matches() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("package");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("kept"), b"original").unwrap();
    fs::write(root.join("removed"), b"original").unwrap();
    let mut inputs = Inputs::default();
    super::super::package_tree_sha256_with(&root, &mut Verification::Capture(&mut inputs)).unwrap();
    fs::remove_file(root.join("removed")).unwrap();
    // Model a filesystem whose directory times do not distinguish these
    // operations. Completeness must not depend on a metadata difference.
    inputs.entries.insert(
        root.clone(),
        Identity::read(&root, &fs::symlink_metadata(&root).unwrap()).unwrap(),
    );
    let error = super::super::package_tree_sha256_with(&root, &mut Verification::Resume(&inputs))
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "selected package entry set changed during approval"
    );
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[ignore = "requires an operator-owned, already fs-verity-enabled fixture on native Linux"]
fn native_verity_reuse_requires_a_real_immutable_inode() {
    let path = PathBuf::from(
        std::env::var_os("SOU124_VERITY_FIXTURE").expect("explicit immutable fixture required"),
    );
    let size = fs::metadata(&path).unwrap().len();
    assert!(size <= super::super::MAX_TREE_BYTES);
    let mut inputs = Inputs::default();
    let digest = Verification::Capture(&mut inputs)
        .digest(&path, size)
        .unwrap();
    assert_eq!(inputs.counts(), (1, 0, 0));
    // The in-memory SHA is reused only with the real measured digest.
    assert_eq!(
        Verification::Resume(&inputs).digest(&path, size).unwrap(),
        digest
    );
    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    inputs
        .files
        .get_mut(&path)
        .unwrap()
        .verity
        .as_mut()
        .unwrap()[2] ^= 1;
    assert!(Verification::Resume(&inputs).digest(&path, size).is_err());
}

#[test]
fn buffered_hash_never_prefetches_beyond_the_size_sentinel() {
    let bytes = vec![b'x'; 2 * 65_536];
    let mut source = std::io::Cursor::new(&bytes);
    let mut hash = Sha256::new();
    assert_eq!(hash_bounded(&mut source, 17, &mut hash).unwrap(), 18);
    assert_eq!(source.position(), 18);
    assert_eq!(
        format!("{:x}", hash.finalize()),
        format!("{:x}", Sha256::digest(&bytes[..18]))
    );
}

#[test]
fn buffered_verification_matches_full_bytes_at_read_boundaries() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("asset");
    for size in [
        0_usize, 63, 64, 8191, 8192, 8193, 65_535, 65_536, 65_537, 131_071,
    ] {
        let bytes: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
        fs::write(&path, &bytes).unwrap();
        let expected = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(
            Verification::Full.digest(&path, size as u64).unwrap(),
            expected
        );
        let mut inputs = Inputs::default();
        assert_eq!(
            Verification::Capture(&mut inputs)
                .digest(&path, size as u64)
                .unwrap(),
            expected
        );
        assert_eq!(
            Verification::Resume(&inputs)
                .digest(&path, size as u64)
                .unwrap(),
            expected
        );
        assert_eq!(inputs.capture_cost.hashed_bytes, size as u64);
        drop(inputs);
        assert!(Verification::Full.digest(&path, size as u64 + 1).is_err());
        if size > 0 {
            assert!(Verification::Full.digest(&path, size as u64 - 1).is_err());
        }
    }
}
