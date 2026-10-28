// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn fixture() -> (tempfile::TempDir, Profile) {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().canonicalize().unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.join("output");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut p = profile::fixture();
    p.root = root;
    p.root_identity = replace_file::inspect_workspace(&p.root).unwrap();
    p.targets[0].name = "result.txt".into();
    (dir, p)
}
fn put(path: &Path, raw: &[u8]) {
    fs::write(path, raw).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn replacing(p: &mut Profile) {
    put(&p.root.join("result.txt"), b"original bounded report\n");
    let v = replace_file::preview(&p.root, &p.root.join("result.txt"), "").unwrap();
    p.targets[0].create = false;
    p.targets[0].replacement = Some(Baseline {
        identity: v.old_identity,
        sha256: v.old_sha256,
    });
}
fn descriptive(p: &Profile, out: &Path) -> Proposal {
    let (mut after, observed_targets) = observe(p).unwrap();
    let old = profile::digest(p).unwrap();
    after.refreshed_from_sha256 = Some(old.clone());
    Proposal {
        format: FORMAT,
        source_plan: out.parent().unwrap().join("old-plan"),
        source_plan_sha256: old,
        destination: out.into(),
        before: p.clone(),
        profile_sha256: profile::digest(&after).unwrap(),
        after,
        observed_targets,
        scope_unchanged: true,
        prior_operation_outcome: "unknown-not-inferred-from-current-bytes",
        requires_fresh_run_and_exact_ask: true,
    }
}

#[test]
fn refreshed_bindings_preserve_scope_and_require_a_distinct_plan_even_if_bytes_match() {
    let (d, mut p) = fixture();
    replacing(&mut p);
    let old = p.clone();
    let unchanged = descriptive(&p, &d.path().join("new-plan"));
    assert_ne!(unchanged.profile_sha256, profile::digest(&p).unwrap());
    assert_eq!(
        unchanged.prior_operation_outcome,
        "unknown-not-inferred-from-current-bytes"
    );
    put(
        &p.root.join("result.txt"),
        b"operator inspected superseding bytes\n",
    );
    let q = descriptive(&p, &d.path().join("new-plan"));
    let mut normalized = q.after.clone();
    normalized.refreshed_from_sha256 = p.refreshed_from_sha256.clone();
    normalized.targets[0].replacement = p.targets[0].replacement.clone();
    assert_eq!(normalized, old);
    assert_eq!(p, old);
    assert_ne!(q.after.targets[0].replacement, p.targets[0].replacement);
    assert_ne!(confirmation(&q).unwrap(), confirmation(&unchanged).unwrap());
    assert_eq!(
        fs::read(p.root.join("result.txt")).unwrap(),
        b"operator inspected superseding bytes\n"
    );
    let mut moved = q;
    moved.destination = d.path().join("different-plan");
    assert_ne!(
        confirmation(&moved).unwrap(),
        confirmation(&unchanged).unwrap()
    );
}

#[test]
fn creation_cannot_be_silently_converted_to_replacement() {
    let (d, p) = fixture();
    assert!(observe(&p).unwrap().1[0].current.is_none());
    put(&p.root.join("result.txt"), b"legitimate earlier creation\n");
    assert!(observe(&p)
        .unwrap_err()
        .to_string()
        .contains("use_explicit_prepare_for_replace"));
    assert!(p.targets[0].create && p.targets[0].replacement.is_none());
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
}

#[test]
fn selected_read_identity_and_content_are_also_bound_to_confirmation() {
    let (d, mut p) = fixture();
    replacing(&mut p);
    let mut read = p.targets[0].clone();
    read.name = "source.txt".into();
    read.replacement = None;
    p.targets.push(read);
    put(&p.root.join("source.txt"), b"read-only input one\n");
    let a = descriptive(&p, &d.path().join("new-plan"));
    put(&p.root.join("source.txt"), b"read-only input two\n");
    let b = descriptive(&p, &d.path().join("new-plan"));
    assert_eq!(a.profile_sha256, b.profile_sha256);
    assert_ne!(confirmation(&a).unwrap(), confirmation(&b).unwrap());
}

#[test]
fn root_replacement_links_hardlinks_and_large_objects_cannot_refresh() {
    let (d, mut p) = fixture();
    replacing(&mut p);
    let path = p.root.join("result.txt");
    let alias = d.path().join("outside-alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(observe(&p).is_err());
    assert_eq!(fs::read(&alias).unwrap(), fs::read(&path).unwrap());
    fs::remove_file(&path).unwrap();
    symlink(&alias, &path).unwrap();
    assert!(observe(&p).is_err());
    fs::remove_file(&path).unwrap();
    put(&path, &[b'x'; 4097]);
    assert!(observe(&p).is_err());
    fs::rename(&p.root, d.path().join("retired-root")).unwrap();
    fs::create_dir(&p.root).unwrap();
    fs::set_permissions(&p.root, fs::Permissions::from_mode(0o700)).unwrap();
    put(&path, b"new root sentinel\n");
    assert!(observe(&p).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"new root sentinel\n");
}

#[test]
fn original_plan_must_be_exact_private_immutable_and_bounded() {
    let (d, p) = fixture();
    let plan = d.path().join("old-plan");
    launch::publish_checked(&plan, &p, || Ok(())).unwrap();
    let digest = profile::digest(&p).unwrap();
    assert_eq!(immutable(&plan, &digest).unwrap(), p);
    assert!(immutable(&plan, &"0".repeat(64)).is_err());
    let file = plan.join("profile.json");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(immutable(&plan, &digest).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    fs::hard_link(&file, d.path().join("plan-alias")).unwrap();
    assert!(immutable(&plan, &digest).is_err());
    fs::remove_file(d.path().join("plan-alias")).unwrap();
    put(&plan.join("unexpected"), b"extra");
    assert!(immutable(&plan, &digest).is_err());
    assert!(!d.path().join("new-plan").exists());
}

#[test]
fn changed_target_or_interrupted_revalidation_does_not_publish_or_touch_original() {
    let (d, mut p) = fixture();
    replacing(&mut p);
    let old = d.path().join("old-plan");
    launch::publish_checked(&old, &p, || Ok(())).unwrap();
    let raw = fs::read(old.join("profile.json")).unwrap();
    let out = d.path().join("new-plan");
    let first = observe(&p).unwrap();
    assert!(launch::publish_checked(&out, &first.0, || {
        put(&p.root.join("result.txt"), b"changed during staging\n");
        ensure!(observe(&p)? == first, "changed_input");
        Ok(())
    })
    .is_err());
    assert!(!out.exists());
    assert!(
        launch::publish_checked(&out, &p, || anyhow::bail!("cancelled before publish")).is_err()
    );
    assert!(!out.exists());
    assert_eq!(fs::read(old.join("profile.json")).unwrap(), raw);
    assert_eq!(
        fs::read(p.root.join("result.txt")).unwrap(),
        b"changed during staging\n"
    );
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 2);
}

#[test]
fn concurrent_publications_have_one_winner_and_never_overwrite_a_destination() {
    let (d, p) = fixture();
    let out = d.path().join("new-plan");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let handles = (0..2)
            .map(|_| {
                let barrier = barrier.clone();
                let p = &p;
                let out = &out;
                scope.spawn(move || {
                    launch::publish_checked(out, p, || {
                        barrier.wait();
                        Ok(())
                    })
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|h| h.join().unwrap().is_ok())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|&&v| v).count(), 1);
    assert_eq!(
        fs::read(out.join("profile.json")).unwrap(),
        profile::canonical(&p).unwrap()
    );
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 2);
    assert!(launch::publish_checked(&out, &p, || Ok(())).is_err());
}

#[test]
fn refresh_directory_lock_conflicts_with_accepted_create_and_replacement_writers() {
    let (_d, p) = fixture();
    let root = crate::sandbox::PinnedWorkspace::open(&p.root).unwrap();
    let fd = root.duplicate_root_descriptor().unwrap();
    let lock = replace_file::writer_lock(&fd).unwrap();
    assert!(replace_file::writer_lock(&fd).is_err());
    assert!(replace_file::create_writer_lock(&fd).is_err());
    drop(lock);
    assert!(replace_file::create_writer_lock(&fd).is_ok());
}

#[test]
fn destinations_cannot_expand_output_or_mutate_original_plan() {
    let (d, p) = fixture();
    let old = d.path().join("old-plan");
    fs::create_dir(&old).unwrap();
    fs::set_permissions(&old, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(destination(&d.path().join("new-plan"), &old, &p).is_ok());
    for invalid in [
        old.clone(),
        old.join("nested"),
        p.root.join("nested"),
        d.path().into(),
    ] {
        assert!(destination(&invalid, &old, &p).is_err());
    }
}
