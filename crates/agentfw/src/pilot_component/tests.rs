// SPDX-License-Identifier: Apache-2.0
use super::*;

fn tar_member(out: &mut Vec<u8>, name: &str, data: &[u8], kind: u8) {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        ");
    header[156] = kind;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|b| *b as u32).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    out.resize(out.len() + (512 - data.len() % 512) % 512, 0);
}

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

fn identity() -> Vec<u8> {
    format!(
        "{{\"format\":\"{SOURCE_FORMAT}\",\"source\":{{\"commit\":\"{COMMIT}\",\"dirty\":false,\"files_sha256\":\"{}\",\"tree\":\"{COMMIT}\"}}}}\n",
        "a".repeat(64)
    )
    .into_bytes()
}

fn files() -> Vec<(String, Vec<u8>)> {
    vec![
        ("scripts/helper.py".into(), b"VALUE = 1\n".to_vec()),
        (ENTRY.into(), b"print('pilot')\n".to_vec()),
        (SOURCE_FILE.into(), identity()),
    ]
}

fn manifest_for(files: &[(String, Vec<u8>)]) -> Manifest {
    Manifest {
        entry: ENTRY.into(),
        files: files
            .iter()
            .map(|(path, data)| FileEntry {
                mode: "0400".into(),
                path: path.clone(),
                sha256: sha256_hex(data),
                size: data.len() as u64,
            })
            .collect(),
        python: PYTHON_RANGE.into(),
        schema: COMPONENT_SCHEMA.into(),
        source: Source {
            commit: COMMIT.into(),
            tree: COMMIT.into(),
        },
    }
}

fn archive_with(manifest: &[u8], files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    tar_member(&mut out, MANIFEST, manifest, b'0');
    for (path, data) in files {
        tar_member(&mut out, path, data, b'0');
    }
    out.resize(out.len() + 1024, 0);
    out
}

fn archive() -> Vec<u8> {
    let files = files();
    archive_with(&serde_json::to_vec(&manifest_for(&files)).unwrap(), &files)
}

#[test]
fn accepts_a_canonical_component() {
    let package = parse(&archive()).unwrap();
    assert_eq!(package.manifest.files.len(), 3);
    assert_eq!(package.id(), sha256_hex(&package.manifest_bytes));
}

#[test]
fn complete_notice_capacity_remains_bounded() {
    let mut list = files();
    for index in 0..MAX_FILES - list.len() {
        list.push((format!("notices/{index:03}.txt"), b"notice\n".to_vec()));
    }
    list.sort();
    let bytes = serde_json::to_vec(&manifest_for(&list)).unwrap();
    let package = parse(&archive_with(&bytes, &list)).unwrap();
    assert_eq!(package.manifest.files.len(), MAX_FILES);

    list.push(("notices/extra.txt".into(), b"notice\n".to_vec()));
    list.sort();
    let bytes = serde_json::to_vec(&manifest_for(&list)).unwrap();
    let error = parse(&archive_with(&bytes, &list)).err().unwrap();
    assert!(error.to_string().contains("manifest file count"));
}

#[test]
fn rejects_traversal_duplicates_unlisted_links_and_malformed_manifests() {
    let base = files();
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    for bad in [
        "../escape.py",
        "/abs.py",
        "scripts/../x.py",
        "scripts//x.py",
        "a b.py",
    ] {
        let mut list = base.clone();
        list.push((bad.into(), b"x".to_vec()));
        list.sort();
        cases.push((
            "traversal",
            archive_with(&serde_json::to_vec(&manifest_for(&list)).unwrap(), &list),
        ));
    }
    let mut duplicate = base.clone();
    duplicate.insert(1, duplicate[0].clone());
    cases.push((
        "duplicate",
        archive_with(
            &serde_json::to_vec(&manifest_for(&duplicate)).unwrap(),
            &duplicate,
        ),
    ));
    let manifest = serde_json::to_vec(&manifest_for(&base)).unwrap();
    let mut unlisted = base.clone();
    unlisted.push(("zz.py".into(), b"x".to_vec()));
    cases.push(("unlisted", archive_with(&manifest, &unlisted)));
    let mut missing = base.clone();
    missing.pop();
    cases.push(("missing", archive_with(&manifest, &missing)));
    let mut changed = base.clone();
    changed[0].1 = b"VALUE = 2\n".to_vec();
    cases.push(("changed", archive_with(&manifest, &changed)));
    let mut link = Vec::new();
    tar_member(&mut link, MANIFEST, &manifest, b'0');
    tar_member(&mut link, &base[0].0, b"", b'2');
    link.resize(link.len() + 1024, 0);
    cases.push(("link", link));
    let mut hard = Vec::new();
    tar_member(&mut hard, MANIFEST, &manifest, b'0');
    tar_member(&mut hard, &base[0].0, b"", b'1');
    hard.resize(hard.len() + 1024, 0);
    cases.push(("hardlink", hard));
    let pretty = serde_json::to_vec_pretty(&manifest_for(&base)).unwrap();
    cases.push(("not canonical", archive_with(&pretty, &base)));
    let mut text = String::from_utf8(manifest.clone()).unwrap();
    text.insert_str(1, "\"extra\":1,");
    cases.push(("unknown field", archive_with(text.as_bytes(), &base)));
    let mut text = String::from_utf8(manifest.clone()).unwrap();
    text = text.replacen("\"entry\"", "\"entry\":\"x\",\"entry\"", 1);
    cases.push(("duplicate key", archive_with(text.as_bytes(), &base)));
    let mut trailing = archive();
    trailing.extend_from_slice(&[0u8; 512]);
    cases.push(("trailing", trailing));
    let mut other = manifest_for(&base);
    other.python = "cpython>=3.9".into();
    cases.push((
        "interpreter",
        archive_with(&serde_json::to_vec(&other).unwrap(), &base),
    ));
    let mut stale = base.clone();
    stale[2].1 = identity()
        .iter()
        .map(|b| if *b == b'0' { b'1' } else { *b })
        .collect();
    cases.push((
        "mixed source",
        archive_with(&serde_json::to_vec(&manifest_for(&stale)).unwrap(), &stale),
    ));
    for (name, bytes) in cases {
        assert!(parse(&bytes).is_err(), "{name} was accepted");
    }
}

fn archive_for(commit: &str) -> Vec<u8> {
    let mut list = files();
    list[2].1 = String::from_utf8(identity())
        .unwrap()
        .replace(COMMIT, commit)
        .into_bytes();
    let mut manifest = manifest_for(&list);
    manifest.source.commit = commit.into();
    manifest.source.tree = commit.into();
    archive_with(&serde_json::to_vec(&manifest).unwrap(), &list)
}

/// The host CPython the lifecycle test records (Linux CI and developer hosts).
fn python() -> PathBuf {
    PathBuf::from("/usr/bin/python3")
}

#[test]
fn lifecycle_verifies_refuses_tampering_recovers_rolls_back_and_removes_owned_state() {
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(home.path().join("unrelated"), b"keep").unwrap();
    let store = Store::new(home.path());
    let missing = store.current().unwrap_err();
    assert_eq!(missing.reason, "front_door_component_not_installed");
    assert!(missing.action.contains("pilot-component install"));

    let first = archive();
    assert!(store.install(&first, &"0".repeat(64), &python()).is_err());
    assert!(!store.current_path().exists());
    let installed = store
        .install(&first, &sha256_hex(&first), &python())
        .unwrap();
    let id = installed["component"].as_str().unwrap().to_string();
    let verified = store.current().unwrap();
    assert!(verified.tree.join(ENTRY).is_file());
    let helper = verified.tree.join("scripts/helper.py");
    let mode = std::fs::metadata(&helper).unwrap().mode() & 0o7777;
    assert_eq!(mode, 0o400);

    // Changed bytes, an unlisted file, a link and a wrong mode are refused.
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&helper, b"VALUE = 2\n").unwrap();
    assert_eq!(
        store.current().unwrap_err().reason,
        "front_door_component_changed"
    );
    std::fs::write(&helper, b"VALUE = 1\n").unwrap();
    assert_eq!(
        store.current().unwrap_err().reason,
        "front_door_component_changed"
    );
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o400)).unwrap();
    store.current().unwrap();
    let extra = verified.tree.join("scripts/sitecustomize.py");
    std::fs::write(&extra, b"").unwrap();
    std::fs::set_permissions(&extra, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        store.current().unwrap_err().reason,
        "front_door_component_changed"
    );
    std::fs::remove_file(&extra).unwrap();
    std::fs::rename(&helper, verified.tree.join("moved")).unwrap();
    std::os::unix::fs::symlink(verified.tree.join("moved"), &helper).unwrap();
    assert_eq!(
        store.current().unwrap_err().reason,
        "front_door_component_changed"
    );
    std::fs::remove_file(&helper).unwrap();
    std::fs::rename(verified.tree.join("moved"), &helper).unwrap();
    store.current().unwrap();

    // An interrupted install blocks use until recover; selection unchanged.
    std::fs::write(store.journal_path(), b"{}").unwrap();
    std::fs::create_dir(store.root().join("staging-x")).unwrap();
    assert_eq!(
        store.current().unwrap_err().reason,
        "front_door_component_interrupted"
    );
    assert!(store
        .install(&first, &sha256_hex(&first), &python())
        .is_err());
    let recovered = store.recover().unwrap();
    assert_eq!(recovered["cleared_journal"], true);
    assert_eq!(recovered["selected"], id.as_str());
    store.current().unwrap();

    // Update, a recorded interpreter mismatch, rollback.
    let second = archive_for("89abcdef0123456789abcdef0123456789abcdef");
    let updated = store
        .install(&second, &sha256_hex(&second), &python())
        .unwrap();
    assert_eq!(updated["previous"], id.as_str());
    let new_id = updated["component"].as_str().unwrap().to_string();
    assert_ne!(new_id, id);
    let mut pointer: Pointer =
        serde_json::from_slice(&std::fs::read(store.current_path()).unwrap()).unwrap();
    let saved = pointer.clone();
    pointer.python.sha256 = "0".repeat(64);
    std::fs::write(store.current_path(), serde_json::to_vec(&pointer).unwrap()).unwrap();
    assert_eq!(
        store.current().unwrap_err().reason,
        "front_door_interpreter_changed"
    );
    std::fs::write(store.current_path(), serde_json::to_vec(&saved).unwrap()).unwrap();
    assert_eq!(store.rollback().unwrap()["component"], id.as_str());
    assert_eq!(store.current().unwrap().id, id);
    assert!(store.remove(Some(&id), false).is_err());
    store.remove(Some(&new_id), false).unwrap();
    store.remove(None, true).unwrap();
    assert!(!store.root().exists());
    assert_eq!(
        std::fs::read(home.path().join("unrelated")).unwrap(),
        b"keep"
    );
    assert_eq!(
        store.current().unwrap_err().reason,
        "front_door_component_not_installed"
    );
}

/// Every file below `root` with its bytes, without following links.
fn snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            let name = entry
                .path()
                .strip_prefix(root)
                .unwrap()
                .display()
                .to_string();
            if kind.is_dir() {
                rows.push((name + "/", Vec::new()));
                stack.push(entry.path());
            } else {
                rows.push((name, std::fs::read(entry.path()).unwrap()));
            }
        }
    }
    rows.sort();
    rows
}

/// An owned external tree shaped like an installed component.
fn external_fixture(base: &Path, id: &str) -> PathBuf {
    let external = base.join("external");
    std::fs::create_dir_all(external.join(id).join("tree/scripts")).unwrap();
    std::fs::write(
        external.join(id).join("manifest.json"),
        b"external manifest",
    )
    .unwrap();
    std::fs::write(
        external.join(id).join("tree/scripts/pilot.py"),
        b"external bytes",
    )
    .unwrap();
    std::fs::write(external.join("sentinel"), b"must stay").unwrap();
    external
}

#[test]
fn removal_refuses_a_redirected_components_parent_and_keeps_external_state() {
    let base = tempfile::tempdir().unwrap();
    let home = base.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let store = Store::new(&home);
    let first = archive();
    let second = archive_for("89abcdef0123456789abcdef0123456789abcdef");
    store
        .install(&second, &sha256_hex(&second), &python())
        .unwrap();
    let installed = store
        .install(&first, &sha256_hex(&first), &python())
        .unwrap();
    let unselected = installed["previous"].as_str().unwrap().to_string();
    let external = external_fixture(base.path(), &unselected);
    let before = snapshot(&external);
    // A pre-existing linked intermediate `components` parent.
    let components = store.root().join("components");
    std::fs::rename(&components, store.root().join("components.real")).unwrap();
    std::os::unix::fs::symlink(&external, &components).unwrap();
    let error = store.remove(Some(&unselected), false).unwrap_err();
    assert!(
        format!("{error:#}").contains("components directory"),
        "{error:#}"
    );
    assert_eq!(snapshot(&external), before);
    assert!(store.current().is_err(), "a linked parent must not verify");
    // Removing everything unlinks the link itself and never follows it.
    store.remove(None, true).unwrap();
    assert!(!store.root().exists());
    assert_eq!(snapshot(&external), before);
}

#[test]
fn removal_and_recovery_refuse_redirected_ancestors_and_linked_staging() {
    let base = tempfile::tempdir().unwrap();
    let real = base.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let store = Store::new(&real);
    let first = archive();
    let id = store
        .install(&first, &sha256_hex(&first), &python())
        .unwrap()["component"]
        .as_str()
        .unwrap()
        .to_string();
    let external = external_fixture(base.path(), &id);
    let before = snapshot(&external);
    // A linked staging entry is never followed by recovery.
    std::os::unix::fs::symlink(&external, store.root().join("staging-linked")).unwrap();
    std::fs::write(store.journal_path(), b"{}").unwrap();
    store.recover().unwrap();
    assert_eq!(snapshot(&external), before);
    assert!(std::fs::symlink_metadata(store.root().join("staging-linked")).is_ok());
    std::fs::remove_file(store.root().join("staging-linked")).unwrap();
    // The same home reached through a linked ancestor is refused.
    let link = base.path().join("linked");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let redirected = Store::new(&link);
    assert!(redirected.remove(None, true).is_err());
    assert!(redirected.recover().is_err());
    assert!(store.current().is_ok(), "the owned component must stay");
    // The normal owned removal still works.
    store.remove(None, true).unwrap();
    assert!(!store.root().exists());
    assert_eq!(snapshot(&external), before);
}

#[test]
fn rejects_a_file_that_is_also_a_directory() {
    let mut list = files();
    list.push(("scripts".into(), b"x".to_vec()));
    list.sort();
    let bytes = archive_with(&serde_json::to_vec(&manifest_for(&list)).unwrap(), &list);
    assert!(parse(&bytes).is_err());
}
