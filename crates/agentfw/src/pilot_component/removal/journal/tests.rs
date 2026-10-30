// SPDX-License-Identifier: Apache-2.0
//! Disposable exact-object protocol fixtures, not installed-run qualification.
use super::*;
use crate::pilot_component::removal::{RetainedInventory, Selection};
use std::path::Path;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};
fn private(p: &Path) {
    fs::create_dir(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}
fn fixture() -> (tempfile::TempDir, Journal) {
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    for n in ["home", "prefix", "state", "journals"] {
        private(&t.path().join(n));
    }
    let home = t.path().join("home");
    let root = home.join("pilot-front-door");
    private(&root);
    fs::write(root.join("owned"), b"verified fixture").unwrap();
    fs::set_permissions(root.join("owned"), fs::Permissions::from_mode(0o400)).unwrap();
    fs::write(home.join("credentials"), b"private retained sentinel").unwrap();
    let mut b = Budget::new();
    let d = Dir::open(&root).unwrap();
    let (raw, id) = d.read("owned", 1024, &mut b).unwrap();
    let path = t.path().join("journals/removal");
    let plan = Plan {
        format: FORMAT.into(),
        scope: "verified_front_door_component_only".into(),
        selected: Selection {
            home: home.clone(),
            prefix: vec![t.path().join("prefix")],
            state: vec![t.path().join("state")],
            journal: path.clone(),
        },
        home: Dir::open(&home).unwrap().id,
        root: d.id.clone(),
        journal_parent: Dir::open(&t.path().join("journals")).unwrap().id,
        entries: vec![
            Entry {
                name: "owned".into(),
                identity: id,
                sha256: Some(sha(&raw)),
            },
            Entry {
                name: String::new(),
                identity: d.id,
                sha256: None,
            },
        ],
        retained: ["prefix", "state"]
            .map(|n| RetainedInventory {
                root: t.path().join(n),
                identity: Dir::open(&t.path().join(n)).unwrap().id,
                entries: vec![],
            })
            .to_vec(),
        components: vec![],
        exclusion: "explicit_quiesced_installation_no_new_launches_or_same_uid_writers".into(),
    };
    private(&path);
    let dir = Dir::open(&path).unwrap();
    let hash = digest(&plan).unwrap();
    dir.write_new("plan.json", &canonical(&plan).unwrap())
        .unwrap();
    dir.write_new(
        "binding.json",
        &canonical(&Binding {
            format: FORMAT.into(),
            plan: hash.clone(),
            directory: dir.id.clone(),
        })
        .unwrap(),
    )
    .unwrap();
    let j = Journal::open(
        &Retained {
            journal: path,
            expect_plan: hash,
            success_ack: None,
        },
        &mut b,
    )
    .unwrap();
    (t, j)
}
#[test]
fn missing_after_intent_is_uncertain_and_new_object_is_never_removed() {
    let (_t, j) = fixture();
    j.write_record(0, "intent").unwrap();
    let target = j.plan.selected.home.join("pilot-front-door/owned");
    fs::remove_file(&target).unwrap();
    assert_eq!(
        j.inspect(&mut Budget::new()).unwrap()[0].status,
        "uncertain"
    );
    fs::write(&target, b"later user data").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o400)).unwrap();
    let rows = j.inspect(&mut Budget::new()).unwrap();
    assert_eq!(rows[0].reason, "substituted_or_reappeared_object");
    assert!(j.verify_remaining(&rows, &mut Budget::new()).is_err());
    assert_eq!(fs::read(target).unwrap(), b"later user data");
}
#[test]
fn durable_completed_objects_are_skipped_and_already_removed_is_repeatable() {
    let (_t, j) = fixture();
    let sentinel = fs::read(j.plan.selected.home.join("credentials")).unwrap();
    for (i, e) in j.plan.entries.iter().enumerate() {
        j.write_record(i, "intent").unwrap();
        let (p, n) = location(&j.plan, e).unwrap();
        Dir::open(&p)
            .unwrap()
            .remove(&n, &e.identity, e.sha256.as_deref(), &mut Budget::new())
            .unwrap();
        j.write_record(i, "done").unwrap();
    }
    for _ in 0..2 {
        let rows = j.inspect(&mut Budget::new()).unwrap();
        assert!(rows.iter().all(|r| r.status == "removed"));
    }
    assert_eq!(
        fs::read(j.plan.selected.home.join("credentials")).unwrap(),
        sentinel
    );
}
#[test]
fn interrupted_before_unlink_can_resume_only_unchanged_objects() {
    let (_t, j) = fixture();
    j.write_record(0, "intent").unwrap();
    let rows = j.inspect(&mut Budget::new()).unwrap();
    assert!(j.verify_remaining(&rows, &mut Budget::new()).is_ok());
    let e = &j.plan.entries[0];
    let (p, n) = location(&j.plan, e).unwrap();
    Dir::open(&p)
        .unwrap()
        .remove(&n, &e.identity, e.sha256.as_deref(), &mut Budget::new())
        .unwrap();
    j.write_record(0, "done").unwrap();
    assert_eq!(j.inspect(&mut Budget::new()).unwrap()[0].status, "removed");
}
#[test]
fn link_hardlink_unexpected_and_redirected_parent_preserve_all_objects() {
    for variant in 0..4 {
        let (t, j) = fixture();
        let root = j.plan.selected.home.join("pilot-front-door");
        let file = root.join("owned");
        match variant {
            0 => {
                fs::remove_file(&file).unwrap();
                symlink(j.plan.selected.home.join("credentials"), &file).unwrap();
            }
            1 => {
                fs::hard_link(&file, t.path().join("alias")).unwrap();
            }
            2 => {
                fs::write(root.join("unrecognized"), b"user data").unwrap();
            }
            _ => {
                fs::rename(&root, t.path().join("kept")).unwrap();
                symlink(t.path().join("kept"), &root).unwrap();
            }
        }
        let result = j
            .inspect(&mut Budget::new())
            .and_then(|r| j.verify_remaining(&r, &mut Budget::new()));
        assert!(result.is_err());
        assert_eq!(
            fs::read(j.plan.selected.home.join("credentials")).unwrap(),
            b"private retained sentinel"
        );
    }
}
#[test]
fn unknown_or_changed_plan_progress_and_replaced_journal_refuse() {
    for variant in 0..3 {
        let (t, j) = fixture();
        let hash = j.hash.clone();
        let path = j.plan.selected.journal.clone();
        match variant {
            0 => {
                let mut v = serde_json::to_value(&j.plan).unwrap();
                v["scope"] = json!("all");
                fs::write(path.join("plan.json"), canonical(&v).unwrap()).unwrap();
            }
            1 => {
                j.dir.write_new("unexpected.json", b"{}").unwrap();
            }
            _ => {
                fs::rename(&path, t.path().join("held")).unwrap();
                symlink(t.path().join("held"), &path).unwrap();
            }
        }
        assert!(Journal::open(
            &Retained {
                journal: path,
                expect_plan: hash,
                success_ack: None,
            },
            &mut Budget::new()
        )
        .is_err());
    }
}

#[test]
fn visible_completion_cannot_reconstruct_withheld_success_ack() {
    let (_t, j) = fixture();
    j.dir
        .write_new(
            "complete.json",
            &canonical(&Completion {
                format: FORMAT.into(),
                plan: j.hash.clone(),
                success_ack_sha256: sha(b"private-unreturned-acknowledgement-value-00000"),
            })
            .unwrap(),
        )
        .unwrap();
    assert!(!j.acknowledged(&mut Budget::new()).unwrap());
}

#[test]
fn orphan_and_damaged_earlier_attempt_records_fail_closed() {
    for orphan in [true, false] {
        let (_t, j) = fixture();
        if orphan {
            j.write_at(0, 1, "done").unwrap();
        } else {
            j.write_at(0, 0, "intent").unwrap();
            j.write_at(0, 0, "failed").unwrap();
            j.write_at(0, 1, "intent").unwrap();
            std::fs::write(
                j.plan.selected.journal.join(record_name(0, 0, "failed")),
                b"{}",
            )
            .unwrap();
        }
        assert!(Journal::open(
            &Retained {
                journal: j.plan.selected.journal.clone(),
                expect_plan: j.hash.clone(),
                success_ack: None
            },
            &mut Budget::new()
        )
        .is_err());
    }
}
