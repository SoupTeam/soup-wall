// SPDX-License-Identifier: Apache-2.0
//! Disposable local record/descriptor controls; not genuine host-run evidence.
use super::*;
use crate::edit_session::review::FileIdentity;
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
};
const OLD: &[u8] = b"Original owned project document.\n";
const NEW: &str = "Reviewed generated report.\n";
fn private(p: &Path) {
    fs::create_dir(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}
fn file(p: &Path, bytes: &[u8]) {
    fs::write(p, bytes).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
}
fn fixture() -> (tempfile::TempDir, Journal) {
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = t.path().join("project");
    private(&root);
    let outputs = t.path().join("outputs");
    private(&outputs);
    let (_, parent) = directory(t.path()).unwrap();
    let mut members = vec![];
    for i in 0..2 {
        let target = format!("destination-{i}.txt");
        let output = format!("output-{i}.txt");
        file(&root.join(&target), OLD);
        file(&outputs.join(&output), NEW.as_bytes());
        let (_, before, _) = snapshot(&root, &target, &mut Budget::new()).unwrap();
        members.push(Member {
            output: output.clone(),
            target,
            source: OutputBinding {
                run: t.path().join("run"),
                run_identity: (1, 2),
                run_sha256: "b".repeat(64),
                profile_sha256: "a".repeat(64),
                component: profile::fixture().component,
                observation_sha256: "c".repeat(64),
                binding_sha256: "d".repeat(64),
                output,
                output_identity: FileIdentity::from(
                    &fs::metadata(outputs.join(format!("output-{i}.txt"))).unwrap(),
                ),
                output_sha256: audit::sha(NEW.as_bytes()),
                output_bytes: NEW.len(),
            },
            before,
            after_sha256: audit::sha(NEW.as_bytes()),
            after_bytes: NEW.len(),
        });
    }
    file(&root.join("sibling.txt"), b"unchanged sibling");
    let plan = Plan {
        format: FORMAT.into(),
        selected: Selection {
            run: t.path().join("run"),
            plan: t.path().join("original-plan"),
            sha256: "a".repeat(64),
            mapping: members
                .iter()
                .map(|m| format!("{}={}", m.output, m.target))
                .collect(),
            root: root.clone(),
            journal: t.path().join("journal"),
        },
        root: directory(&root).unwrap().1,
        source_plan: parent.clone(),
        journal_parent: parent,
        uid: unsafe { libc::geteuid() },
        writer_exclusion: replace_file::EXCLUSION.into(),
        members,
    };
    let mut files = vec![("plan.json".into(), profile::canonical(&plan).unwrap())];
    for i in 0..2 {
        files.push((blob(i), [OLD, NEW.as_bytes()].concat()));
    }
    crate::private_export::publish(
        &plan.selected.journal,
        &files
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect::<Vec<_>>(),
        || Ok(()),
    )
    .unwrap();
    let (read, id) = directory(&plan.selected.journal).unwrap();
    let mut blobs = vec![];
    for i in 0..2 {
        blobs.push(single::identity(
            &read
                .read_output(&blob(i), 2 * CAP, &mut Budget::new())
                .unwrap()
                .unwrap()
                .1,
        ));
    }
    let hash = confirmation(&plan).unwrap();
    let binding = Binding {
        format: FORMAT.into(),
        plan: hash.clone(),
        directory: id,
        blobs,
    };
    Dir::open(&plan.selected.journal)
        .unwrap()
        .write_new("identity.json", &profile::canonical(&binding).unwrap())
        .unwrap();
    let j = Journal::open(
        &Retained {
            journal: plan.selected.journal.clone(),
            expect_plan: hash,
            proof: vec![],
        },
        &mut Budget::new(),
    )
    .unwrap();
    (t, j)
}
fn args(j: &Journal) -> Retained {
    Retained {
        journal: j.plan.selected.journal.clone(),
        expect_plan: j.hash.clone(),
        proof: j
            .proofs
            .iter()
            .map(|p| format!("{}:{}:{}:{}", p.index, p.op.name(), p.receipt, p.ack))
            .collect(),
    }
}
#[test]
fn exact_order_and_final_member_are_one_confirmation() {
    let (_t, j) = fixture();
    let hash = confirmation(&j.plan).unwrap();
    let mut p = j.plan.clone();
    p.members[1].after_sha256 = "e".repeat(64);
    assert_ne!(hash, confirmation(&p).unwrap());
    let mut p = j.plan.clone();
    p.members.swap(0, 1);
    p.selected.mapping.swap(0, 1);
    assert_ne!(hash, confirmation(&p).unwrap());
    assert!(validate(&p).is_ok());
    for map in [
        vec!["a=b".into()],
        vec!["a=b".into(), "a=c".into()],
        vec!["a=b".into(), "c=b".into()],
        vec!["a=../b".into(), "c=d".into()],
    ] {
        let mut s = j.plan.selected.clone();
        s.mapping = map;
        assert!(mappings(&s).is_err());
    }
}
#[test]
fn partial_publication_is_explicit_and_safe_member_reverts() {
    let (_t, mut j) = fixture();
    j.publish(0, Op::Apply, &mut Budget::new(), |_, _| Ok(()))
        .unwrap();
    let rows = j.inspect(&mut Budget::new()).unwrap();
    assert_eq!(
        rows.iter().map(|r| r.status).collect::<Vec<_>>(),
        ["applied", "untouched"]
    );
    assert_ne!(j.response(&mut Budget::new()).unwrap()["status"], "applied");
    let (_, _, eligible) = fresh_restore(&j, &mut Budget::new(), true).unwrap();
    assert_eq!(eligible, [0]);
    assert!(fresh_restore(&j, &mut Budget::new(), false).is_err());
    j.publish(0, Op::Revert, &mut Budget::new(), |_, _| Ok(()))
        .unwrap();
    assert_eq!(
        fs::read(j.plan.selected.root.join("destination-0.txt")).unwrap(),
        OLD
    );
    assert_eq!(
        fs::read(j.plan.selected.root.join("destination-1.txt")).unwrap(),
        OLD
    );
    assert_eq!(
        fs::read(j.plan.selected.root.join("sibling.txt")).unwrap(),
        b"unchanged sibling"
    );
}
#[test]
fn unreturned_ack_cannot_be_reconstructed_from_visible_completion() {
    let (_t, mut j) = fixture();
    j.publish(0, Op::Apply, &mut Budget::new(), |_, _| Ok(()))
        .unwrap();
    let mut a = args(&j);
    a.proof.clear();
    let j = Journal::open(&a, &mut Budget::new()).unwrap();
    assert_eq!(
        j.inspect(&mut Budget::new()).unwrap()[0].status,
        "uncertain"
    );
    assert!(fresh_restore(&j, &mut Budget::new(), true).is_err());
}
#[test]
fn last_target_preflight_refuses_before_any_publication() {
    let (_t, j) = fixture();
    let rows = j.inspect(&mut Budget::new()).unwrap();
    file(
        &j.plan.selected.root.join("destination-1.txt"),
        b"user edit",
    );
    assert!(j.guard_targets(&rows, &mut Budget::new()).is_err());
    assert_eq!(
        fs::read(j.plan.selected.root.join("destination-0.txt")).unwrap(),
        OLD
    );
}
#[test]
fn user_change_and_missing_name_remain_uncertain_while_safe_other_is_recoverable() {
    for missing in [false, true] {
        let (_t, mut j) = fixture();
        for i in 0..2 {
            j.publish(i, Op::Apply, &mut Budget::new(), |_, _| Ok(()))
                .unwrap();
        }
        let target = j.plan.selected.root.join("destination-0.txt");
        if missing {
            fs::remove_file(&target).unwrap()
        } else {
            file(&target, b"later user content")
        }
        let (_, rows, eligible) = fresh_restore(&j, &mut Budget::new(), true).unwrap();
        assert_eq!(eligible, [1]);
        assert_eq!(rows[0].status, "uncertain");
        assert!(fresh_restore(&j, &mut Budget::new(), false).is_err());
        j.guard_targets(&rows, &mut Budget::new()).unwrap();
        j.publish(1, Op::Revert, &mut Budget::new(), |_, _| Ok(()))
            .unwrap();
        if missing {
            assert!(!target.exists())
        } else {
            assert_eq!(fs::read(target).unwrap(), b"later user content")
        }
    }
}
#[test]
fn changed_journal_backup_progress_and_redirected_parent_fail_closed() {
    for case in 0..4 {
        let (t, j) = fixture();
        let a = args(&j);
        match case {
            0 => file(&j.plan.selected.journal.join("images-01.bin"), b"tampered"),
            1 => file(&j.plan.selected.journal.join("apply-00-done.json"), b"{}"),
            2 => file(&j.plan.selected.journal.join("unexpected.json"), b"{}"),
            _ => {
                fs::rename(&j.plan.selected.journal, t.path().join("kept")).unwrap();
                symlink(t.path().join("kept"), &j.plan.selected.journal).unwrap();
            }
        }
        assert!(Journal::open(&a, &mut Budget::new()).is_err());
        assert_eq!(
            fs::read(j.plan.selected.root.join("destination-0.txt")).unwrap(),
            OLD
        );
    }
}
#[test]
fn same_bytes_new_inode_and_bad_or_duplicate_proofs_never_authorize_restore() {
    let (_t, mut j) = fixture();
    j.publish(0, Op::Apply, &mut Budget::new(), |_, _| Ok(()))
        .unwrap();
    let target = j.plan.selected.root.join("destination-0.txt");
    let replacement = j.plan.selected.root.join("new");
    file(&replacement, NEW.as_bytes());
    fs::rename(replacement, target).unwrap();
    assert_eq!(
        j.inspect(&mut Budget::new()).unwrap()[0].status,
        "uncertain"
    );
    let mut a = args(&j);
    a.proof.push(a.proof[0].clone());
    assert!(Journal::open(&a, &mut Budget::new()).is_err());
    assert!(proof("0:apply:bad:bad", 2).is_err());
}

#[test]
fn changed_final_target_at_publication_gate_preserves_first_preimage() {
    let (_t, mut j) = fixture();
    let rows = j.inspect(&mut Budget::new()).unwrap();
    let result = j.publish(0, Op::Apply, &mut Budget::new(), |j, b| {
        file(
            &j.plan.selected.root.join("destination-1.txt"),
            b"later user edit",
        );
        j.guard_targets(&rows, b)
    });
    assert!(result.is_err());
    assert_eq!(
        fs::read(j.plan.selected.root.join("destination-0.txt")).unwrap(),
        OLD
    );
    assert_eq!(
        fs::read(j.plan.selected.root.join("destination-1.txt")).unwrap(),
        b"later user edit"
    );
}
