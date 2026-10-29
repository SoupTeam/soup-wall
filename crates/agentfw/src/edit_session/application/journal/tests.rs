// SPDX-License-Identifier: Apache-2.0
//! Local record/descriptor controls, not claims of a genuine completed host run.
use super::*;
use crate::edit_session::{
    application::Selection,
    review::{FileIdentity, OutputBinding},
};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

const OLD: &[u8] = b"Original private project document.\n";
const NEW: &str = "Reviewed generated document.\n";

fn write(path: &Path, raw: &[u8]) {
    fs::write(path, raw).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn fixture() -> (tempfile::TempDir, Journal) {
    let top = tempfile::tempdir().unwrap();
    fs::set_permissions(top.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = top.path().join("project");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    write(&root.join("selected.txt"), OLD);
    write(&root.join("sentinel.txt"), b"unrelated");
    let (root_identity, before, _) = snapshot(&root, "selected.txt", &mut Budget::new()).unwrap();
    let p = profile::fixture();
    let (_, parent) = directory(top.path()).unwrap();
    let plan = Plan {
        format: FORMAT.into(),
        selected: Selection {
            run: top.path().join("unopened-run"),
            plan: top.path().join("unopened-plan"),
            sha256: "a".repeat(64),
            output: "generated.txt".into(),
            root: root.clone(),
            target: "selected.txt".into(),
            journal: top.path().join("journal"),
        },
        source: OutputBinding {
            run: top.path().join("unopened-run"),
            run_identity: (1, 2),
            run_sha256: "b".repeat(64),
            profile_sha256: "a".repeat(64),
            component: p.component,
            observation_sha256: "c".repeat(64),
            binding_sha256: "d".repeat(64),
            output: "generated.txt".into(),
            output_identity: FileIdentity::from(&fs::metadata(root.join("selected.txt")).unwrap()),
            output_sha256: replace_file::content_sha256(NEW.as_bytes()),
            output_bytes: NEW.len(),
        },
        source_plan_identity: parent.clone(),
        root_identity,
        before,
        after_sha256: replace_file::content_sha256(NEW.as_bytes()),
        after_bytes: NEW.len(),
        journal_parent_identity: parent,
        writer_exclusion: replace_file::EXCLUSION.into(),
        operator_uid: unsafe { libc::geteuid() },
    };
    let raw = profile::canonical(&plan).unwrap();
    crate::private_export::publish(
        &plan.selected.journal,
        &[("plan.json", &raw), ("preimage.bin", OLD)],
        || Ok(()),
    )
    .unwrap();
    let (read, id) = directory(&plan.selected.journal).unwrap();
    let (_, meta) = read
        .read_output("preimage.bin", CAP, &mut Budget::new())
        .unwrap()
        .unwrap();
    let identity = JournalIdentity {
        format: FORMAT.into(),
        plan: confirmation(&plan).unwrap(),
        directory: id,
        preimage: super::identity(&meta),
    };
    Dir::open(&plan.selected.journal)
        .unwrap()
        .write_new("identity.json", &profile::canonical(&identity).unwrap())
        .unwrap();
    let journal =
        Journal::open(&plan.selected.journal, &identity.plan, &mut Budget::new()).unwrap();
    (top, journal)
}

fn actual_publication(
    j: &Journal,
    op: Operation,
    previous: Option<&Receipt>,
    finish: bool,
) -> Receipt {
    let before = previous.map_or(&j.plan.before, |r| &r.after);
    let content = if op == Operation::Apply {
        NEW
    } else {
        std::str::from_utf8(&j.before).unwrap()
    };
    let staged = replace_file::Prepared::prepare(
        &j.plan.selected.root,
        &j.plan.selected.root.join("selected.txt"),
        &j.plan.root_identity,
        &before.identity,
        &before.sha256,
        content,
    )
    .unwrap()
    .stage()
    .unwrap();
    let intent = Intent {
        format: FORMAT.into(),
        operation: op,
        plan: j.identity.plan.clone(),
        journal: j.identity.directory.clone(),
        before: before.clone(),
        staged: staged.staged_identity().unwrap(),
        after_sha256: replace_file::content_sha256(content.as_bytes()),
        previous_receipt: previous.map(receipt_digest).transpose().unwrap(),
    };
    j.dir
        .write_new(op.intent(), &profile::canonical(&intent).unwrap())
        .unwrap();
    let committed = staged
        .publish_before(Instant::now() + Duration::from_secs(3))
        .unwrap();
    assert!(committed.committed && committed.file_synced && committed.directory_synced);
    let (_, after, _) =
        snapshot(&j.plan.selected.root, "selected.txt", &mut Budget::new()).unwrap();
    let receipt = Receipt {
        format: FORMAT.into(),
        operation: op,
        plan: j.identity.plan.clone(),
        journal: j.identity.directory.clone(),
        intent_sha256: digest(b"agentfw/edit-application-intent/v1\0", &intent).unwrap(),
        after,
        file_synced: true,
        directory_synced: true,
    };
    if finish {
        j.dir
            .write_new(op.receipt(), &profile::canonical(&receipt).unwrap())
            .unwrap();
    }
    receipt
}

#[test]
fn application_receipt_requires_actual_bound_descriptors_and_external_success_ack() {
    let (_top, j) = fixture();
    let receipt = actual_publication(&j, Operation::Apply, None, true);
    let hash = receipt_digest(&receipt).unwrap();
    assert!(j.acknowledged(None, &mut Budget::new()).is_err());
    assert!(j
        .acknowledged(Some(&"a".repeat(64)), &mut Budget::new())
        .is_err());
    assert_eq!(
        j.acknowledged(Some(&hash), &mut Budget::new()).unwrap().0,
        Operation::Apply
    );
    assert_eq!(
        fs::read(j.plan.selected.root.join("sentinel.txt")).unwrap(),
        b"unrelated"
    );
    assert_eq!(fs::read(j.path.join("preimage.bin")).unwrap(), OLD);
}

#[test]
fn interrupted_after_publication_never_becomes_success_from_matching_bytes() {
    let (_top, j) = fixture();
    let receipt = actual_publication(&j, Operation::Apply, None, false);
    assert_eq!(
        fs::read(j.plan.selected.root.join("selected.txt")).unwrap(),
        NEW.as_bytes()
    );
    assert!(j
        .acknowledged(Some(&receipt_digest(&receipt).unwrap()), &mut Budget::new())
        .is_err());
    assert!(j
        .dir
        .write_new(Operation::Apply.intent(), b"retry")
        .is_err());
    assert_eq!(fs::read(j.path.join("preimage.bin")).unwrap(), OLD);
}

#[test]
fn later_user_edit_and_byte_restore_both_invalidate_the_postimage_descriptor() {
    let (_top, j) = fixture();
    let receipt = actual_publication(&j, Operation::Apply, None, true);
    let hash = receipt_digest(&receipt).unwrap();
    write(
        &j.plan.selected.root.join("selected.txt"),
        b"Later user work",
    );
    assert!(j.acknowledged(Some(&hash), &mut Budget::new()).is_err());
    write(&j.plan.selected.root.join("selected.txt"), NEW.as_bytes());
    assert!(j.acknowledged(Some(&hash), &mut Budget::new()).is_err());
}

#[test]
fn exact_revert_keeps_original_evidence_and_requires_a_new_success_receipt() {
    let (_top, j) = fixture();
    let applied = actual_publication(&j, Operation::Apply, None, true);
    let reverted = actual_publication(&j, Operation::Revert, Some(&applied), true);
    assert_eq!(
        fs::read(j.plan.selected.root.join("selected.txt")).unwrap(),
        OLD
    );
    assert!(j
        .acknowledged(Some(&receipt_digest(&applied).unwrap()), &mut Budget::new())
        .is_err());
    assert_eq!(
        j.acknowledged(
            Some(&receipt_digest(&reverted).unwrap()),
            &mut Budget::new()
        )
        .unwrap()
        .0,
        Operation::Revert
    );
    assert_eq!(fs::read(j.path.join("preimage.bin")).unwrap(), OLD);
    assert!(j.path.join("applied.json").is_file());
}

#[test]
fn damaged_or_replaced_backup_and_journal_are_refused_even_with_identical_bytes() {
    for variant in 0..4 {
        let (top, j) = fixture();
        let path = j.path.clone();
        let hash = j.identity.plan.clone();
        match variant {
            0 => write(&path.join("preimage.bin"), b"damage"),
            1 => {
                write(&path.join("preimage.bin"), OLD);
            }
            2 => {
                fs::hard_link(path.join("preimage.bin"), top.path().join("alias")).unwrap();
            }
            _ => {
                let held = top.path().join("held");
                fs::rename(&path, &held).unwrap();
                symlink(&held, &path).unwrap();
            }
        }
        assert!(Journal::open(&path, &hash, &mut Budget::new()).is_err());
    }
}

#[test]
fn unknown_nested_plan_or_receipt_fields_and_uncertain_records_fail_closed() {
    for variant in 0..3 {
        let (_top, j) = fixture();
        let receipt = actual_publication(&j, Operation::Apply, None, true);
        let hash = receipt_digest(&receipt).unwrap();
        if variant == 0 {
            let mut plan = serde_json::to_value(&j.plan).unwrap();
            plan["selected"]["unexpected"] = serde_json::json!(true);
            write(
                &j.path.join("plan.json"),
                &serde_json::to_vec(&plan).unwrap(),
            );
            assert!(Journal::open(&j.path, &j.identity.plan, &mut Budget::new()).is_err());
        } else if variant == 1 {
            let mut changed = serde_json::to_value(&receipt).unwrap();
            changed["unexpected"] = serde_json::json!(true);
            write(
                &j.path.join("applied.json"),
                &serde_json::to_vec(&changed).unwrap(),
            );
            assert!(j.acknowledged(Some(&hash), &mut Budget::new()).is_err());
        } else {
            let failure = Failure {
                format: FORMAT.into(),
                operation: Operation::Apply,
                plan: j.identity.plan.clone(),
                status: "indeterminate".into(),
            };
            j.dir
                .write_new("indeterminate.json", &profile::canonical(&failure).unwrap())
                .unwrap();
            assert!(j.acknowledged(Some(&hash), &mut Budget::new()).is_err());
        }
    }
}
