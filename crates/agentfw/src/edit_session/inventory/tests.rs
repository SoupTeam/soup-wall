// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::edit_session::{profile::Profile, record::Context, FORMAT as RUN_FORMAT};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

fn private(path: &Path, bytes: &[u8]) {
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}
fn directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
struct Fixture {
    _temp: tempfile::TempDir,
    state: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let state = temp.path().join("state");
        directory(&state);
        Self { _temp: temp, state }
    }
    fn run(&self, number: u32, completed: bool) -> (String, PathBuf, Profile, Context) {
        let id = format!("00000000-0000-4000-8000-{number:012x}");
        let run = self.state.join(name(&id).unwrap());
        directory(&run);
        let p = profile::fixture();
        let context = Context {
            format: record::FORMAT.into(),
            run: run.clone(),
            home: run.join("h".repeat(43)),
            profile_sha256: profile::digest(&p).unwrap(),
            host_session: "owned-host".into(),
            instance_id: "owned-instance".into(),
            config_sha256: "c".repeat(64),
            listener: record::ListenerIdentity {
                fd: 3,
                inode: 1,
                device: 1,
            },
            started_at_ms: crate::protection_status::now_ms(),
            owner: record::process_identity(std::process::id()).unwrap(),
        };
        private(
            &run.join("diagnostic-context.json"),
            &profile::canonical(&context).unwrap(),
        );
        private(
            &run.join("run.json"),
            &profile::canonical(&json!({"format":RUN_FORMAT,
            "run":run,"home":context.home,"profile_sha256":context.profile_sha256,
            "host_session":context.host_session,"instance_id":context.instance_id}))
            .unwrap(),
        );
        private(&run.join("profile.json"), &profile::canonical(&p).unwrap());
        private(
            &run.join("profile.sha256"),
            context.profile_sha256.as_bytes(),
        );
        if completed {
            private(&run.join("terminal.json"),&profile::canonical(&json!({"format":RUN_FORMAT,
                "state":"host_completed","reason":"host_completed","run":run,
                "profile_sha256":context.profile_sha256,"cleanup":{"cleaned":true,"reaped":true,
                "exit_success":true,"graceful_observed":true,"ownership":"owned","failure":null},
                "daemon_clean":true,"mutation_dispatches":0,
                "effect_status":"consult-native-audit; interrupted-or-withheld-result-is-indeterminate; no-automatic-retry"})).unwrap());
        }
        (id, run, p, context)
    }
}

#[test]
fn inventory_is_bounded_content_free_and_does_not_follow_descriptive_paths() {
    let f = Fixture::new();
    let (one, first, _, _) = f.run(1, true);
    let (two, second, _, _) = f.run(2, false);
    // Missing external roots, executables and daemon homes from profile fixtures
    // must not matter. No arbitrary retained prompt or output is opened.
    symlink("/dev/zero", first.join("raw-prompt.private")).unwrap();
    fs::write(
        second.join("untrusted-private-name"),
        b"private-secret-canary",
    )
    .unwrap();
    let before = fs::read(first.join("run.json")).unwrap();
    let mut report = Report::new();
    inventory(&f.state, None, &mut report).unwrap();
    assert_eq!(report.status, "complete");
    assert_eq!(report.rows.len(), 2);
    let row = |id: &str| {
        report
            .rows
            .iter()
            .find(|r| r.run_id.as_deref() == Some(id))
            .unwrap()
    };
    assert_eq!(row(&one).recorded_host_outcome, "recorded_host_completed");
    assert_eq!(row(&two).recorded_host_outcome, "terminal_not_recorded");
    assert_eq!(
        row(&two).owner_observation,
        "identity_matches_liveness_not_established"
    );
    let rendered = serde_json::to_string(&report).unwrap();
    for secret in [
        f.state.to_str().unwrap(),
        "private-secret-canary",
        "untrusted-private-name",
        "raw-prompt.private",
    ] {
        assert!(!rendered.contains(secret));
    }
    assert_eq!(before, fs::read(first.join("run.json")).unwrap());
    assert!(!report.executed && !report.authority);
}

#[test]
fn damaged_or_unknown_history_is_not_completed_and_names_are_not_disclosed() {
    let f = Fixture::new();
    let (_, run, _, _) = f.run(1, true);
    private(&run.join("terminal.json"), b"{broken private-secret-canary");
    fs::write(f.state.join("private-secret-canary"), b"not a run").unwrap();
    let mut report = Report::new();
    inventory(&f.state, None, &mut report).unwrap();
    assert_eq!(report.status, "incomplete");
    assert!(report
        .rows
        .iter()
        .all(|r| r.status == "unknown" && r.selection_sha256.is_none()));
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("private-secret-canary"));
}

#[test]
fn old_boot_is_retained_history_without_inactivity_or_completion_inference() {
    let f = Fixture::new();
    let (_, run, _, mut c) = f.run(1, false);
    c.owner.boot_id = "00000000-0000-0000-0000-000000000000".into();
    private(
        &run.join("diagnostic-context.json"),
        &profile::canonical(&c).unwrap(),
    );
    let selected = Pinned::inspect(
        &f.state,
        run.file_name().unwrap().to_str().unwrap(),
        &mut Budget::new(),
    )
    .unwrap();
    assert_eq!(selected.row.owner_observation, "recorded_old_boot");
    assert_eq!(selected.row.recorded_host_outcome, "terminal_not_recorded");
}

#[test]
fn exact_id_never_accepts_paths_prefixes_options_or_noncanonical_names() {
    for id in [
        "",
        "..",
        "../outside",
        "-owned-id",
        "--help",
        "00000000",
        "00000000-0000-4000-8000-00000000000A",
        "a/b",
    ] {
        assert!(name(id).is_err(), "{id}");
    }
    let f = Fixture::new();
    let (id, _, _, _) = f.run(1, false);
    f.run(2, false);
    let mut report = Report::new();
    inventory(&f.state, Some(&id), &mut report).unwrap();
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.rows[0].run_id.as_deref(), Some(id.as_str()));
    assert!(inventory(
        &f.state,
        Some("00000000-0000-4000-8000-000000000003"),
        &mut Report::new()
    )
    .is_err());
}

#[test]
fn cap_reports_partial_inventory_instead_of_claiming_full_history() {
    let f = Fixture::new();
    for i in 0..MAX_ENTRIES + 1 {
        directory(&f.state.join(format!("unrecognized-{i}")));
    }
    let mut report = Report::new();
    inventory(&f.state, None, &mut report).unwrap();
    assert_eq!(report.rows.len(), MAX_ENTRIES);
    assert_eq!(report.reason, "inventory_entry_limit");
    assert_eq!(report.status, "incomplete");
}

#[test]
fn links_foreign_modes_special_and_hardlinked_records_never_yield_a_selection() {
    let f = Fixture::new();
    let (_, run, _, _) = f.run(1, false);
    let id = "00000000-0000-4000-8000-000000000002";
    symlink(&run, f.state.join(name(id).unwrap())).unwrap();
    let mut report = Report::new();
    inventory(&f.state, Some(id), &mut report).unwrap_err();
    let raw = fs::read(run.join("run.json")).unwrap();
    fs::remove_file(run.join("run.json")).unwrap();
    let fifo = std::ffi::CString::new(run.join("run.json").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(Pinned::inspect(
        &f.state,
        run.file_name().unwrap().to_str().unwrap(),
        &mut Budget::new()
    )
    .is_err());
    fs::remove_file(run.join("run.json")).unwrap();
    private(&run.join("run.json"), &raw);
    fs::hard_link(run.join("run.json"), run.join("alias")).unwrap();
    assert!(Pinned::inspect(
        &f.state,
        run.file_name().unwrap().to_str().unwrap(),
        &mut Budget::new()
    )
    .is_err());
    fs::remove_file(run.join("alias")).unwrap();
    fs::set_permissions(run.join("run.json"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Pinned::inspect(
        &f.state,
        run.file_name().unwrap().to_str().unwrap(),
        &mut Budget::new()
    )
    .is_err());
}

#[test]
fn changed_root_run_file_or_missing_terminal_invalidates_the_held_selection() {
    let f = Fixture::new();
    let (id, run, _, _) = f.run(1, false);
    let pinned = Pinned::inspect(&f.state, &name(&id).unwrap(), &mut Budget::new()).unwrap();
    pinned.recheck(&f.state, &mut Budget::new()).unwrap();
    private(&run.join("terminal.json"), b"{}");
    assert!(pinned.recheck(&f.state, &mut Budget::new()).is_err());
    fs::remove_file(run.join("terminal.json")).unwrap();
    let selected = Pinned::inspect(&f.state, &name(&id).unwrap(), &mut Budget::new()).unwrap();
    let raw = fs::read(run.join("run.json")).unwrap();
    fs::rename(run.join("run.json"), run.join("old-record")).unwrap();
    private(&run.join("run.json"), &raw);
    assert!(selected.recheck(&f.state, &mut Budget::new()).is_err());
    let selected = Pinned::inspect(&f.state, &name(&id).unwrap(), &mut Budget::new()).unwrap();
    let moved = f.state.with_file_name("old-state");
    fs::rename(&f.state, &moved).unwrap();
    directory(&f.state);
    assert!(selected.recheck(&f.state, &mut Budget::new()).is_err());
}

#[test]
fn unchanged_identity_is_repeatable_and_budget_is_shared() {
    let f = Fixture::new();
    let (id, _, _, _) = f.run(1, true);
    let first = Pinned::inspect(&f.state, &name(&id).unwrap(), &mut Budget::new()).unwrap();
    let second = Pinned::inspect(&f.state, &name(&id).unwrap(), &mut Budget::new()).unwrap();
    assert_eq!(first.row.selection_sha256, second.row.selection_sha256);
    let mut exhausted = Budget::new();
    assert!(exhausted.tick(2097153).is_err());
    assert!(Pinned::inspect(&f.state, &name(&id).unwrap(), &mut exhausted).is_err());
}
