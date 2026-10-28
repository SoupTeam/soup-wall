// SPDX-License-Identifier: Apache-2.0
use super::*;

const REGISTRY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BINDING: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
fn ledger(operations: u64, bytes: u64) -> Arc<Ledger> {
    Ledger::new(
        Limits::new(operations, bytes).unwrap(),
        REGISTRY.into(),
        "host".into(),
    )
    .unwrap()
}
fn reserve(q: &Arc<Ledger>, bytes: u64) -> Ticket {
    q.reserve(
        REGISTRY,
        Some("host"),
        &crate::token::generate(),
        BINDING,
        bytes,
    )
    .unwrap()
}
fn committed(mut ticket: Ticket) {
    ticket.begin_publication().unwrap();
    ticket.complete(true).unwrap();
}

#[test]
fn exact_operation_and_byte_boundaries_include_empty_mutations() {
    let q = ledger(2, 7);
    committed(reserve(&q, 3));
    committed(reserve(&q, 4));
    let s = q.snapshot().unwrap();
    assert_eq!(s.admitted_mutation_attempts, 2);
    assert_eq!(s.known_committed_mutations, 2);
    assert_eq!(s.known_committed_write_bytes, 7);
    assert_eq!((s.remaining_mutations, s.remaining_write_bytes), (0, 0));
    assert_eq!(
        q.reserve(REGISTRY, Some("host"), "new", BINDING, 0)
            .err()
            .unwrap()
            .code,
        "edit_quota_mutation_limit"
    );
    let empty = ledger(1, 0);
    committed(reserve(&empty, 0));
    assert_eq!(empty.snapshot().unwrap().known_committed_mutations, 1);
    assert_eq!(empty.snapshot().unwrap().known_committed_write_bytes, 0);
}

#[test]
fn one_byte_over_limit_is_refused_without_any_charge() {
    let q = ledger(3, 7);
    assert_eq!(
        q.reserve(REGISTRY, Some("host"), "large", BINDING, 8)
            .err()
            .unwrap()
            .code,
        "edit_quota_write_byte_limit"
    );
    assert_eq!(q.snapshot().unwrap().admitted_mutation_attempts, 0);
    committed(reserve(&q, 7));
    assert_eq!(
        q.reserve(REGISTRY, Some("host"), "over", BINDING, 1)
            .err()
            .unwrap()
            .code,
        "edit_quota_write_byte_limit"
    );
    assert_eq!(q.snapshot().unwrap().admitted_mutation_attempts, 1);
    assert_eq!(q.snapshot().unwrap().remaining_write_bytes, 0);
}

#[test]
fn unapproved_work_does_not_reserve_and_spent_credits_are_never_refunded() {
    let q = ledger(4, 4);
    assert_eq!(q.snapshot().unwrap().remaining_mutations, 4);
    // Cancellation/staging failure cannot free capacity while a detached
    // staging worker is still running; no worker owns publication authority.
    drop(reserve(&q, 4));
    let s = q.snapshot().unwrap();
    assert_eq!(s.known_not_committed_mutations, 1);
    assert_eq!(s.known_committed_mutations, 0);
    assert_eq!(s.charged_write_bytes, 4);
    assert_eq!(s.remaining_write_bytes, 0);
    assert!(q
        .reserve(REGISTRY, Some("host"), "retry", BINDING, 1)
        .is_err());
}

#[test]
fn ambiguous_publication_and_lost_result_cannot_reopen_authority() {
    let q = ledger(2, 8);
    let mut ticket = reserve(&q, 4);
    ticket.begin_publication().unwrap();
    drop(ticket);
    let before = q.snapshot().unwrap();
    assert_eq!(before.indeterminate_publications, 1);
    assert_eq!(before.known_committed_mutations, 0);
    committed(reserve(&q, 4));
    // A result can be withheld after this point, but bookkeeping is already
    // final and no result/receipt callback can decrease the charge.
    let s = q.snapshot().unwrap();
    assert_eq!(s.known_committed_mutations, 1);
    assert_eq!(s.indeterminate_publications, 1);
    assert_eq!((s.remaining_mutations, s.remaining_write_bytes), (0, 0));
    assert!(q
        .reserve(REGISTRY, Some("host"), "after-loss", BINDING, 0)
        .is_err());
    assert_eq!(q.snapshot().unwrap(), s);
}

#[test]
fn call_replay_changed_binding_and_foreign_run_are_refused_without_consumption() {
    let q = ledger(4, 20);
    committed(
        q.reserve(REGISTRY, Some("host"), "exact-call", BINDING, 4)
            .unwrap(),
    );
    for binding in [BINDING, REGISTRY] {
        assert_eq!(
            q.reserve(REGISTRY, Some("host"), "exact-call", binding, 4)
                .err()
                .unwrap()
                .code,
            "edit_quota_request_replayed"
        );
    }
    for (registry, host) in [
        (BINDING, Some("host")),
        (REGISTRY, Some("other-host")),
        (REGISTRY, None),
    ] {
        assert_eq!(
            q.reserve(registry, host, "other", BINDING, 4)
                .err()
                .unwrap()
                .code,
            "edit_quota_scope_mismatch"
        );
    }
    assert_eq!(q.snapshot().unwrap().admitted_mutation_attempts, 1);
    let fresh = ledger(4, 20);
    assert_eq!(fresh.snapshot().unwrap().remaining_mutations, 4);
    assert_eq!(q.snapshot().unwrap().known_committed_mutations, 1);
}

#[test]
fn concurrent_last_credit_has_exactly_one_reservation() {
    let q = ledger(1, 7);
    let barrier = Arc::new(std::sync::Barrier::new(16));
    let results = std::thread::scope(|scope| {
        let handles = (0..16)
            .map(|_| {
                let q = q.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    let result = q.reserve(
                        REGISTRY,
                        Some("host"),
                        &crate::token::generate(),
                        BINDING,
                        7,
                    );
                    match result {
                        Ok(ticket) => {
                            committed(ticket);
                            true
                        }
                        Err(_) => false,
                    }
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|&&x| x).count(), 1);
    let s = q.snapshot().unwrap();
    assert_eq!(s.known_committed_mutations, 1);
    assert_eq!(s.charged_write_bytes, 7);
}

#[test]
fn zero_and_invalid_limits_never_create_default_write_authority() {
    let q = ledger(0, 0);
    assert!(q
        .reserve(REGISTRY, Some("host"), "empty", BINDING, 0)
        .is_err());
    assert!(Limits::new(MAX_MUTATIONS + 1, 0).is_err());
    assert!(Limits::new(1, MAX_BYTES + 1).is_err());
    assert!(Limits::new(u64::MAX, u64::MAX).is_err());
    let mut bad = Limits::new(1, 1).unwrap();
    bad.contract_version = "unknown".into();
    assert!(bad.validate().is_err());
}

#[test]
fn strict_profile_versions_reject_ambiguous_unknown_negative_and_overflow_budgets() {
    let old = crate::edit_session::profile::fixture();
    let legacy = crate::edit_session::profile::canonical(&old).unwrap();
    let value: Value = serde_json::from_slice(&legacy).unwrap();
    assert!(value.get("mutation_quota").is_none());
    assert_eq!(
        serde_json::from_slice::<crate::edit_session::Profile>(&legacy).unwrap(),
        old
    );
    let mut quota = old.clone();
    quota.format = crate::edit_session::QUOTA_PROFILE.into();
    assert!(quota.validate().is_err());
    quota.mutation_quota = Some(Limits::new(2, 8).unwrap());
    quota.validate().unwrap();
    assert_eq!(quota.tools(), old.tools());
    assert_eq!(
        quota.registry().unwrap()["tools"],
        old.registry().unwrap()["tools"]
    );
    assert_ne!(
        crate::edit_session::profile::digest(&quota).unwrap(),
        crate::edit_session::profile::digest(&old).unwrap()
    );
    for invalid in [
        Value::Null,
        json!({}),
        json!({"contract_version":CONTRACT,"max_mutations":-1,"max_write_bytes":8}),
        json!({"contract_version":CONTRACT,"max_mutations":1.5,"max_write_bytes":8}),
        json!({"contract_version":CONTRACT,"max_mutations":"2","max_write_bytes":8}),
        json!({"contract_version":CONTRACT,"max_mutations":2,"max_write_bytes":8,"unlimited":true}),
    ] {
        let mut value = serde_json::to_value(&quota).unwrap();
        value["mutation_quota"] = invalid;
        assert!(serde_json::from_value::<crate::edit_session::Profile>(value).is_err());
    }
    let duplicate = format!(
        r#"{{"contract_version":"{CONTRACT}","max_mutations":1,"max_mutations":2,"max_write_bytes":8}}"#
    );
    assert!(serde_json::from_str::<crate::mcp::admission::Strict>(&duplicate).is_err());
    let overflow = format!(
        r#"{{"contract_version":"{CONTRACT}","max_mutations":18446744073709551616,"max_write_bytes":8}}"#
    );
    assert!(serde_json::from_str::<Limits>(&overflow).is_err());
    let mut mixed = quota.clone();
    mixed.format = crate::edit_session::FORMAT.into();
    assert!(mixed.validate().is_err());
}

#[test]
fn poisoned_state_refuses_instead_of_claiming_an_empty_budget() {
    let q = ledger(2, 8);
    let owned = q.clone();
    assert!(std::thread::spawn(move || {
        let _held = owned.entries.lock().unwrap();
        panic!("controlled ledger poison");
    })
    .join()
    .is_err());
    assert_eq!(
        q.snapshot().unwrap_err().code,
        "edit_quota_state_unavailable"
    );
    let error = q
        .reserve(REGISTRY, Some("host"), "call", BINDING, 4)
        .err()
        .unwrap();
    assert_eq!(error.code, "edit_quota_state_unavailable");
    assert!(error.usage.is_none());
    let raw = String::from_utf8(error.response(&json!(1))).unwrap();
    assert!(!raw.contains("remaining_mutations\":0"));
    assert!(raw.contains("inspect_output_then_explicit_prepare"));
}

#[cfg(target_os = "linux")]
#[test]
fn concurrent_last_credit_bounds_actual_create_effects_and_preserves_other_bytes() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let root = d.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.join("sentinel.txt"), b"unrelated owned bytes\n").unwrap();
    let q = ledger(1, 4);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let handles = ["a.txt", "b.txt"]
            .into_iter()
            .map(|name| {
                let root = &root;
                let q = q.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    let ws = crate::sandbox::PinnedWorkspace::open(root).unwrap();
                    let prepared = crate::mcp::create_file::PreparedCreate::prepare(
                        &ws,
                        &root.join(name),
                        "safe",
                    )
                    .unwrap();
                    barrier.wait();
                    let Ok(mut ticket) = q.reserve(REGISTRY, Some("host"), name, BINDING, 4) else {
                        return false;
                    };
                    let staged = prepared.stage().unwrap();
                    ticket.begin_publication().unwrap();
                    let done = staged.publish().unwrap();
                    ticket.complete(done.committed).unwrap();
                    true
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|&&x| x).count(), 1);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 2);
    assert_eq!(
        std::fs::read(root.join("sentinel.txt")).unwrap(),
        b"unrelated owned bytes\n"
    );
    let file = if root.join("a.txt").exists() {
        "a.txt"
    } else {
        "b.txt"
    };
    assert_eq!(std::fs::read(root.join(file)).unwrap(), b"safe");
    assert_eq!(q.snapshot().unwrap().known_committed_write_bytes, 4);
}
