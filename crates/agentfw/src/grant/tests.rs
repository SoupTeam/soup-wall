// SPDX-License-Identifier: Apache-2.0
use super::*;

const KEY: &[u8] = b"test-key-material";
const NOW: u64 = 1_000_000;

/// `file_name` uses the same lossy map as the manifest store, where it was
/// a real defect: distinct ids collided onto one file. It is safe here only
/// because a nonce is base64url, whose alphabet is exactly the set the map
/// preserves. That is the load-bearing fact, so assert it rather than
/// trusting the two functions to stay in agreement.
#[test]
fn nonces_are_already_in_the_preserved_alphabet() {
    for _ in 0..64 {
        let nonce = crate::token::generate();
        assert!(
            nonce
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "nonce {nonce} left the alphabet file_name preserves"
        );
        assert_eq!(
            GrantStore::file_name(&nonce),
            format!("{nonce}.json"),
            "the sanitizer must be the identity on a real nonce"
        );
    }
}

fn action() -> ActionRef {
    ActionRef {
        session: "s1".into(),
        tool: "Bash".into(),
        args_fingerprint: action_fingerprint(
            "Bash",
            &serde_json::json!({"command": "rm -rf ./build"}),
        ),
    }
}

fn granted() -> Grant {
    mint(KEY, &action(), NOW, DEFAULT_TTL_MS, "nonce-1".into())
}

#[test]
fn a_fresh_grant_verifies_for_the_action_it_was_issued_for() {
    assert_eq!(verify(KEY, &granted(), &action(), NOW + 1), Ok(()));
}

/// The core binding: approving one command must not authorize another. A
/// grant that only named the tool would turn "yes, delete ./build" into
/// "yes, run any shell command".
#[test]
fn a_grant_does_not_authorize_different_arguments() {
    let destructive = ActionRef {
        args_fingerprint: action_fingerprint("Bash", &serde_json::json!({"command": "rm -rf /"})),
        ..action()
    };
    assert_eq!(
        verify(KEY, &granted(), &destructive, NOW + 1),
        Err(GrantError::ActionMismatch)
    );
}

#[test]
fn a_grant_does_not_cross_sessions_or_tools() {
    let other_session = ActionRef {
        session: "s2".into(),
        ..action()
    };
    assert_eq!(
        verify(KEY, &granted(), &other_session, NOW + 1),
        Err(GrantError::ActionMismatch)
    );
    let other_tool = ActionRef {
        tool: "Write".into(),
        ..action()
    };
    assert_eq!(
        verify(KEY, &granted(), &other_tool, NOW + 1),
        Err(GrantError::ActionMismatch)
    );
}

#[test]
fn an_expired_grant_is_refused() {
    let grant = granted();
    assert_eq!(
        verify(KEY, &grant, &action(), grant.expires_at_ms),
        Err(GrantError::Expired),
        "expiry is exclusive: the moment it expires it is already unusable"
    );
}

/// A grant minted under another key must not verify, whatever it claims.
#[test]
fn a_grant_from_a_different_key_is_refused() {
    let forged = mint(b"other-key", &action(), NOW, DEFAULT_TTL_MS, "n".into());
    assert_eq!(
        verify(KEY, &forged, &action(), NOW + 1),
        Err(GrantError::BadSignature)
    );
}

/// Every field is covered by the signature, so none can be edited after
/// minting -- in particular the expiry.
#[test]
fn tampering_with_any_field_breaks_the_signature() {
    let base = granted();
    let mutations: Vec<Grant> = vec![
        Grant {
            expires_at_ms: base.expires_at_ms + 86_400_000,
            ..base.clone()
        },
        Grant {
            session: "s2".into(),
            ..base.clone()
        },
        Grant {
            tool: "Write".into(),
            ..base.clone()
        },
        Grant {
            args_fingerprint: "deadbeef".into(),
            ..base.clone()
        },
        Grant {
            nonce: "nonce-2".into(),
            ..base.clone()
        },
        Grant {
            issued_at_ms: base.issued_at_ms - 1,
            ..base.clone()
        },
    ];
    for mutated in mutations {
        assert_eq!(
            verify(KEY, &mutated, &action(), NOW + 1),
            Err(GrantError::BadSignature),
            "field change must invalidate: {mutated:?}"
        );
    }
}

/// The signature is checked before any self-reported field is believed, so a
/// forged grant is rejected as forged rather than as expired -- an operator
/// chasing "expired" would waste time re-approving instead of investigating.
#[test]
fn a_forged_and_expired_grant_reports_the_forgery_first() {
    let mut forged = mint(b"other-key", &action(), 0, 1, "n".into());
    forged.signature = "00".repeat(32);
    assert_eq!(
        verify(KEY, &forged, &action(), NOW),
        Err(GrantError::BadSignature)
    );
}

#[test]
fn a_future_dated_grant_is_refused_beyond_clock_skew() {
    let future = mint(KEY, &action(), NOW + 60_000, DEFAULT_TTL_MS, "n".into());
    assert_eq!(
        verify(KEY, &future, &action(), NOW),
        Err(GrantError::NotYetValid)
    );
    // Small skew is tolerated rather than turning clock jitter into a refusal.
    let jittered = mint(KEY, &action(), NOW + 1_000, DEFAULT_TTL_MS, "n".into());
    assert_eq!(verify(KEY, &jittered, &action(), NOW), Ok(()));
}

/// Key order in the arguments is not a different action. A re-serialization
/// between approval and execution must not silently void a legitimate grant.
#[test]
fn argument_key_order_does_not_change_the_fingerprint() {
    let a = action_fingerprint("Bash", &serde_json::json!({"a": 1, "b": {"x": 1, "y": 2}}));
    let b = action_fingerprint("Bash", &serde_json::json!({"b": {"y": 2, "x": 1}, "a": 1}));
    assert_eq!(a, b);
}

/// Different tools with identical arguments are different actions.
#[test]
fn the_tool_is_part_of_the_fingerprint() {
    let args = serde_json::json!({"path": "x"});
    assert_ne!(
        action_fingerprint("Read", &args),
        action_fingerprint("Write", &args)
    );
}

/// One approval authorizes one action. The second attempt is refused even
/// though the grant is still perfectly valid and unexpired.
#[test]
fn a_grant_can_only_be_redeemed_once() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = GrantLedger::open(&dir.path().join("spent.json"));
    let grant = granted();
    assert_eq!(redeem(KEY, &grant, &action(), NOW + 1, &ledger), Ok(()));
    assert_eq!(
        redeem(KEY, &grant, &action(), NOW + 2, &ledger),
        Err(GrantError::AlreadyUsed)
    );
}

/// The reason the ledger is on disk: a restart inside the TTL must not
/// resurrect a spent approval.
#[test]
fn a_spent_grant_stays_spent_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spent.json");
    let grant = granted();
    {
        let ledger = GrantLedger::open(&path);
        assert_eq!(redeem(KEY, &grant, &action(), NOW + 1, &ledger), Ok(()));
    }
    let reopened = GrantLedger::open(&path);
    assert_eq!(
        redeem(KEY, &grant, &action(), NOW + 2, &reopened),
        Err(GrantError::AlreadyUsed),
        "an in-memory ledger would have forgotten this"
    );
}

/// Spent nonces are pruned once the grants they belong to could no longer be
/// used, so the file does not grow without bound.
#[test]
fn spent_entries_are_pruned_once_they_can_no_longer_matter() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spent.json");
    let ledger = GrantLedger::open(&path);
    let old = mint(KEY, &action(), NOW, 1_000, "old".into());
    assert_eq!(redeem(KEY, &old, &action(), NOW + 1, &ledger), Ok(()));

    // Well past the first grant's expiry: claiming anything prunes it.
    let fresh = mint(KEY, &action(), NOW + 10_000, DEFAULT_TTL_MS, "new".into());
    assert_eq!(
        redeem(KEY, &fresh, &action(), NOW + 10_001, &ledger),
        Ok(())
    );
    let stored: std::collections::BTreeMap<String, u64> =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(!stored.contains_key("old"), "expired entry must be pruned");
    assert!(stored.contains_key("new"));
}

/// An invalid grant must never reach the ledger: recording it would burn a
/// nonce an attacker chose and could be used to evict a legitimate one.
#[test]
fn a_grant_that_fails_verification_is_not_recorded_as_spent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spent.json");
    let ledger = GrantLedger::open(&path);
    let forged = mint(b"other-key", &action(), NOW, DEFAULT_TTL_MS, "n".into());
    assert_eq!(
        redeem(KEY, &forged, &action(), NOW + 1, &ledger),
        Err(GrantError::BadSignature)
    );
    assert!(
        !path.exists() || !std::fs::read_to_string(&path).unwrap().contains("\"n\""),
        "a rejected grant must not consume its nonce"
    );
}

#[test]
fn cached_approval_cannot_be_redeemed_after_policy_switch_or_restart() {
    let temp = tempfile::tempdir().unwrap();
    let store = GrantStore::new(&temp.path().join("grants"));
    let path = temp.path().join("grants-spent.json");
    let ledger = GrantLedger::open(&path);
    store
        .issue(
            KEY,
            &action(),
            NOW,
            DEFAULT_TTL_MS,
            crate::token::generate(),
        )
        .unwrap();
    let cached = store.pending().pop().unwrap();
    assert_eq!(cached.policy_epoch, 0);
    store.invalidate_all_for_policy_switch().unwrap();
    assert!(store.pending().is_empty());
    assert_eq!(
        redeem(KEY, &cached, &action(), NOW + 1, &ledger),
        Err(GrantError::StalePolicy)
    );
    let restarted = GrantLedger::open(&path);
    assert_eq!(
        redeem(KEY, &cached, &action(), NOW + 2, &restarted),
        Err(GrantError::StalePolicy)
    );
}

#[test]
fn approvals_issued_under_current_policy_work_and_old_issuance_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let store = GrantStore::new(&temp.path().join("grants"));
    let ledger = GrantLedger::open(&temp.path().join("grants-spent.json"));
    let (old, _) = store
        .issue(
            KEY,
            &action(),
            NOW,
            DEFAULT_TTL_MS,
            crate::token::generate(),
        )
        .unwrap();
    store.invalidate_all_for_policy_switch().unwrap();
    assert!(store.write(&old).is_err());
    let (new, _) = store
        .issue(
            KEY,
            &action(),
            NOW,
            DEFAULT_TTL_MS,
            crate::token::generate(),
        )
        .unwrap();
    assert_eq!(new.policy_epoch, 1);
    assert_eq!(redeem(KEY, &new, &action(), NOW + 1, &ledger), Ok(()));
}

#[test]
fn concurrent_issuer_observes_new_generation_after_switch_lock_releases() {
    let temp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(GrantStore::new(&temp.path().join("grants")));
    // Hold the same lock used by the CLI to simulate a switch in progress.
    let mut lock = PolicyEpochLock::acquire(temp.path()).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker_store = store.clone();
    let worker = std::thread::spawn(move || {
        let result = worker_store.issue(
            KEY,
            &action(),
            NOW,
            DEFAULT_TTL_MS,
            crate::token::generate(),
        );
        tx.send(result).unwrap();
    });
    lock.advance().unwrap();
    drop(lock);
    let (grant, _) = rx.recv().unwrap().unwrap();
    worker.join().unwrap();
    assert_eq!(grant.policy_epoch, 1);
    let ledger = GrantLedger::open(&temp.path().join("grants-spent.json"));
    assert_eq!(redeem(KEY, &grant, &action(), NOW + 1, &ledger), Ok(()));
}

#[test]
fn corrupt_epoch_fails_closed_for_claims_and_issuance() {
    let temp = tempfile::tempdir().unwrap();
    let store = GrantStore::new(&temp.path().join("grants"));
    let ledger = GrantLedger::open(&temp.path().join("grants-spent.json"));
    let (grant, _) = store
        .issue(
            KEY,
            &action(),
            NOW,
            DEFAULT_TTL_MS,
            crate::token::generate(),
        )
        .unwrap();
    fs::write(temp.path().join("approval-policy-epoch"), "corrupted").unwrap();
    assert_eq!(
        redeem(KEY, &grant, &action(), NOW + 1, &ledger),
        Err(GrantError::StalePolicy)
    );
    assert!(store
        .issue(
            KEY,
            &action(),
            NOW,
            DEFAULT_TTL_MS,
            crate::token::generate()
        )
        .is_err());
}

/// Length-prefixing keeps one field from impersonating part of another.
#[test]
fn field_boundaries_cannot_be_shifted_between_session_and_tool() {
    let left = mint(
        KEY,
        &ActionRef {
            session: "ab".into(),
            tool: "c".into(),
            args_fingerprint: "f".into(),
        },
        NOW,
        DEFAULT_TTL_MS,
        "n".into(),
    );
    let right = mint(
        KEY,
        &ActionRef {
            session: "a".into(),
            tool: "bc".into(),
            args_fingerprint: "f".into(),
        },
        NOW,
        DEFAULT_TTL_MS,
        "n".into(),
    );
    assert_ne!(
        left.signature, right.signature,
        "concatenation without length prefixes would collide here"
    );
}
#[test]
fn pending_profile_blocks_issuance_and_redeem_and_commit_retires_old_grants() {
    let temp = tempfile::tempdir().unwrap();
    let store = GrantStore::new(&temp.path().join("grants"));
    let ledger = GrantLedger::open(&temp.path().join("grants-spent.json"));
    let (grant, _) = store
        .issue(
            KEY,
            &action(),
            NOW,
            DEFAULT_TTL_MS,
            crate::token::generate(),
        )
        .unwrap();
    let root = temp.path().join("mcp-profiles");
    fs::create_dir(&root).unwrap();
    let guard = root.join("connection-transition.json");
    fs::write(&guard, "operation").unwrap();
    assert!(store
        .issue(
            KEY,
            &action(),
            NOW,
            DEFAULT_TTL_MS,
            crate::token::generate()
        )
        .is_err());
    assert_eq!(
        redeem(KEY, &grant, &action(), NOW + 1, &ledger),
        Err(GrantError::StalePolicy)
    );
    // An interrupted transition still permits epoch retirement by recovery.
    store.invalidate_all_for_policy_switch().unwrap();
    fs::remove_file(guard).unwrap();
    assert_eq!(
        redeem(KEY, &grant, &action(), NOW + 1, &ledger),
        Err(GrantError::StalePolicy)
    );
    fs::write(
        root.join("profile-state.json"),
        br#"{"in_progress":{"phase":"prepared"}}"#,
    )
    .unwrap();
    assert!(store
        .issue(
            KEY,
            &action(),
            NOW,
            DEFAULT_TTL_MS,
            crate::token::generate()
        )
        .is_err());
    fs::write(root.join("profile-state.json"), br#"{"in_progress":null}"#).unwrap();
    let (fresh, _) = store
        .issue(
            KEY,
            &action(),
            NOW,
            DEFAULT_TTL_MS,
            crate::token::generate(),
        )
        .unwrap();
    assert_eq!(redeem(KEY, &fresh, &action(), NOW + 1, &ledger), Ok(()));
}
