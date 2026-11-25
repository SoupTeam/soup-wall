// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn sou89_restarted_agent_rebinds_after_authority_expires() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent-root",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);

    // Start worker with standard TTL (60_000ms).
    let (s, r, _) = scoped_start_with_ttl(
        &f,
        "child-first",
        "worker",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        60_000,
    )
    .await;
    assert_allow(s, &r);

    // Active worker rejects duplicate bootstrap.
    let (_, r) = review8dd_start(
        &f,
        "child-dup",
        "worker",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_eq!(r["error_code"], "native_agent_already_bound");

    // Advance deterministic test time past the first worker's authority expiration.
    f.state
        .native
        .as_ref()
        .unwrap()
        .advance_test_time_ms(61_000);

    // Direct call to child-first now fails with native_child_authority_expired (not native_session_unknown).
    let (_, r) = f
        .post(&f.call("child-first", "read_document", &json!({})))
        .await;
    assert_eq!(r["error_code"], "native_child_authority_expired");

    // Restarted worker with fresh authority rebinds cleanly; old dead session is reaped.
    let (s, r, _) = scoped_start_with_ttl(
        &f,
        "child-second",
        "worker",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        60_000,
    )
    .await;
    assert_allow(s, &r);

    // The restarted worker can execute calls.
    let (s, r) = f
        .post(&f.call("child-second", "read_document", &json!({})))
        .await;
    assert_allow(s, &r);
}

#[tokio::test]
async fn sou89_capacity_reclaimed_when_authority_expired_sessions_are_present() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent-root",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);

    // Fill remaining 63 slots with child sessions (TTL = 60_000ms).
    for i in 1..64 {
        let (s, r, _) = scoped_start_with_ttl(
            &f,
            &format!("child-{i}"),
            &format!("worker-{i}"),
            Some("parent"),
            &["read_document"],
            Some(vec![]),
            60_000,
        )
        .await;
        assert_allow(s, &r);
    }

    // Total sessions = 64 (MAX_SESSIONS). A 65th session while all are alive is rejected with native_session_cap.
    let (_, r) = review8dd_start(
        &f,
        "child-excess",
        "worker-excess",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_eq!(r["error_code"], "native_session_cap");

    // Advance deterministic test time past the 63 child sessions' expiration.
    f.state
        .native
        .as_ref()
        .unwrap()
        .advance_test_time_ms(61_000);

    // Starting a new session now reaps the lost sessions and succeeds by reclaiming capacity.
    let (s, r, _) = scoped_start_with_ttl(
        &f,
        "child-recovered",
        "worker-new",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        60_000,
    )
    .await;
    assert_allow(s, &r);

    // Calling tools under child-recovered works.
    let (s, r) = f
        .post(&f.call("child-recovered", "read_document", &json!({})))
        .await;
    assert_allow(s, &r);
}

#[tokio::test]
async fn sou89_instance_endpoint_reclaims_capacity_and_cleans_bindings() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent-root",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);

    let (s, r, _) = scoped_start_with_ttl(
        &f,
        "child-short",
        "worker-short",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        60_000,
    )
    .await;
    assert_allow(s, &r);

    // Verify GET /native/v1/instance lists both bindings initially.
    let response = app(f.state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/native/v1/instance")
                .header("authorization", format!("Bearer {NATIVE_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = serde_json::from_slice::<Value>(
        &to_bytes(response.into_body(), 1024 * 1024).await.unwrap(),
    )
    .unwrap();
    let bindings = body["bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 2);
    // Sessions include host_session context + parent epoch + child epoch = 3 contexts.
    let sessions_before = body["provenance"]["usage"]["sessions"].as_u64().unwrap();
    assert_eq!(sessions_before, 3);

    // Advance deterministic test time past child-short authority expiration.
    f.state
        .native
        .as_ref()
        .unwrap()
        .advance_test_time_ms(61_000);

    // GET /native/v1/instance filters out the expired child session without ad-hoc mutation.
    let response = app(f.state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/native/v1/instance")
                .header("authorization", format!("Bearer {NATIVE_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = serde_json::from_slice::<Value>(
        &to_bytes(response.into_body(), 1024 * 1024).await.unwrap(),
    )
    .unwrap();
    let bindings = body["bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0]["agent_id"], "parent");

    // Autonomous maintenance sweep performs unified terminal retirement and reclaims provenance capacity.
    agentfw::native::liveness::perform_maintenance(&f.state).await;

    let response = app(f.state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/native/v1/instance")
                .header("authorization", format!("Bearer {NATIVE_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = serde_json::from_slice::<Value>(
        &to_bytes(response.into_body(), 1024 * 1024).await.unwrap(),
    )
    .unwrap();
    let sessions_after = body["provenance"]["usage"]["sessions"].as_u64().unwrap();
    assert_eq!(sessions_after, 2);
}

#[tokio::test]
async fn sou89_restarted_session_id_reuses_slot_if_previous_died() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent-root",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);

    let (s, r, _) = scoped_start_with_ttl(
        &f,
        "reused-child",
        "worker-1",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        60_000,
    )
    .await;
    assert_allow(s, &r);

    // While alive, attempting session_start with the same session_id returns native_session_exists.
    let (_, r, _) = scoped_start_with_ttl(
        &f,
        "reused-child",
        "worker-2",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        60_000,
    )
    .await;
    assert_eq!(r["error_code"], "native_session_exists");

    // Advance deterministic test time past the first session's authority expiration.
    f.state
        .native
        .as_ref()
        .unwrap()
        .advance_test_time_ms(61_000);

    // Starting a new session with the same session_id now cleans up the dead session and succeeds.
    let (s, r, _) = scoped_start_with_ttl(
        &f,
        "reused-child",
        "worker-2",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        60_000,
    )
    .await;
    assert_allow(s, &r);
}

#[tokio::test]
async fn sou89_lock_contention_refreshes_time_and_rejects_expired_authority() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent-root",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);

    // Start child with 100ms TTL.
    let (s, r, _) = scoped_start_with_ttl(
        &f,
        "child-contention",
        "worker",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        100,
    )
    .await;
    assert_allow(s, &r);

    // Hold firewall lock while making a call.
    // The request waits for the firewall lock until after the grant expires.
    let state = f.state.clone();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let b = barrier.clone();
    let blocker = std::thread::spawn(move || {
        let guard = state.firewall.lock().unwrap();
        b.wait();
        std::thread::sleep(std::time::Duration::from_millis(150));
        drop(guard);
    });
    barrier.wait();

    let call = f.call("child-contention", "read_document", &json!({}));
    let (_, r) = f.post(&call).await;
    blocker.join().unwrap();

    // Because timestamps are refreshed after acquiring locks, contention cannot extend authority.
    assert_eq!(r["error_code"], "native_child_authority_expired");
}

#[tokio::test]
async fn sou89_liveness_enroll_and_renew_monotonicity() {
    let f = Fixture::new(ALLOW);
    let (s, r) = f
        .post(&f.owned_event("collector-live", "session_start"))
        .await;
    assert_allow(s, &r);
    let owner_token = r["owner_token"].as_str().unwrap().to_string();

    let instance_id = f.state.native.as_ref().unwrap().instance_id().to_string();
    let registry_sha256 = f.state.native.as_ref().unwrap().registry_sha256.clone();

    // 0. Forged enrollment without owner token or with wrong token is rejected
    let forged_missing = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "collector-live",
        "instance_id": instance_id,
        "action": "enroll",
        "lease_seconds": 15,
    });
    let (s, r) = post_liveness(&f, &forged_missing).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(r["error_code"], "native_liveness_owner_token_required");

    let forged_wrong = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "collector-live",
        "instance_id": instance_id,
        "action": "enroll",
        "lease_seconds": 15,
        "owner_token": "forged-owner-token",
    });
    let (s, r) = post_liveness(&f, &forged_wrong).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(r["error_code"], "native_liveness_owner_mismatch");

    // 1. Valid enrollment
    let enroll_req = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "collector-live",
        "instance_id": instance_id,
        "action": "enroll",
        "lease_seconds": 15,
        "owner_token": owner_token,
    });
    let (s, r) = post_liveness(&f, &enroll_req).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["contract_version"], "sw-native-liveness/1");
    assert_eq!(r["action"], "enroll");
    assert_eq!(r["lease_seconds"], 15);
    assert_eq!(r["lease_seq"], 1);
    assert_eq!(r["status"], "active");
    let epoch = r["epoch"].as_str().unwrap().to_string();
    assert!(!epoch.is_empty());

    // Re-enrollment of active lease is rejected
    let (s, r) = post_liveness(&f, &enroll_req).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(r["error_code"], "native_liveness_already_enrolled");

    // 2. Monotonic renewal with next lease_seq
    let renew_req = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "collector-live",
        "instance_id": instance_id,
        "action": "renew",
        "owner_token": owner_token,
        "epoch": epoch,
        "lease_seq": 2,
    });
    let (s, r) = post_liveness(&f, &renew_req).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["lease_seq"], 2);
    assert_eq!(r["status"], "active");

    // 3. Stale sequence or replay is rejected
    let replay_req = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "collector-live",
        "instance_id": instance_id,
        "action": "renew",
        "owner_token": owner_token,
        "epoch": epoch,
        "lease_seq": 2,
    });
    let (s, r) = post_liveness(&f, &replay_req).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(r["error_code"], "native_liveness_seq_stale");

    // 4. Epoch mismatch is rejected
    let bad_epoch_req = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "collector-live",
        "instance_id": instance_id,
        "action": "renew",
        "owner_token": owner_token,
        "epoch": "wrong-secret-epoch",
        "lease_seq": 3,
    });
    let (s, r) = post_liveness(&f, &bad_epoch_req).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(r["error_code"], "native_liveness_epoch_mismatch");

    // 5. Instance mismatch is rejected
    let bad_instance_req = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "collector-live",
        "instance_id": "wrong-daemon-instance",
        "action": "renew",
        "owner_token": owner_token,
        "epoch": epoch,
        "lease_seq": 3,
    });
    let (s, r) = post_liveness(&f, &bad_instance_req).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(r["error_code"], "native_instance_mismatch");
}

#[tokio::test]
async fn sou89_liveness_renewal_cannot_extend_expired_authority() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent-live",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);

    let (s, r, _) = scoped_start_with_ttl(
        &f,
        "child-live",
        "worker",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        10_000,
    )
    .await;
    assert_allow(s, &r);
    let owner_token = r["owner_token"].as_str().unwrap().to_string();

    let instance_id = f.state.native.as_ref().unwrap().instance_id().to_string();
    let registry_sha256 = f.state.native.as_ref().unwrap().registry_sha256.clone();

    // Enroll in liveness with 60s lease
    let enroll_req = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "child-live",
        "instance_id": instance_id,
        "action": "enroll",
        "lease_seconds": 60,
        "owner_token": owner_token,
    });
    let (s, r) = post_liveness(&f, &enroll_req).await;
    assert_eq!(s, StatusCode::OK);
    let epoch = r["epoch"].as_str().unwrap().to_string();

    // Advance deterministic test time past the 10s signed authority expiration (while 60s lease is active)
    f.state
        .native
        .as_ref()
        .unwrap()
        .advance_test_time_ms(11_000);

    // Attempting to renew liveness after signed authority expired cannot revive authority
    let renew_req = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "child-live",
        "instance_id": instance_id,
        "action": "renew",
        "owner_token": owner_token,
        "epoch": epoch,
        "lease_seq": 2,
    });
    let (s, r) = post_liveness(&f, &renew_req).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(r["error_code"], "native_liveness_authority_expired");

    // The child session cannot execute calls
    let call = f.call("child-live", "read_document", &json!({}));
    let (_, r) = f.post(&call).await;
    assert_eq!(r["error_code"], "native_child_authority_expired");
}

#[tokio::test]
async fn sou89_liveness_autonomous_reclamation_and_sibling_isolation() {
    let f = Fixture::new(ALLOW);
    let (s, r) = f.post(&f.owned_event("collector-a", "session_start")).await;
    assert_allow(s, &r);
    let owner_token_a = r["owner_token"].as_str().unwrap().to_string();

    let (s, r) = f.post(&f.owned_event("collector-b", "session_start")).await;
    assert_allow(s, &r);

    let instance_id = f.state.native.as_ref().unwrap().instance_id().to_string();
    let registry_sha256 = f.state.native.as_ref().unwrap().registry_sha256.clone();

    // Enroll collector-a in liveness (10s lease). collector-b is unleased legacy session.
    let enroll_a = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "collector-a",
        "instance_id": instance_id,
        "action": "enroll",
        "lease_seconds": 10,
        "owner_token": owner_token_a,
    });
    let (s, r) = post_liveness(&f, &enroll_a).await;
    assert_eq!(s, StatusCode::OK);
    let epoch_a = r["epoch"].as_str().unwrap().to_string();

    // Both collectors execute calls successfully
    let (s, r) = f
        .post(&f.call("collector-a", "read_document", &json!({})))
        .await;
    assert_allow(s, &r);
    let (s, r) = f
        .post(&f.call("collector-b", "read_document", &json!({})))
        .await;
    assert_allow(s, &r);

    // collector-a stops renewing; advance deterministic clock by 11 seconds (lease expired)
    f.state
        .native
        .as_ref()
        .unwrap()
        .advance_test_time_ms(11_000);

    // Autonomous maintenance sweep runs in background (simulated via perform_maintenance)
    let reclaimed = agentfw::native::liveness::perform_maintenance(&f.state).await;
    assert_eq!(
        reclaimed, 1,
        "expired leased collector was autonomously reclaimed"
    );

    // collector-a is dead; tool calls fail
    let (_, r) = f
        .post(&f.call("collector-a", "read_document", &json!({})))
        .await;
    assert_eq!(r["error_code"], "native_session_unknown");

    // Sibling collector-b was NOT affected and remains fully useful
    let (s, r) = f
        .post(&f.call("collector-b", "read_document", &json!({})))
        .await;
    assert_allow(s, &r);

    // Late renew on collector-a is rejected as terminal
    let renew_a = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "collector-a",
        "instance_id": instance_id,
        "action": "renew",
        "owner_token": owner_token_a,
        "epoch": epoch_a,
        "lease_seq": 2,
    });
    let (s, r) = post_liveness(&f, &renew_a).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(r["error_code"], "native_session_unknown");
}

#[tokio::test]
async fn sou89_liveness_explicit_retire_cascades_children_and_preserves_host_risk() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent-retire",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
    let owner_token_p = r["owner_token"].as_str().unwrap().to_string();

    let (s, r, _) = scoped_start_with_ttl(
        &f,
        "child-retire",
        "worker",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        60_000,
    )
    .await;
    assert_allow(s, &r);

    // Add untrusted taint to host session
    let result = child_result(&f, "parent-retire", UNTRUSTED_TEXT).await;
    let (s, r) = f.post(&result).await;
    assert_allow(s, &r);
    assert!(f.state.firewall.lock().unwrap().taint_len("review-host") > 0);

    let instance_id = f.state.native.as_ref().unwrap().instance_id().to_string();
    let registry_sha256 = f.state.native.as_ref().unwrap().registry_sha256.clone();

    // Enroll parent in liveness
    let enroll_p = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "parent-retire",
        "instance_id": instance_id,
        "action": "enroll",
        "lease_seconds": 15,
        "owner_token": owner_token_p,
    });
    let (s, r) = post_liveness(&f, &enroll_p).await;
    assert_eq!(s, StatusCode::OK);
    let epoch_p = r["epoch"].as_str().unwrap().to_string();

    // Explicit retire of parent
    let retire_p = json!({
        "contract_version": "sw-native-liveness/1",
        "registry_sha256": registry_sha256,
        "session_id": "parent-retire",
        "instance_id": instance_id,
        "action": "retire",
        "owner_token": owner_token_p,
        "epoch": epoch_p,
    });
    let (s, r) = post_liveness(&f, &retire_p).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["status"], "retired");

    assert!(
        f.audit()
            .iter()
            .any(|row| row["session_id"] == "parent-retire"
                && row["event"] == "native_session_retired"),
        "healthy explicit retirement must keep its original terminal cause"
    );

    // Child session was cascade-retired
    let (_, r) = f
        .post(&f.call("child-retire", "read_document", &json!({})))
        .await;
    assert_eq!(r["error_code"], "native_session_unknown");

    // Shared host risk/taint was preserved and NOT erased
    assert!(
        f.state.firewall.lock().unwrap().taint_len("review-host") > 0,
        "host taint must not be erased upon collector retirement"
    );
}

#[tokio::test]
async fn sou124_retirement_cannot_relabel_expired_ancestor_as_healthy_retire() {
    let f = Fixture::new(ALLOW);
    let mut grandchild = None;
    for (sid, agent, parent, seconds) in [
        ("cause-parent", "cause-p", None, 2),
        ("cause-child", "cause-c", Some("cause-p"), 20),
        ("cause-grandchild", "cause-gc", Some("cause-c"), 4),
    ] {
        let (status, started, _) = scoped_start_with_ttl(
            &f,
            sid,
            agent,
            parent,
            &["read_document"],
            Some(vec![]),
            300_000,
        )
        .await;
        assert_allow(status, &started);
        let mut enroll = reviewer_sou89_liveness(&f, sid, "enroll");
        enroll["owner_token"] = started["owner_token"].clone();
        enroll["lease_seconds"] = json!(seconds);
        let (status, enrolled) = post_liveness(&f, &enroll).await;
        assert_eq!(status, StatusCode::OK, "{enrolled}");
        if parent == Some("cause-c") {
            grandchild = Some((started["owner_token"].clone(), enrolled["epoch"].clone()));
        }
    }
    let (owner, epoch) = grandchild.unwrap();
    f.state.native.as_ref().unwrap().advance_test_time_ms(2100);
    let mut renew = reviewer_sou89_liveness(&f, "cause-grandchild", "renew");
    renew["owner_token"] = owner.clone();
    renew["epoch"] = epoch.clone();
    renew["lease_seq"] = json!(2);
    let (status, reply) = post_liveness(&f, &renew).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reply["error_code"], "native_child_parent_unavailable");

    // Reproduce collector shutdown winning the race with maintenance. Neither
    // a forged owner nor an old epoch may remove or relabel the terminal cause.
    let mut retire = reviewer_sou89_liveness(&f, "cause-grandchild", "retire");
    retire["owner_token"] = owner;
    retire["epoch"] = epoch.clone();
    for field in ["owner_token", "epoch"] {
        let mut forged = retire.clone();
        forged[field] = json!("not-the-owner-or-epoch");
        assert_eq!(post_liveness(&f, &forged).await.0, StatusCode::FORBIDDEN);
    }
    assert_eq!(post_liveness(&f, &retire).await.0, StatusCode::OK);
    let records = f.audit();
    let terminal: Vec<_> = records
        .iter()
        .filter(|row| {
            row["session_id"] == "cause-grandchild"
                && row["event"].as_str().is_some_and(|event| {
                    event == "native_session_expired" || event == "native_session_retired"
                })
        })
        .collect();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0]["event"], "native_session_expired");
    assert_eq!(terminal[0]["session"], epoch);
    assert_eq!(terminal[0]["parent_id"], "cause-c");

    // The existing sweep still reclaims the parent and child; no test request
    // or retry substitutes for this autonomous expiry path.
    assert_eq!(
        agentfw::native::liveness::perform_maintenance(&f.state).await,
        2
    );
    let records = f.audit();
    for sid in ["cause-parent", "cause-child", "cause-grandchild"] {
        assert_eq!(
            records
                .iter()
                .filter(|row| row["session_id"] == sid && row["event"] == "native_session_expired")
                .count(),
            1
        );
        assert_eq!(
            post_liveness(&f, &reviewer_sou89_liveness(&f, sid, "status"))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn reviewer_sou89_spent_signed_grant_must_not_rebootstrap() {
    let f = Fixture::new(ALLOW);
    let (s, start, proof) = scoped_start_with_ttl(
        &f,
        "lost-owner",
        "worker",
        None,
        &["read_document"],
        Some(vec![]),
        300_000,
    )
    .await;
    assert_allow(s, &start);
    let mut enroll = reviewer_sou89_liveness(&f, "lost-owner", "enroll");
    enroll["owner_token"] = start["owner_token"].clone();
    enroll["lease_seconds"] = json!(1);
    let (s, _) = post_liveness(&f, &enroll).await;
    assert_eq!(s, StatusCode::OK);
    f.state.native.as_ref().unwrap().advance_test_time_ms(1100);
    assert_eq!(
        agentfw::native::liveness::perform_maintenance(&f.state).await,
        1
    );
    let mut replay = f.owned_event("replayed-owner", "session_start");
    replay["host_session"] = json!("review-host");
    replay["server_id"] = json!("resource-fixture");
    replay["child_authority"] = json!(proof);
    let (status, reply) = f.post(&replay).await;
    let (call_status, call_reply) = f
        .post(&f.call("replayed-owner", "read_document", &json!({})))
        .await;
    assert!(
        status != StatusCode::OK || reply["release"] != true,
        "spent signed grant bootstrapped after expiry: status={status}, reply={reply}; new call={call_status} {call_reply}"
    );
}

#[tokio::test]
async fn reviewer_sou89_parent_close_must_reclaim_descendant() {
    let f = Fixture::new(ALLOW);
    let (s, r) = review8dd_start(
        &f,
        "parent-review",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
    let (s, r) = review8dd_start(
        &f,
        "child-review",
        "worker",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
    )
    .await;
    assert_allow(s, &r);
    let mut enroll = reviewer_sou89_liveness(&f, "child-review", "enroll");
    enroll["owner_token"] = r["owner_token"].clone();
    enroll["lease_seconds"] = json!(60);
    let (s, _) = post_liveness(&f, &enroll).await;
    assert_eq!(s, StatusCode::OK);
    let (s, r) = f.post(&f.event("parent-review", "session_end")).await;
    assert_allow(s, &r);
    let reclaimed = agentfw::native::liveness::perform_maintenance(&f.state).await;
    let (s, r) = post_liveness(&f, &reviewer_sou89_liveness(&f, "child-review", "status")).await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "child capacity survives parent closure and sweep: reclaimed={reclaimed}, reply={r}"
    );
}

#[tokio::test]
async fn reviewer_sou89_enrol_must_not_revive_expired_unleased_session() {
    let f = Fixture::new(ALLOW);
    let (s, start) = f
        .post(&f.owned_event("expired-review", "session_start"))
        .await;
    assert_allow(s, &start);
    f.state
        .native
        .as_ref()
        .unwrap()
        .advance_test_time_ms(301_000);
    let (_, before) = f
        .post(&f.call("expired-review", "read_document", &json!({})))
        .await;
    assert_eq!(before["error_code"], "native_child_authority_expired");
    let mut enroll = reviewer_sou89_liveness(&f, "expired-review", "enroll");
    enroll["owner_token"] = start["owner_token"].clone();
    enroll["lease_seconds"] = json!(60);
    let (s, r) = post_liveness(&f, &enroll).await;
    let (call_status, call_reply) = f
        .post(&f.call("expired-review", "read_document", &json!({})))
        .await;
    assert_ne!(
        s,
        StatusCode::OK,
        "expired unleased authority revived: enrol={r}; call={call_status} {call_reply}"
    );
}

#[tokio::test]
async fn reviewer_r3_tombstone_saturation_must_not_restore_spent_authority() {
    let f = Fixture::new(ALLOW);
    let mut proofs: Vec<(String, String)> = Vec::new();
    for i in 0..513 {
        let sid = format!("cap-owner-{i}");
        let (status, start, proof) = scoped_start_with_ttl(
            &f,
            &sid,
            "worker",
            None,
            &["read_document"],
            Some(vec![]),
            300_000,
        )
        .await;
        if status != StatusCode::OK || start["release"] != true {
            assert!(
                i >= 512,
                "unexpected rejection before declared ledger capacity: {i}, {start}"
            );
            break;
        }
        proofs.push((sha256_hex(proof.as_bytes()), proof));
        let mut enroll = reviewer_sou89_liveness(&f, &sid, "enroll");
        enroll["owner_token"] = start["owner_token"].clone();
        enroll["lease_seconds"] = json!(60);
        let (s, r) = post_liveness(&f, &enroll).await;
        assert_eq!(s, StatusCode::OK, "{r}");
        let mut retire = reviewer_sou89_liveness(&f, &sid, "retire");
        retire["epoch"] = r["epoch"].clone();
        retire["owner_token"] = enroll["owner_token"].clone();
        let (s, r) = post_liveness(&f, &retire).await;
        assert_eq!(s, StatusCode::OK, "{r}");
    }
    assert!(proofs.len() >= 512);
    proofs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut replay = f.owned_event("cap-replay", "session_start");
    replay["host_session"] = json!("review-host");
    replay["server_id"] = json!("resource-fixture");
    replay["child_authority"] = json!(proofs[0].1);
    let (status, reply) = f.post(&replay).await;
    let (call_status, call_reply) = f
        .post(&f.call("cap-replay", "read_document", &json!({})))
        .await;
    assert!(
        status != StatusCode::OK || reply["release"] != true,
        "ledger saturation restored spent signed grant after {} retirements: bootstrap={status} {reply}; call={call_status} {call_reply}",
        proofs.len()
    );
}

#[tokio::test]
async fn sou89_ledger_saturation_fail_closed_and_expiry_lifecycle() {
    let f = Fixture::new(ALLOW);

    // 1. Start a sibling that remains active throughout
    let (s, sib_start, _sib_proof) = scoped_start_with_ttl(
        &f,
        "surviving-sibling",
        "sibling",
        None,
        &["read_document"],
        Some(vec![]),
        300_000,
    )
    .await;
    assert_allow(s, &sib_start);
    let mut sib_enroll = reviewer_sou89_liveness(&f, "surviving-sibling", "enroll");
    sib_enroll["owner_token"] = sib_start["owner_token"].clone();
    sib_enroll["lease_seconds"] = json!(60);
    let (s, sib_enrolled) = post_liveness(&f, &sib_enroll).await;
    assert_eq!(s, StatusCode::OK);
    let sib_epoch = sib_enrolled["epoch"].as_str().unwrap().to_string();

    // 2. Fill the ledger up to MAX_SPENT_AUTHORITIES (512).
    // Note that active sibling occupies 1 slot of reserved capacity (511 spent + 1 active = 512).
    let mut proofs = Vec::new();
    for i in 0..511 {
        let sid = format!("fill-session-{i}");
        let aid = format!("fill-worker-{i}");
        let (status, start, proof) = scoped_start_with_ttl(
            &f,
            &sid,
            &aid,
            None,
            &["read_document"],
            Some(vec![]),
            300_000,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "failed to start fill session {i}");
        assert_eq!(start["release"], true);
        proofs.push(proof.clone());
        let mut enroll = reviewer_sou89_liveness(&f, &sid, "enroll");
        enroll["owner_token"] = start["owner_token"].clone();
        enroll["lease_seconds"] = json!(60);
        let (s, r) = post_liveness(&f, &enroll).await;
        assert_eq!(s, StatusCode::OK, "{r}");
        let mut retire = reviewer_sou89_liveness(&f, &sid, "retire");
        retire["epoch"] = r["epoch"].clone();
        retire["owner_token"] = enroll["owner_token"].clone();
        let (s, r) = post_liveness(&f, &retire).await;
        assert_eq!(s, StatusCode::OK, "{r}");
    }

    // Capacity is now saturated: 511 spent + 1 active = 512.
    // 3. Overflow attempt must fail-closed with CONFLICT (native_authority_ledger_saturated)
    let (status, start, _) = scoped_start_with_ttl(
        &f,
        "overflow-session",
        "overflow-worker",
        None,
        &["read_document"],
        Some(vec![]),
        300_000,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(start["error_code"], "native_authority_ledger_saturated");
    assert_ne!(start["release"], true);

    // 4. Surviving sibling still renews and does useful work despite saturated ledger
    let mut renew = reviewer_sou89_liveness(&f, "surviving-sibling", "renew");
    renew["epoch"] = json!(sib_epoch);
    renew["owner_token"] = sib_start["owner_token"].clone();
    renew["lease_seq"] = json!(sib_enrolled["lease_seq"].as_u64().unwrap_or(1) + 1);
    let (s, r) = post_liveness(&f, &renew).await;
    assert_eq!(s, StatusCode::OK, "sibling renewal refused: {r}");
    let (cs, cr) = f
        .post(&f.call("surviving-sibling", "read_document", &json!({})))
        .await;
    assert_allow(cs, &cr);

    // 5. Replay of old grants must be rejected as already spent
    for p in [
        &proofs[0],
        &proofs[proofs.len() / 2],
        &proofs[proofs.len() - 1],
    ] {
        let mut replay = f.owned_event("replay-attempt", "session_start");
        replay["host_session"] = json!("review-host");
        replay["server_id"] = json!("resource-fixture");
        replay["child_authority"] = json!(p);
        let (status, reply) = f.post(&replay).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(reply["error_code"], "native_child_authority_already_spent");
        assert_ne!(reply["release"], true);
    }

    // 6. Advance test time past the 300s TTL (e.g. 301s)
    f.state
        .native
        .as_ref()
        .unwrap()
        .advance_test_time_ms(301_000);

    // Maintenance prunes expired tombstones
    agentfw::native::liveness::perform_maintenance(&f.state).await;

    // 7. Legitimate capacity returns: a fresh signed grant can now be admitted!
    let (status, start, _) = scoped_start_with_ttl(
        &f,
        "fresh-after-prune",
        "fresh-worker",
        None,
        &["read_document"],
        Some(vec![]),
        300_000,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "fresh grant start rejected after pruning: {start}"
    );
    assert_eq!(start["release"], true);
}

async fn sou89_owner_witness(action: &str) {
    let f = Fixture::new(ALLOW);
    let (_, target) = f
        .post(&f.owned_event("owned-target", "session_start"))
        .await;
    let (_, peer) = f.post(&f.owned_event("owned-peer", "session_start")).await;
    let mut enroll = reviewer_sou89_liveness(&f, "owned-target", "enroll");
    enroll["owner_token"] = target["owner_token"].clone();
    let (status, enrolled) = post_liveness(&f, &enroll).await;
    assert_eq!(status, StatusCode::OK);
    let mut request = reviewer_sou89_liveness(&f, "owned-target", action);
    // The genuine epoch is an audit identity, not a collector ownership secret.
    let audit = std::fs::read_to_string(f.dir.path().join("audit.jsonl")).unwrap();
    let record: Value = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|row| row["event"] == "native_liveness_enrolled")
        .unwrap();
    assert_eq!(record["session"], enrolled["epoch"]);
    request["epoch"] = record["session"].clone();
    if action == "renew" {
        request["lease_seq"] = json!(2);
    }
    for token in [
        None,
        Some(peer["owner_token"].clone()),
        Some(json!("forged-owner")),
    ] {
        let mut forged = request.clone();
        if let Some(token) = token {
            forged["owner_token"] = token;
        }
        let (status, reply) = post_liveness(&f, &forged).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{action} accepted a non-owner: {reply}"
        );
    }
    request["owner_token"] = target["owner_token"].clone();
    let (status, reply) = post_liveness(&f, &request).await;
    assert_eq!(status, StatusCode::OK, "owner {action} refused: {reply}");
    if action == "renew" {
        let (status, call) = f
            .post(&f.call("owned-target", "read_document", &json!({})))
            .await;
        assert_allow(status, &call);
    } else {
        let (status, _) = f
            .post(&f.call("owned-target", "read_document", &json!({})))
            .await;
        assert_ne!(status, StatusCode::OK);
    }
    let (status, call) = f
        .post(&f.call("owned-peer", "read_document", &json!({})))
        .await;
    assert_allow(status, &call);
}

#[tokio::test]
async fn sou89_renew_requires_owner_beyond_the_genuine_audit_epoch() {
    sou89_owner_witness("renew").await;
}

#[tokio::test]
async fn sou89_retire_requires_owner_beyond_the_genuine_audit_epoch() {
    sou89_owner_witness("retire").await;
}

#[tokio::test]
async fn sou89_legacy_session_start_keeps_the_accepted_receipt_schema() {
    let f = Fixture::new(ALLOW);
    let (status, reply) = f.post(&f.event("legacy-schema", "session_start")).await;
    assert_allow(status, &reply);
    // Exact allowed shape used by the accepted pre-liveness collector.
    let expected = std::collections::BTreeSet::from([
        "contract_version",
        "registry_sha256",
        "session_id",
        "event",
        "verdict",
        "enforced",
        "release",
        "call_id",
        "binding_sha256",
        "content_sha256",
        "reason_codes",
    ]);
    let actual = reply
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        expected, actual,
        "opt-in bootstrap fields leaked into a legacy receipt"
    );
    let (status, call) = f
        .post(&f.call("legacy-schema", "read_document", &json!({})))
        .await;
    assert_allow(status, &call);
}

#[tokio::test]
async fn sou89_versioned_bootstrap_returns_owner_only_after_explicit_opt_in() {
    let f = Fixture::new(ALLOW);
    let mut start = f.event("opt-in-bootstrap", "session_start");
    start["liveness"] = json!("sw-native-liveness/1");
    let (status, reply) = f.post(&start).await;
    assert_allow(status, &reply);
    assert!(reply["owner_token"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(
        reply["instance_id"],
        f.state.native.as_ref().unwrap().instance_id()
    );
    let mut enroll = reviewer_sou89_liveness(&f, "opt-in-bootstrap", "enroll");
    enroll["owner_token"] = reply["owner_token"].clone();
    let (status, _) = post_liveness(&f, &enroll).await;
    assert_eq!(status, StatusCode::OK);
    start["session_id"] = json!("unknown-bootstrap-version");
    start["liveness"] = json!("sw-native-liveness/999");
    assert_ne!(f.post(&start).await.0, StatusCode::OK);
}

#[tokio::test]
async fn sou89_leased_session_end_atomically_reclaims_all_descendants() {
    let f = Fixture::new(ALLOW);
    let (s, root, _) = scoped_start_with_ttl(
        &f,
        "leased-root",
        "root",
        None,
        &["read_document"],
        Some(vec![]),
        300_000,
    )
    .await;
    assert_allow(s, &root);
    let mut enroll = reviewer_sou89_liveness(&f, "leased-root", "enroll");
    enroll["owner_token"] = root["owner_token"].clone();
    enroll["lease_seconds"] = json!(60);
    let (s, r) = post_liveness(&f, &enroll).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    for (sid, agent, parent) in [
        ("leased-child", "child", "root"),
        ("leased-grandchild", "grandchild", "child"),
    ] {
        let (s, r, _) = scoped_start_with_ttl(
            &f,
            sid,
            agent,
            Some(parent),
            &["read_document"],
            Some(vec![]),
            300_000,
        )
        .await;
        assert_allow(s, &r);
        f.allowed_call(sid, "read_document", &json!({})).await;
    }
    let (s, r) = f.post(&f.event("leased-root", "session_end")).await;
    assert_allow(s, &r);
    // No background sweep or request that performs cleanup intervenes.
    for sid in ["leased-root", "leased-child", "leased-grandchild"] {
        let (s, r) = post_liveness(&f, &reviewer_sou89_liveness(&f, sid, "status")).await;
        assert_eq!(
            s,
            StatusCode::NOT_FOUND,
            "terminal descendant retained: {sid}: {r}"
        );
    }
}

#[tokio::test]
async fn sou89_ended_leased_child_grant_cannot_rebootstrap_but_fresh_grant_works() {
    let f = Fixture::new(ALLOW);
    let (s, r, _) = scoped_start_with_ttl(
        &f,
        "live-parent",
        "parent",
        None,
        &["read_document"],
        Some(vec![]),
        300_000,
    )
    .await;
    assert_allow(s, &r);
    let (s, child, proof) = scoped_start_with_ttl(
        &f,
        "ended-child",
        "child",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        300_000,
    )
    .await;
    assert_allow(s, &child);
    let mut enroll = reviewer_sou89_liveness(&f, "ended-child", "enroll");
    enroll["owner_token"] = child["owner_token"].clone();
    enroll["lease_seconds"] = json!(60);
    let (s, r) = post_liveness(&f, &enroll).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let (s, r) = f.post(&f.event("ended-child", "session_end")).await;
    assert_allow(s, &r);
    let mut replay = f.owned_event("replayed-child", "session_start");
    replay["host_session"] = json!("review-host");
    replay["server_id"] = json!("resource-fixture");
    replay["child_authority"] = json!(proof);
    let (s, r) = f.post(&replay).await;
    assert_eq!(
        s,
        StatusCode::CONFLICT,
        "ended lease resurrected through signed grant: {r}"
    );
    assert_eq!(r["error_code"], "native_child_authority_already_spent");
    let (s, r, _) = scoped_start_with_ttl(
        &f,
        "fresh-child",
        "child",
        Some("parent"),
        &["read_document"],
        Some(vec![]),
        300_000,
    )
    .await;
    assert_allow(s, &r);
    f.allowed_call("fresh-child", "read_document", &json!({}))
        .await;
    f.allowed_call("live-parent", "read_document", &json!({}))
        .await;
}

#[tokio::test]
async fn sou89_bootstrap_status_exposes_an_epoch_only_to_its_owner() {
    let f = Fixture::new(ALLOW);
    let (s, target) = f
        .post(&f.owned_event("bootstrap-target", "session_start"))
        .await;
    assert_allow(s, &target);
    let (_, peer) = f
        .post(&f.owned_event("bootstrap-peer", "session_start"))
        .await;
    let request = reviewer_sou89_liveness(&f, "bootstrap-target", "status");
    let (s, public) = post_liveness(&f, &request).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(public["status"], "unleased");
    assert!(public.get("epoch").is_none());
    for owner in [peer["owner_token"].clone(), json!("forged-owner")] {
        let mut forged = request.clone();
        forged["owner_token"] = owner;
        let (s, reply) = post_liveness(&f, &forged).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(reply["error_code"], "native_liveness_owner_mismatch");
    }
    let mut owned = request;
    owned["owner_token"] = target["owner_token"].clone();
    let (s, reply) = post_liveness(&f, &owned).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(reply["status"], "unleased");
    let mut retire = reviewer_sou89_liveness(&f, "bootstrap-target", "retire");
    retire["epoch"] = reply["epoch"].clone();
    retire["owner_token"] = target["owner_token"].clone();
    let (s, _) = post_liveness(&f, &retire).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = post_liveness(&f, &owned).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, reply) = f
        .post(&f.call("bootstrap-peer", "read_document", &json!({})))
        .await;
    assert_allow(s, &reply);
}

async fn sou89_post_collector_guard(
    f: &Fixture,
    body: &Value,
    guards: &[String],
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/native/v1")
        .header("authorization", format!("Bearer {NATIVE_TOKEN}"))
        .header("content-type", "application/json");
    for guard in guards {
        request = request.header("x-agentfw-collector-liveness", guard);
    }
    let response = app(f.state.clone())
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn sou89_collector_guard_rejects_forgery_and_stale_identity_without_affecting_legacy_calls() {
    let f = Fixture::new(ALLOW);
    let (_, start) = f.post(&f.owned_event("guarded", "session_start")).await;
    let mut enroll = reviewer_sou89_liveness(&f, "guarded", "enroll");
    enroll["owner_token"] = start["owner_token"].clone();
    let (_, enrolled) = post_liveness(&f, &enroll).await;
    let identity = json!({"contract_version":"sw-native-liveness/1", "instance_id":enroll["instance_id"],
        "epoch":enrolled["epoch"], "owner_token":start["owner_token"]});
    let call = f.call("guarded", "read_document", &json!({}));
    for field in ["instance_id", "epoch", "owner_token"] {
        let mut forged = identity.clone();
        forged[field] = json!("forged-value");
        let (status, reply) = sou89_post_collector_guard(&f, &call, &[forged.to_string()]).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(reply["release"], false);
    }
    let (status, admitted) = sou89_post_collector_guard(&f, &call, &[identity.to_string()]).await;
    assert_allow(status, &admitted);
    let result = f.result(
        "guarded",
        &admitted,
        "read_document",
        &json!({}),
        "value",
        "useful guarded document",
    );
    let (status, reply) = sou89_post_collector_guard(&f, &result, &[identity.to_string()]).await;
    assert_allow(status, &reply);
    // Trusted legacy operator controls retain their accepted schemas.
    let (status, reply) = f.post(&f.event("guarded", "session_end")).await;
    assert_allow(status, &reply);
    let (_, fresh) = f.post(&f.owned_event("guarded", "session_start")).await;
    assert_ne!(fresh["owner_token"], start["owner_token"]);
    let (status, reply) = sou89_post_collector_guard(&f, &call, &[identity.to_string()]).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reply["release"], false);
    let (status, reply) = f.post(&call).await;
    assert_allow(status, &reply);
}

#[tokio::test]
async fn sou89_collector_guard_rejects_duplicate_malformed_and_oversized_headers() {
    let f = Fixture::new(ALLOW);
    f.start("header-bounds").await;
    let call = f.call("header-bounds", "read_document", &json!({}));
    for guards in [
        vec!["{}".into()],
        vec!["{".into()],
        vec!["x".repeat(1025)],
        vec!["{}".into(), "{}".into()],
    ] {
        let (status, reply) = sou89_post_collector_guard(&f, &call, &guards).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(reply["release"], false);
    }
    let (status, reply) = f.post(&call).await;
    assert_allow(status, &reply);
}
