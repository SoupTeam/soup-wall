// SPDX-License-Identifier: Apache-2.0

use super::*;

fn sou125_stop_request(f: &Fixture, fs: &Value, git: &Value) -> Value {
    let proof = fs["child_authority"].as_str().unwrap();
    let grant = agentfw::native::child_authority::decode_token(proof).unwrap();
    json!({"contract_version":agentfw::native::pilot_stop::CONTRACT,
        "instance_id":f.state.native.as_ref().unwrap().instance_id(),
        "registry_sha256":f.registry_sha256,"host_session":fs["host_session"],
        "authorities":{"filesystem":sha256_hex(proof.as_bytes()),"git":sha256_hex(git["child_authority"].as_str().unwrap().as_bytes())},
        "expires_at_ms":grant.expires_at_ms.max(agentfw::native::child_authority::decode_token(git["child_authority"].as_str().unwrap()).unwrap().expires_at_ms)})
}

#[tokio::test]
async fn sou125_stop_revokes_active_and_unenrolled_grants_without_touching_other_run() {
    let f = Fixture::new(ALLOW);
    let fs = child_start(&f, "selected-fs", "selected-host", Some("filesystem"));
    let git = child_start(&f, "selected-git", "selected-host", Some("git"));
    let other = child_start(&f, "other-fs", "other-host", Some("filesystem"));
    let (status, reply) = f.post(&fs).await;
    assert_allow(status, &reply);
    let (status, reply) = f.post(&other).await;
    assert_allow(status, &reply);
    let stop = sou125_stop_request(&f, &fs, &git);
    for _ in 0..2 {
        let (status, reply) = post(
            f.state.clone(),
            agentfw::native::pilot_stop::ENDPOINT,
            &stop,
            Some(NATIVE_TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert_eq!(reply["status"], "revoked");
        assert_eq!(reply["running_effects_rolled_back"], false);
    }
    let (_, refused) = f
        .post(&f.call("selected-fs", "read_document", &json!({})))
        .await;
    assert_eq!(refused["error_code"], "native_session_unknown");
    // Git was never enrolled. The exact old signed grant is still revoked.
    let (_, refused) = f.post(&git).await;
    assert_eq!(
        refused["error_code"],
        "native_child_authority_already_spent"
    );
    let (_, refused) = f.post(&fs).await;
    assert_eq!(
        refused["error_code"],
        "native_child_authority_already_spent"
    );
    let (status, useful) = f
        .post(&f.call("other-fs", "read_document", &json!({})))
        .await;
    assert_allow(status, &useful);
    let fresh = child_start(&f, "restarted-fs", "fresh-host", Some("filesystem"));
    let (status, reply) = f.post(&fresh).await;
    assert_allow(status, &reply);
}

#[tokio::test]
async fn sou125_stop_refuses_missing_wrong_auth_and_foreign_or_restarted_identity() {
    let f = Fixture::new(ALLOW);
    let fs = child_start(&f, "selected-fs", "selected-host", Some("filesystem"));
    let git = child_start(&f, "selected-git", "selected-host", Some("git"));
    let (status, reply) = f.post(&fs).await;
    assert_allow(status, &reply);
    let request = sou125_stop_request(&f, &fs, &git);
    for auth in [None, Some(HOOK_TOKEN), Some("wrong-native-token")] {
        let (status, _) = post(
            f.state.clone(),
            agentfw::native::pilot_stop::ENDPOINT,
            &request,
            auth,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    for field in ["instance_id", "registry_sha256", "host_session"] {
        let mut changed = request.clone();
        changed[field] = json!(if field == "registry_sha256" {
            "0".repeat(64)
        } else {
            "foreign".into()
        });
        let (status, _) = post(
            f.state.clone(),
            agentfw::native::pilot_stop::ENDPOINT,
            &changed,
            Some(NATIVE_TOKEN),
        )
        .await;
        assert!(status == StatusCode::CONFLICT || status == StatusCode::FORBIDDEN);
    }
    let (status, useful) = f
        .post(&f.call("selected-fs", "read_document", &json!({})))
        .await;
    assert_allow(status, &useful);
}

#[tokio::test]
async fn sou125_stop_refuses_unknown_privilege_fields_bad_digests_and_unbounded_expiry() {
    let f = Fixture::new(ALLOW);
    let fs = child_start(&f, "selected-fs", "selected-host", Some("filesystem"));
    let git = child_start(&f, "selected-git", "selected-host", Some("git"));
    let request = sou125_stop_request(&f, &fs, &git);
    for update in [
        json!({"all_runs":true}),
        json!({"expires_at_ms":u64::MAX}),
        json!({"authorities":{"filesystem":"bad","git":"bad"}}),
    ] {
        let mut changed = request.clone();
        changed
            .as_object_mut()
            .unwrap()
            .extend(update.as_object().unwrap().clone());
        let (status, _) = post(
            f.state.clone(),
            agentfw::native::pilot_stop::ENDPOINT,
            &changed,
            Some(NATIVE_TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, reply) = f.post(&fs).await;
    assert_allow(status, &reply);
}

#[tokio::test]
async fn sou125_stop_closes_pending_and_approved_proposals_but_preserves_other_run() {
    for approve in [false, true] {
        let mut f = Fixture::new(ALLOW);
        let state = Arc::get_mut(&mut f.state).unwrap();
        state.native = Some(
            state
                .native
                .take()
                .unwrap()
                .with_approval(f.dir.path(), &state.grant_key, 120)
                .unwrap(),
        );
        let fs = child_start(&f, "selected-fs", "selected-host", Some("filesystem"));
        let git = child_start(&f, "selected-git", "selected-host", Some("git"));
        let other = child_start(&f, "other-fs", "other-host", Some("filesystem"));
        for start in [&fs, &git, &other] {
            let (status, reply) = f.post(start).await;
            assert_allow(status, &reply);
        }
        let open = |session: &str| {
            json!({"contract_version":CONTRACT,
            "registry_sha256":f.registry_sha256,"session_id":session,"action":"request",
            "source":"classifier","tool":"read_document","args":{},"schema_sha256":schema()})
        };
        let (status, pending) = post(
            f.state.clone(),
            "/native/approval/v1",
            &open("selected-fs"),
            Some(NATIVE_TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{pending}");
        let (status, independent) = post(
            f.state.clone(),
            "/native/approval/v1",
            &open("other-fs"),
            Some(NATIVE_TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{independent}");
        let id = pending["pending_id"].as_str().unwrap();
        if approve {
            agentfw::native::approval::operator_approve(
                f.dir.path(),
                HOOK_TOKEN,
                id,
                pending["binding_sha256"].as_str().unwrap(),
            )
            .unwrap();
        }
        let (status, reply) = post(
            f.state.clone(),
            agentfw::native::pilot_stop::ENDPOINT,
            &sou125_stop_request(&f, &fs, &git),
            Some(NATIVE_TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert!(!agentfw::native::approval::pending_dir(f.dir.path())
            .join(format!("{id}.json"))
            .exists());
        assert!(!agentfw::native::approval::grants_dir(f.dir.path())
            .join(format!("{id}.json"))
            .exists());
        assert!(agentfw::native::approval::pending_dir(f.dir.path())
            .join(format!(
                "{}.json",
                independent["pending_id"].as_str().unwrap()
            ))
            .is_file());
        let mut replay = f.call("selected-fs", "read_document", &json!({}));
        replay["approval_id"] = pending["pending_id"].clone();
        let (_, refused) = f.post(&replay).await;
        assert_eq!(refused["release"], false);
        let (status, useful) = f
            .post(&f.call("other-fs", "read_document", &json!({})))
            .await;
        assert_allow(status, &useful);
    }
}

#[tokio::test]
async fn sou125_stop_preserves_shared_host_hard_deny_on_fresh_reconnect() {
    use agentfw::native::child_authority;
    let f = Fixture::new(NATIVE_REUSE_POLICY);
    let fs = child_start(&f, "selected-fs", "selected-host", Some("filesystem"));
    let git = child_start(&f, "selected-git", "selected-host", Some("git"));
    let (status, reply) = f.post(&fs).await;
    assert_allow(status, &reply);
    let result = child_result(&f, "selected-fs", UNTRUSTED_TEXT).await;
    let (status, reply) = f.post(&result).await;
    assert_allow(status, &reply);
    assert!(f.state.firewall.lock().unwrap().taint_len("selected-host") > 0);
    let (status, reply) = post(
        f.state.clone(),
        agentfw::native::pilot_stop::ENDPOINT,
        &sou125_stop_request(&f, &fs, &git),
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(f.state.firewall.lock().unwrap().taint_len("selected-host") > 0);
    let grant = child_authority::mint_scoped(
        &child_authority::derive_key(NATIVE_TOKEN),
        "selected-host",
        "filesystem",
        &["read_document".into(), "delete_document".into()],
        agentfw::native::now_ms(),
        60_000,
        scoped_fixture_nonce(&f, "selected-host", None),
        Some("reconnected-fs".into()),
        None,
        None,
    );
    let mut fresh = f.event("reconnected-fs", "session_start");
    fresh["host_session"] = json!("selected-host");
    fresh["server_id"] = json!("filesystem");
    fresh["child_authority"] = json!(child_authority::encode_token(&grant));
    let (status, reply) = f.post(&fresh).await;
    assert_allow(status, &reply);
    let (status, denied) = f
        .post(&f.call(
            "reconnected-fs",
            "delete_document",
            &json!({"note": UNTRUSTED_TEXT}),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{denied}");
    assert_eq!(denied["verdict"], "deny", "{denied}");
    assert_eq!(denied["release"], false);
    assert_eq!(denied["reason_codes"], json!(["deny-tainted-destructive"]));
}

async fn sou125_cleanup_request(f: &Fixture, start: &Value) -> Value {
    let mut start = start.clone();
    start["liveness"] = json!("sw-native-liveness/1");
    let (status, started) = f.post(&start).await;
    assert_allow(status, &started);
    let session = start["session_id"].as_str().unwrap();
    let mut enroll = reviewer_sou89_liveness(f, session, "enroll");
    enroll["owner_token"] = started["owner_token"].clone();
    let (status, enrolled) = post_liveness(f, &enroll).await;
    assert_eq!(status, StatusCode::OK, "{enrolled}");
    json!({"contract_version":agentfw::native::pilot_cleanup::CONTRACT,
        "instance_id":f.state.native.as_ref().unwrap().instance_id(),
        "registry_sha256":f.registry_sha256,"session_id":session,
        "epoch":enrolled["epoch"],"owner_token":started["owner_token"],"action":"begin"})
}

async fn sou125_cleanup_observations(f: &Fixture) -> Value {
    let response = app(f.state.clone())
        .oneshot(
            Request::builder()
                .uri("/native/v1/instance")
                .header("authorization", format!("Bearer {NATIVE_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    body["pilot_cleanup"].clone()
}

#[tokio::test]
async fn sou125_cleanup_requires_exact_owner_and_survives_authority_retirement() {
    let f = Fixture::new(ALLOW);
    let fs = child_start(&f, "cleanup-fs", "cleanup-host", Some("filesystem"));
    let git = child_start(&f, "cleanup-git", "cleanup-host", Some("git"));
    let request = sou125_cleanup_request(&f, &fs).await;
    let endpoint = agentfw::native::pilot_cleanup::ENDPOINT;
    for token in [None, Some("wrong-token")] {
        let (status, _) = post(f.state.clone(), endpoint, &request, token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    for field in ["owner_token", "epoch", "instance_id", "registry_sha256"] {
        let mut forged = request.clone();
        forged[field] = json!("foreign");
        let (status, _) = post(f.state.clone(), endpoint, &forged, Some(NATIVE_TOKEN)).await;
        assert_ne!(status, StatusCode::OK, "{field}");
    }
    let (status, reply) = post(f.state.clone(), endpoint, &request, Some(NATIVE_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["status"], "registered");
    let observations = sou125_cleanup_observations(&f).await;
    assert_eq!(observations.as_array().unwrap().len(), 1);
    assert_eq!(observations[0]["verified"], false);
    let (status, reply) = post(
        f.state.clone(),
        agentfw::native::pilot_stop::ENDPOINT,
        &sou125_stop_request(&f, &fs, &git),
        Some(NATIVE_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    // Revocation never acknowledges process cleanup. A new begin cannot race
    // the spent grant, but the exact old owner may discharge its obligation.
    let (status, _) = post(f.state.clone(), endpoint, &request, Some(NATIVE_TOKEN)).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(sou125_cleanup_observations(&f).await[0]["verified"], false);
    let mut finish = request.clone();
    finish["action"] = json!("finish");
    let mut forged = finish.clone();
    forged["owner_token"] = json!("wrong-owner");
    let (status, _) = post(f.state.clone(), endpoint, &forged, Some(NATIVE_TOKEN)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(sou125_cleanup_observations(&f).await[0]["verified"], false);
    for _ in 0..2 {
        let (status, reply) = post(f.state.clone(), endpoint, &finish, Some(NATIVE_TOKEN)).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert_eq!(reply["status"], "verified");
        assert_eq!(sou125_cleanup_observations(&f).await[0]["verified"], true);
    }
    let (_, refused) = f.post(&fs).await;
    assert_ne!(
        refused["release"], true,
        "cleanup must never revive authority"
    );
}

#[tokio::test]
async fn sou125_cleanup_receipt_cannot_discharge_another_run_or_restart() {
    let f = Fixture::new(ALLOW);
    let fs = child_start(&f, "cleanup-a", "host-a", Some("filesystem"));
    let other = child_start(&f, "cleanup-b", "host-b", Some("filesystem"));
    let first = sou125_cleanup_request(&f, &fs).await;
    let second = sou125_cleanup_request(&f, &other).await;
    let endpoint = agentfw::native::pilot_cleanup::ENDPOINT;
    for request in [&first, &second] {
        let (status, reply) = post(f.state.clone(), endpoint, request, Some(NATIVE_TOKEN)).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
    }
    let mut forged = first.clone();
    forged["action"] = json!("finish");
    forged["session_id"] = second["session_id"].clone();
    forged["epoch"] = second["epoch"].clone();
    let (status, _) = post(f.state.clone(), endpoint, &forged, Some(NATIVE_TOKEN)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let mut unknown = first.clone();
    unknown["action"] = json!("finish");
    unknown["epoch"] = json!("stale-epoch");
    let (status, _) = post(f.state.clone(), endpoint, &unknown, Some(NATIVE_TOKEN)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let fresh = Fixture::new(ALLOW);
    let (status, _) = post(fresh.state.clone(), endpoint, &first, Some(NATIVE_TOKEN)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, reply) = f
        .post(&f.call("cleanup-b", "read_document", &json!({})))
        .await;
    assert_allow(status, &reply);
}
