// SPDX-License-Identifier: Apache-2.0
//! Protected registration of a launcher-held recipient. No payload release.
use super::*;
use crate::pilot_approval::consumer::Registration;

pub const ENDPOINT: &str = "/native/held-consumer/v1";
const LIMIT: usize = 32;

// Small replay custody is separate from the 32 live process slots. Expired
// registrations cannot pass verify(), so their tombstones can be reclaimed.
fn reclaim_disposed(sessions: &mut Sessions, now: u64) {
    sessions.consumer_terminal.retain(|_, expiry| *expiry > now);
    let disposed: Vec<_> = sessions
        .consumers
        .iter()
        .filter_map(|(host, record)| {
            let authorities = record.authorities();
            let withdrawn = record.authority_expiry() <= now
                || authorities.values().all(|digest| {
                    sessions
                        .spent_authorities
                        .get(digest)
                        .is_some_and(|expiry| *expiry > now)
                });
            let active = sessions.entries.values().any(|session| {
                session.host_session.as_deref() == Some(host.as_str())
                    || session
                        .authority_digest
                        .as_ref()
                        .is_some_and(|digest| authorities.values().any(|v| v == digest))
            });
            let clean = authorities.iter().all(|(server, digest)| {
                sessions.pilot_cleanup.get(digest).is_none_or(|row| {
                    row.verified && row.host_session == *host && row.server_id == *server
                })
            });
            (withdrawn && !active && clean && record.physically_disposed())
                .then(|| (host.clone(), record.expires()))
        })
        .collect();
    for (host, expiry) in disposed {
        if expiry > now {
            if sessions.consumer_terminal.len() >= MAX_SPENT_AUTHORITIES {
                break; // Never drop replay custody to make room.
            }
            sessions.consumer_terminal.insert(host.clone(), expiry);
        }
        sessions.consumers.remove(&host);
    }
}

pub async fn handler(
    State(st): State<Shared>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, String) {
    let Some(native) = &st.native else {
        return (StatusCode::NOT_FOUND, "native_not_configured".into());
    };
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&native.token, auth) {
        return (StatusCode::UNAUTHORIZED, "native_unauthorized".into());
    }
    if !st.config.enforce || st.config.judge.enabled {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "native_enforcement_required".into(),
        );
    }
    let registration: Registration = match serde_json::from_str(&body) {
        Ok(value) if body.len() <= 65_536 => value,
        _ => return (StatusCode::BAD_REQUEST, "consumer_invalid_request".into()),
    };
    let now = match wall_time_ms() {
        Ok(now) => now,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "native_clock_unavailable".into(),
            )
        }
    };
    // Admission and exact-authority retirement use this same lock. A copied
    // registration can never replace a live or terminal host generation.
    let mut sessions = match native.sessions.lock() {
        Ok(sessions) => sessions,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "native_state_unavailable".into(),
            )
        }
    };
    if registration
        .verify(native.instance_id(), &native.registry_sha256, now)
        .is_err()
    {
        return (StatusCode::FORBIDDEN, "consumer_runtime_unverified".into());
    }
    if !identifier(registration.host())
        || !registration.authorities().values().all(|v| is_digest(v))
    {
        return (StatusCode::BAD_REQUEST, "consumer_invalid_binding".into());
    }
    if registration
        .authorities()
        .values()
        .any(|digest| sessions.spent_authorities.contains_key(digest))
    {
        return (StatusCode::CONFLICT, "consumer_authority_retired".into());
    }
    if sessions.entries.values().any(|session| {
        session.host_session.as_deref() == Some(registration.host())
            && session.authority_digest.as_ref().is_some_and(|digest| {
                !registration
                    .authorities()
                    .values()
                    .any(|expected| expected == digest)
            })
    }) {
        return (StatusCode::CONFLICT, "consumer_foreign_authority".into());
    }
    reclaim_disposed(&mut sessions, now);
    if sessions.consumers.contains_key(registration.host())
        || sessions.consumer_terminal.contains_key(registration.host())
        || sessions.consumers.len() >= LIMIT
    {
        return (StatusCode::CONFLICT, "consumer_replay_or_capacity".into());
    }
    sessions
        .consumers
        .insert(registration.host().into(), registration);
    (StatusCode::NO_CONTENT, String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registration_requires_native_auth_and_strict_bounded_body() {
        let dir = tempfile::tempdir().unwrap();
        let st = super::super::tests::fixture(dir.path());
        let empty = HeaderMap::new();
        assert_eq!(
            handler(State(st.clone()), empty, "{}".into()).await.0,
            StatusCode::UNAUTHORIZED
        );
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer native-unit-key".parse().unwrap());
        for body in [
            "{}".to_owned(),
            "x".repeat(65_537),
            r#"{"contract":"sw-held-consumer/1","fake":true}"#.into(),
        ] {
            assert_eq!(
                handler(State(st.clone()), headers.clone(), body).await.0,
                StatusCode::BAD_REQUEST
            );
        }
        assert!(st
            .native
            .as_ref()
            .unwrap()
            .sessions
            .lock()
            .unwrap()
            .consumers
            .is_empty());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod lifecycle_tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    struct Held(std::process::Child);
    impl Drop for Held {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn child() -> Held {
        Held(
            std::process::Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
                .unwrap(),
        )
    }
    fn headers() -> HeaderMap {
        let mut value = HeaderMap::new();
        value.insert("authorization", "Bearer native-unit-key".parse().unwrap());
        value
    }
    async fn register(st: &Shared, registration: &Registration) -> StatusCode {
        handler(
            State(st.clone()),
            headers(),
            serde_json::to_string(registration).unwrap(),
        )
        .await
        .0
    }
    async fn revoke(st: &Shared, registration: &Registration) {
        let native = st.native.as_ref().unwrap();
        let request = pilot_stop::Request {
            contract_version: pilot_stop::CONTRACT.into(),
            instance_id: native.instance_id().into(),
            registry_sha256: native.registry_sha256.clone(),
            host_session: registration.host().into(),
            authorities: registration.authorities().clone(),
            expires_at_ms: registration.authority_expiry(),
        };
        assert_eq!(
            pilot_stop::handler(
                State(st.clone()),
                headers(),
                serde_json::to_string(&request).unwrap()
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    fn binding(st: &Shared, host: &str, child: &Held) -> (Registration, Vec<std::fs::File>) {
        let native = st.native.as_ref().unwrap();
        crate::pilot_approval::consumer::held_fixture(
            native.instance_id(),
            &native.registry_sha256,
            host,
            &child.0,
        )
    }

    #[test]
    fn repeated_completed_runs_reclaim_slots_via_protected_handlers() {
        // Multiple libtest filters allow the trusted launcher argv marker and
        // the single ignored helper, without changing production verification.
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "pilot-launch",
                "native::consumer::lifecycle_tests::handler_lifecycle_child",
                "--ignored",
                "--nocapture",
            ])
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[tokio::test]
    #[ignore = "re-executed with the real launcher argv marker by the parent witness"]
    async fn handler_lifecycle_child() {
        assert_eq!(std::env::args().nth(1).as_deref(), Some("pilot-launch"));
        for expire_registration in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let st = super::super::tests::fixture(dir.path());
            let child = child();
            let native = st.native.as_ref().unwrap();
            let (registration, _files) = crate::pilot_approval::consumer::held_fixture_with_ttl(
                native.instance_id(),
                &native.registry_sha256,
                "expiry-wait-host",
                &child.0,
                if expire_registration { 2_000 } else { 120_000 },
            );
            assert_eq!(register(&st, &registration).await, StatusCode::NO_CONTENT);
            analysis_purpose::expiry_lock_wait_regression(&st, &registration, expire_registration);
        }
        // Actual sealed registration and consume/confirm component path. Only
        // the quarantine record/issuer are explicit fixtures, never production mint.
        for mode in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            let st = super::super::tests::fixture(dir.path());
            let mut child = child();
            let (registration, _files) = binding(&st, "purpose-host", &child);
            assert_eq!(register(&st, &registration).await, StatusCode::NO_CONTENT);
            let grant = analysis_purpose::lifecycle_fixture(&st, &registration, "purpose-q");
            let mut forged = serde_json::to_value(&grant).unwrap();
            forged["binding"]["response_sha256"] = json!("f".repeat(64));
            let forged = serde_json::from_value(forged).unwrap();
            assert!(analysis_purpose::consume(&st, &forged).is_err());
            assert!(st
                .native
                .as_ref()
                .unwrap()
                .sessions
                .lock()
                .unwrap()
                .purpose_spent
                .is_empty());
            let pending = analysis_purpose::consume(&st, &grant).unwrap();
            assert!(analysis_purpose::consume(&st, &grant).is_err());
            assert_eq!(register(&st, &registration).await, StatusCode::CONFLICT);
            if mode == 1 {
                st.native
                    .as_ref()
                    .unwrap()
                    .sessions
                    .lock()
                    .unwrap()
                    .pilot_cleanup
                    .insert(
                        registration.authorities()["filesystem"].clone(),
                        pilot_cleanup::unconfirmed_consumer_fixture(
                            registration.host(),
                            "filesystem",
                        ),
                    );
            }
            if mode != 0 {
                child.0.kill().unwrap();
                child.0.wait().unwrap();
            }
            let confirmed = pending.confirm(&st);
            assert_eq!(confirmed.is_ok(), mode == 2);
            assert!(
                st.native
                    .as_ref()
                    .unwrap()
                    .quarantine
                    .lock()
                    .unwrap()
                    .retained("purpose-q")
                    .unwrap()
                    .1
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let st = super::super::tests::fixture(dir.path());
        for index in 0..40 {
            let mut child = child();
            let (registration, _files) = binding(&st, &format!("completed-{index}"), &child);
            assert_eq!(register(&st, &registration).await, StatusCode::NO_CONTENT);
            assert_eq!(register(&st, &registration).await, StatusCode::CONFLICT);
            revoke(&st, &registration).await;
            assert_eq!(register(&st, &registration).await, StatusCode::CONFLICT);
            assert!(!registration.physically_disposed());
            {
                let mut sessions = st.native.as_ref().unwrap().sessions.lock().unwrap();
                reclaim_disposed(&mut sessions, wall_time_ms().unwrap());
                assert!(sessions.consumers.contains_key(registration.host()));
            }
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            assert!(registration.physically_disposed());
            assert_ne!(register(&st, &registration).await, StatusCode::NO_CONTENT);
        }
        let native = st.native.as_ref().unwrap();
        assert_eq!(native.sessions.lock().unwrap().consumers.len(), 1);
        assert_eq!(native.sessions.lock().unwrap().consumer_terminal.len(), 39);

        // Unconfirmed namespace cleanup must retain all live slots even after
        // authority withdrawal and actual child reaping. Finish uses the real
        // protected cleanup handler over explicit pre-existing owner fixtures.
        let dir2 = tempfile::tempdir().unwrap();
        let st2 = super::super::tests::fixture(dir2.path());
        let mut records = Vec::new();
        for index in 0..32 {
            let mut child = child();
            let (registration, files) = binding(&st2, &format!("unconfirmed-{index}"), &child);
            assert_eq!(register(&st2, &registration).await, StatusCode::NO_CONTENT);
            revoke(&st2, &registration).await;
            let mut sessions = st2.native.as_ref().unwrap().sessions.lock().unwrap();
            sessions.pilot_cleanup.insert(
                registration.authorities()["filesystem"].clone(),
                pilot_cleanup::unconfirmed_consumer_fixture(registration.host(), "filesystem"),
            );
            drop(sessions);
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            records.push((registration, files));
        }
        let fresh = child();
        let (registration, _files) = binding(&st2, "fresh-after-unconfirmed", &fresh);
        assert_eq!(register(&st2, &registration).await, StatusCode::CONFLICT);
        for (old, _) in &records {
            let native = st2.native.as_ref().unwrap();
            let body = json!({"contract_version":pilot_cleanup::CONTRACT,"instance_id":native.instance_id(),
                "registry_sha256":native.registry_sha256,"session_id":old.host(),"epoch":"fixture-epoch",
                "owner_token":"fixture-owner","action":"finish"}).to_string();
            assert_eq!(
                pilot_cleanup::handler(State(st2.clone()), headers(), body)
                    .await
                    .0,
                StatusCode::OK
            );
        }
        assert_eq!(register(&st2, &registration).await, StatusCode::NO_CONTENT);
        assert_eq!(
            st2.native
                .as_ref()
                .unwrap()
                .sessions
                .lock()
                .unwrap()
                .consumer_terminal
                .len(),
            32
        );
    }
}
