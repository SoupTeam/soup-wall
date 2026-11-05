// SPDX-License-Identifier: Apache-2.0
//! Protected registration of a launcher-held recipient. No payload release.
use super::*;
use crate::pilot_approval::consumer::Registration;

pub const ENDPOINT: &str = "/native/held-consumer/v1";
const LIMIT: usize = 32;

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
    sessions.consumers.retain(|_, value| value.expires() > now);
    if sessions.consumers.contains_key(registration.host()) || sessions.consumers.len() >= LIMIT {
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
