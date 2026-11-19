// SPDX-License-Identifier: Apache-2.0
//! Opt-in managed Agent heartbeat routes (`sw-agent-heartbeat/1`).
//!
//! Agent side: the existing Bearer Agent credential only; admin tokens never
//! work here. Admin side: one read-only status under the existing fleet read
//! authorization. Nothing here changes policy, credentials or rollout state.
use crate::{
    handlers::Shared,
    tenant_store::agent_heartbeat::{self, Heartbeat, Outcome, Refusal, Registration},
};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

fn reply(code: StatusCode, error: &'static str) -> Response {
    (
        code,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({"error": error})),
    )
        .into_response()
}
fn refused(refusal: Refusal) -> Response {
    let code = if refusal == Refusal::WrongAgent {
        StatusCode::FORBIDDEN
    } else if refusal == Refusal::TooFrequent {
        StatusCode::TOO_MANY_REQUESTS
    } else {
        StatusCode::CONFLICT
    };
    reply(code, refusal.code())
}
fn authorization(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
/// Strict JSON within the route's body limit; unknown fields refuse.
fn parse<T: serde::de::DeserializeOwned>(body: &Bytes) -> Option<T> {
    serde_json::from_slice(body).ok()
}

pub async fn register(State(st): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(store) = st.tenant_store.clone() else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, "heartbeat unavailable");
    };
    let Some(request) = parse::<Registration>(&body).filter(Registration::valid) else {
        return reply(StatusCode::BAD_REQUEST, "invalid heartbeat registration");
    };
    match store
        .register_agent_heartbeat(authorization(&headers), request)
        .await
    {
        Ok(Outcome::Accepted(value)) => (
            StatusCode::CREATED,
            [(header::CACHE_CONTROL, "no-store")],
            Json(value),
        )
            .into_response(),
        Ok(Outcome::Unauthorized) => {
            reply(StatusCode::UNAUTHORIZED, "Agent authentication required")
        }
        Ok(Outcome::Refused(r)) => refused(r),
        Ok(Outcome::Unavailable) => reply(
            StatusCode::SERVICE_UNAVAILABLE,
            "heartbeat store not migrated",
        ),
        Err(error) => {
            tracing::error!(error = %error, "heartbeat registration unavailable");
            reply(StatusCode::SERVICE_UNAVAILABLE, "heartbeat unavailable")
        }
    }
}

pub async fn record(State(st): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(store) = st.tenant_store.clone() else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, "heartbeat unavailable");
    };
    let Some(request) = parse::<Heartbeat>(&body).filter(Heartbeat::valid) else {
        return reply(StatusCode::BAD_REQUEST, "invalid heartbeat");
    };
    match store
        .record_agent_heartbeat(authorization(&headers), request)
        .await
    {
        Ok(Outcome::Accepted(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Outcome::Unauthorized) => {
            reply(StatusCode::UNAUTHORIZED, "Agent authentication required")
        }
        Ok(Outcome::Refused(r)) => refused(r),
        Ok(Outcome::Unavailable) => reply(
            StatusCode::SERVICE_UNAVAILABLE,
            "heartbeat store not migrated",
        ),
        Err(error) => {
            tracing::error!(error = %error, "heartbeat unavailable");
            reply(StatusCode::SERVICE_UNAVAILABLE, "heartbeat unavailable")
        }
    }
}

pub async fn status(
    State(st): State<Shared>,
    Path((tenant, agent)): Path<(String, String)>,
) -> Response {
    let Some(store) = st.tenant_store.clone() else {
        return reply(
            StatusCode::SERVICE_UNAVAILABLE,
            "heartbeat status unavailable",
        );
    };
    if !agent_heartbeat::valid_ids(&tenant, &agent) {
        return reply(StatusCode::BAD_REQUEST, "invalid identity");
    }
    match store.agent_heartbeat_status(&tenant, &agent).await {
        Ok(Some(value)) => ([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response(),
        Ok(None) => reply(StatusCode::NOT_FOUND, "Tenant or Agent not found"),
        Err(error) => {
            tracing::error!(error = %error, "heartbeat status unavailable");
            reply(
                StatusCode::SERVICE_UNAVAILABLE,
                "heartbeat status unavailable",
            )
        }
    }
}
