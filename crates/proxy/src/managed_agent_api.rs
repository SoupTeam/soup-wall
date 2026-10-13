// SPDX-License-Identifier: Apache-2.0
//! Bounded managed Agent enrollment HTTP surface (SOU-30).
//!
//! Admin routes are protected by the existing control-plane admin middleware.
//! Agent routes authenticate the distinct per-Agent Bearer credential, not any
//! tenant proxy token, admin token, browser session or provider credential.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::handlers::Shared;
use crate::tenant_store::TenantStore;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    pub agent_id: String,
}

fn failure(code: StatusCode, message: &'static str) -> Response {
    (code, Json(serde_json::json!({"error": message}))).into_response()
}

fn store(state: &Shared) -> Option<TenantStore> {
    state.tenant_store.as_ref().cloned()
}

/// Operator-only: issues the Agent credential once, never on later reads.
pub async fn enroll(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Json(input): Json<EnrollRequest>,
) -> Response {
    let Some(store) = store(&state) else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "managed Agent enrollment unavailable");
    };
    let result = tokio::task::spawn_blocking(move || {
        store.enroll_managed_agent(&tenant_id, &input.agent_id)
    })
    .await;
    match result {
        Ok(Ok(credential)) => (StatusCode::CREATED, Json(credential)).into_response(),
        Ok(Err(error_value)) => {
            tracing::warn!(error = %error_value, "managed Agent enrollment refused");
            failure(StatusCode::BAD_REQUEST, "Agent enrollment refused")
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "managed Agent enrollment task failed");
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Agent enrollment temporarily unavailable",
            )
        }
    }
}

/// Admin inventory never returns credentials or their persisted hashes.
pub async fn list(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
) -> Response {
    let Some(store) = store(&state) else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "managed Agent enrollment unavailable");
    };
    match tokio::task::spawn_blocking(move || store.list_managed_agents(&tenant_id)).await {
        Ok(Ok(agents)) => Json(agents).into_response(),
        Ok(Err(error_value)) => {
            tracing::error!(error = %error_value, "managed Agent inventory unavailable");
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Agent inventory unavailable",
            )
        }
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Agent inventory unavailable",
        ),
    }
}

/// Operator-only revocation. The Bearer token stops working immediately.
pub async fn revoke(
    State(state): State<Shared>,
    Path((tenant_id, agent_id)): Path<(String, String)>,
) -> Response {
    let Some(store) = store(&state) else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "managed Agent enrollment unavailable");
    };
    match tokio::task::spawn_blocking(move || {
        store.revoke_managed_agent(&tenant_id, &agent_id)
    }).await {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => failure(StatusCode::NOT_FOUND, "Agent enrollment not found"),
        Ok(Err(error_value)) => {
            tracing::warn!(error = %error_value, "managed Agent revocation refused");
            failure(StatusCode::BAD_REQUEST, "Agent revocation refused")
        }
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Agent revocation unavailable",
        ),
    }
}

/// Explicit Agent identity proof; never reuses admin/tenant authentication.
pub async fn whoami(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let auth = headers.get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let Some(store) = store(&state) else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "managed Agent enrollment unavailable");
    };
    match tokio::task::spawn_blocking(move || {
        store.authenticate_managed_agent(auth.as_deref())
    }).await {
        Ok(Ok(Some(identity))) => Json(identity).into_response(),
        Ok(Ok(None)) => failure(StatusCode::UNAUTHORIZED, "Agent authentication required"),
        Ok(Err(error_value)) => {
            tracing::error!(error = %error_value, "managed Agent authentication unavailable");
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Agent authentication unavailable",
            )
        }
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Agent authentication unavailable",
        ),
    }
}
