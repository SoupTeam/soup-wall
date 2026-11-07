// SPDX-License-Identifier: Apache-2.0
//! SOU-242 stale-restore recovery endpoints (`sw-console-stale-restore-recovery/1`).
//!
//! `POST .../stale-recovery/preview` and `.../confirm` are Owner-only through
//! the existing admin role rules for non-GET Agent routes; `GET
//! .../stale-recovery` uses the normal read role. Refusals carry one fixed
//! code and message, never evidence text.
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};

use crate::handlers::Shared;
use crate::tenant_store::managed_stale_recovery::{ConfirmRequest, PreviewRequest, Refusal};
use crate::tenant_store::AdminIdentity;
use crate::tenant_store::ManagedIssuer;

fn failure(code: StatusCode, message: &'static str) -> Response {
    (code, Json(serde_json::json!({"error": message}))).into_response()
}
fn refused(refusal: Refusal) -> Response {
    (
        StatusCode::from_u16(refusal.http_status()).unwrap_or(StatusCode::CONFLICT),
        Json(serde_json::json!({
            "error": refusal.message(),
            "refusal": refusal.code(),
            "recovery_open": false,
        })),
    )
        .into_response()
}
/// The current default issuer only: recovery never selects another key.
fn issuer() -> Option<ManagedIssuer> {
    ManagedIssuer::from_environment().ok()
}

pub(crate) async fn preview(
    State(state): State<Shared>,
    Path((tenant, agent)): Path<(String, String)>,
    body: Result<Json<PreviewRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(request)) = body else {
        return refused(Refusal::EvidenceMalformed);
    };
    let Some(store) = state.tenant_store.clone() else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    let Some(issuer) = issuer() else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console issuer unavailable",
        );
    };
    match store
        .stale_recovery_preview(&tenant, &agent, request.evidence, issuer)
        .await
    {
        Ok(Ok(preview)) => (StatusCode::OK, Json(preview)).into_response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(error) => {
            tracing::warn!(error = %error, "stale recovery preview unavailable");
            failure(StatusCode::BAD_REQUEST, "recovery preview unavailable")
        }
    }
}

pub(crate) async fn confirm(
    State(state): State<Shared>,
    Extension(identity): Extension<AdminIdentity>,
    Path((tenant, agent)): Path<(String, String)>,
    body: Result<Json<ConfirmRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(request)) = body else {
        return refused(Refusal::EvidenceMalformed);
    };
    let Some(store) = state.tenant_store.clone() else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    let Some(issuer) = issuer() else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console issuer unavailable",
        );
    };
    match store
        .stale_recovery_confirm(&tenant, &agent, request, issuer, &identity.admin_id)
        .await
    {
        Ok(Ok(confirmed)) => (
            if confirmed.replayed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            Json(confirmed),
        )
            .into_response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(error) => {
            // A concurrent confirmation loses on the unique fence keys.
            tracing::warn!(error = %error, "stale recovery confirmation refused");
            refused(Refusal::StateChanged)
        }
    }
}

pub(crate) async fn status(
    State(state): State<Shared>,
    Path((tenant, agent)): Path<(String, String)>,
) -> Response {
    let Some(store) = state.tenant_store.clone() else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match store.stale_recovery_status(&tenant, &agent).await {
        Ok(Some(status)) => (StatusCode::OK, Json(status)).into_response(),
        Ok(None) => failure(StatusCode::NOT_FOUND, "Agent not found"),
        Err(error) => {
            tracing::warn!(error = %error, "stale recovery status unavailable");
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "recovery status unavailable",
            )
        }
    }
}
