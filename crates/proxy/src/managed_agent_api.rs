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
use crate::tenant_store::{AppliedReport, EnrolledAgent, ManagedIssuer, TenantStore};

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

/// Owner-only: issues the Agent credential once, never on later reads.
pub async fn enroll(
    State(state): State<Shared>,
    Path(tenant_id): Path<String>,
    Json(input): Json<EnrollRequest>,
) -> Response {
    let Some(store) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "managed Agent enrollment unavailable",
        );
    };
    let result = tokio::task::spawn(async move {
        store
            .enroll_managed_agent_async(&tenant_id, &input.agent_id)
            .await
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
pub async fn list(State(state): State<Shared>, Path(tenant_id): Path<String>) -> Response {
    let Some(store) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "managed Agent enrollment unavailable",
        );
    };
    match tokio::task::spawn(async move { store.list_managed_agents_async(&tenant_id).await }).await
    {
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

/// Owner-only revocation. The Bearer token stops working immediately.
pub async fn revoke(
    State(state): State<Shared>,
    Path((tenant_id, agent_id)): Path<(String, String)>,
) -> Response {
    let Some(store) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "managed Agent enrollment unavailable",
        );
    };
    match tokio::task::spawn(async move {
        store
            .revoke_managed_agent_async(&tenant_id, &agent_id)
            .await
    })
    .await
    {
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
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let Some(store) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "managed Agent enrollment unavailable",
        );
    };
    match tokio::task::spawn(async move {
        store
            .authenticate_managed_agent_async(auth.as_deref())
            .await
    })
    .await
    {
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRevisionRequest {
    pub revision: String,
    pub policy_yaml: String,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewDeploymentRequest {
    #[serde(default)]
    pub rollback: bool,
}

/// Strictly privileged Console authoring: payload is AgentPolicySet YAML,
/// never a Gateway TenantPolicyDocument.
pub async fn create_revision(
    State(state): State<Shared>,
    Path((tenant, agent)): Path<(String, String)>,
    Json(input): Json<NewRevisionRequest>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.create_managed_revision_async(&tenant, &agent, &input.revision, &input.policy_yaml)
            .await
    })
    .await
    {
        Ok(Ok(version)) => (StatusCode::CREATED, Json(version)).into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "managed revision creation denied");
            failure(
                StatusCode::BAD_REQUEST,
                "revision invalid or already exists",
            )
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub async fn approve_revision(
    State(state): State<Shared>,
    Path((tenant, agent, revision)): Path<(String, String, String)>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.approve_managed_revision_async(&tenant, &agent, &revision)
            .await
    })
    .await
    {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => failure(StatusCode::NOT_FOUND, "revision absent or already approved"),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "Agent revision approval denied");
            failure(StatusCode::BAD_REQUEST, "revision approval denied")
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

/// The seed never leaves the operator's environment; each deployment has
/// fresh sequence and expiry. Rollback re-signs an older approved payload.
pub async fn deploy_revision(
    State(state): State<Shared>,
    Path((tenant, agent, revision)): Path<(String, String, String)>,
    Json(input): Json<NewDeploymentRequest>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        let issuer = ManagedIssuer::from_environment()?;
        db.deploy_managed_revision_async(&tenant, &agent, &revision, input.rollback, &issuer)
            .await
    })
    .await
    {
        Ok(Ok(deployment)) => (StatusCode::CREATED, Json(deployment)).into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "Agent deployment refused");
            failure(
                StatusCode::BAD_REQUEST,
                "deployment unavailable or not approved",
            )
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

/// Public verification key, obtainable via authenticated Console on the
/// provisioning channel; the Agent still requires local operator pinning.
pub async fn issuer_public_key() -> Response {
    match tokio::task::spawn_blocking(ManagedIssuer::from_environment).await {
        Ok(Ok(issuer)) => Json(serde_json::json!({
            "public_key_hex": issuer.public_key_hex()
        }))
        .into_response(),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "issuer not configured"),
    }
}

pub async fn deployments(
    State(state): State<Shared>,
    Path((tenant, agent)): Path<(String, String)>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(
        async move { db.list_managed_deployments_async(&tenant, &agent).await },
    )
    .await
    {
        Ok(Ok(items)) => Json(items).into_response(),
        _ => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "deployment inventory unavailable",
        ),
    }
}

async fn principal(state: &Shared, headers: &HeaderMap) -> Option<(TenantStore, EnrolledAgent)> {
    let db = store(state)?;
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())?
        .to_owned();
    let lookup = db.clone();
    let identity =
        tokio::task::spawn(
            async move { lookup.authenticate_managed_agent_async(Some(&bearer)).await },
        )
        .await
        .ok()?
        .ok()??;
    Some((db, identity))
}

/// Only an enrolled Agent may fetch its own latest pending deployment.
pub async fn fetch_policy(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let Some((db, who)) = principal(&state, &headers).await else {
        return failure(StatusCode::UNAUTHORIZED, "Agent authentication required");
    };
    match tokio::task::spawn(async move {
        db.deliver_managed_bundle_async(&who.tenant_id, &who.agent_id)
            .await
    })
    .await
    {
        Ok(Ok(Some(bundle))) => Json(bundle).into_response(),
        Ok(Ok(None)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "managed policy delivery unavailable");
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "policy delivery unavailable",
            )
        }
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "policy delivery unavailable",
        ),
    }
}

/// Agent MUST call this only after inspecting its own active runtime policy.
/// Token possession is a bounded Agent assertion, not a cryptographic quote
/// from trusted hardware. Console validates exact current sequence/revision/hash.
pub async fn acknowledge_policy(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(report): Json<AppliedReport>,
) -> Response {
    let Some((db, who)) = principal(&state, &headers).await else {
        return failure(StatusCode::UNAUTHORIZED, "Agent authentication required");
    };
    match tokio::task::spawn(async move {
        db.acknowledge_managed_bundle_async(&who.tenant_id, &who.agent_id, &report)
            .await
    })
    .await
    {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => failure(StatusCode::CONFLICT, "ack mismatch, stale or superseded"),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "policy ack invalid");
            failure(StatusCode::BAD_REQUEST, "invalid policy acknowledgement")
        }
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "acknowledgement unavailable",
        ),
    }
}
