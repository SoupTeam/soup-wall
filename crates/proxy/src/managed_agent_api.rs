// SPDX-License-Identifier: Apache-2.0
//! Bounded managed Agent enrollment HTTP surface (SOU-30).
//!
//! Admin routes are protected by the existing control-plane admin middleware.
//! Agent routes authenticate the distinct per-Agent Bearer credential, not any
//! tenant proxy token, admin token, browser session or provider credential.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use serde::Deserialize;

use crate::handlers::Shared;
use crate::tenant_store::operator_audit::OperatorContext;
use crate::tenant_store::{
    valid_idempotency_key, AdminIdentity, AppliedReport, ConfirmationRefused,
    DeploymentIdempotency, EnrolledAgent, IdempotencyConflict, ManagedIssuer, RotationRequest,
    StartGuard, TenantStore,
};

/// Optional header that makes one individual deployment POST safe to retry.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

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
pub(crate) async fn enroll(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path(tenant_id): Path<String>,
    Json(input): Json<EnrollRequest>,
) -> Response {
    let Some(store) = store(&state).map(|store| store.for_operator(&operator)) else {
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
        Ok(Ok(credential)) => (
            StatusCode::CREATED,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(credential),
        )
            .into_response(),
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
pub(crate) async fn revoke(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path((tenant_id, agent_id)): Path<(String, String)>,
) -> Response {
    let Some(store) = store(&state).map(|store| store.for_operator(&operator)) else {
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

/// Admin-only credential rotation. Never authenticates using the Agent bearer.
pub(crate) async fn rotate_credential(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(input): Json<RotationRequest>,
) -> Response {
    let Some(store) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        store
            .rotate_managed_agent_async(&tenant_id, &agent_id, &input)
            .await
    })
    .await
    {
        Ok(Ok(receipt)) => Json(receipt).into_response(),
        Ok(Err(_)) => failure(StatusCode::CONFLICT, "credential rotation refused"),
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential rotation unavailable",
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
    #[serde(default)]
    pub expected_sequence: Option<u64>,
    #[serde(default)]
    pub issuer_key_id: Option<String>,
}

/// Strictly privileged Console authoring: payload is AgentPolicySet YAML,
/// never a Gateway TenantPolicyDocument.
pub(crate) async fn create_revision(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Extension(identity): Extension<AdminIdentity>,
    Path((tenant, agent)): Path<(String, String)>,
    Json(input): Json<NewRevisionRequest>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.create_managed_revision_authorized_async(
            &tenant,
            &agent,
            &input.revision,
            &input.policy_yaml,
            &identity.admin_id,
        )
        .await
    })
    .await
    {
        Ok(Ok(version)) => (StatusCode::CREATED, Json(version)).into_response(),
        Ok(Err(_)) => {
            tracing::warn!("managed revision creation denied");
            failure(
                StatusCode::BAD_REQUEST,
                "revision invalid or already exists",
            )
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub(crate) async fn approve_revision(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Extension(identity): Extension<AdminIdentity>,
    Path((tenant, agent, revision)): Path<(String, String, String)>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.approve_managed_revision_authorized_async(&tenant, &agent, &revision, &identity.admin_id)
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
///
/// With an `Idempotency-Key` header an exact retry returns the original issuance. Without it the
/// request is the documented keyless operation and always issues a new sequence.
pub(crate) async fn deploy_revision(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Extension(identity): Extension<AdminIdentity>,
    headers: HeaderMap,
    Path((tenant, agent, revision)): Path<(String, String, String)>,
    Json(input): Json<NewDeploymentRequest>,
) -> Response {
    let key = match idempotency_key(&headers) {
        Ok(key) => key,
        Err(()) => return failure(StatusCode::BAD_REQUEST, "invalid Idempotency-Key"),
    };
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    let target_key = input.issuer_key_id.clone();
    if input.expected_sequence.is_some() && key.is_none() {
        return failure(
            StatusCode::BAD_REQUEST,
            "expected_sequence requires Idempotency-Key",
        );
    }
    let Some(key) = key else {
        return match tokio::task::spawn(async move {
            let issuer = ManagedIssuer::from_environment_for_key(target_key.as_deref())?;
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
        };
    };
    match tokio::task::spawn(async move {
        // A retry needs no signer; only a new issuance does.
        let issuer = ManagedIssuer::from_environment_for_key(target_key.as_deref()).ok();
        let idem = DeploymentIdempotency {
            key: &key,
            admin_id: &identity.admin_id,
            requested_issuer_key: target_key.as_deref(),
            expected_sequence: input.expected_sequence,
        };
        db.deploy_managed_revision_keyed_async(
            &tenant,
            &agent,
            &revision,
            input.rollback,
            issuer.as_ref(),
            &idem,
        )
        .await
        .map(|issued| (issued, key.clone()))
    })
    .await
    {
        Ok(Ok((issued, key))) => {
            let mut body = serde_json::to_value(&issued.deployment).unwrap_or_default();
            body["idempotency"] = serde_json::json!({
                "key": key,
                "replayed": issued.replayed,
                "envelope_sha256": issued.envelope_sha256,
                "issuer_key_id": issued.issuer_key_id,
                "expires_at_unix": issued.expires_at_unix,
            });
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Ok(Err(e))
            if e.downcast_ref::<crate::tenant_store::DeploymentPreconditionFailed>()
                .is_some() =>
        {
            failure(
                StatusCode::CONFLICT,
                "deployment inventory changed or group rollout active; review and confirm again",
            )
        }
        Ok(Err(e)) if e.downcast_ref::<IdempotencyConflict>().is_some() => failure(
            StatusCode::CONFLICT,
            "idempotency key conflicts with a previous request",
        ),
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

/// `Ok(None)` when absent; a repeated, non-ASCII or out-of-bounds header is rejected, never ignored.
fn idempotency_key(headers: &HeaderMap) -> Result<Option<String>, ()> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    match first.to_str() {
        Ok(key) if valid_idempotency_key(key) => Ok(Some(key.to_owned())),
        _ => Err(()),
    }
}

#[derive(Default, Deserialize)]
pub struct IssuerQuery {
    pub key_id: Option<String>,
}

/// Public verification key, obtainable via authenticated Console on the
/// provisioning channel; the Agent still requires local operator pinning.
pub async fn issuer_public_key(
    axum::extract::Query(query): axum::extract::Query<IssuerQuery>,
) -> Response {
    let target_key = query.key_id;
    match tokio::task::spawn_blocking(move || {
        ManagedIssuer::from_environment_for_key(target_key.as_deref())
    })
    .await
    {
        Ok(Ok(issuer)) => Json(serde_json::json!({
            "key_id": issuer.key_id(),
            "public_key_hex": issuer.public_key_hex()
        }))
        .into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "issuer key not found or not configured");
            failure(StatusCode::NOT_FOUND, "issuer not configured")
        }
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

async fn principal(
    state: &Shared,
    headers: &HeaderMap,
) -> Option<(TenantStore, EnrolledAgent, String)> {
    let db = store(state)?;
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())?
        .to_owned();
    let lookup = db.clone();
    let lookup_bearer = bearer.clone();
    let identity = tokio::task::spawn(async move {
        lookup
            .authenticate_managed_agent_async(Some(&lookup_bearer))
            .await
    })
    .await
    .ok()?
    .ok()??;
    Some((db, identity, bearer))
}

/// Only an enrolled Agent may fetch its own latest pending deployment.
pub async fn fetch_policy(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let Some((db, who, bearer)) = principal(&state, &headers).await else {
        return failure(StatusCode::UNAUTHORIZED, "Agent authentication required");
    };
    // Credential scope is available even after the pending inbox becomes empty.
    // These public identifiers come from authenticated enrollment, never request headers.
    let (Ok(tenant), Ok(agent)) = (
        HeaderValue::from_str(&who.tenant_id),
        HeaderValue::from_str(&who.agent_id),
    ) else {
        return failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Agent identity unavailable",
        );
    };
    let mut response = match tokio::task::spawn(async move {
        db.deliver_authorized_managed_bundle_async(&who.tenant_id, &who.agent_id, &bearer)
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
    };
    if response.status().is_success() {
        response.headers_mut().insert("x-soup-agent-tenant", tenant);
        response.headers_mut().insert("x-soup-agent-id", agent);
    }
    response
}

/// Agent MUST call this only after inspecting its own active runtime policy.
/// Token possession is a bounded Agent assertion, not a cryptographic quote
/// from trusted hardware. Console validates exact current sequence/revision/hash.
/// The acknowledgement body: the accepted four fields plus, since SOU-241,
/// an optional versioned finite rejection reason. Unknown fields refuse.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckBody {
    pub deployment_sequence: u64,
    pub revision: String,
    pub policy_sha256: String,
    pub status: String,
    #[serde(default)]
    pub rejection: Option<crate::tenant_store::managed_rejection::RejectionReport>,
}

pub async fn acknowledge_policy(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<AckBody>,
) -> Response {
    let Some((db, who, bearer)) = principal(&state, &headers).await else {
        return failure(StatusCode::UNAUTHORIZED, "Agent authentication required");
    };
    let report = AppliedReport {
        deployment_sequence: body.deployment_sequence,
        revision: body.revision,
        policy_sha256: body.policy_sha256,
        status: body.status,
    };
    let reason = body.rejection;
    match tokio::task::spawn(async move {
        db.acknowledge_authorized_managed_bundle_with_reason_async(
            &who.tenant_id,
            &who.agent_id,
            &bearer,
            &report,
            reason.as_ref(),
        )
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGroupRequest {
    pub group_id: String,
    pub name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddGroupMemberRequest {
    pub agent_id: String,
    #[serde(default)]
    pub is_pilot: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGroupRevisionRequest {
    pub revision: String,
    pub policy_yaml: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRolloutRequest {
    pub revision: String,
    #[serde(default)]
    pub issuer_key_id: Option<String>,
    /// From `POST .../rollout/preview`. Absent keeps the documented unguarded start.
    #[serde(default)]
    pub confirmation_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewRolloutRequest {
    pub revision: String,
    #[serde(default)]
    pub issuer_key_id: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub struct RolloutActionRequest {
    pub issuer_key_id: Option<String>,
}

pub(crate) async fn create_group(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path(tenant_id): Path<String>,
    Json(input): Json<CreateGroupRequest>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.create_managed_group_async(&tenant_id, &input.group_id, &input.name)
            .await
    })
    .await
    {
        Ok(Ok(group)) => (StatusCode::CREATED, Json(group)).into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "managed group creation refused");
            failure(StatusCode::BAD_REQUEST, "group invalid or already exists")
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub async fn list_groups(State(state): State<Shared>, Path(tenant_id): Path<String>) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move { db.list_managed_groups_async(&tenant_id).await }).await {
        Ok(Ok(groups)) => Json(groups).into_response(),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub async fn get_group(
    State(state): State<Shared>,
    Path((tenant_id, group_id)): Path<(String, String)>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move { db.get_managed_group_async(&tenant_id, &group_id).await })
        .await
    {
        Ok(Ok(Some(group))) => Json(group).into_response(),
        Ok(Ok(None)) => failure(StatusCode::NOT_FOUND, "group not found"),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub(crate) async fn delete_group(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path((tenant_id, group_id)): Path<(String, String)>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(
        async move { db.delete_managed_group_async(&tenant_id, &group_id).await },
    )
    .await
    {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => failure(StatusCode::NOT_FOUND, "group not found"),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub(crate) async fn add_group_member(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path((tenant_id, group_id)): Path<(String, String)>,
    Json(input): Json<AddGroupMemberRequest>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.add_managed_group_member_async(&tenant_id, &group_id, &input.agent_id, input.is_pilot)
            .await
    })
    .await
    {
        Ok(Ok(member)) => (StatusCode::CREATED, Json(member)).into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "group member addition refused");
            failure(StatusCode::BAD_REQUEST, "invalid group member request")
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub(crate) async fn remove_group_member(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path((tenant_id, group_id, agent_id)): Path<(String, String, String)>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.remove_managed_group_member_async(&tenant_id, &group_id, &agent_id)
            .await
    })
    .await
    {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => failure(StatusCode::NOT_FOUND, "member not found"),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub async fn list_group_members(
    State(state): State<Shared>,
    Path((tenant_id, group_id)): Path<(String, String)>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.list_managed_group_members_async(&tenant_id, &group_id)
            .await
    })
    .await
    {
        Ok(Ok(members)) => Json(members).into_response(),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub(crate) async fn create_group_revision(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path((tenant_id, group_id)): Path<(String, String)>,
    Json(input): Json<CreateGroupRevisionRequest>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.create_managed_group_revision_async(
            &tenant_id,
            &group_id,
            &input.revision,
            &input.policy_yaml,
        )
        .await
    })
    .await
    {
        Ok(Ok(rev)) => (StatusCode::CREATED, Json(rev)).into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "group revision creation refused");
            failure(
                StatusCode::BAD_REQUEST,
                "revision invalid or already exists",
            )
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub(crate) async fn approve_group_revision(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path((tenant_id, group_id, revision)): Path<(String, String, String)>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.approve_managed_group_revision_async(&tenant_id, &group_id, &revision)
            .await
    })
    .await
    {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => failure(StatusCode::NOT_FOUND, "revision absent or already approved"),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "group revision approval refused");
            failure(StatusCode::BAD_REQUEST, "revision approval refused")
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub async fn list_group_revisions(
    State(state): State<Shared>,
    Path((tenant_id, group_id)): Path<(String, String)>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.list_managed_group_revisions_async(&tenant_id, &group_id)
            .await
    })
    .await
    {
        Ok(Ok(revisions)) => Json(revisions).into_response(),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub(crate) async fn start_group_rollout(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Extension(identity): Extension<AdminIdentity>,
    Path((tenant_id, group_id)): Path<(String, String)>,
    Json(input): Json<StartRolloutRequest>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    let target_key = input.issuer_key_id.clone();
    let result = tokio::task::spawn(async move {
        let issuer = ManagedIssuer::from_environment_for_key(target_key.as_deref());
        match input.confirmation_id.as_deref() {
            None => {
                let issuer = issuer?;
                db.start_managed_group_rollout_async(
                    &tenant_id,
                    &group_id,
                    &input.revision,
                    &issuer,
                )
                .await
                .map(|rollout| (rollout, None))
            }
            Some(id) => {
                let guard = StartGuard {
                    confirmation_id: id,
                    admin_id: &identity.admin_id,
                    requested_issuer_key: target_key.as_deref(),
                };
                db.start_managed_group_rollout_guarded_async(
                    &tenant_id,
                    &group_id,
                    &input.revision,
                    issuer.ok().as_ref(),
                    &guard,
                )
                .await
                .map(|started| (started.rollout, Some(started.replayed)))
            }
        }
    })
    .await;
    match result {
        Ok(Ok((rollout, replayed))) => {
            let mut body = serde_json::to_value(&rollout).unwrap_or_default();
            if let Some(replayed) = replayed {
                body["confirmation"] = serde_json::json!({ "replayed": replayed });
            }
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Ok(Err(e)) => {
            if let Some(refused) = e.downcast_ref::<ConfirmationRefused>() {
                tracing::warn!(code = refused.code(), "guarded group rollout start refused");
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "error": refused.to_string(),
                        "code": refused.code(),
                    })),
                )
                    .into_response();
            }
            let msg = e.to_string();
            tracing::warn!(error = %msg, "group rollout start refused");
            if msg.contains("already in progress")
                || msg.contains("already enrolled in active rollout")
            {
                failure(StatusCode::CONFLICT, "active rollout already in progress")
            } else {
                failure(StatusCode::BAD_REQUEST, "rollout cannot be started")
            }
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

/// Authoritative, non-executing preview of what a start would freeze and issue right now.
/// It grants no authority; the start re-derives every fact under its own transaction.
pub async fn preview_group_rollout(
    State(state): State<Shared>,
    Extension(identity): Extension<AdminIdentity>,
    Path((tenant_id, group_id)): Path<(String, String)>,
    Json(input): Json<PreviewRolloutRequest>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.preview_managed_group_start_async(
            &tenant_id,
            &group_id,
            &input.revision,
            &identity.admin_id,
            input.issuer_key_id.as_deref(),
        )
        .await
    })
    .await
    {
        Ok(Ok(preview)) => Json(preview).into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "group rollout preview refused");
            if e.to_string().contains("not found") {
                failure(StatusCode::NOT_FOUND, "group not found")
            } else {
                failure(StatusCode::BAD_REQUEST, "rollout preview unavailable")
            }
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub async fn get_group_rollout(
    State(state): State<Shared>,
    Path((tenant_id, group_id)): Path<(String, String)>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.get_managed_group_rollout_async(&tenant_id, &group_id)
            .await
    })
    .await
    {
        Ok(Ok(Some(rollout))) => Json(rollout).into_response(),
        Ok(Ok(None)) => failure(StatusCode::NOT_FOUND, "no rollout found for group"),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub(crate) async fn advance_group_rollout(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path((tenant_id, group_id)): Path<(String, String)>,
    body: Option<Json<RolloutActionRequest>>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    let target_key = body.and_then(|b| b.0.issuer_key_id);
    match tokio::task::spawn(async move {
        let issuer = ManagedIssuer::from_environment_for_key(target_key.as_deref()).ok();
        db.advance_managed_group_rollout_async(&tenant_id, &group_id, issuer.as_ref())
            .await
    })
    .await
    {
        Ok(Ok(Some(rollout))) => Json(rollout).into_response(),
        Ok(Ok(None)) => failure(StatusCode::NOT_FOUND, "no active rollout to advance"),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "advance rollout refused");
            failure(StatusCode::BAD_REQUEST, "advance rollout refused")
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub(crate) async fn rollback_group_rollout(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path((tenant_id, group_id)): Path<(String, String)>,
    body: Option<Json<RolloutActionRequest>>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    let target_key = body.and_then(|b| b.0.issuer_key_id);
    match tokio::task::spawn(async move {
        let issuer = ManagedIssuer::from_environment_for_key(target_key.as_deref())?;
        db.rollback_managed_group_rollout_async(&tenant_id, &group_id, &issuer)
            .await
    })
    .await
    {
        Ok(Ok(Some(rollout))) => Json(rollout).into_response(),
        Ok(Ok(None)) => failure(StatusCode::NOT_FOUND, "no active rollout to rollback"),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "rollback refused");
            failure(StatusCode::BAD_REQUEST, "rollback refused")
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub(crate) async fn pause_group_rollout(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path((tenant_id, group_id)): Path<(String, String)>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match tokio::task::spawn(async move {
        db.pause_managed_group_rollout_async(&tenant_id, &group_id)
            .await
    })
    .await
    {
        Ok(Ok(Some(rollout))) => Json(rollout).into_response(),
        Ok(Ok(None)) => failure(StatusCode::NOT_FOUND, "no active rollout to pause"),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "pause rollout refused");
            failure(StatusCode::BAD_REQUEST, "pause rollout refused")
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

pub(crate) async fn resume_group_rollout(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path((tenant_id, group_id)): Path<(String, String)>,
    body: Option<Json<RolloutActionRequest>>,
) -> Response {
    let Some(db) = store(&state).map(|store| store.for_operator(&operator)) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    let target_key = body.and_then(|b| b.0.issuer_key_id);
    match tokio::task::spawn(async move {
        let issuer = ManagedIssuer::from_environment_for_key(target_key.as_deref())?;
        db.resume_managed_group_rollout_async(&tenant_id, &group_id, &issuer)
            .await
    })
    .await
    {
        Ok(Ok(Some(rollout))) => Json(rollout).into_response(),
        Ok(Ok(None)) => failure(StatusCode::NOT_FOUND, "no paused rollout to resume"),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "resume rollout refused");
            failure(StatusCode::BAD_REQUEST, "resume rollout refused")
        }
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable"),
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RevisionPage {
    pub after: String,
    pub limit: Option<usize>,
}
/// Bounded metadata discovery, with the same server-side tenant/role middleware.
pub async fn list_revisions(
    State(state): State<Shared>,
    Path((tenant, agent)): Path<(String, String)>,
    axum::extract::Query(page): axum::extract::Query<RevisionPage>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    if !(1..=100).contains(&page.limit.unwrap_or(50))
        || page.after.len() > 128
        || !page
            .after
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return failure(StatusCode::BAD_REQUEST, "invalid revision page");
    }
    match db
        .list_managed_revisions_async(&tenant, &agent, &page.after, page.limit.unwrap_or(50))
        .await
    {
        Ok(rows) => Json(rows).into_response(),
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "revision inventory unavailable",
        ),
    }
}
pub async fn read_revision(
    State(state): State<Shared>,
    Path((tenant, agent, revision)): Path<(String, String, String)>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match db
        .read_managed_revision_async(&tenant, &agent, &revision)
        .await
    {
        Ok(Some(row)) => Json(row).into_response(),
        Ok(None) => failure(StatusCode::NOT_FOUND, "revision not found"),
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "revision unavailable"),
    }
}

/// Query addressing preserves valid `.` and `..` Agent/revision identifiers,
/// which URL clients normalize in path segments. Existing routes remain.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedAgent {
    #[serde(deserialize_with = "selected_identifier")]
    pub(crate) agent_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedRevision {
    #[serde(deserialize_with = "selected_identifier")]
    pub agent_id: String,
    #[serde(deserialize_with = "selected_identifier")]
    pub revision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedRevisionPage {
    #[serde(deserialize_with = "selected_identifier")]
    pub agent_id: String,
    #[serde(default)]
    pub after: String,
    pub limit: Option<usize>,
}

fn selected_identifier<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(serde::de::Error::custom("invalid identifier selector"));
    }
    Ok(value)
}

pub async fn list_selected_revisions(
    State(state): State<Shared>,
    Path(tenant): Path<String>,
    axum::extract::Query(selected): axum::extract::Query<SelectedRevisionPage>,
) -> Response {
    list_revisions(
        State(state),
        Path((tenant, selected.agent_id)),
        axum::extract::Query(RevisionPage {
            after: selected.after,
            limit: selected.limit,
        }),
    )
    .await
}

pub(crate) async fn create_selected_revision(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Extension(identity): Extension<AdminIdentity>,
    Path(tenant): Path<String>,
    axum::extract::Query(selected): axum::extract::Query<SelectedAgent>,
    Json(input): Json<NewRevisionRequest>,
) -> Response {
    create_revision(
        State(state),
        Extension(operator),
        Extension(identity),
        Path((tenant, selected.agent_id)),
        Json(input),
    )
    .await
}

/// Read one enrollment beyond the bounded list, including after a lost one-time response.
pub(crate) async fn selected_enrollment(
    State(state): State<Shared>,
    Path(tenant): Path<String>,
    axum::extract::Query(selected): axum::extract::Query<SelectedAgent>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    match db
        .get_managed_agent_async(&tenant, &selected.agent_id)
        .await
    {
        Ok(Some(agent)) => (
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(agent),
        )
            .into_response(),
        Ok(None) => failure(StatusCode::NOT_FOUND, "Agent enrollment not found"),
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Agent enrollment unavailable",
        ),
    }
}

pub(crate) async fn rotate_selected_credential(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path(tenant): Path<String>,
    axum::extract::Query(selected): axum::extract::Query<SelectedAgent>,
    Json(input): Json<RotationRequest>,
) -> Response {
    rotate_credential(
        State(state),
        Extension(operator),
        Path((tenant, selected.agent_id)),
        Json(input),
    )
    .await
}

pub(crate) async fn revoke_selected_agent(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Path(tenant): Path<String>,
    axum::extract::Query(selected): axum::extract::Query<SelectedAgent>,
) -> Response {
    revoke(
        State(state),
        Extension(operator),
        Path((tenant, selected.agent_id)),
    )
    .await
}

pub async fn selected_deployments(
    State(state): State<Shared>,
    Path(tenant): Path<String>,
    axum::extract::Query(selected): axum::extract::Query<SelectedAgent>,
) -> Response {
    deployments(State(state), Path((tenant, selected.agent_id))).await
}

pub async fn read_selected_revision(
    State(state): State<Shared>,
    Path(tenant): Path<String>,
    axum::extract::Query(selected): axum::extract::Query<SelectedRevision>,
) -> Response {
    read_revision(
        State(state),
        Path((tenant, selected.agent_id, selected.revision)),
    )
    .await
}

pub(crate) async fn approve_selected_revision(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Extension(identity): Extension<AdminIdentity>,
    Path(tenant): Path<String>,
    axum::extract::Query(selected): axum::extract::Query<SelectedRevision>,
) -> Response {
    approve_revision(
        State(state),
        Extension(operator),
        Extension(identity),
        Path((tenant, selected.agent_id, selected.revision)),
    )
    .await
}

pub(crate) async fn deploy_selected_revision(
    State(state): State<Shared>,
    Extension(operator): Extension<OperatorContext>,
    Extension(identity): Extension<AdminIdentity>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
    axum::extract::Query(selected): axum::extract::Query<SelectedRevision>,
    Json(input): Json<NewDeploymentRequest>,
) -> Response {
    deploy_revision(
        State(state),
        Extension(operator),
        Extension(identity),
        headers,
        Path((tenant, selected.agent_id, selected.revision)),
        Json(input),
    )
    .await
}

/// Read-only tenant-authorized diagnostics. GET never scans or advances plans.
pub async fn reconciliation_status(
    State(state): State<Shared>,
    Path((tenant, group)): Path<(String, String)>,
) -> Response {
    let Some(db) = store(&state) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Console storage unavailable",
        );
    };
    Json(serde_json::json!({"configured": state.config.rollout_reconciliation.enabled, "status": db.reconciliation_status(&tenant, &group)})).into_response()
}
