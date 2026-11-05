// SPDX-License-Identifier: Apache-2.0

use axum::{
    body::Body,
    extract::{MatchedPath, Path, Query, State},
    http::{header, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use crate::{
    handlers::Shared,
    tenant_store::operator_audit::{
        AuditOperation, AuditOutcome, OperatorAuditQuery, OperatorContext,
    },
};

pub(crate) struct Attempt {
    tenant: String,
    operation: AuditOperation,
}

impl Attempt {
    /// Match only routed mutations. Never store a submitted path, selector,
    /// query string or body for a request that has no committed target.
    pub(crate) fn identify(request: &Request<Body>) -> Option<Self> {
        use AuditOperation::*;
        let route = request
            .extensions()
            .get::<MatchedPath>()?
            .as_str()
            .strip_prefix("/admin/v1/tenants/:tenant_id")?;
        let operation = match (request.method(), route) {
            (&Method::POST, "/agents") => AgentEnroll,
            (&Method::POST, "/agents/:agent_id/revoke" | "/agents/revoke") => AgentRevoke,
            (
                &Method::POST,
                "/agents/:agent_id/credential-rotations" | "/agents/credential-rotations",
            ) => AgentRotate,
            (&Method::POST, "/agents/:agent_id/revisions" | "/agents/policy-revisions") => {
                AgentPolicyCreate
            }
            (
                &Method::POST,
                "/agents/:agent_id/revisions/:revision/approve" | "/agents/policy-revision/approve",
            ) => AgentPolicyApprove,
            (
                &Method::POST,
                "/agents/:agent_id/revisions/:revision/deploy" | "/agents/policy-revision/deploy",
            ) => AgentPolicyDeploy,
            (&Method::POST, "/groups") => GroupCreate,
            (&Method::DELETE, "/groups/:group_id") => GroupDelete,
            (&Method::POST, "/groups/:group_id/members") => GroupAddMember,
            (&Method::DELETE, "/groups/:group_id/members/:agent_id") => GroupRemoveMember,
            (&Method::POST, "/groups/:group_id/revisions") => GroupPolicyCreate,
            (&Method::POST, "/groups/:group_id/revisions/:revision/approve") => GroupPolicyApprove,
            (&Method::POST, "/groups/:group_id/rollout") => RolloutStart,
            (&Method::POST, "/groups/:group_id/rollout/advance") => RolloutAdvance,
            (&Method::POST, "/groups/:group_id/rollout/pause") => RolloutPause,
            (&Method::POST, "/groups/:group_id/rollout/resume") => RolloutResume,
            (&Method::POST, "/groups/:group_id/rollout/rollback") => RolloutRollback,
            (&Method::POST, "/policy-versions") => PolicyCreate,
            (&Method::POST, "/policy-versions/:version_id/approve") => PolicyApprove,
            (&Method::POST, "/policy-versions/:version_id/activate") => PolicyActivate,
            (&Method::POST, "/policy-versions/:version_id/rollback") => PolicyRollback,
            (&Method::PUT, "/model-policy") => ModelPolicySet,
            _ => return None,
        };
        let tenant = request
            .uri()
            .path()
            .strip_prefix("/admin/v1/tenants/")?
            .split('/')
            .next()?;
        if !crate::tenant_store::operator_audit::canonical_scope(tenant) {
            return None;
        }
        Some(Self {
            tenant: tenant.to_owned(),
            operation,
        })
    }

    pub(crate) async fn record(&self, state: &Shared, actor: &OperatorContext, status: StatusCode) {
        let outcome = match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => AuditOutcome::Denied,
            s if s.is_client_error() || s.is_server_error() => AuditOutcome::Failed,
            _ => return,
        };
        record_attempt(state, &self.tenant, actor, self.operation, outcome).await;
    }
}

pub(crate) async fn record_attempt(
    state: &Shared,
    tenant: &str,
    actor: &OperatorContext,
    operation: AuditOperation,
    outcome: AuditOutcome,
) {
    if let Some(store) = &state.tenant_store {
        if store
            .record_operator_attempt(tenant, actor, operation, outcome)
            .await
            .is_err()
        {
            // Keep the original refusal. No mutation was allowed by this path.
            tracing::warn!("Console operator attempt audit could not be persisted");
        }
    }
}

pub(crate) async fn history(
    State(state): State<Shared>,
    Path(tenant): Path<String>,
    Query(query): Query<OperatorAuditQuery>,
) -> Response {
    let Ok((before, limit)) = query.bounds(&tenant) else {
        return error(StatusCode::BAD_REQUEST, "Invalid operator audit page");
    };
    let Some(store) = &state.tenant_store else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Operator audit unavailable",
        );
    };
    match store.operator_audit_page(&tenant, before, limit).await {
        Ok(page) => {
            let mut response = ([(header::CACHE_CONTROL, "no-store")], Json(page)).into_response();
            if query.download {
                response.headers_mut().insert(
                    header::CONTENT_DISPOSITION,
                    axum::http::HeaderValue::from_static(
                        "attachment; filename=operator-audit.json",
                    ),
                );
            }
            response
        }
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Operator audit unavailable",
        ),
    }
}

fn error(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({"error": {"message": message}})),
    )
        .into_response()
}
