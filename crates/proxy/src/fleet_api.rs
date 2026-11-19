// SPDX-License-Identifier: Apache-2.0
//! Additive read-only fleet routes behind existing control-plane role checks.
use crate::{
    handlers::Shared,
    tenant_store::{fleet::FleetQuery, fleet_triage::TriageQuery},
};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
fn error(code: StatusCode, message: &'static str) -> Response {
    (
        code,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({"error":{"message":message}})),
    )
        .into_response()
}
fn result<T: serde::Serialize>(value: anyhow::Result<Option<T>>) -> Response {
    match value {
        Ok(Some(value)) => ([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "Tenant or Agent not found"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "Fleet records unavailable"),
    }
}
pub async fn inventory(
    State(st): State<Shared>,
    Path(tenant): Path<String>,
    Query(q): Query<FleetQuery>,
) -> Response {
    if q.validate(&tenant, None).is_err() {
        return error(StatusCode::BAD_REQUEST, "Invalid fleet query");
    }
    let Some(store) = &st.tenant_store else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "Fleet records unavailable");
    };
    result(store.fleet_page(&tenant, q).await)
}
pub async fn detail(
    State(st): State<Shared>,
    Path((tenant, agent)): Path<(String, String)>,
    Query(q): Query<FleetQuery>,
) -> Response {
    if q.validate(&tenant, Some(&agent)).is_err() {
        return error(StatusCode::BAD_REQUEST, "Invalid fleet query");
    }
    let Some(store) = &st.tenant_store else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "Fleet records unavailable");
    };
    result(store.fleet_detail(&tenant, &agent, q).await)
}
/// Reuse the tenant-scoped detail projection with a query selector so that
/// valid dot Agent IDs are not normalized by a browser or reverse proxy.
pub async fn selected_detail(
    State(st): State<Shared>,
    Path(tenant): Path<String>,
    Query(selected): Query<crate::managed_agent_api::SelectedAgent>,
) -> Response {
    detail(
        State(st),
        Path((tenant, selected.agent_id)),
        Query(FleetQuery {
            limit: 1,
            ..FleetQuery::default()
        }),
    )
    .await
}

/// Cross-Agent triage overview: recorded problems, bounded counts and one
/// keyset page. Same read authorization as the fleet inventory.
pub async fn triage(
    State(st): State<Shared>,
    Path(tenant): Path<String>,
    Query(q): Query<TriageQuery>,
) -> Response {
    if q.validate(&tenant).is_err() {
        return error(StatusCode::BAD_REQUEST, "Invalid triage query");
    }
    let Some(store) = &st.tenant_store else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "Fleet records unavailable");
    };
    result(store.fleet_triage(&tenant, q).await)
}
