// SPDX-License-Identifier: Apache-2.0
//! Additive read-only fleet routes behind existing control-plane role checks.
use axum::{extract::{Path, Query, State}, http::{header, StatusCode}, response::{IntoResponse, Response}, Json};
use crate::{handlers::Shared, tenant_store::fleet::FleetQuery};
fn error(code:StatusCode,message:&'static str) -> Response {
    (code, [(header::CACHE_CONTROL,"no-store")], Json(serde_json::json!({"error":{"message":message}}))).into_response()
}
fn result<T:serde::Serialize>(value:anyhow::Result<Option<T>>) -> Response {
    match value {
        Ok(Some(value)) => ([(header::CACHE_CONTROL,"no-store")],Json(value)).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND,"Tenant or Agent not found"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE,"Fleet records unavailable"),
    }
}
pub async fn inventory(State(st):State<Shared>, Path(tenant):Path<String>, Query(q):Query<FleetQuery>) -> Response {
    if q.validate(&tenant,None).is_err() { return error(StatusCode::BAD_REQUEST,"Invalid fleet query"); }
    let Some(store)=&st.tenant_store else { return error(StatusCode::SERVICE_UNAVAILABLE,"Fleet records unavailable"); };
    result(store.fleet_page(&tenant,q).await)
}
pub async fn detail(State(st):State<Shared>, Path((tenant,agent)):Path<(String,String)>, Query(q):Query<FleetQuery>) -> Response {
    if q.validate(&tenant,Some(&agent)).is_err() { return error(StatusCode::BAD_REQUEST,"Invalid fleet query"); }
    let Some(store)=&st.tenant_store else { return error(StatusCode::SERVICE_UNAVAILABLE,"Fleet records unavailable"); };
    result(store.fleet_detail(&tenant,&agent,q).await)
}
