// SPDX-License-Identifier: Apache-2.0
//! Completion of the selected collectors' existing crash owners. Retirement of
//! native authority alone is never evidence that a namespace was terminated.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;

use super::{failure, validate_lineage, wall_time_ms};
use crate::handlers::Shared;

pub const ENDPOINT: &str = "/native/pilot-cleanup/v1";
pub const CONTRACT: &str = "sw-native-pilot-cleanup/1";

pub(crate) struct Record {
    session: String,
    epoch: String,
    owner: String,
    pub(crate) host_session: String,
    pub(crate) server_id: String,
    pub(crate) verified: bool,
    expires_at_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    contract_version: String,
    instance_id: String,
    registry_sha256: String,
    session_id: String,
    epoch: String,
    owner_token: String,
    action: String,
}

pub async fn handler(
    State(st): State<Shared>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<Value>) {
    let Some(native) = &st.native else {
        return failure("native_not_configured", StatusCode::NOT_FOUND);
    };
    if !crate::token::verify(
        &native.token,
        headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .unwrap_or(""),
    ) {
        return failure("native_unauthorized", StatusCode::UNAUTHORIZED);
    }
    let request: Request = match serde_json::from_str(&body) {
        Ok(value) if body.len() <= 4096 => value,
        _ => return failure("pilot_cleanup_invalid_request", StatusCode::BAD_REQUEST),
    };
    if !st.config.enforce || st.config.judge.enabled {
        return failure(
            "native_enforcement_required",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    if request.contract_version != CONTRACT
        || request.instance_id != native.instance_id()
        || request.registry_sha256 != native.registry_sha256
    {
        return failure("pilot_cleanup_instance_mismatch", StatusCode::CONFLICT);
    }
    let now = match wall_time_ms() {
        Ok(now) => now.saturating_add(native.test_time_offset()),
        Err(code) => return failure(code, StatusCode::SERVICE_UNAVAILABLE),
    };
    let Ok(mut sessions) = native.sessions.lock() else {
        return failure("native_state_unavailable", StatusCode::SERVICE_UNAVAILABLE);
    };
    if request.action == "begin" {
        let Some(session) = sessions.entries.get(&request.session_id) else {
            return failure("pilot_cleanup_owner_unknown", StatusCode::CONFLICT);
        };
        if !owner_matches(&request, &session.epoch, &session.owner_token)
            || session.liveness_lease.is_none()
            || validate_lineage(&sessions, session, now, native.monotonic_now()).is_err()
        {
            return failure("pilot_cleanup_owner_invalid", StatusCode::FORBIDDEN);
        }
        let (Some(authority), Some(host), Some(server), Some(expires)) = (
            session.authority_digest.as_ref(),
            session.host_session.as_ref(),
            session.server_id.as_ref(),
            session.authority_expires_at_ms,
        ) else {
            return failure("pilot_cleanup_binding_required", StatusCode::FORBIDDEN);
        };
        if !matches!(server.as_str(), "filesystem" | "git") {
            return failure("pilot_cleanup_binding_required", StatusCode::FORBIDDEN);
        }
        let authority = authority.clone();
        let record = Record {
            session: request.session_id.clone(),
            epoch: session.epoch.clone(),
            owner: session.owner_token.clone(),
            host_session: host.clone(),
            server_id: server.clone(),
            verified: false,
            expires_at_ms: expires,
        };
        sessions
            .pilot_cleanup
            .retain(|_, row| !row.verified || row.expires_at_ms > now);
        if let Some(previous) = sessions.pilot_cleanup.get(&authority) {
            if previous.session != request.session_id
                || !owner_matches(&request, &previous.epoch, &previous.owner)
                || previous.verified
            {
                return failure("pilot_cleanup_duplicate_owner", StatusCode::CONFLICT);
            }
        } else {
            if sessions.pilot_cleanup.len() >= super::MAX_SPENT_AUTHORITIES {
                return failure("pilot_cleanup_capacity", StatusCode::SERVICE_UNAVAILABLE);
            }
            sessions.pilot_cleanup.insert(authority, record);
        }
    } else if request.action == "finish" {
        // Revocation deliberately removes the live session. This one-purpose
        // retained capability can acknowledge cleanup, never admit a call.
        let Some(record) = sessions
            .pilot_cleanup
            .values_mut()
            .find(|record| record.session == request.session_id && record.epoch == request.epoch)
        else {
            return failure("pilot_cleanup_owner_unknown", StatusCode::CONFLICT);
        };
        if !owner_matches(&request, &record.epoch, &record.owner) {
            return failure("pilot_cleanup_owner_invalid", StatusCode::FORBIDDEN);
        }
        record.verified = true;
    } else {
        return failure("pilot_cleanup_invalid_action", StatusCode::BAD_REQUEST);
    }
    (
        StatusCode::OK,
        Json(json!({"contract_version":CONTRACT,
        "instance_id":request.instance_id,"session_id":request.session_id,
        "epoch":request.epoch,"status":if request.action == "begin" {"registered"} else {"verified"}})),
    )
}

fn owner_matches(request: &Request, epoch: &str, owner: &str) -> bool {
    request.epoch == epoch && bool::from(request.owner_token.as_bytes().ct_eq(owner.as_bytes()))
}
