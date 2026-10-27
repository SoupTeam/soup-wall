// SPDX-License-Identifier: Apache-2.0
//! Trusted run operator revocation. A run ID alone conveys no authority.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::{failure, identifier, is_digest, retire_sessions_terminal, wall_time_ms};
use crate::handlers::Shared;

pub const ENDPOINT: &str = "/native/pilot-stop/v1";
pub const CONTRACT: &str = "sw-native-pilot-stop/1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub contract_version: String,
    pub instance_id: String,
    pub registry_sha256: String,
    pub host_session: String,
    #[serde(deserialize_with = "authorities")]
    pub authorities: BTreeMap<String, String>,
    pub expires_at_ms: u64,
}

fn authorities<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Pair {
        filesystem: String,
        git: String,
    }
    let pair = Pair::deserialize(deserializer)?;
    Ok(BTreeMap::from([
        ("filesystem".into(), pair.filesystem),
        ("git".into(), pair.git),
    ]))
}

pub async fn handler(
    State(st): State<Shared>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<Value>) {
    let Some(native) = &st.native else {
        return failure("native_not_configured", StatusCode::NOT_FOUND);
    };
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&native.token, auth) {
        return failure("native_unauthorized", StatusCode::UNAUTHORIZED);
    }
    if !st.config.enforce || st.config.judge.enabled {
        return failure(
            "native_enforcement_required",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    let request: Request = match serde_json::from_str(&body) {
        Ok(request) if body.len() <= 4096 => request,
        _ => return failure("pilot_stop_invalid_request", StatusCode::BAD_REQUEST),
    };
    if request.contract_version != CONTRACT
        || !identifier(&request.host_session)
        || request.authorities.len() != 2
        || !request.authorities.contains_key("filesystem")
        || !request.authorities.contains_key("git")
        || !request.authorities.values().all(|v| is_digest(v))
        || request.authorities["filesystem"] == request.authorities["git"]
    {
        return failure("pilot_stop_invalid_request", StatusCode::BAD_REQUEST);
    }
    if request.instance_id != native.instance_id()
        || request.registry_sha256 != native.registry_sha256
    {
        return failure("pilot_stop_instance_mismatch", StatusCode::CONFLICT);
    }
    let now = match wall_time_ms() {
        Ok(now) => now,
        Err(code) => return failure(code, StatusCode::SERVICE_UNAVAILABLE),
    };
    // Includes the launcher's existing extra minute of authority grace, without extending it.
    if request.expires_at_ms == 0 || request.expires_at_ms.saturating_sub(now) > 3_660_000 {
        return failure("pilot_stop_expiry_invalid", StatusCode::BAD_REQUEST);
    }
    let targets = {
        let Ok(mut sessions) = native.sessions.lock() else {
            return failure("native_state_unavailable", StatusCode::SERVICE_UNAVAILABLE);
        };
        sessions.spent_authorities.retain(|_, exp| *exp > now);
        if !sessions.scoped_hosts.contains(&request.host_session)
            && sessions.scoped_hosts.len() >= super::MAX_SESSIONS
        {
            return failure("native_host_binding_cap", StatusCode::SERVICE_UNAVAILABLE);
        }
        let mut targets = Vec::new();
        for (id, session) in &sessions.entries {
            if session
                .authority_digest
                .as_ref()
                .is_some_and(|digest| request.authorities.values().any(|v| v == digest))
            {
                if session.host_session.as_deref() != Some(&request.host_session)
                    || !session.server_id.as_ref().is_some_and(|server| {
                        request.authorities.get(server) == session.authority_digest.as_ref()
                    })
                {
                    return failure("pilot_stop_foreign_authority", StatusCode::FORBIDDEN);
                }
                if session
                    .authority_expires_at_ms
                    .is_some_and(|expiry| expiry > request.expires_at_ms)
                {
                    return failure("pilot_stop_expiry_invalid", StatusCode::BAD_REQUEST);
                }
                targets.push((id.clone(), Some(session.epoch.clone())));
            }
        }
        let ledger: BTreeSet<_> = sessions
            .spent_authorities
            .keys()
            .chain(
                sessions
                    .entries
                    .values()
                    .filter_map(|s| s.authority_digest.as_ref()),
            )
            .chain(request.authorities.values())
            .collect();
        if ledger.len() > super::MAX_SPENT_AUTHORITIES {
            return failure(
                "native_authority_ledger_saturated",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }
        // Never permit an as-yet unconnected signed host to fall back to unsigned hooks.
        sessions.scoped_hosts.insert(request.host_session.clone());
        // The same lock gates new sessions and all current lineage checks. From
        // here onward, even a not-yet-enrolled collector cannot use either grant.
        for digest in request.authorities.values() {
            let expiry = sessions
                .spent_authorities
                .entry(digest.clone())
                .or_default();
            *expiry = (*expiry).max(request.expires_at_ms);
        }
        targets
    };
    let retired = retire_sessions_terminal(&st, native, &targets, "revoked");
    let audited = st
        .audit
        .write_native(&json!({
            "event":"pilot_run_authority_revoked", "at_ms":now,
            "instance_id":request.instance_id, "host_session":request.host_session,
            "registry_sha256":request.registry_sha256, "retired_sessions":retired,
            "released":false, "running_effects_rolled_back":false,
        }))
        .is_ok();
    let Ok(sessions) = native.sessions.lock() else {
        return failure(
            "pilot_stop_cleanup_incomplete",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    let pending_closed = native
        .approval
        .as_ref()
        .map(|approval| approval.operator_bindings())
        .transpose()
        .map(|bindings| {
            !bindings
                .unwrap_or_default()
                .iter()
                .any(|record| targets.iter().any(|(id, _)| record["session_id"] == *id))
        })
        .unwrap_or(false);
    if !audited
        || !pending_closed
        || sessions.entries.values().any(|s| {
            s.authority_digest
                .as_ref()
                .is_some_and(|digest| request.authorities.values().any(|v| v == digest))
        })
    {
        return failure(
            "pilot_stop_cleanup_incomplete",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "contract_version":CONTRACT, "instance_id":request.instance_id,
            "host_session":request.host_session, "status":"revoked",
            "retired_sessions":retired, "running_effects_rolled_back":false,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicated_authorities_and_unknown_privilege_fields_refuse() {
        let valid = serde_json::to_string(&Request {
            contract_version: CONTRACT.into(),
            instance_id: "owned".into(),
            registry_sha256: "a".repeat(64),
            host_session: "owned-host".into(),
            authorities: BTreeMap::from([
                ("filesystem".into(), "b".repeat(64)),
                ("git".into(), "c".repeat(64)),
            ]),
            expires_at_ms: 1,
        })
        .unwrap();
        assert!(serde_json::from_str::<Request>(&valid).is_ok());
        let duplicated = valid.replace(
            "\"filesystem\":",
            "\"filesystem\":\"forged\",\"filesystem\":",
        );
        assert!(serde_json::from_str::<Request>(&duplicated).is_err());
        let unknown = valid.replacen('{', "{\"all_runs\":true,", 1);
        assert!(serde_json::from_str::<Request>(&unknown).is_err());
    }
}
