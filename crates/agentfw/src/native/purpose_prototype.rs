// SPDX-License-Identifier: Apache-2.0
//! Test-build-only contract prototype, NOT an authenticated operator endpoint.
//! The production binary has neither this issuer nor these routing guards.
//! Never lowers findings, delivers result text, or grants any action.
use super::*;

/// Affine control-side intent. No Clone, Serialize, Deserialize or wire parser.
/// The fixture issuer stands in for a missing reviewed operator-purpose API.
pub(super) struct Purpose {
    instance: String,
    session: String,
    epoch: String,
    host: String,
    grant: String,
    call: String,
    binding: String,
    receipt: String,
    expires: Instant,
}

impl Purpose {
    pub(super) fn arm_fixture(
        native: &NativeState,
        session_id: &str,
        source: &execution::OriginalResult,
    ) -> Result<Self, &'static str> {
        let state = native.sessions.lock().map_err(|_| "purpose_state")?;
        let session = state.entries.get(session_id).ok_or("purpose_session")?;
        let receipt = source.metadata();
        let call = session
            .calls
            .get(&receipt.native_call_id)
            .ok_or("purpose_call")?;
        let grant = session
            .authority_digest
            .clone()
            .ok_or("purpose_grant_required")?;
        let host = session
            .host_session
            .clone()
            .ok_or("purpose_host_required")?;
        if session.terminal
            || call.expires <= Instant::now()
            || state.analysis_hosts.contains(&host)
        {
            return Err("purpose_inactive");
        }
        Ok(Self {
            instance: native.instance_id.clone(),
            session: session_id.into(),
            epoch: session.epoch.clone(),
            host,
            grant,
            call: receipt.native_call_id.clone(),
            binding: call.binding_sha256.clone(),
            receipt: canonical_digest(&serde_json::to_value(receipt).expect("receipt")),
            expires: call.expires,
        })
    }

    /// Exercise the existing private consume validator and call-spending ledger.
    /// No parsed/copied receipt can enter this function as an OriginalResult.
    pub(super) fn consume_fixture(
        self,
        native: &NativeState,
        request: &Request,
        source: execution::OriginalResult,
    ) -> Result<(), &'static str> {
        let mut state = native.sessions.lock().map_err(|_| "purpose_state")?;
        let session = state
            .entries
            .get_mut(&self.session)
            .ok_or("purpose_session")?;
        // Spend before validating: any attempted substitution destroys the grant.
        let call = session.calls.remove(&self.call).ok_or("purpose_spent")?;
        if self.instance != native.instance_id
            || request.session_id != self.session
            || self.epoch != session.epoch
            || session.authority_digest.as_ref() != Some(&self.grant)
            || session.host_session.as_ref() != Some(&self.host)
            || session.terminal
            || self.expires != call.expires
            || Instant::now() >= self.expires
            || self.binding != call.binding_sha256
        {
            return Err("purpose_binding");
        }
        let consumed = source.consume(native, session, request, &call, Instant::now())?;
        let receipt =
            canonical_digest(&serde_json::to_value(consumed.metadata()).expect("receipt"));
        if receipt != self.receipt {
            return Err("purpose_receipt");
        }
        if state.analysis_hosts.len() >= MAX_SESSIONS && !state.analysis_hosts.contains(&self.host)
        {
            return Err("purpose_capacity");
        }
        // Sticky whole-host restriction. Expiry/end/re-registration cannot restore
        // old capabilities. All parent/sibling/child pending calls are withdrawn.
        state.analysis_hosts.insert(self.host.clone());
        for sibling in state
            .entries
            .values_mut()
            .filter(|s| s.host_session.as_ref() == Some(&self.host))
        {
            sibling.calls.clear();
            sibling.granted_tools.clear();
            sibling.granted_resources = Some(Vec::new());
        }
        Ok(())
    }
}

pub(super) fn guard(state: &Sessions, request: &Request) -> Result<(), &'static str> {
    let existing_host = state
        .entries
        .get(&request.session_id)
        .and_then(|s| s.host_session.as_ref());
    if existing_host
        .into_iter()
        .chain(request.host_session.as_ref())
        .any(|host| state.analysis_hosts.contains(host))
        && request.event != "session_end"
    {
        return Err("analysis_purpose_effects_withheld");
    }
    Ok(())
}
