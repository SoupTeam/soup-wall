// SPDX-License-Identifier: Apache-2.0

//! Fail-closed SAML 2.0 service-provider flow.
//!
//! The owner stores a signed IdP metadata document and its pinned signing
//! certificate. Every login reparses and verifies that metadata, creates a
//! short-lived opaque RelayState, and persists the pending request only by a
//! one-way hash. No SAML claim can grant a workspace role: the verified
//! `(issuer, NameID)` pair must already have an active local membership.

use std::collections::BTreeMap;
use std::env;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequestSigningPolicy,
    BrowserInput, CertificatePem, ClockSkew, Credentials, EntityId, FormField, IdpDescriptor,
    MetadataTrustPolicy, PendingAuthnRequest, PendingSnapshot, PrivateKeyPem, RelayStateParam,
    ReplayCache, ReplayKey, ReplayPolicy, Saml, SamlError, SamlValidationContext, SpConfig,
    SpValidationPolicy, SsoResponse, SsoResponseBinding, StartSso, XmlEncryptionPolicy, XmlPolicy,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::handlers::Shared;
use crate::oidc::OidcStateCipher;
use crate::tenant_store::{
    BrowserSessionFederation, OrganizationSamlConnection, SamlAuthorizationPending, TenantStore,
};

pub const SAML_ACS_PATH: &str = "/auth/saml/acs";
const SAML_STATE_TTL_SECONDS: i64 = 10 * 60;
const MAX_FORM_FIELDS: usize = 64;
const MAX_FORM_FIELD_BYTES: usize = 2 * 1024 * 1024;
const FLOW_COOKIE_NAME: &str = "__Host-llm-fw-saml-flow";

fn sp_validation_policy() -> SpValidationPolicy {
    // Preserve the former strict preset's named requirements across upgrades.
    SpValidationPolicy {
        assertions: AssertionSignaturePolicy::RequireSigned,
        authn_requests: AuthnRequestSigningPolicy::Sign,
        audience: AudienceValidationPolicy::Validate,
        ..SpValidationPolicy::recommended()
    }
}

fn validation_context(now: SystemTime, replay: ReplayPolicy<'_>) -> SamlValidationContext<'_> {
    // saml-rs 0.6 defaults to five minutes of tolerance. Console assertions
    // retain their original exact NotBefore/NotOnOrAfter boundary.
    SamlValidationContext::new(now, replay)
        .with_clock_skew(ClockSkew::strict())
        .with_replay_retention(Duration::from_secs(SAML_STATE_TTL_SECONDS as u64))
}

// SAML uses a cross-site POST, so Lax would discard the correlation cookie.
// This cookie grants no access; the opaque session keeps its existing Lax policy.
fn flow_cookie(relay: &str) -> HeaderValue {
    let binding = URL_SAFE_NO_PAD.encode(Sha256::digest(relay.as_bytes()));
    HeaderValue::from_str(&format!(
        "{FLOW_COOKIE_NAME}={binding}; Path=/; Max-Age={SAML_STATE_TTL_SECONDS}; Secure; HttpOnly; SameSite=None"
    )).expect("digest is a valid cookie value")
}

fn browser_matches(headers: &HeaderMap, relay: &str) -> bool {
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(relay.as_bytes()));
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        let Ok(value) = header.to_str() else {
            return false;
        };
        for part in value.split(';') {
            if let Some((name, value)) = part.trim().split_once('=') {
                if name == FLOW_COOKIE_NAME {
                    if found.is_some() {
                        return false;
                    }
                    found = Some(value);
                }
            }
        }
    }
    found.is_some_and(|value| bool::from(value.as_bytes().ct_eq(expected.as_bytes())))
}

fn login_redirect(url: String, relay: String) -> Response {
    let mut response = Redirect::to(&url).into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, flow_cookie(&relay));
    response
}

/// Secret-bearing local SP configuration. Values are loaded from the process
/// environment only and deliberately do not implement `Serialize`.
#[derive(Clone)]
pub struct SamlRuntimeConfig {
    pub(crate) sp_entity_id: String,
    pub(crate) acs_url: String,
    pub(crate) sp_private_key_pem: String,
    pub(crate) sp_certificate_pem: String,
}

impl SamlRuntimeConfig {
    /// Load all SAML SP settings, or disable SAML when all are absent. Partial
    /// configuration is an operator error and never falls back to unsigned or
    /// locally generated credentials.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let names = [
            "LLM_FW_SAML_SP_ENTITY_ID",
            "LLM_FW_SAML_ACS_URL",
            "LLM_FW_SAML_SP_PRIVATE_KEY_PEM",
            "LLM_FW_SAML_SP_CERTIFICATE_PEM",
        ];
        let values = names.map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()));
        Self::from_optional_values(values)
    }

    fn from_optional_values(values: [Option<String>; 4]) -> anyhow::Result<Option<Self>> {
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        if values.iter().any(Option::is_none) {
            anyhow::bail!(
                "SAML SP configuration requires all four LLM_FW_SAML_* environment variables"
            );
        }
        let entity_id = values[0].as_ref().expect("checked above").trim().to_owned();
        let acs_url = values[1].as_ref().expect("checked above").trim().to_owned();
        let sp_private_key_pem = values[2].as_ref().expect("checked above").to_owned();
        let sp_certificate_pem = values[3].as_ref().expect("checked above").to_owned();
        EntityId::try_new(entity_id.clone())
            .map_err(|_| anyhow::anyhow!("SAML SP entity ID is invalid"))?;
        let url = reqwest::Url::parse(&acs_url)
            .map_err(|_| anyhow::anyhow!("SAML ACS URL is invalid"))?;
        if url.scheme() != "https"
            || url.query().is_some()
            || url.fragment().is_some()
            || url.username() != ""
        {
            anyhow::bail!(
                "SAML ACS URL must be an HTTPS URL without credentials, query, or fragment"
            );
        }
        if url.path() != SAML_ACS_PATH {
            anyhow::bail!("SAML ACS URL must use the fixed /auth/saml/acs path");
        }
        if sp_private_key_pem.len() > 32 * 1024 || sp_certificate_pem.len() > 32 * 1024 {
            anyhow::bail!("SAML SP key and certificate are too large");
        }
        if !sp_private_key_pem.contains("-----BEGIN")
            || !sp_certificate_pem.contains("-----BEGIN CERTIFICATE-----")
        {
            anyhow::bail!("SAML SP credentials must be PEM encoded");
        }
        Ok(Some(Self {
            sp_entity_id: entity_id,
            acs_url,
            sp_private_key_pem,
            sp_certificate_pem,
        }))
    }

    fn sp(&self) -> anyhow::Result<Saml<saml_rs::Sp>> {
        Ok(Saml::sp(self.sp_config()?)?)
    }

    fn sp_config(&self) -> anyhow::Result<SpConfig> {
        // Do not configure a decryption key or encrypted assertions. This
        // deliberately rejects encrypted inbound assertions on every provider.
        // Provider selection does not approve encrypted-assertion support;
        // that requires a separate threat review and interoperability evidence.
        let xml = XmlPolicy {
            encryption: XmlEncryptionPolicy::default(),
            ..XmlPolicy::default()
        };
        Ok(
            SpConfig::builder(EntityId::try_new(self.sp_entity_id.clone())?)
                .acs_endpoint(AcsEndpoint::post(self.acs_url.clone())?)
                .credentials(Credentials {
                    signing_key: Some(PrivateKeyPem::new(self.sp_private_key_pem.clone())),
                    signing_certificate: Some(CertificatePem::new(self.sp_certificate_pem.clone())),
                    ..Credentials::default()
                })
                .validation(sp_validation_policy())
                .xml(xml)
                .build()?,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartSamlLoginQuery {
    pub organization_id: String,
    pub workspace_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationStartForm {
    pub token: String,
}

/// Start an SP-initiated SAML login for an explicitly selected workspace.
pub async fn start_login(
    State(state): State<Shared>,
    Query(query): Query<StartSamlLoginQuery>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(runtime) = state.saml.as_ref() else {
        return unavailable();
    };
    match store
        .active_workspace_in_organization_async(&query.organization_id, &query.workspace_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => return unavailable(),
        Err(error) => {
            tracing::error!(error = %error, "failed to verify SAML workspace");
            return unavailable();
        }
    }
    let connection = match store
        .organization_saml_connection_async(&query.organization_id)
        .await
    {
        Ok(Some(connection)) if connection.active => connection,
        Ok(_) => return unavailable(),
        Err(error) => {
            tracing::error!(error = %error, "failed to load SAML connection");
            return unavailable();
        }
    };
    match start_login_inner(
        store,
        cipher,
        runtime,
        connection,
        &query.workspace_id,
        None,
    )
    .await
    {
        Ok((url, relay)) => login_redirect(url, relay),
        Err(error) => {
            tracing::warn!(error = %error, "SAML login start failed");
            login_failed()
        }
    }
}

/// Begin SAML enrollment from a raw invitation bearer posted by the same-origin
/// acceptance page. The token selects the organization and workspace; no
/// browser-supplied routing values are trusted.
pub async fn start_invitation_login(
    State(state): State<Shared>,
    Form(form): Form<InvitationStartForm>,
) -> Response {
    if form.token.len() > 256 || !form.token.starts_with("llmfw_invite_") {
        return login_failed();
    }
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(runtime) = state.saml.as_ref() else {
        return unavailable();
    };
    let invitation = match store
        .workspace_invitation_for_federation_token_async(
            &form.token,
            BrowserSessionFederation::Saml,
        )
        .await
    {
        Ok(Some(invitation)) => invitation,
        Ok(None) => return login_failed(),
        Err(error) => {
            tracing::error!(error = %error, "failed to resolve SAML workspace invitation");
            return unavailable();
        }
    };
    let connection = match store
        .organization_saml_connection_async(&invitation.organization_id)
        .await
    {
        Ok(Some(connection)) if connection.active => connection,
        Ok(_) => return unavailable(),
        Err(error) => {
            tracing::error!(error = %error, "failed to load SAML invitation connection");
            return unavailable();
        }
    };
    match start_login_inner(
        store,
        cipher,
        runtime,
        connection,
        &invitation.workspace_id,
        Some(&invitation.id),
    )
    .await
    {
        Ok((url, relay)) => login_redirect(url, relay),
        Err(error) => {
            tracing::warn!(error = %error, "SAML invitation login start failed");
            login_failed()
        }
    }
}

async fn start_login_inner(
    store: &TenantStore,
    cipher: &OidcStateCipher,
    runtime: &SamlRuntimeConfig,
    connection: OrganizationSamlConnection,
    workspace_id: &str,
    invitation_id: Option<&str>,
) -> anyhow::Result<(String, String)> {
    let sp = runtime.sp()?;
    let idp = idp_descriptor(&connection)?;
    let expires_at_unix = now_unix()?
        .checked_add(SAML_STATE_TTL_SECONDS)
        .ok_or_else(|| anyhow::anyhow!("SAML state expiry overflow"))?;
    // The sealed value is RelayState. Pending AuthnRequest details are stored
    // durably after the library creates the request ID, avoiding a circular
    // dependency between the request ID and the browser correlation value.
    let state_value = cipher.seal_saml_relay_state()?;
    let relay = RelayStateParam::try_from_option(Some(state_value.clone()))?;
    let started = sp.start_sso(
        &idp,
        StartSso::redirect()
            .response_binding(SsoResponseBinding::Post)
            .relay_state(relay),
    )?;
    let snapshot = started.pending.snapshot();
    let pending = SamlAuthorizationPending {
        organization_id: connection.organization_id.clone(),
        workspace_id: workspace_id.to_owned(),
        invitation_id: invitation_id.map(str::to_owned),
        request_id: snapshot.id,
        idp_entity_id: snapshot.peer_entity_id,
        expected_binding: snapshot.expected_binding,
        request_binding: snapshot
            .request_binding
            .unwrap_or_else(|| "redirect".to_owned()),
        acs_url: snapshot.acs_url,
        acs_binding: snapshot.acs_binding,
    };
    store
        .reserve_saml_authorization_state_async(&state_value, &pending, expires_at_unix)
        .await?;
    Ok((started.outbound.redirect_url()?.to_owned(), state_value))
}

#[derive(Deserialize)]
pub struct SamlAcsForm(pub Vec<(String, String)>);

/// Consume and validate a SAML HTTP-POST response. Duplicate RelayState or
/// SAMLResponse fields are rejected to avoid parser differentials.
pub async fn acs(
    State(state): State<Shared>,
    headers: HeaderMap,
    Form(fields): Form<Vec<(String, String)>>,
) -> Response {
    let Some(store) = state.tenant_store.as_ref() else {
        return unavailable();
    };
    let Some(cipher) = state.oidc_state_cipher.as_ref() else {
        return unavailable();
    };
    let Some(runtime) = state.saml.as_ref() else {
        return unavailable();
    };
    if fields.len() > MAX_FORM_FIELDS
        || fields
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>()
            > MAX_FORM_FIELD_BYTES
    {
        return login_failed();
    }
    let relay_states = fields.iter().filter(|(key, _)| key == "RelayState").count();
    let responses = fields
        .iter()
        .filter(|(key, _)| key == "SAMLResponse")
        .count();
    if relay_states != 1 || responses != 1 {
        return login_failed();
    }
    let state_value = fields
        .iter()
        .find_map(|(key, value)| (key == "RelayState").then_some(value.clone()))
        .unwrap_or_default();
    if !browser_matches(&headers, &state_value)
        || cipher.open_saml_relay_state(&state_value).is_err()
    {
        return login_failed();
    }
    let pending = match store
        .consume_saml_authorization_state_async(&state_value)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(error = %error, "failed to consume SAML state");
            return unavailable();
        }
    };
    let Some(pending) = pending else {
        return login_failed();
    };
    let organization_id = pending.organization_id.clone();
    let workspace_id = pending.workspace_id.clone();
    let invitation_id = pending.invitation_id.clone();
    let connection = match store
        .organization_saml_connection_async(&pending.organization_id)
        .await
    {
        Ok(Some(connection)) if connection.active => connection,
        Ok(_) => return login_failed(),
        Err(error) => {
            tracing::error!(error = %error, "failed to load SAML connection");
            return unavailable();
        }
    };
    let result = finish_sso(runtime, connection, pending, &state_value, fields);
    let session = match result {
        Ok(session) => session,
        Err(error) => {
            tracing::warn!(error = %error, "SAML response validation failed");
            return login_failed();
        }
    };
    let issuer = session.issuer().as_str();
    let subject = session.name_id().value();
    let access_result = match invitation_id.as_deref() {
        Some(invitation_id) => {
            store
                .accept_workspace_invitation_async(
                    invitation_id,
                    &organization_id,
                    &workspace_id,
                    issuer,
                    subject,
                    BrowserSessionFederation::Saml,
                )
                .await
        }
        None => {
            store
                .verified_saml_identity_workspace_access_async(
                    &organization_id,
                    &workspace_id,
                    issuer,
                    subject,
                )
                .await
        }
    };
    let access = match access_result {
        Ok(Some(access)) => access,
        Ok(None) => return login_failed(),
        Err(error) => {
            tracing::error!(error = %error, "failed to authorize SAML identity");
            return unavailable();
        }
    };
    let expires_at = match now_unix().and_then(|now| {
        now.checked_add(8 * 60 * 60)
            .ok_or_else(|| anyhow::anyhow!("session expiry overflow"))
    }) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(error = %error, "failed to create SAML session expiry");
            return unavailable();
        }
    };
    let session = match store
        .issue_oidc_browser_session_async(&access, BrowserSessionFederation::Saml, expires_at)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(error = %error, "failed to issue SAML browser session");
            return unavailable();
        }
    };
    let cookie = match crate::oidc_auth::session_cookie(&session.token, 8 * 60 * 60) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(error = %error, "failed to create SAML session cookie");
            return unavailable();
        }
    };
    let mut response = Redirect::to("/customer").into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

fn finish_sso(
    runtime: &SamlRuntimeConfig,
    connection: OrganizationSamlConnection,
    pending: SamlAuthorizationPending,
    state_value: &str,
    fields: Vec<(String, String)>,
) -> anyhow::Result<saml_rs::SsoSession> {
    let prepared = PreparedSso::new(runtime, connection, pending, state_value, fields)?;
    let mut replay = replay_cache()
        .lock()
        .expect("SAML replay cache mutex poisoned");
    let validation =
        validation_context(SystemTime::now(), ReplayPolicy::RequireCache(&mut *replay));
    prepared.finish(validation)
}

struct PreparedSso {
    sp: Saml<saml_rs::Sp>,
    idp: IdpDescriptor,
    pending: PendingAuthnRequest,
    fields: Vec<FormField>,
}

impl PreparedSso {
    fn new(
        runtime: &SamlRuntimeConfig,
        connection: OrganizationSamlConnection,
        pending: SamlAuthorizationPending,
        state_value: &str,
        fields: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        let sp = runtime.sp()?;
        let idp = idp_descriptor(&connection)?;
        let relay = RelayStateParam::try_from_option(Some(state_value.to_owned()))?;
        let snapshot = PendingSnapshot::<saml_rs::AuthnRequest>::authn_request(
            pending.request_id,
            relay,
            pending.idp_entity_id,
            pending.expected_binding,
            pending.acs_url,
            pending.acs_binding,
        );
        let pending = PendingAuthnRequest::from_snapshot(snapshot)?;
        let fields = fields
            .into_iter()
            .map(|(name, value)| FormField::new(name, value))
            .collect();
        Ok(Self {
            sp,
            idp,
            pending,
            fields,
        })
    }

    fn finish(self, validation: SamlValidationContext<'_>) -> anyhow::Result<saml_rs::SsoSession> {
        Ok(self.sp.finish_sso(
            &self.idp,
            &self.pending,
            BrowserInput::<SsoResponse>::post(self.fields),
            validation,
        )?)
    }
}

fn idp_descriptor(connection: &OrganizationSamlConnection) -> anyhow::Result<IdpDescriptor> {
    let entity_id = EntityId::try_new(connection.entity_id.clone())?;
    let certificate = CertificatePem::new(connection.metadata_signing_cert_pem.clone());
    Ok(IdpDescriptor::from_metadata_xml_for(
        entity_id,
        &connection.metadata_xml,
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates: std::slice::from_ref(&certificate),
        },
    )?)
}

/// Validate an externally supplied signed IdP metadata document using the same
/// parser and pinned certificate path as the login flow. This is intentionally
/// a metadata-only helper for operator conformance probes; it does not create
/// a session or trust any role claim.
pub fn validate_idp_metadata(connection: &OrganizationSamlConnection) -> anyhow::Result<()> {
    let _ = idp_descriptor(connection)?;
    Ok(())
}

#[derive(Default)]
struct BoundedReplayCache {
    entries: BTreeMap<String, SystemTime>,
}

impl ReplayCache for BoundedReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        let now = SystemTime::now();
        self.entries.retain(|_, expiry| *expiry > now);
        let cache_key = format!("{}:{}", key.kind(), key.value());
        if self.entries.contains_key(&cache_key) {
            return Err(SamlError::ReplayDetected { key: cache_key });
        }
        if self.entries.len() >= 4_096 {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, expiry)| *expiry)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(cache_key, expires_at);
        Ok(())
    }
}

fn replay_cache() -> &'static Mutex<BoundedReplayCache> {
    static CACHE: OnceLock<Mutex<BoundedReplayCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BoundedReplayCache::default()))
}

fn now_unix() -> anyhow::Result<i64> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(i64::try_from(seconds)?)
}

fn unavailable() -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({"error": {"message": "SAML browser login is not enabled"}})),
    )
        .into_response()
}

fn login_failed() -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({"error": {"message": "SAML login could not be completed"}})),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
