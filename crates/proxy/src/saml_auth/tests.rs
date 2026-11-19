// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;

use super::*;
use axum::extract::{Form, State};
use axum::http::{header, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::Url;
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::crypto::construct_saml_signature;
use saml_rs::crypto::keys::load_private_key;
use saml_rs::entity::{SignatureAction, SignatureConfig};
use saml_rs::{
    AuthnRequestValidationPolicy, BrowserInput, CertificatePem, Credentials, EntityId, IdpConfig,
    IdpValidationPolicy, MetadataTrustPolicy, NameId, PrivateKeyPem, ReplayPolicy, RespondSso,
    Saml, SamlValidationContext, SpDescriptor, SsoEndpoint, Subject,
};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};

use crate::handlers::AppState;
use crate::tenant_store::{TenantStore, WorkspaceRole};
use crate::test_config;

const FIXTURE_KEY: &str = include_str!("../../tests/fixtures/saml/local-idp-key.pem");
const FIXTURE_CERT: &str = include_str!("../../tests/fixtures/saml/local-idp-cert.pem");
const SP_ENTITY_ID: &str = "https://sp.example.test/metadata";
const SP_ACS_URL: &str = "https://sp.example.test/auth/saml/acs";
const IDP_ENTITY_ID: &str = "https://idp.example.test/metadata";
const IDP_SSO_URL: &str = "https://idp.example.test/sso";

#[test]
fn saml_post_requires_unique_originating_browser_cookie() {
    let relay = "synthetic-relay-a";
    let cookie = flow_cookie(relay);
    let text = cookie.to_str().unwrap();
    assert!(text.contains("SameSite=None"));
    assert!(text.contains("Secure; HttpOnly"));
    assert!(!text.contains("Domain="));
    let mut headers = HeaderMap::new();
    assert!(!browser_matches(&headers, relay));
    headers.insert(
        header::COOKIE,
        text.split(';').next().unwrap().parse().unwrap(),
    );
    assert!(browser_matches(&headers, relay));
    assert!(!browser_matches(&headers, "synthetic-relay-b"));
    headers.append(header::COOKIE, headers[header::COOKIE].clone());
    assert!(!browser_matches(&headers, relay));
}

fn fixture_runtime() -> SamlRuntimeConfig {
    SamlRuntimeConfig {
        sp_entity_id: SP_ENTITY_ID.to_owned(),
        acs_url: SP_ACS_URL.to_owned(),
        sp_private_key_pem: FIXTURE_KEY.to_owned(),
        sp_certificate_pem: FIXTURE_CERT.to_owned(),
    }
}

fn fixture_idp() -> anyhow::Result<Saml<saml_rs::Idp>> {
    let config = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_URL)?)
        .credentials(Credentials {
            signing_key: Some(PrivateKeyPem::new(FIXTURE_KEY)),
            signing_certificate: Some(CertificatePem::new(FIXTURE_CERT)),
            ..Credentials::default()
        })
        .validation(idp_validation_policy())
        .build()?;
    Ok(Saml::idp(config)?)
}

fn signed_idp_metadata(idp: &Saml<saml_rs::Idp>) -> anyhow::Result<String> {
    let key = load_private_key(FIXTURE_KEY, None)?;
    let signature = SignatureConfig {
        prefix: "ds".into(),
        reference: Some("/*[local-name(.)='EntityDescriptor']".into()),
        action: SignatureAction::Prepend,
    };
    let unsigned = idp.metadata_xml().replacen(
        "<EntityDescriptor ",
        "<EntityDescriptor ID=\"_fixture_metadata\" ",
        1,
    );
    Ok(construct_saml_signature(
        &unsigned,
        true,
        &key,
        FIXTURE_CERT,
        RSA_SHA256,
        &[],
        Some(&signature),
    )?)
}

fn validation() -> SamlValidationContext<'static> {
    validation_context(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn idp_validation_policy() -> IdpValidationPolicy {
    IdpValidationPolicy {
        authn_requests: AuthnRequestValidationPolicy::RequireSigned,
        ..IdpValidationPolicy::recommended()
    }
}

struct FixedReplayCache {
    now: SystemTime,
    entries: BTreeMap<String, SystemTime>,
}

impl FixedReplayCache {
    fn new(now: SystemTime) -> Self {
        Self {
            now,
            entries: BTreeMap::new(),
        }
    }

    fn validation(&mut self) -> SamlValidationContext<'_> {
        validation_context(self.now, ReplayPolicy::RequireCache(self))
    }
}

impl ReplayCache for FixedReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        self.entries.retain(|_, expiry| *expiry > self.now);
        let key = format!("{}:{}", key.kind(), key.value());
        if self.entries.contains_key(&key) {
            return Err(SamlError::ReplayDetected { key });
        }
        self.entries.insert(key, expires_at);
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeycloakVendor {
    name: String,
    version: String,
    archive_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeycloakProvenance {
    driver_sha256: String,
    saml_source_sha256: String,
    gateway_sha256: String,
    bootstrap_helper_sha256: String,
    keycloak_archive_sha256: String,
    jdk_archive_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeycloakCorpus {
    schema_version: u32,
    acceptance_complete: bool,
    synthetic_fixture: bool,
    vendor: KeycloakVendor,
    captured_at_unix: u64,
    sp_entity_id: String,
    acs_url: String,
    idp_entity_id: String,
    idp_signing_cert_pem: String,
    request_id: String,
    relay_state: String,
    expected_name_id: String,
    metadata_xml: String,
    saml_response: String,
    provenance: KeycloakProvenance,
}

impl KeycloakCorpus {
    fn load() -> anyhow::Result<Self> {
        // Runtime loading keeps ordinary Gateway builds independent of
        // fixture generation. Missing or incomplete corpus is a test failure.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/saml/keycloak-corpus.json");
        let bytes = std::fs::read(path).map_err(|error| {
            anyhow::anyhow!("required fresh Keycloak corpus unavailable: {error}")
        })?;
        let corpus: Self = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            corpus.schema_version == 1,
            "unsupported Keycloak corpus schema"
        );
        anyhow::ensure!(
            corpus.acceptance_complete && corpus.synthetic_fixture,
            "Keycloak corpus requires complete synthetic vendor acceptance"
        );
        anyhow::ensure!(
            corpus.vendor.name == "Keycloak" && corpus.vendor.version == "26.8.0",
            "Keycloak corpus vendor provenance is unsupported"
        );
        anyhow::ensure!(
            corpus.vendor.archive_sha256
                == "7ed1de3fda2598369262613bf682aab7e233d80a38c405e91588f7a7454370a1",
            "Keycloak corpus does not identify the pinned official archive"
        );
        anyhow::ensure!(
            corpus.vendor.archive_sha256 == corpus.provenance.keycloak_archive_sha256,
            "Keycloak corpus archive provenance differs"
        );
        for digest in [
            &corpus.provenance.driver_sha256,
            &corpus.provenance.saml_source_sha256,
            &corpus.provenance.gateway_sha256,
            &corpus.provenance.bootstrap_helper_sha256,
            &corpus.provenance.keycloak_archive_sha256,
            &corpus.provenance.jdk_archive_sha256,
        ] {
            anyhow::ensure!(
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "Keycloak corpus lacks a SHA-256 provenance digest"
            );
        }
        anyhow::ensure!(
            !corpus.request_id.is_empty()
                && !corpus.relay_state.is_empty()
                && !corpus.expected_name_id.is_empty(),
            "Keycloak corpus correlation is absent"
        );
        Ok(corpus)
    }

    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.captured_at_unix)
    }

    fn runtime(&self) -> SamlRuntimeConfig {
        // Published local test credentials satisfy the strict SP builder;
        // plaintext response verification needs no captured private key.
        SamlRuntimeConfig {
            sp_entity_id: self.sp_entity_id.clone(),
            acs_url: self.acs_url.clone(),
            sp_private_key_pem: FIXTURE_KEY.into(),
            sp_certificate_pem: FIXTURE_CERT.into(),
        }
    }

    fn connection(&self) -> OrganizationSamlConnection {
        OrganizationSamlConnection {
            organization_id: "keycloak-corpus".into(),
            entity_id: self.idp_entity_id.clone(),
            metadata_xml: self.metadata_xml.clone(),
            metadata_signing_cert_pem: self.idp_signing_cert_pem.clone(),
            active: true,
            created_at_unix: 0,
            updated_at_unix: 0,
        }
    }

    fn pending(&self) -> SamlAuthorizationPending {
        // These expectations were captured from the original outgoing SP
        // request, independently of the vendor response under validation.
        SamlAuthorizationPending {
            organization_id: "keycloak-corpus".into(),
            workspace_id: "corpus-workspace".into(),
            invitation_id: None,
            request_id: self.request_id.clone(),
            idp_entity_id: self.idp_entity_id.clone(),
            expected_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".into(),
            request_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".into(),
            acs_url: self.acs_url.clone(),
            acs_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".into(),
        }
    }

    fn fields(&self) -> Vec<(String, String)> {
        vec![
            ("SAMLResponse".into(), self.saml_response.clone()),
            ("RelayState".into(), self.relay_state.clone()),
        ]
    }

    fn verify(&self, replay: &mut FixedReplayCache) -> anyhow::Result<saml_rs::SsoSession> {
        PreparedSso::new(
            &self.runtime(),
            self.connection(),
            self.pending(),
            &self.relay_state,
            self.fields(),
        )?
        .finish(replay.validation())
    }

    fn assert_valid(&self) -> anyhow::Result<()> {
        let session = self.verify(&mut FixedReplayCache::new(self.now()))?;
        assert_eq!(session.issuer().as_str(), self.idp_entity_id);
        assert_eq!(session.name_id().value(), self.expected_name_id);
        assert!(!session.verified_xml_signatures().is_empty());
        Ok(())
    }
}

#[test]
fn keycloak_corpus_accepts_original_vendor_signed_documents() -> anyhow::Result<()> {
    KeycloakCorpus::load()?.assert_valid()
}

#[test]
fn keycloak_corpus_rejects_tampered_metadata_endpoint() -> anyhow::Result<()> {
    let corpus = KeycloakCorpus::load()?;
    corpus.assert_valid()?;
    let mut connection = corpus.connection();
    let service = connection
        .metadata_xml
        .find("SingleSignOnService")
        .ok_or_else(|| anyhow::anyhow!("vendor corpus lacks an SSO endpoint"))?;
    let start = service
        + connection.metadata_xml[service..]
            .find("Location=\"")
            .ok_or_else(|| anyhow::anyhow!("vendor corpus lacks a quoted SSO location"))?
        + "Location=\"".len();
    let end = start
        + connection.metadata_xml[start..]
            .find('"')
            .ok_or_else(|| anyhow::anyhow!("vendor corpus has an unterminated SSO location"))?;
    connection
        .metadata_xml
        .replace_range(start..end, "https://attacker.example.test/sso");
    assert!(idp_descriptor(&connection).is_err());
    Ok(())
}

#[test]
fn keycloak_corpus_rejects_tampered_name_id() -> anyhow::Result<()> {
    let corpus = KeycloakCorpus::load()?;
    corpus.assert_valid()?;
    let mut xml = String::from_utf8(
        base64::engine::general_purpose::STANDARD.decode(&corpus.saml_response)?,
    )?;
    let positions: Vec<usize> = xml
        .match_indices(&corpus.expected_name_id)
        .filter_map(|(offset, _)| {
            let (_, prefix) = xml[..offset].rsplit_once('<')?;
            let tag = prefix.split_whitespace().next()?.trim_end_matches('>');
            (prefix.ends_with('>') && tag.rsplit(':').next() == Some("NameID")).then_some(offset)
        })
        .collect();
    assert_eq!(
        positions.len(),
        1,
        "vendor corpus must have exactly one expected NameID"
    );
    let start = positions[0];
    xml.replace_range(
        start..start + corpus.expected_name_id.len(),
        "tampered-synthetic@example.test",
    );
    let mut fields = corpus.fields();
    fields[0].1 = base64::engine::general_purpose::STANDARD.encode(xml);
    let mut replay = FixedReplayCache::new(corpus.now());
    assert!(PreparedSso::new(
        &corpus.runtime(),
        corpus.connection(),
        corpus.pending(),
        &corpus.relay_state,
        fields,
    )?
    .finish(replay.validation())
    .is_err());
    Ok(())
}

#[test]
fn keycloak_corpus_rejects_wrong_original_request_correlation() -> anyhow::Result<()> {
    let corpus = KeycloakCorpus::load()?;
    corpus.assert_valid()?;
    for mutation in ["request_id", "relay_state", "acs_url"] {
        let mut pending = corpus.pending();
        let mut fields = corpus.fields();
        match mutation {
            "request_id" => pending.request_id = "_different_original_request".into(),
            "relay_state" => fields[1].1 = "different-original-relay".into(),
            "acs_url" => pending.acs_url = "https://different.example.test/auth/saml/acs".into(),
            _ => unreachable!(),
        }
        let mut replay = FixedReplayCache::new(corpus.now());
        assert!(
            PreparedSso::new(
                &corpus.runtime(),
                corpus.connection(),
                pending,
                &corpus.relay_state,
                fields,
            )?
            .finish(replay.validation())
            .is_err(),
            "accepted incorrect {mutation}"
        );
    }
    Ok(())
}

#[test]
fn keycloak_corpus_rejects_expired_vendor_assertion() -> anyhow::Result<()> {
    let corpus = KeycloakCorpus::load()?;
    corpus.assert_valid()?;
    let mut replay = FixedReplayCache::new(corpus.now() + Duration::from_secs(24 * 60 * 60));
    assert!(corpus.verify(&mut replay).is_err());
    Ok(())
}

#[test]
fn genuine_signed_response_is_bound_to_sp_audience_and_expected_issuer() -> anyhow::Result<()> {
    let corpus = KeycloakCorpus::load()?;
    corpus.assert_valid()?;
    for mutation in ["audience", "issuer"] {
        let mut runtime = corpus.runtime();
        let mut pending = corpus.pending();
        match mutation {
            "audience" => runtime.sp_entity_id = "urn:other-service-provider".into(),
            "issuer" => pending.idp_entity_id = "https://other-idp.example.test/metadata".into(),
            _ => unreachable!(),
        }
        // Preserve the genuine signature and timestamp. Only the trusted
        // local expectation differs from the positive control.
        let result = PreparedSso::new(
            &runtime,
            corpus.connection(),
            pending,
            &corpus.relay_state,
            corpus.fields(),
        )
        .and_then(|prepared| prepared.finish(FixedReplayCache::new(corpus.now()).validation()));
        assert!(result.is_err(), "accepted mismatched {mutation}");
    }
    Ok(())
}

#[test]
fn keycloak_corpus_rejects_replayed_vendor_assertion() -> anyhow::Result<()> {
    let corpus = KeycloakCorpus::load()?;
    let mut replay = FixedReplayCache::new(corpus.now());
    let session = corpus.verify(&mut replay)?;
    assert_eq!(session.name_id().value(), corpus.expected_name_id);
    let error = corpus
        .verify(&mut replay)
        .err()
        .ok_or_else(|| anyhow::anyhow!("replayed vendor assertion was accepted"))?;
    assert!(
        matches!(
            error.downcast_ref::<SamlError>(),
            Some(SamlError::ReplayDetected { .. })
        ),
        "expected replay rejection, got {error}"
    );
    Ok(())
}

#[test]
fn historical_signed_response_is_accepted_at_its_validation_time() -> anyhow::Result<()> {
    let runtime = fixture_runtime();
    let connection = OrganizationSamlConnection {
        organization_id: "context-fixture".into(),
        entity_id: IDP_ENTITY_ID.into(),
        metadata_xml: signed_idp_metadata(&fixture_idp()?)?,
        metadata_signing_cert_pem: FIXTURE_CERT.into(),
        active: true,
        created_at_unix: 0,
        updated_at_unix: 0,
    };
    let pending = SamlAuthorizationPending {
        organization_id: "context-fixture".into(),
        workspace_id: "context-workspace".into(),
        invitation_id: None,
        request_id: "_context_request".into(),
        idp_entity_id: IDP_ENTITY_ID.into(),
        expected_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".into(),
        request_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".into(),
        acs_url: SP_ACS_URL.into(),
        acs_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".into(),
    };
    let unsigned = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_context_response" Version="2.0" IssueInstant="2020-01-01T00:00:00Z" Destination="{SP_ACS_URL}" InResponseTo="_context_request"><saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_context_assertion" Version="2.0" IssueInstant="2020-01-01T00:00:00Z"><saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer><saml:Subject><saml:NameID>alice@example.test</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="_context_request" Recipient="{SP_ACS_URL}" NotOnOrAfter="2020-01-01T00:05:00Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2020-01-01T00:05:00Z"><saml:AudienceRestriction><saml:Audience>{SP_ENTITY_ID}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2020-01-01T00:00:00Z" SessionIndex="_context_session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>"#
    );
    let key = load_private_key(FIXTURE_KEY, None)?;
    let signed =
        construct_saml_signature(&unsigned, false, &key, FIXTURE_CERT, RSA_SHA256, &[], None)?;
    let fields = vec![
        (
            "SAMLResponse".into(),
            base64::engine::general_purpose::STANDARD.encode(signed),
        ),
        ("RelayState".into(), "context-relay".into()),
    ];
    // Establish that the real signed response is valid at this independent
    // instant before exercising the application's shared verifier.
    let captured_at = UNIX_EPOCH + Duration::from_secs(1_577_836_801);
    let snapshot = PendingSnapshot::<saml_rs::AuthnRequest>::authn_request(
        pending.request_id.clone(),
        RelayStateParam::try_from_option(Some("context-relay"))?,
        pending.idp_entity_id.clone(),
        pending.expected_binding.clone(),
        pending.acs_url.clone(),
        pending.acs_binding.clone(),
    );
    let request = PendingAuthnRequest::from_snapshot(snapshot)?;
    let verified = runtime
        .sp()?
        .finish_sso(
            &idp_descriptor(&connection)?,
            &request,
            BrowserInput::<SsoResponse>::post(
                fields
                    .iter()
                    .map(|(name, value)| FormField::new(name, value))
                    .collect(),
            ),
            validation_context(captured_at, ReplayPolicy::DisabledForCompatibility),
        )
        .map_err(|error| anyhow::anyhow!("fixed-time signed fixture control failed: {error}"))?;
    assert_eq!(verified.name_id().value(), "alice@example.test");
    // The same genuine signed response must fail one second after its
    // deadline, even though the upstream default now allows five minutes.
    assert!(runtime
        .sp()?
        .finish_sso(
            &idp_descriptor(&connection)?,
            &request,
            BrowserInput::<SsoResponse>::post(
                fields
                    .iter()
                    .map(|(name, value)| FormField::new(name, value))
                    .collect()
            ),
            validation_context(
                captured_at + Duration::from_secs(300),
                ReplayPolicy::DisabledForCompatibility
            ),
        )
        .is_err());
    assert!(finish_sso(
        &runtime,
        connection.clone(),
        pending.clone(),
        "context-relay",
        fields.clone()
    )
    .is_err());
    let mut replay = FixedReplayCache::new(captured_at);
    let session = PreparedSso::new(&runtime, connection, pending, "context-relay", fields)?
        .finish(replay.validation())?;
    assert_eq!(session.name_id().value(), "alice@example.test");
    Ok(())
}

#[test]
fn saml_initializes_the_timing_safe_document_provider() -> anyhow::Result<()> {
    let provider = saml_rs::initialize_crypto_provider()?;
    assert_eq!(provider.provider(), saml_rs::CryptoProvider::AwsLc);
    assert_eq!(provider.fips_status(), saml_rs::CryptoFipsStatus::Disabled);
    Ok(())
}

#[test]
fn runtime_requires_complete_fixed_https_configuration() {
    assert!(
        SamlRuntimeConfig::from_optional_values([None, None, None, None])
            .unwrap()
            .is_none()
    );
    assert!(SamlRuntimeConfig::from_optional_values([
        Some("https://sp.example.test/metadata".to_owned()),
        None,
        None,
        None,
    ])
    .is_err());

    let valid = [
        Some("https://sp.example.test/metadata".to_owned()),
        Some("https://sp.example.test/auth/saml/acs".to_owned()),
        Some("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----".to_owned()),
        Some("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----".to_owned()),
    ];
    assert!(SamlRuntimeConfig::from_optional_values(valid)
        .unwrap()
        .is_some());

    assert!(SamlRuntimeConfig::from_optional_values([
        Some("https://sp.example.test/metadata".to_owned()),
        Some("http://sp.example.test/auth/saml/acs".to_owned()),
        Some("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----".to_owned()),
        Some("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----".to_owned()),
    ])
    .is_err());
}

#[test]
fn runtime_never_configures_xml_decryption() {
    let runtime = SamlRuntimeConfig::from_optional_values([
        Some("https://sp.example.test/metadata".to_owned()),
        Some("https://sp.example.test/auth/saml/acs".to_owned()),
        Some("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----".to_owned()),
        Some("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----".to_owned()),
    ])
    .unwrap()
    .unwrap();
    let config = runtime.sp_config().unwrap();
    assert!(config.credentials.decryption_key.is_none());
    assert!(config.credentials.encryption_certificate.is_none());
    assert_eq!(
        config.xml.encryption.assertions,
        saml_rs::AssertionEncryptionPolicy::PlaintextAssertions
    );
}

#[test]
fn runtime_metadata_does_not_advertise_assertion_encryption() -> anyhow::Result<()> {
    let sp = fixture_runtime().sp()?;
    assert!(sp.metadata_xml().contains("use=\"signing\""));
    assert!(!sp.metadata_xml().contains("use=\"encryption\""));
    Ok(())
}

#[test]
fn pinned_metadata_rejects_a_tampered_sso_endpoint() -> anyhow::Result<()> {
    let metadata_xml = signed_idp_metadata(&fixture_idp()?)?;
    let mut connection = OrganizationSamlConnection {
        organization_id: "org_signature_fixture".to_owned(),
        entity_id: IDP_ENTITY_ID.to_owned(),
        metadata_xml,
        metadata_signing_cert_pem: FIXTURE_CERT.to_owned(),
        active: true,
        created_at_unix: now_unix()?,
        updated_at_unix: now_unix()?,
    };
    // Establish that this exact signed metadata is trusted before changing
    // an authenticated field while leaving the signature intact.
    idp_descriptor(&connection)?;
    connection.metadata_xml = connection
        .metadata_xml
        .replace(IDP_SSO_URL, "https://attacker.example.test/sso");
    assert!(connection
        .metadata_xml
        .contains("https://attacker.example.test/sso"));
    assert!(idp_descriptor(&connection).is_err());
    Ok(())
}

#[test]
fn signed_response_rejects_a_tampered_name_id() -> anyhow::Result<()> {
    let sp = fixture_runtime().sp()?;
    let idp = fixture_idp()?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
    let redirect = Url::parse(started.outbound.redirect_url()?)?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<saml_rs::AuthnRequest>::redirect(redirect.query().expect("SSO query")),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        Subject::new(NameId::new("alice@example.test", None), Vec::new()),
        RespondSso::post(),
    )?;
    let form = response.post_form()?;
    let fields = || {
        form.fields()
            .iter()
            .map(|field| FormField::new(field.name(), field.value()))
            .collect()
    };
    // A valid response and the modified response use identical request
    // correlation, binding, timestamps, issuer and audience.
    let valid = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(fields()),
        validation(),
    )?;
    assert_eq!(valid.name_id().value(), "alice@example.test");
    let mut tampered = Vec::new();
    for field in form.fields() {
        if field.name() == "SAMLResponse" {
            let xml = String::from_utf8(
                base64::engine::general_purpose::STANDARD.decode(field.value())?,
            )?;
            assert!(xml.contains("alice@example.test"));
            let changed = xml.replace("alice@example.test", "mallory@example.test");
            tampered.push(FormField::new(
                field.name(),
                base64::engine::general_purpose::STANDARD.encode(changed),
            ));
        } else {
            tampered.push(FormField::new(field.name(), field.value()));
        }
    }
    assert!(sp
        .finish_sso(
            &idp_descriptor,
            &started.pending,
            BrowserInput::<SsoResponse>::post(tampered),
            validation(),
        )
        .is_err());
    Ok(())
}

#[test]
fn signed_response_with_encrypted_assertion_is_rejected_without_a_decryption_key(
) -> anyhow::Result<()> {
    let runtime = fixture_runtime();
    let sp = runtime.sp()?;

    // Advertise an encryption certificate to the test IdP so it can send
    // a valid encrypted response. The actual runtime SP still has no
    // decryption key and must reject that response.
    let advertised_sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS_URL)?)
            .credentials(Credentials {
                signing_key: Some(PrivateKeyPem::new(FIXTURE_KEY)),
                signing_certificate: Some(CertificatePem::new(FIXTURE_CERT)),
                encryption_certificate: Some(CertificatePem::new(FIXTURE_CERT)),
                ..Credentials::default()
            })
            .validation(sp_validation_policy())
            .build()?,
    )?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        advertised_sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_URL)?)
            .credentials(Credentials {
                signing_key: Some(PrivateKeyPem::new(FIXTURE_KEY)),
                signing_certificate: Some(CertificatePem::new(FIXTURE_CERT)),
                ..Credentials::default()
            })
            .validation(idp_validation_policy())
            .xml(XmlPolicy {
                encryption: XmlEncryptionPolicy::encrypt_assertions(),
                ..XmlPolicy::default()
            })
            .build()?,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let request_fields = started
        .outbound
        .post_form()?
        .fields()
        .iter()
        .map(|field| FormField::new(field.name(), field.value()))
        .collect();
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<saml_rs::AuthnRequest>::post(request_fields),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        Subject::new(NameId::new("alice@example.test", None), Vec::new()),
        RespondSso::post(),
    )?;
    let response_fields: Vec<_> = response
        .post_form()?
        .fields()
        .iter()
        .map(|field| FormField::new(field.name(), field.value()))
        .collect();
    let encoded = response_fields
        .iter()
        .find(|field| field.name() == "SAMLResponse")
        .ok_or_else(|| anyhow::anyhow!("test IdP omitted SAMLResponse"))?;
    let xml =
        String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded.value())?)?;
    assert!(xml.contains("EncryptedAssertion"));
    assert!(xml.contains("<ds:Signature"));

    let error = sp
        .finish_sso(
            &idp_descriptor,
            &started.pending,
            BrowserInput::<SsoResponse>::post(response_fields),
            validation(),
        )
        .err()
        .ok_or_else(|| anyhow::anyhow!("encrypted assertion was accepted"))?;
    assert!(
        matches!(error, SamlError::AssertionSignatureRequired),
        "expected a signed plaintext assertion, got {error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn local_signed_customer_idp_completes_sp_initiated_flow() -> anyhow::Result<()> {
    let runtime = fixture_runtime();
    let idp = fixture_idp()?;
    let metadata_xml = signed_idp_metadata(&idp)?;
    let idp_connection = OrganizationSamlConnection {
        organization_id: "org_fixture".to_owned(),
        entity_id: IDP_ENTITY_ID.to_owned(),
        metadata_xml: metadata_xml.clone(),
        metadata_signing_cert_pem: FIXTURE_CERT.to_owned(),
        active: true,
        created_at_unix: now_unix()?,
        updated_at_unix: now_unix()?,
    };
    let sp = runtime.sp()?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    let store = TenantStore::open(":memory:")?;
    let organization = store.create_organization("Local SAML fixture")?;
    let tenant = store.create_tenant_in_organization(&organization.id, "Fixture tenant")?;
    let workspace = store.workspace_for_tenant(&tenant.id)?.expect("workspace");
    let principal = store.create_workspace_principal("Fixture Alice")?;
    store.set_workspace_membership(
        &workspace.id,
        &principal.id,
        crate::tenant_store::WorkspaceRole::Analyst,
    )?;
    store.link_workspace_external_identity(&principal.id, IDP_ENTITY_ID, "alice@example.test")?;
    let connection = store.set_organization_saml_connection(
        &organization.id,
        IDP_ENTITY_ID,
        &metadata_xml,
        FIXTURE_CERT,
        true,
    )?;
    let cipher = OidcStateCipher::from_base64url_key(&URL_SAFE_NO_PAD.encode([7_u8; 32]))?;

    let (redirect_url, _) =
        start_login_inner(&store, &cipher, &runtime, connection, &workspace.id, None).await?;
    let redirect = Url::parse(&redirect_url)?;
    let query = redirect
        .query()
        .ok_or_else(|| anyhow::anyhow!("fixture redirect has no query"))?;
    let relay_state = redirect
        .query_pairs()
        .find(|(key, _)| key == "RelayState")
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| anyhow::anyhow!("fixture redirect has no RelayState"))?;
    let request = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<saml_rs::AuthnRequest>::redirect(query),
        validation(),
    )?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &request,
        Subject::new(NameId::new("alice@example.test", None), Vec::new()),
        RespondSso::post(),
    )?;
    let form = response.post_form()?;
    let response_fields = form
        .fields()
        .iter()
        .map(|field| (field.name().to_owned(), field.value().to_owned()))
        .collect::<Vec<(String, String)>>();
    assert_eq!(
        response_fields
            .iter()
            .find(|(key, _)| key == "RelayState")
            .map(|(_, value)| value),
        Some(&relay_state)
    );
    let pending = store
        .consume_saml_authorization_state(&relay_state)?
        .ok_or_else(|| anyhow::anyhow!("fixture RelayState was not pending"))?;
    let session = finish_sso(
        &runtime,
        idp_connection,
        pending,
        &relay_state,
        response_fields,
    )?;
    assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);
    assert_eq!(session.name_id().value(), "alice@example.test");

    let access = store
        .verified_saml_identity_workspace_access(
            &organization.id,
            &workspace.id,
            IDP_ENTITY_ID,
            "alice@example.test",
        )?
        .expect("local fixture identity is a member");
    assert_eq!(access.principal_id, principal.id);
    assert_eq!(access.role, crate::tenant_store::WorkspaceRole::Analyst);
    let browser_session = store.issue_oidc_browser_session(
        &access,
        BrowserSessionFederation::Saml,
        now_unix()? + 3_600,
    )?;
    assert!(!browser_session.token.is_empty());
    Ok(())
}

#[tokio::test]
async fn saml_invitation_start_redirects_and_persists_only_invitation_id() -> anyhow::Result<()> {
    let runtime = fixture_runtime();
    let idp = fixture_idp()?;
    let metadata_xml = signed_idp_metadata(&idp)?;
    let store = TenantStore::open(":memory:")?;
    let organization = store.create_organization("SAML invitation route")?;
    let issuer = IDP_ENTITY_ID;
    store.set_organization_saml_connection(
        &organization.id,
        issuer,
        &metadata_xml,
        FIXTURE_CERT,
        true,
    )?;
    let tenant = store.create_tenant_in_organization(&organization.id, "SAML route tenant")?;
    let workspace = store.workspace_for_tenant(&tenant.id)?.expect("workspace");
    let owner = store.create_workspace_principal("SAML route owner")?;
    store.set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)?;
    let invitation = store.create_workspace_invitation_as_owner(
        &workspace.id,
        &owner.id,
        "SAML route recipient",
        WorkspaceRole::Analyst,
        now_unix()? + 3_600,
    )?;
    let cipher = OidcStateCipher::from_base64url_key(&URL_SAFE_NO_PAD.encode([8_u8; 32]))?;
    let state = Arc::new(AppState {
        firewall: Firewall::new(
            vec![Box::new(InjectionDetector::new())],
            PolicySet::from_yaml("default: allow")?,
        ),
        http: reqwest::Client::new(),
        openai_api_key: None,
        proxy_auth_token: None,
        tenant_store: Some(store),
        admin_token: None,
        oidc_state_cipher: Some(cipher),
        saml: Some(runtime),
        rate_limiter: std::sync::Mutex::new(
            crate::rate_limit::RateLimiter::new(Default::default()),
        ),
        spend_ledger: std::sync::Mutex::new(crate::spend_limit::SpendLedger::new(
            Default::default(),
        )),
        redis_limits: None,
        agent: std::sync::Mutex::new(soup_wall_agent::AgentFirewall::with_default_policy()),
        moderation: crate::moderation::ModerationGate::new(Default::default()),
        config: test_config("http://127.0.0.1:1".into()),
    });

    let response = start_invitation_login(
        State(state.clone()),
        Form(InvitationStartForm {
            token: invitation.token,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("SAML invitation response has no redirect"))?;
    let redirect = Url::parse(location)?;
    let relay_state = redirect
        .query_pairs()
        .find(|(key, _)| key == "RelayState")
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| anyhow::anyhow!("SAML invitation redirect has no RelayState"))?;
    let pending = state
        .tenant_store
        .as_ref()
        .expect("test store")
        .consume_saml_authorization_state(&relay_state)?
        .ok_or_else(|| anyhow::anyhow!("SAML invitation state was not persisted"))?;
    assert_eq!(pending.invitation_id, Some(invitation.invitation.id));
    Ok(())
}
