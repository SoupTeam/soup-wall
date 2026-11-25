// SPDX-License-Identifier: Apache-2.0
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{
    append_bounded_chunk, discovery_url, parse_and_validate_discovery, parse_jwks,
    parse_token_response, random_urlsafe_value, validate_token_exchange_component,
    DiscoveryDocument, OidcHttpClient, OidcStateCipher, PkcePair, ValidatedEndpoints,
    MAX_DISCOVERY_DOCUMENT_BYTES, MAX_SEALED_AUTHORIZATION_STATE_BYTES,
};
use crate::tenant_store::OrganizationOidcConnection;

#[test]
fn oidc_private_ca_requires_a_valid_certificate() {
    assert!(OidcHttpClient::with_ca_certificate(None).is_ok());
    assert!(OidcHttpClient::with_ca_certificate(Some(b"not a certificate")).is_err());
    assert!(OidcHttpClient::with_ca_certificate(Some(b"")).is_err());
    assert!(OidcHttpClient::with_ca_certificate(Some(include_bytes!(
        "../../tests/fixtures/saml/local-idp-cert.pem"
    )))
    .is_ok());
}

fn connection() -> OrganizationOidcConnection {
    OrganizationOidcConnection {
        organization_id: "org_test".into(),
        issuer: "https://id.example.test/realms/acme".into(),
        client_id: "firewall-console".into(),
        redirect_uri: "https://console.example.test/auth/oidc/callback".into(),
        active: true,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn discovery() -> DiscoveryDocument {
    DiscoveryDocument {
        issuer: "https://id.example.test/realms/acme".into(),
        authorization_endpoint: "https://id.example.test/authorize".into(),
        token_endpoint: "https://id.example.test/token".into(),
        jwks_uri: "https://id.example.test/keys".into(),
        response_types_supported: vec!["code".into()],
        grant_types_supported: vec!["authorization_code".into()],
        code_challenge_methods_supported: vec!["S256".into()],
    }
}

#[test]
fn discovery_url_appends_well_known_to_the_oidc_issuer_path() {
    // OIDC Discovery 1.0 section 4.1, including Keycloak's realm endpoint.
    for (issuer, expected) in [
        (
            "https://id.example.test",
            "https://id.example.test/.well-known/openid-configuration",
        ),
        (
            "https://id.example.test/",
            "https://id.example.test/.well-known/openid-configuration",
        ),
        (
            "https://id.example.test/realms/acme",
            "https://id.example.test/realms/acme/.well-known/openid-configuration",
        ),
        (
            "https://id.example.test/auth/realms/acme/",
            "https://id.example.test/auth/realms/acme/.well-known/openid-configuration",
        ),
    ] {
        assert_eq!(discovery_url(issuer).unwrap().as_str(), expected);
    }
}

#[test]
fn discovery_url_preserves_ports_and_encoded_path_components() {
    for (issuer, expected) in [
        (
            "https://id.example.test:8443/realms/acme%2Fdivision%20one/",
            "https://id.example.test:8443/realms/acme%2Fdivision%20one/.well-known/openid-configuration",
        ),
        (
            "https://[::1]:8443/realms/acme",
            "https://[::1]:8443/realms/acme/.well-known/openid-configuration",
        ),
    ] {
        assert_eq!(discovery_url(issuer).unwrap().as_str(), expected);
    }
}

#[test]
fn discovery_url_rejects_unsafe_issuer_uris() {
    for issuer in [
        "http://id.example.test/realms/acme",
        "https://user:pass@id.example.test/realms/acme",
        "https://id.example.test/realms/acme?other=issuer",
        "https://id.example.test/realms/acme#fragment",
    ] {
        assert!(discovery_url(issuer).is_err());
    }
}

#[test]
fn discovery_path_trimming_does_not_relax_exact_issuer_validation() {
    let mut connection = connection();
    connection.issuer.push('/');
    let mut document = discovery();
    assert!(document.validate_for_connection(&connection).is_err());
    document.issuer.push('/');
    assert!(document.validate_for_connection(&connection).is_ok());
    assert_eq!(
        discovery_url(&connection.issuer).unwrap().as_str(),
        "https://id.example.test/realms/acme/.well-known/openid-configuration"
    );
}

#[test]
fn pkce_uses_a_high_entropy_s256_verifier() {
    let pair = PkcePair::generate();
    assert_eq!(pair.code_verifier().len(), 43);
    assert_eq!(pair.code_challenge().len(), 43);
    assert_ne!(pair.code_verifier(), pair.code_challenge());
    assert!(pair
        .code_verifier()
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
}

#[test]
fn discovery_must_match_the_connection_and_advertise_s256() {
    let connection = connection();
    assert!(discovery().validate_for_connection(&connection).is_ok());

    let mut wrong_issuer = discovery();
    wrong_issuer.issuer = "https://id.example.test/other".into();
    assert!(wrong_issuer.validate_for_connection(&connection).is_err());

    let mut no_s256 = discovery();
    no_s256.code_challenge_methods_supported = vec!["plain".into()];
    assert!(no_s256.validate_for_connection(&connection).is_err());

    let mut unsafe_endpoint = discovery();
    unsafe_endpoint.jwks_uri = "https://user:pass@id.example.test/keys".into();
    assert!(unsafe_endpoint
        .validate_for_connection(&connection)
        .is_err());
}

#[test]
fn discovery_json_is_parsed_only_after_bounded_complete_read() {
    let connection = connection();
    let body = br#"{
            "issuer":"https://id.example.test/realms/acme",
            "authorization_endpoint":"https://id.example.test/authorize",
            "token_endpoint":"https://id.example.test/token",
            "jwks_uri":"https://id.example.test/keys",
            "response_types_supported":["code"],
            "grant_types_supported":["authorization_code"],
            "code_challenge_methods_supported":["S256"]
        }"#;
    assert!(parse_and_validate_discovery(body, &connection).is_ok());
    assert!(parse_and_validate_discovery(b"not JSON", &connection).is_err());

    let mut collected = Vec::new();
    append_bounded_chunk(&mut collected, &[1, 2], 3, "test response").unwrap();
    append_bounded_chunk(&mut collected, &[3], 3, "test response").unwrap();
    assert_eq!(collected, vec![1, 2, 3]);
    assert!(append_bounded_chunk(&mut collected, &[4], 3, "test response").is_err());
    assert!(append_bounded_chunk(
        &mut Vec::new(),
        &vec![0; MAX_DISCOVERY_DOCUMENT_BYTES + 1],
        MAX_DISCOVERY_DOCUMENT_BYTES,
        "test response",
    )
    .is_err());
}

#[tokio::test]
async fn local_idp_exchanges_pkce_code_and_serves_jwks_without_external_network() {
    let provider = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": [{
                "kty": "RSA", "kid": "local-key", "alg": "RS256", "use": "sig",
                "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyoP7gJ-vT7I7Y8", "e": "AQAB"
            }]
        })))
        .expect(1)
        .mount(&provider)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=local-code"))
        .and(body_string_contains("client_id=firewall-console"))
        .and(body_string_contains("code_verifier=local-verifier"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id_token": "header.claims.signature"
        })))
        .expect(1)
        .mount(&provider)
        .await;

    let endpoints = ValidatedEndpoints {
        authorization_endpoint: reqwest::Url::parse(&format!("{}/authorize", provider.uri()))
            .unwrap(),
        token_endpoint: reqwest::Url::parse(&format!("{}/token", provider.uri())).unwrap(),
        jwks_uri: reqwest::Url::parse(&format!("{}/jwks", provider.uri())).unwrap(),
    };
    let client = OidcHttpClient::for_local_test_provider(endpoints.clone()).unwrap();
    let jwks = client.fetch_jwks(&endpoints).await.unwrap();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].common.key_id.as_deref(), Some("local-key"));
    let token = client
        .exchange_authorization_code(&endpoints, &connection(), "local-code", "local-verifier")
        .await
        .unwrap();
    assert_eq!(token.id_token(), "header.claims.signature");
}

#[test]
fn token_and_jwks_responses_must_have_the_data_needed_for_verification() {
    assert_eq!(
        parse_token_response(br#"{"id_token":"header.claims.signature"}"#)
            .unwrap()
            .id_token(),
        "header.claims.signature"
    );
    assert!(parse_token_response(br#"{}"#).is_err());
    assert!(parse_token_response(br#"{"id_token":""}"#).is_err());
    assert!(parse_token_response(b"not JSON").is_err());

    assert!(parse_jwks(br#"{"keys":[]}"#).is_err());
    assert!(parse_jwks(br#"{"keys":[{"kty":"RSA","kid":"key-1","n":"abc","e":"AQAB"}]}"#).is_ok());
}

#[test]
fn token_exchange_values_are_bounded_and_control_free() {
    assert!(validate_token_exchange_component("code-value", "code", 16).is_ok());
    assert!(validate_token_exchange_component("", "code", 16).is_err());
    assert!(validate_token_exchange_component("too-long-value", "code", 3).is_err());
    assert!(validate_token_exchange_component("line\nbreak", "code", 16).is_err());
}

#[test]
fn authorization_state_is_authenticated_encrypted_and_key_bound() {
    let encoded_key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let cipher = OidcStateCipher::from_base64url_key(&encoded_key).unwrap();
    let pkce = PkcePair::generate();
    let nonce = random_urlsafe_value(32);
    let sealed = cipher
        .seal_authorization_state("org_acme", "workspace_prod", &pkce, &nonce, 1_700_000_000)
        .unwrap();
    assert!(!sealed.contains(pkce.code_verifier()));
    assert!(!sealed.contains(&nonce));

    let opened = cipher.open_authorization_state(&sealed).unwrap();
    assert_eq!(opened.organization_id(), "org_acme");
    assert_eq!(opened.workspace_id(), "workspace_prod");
    assert_eq!(opened.invitation_id(), None);
    assert_eq!(opened.code_verifier(), pkce.code_verifier());
    assert_eq!(opened.nonce(), nonce);
    assert_eq!(opened.expires_at_unix(), 1_700_000_000);

    let invitation_sealed = cipher
        .seal_authorization_state_with_invitation(
            "org_acme",
            "workspace_prod",
            Some("invitation_one"),
            &pkce,
            &nonce,
            1_700_000_000,
        )
        .unwrap();
    assert!(!invitation_sealed.contains("invitation_one"));
    assert_eq!(
        cipher
            .open_authorization_state(&invitation_sealed)
            .unwrap()
            .invitation_id(),
        Some("invitation_one")
    );

    let sealed_for_other_key = sealed.clone();
    let mut tampered = sealed.into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    assert!(cipher.open_authorization_state(&tampered).is_err());
    assert!(cipher
        .open_authorization_state(&"A".repeat(MAX_SEALED_AUTHORIZATION_STATE_BYTES + 1))
        .is_err());

    let other_key = URL_SAFE_NO_PAD.encode([8_u8; 32]);
    let other_cipher = OidcStateCipher::from_base64url_key(&other_key).unwrap();
    assert!(other_cipher
        .open_authorization_state(&sealed_for_other_key)
        .is_err());
    assert!(OidcStateCipher::from_base64url_key("not-a-key").is_err());
}

#[test]
fn saml_state_is_authenticated_and_key_bound() {
    let cipher = OidcStateCipher::from_base64url_key(&URL_SAFE_NO_PAD.encode([9_u8; 32])).unwrap();
    let sealed = cipher
        .seal_saml_authorization_state("org_acme", "workspace_prod", 1_700_000_000)
        .unwrap();
    let opened = cipher.open_saml_authorization_state(&sealed).unwrap();
    assert_eq!(opened.organization_id(), "org_acme");
    assert_eq!(opened.workspace_id(), "workspace_prod");
    assert_eq!(opened.expires_at_unix(), 1_700_000_000);
    let mut tampered = sealed.into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    assert!(cipher
        .open_saml_authorization_state(&String::from_utf8(tampered).unwrap())
        .is_err());

    let relay = cipher.seal_saml_relay_state().unwrap();
    assert!(relay.len() <= 80);
    cipher.open_saml_relay_state(&relay).unwrap();
    let mut tampered_relay = relay.into_bytes();
    let last = tampered_relay.len() - 1;
    tampered_relay[last] = if tampered_relay[last] == b'A' {
        b'B'
    } else {
        b'A'
    };
    assert!(cipher
        .open_saml_relay_state(&String::from_utf8(tampered_relay).unwrap())
        .is_err());
}

#[test]
fn browser_csrf_token_is_bound_to_the_opaque_session() {
    let cipher = OidcStateCipher::from_base64url_key(&URL_SAFE_NO_PAD.encode([5_u8; 32])).unwrap();
    let token = cipher.browser_csrf_token("session-a");
    assert!(cipher.verifies_browser_csrf_token("session-a", &token));
    assert!(!cipher.verifies_browser_csrf_token("session-b", &token));
    assert!(!cipher.verifies_browser_csrf_token("session-a", "not-a-valid-token"));
}
