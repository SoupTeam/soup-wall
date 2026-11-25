// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use soup_wall_core::{Firewall, InjectionDetector, PolicySet};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{
    authorization_url, callback_path, callback_with_client, expired_session_cookie, session_cookie,
    session_cookie_token, CallbackQuery, CustomerInvoicePreview,
};
use crate::{
    handlers::AppState,
    oidc::{OidcHttpClient, OidcStateCipher, PkcePair, ValidatedEndpoints},
    tenant_store::{
        OrganizationOidcConnection, TenantStore, UsageReconciliationReadiness, UsageReport,
        UsageTotals, WorkspaceRole,
    },
    test_config,
};
use reqwest::Url;

#[test]
fn callback_binding_requires_the_browser_that_started_the_flow() {
    let cookie = super::flow_cookie("encrypted-state-from-browser-a");
    let text = cookie.to_str().unwrap();
    for attribute in [
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Max-Age=600",
    ] {
        assert!(text.contains(attribute));
    }
    assert!(!text.contains("encrypted-state"));
    let mut headers = HeaderMap::new();
    assert!(!super::browser_started_flow(
        &headers,
        Some("encrypted-state-from-browser-a")
    ));
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(text.split(';').next().unwrap()).unwrap(),
    );
    assert!(super::browser_started_flow(
        &headers,
        Some("encrypted-state-from-browser-a")
    ));
    assert!(!super::browser_started_flow(
        &headers,
        Some("encrypted-state-from-browser-b")
    ));
    assert!(!super::browser_started_flow(&headers, None));
    assert!(!super::browser_started_flow(&headers, Some("")));
    headers.append(header::COOKIE, headers[header::COOKIE].clone());
    assert!(!super::browser_started_flow(
        &headers,
        Some("encrypted-state-from-browser-a")
    ));
}

fn connection() -> OrganizationOidcConnection {
    OrganizationOidcConnection {
        organization_id: "org_acme".into(),
        issuer: "https://id.example.test/acme".into(),
        client_id: "firewall-console".into(),
        redirect_uri: "https://console.example.test/auth/oidc/callback".into(),
        active: true,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn endpoints() -> ValidatedEndpoints {
    ValidatedEndpoints {
        authorization_endpoint: Url::parse("https://id.example.test/authorize?tenant=acme")
            .unwrap(),
        token_endpoint: Url::parse("https://id.example.test/token").unwrap(),
        jwks_uri: Url::parse("https://id.example.test/keys").unwrap(),
    }
}

fn test_state(store: TenantStore, cipher: OidcStateCipher) -> Arc<AppState> {
    let config = test_config("http://127.0.0.1:1".into());
    Arc::new(AppState {
        firewall: Firewall::new(
            vec![Box::new(InjectionDetector::new())],
            PolicySet::from_yaml("default: allow").unwrap(),
        ),
        http: reqwest::Client::new(),
        openai_api_key: None,
        proxy_auth_token: None,
        tenant_store: Some(store),
        admin_token: None,
        oidc_state_cipher: Some(cipher),
        saml: None,
        rate_limiter: std::sync::Mutex::new(
            crate::rate_limit::RateLimiter::new(Default::default()),
        ),
        spend_ledger: std::sync::Mutex::new(crate::spend_limit::SpendLedger::new(
            Default::default(),
        )),
        redis_limits: None,
        agent: std::sync::Mutex::new(soup_wall_agent::AgentFirewall::with_default_policy()),
        moderation: crate::moderation::ModerationGate::new(Default::default()),
        config,
    })
}

#[test]
fn authorization_redirect_uses_only_fixed_protocol_parameters() {
    let connection = connection();
    let pair = PkcePair::generate();
    let url = authorization_url(&endpoints(), &connection, "sealed-state", &pair, "nonce").unwrap();
    let values = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
        values.get("tenant").map(|value| value.as_ref()),
        Some("acme")
    );
    assert_eq!(
        values.get("response_type").map(|value| value.as_ref()),
        Some("code")
    );
    assert_eq!(
        values.get("client_id").map(|value| value.as_ref()),
        Some("firewall-console")
    );
    assert_eq!(
        values.get("redirect_uri").map(|value| value.as_ref()),
        Some("https://console.example.test/auth/oidc/callback")
    );
    assert_eq!(
        values.get("scope").map(|value| value.as_ref()),
        Some("openid")
    );
    assert_eq!(
        values.get("state").map(|value| value.as_ref()),
        Some("sealed-state")
    );
    assert_eq!(
        values.get("nonce").map(|value| value.as_ref()),
        Some("nonce")
    );
    assert_eq!(
        values
            .get("code_challenge_method")
            .map(|value| value.as_ref()),
        Some("S256")
    );
    assert_eq!(
        values.get("code_challenge").map(|value| value.as_ref()),
        Some(pair.code_challenge())
    );
}

#[test]
fn start_login_rejects_a_configuration_that_cannot_return_to_the_proxy() {
    let mut connection = connection();
    connection.redirect_uri = "https://console.example.test/welcome".into();
    assert!(callback_path(&connection).is_err());
    assert!(authorization_url(
        &endpoints(),
        &connection,
        "state",
        &PkcePair::generate(),
        "nonce"
    )
    .is_err());
}

#[test]
fn invoice_preview_is_never_final_and_flags_incomplete_evidence() {
    let preview = CustomerInvoicePreview::from(UsageReport {
        from_unix: 10,
        until_unix: 20,
        totals: UsageTotals {
            request_count: 1,
            missing_token_events: 1,
            unpriced_events: 1,
            ..UsageTotals::default()
        },
        daily: Vec::new(),
        models: Vec::new(),
        reconciliation: UsageReconciliationReadiness {
            review_required_events: 1,
            ..UsageReconciliationReadiness::default()
        },
    });
    let json = serde_json::to_value(preview).unwrap();
    assert_eq!(json["status"], "review_required");
    assert_eq!(json["is_final"], false);
    assert_eq!(json["notice"], "Preview only. Final invoices require provider reconciliation, tax/privacy review, and an explicit billing workflow.");
}

#[tokio::test]
async fn local_idp_callback_verifies_token_and_creates_single_use_browser_session() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store.create_organization("Local IdP organization").unwrap();
    let issuer = "https://id.local.test/acme";
    store
        .set_organization_oidc_connection(
            &organization.id,
            issuer,
            "firewall-console",
            "https://console.example.test/auth/oidc/callback",
            true,
        )
        .unwrap();
    let tenant = store
        .create_tenant_in_organization(&organization.id, "Local IdP tenant")
        .unwrap();
    let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
    let principal = store
        .create_workspace_principal("Local IdP customer")
        .unwrap();
    store
        .link_workspace_external_identity(&principal.id, issuer, "local-subject")
        .unwrap();
    store
        .set_workspace_membership(&workspace.id, &principal.id, WorkspaceRole::Analyst)
        .unwrap();

    let cipher = OidcStateCipher::from_base64url_key(&URL_SAFE_NO_PAD.encode([11_u8; 32])).unwrap();
    let pkce = PkcePair::generate();
    let nonce = "local-idp-nonce";
    let expires_at_unix = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
        + 600;
    let state_value = cipher
        .seal_authorization_state(
            &organization.id,
            &workspace.id,
            &pkce,
            nonce,
            expires_at_unix,
        )
        .unwrap();
    store
        .reserve_oidc_authorization_state(&state_value, &organization.id, expires_at_unix)
        .unwrap();

    let (id_token, jwks) = crate::oidc_token::tests::signed_local_id_token(
        issuer,
        "local-subject",
        "firewall-console",
        nonce,
    );
    let provider = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .expect(1)
        .mount(&provider)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=local-code"))
        .and(body_string_contains("client_id=firewall-console"))
        .and(body_string_contains(format!(
            "code_verifier={}",
            pkce.code_verifier()
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id_token": id_token })),
        )
        .expect(1)
        .mount(&provider)
        .await;
    let endpoints = ValidatedEndpoints {
        authorization_endpoint: reqwest::Url::parse(&format!("{}/authorize", provider.uri()))
            .unwrap(),
        token_endpoint: reqwest::Url::parse(&format!("{}/token", provider.uri())).unwrap(),
        jwks_uri: reqwest::Url::parse(&format!("{}/jwks", provider.uri())).unwrap(),
    };
    let client = OidcHttpClient::for_local_test_provider(endpoints).unwrap();
    let state = test_state(store, cipher);

    let response = callback_with_client(
        state.clone(),
        CallbackQuery {
            state: Some(state_value.clone()),
            code: Some("local-code".into()),
            error: None,
        },
        client.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/customer");
    let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.contains("; HttpOnly"));
    assert!(set_cookie.contains("; Secure"));
    let session_token = set_cookie
        .strip_prefix("__Host-llm-fw-session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let session = state
        .tenant_store
        .as_ref()
        .unwrap()
        .authenticate_oidc_browser_session(session_token)
        .unwrap()
        .unwrap();
    assert_eq!(session.access.organization_id, organization.id);
    assert_eq!(session.access.workspace_id, workspace.id);
    assert_eq!(session.access.principal_id, principal.id);
    assert_eq!(session.access.role, WorkspaceRole::Analyst);

    let replay = callback_with_client(
        state,
        CallbackQuery {
            state: Some(state_value),
            code: Some("local-code".into()),
            error: None,
        },
        client,
    )
    .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn local_idp_callback_consumes_invitation_and_creates_membership() {
    let store = TenantStore::open(":memory:").unwrap();
    let organization = store
        .create_organization("Local invitation organization")
        .unwrap();
    let issuer = "https://id.local.test/invitations";
    store
        .set_organization_oidc_connection(
            &organization.id,
            issuer,
            "firewall-console",
            "https://console.example.test/auth/oidc/callback",
            true,
        )
        .unwrap();
    let tenant = store
        .create_tenant_in_organization(&organization.id, "Local invitation tenant")
        .unwrap();
    let workspace = store.workspace_for_tenant(&tenant.id).unwrap().unwrap();
    let owner = store
        .create_workspace_principal("Local invitation owner")
        .unwrap();
    store
        .set_workspace_membership(&workspace.id, &owner.id, WorkspaceRole::Owner)
        .unwrap();
    let issued = store
        .create_workspace_invitation_as_owner(
            &workspace.id,
            &owner.id,
            "Invited developer",
            WorkspaceRole::Developer,
            super::now_unix().unwrap() + 600,
        )
        .unwrap();

    let cipher = OidcStateCipher::from_base64url_key(&URL_SAFE_NO_PAD.encode([13_u8; 32])).unwrap();
    let pkce = PkcePair::generate();
    let nonce = "local-invitation-nonce";
    let expires_at_unix = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
        + 600;
    let state_value = cipher
        .seal_authorization_state_with_invitation(
            &organization.id,
            &workspace.id,
            Some(&issued.invitation.id),
            &pkce,
            nonce,
            expires_at_unix,
        )
        .unwrap();
    store
        .reserve_oidc_authorization_state(&state_value, &organization.id, expires_at_unix)
        .unwrap();

    let (id_token, jwks) = crate::oidc_token::tests::signed_local_id_token(
        issuer,
        "local-invitation-subject",
        "firewall-console",
        nonce,
    );
    let provider = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .expect(1)
        .mount(&provider)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=invitation-code"))
        .and(body_string_contains("client_id=firewall-console"))
        .and(body_string_contains(format!(
            "code_verifier={}",
            pkce.code_verifier()
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id_token": id_token })),
        )
        .expect(1)
        .mount(&provider)
        .await;
    let endpoints = ValidatedEndpoints {
        authorization_endpoint: reqwest::Url::parse(&format!("{}/authorize", provider.uri()))
            .unwrap(),
        token_endpoint: reqwest::Url::parse(&format!("{}/token", provider.uri())).unwrap(),
        jwks_uri: reqwest::Url::parse(&format!("{}/jwks", provider.uri())).unwrap(),
    };
    let client = OidcHttpClient::for_local_test_provider(endpoints).unwrap();
    let state = test_state(store, cipher);

    let response = callback_with_client(
        state.clone(),
        CallbackQuery {
            state: Some(state_value),
            code: Some("invitation-code".into()),
            error: None,
        },
        client,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    let session_token = set_cookie
        .strip_prefix("__Host-llm-fw-session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let session = state
        .tenant_store
        .as_ref()
        .unwrap()
        .authenticate_oidc_browser_session(session_token)
        .unwrap()
        .unwrap();
    assert_eq!(session.access.organization_id, organization.id);
    assert_eq!(session.access.workspace_id, workspace.id);
    assert_eq!(session.access.role, WorkspaceRole::Developer);
    assert_ne!(session.access.principal_id, owner.id);
    assert!(state
        .tenant_store
        .as_ref()
        .unwrap()
        .workspace_invitation_for_token(&issued.token)
        .unwrap()
        .is_none());
    let access = state
        .tenant_store
        .as_ref()
        .unwrap()
        .verified_identity_workspace_access(
            &organization.id,
            &workspace.id,
            issuer,
            "local-invitation-subject",
        )
        .unwrap()
        .unwrap();
    assert_eq!(access.principal_id, session.access.principal_id);
    assert_eq!(access.role, WorkspaceRole::Developer);
}

#[test]
fn browser_session_cookie_is_host_scoped_and_not_accepted_from_another_name() {
    let cookie = session_cookie("opaque-session", 60).unwrap();
    let cookie = cookie.to_str().unwrap();
    assert!(cookie.starts_with("__Host-llm-fw-session=opaque-session; Path=/"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(!cookie.contains("Domain="));

    let mut headers = HeaderMap::new();
    headers.append(
        header::COOKIE,
        HeaderValue::from_static("other=opaque-session; __Host-llm-fw-session=accepted"),
    );
    assert_eq!(session_cookie_token(&headers), Some("accepted"));
    headers.append(
        header::COOKIE,
        HeaderValue::from_static("__Host-llm-fw-session=duplicate"),
    );
    assert_eq!(session_cookie_token(&headers), None);
    let mut wrong_name = HeaderMap::new();
    wrong_name.append(
        header::COOKIE,
        HeaderValue::from_static("session=opaque-session"),
    );
    assert_eq!(session_cookie_token(&wrong_name), None);
    assert!(session_cookie("line\nbreak", 60).is_err());
    assert!(session_cookie("token;injection", 60).is_err());
    assert!(session_cookie("token", 0).is_err());
    assert!(expired_session_cookie()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
}
