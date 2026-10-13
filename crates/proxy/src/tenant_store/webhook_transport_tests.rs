// SPDX-License-Identifier: Apache-2.0

//! Loopback transport fixtures are confined to the unit-test binary. They
//! exercise the shared HTTP sender without relaxing production destination rules.

use super::*;
use axum::http::{header::LOCATION, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::{TcpListener, TcpSocket};
use tokio::task::JoinHandle;

fn fixture_pending() -> PendingWebhookDelivery {
    PendingWebhookDelivery {
        delivery: WebhookDelivery {
            id: "delivery_transport_fixture".into(),
            tenant_id: "tenant_transport_fixture".into(),
            event_id: "event_transport_fixture".into(),
            destination_id: "destination_transport_fixture".into(),
            status: WebhookDeliveryStatus::InFlight,
            attempt_count: 1,
            next_attempt_at_unix: 1,
            locked_until_unix: Some(i64::MAX),
            delivered_at_unix: None,
            last_http_status: None,
            last_error: None,
            created_at_unix: 1,
        },
        destination: WebhookDestination {
            id: "destination_transport_fixture".into(),
            tenant_id: "tenant_transport_fixture".into(),
            url: "https://hooks.example.test/events".into(),
            event_types: vec![WEBHOOK_POLICY_DEPLOYED_EVENT.into()],
            active: true,
            created_at_unix: 1,
            updated_at_unix: 1,
        },
        event: TenantSecurityEvent {
            id: "event_transport_fixture".into(),
            tenant_id: "tenant_transport_fixture".into(),
            sequence: 1,
            event_type: WEBHOOK_POLICY_DEPLOYED_EVENT.into(),
            payload: serde_json::json!({"fixture": true}),
            content_sha256: "0".repeat(64),
            occurred_at_unix: 1,
        },
    }
}

fn fixture_key() -> WebhookSigningKey {
    WebhookSigningKey::from_base64url(&base64url(&[23; 32])).unwrap()
}

async fn receiver(
    status: StatusCode,
    redirect: Option<String>,
    delay: Duration,
    hits: Arc<AtomicUsize>,
) -> (Url, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}/events", listener.local_addr().unwrap())).unwrap();
    let app = Router::new().fallback(move || {
        let hits = hits.clone();
        let redirect = redirect.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            let mut response = (status, "private-receiver-body-must-not-be-stored").into_response();
            if let Some(location) = redirect {
                response
                    .headers_mut()
                    .insert(LOCATION, HeaderValue::from_str(&location).unwrap());
            }
            response
        }
    });
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, task)
}

fn fixture_client(timeout: Duration) -> Client {
    Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(timeout)
        .build()
        .unwrap()
}

#[test]
fn webhook_transport_destination_rules_remain_strict() {
    for rejected in [
        "http://hooks.example.test/events",
        "https://user:password@hooks.example.test/events",
        "https://hooks.example.test/events?secret=fixture",
        "https://hooks.example.test/events#fragment",
        "https://localhost/events",
        "https://localhost./events",
        "https://child.localhost/events",
        "https://child.localhost./events",
        "https://metadata.google.internal/events",
        "https://metadata.google.internal./events",
        "https://127.0.0.1/events",
        "https://8.8.8.8/events",
        "https://[::1]/events",
        "https://[2606:4700:4700::1111]/events",
    ] {
        assert!(
            validate_webhook_destination_url(rejected).is_err(),
            "accepted restricted destination: {rejected}"
        );
    }
    assert_eq!(
        validate_webhook_destination_url("https://hooks.example.test/events").unwrap(),
        "https://hooks.example.test/events"
    );
}

#[test]
fn webhook_transport_public_addresses_reject_private_mapped_and_full_cgnat_range() {
    for rejected in [
        "127.0.0.1:443",
        "10.0.0.1:443",
        "172.16.0.1:443",
        "192.168.0.1:443",
        "169.254.169.254:443",
        "0.0.0.0:443",
        "224.0.0.1:443",
        "255.255.255.255:443",
        "100.64.0.0:443",
        "100.65.1.2:443",
        "100.127.255.255:443",
        "198.18.0.1:443",
        "198.19.255.254:443",
        "[::1]:443",
        "[::]:443",
        "[fc00::1]:443",
        "[fe80::1]:443",
        "[ff02::1]:443",
        "[::ffff:127.0.0.1]:443",
        "[::ffff:10.0.0.1]:443",
        "[::ffff:8.8.8.8]:443",
    ] {
        assert!(
            !is_public_socket_address(rejected.parse().unwrap()),
            "accepted restricted socket address: {rejected}"
        );
    }
    for permitted in [
        "100.63.255.255:443",
        "100.128.0.0:443",
        "8.8.8.8:443",
        "[2606:4700:4700::1111]:443",
    ] {
        assert!(
            is_public_socket_address(permitted.parse().unwrap()),
            "rejected public boundary address: {permitted}"
        );
    }
}

#[tokio::test]
async fn webhook_transport_revalidates_stored_destinations_before_sending() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (url, server) = receiver(StatusCode::OK, None, Duration::ZERO, hits.clone()).await;
    let mut pending = fixture_pending();
    pending.destination.url = url.to_string();
    let result = deliver_webhook(
        &fixture_client(Duration::from_secs(2)),
        &fixture_key(),
        &pending,
    )
    .await;
    assert_eq!(result.http_status, None);
    assert_eq!(
        result.error.as_deref(),
        Some("webhook destination is invalid")
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn webhook_transport_redirects_are_not_followed_or_stored_as_success() {
    let trap_hits = Arc::new(AtomicUsize::new(0));
    let (trap_url, trap) = receiver(StatusCode::OK, None, Duration::ZERO, trap_hits.clone()).await;
    let client = fixture_client(Duration::from_secs(2));
    for status in [StatusCode::MOVED_PERMANENTLY, StatusCode::FOUND] {
        let source_hits = Arc::new(AtomicUsize::new(0));
        let (url, source) = receiver(
            status,
            Some(trap_url.to_string()),
            Duration::ZERO,
            source_hits.clone(),
        )
        .await;
        let result = send_webhook_request(&client, url, &fixture_key(), &fixture_pending()).await;
        assert_eq!(result.http_status, Some(status.as_u16()));
        assert_eq!(
            result.error,
            Some(format!(
                "webhook endpoint returned HTTP {}",
                status.as_u16()
            ))
        );
        assert_eq!(source_hits.load(Ordering::SeqCst), 1);
        assert_eq!(trap_hits.load(Ordering::SeqCst), 0);
        source.abort();
    }
    trap.abort();
}

#[tokio::test]
async fn webhook_transport_timeout_is_bounded_and_does_not_disclose_request_url() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (mut url, server) =
        receiver(StatusCode::OK, None, Duration::from_secs(2), hits.clone()).await;
    // A deliberately sensitive test-only URL checks error redaction. Production
    // destination validation rejects query strings before this HTTP boundary.
    url.set_query(Some("secret=timeout-fixture-secret"));
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        send_webhook_request(
            &fixture_client(Duration::from_millis(200)),
            url,
            &fixture_key(),
            &fixture_pending(),
        ),
    )
    .await
    .expect("request exceeded the bounded fixture deadline");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(result.http_status, None);
    assert_eq!(result.error.as_deref(), Some("webhook request timed out"));
    server.abort();
}

#[tokio::test]
async fn webhook_transport_connection_failure_is_bounded_and_sanitized() {
    // Reserve a socket without listening, avoiding a released-port race with
    // another test. Some OSes refuse immediately; others time out a socket
    // that is bound but not listening. Both must remain bounded and sanitized.
    let reserved = TcpSocket::new_v4().unwrap();
    reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let url = Url::parse(&format!(
        "http://{}/events?secret=connection-fixture-secret",
        reserved.local_addr().unwrap()
    ))
    .unwrap();
    let result = send_webhook_request(
        &fixture_client(Duration::from_secs(2)),
        url,
        &fixture_key(),
        &fixture_pending(),
    )
    .await;
    assert_eq!(result.http_status, None);
    assert!(matches!(
        result.error.as_deref(),
        Some("webhook connection failed" | "webhook request timed out")
    ));
    drop(reserved);
}

#[tokio::test]
async fn webhook_transport_http_failure_does_not_store_receiver_body() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (url, server) = receiver(
        StatusCode::SERVICE_UNAVAILABLE,
        None,
        Duration::ZERO,
        hits.clone(),
    )
    .await;
    let result = send_webhook_request(
        &fixture_client(Duration::from_secs(2)),
        url,
        &fixture_key(),
        &fixture_pending(),
    )
    .await;
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(result.http_status, Some(503));
    assert_eq!(
        result.error.as_deref(),
        Some("webhook endpoint returned HTTP 503")
    );
    server.abort();
}
