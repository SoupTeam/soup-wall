// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)
use super::*;

fn authority(url: &str, address: &str) -> HttpsGetAuthority {
    HttpsGetAuthority {
        exact_url: url.to_owned(),
        approved_addresses: vec![address.parse().unwrap()],
        private_endpoint: None,
        root_certificate_pem: None,
    }
}

#[test]
fn exact_url_scope_rejects_parser_and_authority_aliases() {
    for bad in [
        "http://example.com/",
        "HTTPS://example.com/",
        "https://EXAMPLE.com/",
        "https://example.com:443/",
        "https://example.com",
        "https://example.com./",
        "https://user:secret@example.com/",
        "https://@example.com/",
        "https://example.com/#fragment",
        "https://example.com/%2e%2e/secrets",
        "https://example.com/a/../b",
        "https://example.com/\\evil",
        "https://example.com/?key=%41",
        "https://example.com/white space",
        "https://example.com/\n",
        "https://éxample.com/",
        "https://127.1/",
        "https://2130706433/",
        "https://0x7f000001/",
        "https://example.com:0/",
    ] {
        assert!(canonical_url(bad).is_err(), "accepted {bad:?}");
    }
    assert_eq!(
        canonical_url("https://example.com:8443/document?item=7").unwrap(),
        (
            "https://example.com:8443/document?item=7".to_owned(),
            "example.com".to_owned(),
            8443
        )
    );
}

#[test]
fn default_denies_private_reserved_and_embedded_addresses() {
    for address in [
        "0.1.2.3",
        "10.1.2.3",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.9",
        "192.0.2.3",
        "192.168.1.1",
        "198.18.1.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "2001::1",
        "2002:808:808::1",
        "3fff::1",
    ] {
        assert!(
            !is_public_address(address.parse().unwrap()),
            "allowed {address}"
        );
    }
    for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
        assert!(
            is_public_address(address.parse().unwrap()),
            "denied {address}"
        );
    }
}

#[test]
fn private_exception_is_exact_and_never_a_global_switch() {
    let mut a = authority("https://127.0.0.1:8443/document?item=7", "127.0.0.1");
    assert_eq!(a.validate().unwrap_err().code, "forbidden_address");
    a.private_endpoint = Some(PrivateEndpointException {
        host: "127.0.0.1".to_owned(),
        port: 8443,
        address: "127.0.0.1".parse().unwrap(),
    });
    assert!(a.validate().is_ok());
    for changed in [
        PrivateEndpointException {
            host: "localhost".to_owned(),
            ..a.private_endpoint.clone().unwrap()
        },
        PrivateEndpointException {
            port: 8444,
            ..a.private_endpoint.clone().unwrap()
        },
        PrivateEndpointException {
            address: "127.0.0.2".parse().unwrap(),
            ..a.private_endpoint.clone().unwrap()
        },
    ] {
        let mut substituted = a.clone();
        substituted.private_endpoint = Some(changed);
        assert_eq!(
            substituted.validate().unwrap_err().code,
            "invalid_private_exception"
        );
    }
}

#[test]
fn authority_is_closed_and_identity_binds_all_fields() {
    let a = authority("https://example.com/document?item=7", "8.8.8.8");
    let id = a.executor_id().unwrap();
    let mut b = a.clone();
    b.exact_url = "https://example.com/document?item=8".to_owned();
    assert_ne!(id, b.executor_id().unwrap());
    b = a.clone();
    b.approved_addresses = vec!["1.1.1.1".parse().unwrap()];
    assert_ne!(id, b.executor_id().unwrap());
    b.approved_addresses.push("8.8.8.8".parse().unwrap());
    assert_eq!(b.validate().unwrap_err().code, "unsupported_address_count");
    let mut json = serde_json::to_value(a).unwrap();
    json["danger_accept_invalid_certs"] = serde_json::json!(true);
    assert!(serde_json::from_value::<HttpsGetAuthority>(json).is_err());
    assert_eq!(executor_profile_sha256().len(), 64);
}

#[test]
fn literal_addresses_cannot_override_the_url() {
    let a = authority("https://8.8.8.8/", "1.1.1.1");
    assert_eq!(a.validate().unwrap_err().code, "address_substitution");
    let a = authority("https://[2606:4700:4700::1111]/", "2606:4700:4700::1111");
    assert!(a.validate().is_ok());
}

#[test]
fn response_scope_requires_one_explicit_utf8_text_or_json_type() {
    for accepted in [
        "text/plain",
        "text/plain; charset=utf-8",
        "application/json",
    ] {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, accepted.parse().unwrap());
        assert!(supported_content_type(&headers).is_ok());
    }
    for refused in [
        "text/html",
        "application/octet-stream",
        "text/plain; charset=latin1",
        "application/json; charset=UTF-8",
        "text/plain; charset=utf-8; x=y",
    ] {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, refused.parse().unwrap());
        assert_eq!(
            supported_content_type(&headers).unwrap_err().code,
            "unsupported_content_type"
        );
    }
    let mut headers = reqwest::header::HeaderMap::new();
    assert!(supported_content_type(&headers).is_err());
    headers.append(CONTENT_TYPE, "text/plain".parse().unwrap());
    headers.append(CONTENT_TYPE, "application/json".parse().unwrap());
    assert!(supported_content_type(&headers).is_err());
}

#[test]
fn errors_do_not_disclose_endpoint_or_response() {
    let error = HttpsGetError::issued("request_failed");
    assert_eq!(
        error.to_string(),
        "constrained HTTPS GET refused: code=request_failed request_issued=true"
    );
    let a = authority("https://example.com/", "8.8.8.8");
    assert!(a.validate().is_ok());
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn non_linux_never_dispatches() {
    let a = authority("https://example.com/", "8.8.8.8");
    let error = PreparedHttpsGet::prepare(&a, &a.exact_url)
        .await
        .unwrap_err();
    assert_eq!(error.code, "unsupported_platform");
    assert!(!error.request_issued);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn dns_and_exact_arguments_refuse_before_http_effect() {
    let a = authority("https://localhost.test:8443/", "8.8.8.8");
    let error = PreparedHttpsGet::prepare(&a, &a.exact_url)
        .await
        .unwrap_err();
    assert_eq!(error.code, "forbidden_address");
    assert!(!error.request_issued);
    let a = authority("https://127.0.0.1:8443/", "127.0.0.1");
    let error = PreparedHttpsGet::prepare(&a, "https://127.0.0.1:8444/")
        .await
        .unwrap_err();
    assert!(!error.request_issued);
}

#[test]
fn current_dns_must_equal_the_frozen_set() {
    let approved = ["8.8.8.8".parse().unwrap()];
    let mut same = vec![approved[0], approved[0]];
    assert!(verify_address_set(&mut same, &approved).is_ok());
    for mut changed in [
        vec![],
        vec!["1.1.1.1".parse().unwrap()],
        vec![approved[0], "1.1.1.1".parse().unwrap()],
        vec!["127.0.0.1".parse().unwrap()],
    ] {
        let error = verify_address_set(&mut changed, &approved).unwrap_err();
        assert_eq!(error.code, "dns_address_substitution");
        assert!(!error.request_issued);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn encrypted_reads_are_capped_before_polling_the_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let writer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = stream
            .write_all(&vec![0u8; MAX_HTTPS_ENCRYPTED_BYTES + 4096])
            .await;
    });
    let received = Arc::new(AtomicUsize::new(0));
    let mut counted = CountedSocket {
        socket,
        received: received.clone(),
    };
    let mut bytes = Vec::new();
    assert!(counted.read_to_end(&mut bytes).await.is_err());
    assert_eq!(bytes.len(), MAX_HTTPS_ENCRYPTED_BYTES);
    assert_eq!(received.load(Ordering::Relaxed), MAX_HTTPS_ENCRYPTED_BYTES);
    drop(counted);
    writer.await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn preparation_and_substitution_do_not_open_a_target_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("https://127.0.0.1:{}/document?item=7", address.port());
    let mut a = authority(&url, "127.0.0.1");
    a.private_endpoint = Some(PrivateEndpointException {
        host: "127.0.0.1".to_owned(),
        port: address.port(),
        address: address.ip(),
    });
    let prepared = PreparedHttpsGet::prepare(&a, &url).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    drop(prepared);
    let replaced = url.replace("item=7", "item=8");
    let error = PreparedHttpsGet::prepare(&a, &replaced).await.unwrap_err();
    assert_eq!(error.code, "url_substitution");
    assert!(!error.request_issued);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn invalid_tls_is_refused_after_one_connection_attempt() {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("https://127.0.0.1:{}/", address.port());
    let mut a = authority(&url, "127.0.0.1");
    a.private_endpoint = Some(PrivateEndpointException {
        host: "127.0.0.1".to_owned(),
        port: address.port(),
        address: address.ip(),
    });
    let prepared = PreparedHttpsGet::prepare(&a, &url).await.unwrap();
    let receiver = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        connection.write_all(b"not TLS").await.unwrap();
        connection.shutdown().await.unwrap();
        drop(connection);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    });
    let error = prepared.execute().await.unwrap_err();
    assert_eq!(error.code, "tls_verification_failed");
    assert!(!error.request_issued);
    receiver.await.unwrap();
}

#[test]
fn strict_response_framing_refuses_unsupported_or_ambiguous_material() {
    let valid = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n";
    assert_eq!(
        parse_response_head(valid).unwrap(),
        ("text/plain".to_owned(), 2)
    );
    for refused in [
        "HTTP/1.1 100 Continue\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: https://evil.test/\r\n\r\n",
        "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 02\r\nContent-Type: text/plain\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 4097\r\nContent-Type: text/plain\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n",
    ] {
        assert!(parse_response_head(refused.as_bytes()).is_err(), "accepted {refused:?}");
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn complete_body_read_refuses_short_extra_and_oversized_headers() {
    let valid = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok";
    let mut input = valid.as_slice();
    let (mime, bytes, count) = read_response(&mut input).await.unwrap();
    assert_eq!(mime, "text/plain");
    assert_eq!(bytes, b"ok");
    assert_eq!(count, valid.len());
    let mut short = &valid[..valid.len() - 1];
    assert_eq!(
        read_response(&mut short).await.unwrap_err().code,
        "incomplete_response_body"
    );
    let mut extra = [valid.as_slice(), b"extra"].concat();
    assert_eq!(
        read_response(&mut extra.as_slice()).await.unwrap_err().code,
        "unexpected_response_bytes"
    );
    extra = [
        b"HTTP/1.1 200 OK\r\nX-Huge: ".as_slice(),
        &vec![b'x'; MAX_HTTPS_HEADER_BYTES],
    ]
    .concat();
    assert_eq!(
        read_response(&mut extra.as_slice()).await.unwrap_err().code,
        "response_headers_too_large"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn maximum_complete_body_is_accepted_without_truncation() {
    let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {MAX_HTTPS_BODY_BYTES}\r\nContent-Type: text/plain\r\n\r\n");
    let input = [header.as_bytes(), &vec![b'x'; MAX_HTTPS_BODY_BYTES]].concat();
    let (mime, body, received) = read_response(&mut input.as_slice()).await.unwrap();
    assert_eq!(mime, "text/plain");
    assert_eq!(body, vec![b'x'; MAX_HTTPS_BODY_BYTES]);
    assert_eq!(received, input.len());
    assert!(received <= MAX_HTTPS_HTTP_BYTES);
    let oversized = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n",
        MAX_HTTPS_BODY_BYTES + 1
    );
    assert_eq!(
        read_response(&mut oversized.as_bytes())
            .await
            .unwrap_err()
            .code,
        "response_too_large"
    );
}

#[test]
fn metadata_and_special_ranges_cannot_use_private_fixture_exception() {
    for address in [
        "169.254.169.254",
        "198.18.0.1",
        "192.0.2.1",
        "8.8.8.8",
        "fe80::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(
            !exception_address_supported(address.parse().unwrap()),
            "accepted {address}"
        );
    }
    for address in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.1.2",
        "192.168.1.2",
        "::1",
        "fd00::1",
    ] {
        assert!(
            exception_address_supported(address.parse().unwrap()),
            "refused {address}"
        );
    }
    let a = authority("https://localhost/", "8.8.8.8");
    assert_eq!(a.validate().unwrap_err().code, "forbidden_address");
}
