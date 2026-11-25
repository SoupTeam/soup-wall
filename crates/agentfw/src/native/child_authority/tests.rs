// SPDX-License-Identifier: Apache-2.0
use super::*;

fn fixture() -> (Vec<u8>, ChildAuthorityGrant) {
    let key = derive_key("test-only-daemon-token");
    let grant = mint(
        &key,
        "host",
        "server",
        &["read".into(), "search".into()],
        10_000,
        20_000,
        crate::token::generate(),
    );
    (key, grant)
}

#[test]
fn token_round_trip_and_verification() {
    let (key, grant) = fixture();
    let token = encode_token(&grant);
    assert!(token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)));
    assert_eq!(decode_token(&token), Ok(grant.clone()));
    assert_eq!(
        verify_token(&key, &token, "host", "server", 10_000),
        Ok(grant.clone())
    );
    assert_eq!(verify(&key, &grant, "host", "server", 29_999), Ok(()));
}

#[test]
fn key_derivation_known_vector_and_separation() {
    // Independently generated HMAC-SHA256 vector (key = daemon token).
    let key = derive_key("test-only-daemon-token");
    assert_eq!(
        key,
        [
            122, 238, 143, 186, 50, 216, 24, 83, 188, 103, 30, 85, 13, 117, 211, 180, 137, 130, 65,
            3, 16, 169, 104, 245, 196, 1, 87, 248, 207, 47, 83, 128
        ]
    );
    assert_eq!(key, derive_key("test-only-daemon-token"));
    assert_ne!(key, derive_key("other-token"));
    assert_ne!(key, crate::grant::derive_key("test-only-daemon-token"));
}

#[test]
fn expiry_and_future_skew_boundaries() {
    let (key, grant) = fixture();
    assert_eq!(
        verify(&key, &grant, "host", "server", 30_000),
        Err(ChildAuthorityError::Expired)
    );
    assert_eq!(
        verify(&key, &grant, "host", "server", 30_001),
        Err(ChildAuthorityError::Expired)
    );
    assert_eq!(verify(&key, &grant, "host", "server", 5_000), Ok(()));
    assert_eq!(
        verify(&key, &grant, "host", "server", 4_999),
        Err(ChildAuthorityError::NotYetValid)
    );
    let zero = mint(
        &key,
        "host",
        "server",
        &[],
        10_000,
        0,
        crate::token::generate(),
    );
    assert_eq!(
        verify(&key, &zero, "host", "server", 10_000),
        Err(ChildAuthorityError::Expired)
    );
    let overflow = mint(
        &key,
        "host",
        "server",
        &[],
        u64::MAX - 1,
        10,
        crate::token::generate(),
    );
    assert_eq!(overflow.expires_at_ms, u64::MAX);
    assert_eq!(
        verify(&key, &overflow, "host", "server", u64::MAX - 1),
        Ok(())
    );
    assert_eq!(
        verify(&key, &overflow, "host", "server", u64::MAX),
        Err(ChildAuthorityError::Expired)
    );
}

#[test]
fn rejects_mismatched_authority_and_wrong_key() {
    let (key, grant) = fixture();
    for (host, server, error) in [
        ("other", "server", ChildAuthorityError::HostSessionMismatch),
        ("host", "other", ChildAuthorityError::ServerIdMismatch),
    ] {
        assert_eq!(
            verify_token(&key, &encode_token(&grant), host, server, 10_000),
            Err(error)
        );
    }
    assert_eq!(
        verify(b"wrong-key", &grant, "host", "server", 10_000),
        Err(ChildAuthorityError::BadSignature)
    );
}

#[test]
fn every_claim_is_authenticated() {
    let (key, grant) = fixture();
    let original = serde_json::to_value(&grant).unwrap();
    for (field, value) in [
        ("contract_version", serde_json::json!("other")),
        ("host_session", serde_json::json!("other")),
        ("server_id", serde_json::json!("other")),
        ("granted_tools", serde_json::json!(["admin"])),
        ("issued_at_ms", serde_json::json!(11_000)),
        ("expires_at_ms", serde_json::json!(40_000)),
        ("nonce", serde_json::json!(crate::token::generate())),
        ("agent_id", serde_json::json!("injected-agent")),
        ("parent_id", serde_json::json!("injected-parent")),
        ("granted_resources", serde_json::json!(["/etc/passwd"])),
        ("signature", serde_json::json!("")),
        (
            "signature",
            serde_json::json!("A".repeat(grant.signature.len())),
        ),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        let changed: ChildAuthorityGrant = serde_json::from_value(changed).unwrap();
        assert_eq!(
            verify(&key, &changed, "host", "server", 10_000),
            Err(ChildAuthorityError::BadSignature),
            "{field}"
        );
    }

    let scoped = mint_scoped(
        &key,
        "host",
        "server",
        &["read".into()],
        10_000,
        20_000,
        crate::token::generate(),
        Some("sub-agent-1".into()),
        Some("main-agent".into()),
        Some(vec!["workspace/docs".into(), "127.0.0.1".into()]),
    );
    let token = encode_token(&scoped);
    assert_eq!(
        verify_token(&key, &token, "host", "server", 10_000),
        Ok(scoped.clone())
    );

    let scoped_val = serde_json::to_value(&scoped).unwrap();
    for (field, value) in [
        ("agent_id", serde_json::json!("other-agent")),
        ("parent_id", serde_json::json!("other-parent")),
        ("granted_resources", serde_json::json!(["/other/path"])),
    ] {
        let mut changed = scoped_val.clone();
        changed[field] = value;
        let changed: ChildAuthorityGrant = serde_json::from_value(changed).unwrap();
        assert_eq!(
            verify(&key, &changed, "host", "server", 10_000),
            Err(ChildAuthorityError::BadSignature),
            "scoped {field}"
        );
    }
}

#[test]
fn rejects_authenticated_invalid_contract_and_interval() {
    let (key, mut grant) = fixture();
    grant.contract_version = "sw-child-authority/2".into();
    grant.signature = sign(&key, &grant);
    assert_eq!(
        verify(&key, &grant, "host", "server", 10_000),
        Err(ChildAuthorityError::InvalidContract)
    );
    grant.contract_version = CHILD_AUTHORITY_CONTRACT.into();
    grant.expires_at_ms = grant.issued_at_ms - 1;
    grant.signature = sign(&key, &grant);
    assert_eq!(
        verify(&key, &grant, "host", "server", 10_000),
        Err(ChildAuthorityError::MalformedToken)
    );
}

#[test]
fn rejects_malformed_wire_data() {
    let (key, grant) = fixture();
    let json = serde_json::to_string(&grant).unwrap();
    let extra = json.replacen('{', "{\"unknown\":true,", 1);
    let duplicate = json.replacen('{', "{\"host_session\":\"spoof\",", 1);
    for token in [
        String::new(),
        "%%%".into(),
        URL_SAFE_NO_PAD.encode(b"not json"),
        URL_SAFE_NO_PAD.encode(b"{}"),
        URL_SAFE_NO_PAD.encode(b"null"),
        URL_SAFE_NO_PAD.encode(extra),
        URL_SAFE_NO_PAD.encode(duplicate),
        URL_SAFE_NO_PAD.encode(json.replace("10000", "-1")),
    ] {
        assert_eq!(
            decode_token(&token),
            Err(ChildAuthorityError::MalformedToken)
        );
        assert_eq!(
            verify_token(&key, &token, "host", "server", 10_000),
            Err(ChildAuthorityError::MalformedToken)
        );
    }
}

#[test]
fn signing_boundaries_cannot_be_shifted() {
    let (key, grant) = fixture();
    let mut signatures = std::collections::BTreeSet::new();
    for (host, server, tools) in [
        ("ab", "c", vec!["read".into()]),
        ("a", "bc", vec!["read".into()]),
        ("host", "server", vec!["ab".into(), "c".into()]),
        ("host", "server", vec!["a".into(), "bc".into()]),
        ("host", "server", vec![]),
        ("host", "server", vec!["".into()]),
        ("host", "server", vec!["read\0search".into()]),
        ("host", "server", vec!["read".into(), "search".into()]),
    ] {
        let candidate = mint(
            &key,
            host,
            server,
            &tools,
            grant.issued_at_ms,
            20_000,
            grant.nonce.clone(),
        );
        assert!(signatures.insert(candidate.signature));
    }
    let tools = |items: &[&str]| items.iter().map(|s| (*s).into()).collect::<Vec<String>>();
    let issue = |host, server, items: Vec<String>| {
        mint(
            &key,
            host,
            server,
            &items,
            10_000,
            20_000,
            grant.nonce.clone(),
        )
        .signature
    };
    assert_ne!(issue("ab", "c", tools(&[])), issue("a", "bc", tools(&[])));
    assert_ne!(
        issue("h", "s", tools(&["ab", "c"])),
        issue("h", "s", tools(&["a", "bc"]))
    );
    assert_ne!(issue("h", "s", tools(&[])), issue("h", "s", tools(&[""])));
}

#[test]
fn concurrent_verification_keeps_session_bindings_isolated() {
    let (key, grant) = fixture();
    let token = encode_token(&grant);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                assert_eq!(
                    verify_token(&key, &token, "host", "server", 10_000),
                    Ok(grant.clone())
                );
                assert_eq!(
                    verify_token(&key, &token, "spoof", "server", 10_000),
                    Err(ChildAuthorityError::HostSessionMismatch)
                );
            });
        }
    });
}

#[test]
fn reasons_are_distinct_and_nonempty() {
    let reasons = [
        ChildAuthorityError::BadSignature,
        ChildAuthorityError::Expired,
        ChildAuthorityError::NotYetValid,
        ChildAuthorityError::HostSessionMismatch,
        ChildAuthorityError::ServerIdMismatch,
        ChildAuthorityError::InvalidContract,
        ChildAuthorityError::MalformedToken,
    ]
    .map(|error| error.reason());
    assert!(reasons.iter().all(|reason| !reason.is_empty()));
    assert_eq!(
        reasons
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        7
    );
}
