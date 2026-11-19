// SPDX-License-Identifier: Apache-2.0
use super::*;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

fn fixture() -> (SignedAgentPolicy, PinnedIssuerKey) {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap();
    let yaml = "default: deny\n".to_string();
    let mut bundle = SignedAgentPolicy {
        schema_version: 1,
        tenant_id: "tenant-1".into(),
        agent_id: "agent-1".into(),
        revision: "approved-v1".into(),
        deployment_sequence: 1,
        issued_at_unix: 1000,
        expires_at_unix: 2000,
        issuer_key_id: "issuer-1".into(),
        policy_sha256: hex_lower(&Sha256::digest(yaml.as_bytes())),
        policy_yaml: yaml,
        signature_hex: String::new(),
    };
    bundle.signature_hex = hex_lower(pair.sign(&bundle.signing_transcript().unwrap()).as_ref());
    let key = PinnedIssuerKey {
        key_id: "issuer-1".into(),
        public_key: pair.public_key().as_ref().try_into().unwrap(),
        revoked: false,
    };
    (bundle, key)
}

fn verify(
    bundle: &SignedAgentPolicy,
    key: &PinnedIssuerKey,
    seq: u64,
) -> Result<VerifiedAgentPolicy> {
    verify_candidate(
        bundle,
        std::slice::from_ref(key),
        "tenant-1",
        "agent-1",
        seq,
        1500,
    )
}

#[test]
fn valid_signed_agent_policy_is_verified() {
    let (bundle, key) = fixture();
    let result = verify(&bundle, &key, 0).unwrap();
    assert_eq!(result.revision, "approved-v1");
    assert_eq!(result.deployment_sequence, 1);
    assert_eq!(result.policy_sha256, bundle.policy_sha256);
}

#[test]
fn rejects_policy_tampering() {
    let (mut bundle, key) = fixture();
    bundle.policy_yaml = "default: allow\n".into();
    assert!(verify(&bundle, &key, 0).is_err());
}

#[test]
fn rejects_signed_metadata_tampering() {
    let (mut bundle, key) = fixture();
    bundle.revision = "approved-v2".into();
    assert!(verify(&bundle, &key, 0).is_err());
}

#[test]
fn rejects_cross_tenant_or_agent() {
    let (bundle, key) = fixture();
    assert!(verify_candidate(
        &bundle,
        std::slice::from_ref(&key),
        "tenant-2",
        "agent-1",
        0,
        1500
    )
    .is_err());
    assert!(verify_candidate(
        &bundle,
        std::slice::from_ref(&key),
        "tenant-1",
        "agent-2",
        0,
        1500
    )
    .is_err());
}

#[test]
fn rejects_replay_and_stale_sequence() {
    let (bundle, key) = fixture();
    assert!(verify(&bundle, &key, 1).is_err());
    assert!(verify(&bundle, &key, 4).is_err());
}

#[test]
fn rejects_expiry_and_excessive_ttl() {
    let (mut bundle, key) = fixture();
    assert!(verify_candidate(
        &bundle,
        std::slice::from_ref(&key),
        "tenant-1",
        "agent-1",
        0,
        2000
    )
    .is_err());
    bundle.expires_at_unix = 1_000_000;
    assert!(verify(&bundle, &key, 0).is_err());
}

#[test]
fn rejects_unknown_or_revoked_signing_key() {
    let (bundle, mut key) = fixture();
    key.key_id = "other".into();
    assert!(verify(&bundle, &key, 0).is_err());
    key.key_id = "issuer-1".into();
    key.revoked = true;
    assert!(verify(&bundle, &key, 0).is_err());
}

#[test]
fn rejects_invalid_signature() {
    let (mut bundle, key) = fixture();
    bundle.signature_hex = "00".repeat(64);
    assert!(verify(&bundle, &key, 0).is_err());
}

#[test]
fn rejects_unknown_fields_and_oversize_input() {
    let (bundle, _) = fixture();
    let mut json = serde_json::to_value(&bundle).unwrap();
    json["enforce"] = serde_json::json!(false);
    assert!(parse_bounded(&serde_json::to_vec(&json).unwrap()).is_err());
    assert!(parse_bounded(&vec![b'x'; MAX_BUNDLE_BYTES + 1]).is_err());
}

#[test]
fn rejects_invalid_policy_yaml_even_with_valid_signature() {
    let (mut bundle, key) = fixture();
    let pair = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap();
    bundle.policy_yaml = "default: escalate\n".into();
    bundle.policy_sha256 = hex_lower(&Sha256::digest(bundle.policy_yaml.as_bytes()));
    bundle.signature_hex = hex_lower(pair.sign(&bundle.signing_transcript().unwrap()).as_ref());
    assert!(verify(&bundle, &key, 0).is_err());
}

/// SOU-241: every rejection carries the finite code of its boundary,
/// while the existing local message stays the top-level error text.
#[test]
fn rejection_codes_come_from_the_failure_boundary() {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap();
    let resign = |b: &mut SignedAgentPolicy| {
        b.policy_sha256 = hex_lower(&Sha256::digest(b.policy_yaml.as_bytes()));
        b.signature_hex = hex_lower(pair.sign(&b.signing_transcript().unwrap()).as_ref());
    };
    let code = |b: &SignedAgentPolicy, k: &PinnedIssuerKey, seq: u64, now: i64| {
        let e = verify_candidate(b, std::slice::from_ref(k), "tenant-1", "agent-1", seq, now)
            .unwrap_err();
        (rejection_code(&e), e.to_string())
    };
    let (bundle, key) = fixture();
    assert_eq!(
        code(&bundle, &key, 0, 2000),
        (Some("bundle_expired"), "expired policy bundle".into())
    );
    assert_eq!(code(&bundle, &key, 0, 900).0, Some("issued_in_future"));
    assert_eq!(
        code(&bundle, &key, 1, 1500),
        (
            Some("sequence_stale"),
            "replayed or stale policy deployment".into()
        )
    );
    let mut other = key.clone();
    other.key_id = "other".into();
    assert_eq!(code(&bundle, &other, 0, 1500).0, Some("issuer_key_unknown"));
    let mut revoked = key.clone();
    revoked.revoked = true;
    assert_eq!(
        code(&bundle, &revoked, 0, 1500).0,
        Some("issuer_key_revoked")
    );
    let mut b = bundle.clone();
    b.signature_hex = "00".repeat(64);
    assert_eq!(code(&b, &key, 0, 1500).0, Some("signature_invalid"));
    b.signature_hex = "zz".into();
    assert_eq!(code(&b, &key, 0, 1500).0, Some("signature_invalid"));
    let mut b = bundle.clone();
    b.policy_yaml = "default: allow\n".into();
    assert_eq!(code(&b, &key, 0, 1500).0, Some("digest_mismatch"));
    let mut b = bundle.clone();
    b.tenant_id = "tenant-2".into();
    assert_eq!(code(&b, &key, 0, 1500).0, Some("audience_mismatch"));
    let mut b = bundle.clone();
    b.schema_version = 9;
    assert_eq!(code(&b, &key, 0, 1500).0, Some("schema_unsupported"));
    let mut b = bundle.clone();
    b.expires_at_unix = 1_000_000;
    assert_eq!(code(&b, &key, 0, 1500).0, Some("lifetime_invalid"));
    let mut b = bundle.clone();
    b.revision = String::new();
    assert_eq!(code(&b, &key, 0, 1500).0, Some("bundle_malformed"));
    let mut b = bundle.clone();
    b.policy_yaml = "default: escalate\n".into();
    resign(&mut b);
    let (c, message) = code(&b, &key, 0, 1500);
    assert_eq!(
        (c, message.as_str()),
        (Some("policy_invalid"), "invalid AgentPolicySet YAML")
    );
    let mut b = bundle.clone();
    b.policy_yaml = "x".repeat(MAX_POLICY_BYTES + 1);
    resign(&mut b);
    assert_eq!(code(&b, &key, 0, 1500).0, Some("policy_too_large"));
    assert_eq!(rejection_code(&anyhow::anyhow!("other")), None);
}

#[test]
fn keyring_parse_and_serialize_round_trip() {
    let key1 = PinnedIssuerKey {
        key_id: "issuer-1".into(),
        public_key: [1u8; 32],
        revoked: false,
    };
    let key2 = PinnedIssuerKey {
        key_id: "issuer-2".into(),
        public_key: [2u8; 32],
        revoked: true,
    };
    let bytes = serialize_keyring(&[key1.clone(), key2.clone()]).unwrap();
    let parsed = parse_keyring(&bytes).unwrap();
    assert_eq!(parsed, vec![key1, key2]);
}

#[test]
fn keyring_rejects_empty_or_invalid_entries() {
    assert!(parse_keyring(b"[]").is_err());
    assert!(parse_keyring(b"").is_err());
    assert!(parse_keyring(b"not json").is_err());
    // duplicate key_id
    let dup = serde_json::json!([
        {"key_id": "k1", "public_key_hex": "00".repeat(32)},
        {"key_id": "k1", "public_key_hex": "11".repeat(32)},
    ]);
    assert!(parse_keyring(&serde_json::to_vec(&dup).unwrap()).is_err());
    // invalid hex
    let bad_hex = serde_json::json!([
        {"key_id": "k1", "public_key_hex": "nothex"},
    ]);
    assert!(parse_keyring(&serde_json::to_vec(&bad_hex).unwrap()).is_err());
}

#[test]
fn multi_key_verification_supports_rotation_and_revocation() {
    let pair1 = Ed25519KeyPair::from_seed_unchecked(&[1u8; 32]).unwrap();
    let pair2 = Ed25519KeyPair::from_seed_unchecked(&[2u8; 32]).unwrap();
    let yaml = "default: deny\n".to_string();

    let make_bundle = |pair: &Ed25519KeyPair, issuer_id: &str, seq: u64| {
        let mut b = SignedAgentPolicy {
            schema_version: 1,
            tenant_id: "tenant-1".into(),
            agent_id: "agent-1".into(),
            revision: format!("rev-{seq}"),
            deployment_sequence: seq,
            issued_at_unix: 1000,
            expires_at_unix: 2000,
            issuer_key_id: issuer_id.into(),
            policy_sha256: hex_lower(&Sha256::digest(yaml.as_bytes())),
            policy_yaml: yaml.clone(),
            signature_hex: String::new(),
        };
        b.signature_hex = hex_lower(pair.sign(&b.signing_transcript().unwrap()).as_ref());
        b
    };

    let bundle1 = make_bundle(&pair1, "issuer-1", 1);
    let bundle2 = make_bundle(&pair2, "issuer-2", 2);

    // Keyring with both keys active
    let keys = vec![
        PinnedIssuerKey {
            key_id: "issuer-1".into(),
            public_key: pair1.public_key().as_ref().try_into().unwrap(),
            revoked: false,
        },
        PinnedIssuerKey {
            key_id: "issuer-2".into(),
            public_key: pair2.public_key().as_ref().try_into().unwrap(),
            revoked: false,
        },
    ];

    // Both verify successfully
    assert!(verify_candidate(&bundle1, &keys, "tenant-1", "agent-1", 0, 1500).is_ok());
    assert!(verify_candidate(&bundle2, &keys, "tenant-1", "agent-1", 1, 1500).is_ok());

    // Revoke issuer-1
    let keys_revoked = vec![
        PinnedIssuerKey {
            key_id: "issuer-1".into(),
            public_key: pair1.public_key().as_ref().try_into().unwrap(),
            revoked: true,
        },
        PinnedIssuerKey {
            key_id: "issuer-2".into(),
            public_key: pair2.public_key().as_ref().try_into().unwrap(),
            revoked: false,
        },
    ];

    // Bundle from issuer-1 is rejected as revoked
    let err =
        verify_candidate(&bundle1, &keys_revoked, "tenant-1", "agent-1", 0, 1500).unwrap_err();
    assert!(err.to_string().contains("revoked issuer signing key"));

    // Bundle from issuer-2 continues to succeed
    assert!(verify_candidate(&bundle2, &keys_revoked, "tenant-1", "agent-1", 1, 1500).is_ok());
}

#[test]
fn keyring_versioned_format_supports_schema_version_and_denies_unknown_fields() {
    // Valid versioned keyring
    let valid = serde_json::json!({
        "schema_version": 1,
        "issuers": [
            {"key_id": "k1", "public_key_hex": "00".repeat(32), "revoked": false}
        ]
    });
    let parsed = parse_keyring(&serde_json::to_vec(&valid).unwrap()).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].key_id, "k1");

    // Unsupported schema version
    let bad_ver = serde_json::json!({
        "schema_version": 2,
        "issuers": [
            {"key_id": "k1", "public_key_hex": "00".repeat(32)}
        ]
    });
    assert!(parse_keyring(&serde_json::to_vec(&bad_ver).unwrap()).is_err());

    // Unknown fields at root rejected
    let unknown_root = serde_json::json!({
        "schema_version": 1,
        "issuers": [
            {"key_id": "k1", "public_key_hex": "00".repeat(32)}
        ],
        "extra_field": "disallowed"
    });
    assert!(parse_keyring(&serde_json::to_vec(&unknown_root).unwrap()).is_err());

    // Unknown fields in issuer entry rejected
    let unknown_entry = serde_json::json!({
        "schema_version": 1,
        "issuers": [
            {"key_id": "k1", "public_key_hex": "00".repeat(32), "unknown": 123}
        ]
    });
    assert!(parse_keyring(&serde_json::to_vec(&unknown_entry).unwrap()).is_err());
}

#[test]
fn read_keyring_file_enforces_bounds_and_regular_file() {
    let temp = tempfile::tempdir().unwrap();
    let valid_path = temp.path().join("trusted-issuers.json");
    let valid = serde_json::json!({
        "schema_version": 1,
        "issuers": [
            {"key_id": "k1", "public_key_hex": "00".repeat(32)}
        ]
    });
    std::fs::write(&valid_path, serde_json::to_vec(&valid).unwrap()).unwrap();
    assert!(read_keyring_file(&valid_path).is_ok());

    // Refuses directory
    let dir_path = temp.path().join("dir");
    std::fs::create_dir(&dir_path).unwrap();
    assert!(read_keyring_file(&dir_path).is_err());

    // Refuses missing file
    let missing = temp.path().join("missing.json");
    assert!(read_keyring_file(&missing).is_err());

    // Refuses oversized file (> 64 KiB)
    let large_path = temp.path().join("large.json");
    std::fs::write(&large_path, vec![b' '; MAX_KEYRING_BYTES + 1]).unwrap();
    assert!(read_keyring_file(&large_path).is_err());
}
