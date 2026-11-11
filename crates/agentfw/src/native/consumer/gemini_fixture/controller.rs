// SPDX-License-Identifier: Apache-2.0
//! One frozen, serial public experiment. Never a production release permission.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[cfg(target_os = "linux")]
pub(in crate::native) mod operator;
#[cfg(target_os = "linux")]
pub(in crate::native) mod runner;

// Operator evidence is authenticated separately from model/source data. This
// manual operator signs a local declaration; this cannot attest billing itself.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessClaim {
    profile: String,
    ledger: String,
    key_sha256: String,
    project: String,
    evidence_sha256: String,
    non_billed_free_tier: bool,
    quota_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata_recovery_started_sha256: Option<String>,
    issued: u64,
    expires: u64,
    signature: String,
}
fn access_mac(secret: &[u8], claim: &AccessClaim) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC key");
    mac.update(b"agentfw/public-gemini-operator-access/v1\0");
    let mut unsigned = claim.clone();
    unsigned.signature.clear();
    mac.update(&serde_json::to_vec(&unsigned).unwrap());
    mac
}
struct Access {
    claim: AccessClaim,
    key: Key,
    deadline: Instant,
}
impl Access {
    fn verify(
        bytes: &[u8],
        key: Option<String>,
        operator_secret: &[u8],
        ledger: &str,
        now: u64,
    ) -> Result<Self> {
        let mut key = key.map(zeroize::Zeroizing::new);
        ensure!(bytes.len() <= 4096, "gemini_access_limit");
        ensure!(
            (32..=256).contains(&operator_secret.len()),
            "gemini_operator_key_missing"
        );
        let Strict(value) = serde_json::from_slice(bytes)?;
        let claim: AccessClaim = serde_json::from_value(value)?;
        access_mac(operator_secret, &claim)
            .verify_slice(&URL_SAFE_NO_PAD.decode(&claim.signature)?)
            .map_err(|_| anyhow::anyhow!("gemini_operator_signature"))?;
        let key = Key::new(std::mem::take(
            key.as_deref_mut()
                .ok_or_else(|| anyhow::anyhow!("gemini_operator_key_missing"))?,
        ))?;
        ensure!(
            claim.profile == profile_hash()
                && claim.ledger == ledger
                && claim.key_sha256 == hash(key.0.as_bytes())
                && !claim.project.is_empty()
                && claim.project.len() <= 128
                && claim
                    .project
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && claim.evidence_sha256.len() == 64
                && claim.evidence_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                && claim.non_billed_free_tier
                && claim.quota_available,
            "gemini_operator_free_project_required"
        );
        ensure!(
            claim.issued <= now && now < claim.expires && claim.expires - claim.issued <= 3600,
            "gemini_operator_expired"
        );
        let deadline = Instant::now() + std::time::Duration::from_secs(claim.expires - now);
        Ok(Self {
            claim,
            key,
            deadline,
        })
    }
    fn check(&self, ledger: &str) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline
                && self.claim.ledger == ledger
                && self.claim.profile == profile_hash(),
            "gemini_operator_expired_or_changed"
        );
        Ok(())
    }
}

struct Row {
    id: String,
    original: bool,
    text: String,
    frame: String,
}
fn row(index: usize) -> Result<Row> {
    let plan: Value = serde_json::from_str(PLAN)?;
    let rows = plan["cases"].as_array().unwrap();
    ensure!(rows.len() == 30 && index < 30, "gemini_corpus_limit");
    let r = &rows[index];
    let source = match r["source_case"].as_str() {
        Some("g05-a") => include_str!("../../../../../../eval/sou123/payloads/g05-a.txt"),
        Some("g06-b") => include_str!("../../../../../../eval/sou123/payloads/g06-b.txt"),
        Some("f05-a") => include_str!("../../../../../../eval/sou123/payloads/f05-a.txt"),
        Some("g11-a") => include_str!("../../../../../../eval/sou123/payloads/g11-a.txt"),
        Some("g12-a") => include_str!("../../../../../../eval/sou123/payloads/g12-a.txt"),
        Some("f12-a") => include_str!("../../../../../../eval/sou123/payloads/f12-a.txt"),
        _ => anyhow::bail!("gemini_corpus_source"),
    };
    ensure!(
        hash(source.as_bytes()) == r["source_sha256"],
        "gemini_corpus_original_hash"
    );
    let e = &r["edit"];
    let start = e["start"].as_u64().unwrap() as usize;
    let end = e["end"].as_u64().unwrap() as usize;
    ensure!(
        start <= end && source.is_char_boundary(start) && source.is_char_boundary(end),
        "gemini_corpus_edit"
    );
    let text = format!(
        "{}{}{}",
        &source[..start],
        e["replacement"].as_str().unwrap(),
        &source[end..]
    );
    ensure!(
        hash(text.as_bytes()) == r["sha256"]
            && text.len() == r["size_bytes"].as_u64().unwrap() as usize,
        "gemini_corpus_hash"
    );
    let frame = json!({"jsonrpc":"2.0","id":"host-call","result":{"content":[{"type":"text","text":text}],"structuredContent":{"content":text}}}).to_string();
    approved_source(&frame)?;
    Ok(Row {
        id: r["case_id"].as_str().unwrap().into(),
        original: r["variant"] == "original",
        text,
        frame,
    })
}

fn count_body(source: &str) -> Result<Vec<u8>> {
    approved_source(source)?;
    let mut request = request_value(source);
    request["model"] = json!(format!("models/{MODEL}"));
    let bytes = serde_json::to_vec(&json!({"generateContentRequest": request}))?;
    ensure!(bytes.len() <= REQUEST_LIMIT, "gemini_request_limit");
    Ok(bytes)
}
fn metadata(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len() <= RESPONSE_LIMIT, "gemini_response_limit");
    let Strict(v) = serde_json::from_slice(bytes)?;
    ensure!(
        v["name"] == format!("models/{MODEL}")
            && v["baseModelId"] == MODEL
            && v["version"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 128)
            && v["inputTokenLimit"] == 1_048_576
            && v["outputTokenLimit"].as_u64().is_some_and(|n| n >= 2048)
            && v["supportedGenerationMethods"].as_array().is_some_and(|a| a
                .contains(&json!("generateContent"))
                && a.contains(&json!("countTokens"))),
        "gemini_model_metadata"
    );
    Ok(v)
}
fn counted(source: &str, bytes: &[u8]) -> Result<Preflight> {
    ensure!(bytes.len() <= RESPONSE_LIMIT, "gemini_response_limit");
    let Strict(v) = serde_json::from_slice(bytes)?;
    let count = v["totalTokens"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= 1_048_576)
        .ok_or_else(|| anyhow::anyhow!("gemini_context_preflight"))?;
    Ok(Preflight {
        free_project_confirmed: true,
        quota_available: true,
        counted_tokens: count,
        counted_request_sha256: hash(&request_body(source)?),
        input_limit: 1_048_576,
        model_version: MODEL.into(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Unrun,
    StartedUnknown,
    ValidUntrusted,
    Invalid,
    Blocked,
    QuotaStop,
    ModelDrift,
    TechnicalStop,
}
impl State {
    fn stops(&self) -> bool {
        matches!(
            self,
            Self::StartedUnknown | Self::QuotaStop | Self::ModelDrift | Self::TechnicalStop
        )
    }
}

#[test]
fn gemini_controller_operator_access_requires_signed_free_project_key_and_time() {
    let secret = crate::token::generate();
    let raw_key = crate::token::generate();
    let mut c = AccessClaim {
        profile: profile_hash(),
        ledger: hash(b"held ledger"),
        key_sha256: hash(raw_key.as_bytes()),
        project: "operator-owned-project".into(),
        evidence_sha256: hash(b"operator billing evidence"),
        non_billed_free_tier: true,
        quota_available: true,
        metadata_recovery_started_sha256: None,
        issued: 100,
        expires: 200,
        signature: String::new(),
    };
    c.signature = URL_SAFE_NO_PAD.encode(access_mac(secret.as_bytes(), &c).finalize().into_bytes());
    let bytes = serde_json::to_vec(&c).unwrap();
    let a = Access::verify(
        &bytes,
        Some(raw_key.clone()),
        secret.as_bytes(),
        &c.ledger,
        101,
    )
    .unwrap();
    a.check(&c.ledger).unwrap();
    let mut forged = c.clone();
    forged.metadata_recovery_started_sha256 = Some(hash(b"not personally signed"));
    assert!(Access::verify(
        &serde_json::to_vec(&forged).unwrap(),
        Some(raw_key.clone()),
        secret.as_bytes(),
        &c.ledger,
        101
    )
    .is_err());
    assert_eq!(hash(a.key.0.as_bytes()), c.key_sha256);
    assert!(a.check("different ledger").is_err());
    for (key, ledger, now) in [
        (None, c.ledger.as_str(), 101),
        (Some(crate::token::generate()), c.ledger.as_str(), 101),
        (Some(raw_key.clone()), "foreign", 101),
        (Some(raw_key.clone()), c.ledger.as_str(), 200),
    ] {
        assert!(Access::verify(&bytes, key, secret.as_bytes(), ledger, now).is_err());
    }
    c.non_billed_free_tier = false;
    // Even an authentic operator statement that billing is enabled must fail.
    c.signature = URL_SAFE_NO_PAD.encode(access_mac(secret.as_bytes(), &c).finalize().into_bytes());
    assert!(Access::verify(
        &serde_json::to_vec(&c).unwrap(),
        Some(raw_key.clone()),
        secret.as_bytes(),
        &c.ledger,
        101
    )
    .is_err());
    c.non_billed_free_tier = true; // changing signed evidence also fails
    assert!(Access::verify(
        &serde_json::to_vec(&c).unwrap(),
        Some(raw_key),
        secret.as_bytes(),
        &c.ledger,
        101
    )
    .is_err());
}

#[test]
fn gemini_controller_frozen_corpus_preflight_complete_and_closed() {
    let mut identities = BTreeSet::new();
    let mut originals = 0;
    for i in 0..30 {
        let r = row(i).unwrap();
        identities.insert(hash(r.frame.as_bytes()));
        originals += usize::from(r.original);
        assert!(!r.id.is_empty() && !r.text.is_empty());
        let count: Value = serde_json::from_slice(&count_body(&r.frame).unwrap()).unwrap();
        assert_eq!(
            count["generateContentRequest"]["contents"][0]["parts"][0]["text"],
            r.frame
        );
        assert!(count.get("contents").is_none());
        let p = counted(&r.frame, br#"{"totalTokens":100}"#).unwrap();
        assert_eq!(
            p.counted_request_sha256,
            hash(&request_body(&r.frame).unwrap())
        );
    }
    assert_eq!((identities.len(), originals), (30, 6));
    assert!(row(30).is_err());
    let r = row(0).unwrap();
    for raw in [
        br#"{"totalTokens":0}"#.as_slice(),
        br#"{"totalTokens":1048577}"#,
        br#"{"totalTokens":1,"totalTokens":2}"#,
    ] {
        assert!(counted(&r.frame, raw).is_err());
    }
    let mut m = json!({"name":format!("models/{MODEL}"),"baseModelId":MODEL,"version":"001","inputTokenLimit":1048576,"outputTokenLimit":8192,"supportedGenerationMethods":["generateContent","countTokens"]});
    assert!(metadata(&serde_json::to_vec(&m).unwrap()).is_ok());
    m["name"] = json!("models/other");
    assert!(metadata(&serde_json::to_vec(&m).unwrap()).is_err());
    assert!(State::QuotaStop.stops());
    assert!(State::StartedUnknown.stops());
    assert!(!State::Invalid.stops());
}
