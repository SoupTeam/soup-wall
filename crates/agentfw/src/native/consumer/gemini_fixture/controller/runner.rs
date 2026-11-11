// SPDX-License-Identifier: Apache-2.0
//! Linux controller: concrete fixed TLS connector and accepted custody delivery.
use super::super::ledger::Ledger;
use super::super::transport::{self, Operation};
use super::*;
use crate::handlers::Shared;
use crate::native::analysis_purpose::fixture_v2::provider::PendingProvider;

/// Capture/register through the already reviewed native fixture. This callback
/// cannot select an HTTP backend, model, prompt, response parser or corpus.
pub(in crate::native) trait Capture {
    async fn authorize(
        &mut self,
        text: &str,
        preflight: Preflight,
        ledger: &Ledger,
    ) -> Result<(Shared, PendingProvider)>;
}

pub(in crate::native) struct Controller {
    ledger: Ledger,
    access: Access,
}
// Private test seam. The only externally callable run() selects Direct, whose
// three operations use the reviewed fixed TLS/HTTP connector.
trait Wire {
    async fn request(
        &mut self,
        operation: Operation,
        body: &[u8],
        key: &Key,
        deadline: Instant,
    ) -> Result<Vec<u8>>;
}
struct Direct;
impl Wire for Direct {
    async fn request(
        &mut self,
        operation: Operation,
        body: &[u8],
        key: &Key,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        transport::request(operation, body, key, deadline).await
    }
}
impl Controller {
    /// Call only from the operator's own terminal, before entering async work.
    /// No stdin/env/argument fallback and no provider request at opening.
    pub(in crate::native) fn open_interactive(
        path: &std::path::Path,
        claim: &[u8],
        operator_secret: &[u8],
    ) -> Result<Self> {
        let mut key = super::super::manual_key::prompt()?;
        Self::open(path, claim, Some(std::mem::take(&mut key)), operator_secret)
    }

    /// The operator key and signed evidence come from the trusted caller, never
    /// source content, a model answer or a chat. Opening does not dispatch.
    pub(in crate::native) fn open(
        path: &std::path::Path,
        claim: &[u8],
        key: Option<String>,
        operator_secret: &[u8],
    ) -> Result<Self> {
        let mut key = key.map(zeroize::Zeroizing::new);
        let ledger = Ledger::open(path)?;
        Self::open_held(
            ledger,
            claim,
            key.as_deref_mut().map(std::mem::take),
            operator_secret,
        )
    }

    pub(super) fn open_held(
        ledger: Ledger,
        claim: &[u8],
        key: Option<String>,
        operator_secret: &[u8],
    ) -> Result<Self> {
        let mut key = key.map(zeroize::Zeroizing::new);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let identity = ledger.identity()?;
        let access = Access::verify(
            claim,
            key.as_deref_mut().map(std::mem::take),
            operator_secret,
            &identity,
            now,
        )?;
        let manifest = serde_json::to_vec(
            &json!({"contract":"sw-gemini-serial/1","profile":profile_hash(),"plan":json_digest(PLAN),"acceptance":json_digest(ACCEPTANCE),"project":access.claim.project,"key_sha256":access.claim.key_sha256,"rows":30,"originals":6,"attacks":24,"usd_ceiling":0}),
        )?;
        match ledger.read("batch.manifest")? {
            Some(old) => ensure!(old == manifest, "gemini_batch_profile_changed"),
            None => ledger.create("batch.manifest", &manifest)?,
        }
        let evidence = serde_json::to_vec(&access.claim)?;
        let name = format!("access-{}.claim", hash(&evidence));
        match ledger.read(&name)? {
            Some(old) => ensure!(old == evidence, "gemini_operator_evidence_changed"),
            None => ledger.create(&name, &evidence)?,
        }
        Ok(Self { ledger, access })
    }

    fn check(&self) -> Result<()> {
        self.access.check(&self.ledger.identity()?)
    }

    pub(super) fn save_operator_report(&self) -> Result<()> {
        let report = serde_json::to_vec(&self.report()?)?;
        let name = format!("report-{}.json", hash(&report));
        if let Some(old) = self.ledger.read(&name)? {
            ensure!(old == report, "gemini_report_changed");
        } else {
            self.ledger.create(&name, &report)?;
        }
        Ok(())
    }
    fn deadline(&self) -> Instant {
        self.access
            .deadline
            .min(Instant::now() + std::time::Duration::from_secs(30))
    }

    async fn model(&self, wire: &mut impl Wire) -> Result<()> {
        self.check()?;
        if let Some(raw) = self.ledger.read("model.response")? {
            metadata(&raw)?;
            return Ok(());
        }
        // A missing response after this marker is uncertain, never retried.
        self.ledger
            .create("model.started", b"{\"state\":\"started_unknown\"}")?;
        let raw = match wire
            .request(Operation::Metadata, &[], &self.access.key, self.deadline())
            .await
        {
            Ok(raw) => raw,
            Err(e) => {
                let code = super::super::transport::failure_code(&e);
                self.ledger.create("model.failure", code.as_bytes())?;
                if let Some(raw) = rejected_body(&e) {
                    self.ledger.create("model.error-response", raw)?;
                }
                return Err(e);
            }
        };
        self.ledger.create("model.response", &raw)?;
        metadata(&raw)?;
        Ok(())
    }

    /// One awaited row at a time, no task spawning, fallback or retry. Reopening
    /// preserves every prior marker. A fresh quota attestation permits only
    /// untouched rows; already attempted rows are always skipped.
    pub(in crate::native) async fn run(&mut self, capture: &mut impl Capture) -> Result<Value> {
        self.run_bounded(capture, 20).await
    }
    pub(super) async fn run_bounded(
        &mut self,
        capture: &mut impl Capture,
        row_ceiling: usize,
    ) -> Result<Value> {
        self.run_limited(
            capture,
            &mut Direct,
            row_ceiling,
            std::time::Duration::from_secs(61),
        )
        .await
    }
    async fn run_with(
        &mut self,
        capture: &mut impl Capture,
        wire: &mut impl Wire,
    ) -> Result<Value> {
        self.run_limited(capture, wire, 30, std::time::Duration::ZERO)
            .await
    }
    async fn run_limited(
        &mut self,
        capture: &mut impl Capture,
        wire: &mut impl Wire,
        row_ceiling: usize,
        spacing: std::time::Duration,
    ) -> Result<Value> {
        ensure!((1..=30).contains(&row_ceiling), "gemini_row_ceiling");
        self.check()?;
        let mut attempted = 0;
        // Check old fences before metadata or any other network operation.
        for i in 0..30 {
            let r = row(i)?;
            let id = hash(r.frame.as_bytes());
            let state = self.state(&id)?;
            if state != State::Unrun {
                attempted += 1;
            }
            if state == State::StartedUnknown
                || matches!(state, State::ModelDrift | State::TechnicalStop)
            {
                return self.report();
            }
            if state == State::QuotaStop {
                let raw = self
                    .ledger
                    .read(&format!("{id}.controller-terminal"))?
                    .unwrap();
                let Strict(v) = serde_json::from_slice(&raw)?;
                if self.access.claim.issued <= v["access_issued"].as_u64().unwrap_or(u64::MAX) {
                    return self.report();
                }
            }
        }
        // A cumulative ceiling survives reopening: no counter reset or
        // deliberately consuming an extra row to discover the daily limit.
        if attempted >= row_ceiling {
            return self.report();
        }
        self.model(wire).await?;
        for i in 0..30 {
            self.check()?;
            let r = row(i)?;
            let id = hash(r.frame.as_bytes());
            if self.state(&id)? != State::Unrun {
                continue;
            }
            if attempted >= row_ceiling {
                break;
            }
            // Wait before the attempt fence, count disclosure and custody grant.
            // Never extend a grant/lease or wait inside provider delivery.
            if !spacing.is_zero() {
                tokio::time::sleep(spacing).await;
            }
            self.check()?;
            // Includes countTokens disclosure. Crash during ANY row stage is
            // fenced before I/O; do not infer that generation was not submitted.
            self.ledger.create(
                &format!("{id}.controller-started"),
                &serde_json::to_vec(
                    &json!({"profile":profile_hash(),"source":id,"state":"started_unknown"}),
                )?,
            )?;
            attempted += 1;
            let result = self.one(r, &id, capture, wire).await;
            let state = match result {
                Ok(state) => state,
                Err(e) if e.to_string() == "gemini_quota_stop" => State::QuotaStop,
                Err(_) => State::TechnicalStop,
            };
            self.ledger.create(&format!("{id}.controller-terminal"), &serde_json::to_vec(&json!({"state":state,"access_issued":self.access.claim.issued,"semantic":"pending_independent_review","policy_allow":false,"usd_ceiling":0}))?)?;
            if state.stops() {
                break;
            }
        }
        self.report()
    }

    async fn one(
        &self,
        r: Row,
        id: &str,
        capture: &mut impl Capture,
        wire: &mut impl Wire,
    ) -> Result<State> {
        self.check()?;
        let body = count_body(&r.frame)?;
        let raw = match wire
            .request(Operation::Count, &body, &self.access.key, self.deadline())
            .await
        {
            Ok(raw) => raw,
            Err(e) => {
                if let Some(raw) = rejected_body(&e) {
                    self.ledger
                        .create(&format!("{id}.count-error-response"), raw)?;
                }
                return Err(e);
            }
        };
        drop(body);
        self.ledger.create(&format!("{id}.count-response"), &raw)?;
        let p = counted(&r.frame, &raw)?;
        drop(raw);
        self.check()?;
        let (st, pending) = capture.authorize(&r.text, p, &self.ledger).await?;
        // Do not overlap these full public copies with the charged custody /
        // prepared body during provider delivery. Only its fixed hash survives.
        drop(r);
        let result = pending
            .deliver(
                &st,
                &self.ledger,
                async |prepared: &Prepared| {
                    self.check()?;
                    ensure!(
                        hash(prepared.source.as_bytes()) == id,
                        "gemini_controller_custody_mismatch"
                    );
                    // No clone of the large body; original lease spans this await.
                    wire.request(
                        Operation::Generate,
                        &prepared.body,
                        &self.access.key,
                        prepared.deadline.min(self.access.deadline),
                    )
                    .await
                },
                None,
            )
            .await;
        // Complete raw provider envelope is already durable even for blocked
        // or malformed responses. A structural pass is not a semantic pass.
        if let Some(raw) = self.ledger.read(&format!("{id}.terminal"))? {
            let Strict(v) = serde_json::from_slice(&raw)?;
            if v["state"] == "quota_stop" {
                return Ok(State::QuotaStop);
            }
            if matches!(
                v["state"].as_str(),
                Some("transport_unknown" | "cancelled_unknown" | "stale")
            ) {
                return Ok(State::TechnicalStop);
            }
        }
        if let Some(raw) = self.ledger.read(&format!("{id}.response"))? {
            if let Ok(Strict(v)) = serde_json::from_slice::<Strict>(&raw) {
                // Missing identity is a batch stop even on a safety block.
                // Do not let blockReason turn an unverified model into a
                // normal per-row outcome and permit more generations.
                if v["modelVersion"] != MODEL {
                    return Ok(State::ModelDrift);
                }
                if v["promptFeedback"].get("blockReason").is_some() {
                    return Ok(State::Blocked);
                }
            }
        }
        if let Ok(review) = result {
            self.check()?;
            self.ledger.create(&format!("{id}.private-review"), &serde_json::to_vec(&json!({"summary":review.summary,"excerpts":review.excerpts,"source":id,"untrusted":true,"policy_allow":false,"semantic":"pending_independent_review"}))?)?;
            return Ok(State::ValidUntrusted);
        }
        if let Some(raw) = self.ledger.read(&format!("{id}.terminal"))? {
            let Strict(v) = serde_json::from_slice(&raw)?;
            return Ok(match v["state"].as_str() {
                Some("quota_stop") => State::QuotaStop,
                Some("invalid") => State::Invalid,
                _ => State::TechnicalStop,
            });
        }
        Ok(State::TechnicalStop)
    }

    fn state(&self, id: &str) -> Result<State> {
        if let Some(raw) = self.ledger.read(&format!("{id}.controller-terminal"))? {
            let Strict(v) = serde_json::from_slice(&raw)?;
            return Ok(serde_json::from_value(v["state"].clone())?);
        }
        if self
            .ledger
            .read(&format!("{id}.controller-started"))?
            .is_some()
            || self.ledger.read(&format!("{id}.started"))?.is_some()
        {
            return Ok(State::StartedUnknown);
        }
        Ok(State::Unrun)
    }

    pub(in crate::native) fn report(&self) -> Result<Value> {
        let mut rows = Vec::with_capacity(30);
        for i in 0..30 {
            let r = row(i)?;
            let id = hash(r.frame.as_bytes());
            let raw = self.ledger.read(&format!("{id}.response"))?;
            let value = raw
                .as_ref()
                .and_then(|b| serde_json::from_slice::<Strict>(b).ok())
                .map(|Strict(v)| v);
            // Summary report stays bounded. Full untrusted metadata stays in
            // the private raw file, including any unknown future usage fields.
            let mut usage = serde_json::Map::new();
            if let Some(v) = &value {
                for name in [
                    "promptTokenCount",
                    "candidatesTokenCount",
                    "totalTokenCount",
                    "thoughtsTokenCount",
                    "cachedContentTokenCount",
                ] {
                    if let Some(n) = v["usageMetadata"][name].as_u64() {
                        usage.insert(name.into(), json!(n));
                    }
                }
            }
            rows.push(json!({"case_id":r.id,"group":if r.original {"six_originals"}else{"24_matched_attacks"},"state":self.state(&id)?,"source_sha256":id,"raw_sha256":raw.as_ref().map(|b|hash(b)),"modelVersion":value.as_ref().and_then(|v|v["modelVersion"].as_str()).filter(|s|s.len()<=128),"usageMetadata":usage,"semantic":"pending_independent_review","policy_allow":false}));
        }
        Ok(
            json!({"contract":"sw-gemini-serial-report/1","profile":profile_hash(),"baseline":{"semantic":48,"technical":3},"originals":6,"matched_attacks":24,"usd_ceiling":0,"rows":rows,"done":false}),
        )
    }
}

// Offline witness invoked only by the required launcher-identity Linux test.
// No environment credential lookup and no real connector in this witness.
pub(in crate::native) async fn exercise_serial(capture: &mut impl Capture) {
    use std::os::unix::fs::PermissionsExt;
    struct FixtureWire {
        generations: usize,
        mode: &'static str,
        requests: usize,
    }
    impl Wire for FixtureWire {
        async fn request(
            &mut self,
            operation: Operation,
            body: &[u8],
            _: &Key,
            _: Instant,
        ) -> Result<Vec<u8>> {
            self.requests += 1;
            match operation {
                Operation::Metadata => Ok(serde_json::to_vec(
                    &json!({"name":format!("models/{MODEL}"),"baseModelId":MODEL,"version":"fixture-version","inputTokenLimit":1048576,"outputTokenLimit":8192,"supportedGenerationMethods":["generateContent","countTokens"]}),
                )?),
                Operation::Count => {
                    let v: Value = serde_json::from_slice(body)?;
                    approved_source(
                        v["generateContentRequest"]["contents"][0]["parts"][0]["text"]
                            .as_str()
                            .unwrap(),
                    )?;
                    Ok(br#"{"totalTokens":1024}"#.to_vec())
                }
                Operation::Generate => {
                    self.generations += 1;
                    if self.mode == "quota"
                        || (matches!(self.mode, "malformed" | "blocked" | "blocked-unknown")
                            && self.generations > 1)
                    {
                        anyhow::bail!("gemini_quota_stop");
                    }
                    if self.mode == "malformed" {
                        return Ok(b"not JSON".to_vec());
                    }
                    if matches!(self.mode, "blocked" | "blocked-unknown") {
                        let mut response =
                            json!({"modelVersion":MODEL,"promptFeedback":{"blockReason":"SAFETY"}});
                        if self.mode == "blocked-unknown" {
                            response.as_object_mut().unwrap().remove("modelVersion");
                        }
                        return Ok(serde_json::to_vec(&response)?);
                    }
                    let v: Value = serde_json::from_slice(body)?;
                    let source = v["contents"][0]["parts"][0]["text"].as_str().unwrap();
                    approved_source(source)?;
                    // Protocol-only witness: attack edits may remove original tail
                    // text. This exact root key is present in every frozen frame;
                    // it proves citation validation, never semantic usefulness.
                    let quote = "\"jsonrpc\"";
                    Ok(serde_json::to_vec(
                        &json!({"modelVersion":if self.mode=="drift" {"different-model"}else{MODEL},"usageMetadata":{"promptTokenCount":1024,"candidatesTokenCount":10,"totalTokenCount":1034},"candidates":[{"finishReason":"STOP","content":{"role":"model","parts":[{"text":json!({"summary":"Synthetic protocol witness only; no semantic evidence.","quotes":[quote]}).to_string()}]}}]}),
                    )?)
                }
            }
        }
    }
    for mode in [
        "valid",
        "quota",
        "drift",
        "malformed",
        "blocked",
        "blocked-unknown",
        "crash",
    ] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let ledger = Ledger::open(directory.path()).unwrap();
        let secret = crate::token::generate();
        let key = crate::token::generate();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut claim = AccessClaim {
            profile: profile_hash(),
            ledger: ledger.identity().unwrap(),
            key_sha256: hash(key.as_bytes()),
            project: "offline-fixture".into(),
            evidence_sha256: hash(b"synthetic not permission"),
            non_billed_free_tier: true,
            quota_available: true,
            issued: now - 10,
            expires: now + 3590,
            signature: String::new(),
        };
        claim.signature = URL_SAFE_NO_PAD.encode(
            access_mac(secret.as_bytes(), &claim)
                .finalize()
                .into_bytes(),
        );
        drop(ledger);
        let bytes = serde_json::to_vec(&claim).unwrap();
        assert!(Controller::open(directory.path(), &bytes, None, secret.as_bytes()).is_err());
        assert!(!directory.path().join("batch.manifest").exists());
        let mut controller = Controller::open(
            directory.path(),
            &bytes,
            Some(key.clone()),
            secret.as_bytes(),
        )
        .unwrap();
        let id = hash(row(0).unwrap().frame.as_bytes());
        if mode == "crash" {
            controller
                .ledger
                .create(&format!("{id}.controller-started"), b"{}")
                .unwrap();
        }
        let mut wire = FixtureWire {
            generations: 0,
            mode,
            requests: 0,
        };
        if mode == "valid" {
            // Cancelling during pacing must not fence or disclose a row.
            assert!(tokio::time::timeout(
                std::time::Duration::from_millis(20),
                controller.run_limited(capture, &mut wire, 20, std::time::Duration::from_secs(61)),
            )
            .await
            .is_err());
            assert_eq!(wire.generations, 0);
            assert!(controller
                .ledger
                .read(&format!("{id}.controller-started"))
                .unwrap()
                .is_none());
            let partial = controller
                .run_limited(capture, &mut wire, 20, std::time::Duration::ZERO)
                .await
                .unwrap();
            assert_eq!(wire.generations, 20, "partial report: {partial}");
            assert_eq!(partial["rows"][20]["state"], "unrun");
            let untouched = hash(row(20).unwrap().frame.as_bytes());
            assert!(controller
                .ledger
                .read(&format!("{untouched}.controller-started"))
                .unwrap()
                .is_none());
            controller.save_operator_report().unwrap();
            drop(controller);
            controller = Controller::open(
                directory.path(),
                &bytes,
                Some(key.clone()),
                secret.as_bytes(),
            )
            .unwrap();
            let requests = wire.requests;
            assert_eq!(
                controller
                    .run_limited(capture, &mut wire, 20, std::time::Duration::ZERO)
                    .await
                    .unwrap(),
                partial
            );
            assert_eq!(
                wire.requests, requests,
                "same ceiling must not contact provider on reopening"
            );
            // Raising the cumulative ceiling simulates renewed operator evidence
            // after reset; the twenty completed originals/controls never replay.
        }
        let report = controller.run_with(capture, &mut wire).await.unwrap();
        let expected = match mode {
            "valid" => "valid_untrusted",
            "quota" => "quota_stop",
            "drift" | "blocked-unknown" => "model_drift",
            "malformed" => "invalid",
            "blocked" => "blocked",
            _ => "started_unknown",
        };
        assert_eq!(report["rows"][0]["state"], expected, "{mode}");
        assert_eq!(report["rows"].as_array().unwrap().len(), 30);
        assert_eq!(
            wire.generations,
            if mode == "crash" {
                0
            } else if matches!(mode, "quota" | "drift" | "blocked-unknown") {
                1
            } else if matches!(mode, "malformed" | "blocked") {
                2
            } else {
                30
            }
        );
        assert_eq!(report["baseline"], json!({"semantic":48,"technical":3}));
        assert_eq!(report["done"], false);
        if mode == "valid" {
            assert!(report["rows"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["state"] == "valid_untrusted"));
        }
        drop(controller);
        let mut reopened = Controller::open(
            directory.path(),
            &bytes,
            Some(key.clone()),
            secret.as_bytes(),
        )
        .unwrap();
        let count = wire.requests;
        let again = reopened.run_with(capture, &mut wire).await.unwrap();
        assert_eq!(again, report);
        assert_eq!(wire.requests, count, "replay {mode}");
        if mode == "crash" {
            // Exercise the public concrete connector path with an unknown fence:
            // this must return before metadata/DNS/TLS, even with a valid claim.
            assert_eq!(reopened.run(capture).await.unwrap(), report);
        }
        assert!(reopened.ledger.read("../escape").is_err());
        assert!(reopened.ledger.create("../escape", b"x").is_err());
        if mode == "quota" {
            drop(reopened);
            claim.issued = now - 5;
            claim.expires = now + 3595;
            claim.signature = URL_SAFE_NO_PAD.encode(
                access_mac(secret.as_bytes(), &claim)
                    .finalize()
                    .into_bytes(),
            );
            let bytes = serde_json::to_vec(&claim).unwrap();
            let mut resumed =
                Controller::open(directory.path(), &bytes, Some(key), secret.as_bytes()).unwrap();
            wire.mode = "valid";
            let report = resumed.run_with(capture, &mut wire).await.unwrap();
            assert_eq!(wire.generations, 30); // one quota outcome + 29 untouched
            assert_eq!(report["rows"][0]["state"], "quota_stop");
            assert!(report["rows"].as_array().unwrap()[1..]
                .iter()
                .all(|r| r["state"] == "valid_untrusted"));
        }
    }
}
