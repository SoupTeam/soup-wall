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
        if let Some(blocked) = self.ledger.read("model.metadata.blocked")? {
            return self.revalidate_absent_base_model(&blocked);
        }
        if let Some(raw) = self.ledger.read("model.response")? {
            metadata(&raw)?;
            return Ok(());
        }
        let original = self.ledger.read("model.started")?;
        let prefix = if let Some(original) = original {
            let original_sha256 = hash(&original);
            ensure!(
                self.ledger.read("model.error-response")?.is_none()
                    && self.ledger.read("model.recovery.error-response")?.is_none(),
                "gemini_metadata_recovery_http_error"
            );
            // Read historical successful metadata using its original binding.
            if let Some(raw) = self.ledger.read("model.recovery.response")? {
                let receipt = self
                    .ledger
                    .read("model.recovery.started")?
                    .ok_or_else(|| anyhow::anyhow!("gemini_metadata_recovery_receipt"))?;
                let Strict(receipt) = serde_json::from_slice(&receipt)?;
                ensure!(
                    receipt["original_started_sha256"] == original_sha256,
                    "gemini_metadata_recovery_receipt"
                );
                metadata(&raw)?;
                return Ok(());
            }
            if let Some(receipt) = self.ledger.read("model.metadata.accepted")? {
                let Strict(receipt) = serde_json::from_slice(&receipt)?;
                let approval = receipt["access_claim_sha256"]
                    .as_str()
                    .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
                    .ok_or_else(|| anyhow::anyhow!("gemini_metadata_observation_receipt"))?;
                ensure!(
                    receipt["contract"] == "sw-metadata-observation/1"
                        && receipt["original_started_sha256"] == original_sha256
                        && receipt["ledger"] == self.ledger.identity()?
                        && receipt["profile"] == profile_hash(),
                    "gemini_metadata_observation_receipt"
                );
                let prefix = format!("model.observation-{approval}");
                let start = self
                    .ledger
                    .read(&format!("{prefix}.started"))?
                    .ok_or_else(|| anyhow::anyhow!("gemini_metadata_observation_receipt"))?;
                let raw = self
                    .ledger
                    .read(&format!("{prefix}.response"))?
                    .ok_or_else(|| anyhow::anyhow!("gemini_metadata_observation_receipt"))?;
                ensure!(
                    receipt["started_sha256"] == hash(&start)
                        && receipt["response_sha256"] == hash(&raw),
                    "gemini_metadata_observation_receipt"
                );
                metadata(&raw)?;
                return Ok(());
            }
            ensure!(
                self.access
                    .claim
                    .metadata_recovery_started_sha256
                    .as_deref()
                    == Some(original_sha256.as_str()),
                "gemini_metadata_recovery_not_authorized"
            );
            // Read-only preflight observation, before any count/generation disclosure.
            for i in 0..30 {
                let id = hash(row(i)?.frame.as_bytes());
                ensure!(
                    self.state(&id)? == State::Unrun,
                    "gemini_metadata_recovery_rows_started"
                );
                for suffix in [
                    "count-response",
                    "count-error-response",
                    "response",
                    "terminal",
                    "private-review",
                    "publication-refused",
                ] {
                    ensure!(
                        self.ledger.read(&format!("{id}.{suffix}"))?.is_none(),
                        "gemini_metadata_recovery_row_artifact"
                    );
                }
            }
            // Each signed personal approval permits exactly one GET. Fresh
            // confirmations append new observations; old uncertain fences persist.
            let approval = hash(&serde_json::to_vec(&self.access.claim)?);
            let prefix = format!("model.observation-{approval}");
            self.ledger.create(
                &format!("{prefix}.started"),
                &serde_json::to_vec(&json!({
                    "operation":"metadata_get_only","access_claim_sha256":approval,
                    "original_started_sha256":original_sha256,
                    "ledger":self.ledger.identity()?,"profile":profile_hash()
                }))?,
            )?;
            prefix
        } else {
            ensure!(
                self.access.claim.metadata_recovery_started_sha256.is_none()
                    && self.ledger.read("model.metadata.accepted")?.is_none(),
                "gemini_metadata_recovery_without_original"
            );
            self.ledger
                .create("model.started", b"{\"state\":\"started_unknown\"}")?;
            "model".to_owned()
        };
        let raw = match wire
            .request(Operation::Metadata, &[], &self.access.key, self.deadline())
            .await
        {
            Ok(raw) => raw,
            Err(error) => {
                let code = super::super::transport::failure_code(&error);
                self.ledger
                    .create(&format!("{prefix}.failure"), code.as_bytes())?;
                if let Some(raw) = rejected_body(&error) {
                    self.ledger
                        .create(&format!("{prefix}.error-response"), raw)?;
                    self.ledger.create(
                        "model.metadata.blocked",
                        &serde_json::to_vec(&json!({"state":"http_error",
                            "observation":prefix,"failure":code}))?,
                    )?;
                }
                return Err(error);
            }
        };
        self.ledger.create(&format!("{prefix}.response"), &raw)?;
        if let Err(error) = metadata(&raw) {
            self.ledger.create(
                "model.metadata.blocked",
                &serde_json::to_vec(&json!({"state":"invalid_metadata",
                    "observation":prefix}))?,
            )?;
            return Err(error);
        }
        if prefix != "model" {
            let start = self
                .ledger
                .read(&format!("{prefix}.started"))?
                .ok_or_else(|| anyhow::anyhow!("gemini_metadata_observation_receipt"))?;
            let Strict(mut receipt) = serde_json::from_slice(&start)?;
            receipt["contract"] = json!("sw-metadata-observation/1");
            receipt["started_sha256"] = json!(hash(&start));
            receipt["response_sha256"] = json!(hash(&raw));
            self.ledger
                .create("model.metadata.accepted", &serde_json::to_vec(&receipt)?)?;
        }
        Ok(())
    }

    // Reinterpret only the agreed absent-field contract mismatch, using the
    // retained response. Never delete the stop marker or send another GET.
    fn revalidate_absent_base_model(&self, blocked: &[u8]) -> Result<()> {
        let Strict(stop) = serde_json::from_slice(blocked)?;
        ensure!(
            stop["state"] == "invalid_metadata",
            "gemini_metadata_observed_error"
        );
        let prefix = stop["observation"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("gemini_metadata_observation_receipt"))?;
        let approval = prefix
            .strip_prefix("model.observation-")
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| anyhow::anyhow!("gemini_metadata_observation_receipt"))?;
        let read = |name: &str| -> Result<Vec<u8>> {
            self.ledger
                .read(name)?
                .ok_or_else(|| anyhow::anyhow!("gemini_metadata_observation_receipt"))
        };
        let original = read("model.started")?;
        let start = read(&format!("{prefix}.started"))?;
        let raw = read(&format!("{prefix}.response"))?;
        let claim = read(&format!("access-{approval}.claim"))?;
        let Strict(start_value) = serde_json::from_slice(&start)?;
        let Strict(claim_value) = serde_json::from_slice(&claim)?;
        ensure!(
            hash(&claim) == approval
                && start_value["operation"] == "metadata_get_only"
                && start_value["access_claim_sha256"] == approval
                && start_value["original_started_sha256"] == hash(&original)
                && start_value["ledger"] == self.ledger.identity()?
                && start_value["profile"] == profile_hash()
                && claim_value["ledger"] == self.access.claim.ledger
                && claim_value["profile"] == self.access.claim.profile
                && claim_value["project"] == self.access.claim.project
                && claim_value["key_sha256"] == self.access.claim.key_sha256,
            "gemini_metadata_observation_receipt"
        );
        for name in [
            "model.error-response".to_owned(),
            "model.recovery.error-response".to_owned(),
            format!("{prefix}.error-response"),
            format!("{prefix}.failure"),
        ] {
            ensure!(
                self.ledger.read(&name)?.is_none(),
                "gemini_metadata_observed_error"
            );
        }
        let value = metadata(&raw)?;
        ensure!(
            value.get("baseModelId").is_none(),
            "gemini_metadata_observed_error"
        );
        let receipt = serde_json::to_vec(&json!({
            "contract":"sw-metadata-absent-base-model/1", "blocked_sha256":hash(blocked),
            "started_sha256":hash(&start), "response_sha256":hash(&raw),
            "original_started_sha256":hash(&original), "access_claim_sha256":approval,
            "ledger":self.ledger.identity()?, "profile":profile_hash()
        }))?;
        if let Some(old) = self.ledger.read("model.metadata.revalidated")? {
            ensure!(old == receipt, "gemini_metadata_observation_receipt");
            return Ok(());
        }
        ensure!(
            self.access
                .claim
                .metadata_recovery_started_sha256
                .as_deref()
                == Some(hash(&original).as_str()),
            "gemini_metadata_recovery_not_authorized"
        );
        for i in 0..30 {
            let id = hash(row(i)?.frame.as_bytes());
            ensure!(
                self.state(&id)? == State::Unrun,
                "gemini_metadata_recovery_rows_started"
            );
            for suffix in [
                "count-response",
                "count-error-response",
                "response",
                "terminal",
                "private-review",
                "publication-refused",
            ] {
                ensure!(
                    self.ledger.read(&format!("{id}.{suffix}"))?.is_none(),
                    "gemini_metadata_recovery_row_artifact"
                );
            }
        }
        self.ledger.create("model.metadata.revalidated", &receipt)
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
                self.ledger.create(
                    &format!("{id}.count-failure"),
                    super::super::transport::failure_code(&e).as_bytes(),
                )?;
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
        let mut report = json!({"contract":"sw-gemini-serial-report/1","profile":profile_hash(),"baseline":{"semantic":48,"technical":3},"originals":6,"matched_attacks":24,"usd_ceiling":0,"rows":rows,"done":false});
        if let Some(receipt) = self.ledger.read("http503-continuation.receipt")? {
            let Strict(receipt) = serde_json::from_slice(&receipt)?;
            report["continuation"] = receipt;
        }
        Ok(report)
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
            metadata_recovery_started_sha256: None,
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

#[tokio::test]
async fn gemini_metadata_saved_absent_field_revalidation_is_offline_and_bound() {
    use std::os::unix::fs::PermissionsExt;
    struct NoNetwork;
    impl Wire for NoNetwork {
        async fn request(
            &mut self,
            _: Operation,
            _: &[u8],
            _: &Key,
            _: Instant,
        ) -> Result<Vec<u8>> {
            panic!("saved metadata must not issue a request");
        }
    }
    for mode in [
        "success",
        "http",
        "wrong-project",
        "wrong-start",
        "present-id",
        "null-id",
        "wrong-model",
        "no-approval",
        "row-started",
        "orphan-response",
        "changed-receipt",
    ] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let ledger = Ledger::open(directory.path()).unwrap();
        let original = br#"{"state":"started_unknown"}"#;
        ledger.create("model.started", original).unwrap();
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
            project: "offline-revalidation".into(),
            evidence_sha256: hash(b"synthetic evidence"),
            non_billed_free_tier: true,
            quota_available: true,
            metadata_recovery_started_sha256: if mode == "no-approval" {
                None
            } else {
                Some(hash(original))
            },
            issued: now - 1,
            expires: now + 3500,
            signature: String::new(),
        };
        claim.signature = URL_SAFE_NO_PAD.encode(
            access_mac(secret.as_bytes(), &claim)
                .finalize()
                .into_bytes(),
        );
        let controller = Controller::open_held(
            ledger,
            &serde_json::to_vec(&claim).unwrap(),
            Some(key),
            secret.as_bytes(),
        )
        .unwrap();
        let mut historical = claim.clone();
        if mode == "wrong-project" {
            historical.project = "other-project".into();
        }
        let evidence = serde_json::to_vec(&historical).unwrap();
        let approval = hash(&evidence);
        if mode == "wrong-project" {
            controller
                .ledger
                .create(&format!("access-{approval}.claim"), &evidence)
                .unwrap();
        }
        let prefix = format!("model.observation-{approval}");
        let start = serde_json::to_vec(&json!({"operation":"metadata_get_only", "access_claim_sha256":approval,
            "original_started_sha256":if mode == "wrong-start" {hash(b"other")} else {hash(original)},
            "ledger":claim.ledger,"profile":claim.profile})).unwrap();
        controller
            .ledger
            .create(&format!("{prefix}.started"), &start)
            .unwrap();
        let mut raw = json!({"name":format!("models/{MODEL}"),"version":"3.0","inputTokenLimit":1048576,
            "outputTokenLimit":65536,"supportedGenerationMethods":["generateContent","countTokens"]});
        match mode {
            "present-id" => raw["baseModelId"] = json!(MODEL),
            "null-id" => raw["baseModelId"] = Value::Null,
            "wrong-model" => raw["name"] = json!("models/other"),
            _ => {}
        }
        let raw = serde_json::to_vec(&raw).unwrap();
        controller
            .ledger
            .create(&format!("{prefix}.response"), &raw)
            .unwrap();
        let blocked = serde_json::to_vec(&json!({"state":if mode == "http" {"http_error"} else {"invalid_metadata"},"observation":prefix})).unwrap();
        controller
            .ledger
            .create("model.metadata.blocked", &blocked)
            .unwrap();
        let id = hash(row(0).unwrap().frame.as_bytes());
        match mode {
            "row-started" => controller
                .ledger
                .create(&format!("{id}.controller-started"), b"{}")
                .unwrap(),
            "orphan-response" => controller
                .ledger
                .create(&format!("{id}.response"), b"{}")
                .unwrap(),
            "changed-receipt" => controller
                .ledger
                .create("model.metadata.revalidated", b"{}")
                .unwrap(),
            _ => {}
        }
        let result = controller.model(&mut NoNetwork).await;
        assert_eq!(result.is_ok(), mode == "success", "{mode}: {result:?}");
        assert_eq!(
            controller
                .ledger
                .read("model.metadata.blocked")
                .unwrap()
                .unwrap(),
            blocked
        );
        assert_eq!(
            controller
                .ledger
                .read(&format!("{prefix}.response"))
                .unwrap()
                .unwrap(),
            raw
        );
        assert_eq!(
            controller
                .ledger
                .read(&format!("{prefix}.started"))
                .unwrap()
                .unwrap(),
            start
        );
        assert_eq!(
            controller.ledger.read("model.started").unwrap().unwrap(),
            original
        );
        if mode == "success" {
            let receipt = controller
                .ledger
                .read("model.metadata.revalidated")
                .unwrap()
                .unwrap();
            controller.model(&mut NoNetwork).await.unwrap();
            assert_eq!(
                controller
                    .ledger
                    .read("model.metadata.revalidated")
                    .unwrap()
                    .unwrap(),
                receipt
            );
            // Even another individually valid response cannot replace the
            // response bound by the durable revalidation receipt.
            let mut changed: Value = serde_json::from_slice(&raw).unwrap();
            changed["version"] = json!("different-valid-version");
            std::fs::write(
                directory.path().join(format!("{prefix}.response")),
                serde_json::to_vec(&changed).unwrap(),
            )
            .unwrap();
            assert!(controller.model(&mut NoNetwork).await.is_err());
            for i in 0..30 {
                assert_eq!(
                    controller
                        .state(&hash(row(i).unwrap().frame.as_bytes()))
                        .unwrap(),
                    State::Unrun
                );
            }
        }
    }
}

#[tokio::test]
async fn gemini_metadata_observations_are_single_use_per_approval_and_preserve_fences() {
    use std::os::unix::fs::PermissionsExt;
    struct MetadataWire {
        requests: usize,
        fail: bool,
        invalid: bool,
    }
    impl Wire for MetadataWire {
        async fn request(
            &mut self,
            operation: Operation,
            body: &[u8],
            _: &Key,
            _: Instant,
        ) -> Result<Vec<u8>> {
            assert!(matches!(operation, Operation::Metadata));
            assert!(body.is_empty());
            self.requests += 1;
            if self.fail {
                anyhow::bail!("gemini_timeout_unknown");
            }
            if self.invalid {
                return Ok(b"{}".to_vec());
            }
            Ok(serde_json::to_vec(
                &json!({"name":format!("models/{MODEL}"),"baseModelId":MODEL,
                "version":"offline-metadata","inputTokenLimit":1048576,"outputTokenLimit":8192,
                "supportedGenerationMethods":["generateContent","countTokens"]}),
            )?)
        }
    }
    for mode in [
        "legacy-spent",
        "success",
        "absent-approval",
        "wrong-digest",
        "row-started",
        "row-provider-started",
        "row-terminal",
        "row-orphan-response",
        "http-error",
        "network-failure",
        "invalid-response",
    ] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let ledger = Ledger::open(directory.path()).unwrap();
        let original = br#"{"state":"started_unknown"}"#;
        ledger.create("model.started", original).unwrap();
        let id = hash(row(0).unwrap().frame.as_bytes());
        match mode {
            "row-started" => ledger
                .create(&format!("{id}.controller-started"), b"{}")
                .unwrap(),
            "row-provider-started" => ledger.create(&format!("{id}.started"), b"{}").unwrap(),
            "row-terminal" => ledger
                .create(
                    &format!("{id}.controller-terminal"),
                    br#"{"state":"quota_stop"}"#,
                )
                .unwrap(),
            "row-orphan-response" => ledger.create(&format!("{id}.response"), b"{}").unwrap(),
            "http-error" => ledger.create("model.error-response", b"{}").unwrap(),
            "legacy-spent" => {
                ledger
                    .create("model.recovery.started", b"historical retained receipt")
                    .unwrap();
                ledger
                    .create("model.recovery.failure", b"gemini_http_eof")
                    .unwrap();
            }
            _ => {}
        }
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
            project: "offline-recovery".into(),
            evidence_sha256: hash(b"synthetic personal confirmation"),
            non_billed_free_tier: true,
            quota_available: true,
            metadata_recovery_started_sha256: match mode {
                "absent-approval" => None,
                "wrong-digest" => Some(hash(b"wrong")),
                _ => Some(hash(original)),
            },
            issued: now - 1,
            expires: now + 3500,
            signature: String::new(),
        };
        claim.signature = URL_SAFE_NO_PAD.encode(
            access_mac(secret.as_bytes(), &claim)
                .finalize()
                .into_bytes(),
        );
        let mut controller = Controller::open_held(
            ledger,
            &serde_json::to_vec(&claim).unwrap(),
            Some(key.clone()),
            secret.as_bytes(),
        )
        .unwrap();
        let mut wire = MetadataWire {
            requests: 0,
            fail: mode == "network-failure",
            invalid: mode == "invalid-response",
        };
        let result = controller.model(&mut wire).await;
        assert_eq!(
            result.is_ok(),
            matches!(mode, "success" | "legacy-spent"),
            "{mode}: {result:?}"
        );
        let permitted = matches!(
            mode,
            "success" | "legacy-spent" | "network-failure" | "invalid-response"
        );
        assert_eq!(wire.requests, usize::from(permitted), "{mode}");
        assert_eq!(
            controller.ledger.read("model.started").unwrap().unwrap(),
            original
        );
        if permitted {
            let prefix = format!(
                "model.observation-{}",
                hash(&serde_json::to_vec(&claim).unwrap())
            );
            assert!(controller
                .ledger
                .read(&format!("{prefix}.started"))
                .unwrap()
                .is_some());
            if mode == "legacy-spent" {
                assert_eq!(
                    controller
                        .ledger
                        .read("model.recovery.started")
                        .unwrap()
                        .unwrap(),
                    b"historical retained receipt"
                );
                assert_eq!(
                    controller
                        .ledger
                        .read("model.recovery.failure")
                        .unwrap()
                        .unwrap(),
                    b"gemini_http_eof"
                );
            }
            let requests = wire.requests;
            let again = controller.model(&mut wire).await;
            assert_eq!(again.is_ok(), matches!(mode, "success" | "legacy-spent"));
            assert_eq!(
                wire.requests, requests,
                "no second metadata observation: {mode}"
            );
            if mode == "network-failure" {
                assert_eq!(
                    controller
                        .ledger
                        .read(&format!("{prefix}.failure"))
                        .unwrap()
                        .unwrap(),
                    b"gemini_timeout_unknown"
                );
            }
            drop(controller);
            // Same held-directory identity, no journal reset, fresh opening.
            controller = Controller::open(
                directory.path(),
                &serde_json::to_vec(&claim).unwrap(),
                Some(key.clone()),
                secret.as_bytes(),
            )
            .unwrap();
            assert_eq!(
                controller.model(&mut wire).await.is_ok(),
                matches!(mode, "success" | "legacy-spent")
            );
            assert_eq!(
                wire.requests, requests,
                "reopening must never repeat metadata: {mode}"
            );
            if matches!(mode, "network-failure" | "invalid-response") {
                let old_start = controller
                    .ledger
                    .read(&format!("{prefix}.started"))
                    .unwrap()
                    .unwrap();
                drop(controller);
                // A separately signed fresh personal approval can observe a failed
                // read-only GET. Observed HTTP/model failures are terminal.
                claim.issued += 1;
                claim.signature = URL_SAFE_NO_PAD.encode(
                    access_mac(secret.as_bytes(), &claim)
                        .finalize()
                        .into_bytes(),
                );
                let fresh = Controller::open(
                    directory.path(),
                    &serde_json::to_vec(&claim).unwrap(),
                    Some(key),
                    secret.as_bytes(),
                )
                .unwrap();
                wire.fail = false;
                wire.invalid = false;
                let fresh_result = fresh.model(&mut wire).await;
                assert_eq!(fresh_result.is_ok(), mode == "network-failure");
                assert_eq!(
                    wire.requests,
                    requests + usize::from(mode == "network-failure")
                );
                assert_eq!(
                    fresh
                        .ledger
                        .read(&format!("{prefix}.started"))
                        .unwrap()
                        .unwrap(),
                    old_start
                );
                assert!(fresh.ledger.read("model.response").unwrap().is_none());
                for i in 0..30 {
                    assert_eq!(
                        fresh
                            .state(&hash(row(i).unwrap().frame.as_bytes()))
                            .unwrap(),
                        State::Unrun
                    );
                }
                if mode == "network-failure" {
                    let count = wire.requests;
                    fresh.model(&mut wire).await.unwrap();
                    assert_eq!(wire.requests, count, "validated metadata is reused");
                }
            }
        }
    }
}
