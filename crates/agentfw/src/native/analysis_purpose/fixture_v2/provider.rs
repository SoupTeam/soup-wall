// SPDX-License-Identifier: Apache-2.0
//! Test-only connected provider purpose. No production mint or API invocation.
use super::*;
use crate::native::consumer::gemini_fixture as gemini;

const PROVIDER_DOMAIN: &[u8] = b"agentfw/analysis-provider-purpose/v1\0";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::native) struct ProviderGrant {
    fixture: FixtureGrant,
    profile: String,
    ledger: String,
    preflight: String,
    signature: String,
}
fn provider_mac(key: &[u8], g: &ProviderGrant) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(key).unwrap();
    m.update(PROVIDER_DOMAIN);
    m.update(&serde_json::to_vec(&(&g.fixture, &g.profile, &g.ledger, &g.preflight)).unwrap());
    m
}
fn preflight_hash(p: &gemini::Preflight) -> String {
    analysis::hash(&serde_json::to_vec(p).unwrap())
}
fn verify_provider(
    key: &[u8],
    g: &ProviderGrant,
    ledger: &str,
    p: &gemini::Preflight,
) -> anyhow::Result<()> {
    use anyhow::ensure;
    let sig = URL_SAFE_NO_PAD.decode(&g.signature)?;
    provider_mac(key, g)
        .verify_slice(&sig)
        .map_err(|_| anyhow::anyhow!("analysis_provider_signature"))?;
    ensure!(
        g.profile == gemini::profile_hash()
            && g.ledger == ledger
            && g.preflight == preflight_hash(p),
        "analysis_provider_binding"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(in crate::native) fn mint_fixture_provider(
    st: &crate::handlers::Shared,
    registration: &crate::pilot_approval::consumer::Registration,
    id: &str,
    ledger: &gemini::ledger::Ledger,
    p: &gemini::Preflight,
) -> ProviderGrant {
    let mut g = ProviderGrant {
        fixture: mint_fixture(st, registration, id),
        profile: gemini::profile_hash(),
        ledger: ledger.identity().unwrap(),
        preflight: preflight_hash(p),
        signature: String::new(),
    };
    g.signature = URL_SAFE_NO_PAD.encode(
        provider_mac(&derive_key(&st.native.as_ref().unwrap().token), &g)
            .finalize()
            .into_bytes(),
    );
    g
}

#[cfg(target_os = "linux")]
pub(in crate::native) struct PendingProvider {
    pending: PendingAnalysis,
    grant: ProviderGrant,
    preflight: gemini::Preflight,
}

#[cfg(target_os = "linux")]
pub(in crate::native) fn consume(
    st: &crate::handlers::Shared,
    g: &ProviderGrant,
    ledger: &gemini::ledger::Ledger,
    p: gemini::Preflight,
) -> anyhow::Result<PendingProvider> {
    use anyhow::Context;
    let native = st.native.as_ref().context("native_not_configured")?;
    verify_provider(&derive_key(&native.token), g, &ledger.identity()?, &p)?;
    // The original verifier rechecks exact live custody/registration/time under
    // locks and atomically spends the SAME nonce before authority withdrawal.
    let pending = consume_fixture(st, &g.fixture).map_err(anyhow::Error::msg)?;
    Ok(PendingProvider {
        pending,
        grant: g.clone(),
        preflight: p,
    })
}

#[cfg(target_os = "linux")]
impl PendingProvider {
    /// Backend is injectable only in this cfg(test) integration. The live
    /// connector is intentionally not selected by an environment variable.
    /// A reviewed controller must supply real authenticated preflight facts.
    pub(in crate::native) async fn deliver<F>(
        self,
        st: &crate::handlers::Shared,
        ledger: &gemini::ledger::Ledger,
        backend: F,
        before_publish: BeforePublish,
    ) -> anyhow::Result<PrivateReview>
    where
        F: std::ops::AsyncFnOnce(&gemini::Prepared) -> anyhow::Result<Vec<u8>>,
    {
        use anyhow::{ensure, Context};
        verify_provider(
            &derive_key(&st.native.as_ref().context("native_not_configured")?.token),
            &self.grant,
            &ledger.identity()?,
            &self.preflight,
        )?;
        // Accepted connected networkless receiver, original purpose withdrawal,
        // full-source transfer and confirmed cleanup all precede egress.
        let mut review = self
            .pending
            .deliver(
                st,
                crate::sandbox::fixture_reader::AnalysisMode::Normal,
                None,
            )
            .await?;
        let prepared = review.with_current(st, |review, q| {
            let source = std::str::from_utf8(&review.source.bytes)?;
            gemini::approved_source(source)?;
            let extra = gemini::provider_copy_charge(source)?;
            review
                .source
                .lease
                .extend_provider(q, extra)
                .map_err(anyhow::Error::msg)?;
            gemini::prepare(
                source,
                &review.request.nonce,
                review.deadline,
                self.preflight,
            )
        })?;
        ensure!(
            prepared.profile == self.grant.profile
                && analysis::hash(prepared.source.as_bytes())
                    == self.grant.fixture.binding.response_sha256,
            "analysis_provider_binding"
        );
        // Durable marker is created under fresh live-state locks before exposing
        // the source to the backend. A cancellation cannot make it replayable.
        let attempt = review.with_current(st, |_, _| ledger.reserve(&prepared))?;
        let raw = match tokio::time::timeout_at(
            tokio::time::Instant::from_std(prepared.deadline),
            backend(&prepared),
        )
        .await
        {
            Ok(Ok(body)) => body,
            error => {
                let quota = matches!(&error,Ok(Err(e)) if e.to_string()=="gemini_quota_stop");
                if let Ok(Err(e)) = &error {
                    attempt.failure(e)?;
                    if let Some(body) = gemini::rejected_body(e) {
                        attempt.raw(body)?;
                    }
                } else {
                    attempt.failure(&anyhow::anyhow!("gemini_timeout_unknown"))?;
                }
                attempt.finish(if quota {
                    "quota_stop"
                } else {
                    "transport_unknown"
                })?;
                anyhow::bail!("analysis_provider_transport_terminal");
            }
        };
        // Store the complete bounded private response (including usage/model)
        // before structural decoding; invalid/blocked responses remain evidence.
        attempt.raw(&raw)?;
        let frame = match gemini::decode(&prepared, &raw) {
            Ok(frame) => frame,
            Err(_) => {
                attempt.finish("invalid")?;
                anyhow::bail!("analysis_provider_invalid");
            }
        };
        drop(raw);
        drop(prepared);
        if let Some((ready, resume)) = before_publish {
            ready
                .send(())
                .map_err(|_| anyhow::anyhow!("analysis_publication_observer"))?;
            tokio::time::timeout_at(tokio::time::Instant::from_std(review.deadline), resume)
                .await??;
        }
        let result = review.with_current(st, |review, _| {
            let decoded = crate::native::consumer::result_contract::ProposedAttempt {
                nonce: &review.request.nonce,
                source: std::str::from_utf8(&review.source.bytes)?,
            }
            .decode(&frame)
            .map_err(|_| anyhow::anyhow!("analysis_provider_result"))?;
            review.summary = decoded.summary;
            review.excerpts = decoded.excerpts.iter().map(|x| x.to_string()).collect();
            Ok(())
        });
        if result.is_err() {
            attempt.finish("stale")?;
            result?;
        } else {
            attempt.finish("valid_untrusted")?;
        }
        // Journal I/O may consume the remaining lifetime; no stale object may
        // escape after it. valid_untrusted describes structure, not delivery.
        if let Err(error) = review.with_current(st, |_, _| Ok(())) {
            ledger.publication_refused(&self.grant.fixture.binding.response_sha256)?;
            return Err(error);
        }
        Ok(review)
    }
}

#[test]
fn gemini_provider_purpose_binds_fixture_profile_ledger_preflight_and_domain() {
    let nonce = crate::token::generate();
    let binding:Binding=serde_json::from_value(serde_json::json!({"quarantine_id":"q","response_sha256":analysis::hash(b"source"),"response_bytes":6,"native_instance":"i","host_generation":"h","consumer_identity":"c","consumer_lifecycle":"l","session_epoch":"e","source_grant_digest":analysis::hash(b"g"),"invocation_binding":analysis::hash(b"call"),"policy_generation":"p"})).unwrap();
    let fixture = FixtureGrant {
        contract: CONTRACT_V2.into(),
        request: analysis::Request {
            nonce,
            source_sha256: binding.response_sha256.clone(),
            source_bytes: 6,
            question_sha256: analysis::hash(analysis::QUESTION.as_bytes()),
            executable_sha256: analysis::hash(b"exe"),
            profile_sha256: analysis::hash(analysis::PROFILE.as_bytes()),
            output_sha256: analysis::hash(analysis::OUTPUT.as_bytes()),
        },
        binding,
        issued: 10,
        expires: 20,
        signature: String::new(),
    };
    let p = gemini::Preflight {
        free_project_confirmed: true,
        quota_available: true,
        counted_tokens: 1,
        counted_request_sha256: analysis::hash(b"request"),
        input_limit: 1_048_576,
        model_version: "gemini-3.8-flash".into(),
    };
    let key = derive_key(&crate::token::generate());
    let mut g = ProviderGrant {
        fixture,
        profile: gemini::profile_hash(),
        ledger: analysis::hash(b"ledger"),
        preflight: preflight_hash(&p),
        signature: String::new(),
    };
    g.signature = URL_SAFE_NO_PAD.encode(provider_mac(&key, &g).finalize().into_bytes());
    assert!(verify_provider(&key, &g, &g.ledger, &p).is_ok());
    for i in 0..6 {
        let mut bad = g.clone();
        match i {
            0 => bad.profile = analysis::hash(b"other"),
            1 => bad.ledger = analysis::hash(b"other"),
            2 => bad.preflight = analysis::hash(b"other"),
            3 => bad.fixture.binding.response_bytes += 1,
            4 => bad.fixture.expires += 1,
            _ => {
                bad.signature = URL_SAFE_NO_PAD.encode(
                    signature(&key, &bad.fixture, DOMAIN)
                        .finalize()
                        .into_bytes(),
                )
            }
        }
        assert!(verify_provider(&key, &bad, &g.ledger, &p).is_err());
    }
    assert!(verify_provider(&key, &g, "foreign ledger", &p).is_err());
    let mut old = g.clone();
    old.profile = analysis::hash(analysis::PROFILE.as_bytes());
    old.signature = URL_SAFE_NO_PAD.encode(provider_mac(&key, &old).finalize().into_bytes());
    assert!(verify_provider(&key, &old, &g.ledger, &p).is_err());
}
