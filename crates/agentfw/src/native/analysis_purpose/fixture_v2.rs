// SPDX-License-Identifier: Apache-2.0
//! Test-only v2 purpose. Not an operator mint, endpoint or production permission.
use super::*;
use crate::sandbox::fixture_reader::analysis;

const CONTRACT_V2: &str = "sw-analysis-purpose/2";
const DOMAIN: &[u8] = b"agentfw/analysis-purpose-signature/v2\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::native) struct FixtureGrant {
    contract: String,
    binding: Binding,
    request: analysis::Request,
    issued: u64,
    expires: u64,
    signature: String,
}

fn signature(key: &[u8], grant: &FixtureGrant, domain: &[u8]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(domain);
    mac.update(
        &serde_json::to_vec(&(
            &grant.contract,
            &grant.binding,
            &grant.request,
            grant.issued,
            grant.expires,
        ))
        .expect("fixed claims"),
    );
    mac
}

fn verify_fixture(
    key: &[u8],
    grant: &FixtureGrant,
    binding: &Binding,
    executable: &str,
    now: u64,
) -> Result<(), &'static str> {
    let decoded = URL_SAFE_NO_PAD
        .decode(&grant.signature)
        .map_err(|_| "analysis_v2_signature")?;
    signature(key, grant, DOMAIN)
        .verify_slice(&decoded)
        .map_err(|_| "analysis_v2_signature")?;
    if grant.contract != CONTRACT_V2
        || &grant.binding != binding
        || grant.request.source_sha256 != binding.response_sha256
        || grant.request.source_bytes != binding.response_bytes
        || grant.request.check(executable).is_err()
    {
        return Err("analysis_v2_binding");
    }
    if now < grant.issued || now >= grant.expires || grant.expires <= grant.issued {
        return Err("analysis_v2_time");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(in crate::native) fn mint_fixture(
    st: &crate::handlers::Shared,
    registration: &crate::pilot_approval::consumer::Registration,
    id: &str,
) -> FixtureGrant {
    let native = st.native.as_ref().unwrap();
    let firewall = st.firewall.lock().unwrap();
    let policy = super::super::canonical_digest(
        &serde_json::to_value(firewall.policy_for_diagnostics()).unwrap(),
    );
    let q = native.quarantine.lock().unwrap();
    let binding = q
        .purpose_binding(
            id,
            registration,
            native.instance_id(),
            &policy,
            native.monotonic_now(),
        )
        .unwrap();
    let request = analysis::Request {
        nonce: crate::token::generate(),
        source_sha256: binding.response_sha256.clone(),
        source_bytes: binding.response_bytes,
        question_sha256: analysis::hash(analysis::QUESTION.as_bytes()),
        executable_sha256: crate::sandbox::fixture_reader::reader_identity().unwrap(),
        profile_sha256: analysis::hash(analysis::PROFILE.as_bytes()),
        output_sha256: analysis::hash(analysis::OUTPUT.as_bytes()),
    };
    let now = super::super::wall_time_ms().unwrap();
    let mut grant = FixtureGrant {
        contract: CONTRACT_V2.into(),
        binding,
        request,
        issued: now,
        expires: now + 30_000,
        signature: String::new(),
    };
    grant.signature = URL_SAFE_NO_PAD.encode(
        signature(&derive_key(&native.token), &grant, DOMAIN)
            .finalize()
            .into_bytes(),
    );
    grant
}

#[cfg(target_os = "linux")]
pub(in crate::native) fn shorten_fixture(
    st: &crate::handlers::Shared,
    grant: &mut FixtureGrant,
    millis: u64,
) {
    grant.expires = super::super::wall_time_ms().unwrap() + millis;
    grant.signature = URL_SAFE_NO_PAD.encode(
        signature(
            &derive_key(&st.native.as_ref().unwrap().token),
            grant,
            DOMAIN,
        )
        .finalize()
        .into_bytes(),
    );
}

#[cfg(target_os = "linux")]
pub(in crate::native) fn old_profile_fixture(
    st: &crate::handlers::Shared,
    grant: &FixtureGrant,
) -> FixtureGrant {
    let mut old = grant.clone();
    old.request.profile_sha256 = analysis::hash(b"sw-analysis-fixture/1;source=262144;chunk=4096;frame=4096;summary=2048;citations=8x256;provider=none");
    old.signature = URL_SAFE_NO_PAD.encode(
        signature(
            &derive_key(&st.native.as_ref().unwrap().token),
            &old,
            DOMAIN,
        )
        .finalize()
        .into_bytes(),
    );
    old
}

#[cfg(target_os = "linux")]
pub(in crate::native) struct PendingAnalysis {
    registration: crate::pilot_approval::consumer::Registration,
    grant: FixtureGrant,
    source: super::super::quarantine::ReaderSource,
}

#[cfg(target_os = "linux")]
pub(in crate::native) fn consume_fixture(
    st: &crate::handlers::Shared,
    grant: &FixtureGrant,
) -> Result<PendingAnalysis, &'static str> {
    let native = st.native.as_ref().ok_or("native_not_configured")?;
    if !st.config.enforce || st.config.judge.enabled {
        return Err("native_enforcement_required");
    }
    let executable =
        crate::sandbox::fixture_reader::reader_identity().map_err(|_| "analysis_v2_executable")?;
    let (registration, source) = {
        let mut sessions = native
            .sessions
            .lock()
            .map_err(|_| "native_state_unavailable")?;
        let registration = sessions
            .consumers
            .get(&grant.binding.host_generation)
            .ok_or("analysis_consumer_missing")?
            .clone();
        let firewall = st.firewall.lock().map_err(|_| "native_state_unavailable")?;
        let policy = super::super::canonical_digest(
            &serde_json::to_value(firewall.policy_for_diagnostics())
                .map_err(|_| "analysis_policy")?,
        );
        let mut q = native
            .quarantine
            .lock()
            .map_err(|_| "analysis_quarantine_state")?;
        registration
            .verify(
                native.instance_id(),
                &native.registry_sha256,
                super::super::wall_time_ms()?,
            )
            .map_err(|_| "analysis_consumer_unverified")?;
        let expected = q.purpose_binding(
            &grant.binding.quarantine_id,
            &registration,
            native.instance_id(),
            &policy,
            native.monotonic_now(),
        )?;
        verify_fixture(
            &derive_key(&native.token),
            grant,
            &expected,
            &executable,
            super::super::wall_time_ms()?,
        )?;
        let source = q.reader_source(expected)?;
        commit_claims(
            &mut sessions,
            &grant.request.nonce,
            grant.issued,
            grant.expires,
            &registration,
            super::super::wall_time_ms()?,
        )?;
        q.spend(&grant.binding.quarantine_id);
        (registration, source)
    };
    super::super::pilot_stop::revoke_selected(
        st,
        registration.host(),
        registration.authorities(),
        registration.authority_expiry(),
    )
    .map_err(|(code, _)| code)?;
    Ok(PendingAnalysis {
        registration,
        grant: grant.clone(),
        source,
    })
}

/// No Serialize/Debug/tool-response conversion. Full retained custody carries
/// original findings, taint, provenance and identities beside untrusted analysis.
#[cfg(target_os = "linux")]
pub(in crate::native) struct PrivateReview {
    pub summary: String,
    pub excerpts: Vec<String>,
    pub custody: Vec<u8>,
    pub request: analysis::Request,
    _budget: super::super::quarantine::AnalysisBudget,
}

#[cfg(target_os = "linux")]
pub(in crate::native) type BeforePublish = Option<(
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
)>;

#[cfg(target_os = "linux")]
impl PendingAnalysis {
    pub(in crate::native) async fn deliver(
        self,
        st: &crate::handlers::Shared,
        mode: crate::sandbox::fixture_reader::AnalysisMode,
        before_publish: BeforePublish,
    ) -> anyhow::Result<PrivateReview> {
        use anyhow::{ensure, Context};
        let native = st.native.as_ref().context("native_not_configured")?;
        let instance = &self.grant.binding.native_instance;
        confirm_source_disposal(st, instance, &self.registration).map_err(anyhow::Error::msg)?;
        let now = super::super::wall_time_ms().map_err(anyhow::Error::msg)?;
        let expires = self.grant.expires.min(self.registration.expires());
        ensure!(now < expires, "analysis_v2_time");
        let deadline = self
            .source
            .deadline
            .min(std::time::Instant::now() + std::time::Duration::from_millis(expires - now));
        let mut reserved = None;
        let frame = crate::sandbox::fixture_reader::analyze_retained(
            deadline,
            self.grant.request.clone(),
            mode,
            || {
                confirm_source_disposal(st, instance, &self.registration)
                    .map_err(anyhow::Error::msg)?;
                let sessions = native
                    .sessions
                    .lock()
                    .map_err(|_| anyhow::anyhow!("native_state_unavailable"))?;
                let firewall = st
                    .firewall
                    .lock()
                    .map_err(|_| anyhow::anyhow!("native_state_unavailable"))?;
                let policy = super::super::canonical_digest(&serde_json::to_value(
                    firewall.policy_for_diagnostics(),
                )?);
                let mut q = native
                    .quarantine
                    .lock()
                    .map_err(|_| anyhow::anyhow!("analysis_quarantine_state"))?;
                check_current(st, &sessions, &self.registration, &self.grant, expires)?;
                let source = self
                    .source
                    .reserve_analysis(
                        &mut q,
                        native.instance_id(),
                        &policy,
                        native.monotonic_now(),
                    )
                    .map_err(anyhow::Error::msg)?;
                let bytes = source.bytes.clone();
                reserved = Some(source);
                Ok(bytes)
            },
        )
        .await?; // Returns bytes ONLY after required recipient disposal and EOF.
        let source = reserved.context("analysis_reservation_missing")?;
        if let Some((ready, resume)) = before_publish {
            ready
                .send(())
                .map_err(|_| anyhow::anyhow!("analysis_publication_observer"))?;
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), resume).await??;
        }
        // Recheck under the same lock ordering as consume and reservation. No
        // await occurs between this current-state check and object construction.
        confirm_source_disposal(st, instance, &self.registration).map_err(anyhow::Error::msg)?;
        let sessions = native
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("native_state_unavailable"))?;
        let firewall = st
            .firewall
            .lock()
            .map_err(|_| anyhow::anyhow!("native_state_unavailable"))?;
        let policy = super::super::canonical_digest(&serde_json::to_value(
            firewall.policy_for_diagnostics(),
        )?);
        let q = native
            .quarantine
            .lock()
            .map_err(|_| anyhow::anyhow!("analysis_quarantine_state"))?;
        check_current(st, &sessions, &self.registration, &self.grant, expires)?;
        ensure!(std::time::Instant::now() < deadline, "analysis_v2_time");
        let custody = source
            .recheck(&q, native.instance_id(), &policy, native.monotonic_now())
            .map_err(anyhow::Error::msg)?;
        let decoded = super::super::consumer::result_contract::ProposedAttempt {
            nonce: &self.grant.request.nonce,
            source: std::str::from_utf8(&source.bytes)?,
        }
        .decode(&frame)
        .map_err(|_| anyhow::anyhow!("analysis_invalid_result"))?;
        let review = PrivateReview {
            summary: decoded.summary,
            excerpts: decoded.excerpts.iter().map(|s| s.to_string()).collect(),
            custody,
            request: self.grant.request,
            _budget: source.lease,
        };
        Ok(review)
    }
}

#[cfg(target_os = "linux")]
fn check_current(
    st: &crate::handlers::Shared,
    sessions: &super::super::Sessions,
    registration: &crate::pilot_approval::consumer::Registration,
    grant: &FixtureGrant,
    expires: u64,
) -> anyhow::Result<()> {
    use anyhow::ensure;
    ensure!(
        st.config.enforce && !st.config.judge.enabled,
        "native_enforcement_required"
    );
    let now = super::super::wall_time_ms().map_err(anyhow::Error::msg)?;
    ensure!(now >= grant.issued && now < expires, "analysis_v2_time");
    ensure!(
        sessions
            .consumers
            .get(registration.host())
            .is_some_and(|r| r.identity() == registration.identity()
                && r.generation() == registration.generation()),
        "analysis_v2_consumer_changed"
    );
    ensure!(
        sessions.purpose_spent.get(&grant.request.nonce) == Some(&grant.expires),
        "analysis_v2_spend_missing"
    );
    ensure!(
        registration.physically_disposed()
            && !sessions.entries.values().any(|s| s.host_session.as_deref()
                == Some(registration.host())
                || s.authority_digest
                    .as_ref()
                    .is_some_and(|d| registration.authorities().values().any(|x| x == d))),
        "analysis_purpose_cleanup_unconfirmed"
    );
    ensure!(
        registration
            .authorities()
            .iter()
            .all(
                |(server, digest)| sessions.pilot_cleanup.get(digest).is_none_or(|r| r.verified
                    && r.host_session == registration.host()
                    && r.server_id == *server)
            ),
        "analysis_purpose_cleanup_unconfirmed"
    );
    Ok(())
}

#[test]
fn analysis_v2_fixture_binds_profile_source_question_nonce_and_mac_domain() {
    let binding:Binding=serde_json::from_value(serde_json::json!({
        "quarantine_id":"q","response_sha256":analysis::hash(b"source"),"response_bytes":6,
        "native_instance":"i","host_generation":"h","consumer_identity":"c","consumer_lifecycle":"l",
        "session_epoch":"e","source_grant_digest":analysis::hash(b"grant"),"invocation_binding":analysis::hash(b"call"),"policy_generation":"p"
    })).unwrap();
    let request = analysis::Request {
        nonce: "n".into(),
        source_sha256: binding.response_sha256.clone(),
        source_bytes: 6,
        question_sha256: analysis::hash(analysis::QUESTION.as_bytes()),
        executable_sha256: analysis::hash(b"exe"),
        profile_sha256: analysis::hash(analysis::PROFILE.as_bytes()),
        output_sha256: analysis::hash(analysis::OUTPUT.as_bytes()),
    };
    let mut valid = FixtureGrant {
        contract: CONTRACT_V2.into(),
        binding: binding.clone(),
        request,
        issued: 10,
        expires: 30,
        signature: String::new(),
    };
    let key = derive_key("test-key");
    valid.signature =
        URL_SAFE_NO_PAD.encode(signature(&key, &valid, DOMAIN).finalize().into_bytes());
    assert!(verify_fixture(&key, &valid, &binding, &analysis::hash(b"exe"), 20).is_ok());
    for mode in 0..12 {
        let mut g = valid.clone();
        match mode {
            0 => g.request.nonce = "other".into(),
            1 => g.request.question_sha256 = analysis::hash(b"other"),
            2 => g.request.executable_sha256 = analysis::hash(b"other"),
            3 => g.request.profile_sha256 = analysis::hash(b"other"),
            4 => g.request.output_sha256 = analysis::hash(b"other"),
            5 => g.binding.session_epoch = "other".into(),
            6 => g.binding.policy_generation = "other".into(),
            7 => g.binding.invocation_binding = analysis::hash(b"other"),
            8 => g.contract = CONTRACT.into(),
            9 => g.request.source_bytes += 1,
            10 => {
                g.signature = URL_SAFE_NO_PAD.encode(
                    signature(&key, &g, b"agentfw/analysis-purpose-signature/v1\0")
                        .finalize()
                        .into_bytes(),
                )
            }
            _ => g.expires = 20,
        }
        assert!(verify_fixture(&key, &g, &binding, &analysis::hash(b"exe"), 20).is_err());
    }
    for now in [9, 30, 31] {
        assert_eq!(
            verify_fixture(&key, &valid, &binding, &analysis::hash(b"exe"), now),
            Err("analysis_v2_time")
        );
    }
    // Authentic old-profile MAC with matching source binding still fails.
    for length in [6, 530_442] {
        let mut old = valid.clone();
        old.binding.response_bytes = length;
        old.request.source_bytes = length;
        old.request.profile_sha256 = analysis::hash(b"sw-analysis-fixture/1;source=262144;chunk=4096;frame=4096;summary=2048;citations=8x256;provider=none");
        old.signature =
            URL_SAFE_NO_PAD.encode(signature(&key, &old, DOMAIN).finalize().into_bytes());
        assert_eq!(
            verify_fixture(&key, &old, &old.binding, &analysis::hash(b"exe"), 20),
            Err("analysis_v2_binding")
        );
    }
    // Correctly signed but unauthorized question/profile still fails constants.
    valid.request.question_sha256 = analysis::hash(b"source-controlled question");
    valid.signature =
        URL_SAFE_NO_PAD.encode(signature(&key, &valid, DOMAIN).finalize().into_bytes());
    assert!(verify_fixture(&key, &valid, &binding, &analysis::hash(b"exe"), 20).is_err());
}
