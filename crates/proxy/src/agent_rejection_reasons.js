// SPDX-License-Identifier: Apache-2.0
// SOU-241: fixed text for the allowlisted Agent rejection reasons
// (`sw-agent-rejection-reason/1`). The Console stores only the code; this
// table supplies the label and a safe next step. An unknown or missing code
// never renders server text: it falls back to fixed wording.
const agentRejection = (() => {
  const VERSION = 1, CODE = /^[a-z_]{1,48}$/;
  const T = (category, label, next) => Object.freeze({ category, label, next });
  const REASONS = Object.freeze({
    issuer_key_unknown: T("trust", "Signed by an issuer key the Agent does not trust", "Deploy again with a trusted Console signing key, or update the Agent's pinned keyring through your normal change process."),
    issuer_key_revoked: T("trust", "Signed by a revoked issuer key", "Deploy again after the Console signs with a current, non-revoked key."),
    keyring_unavailable: T("trust", "The Agent could not read its trusted keyring", "Check the Agent's keyring file and service account on the host, then redeploy."),
    signature_invalid: T("signature", "Signature did not verify", "Redeploy the approved revision so the Console issues a freshly signed bundle."),
    digest_mismatch: T("signature", "Policy digest did not match the signed bundle", "Redeploy the approved revision; do not edit bundles in transit."),
    audience_mismatch: T("signature", "Bundle was for a different tenant or Agent", "Check that the Agent is enrolled to this tenant and Agent ID, then redeploy."),
    schema_unsupported: T("signature", "Bundle schema is not supported by this Agent", "Upgrade the Agent to a version that supports this Console, then redeploy."),
    bundle_malformed: T("signature", "Bundle metadata was malformed", "Redeploy the approved revision; report a Console defect if it repeats."),
    bundle_expired: T("expiry", "Bundle had expired when the Agent checked it", "Check the Agent host clock, then redeploy to issue a fresh bundle."),
    issued_in_future: T("expiry", "Bundle was issued in the future for the Agent's clock", "Check the Agent and Console clocks (NTP), then redeploy."),
    lifetime_invalid: T("expiry", "Bundle lifetime was outside the allowed window", "Redeploy the approved revision with the default lifetime."),
    policy_invalid: T("policy", "Policy failed the Agent's validation", "Fix the policy as a new revision, approve it and deploy that revision."),
    policy_too_large: T("policy", "Policy was empty or over the size limit", "Reduce the policy as a new revision, approve it and deploy that revision."),
    sequence_stale: T("activation", "Agent already runs this or a newer deployment", "No action for this candidate; check the Agent's latest applied deployment."),
    activation_failed: T("activation", "Agent verified the bundle but could not activate it", "Check the Agent's local status and logs, then retry the deployment.")
  });
  const LEGACY = T("unknown", "Rejected; this Agent did not report a reason", "Upgrade the Agent to report reasons, or inspect its local status, then redeploy.");
  const UNKNOWN = T("unknown", "Rejected with a reason this Console does not recognise", "Inspect the Agent's local status, then redeploy.");
  // Returns fixed text only. `code` must be a short allowlisted token.
  function describe(code) {
    if (code == null) return { code: null, ...LEGACY };
    if (typeof code !== "string" || !CODE.test(code) || !Object.hasOwn(REASONS, code)) return { code: null, ...UNKNOWN };
    return { code, ...REASONS[code] };
  }
  const valid = code => code == null || (typeof code === "string" && CODE.test(code) && Object.hasOwn(REASONS, code));
  return Object.freeze({ VERSION, describe, valid, codes: Object.freeze(Object.keys(REASONS)) });
})();
