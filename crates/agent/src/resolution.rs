// SPDX-License-Identifier: Apache-2.0
//! Finalize policy decisions. Optional judges can only tighten a declared fallback.

use crate::Verdict;

/// Resolve an optional judge's injection finding against an authoritative decision.
/// Missing/recursive fallbacks are unresolved evidence and require human review.
/// Concrete decisions (especially Deny) cannot be replaced by a judge reply.
pub fn resolve(verdict: Verdict, fallback: Option<Verdict>, injection: bool) -> Verdict {
    if verdict != Verdict::Escalate {
        return verdict;
    }
    match fallback {
        Some(Verdict::Deny) => Verdict::Deny,
        Some(Verdict::Allow) if !injection => Verdict::Allow,
        _ => Verdict::Ask,
    }
}
