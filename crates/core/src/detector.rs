// SPDX-License-Identifier: Apache-2.0

//! The uniform interface every detection stage implements.

use crate::{Context, Finding};

pub trait Detector: Send + Sync {
    /// Stable id, e.g. "injection".
    fn name(&self) -> &'static str;

    /// Inspect `ctx` and return zero or more findings.
    fn inspect(&self, ctx: &Context) -> Vec<Finding>;

    /// A trusted execution owner may identify the exact formatter-owned object
    /// hash in an otherwise entirely untrusted result. This is not wire input
    /// or an origin verifier. Every detector defaults to the original bytes.
    /// The injection implementation changes only the weak encoding contribution;
    /// signatures, model input, other heuristics and all other detectors stay raw.
    fn inspect_with_formatter_hash(
        &self,
        ctx: &Context,
        _span: &std::ops::Range<usize>,
    ) -> Vec<Finding> {
        self.inspect(ctx)
    }
}
