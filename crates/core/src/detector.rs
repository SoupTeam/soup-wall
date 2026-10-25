// SPDX-License-Identifier: Apache-2.0

//! The uniform interface every detection stage implements.

use crate::{Context, Finding};

pub trait Detector: Send + Sync {
    /// Stable id, e.g. "injection".
    fn name(&self) -> &'static str;

    /// Inspect `ctx` and return zero or more findings.
    fn inspect(&self, ctx: &Context) -> Vec<Finding>;

    /// Trusted native result boundary only. Ranges attribute fixed formatter
    /// separators, never body safety or authority. No wire field selects this.
    fn inspect_attributed_result(
        &self,
        ctx: &Context,
        _: &[std::ops::Range<usize>],
    ) -> Vec<Finding> {
        self.inspect(ctx)
    }

    /// Inspect a native MCP result after a trusted local, content-sensitive
    /// reviewer has affirmatively classified the complete original delivery
    /// as data. Callers must bind the review to every original channel; format,
    /// a missing keyword, model failure or a wire-supplied claim is insufficient.
    /// Independent detectors preserve their findings by default.
    fn inspect_reviewed_result_data(&self, ctx: &Context) -> Vec<Finding> {
        self.inspect(ctx)
    }
}
