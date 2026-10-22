# SOU-106 installed-host development evidence

## Attempt 1 (retained unsuccessful measurement)

Source: `bd1c17c2f18f32438497828b9a60afa2b744e14d`.
[Focused Linux run](https://github.com/SoupTeam/soup-wall/actions/runs/39759490160).
[Original report](attempt-1.json). No passing pilot claim.

Linux setup and focused checks passed: preparation 6/6, gate 12/12,
existing installed-pilot regressions 26/26 and namespace checks 6/6.
Actual host measurement failed. Distinct findings:

- Control host roots selected the empty host project instead of the owned fixture
  root. Original filesystem access was denied. The matched extension now runs
  both hosts with the owned filesystem workspace as their project/root.
- `read_multiple_files` returned per-file errors inside a successful MCP result.
  Nonempty result checking was insufficient; source-specific useful-content
  assertions now reject such results independently of `is_error`.
- `tail=1` selected the trailing empty line of the original text fixture. v1 is
  preserved; v2 requests `tail=2`, retaining the required useful source content.
- POSIX rename can leave both names when restoring the same hard-linked inode.
  Explicit owned-link cleanup and restoration regression preserve original inputs.
- Search-followed-by-read triggered `combined-ask-mcp-derived-read` in protected
  mode. These remain supported benign failures, not reclassified successes.

The run aborted during the first mutation pair. Remaining rows are incomplete,
not passed. The original report and source history retain the unsuccessful
inputs, reasons and denominators. A corrected exact-source run is required.

Local Windows checks are not Linux acceptance. The existing suite uses FIFOs,
POSIX paths/permissions and external temporary directories; its Windows failures
are not suppressed. The focused new gate/restoration suite passed 14/14 with
an owned writable temporary directory and hard-link permissions. Documentation
links passed (232 documents / 881 links before this evidence addition).

## Attempt 2 (full workload, retained failure)

Source: `41e3f10d6c1dd27c530f17e3086363c0fb8c68f3`.
[Focused Linux run](https://github.com/SoupTeam/soup-wall/actions/runs/39760959479).
[Original report](attempt-2.json). All 40 arms ran; source and assets stayed
unchanged and cleanup passed. All eight refusal variants passed, calibrating
nine mutating calls before observing zero protected effects/opens.

The gate remained failed: 9/12 benign pairs passed. Both head-and-diff arms
failed an oracle comparison that incorrectly retained the final newline; the
original server's head slicing omits it. The corrected source-based oracle has
focused head/tail tests. Search-read-status and search-exclusion still failed
in protected mode at the existing `combined-ask-mcp-derived-read` rule.
These original outcomes are retained; no runtime policy/classifier is changed.

The original report called all four failed arms `technical_failures`. The next
report distinguishes `failed_arms` from runtime/transport technical failures and
reports false interruptions separately. This bookkeeping correction does not
change the gate or case outcomes. All per-arm reasons remain available.

Observed successful benign-pair call overhead (27 samples): median 53.467 ms,
p95 125.687 ms. These exclude the failed pairs and are not overall utility or
an accepted latency threshold. The final corrected source requires its own run.

## Latest exact-source measurement

Source: `ce4f76d823f9f1b5a7ea1dec97a8ff260a5f94dc`. [Focused run](https://github.com/SoupTeam/soup-wall/actions/runs/39762231154).
[Full report](measured-report.json), [English scorecard](scorecard.md),
[minimal runtime blockers](runtime-blockers.json).

Gate: **failed**. Benign pairs: 10/12; false interruptions: 2; technical failures: 0; incomplete arms: 0.
Refusal variants: 8; denied executions: 9; forbidden effects: 0.
Source unchanged: True; cleanup: True.

Both search-followed-by-read cases retain their expected useful outcomes.
The current selected policy returns Ask at `combined-ask-mcp-derived-read`;
the default refusal flow does not execute/release the requested read. This is
a reproducible runtime/policy compatibility blocker for this workload. The
measurement increment does not change policy or implement the separately owned
Ask flow. Review the intended approval/policy behavior before claiming pilot
acceptance. Do not reclassify these failures to make the gate pass.

The measured implementation is the source above; subsequent evidence-only
commits preserve its measured identity rather than claiming a new measurement.
No live model, paid access, Phase 4 effectiveness or release claim.

Focused Linux checks on the measured source passed: new gate/restoration 16/16,
existing installed-pilot 26/26, preparation 6/6 and namespace checks 6/6.
Both required real sandbox positive tests passed. The **workflow still failed**
because the actual-host utility gate correctly rejected the two interruptions.

Successful benign pair call overhead: n=29, median 50.294 ms, p95 64.634 ms.
Host startup was materially more expensive: median 1207.341 ms for controls
(n=20) and 6821.055 ms for successful protected arms (n=18). These startup
populations differ; this is not a paired startup delta or a cold-cache claim.
The full report preserves failed-arm timings too. Useful-call overhead alone
must not be presented as total pilot startup cost.
