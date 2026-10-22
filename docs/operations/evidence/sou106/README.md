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
