# SOU-143 verification ledger

Implementation candidate: `1dcfffb7876c9687f5c301a93fd7da5ed7292526`. Accepted base:
`04efdf1d959599238a0a9a3eb42cbe26b3531b74`.

Status: task-specific native qualification **passed** in workflow `40168804513`
for source `1dcfffb7876c9687f5c301a93fd7da5ed7292526`. The trusted public
projection reports no verification errors: 13 main cases and four emergency-stop
cases passed, with zero residual observed owned processes. Useful original
filesystem/Git operations, exact Ask, provider rejection/redaction, fresh restart,
cancellation, daemon/host loss and stop controls are included.

Every actual client receives all seven selected synthetic inputs. Every other
successful exec contains none of their values; argv, observed private log writes
and retained files contain none. The three-second timeout case truthfully reports
zero authenticated requests and a kernel-attributed native deadline refusal;
it never claims successful authentication. Every other exercised runtime case
has observed authenticated loopback requests. Paid provider calls: zero.

The implementation is ready for TL review. This is not TL approval or final shared
CI/admission; those remain TL-owned. The evidence-only commit does not change the
qualified runtime source.

- `local-attempts.json` records every retained local attempt, including failures,
  source hashes, elapsed time and private-log hashes. macOS controls do not prove
  Linux-only behavior. Platform skips remain unavailable observations.
- `native-*-first-slice.json` records bounded native compile, unit and Clippy
  slices. These alone do not prove actual pinned-host runtime acceptance.
- `native-*-host.json` records independently projected host observations.
  Older failed/incomplete attempts remain evidence of failure, even when a newer
  candidate fixes the cause. They are not interchangeable source qualifications.

Candidate execution uses read-only source, isolated writable scratch and private
loopback-only networking. Runtime inputs are pinned. No paid provider, live
credentials, private raw process tables, environment arrays, argv, or raw
subprocess logs are published here. The public files contain only finite
statuses, counts, hashes and reviewed reason codes.
