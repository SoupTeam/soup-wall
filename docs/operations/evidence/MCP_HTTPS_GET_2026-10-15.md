# Native MCP HTTPS GET: exact egress and real receiver evidence

SOU-56, 2026-10-15. Local acceptance passed; final PR CI and maintainer review
still gate source acceptance. No release, deployment or customer change is
claimed. This evidence does not close SOU-56 by itself.

Exact clean build and runtime source:
`283108482d792a33c1a07a3eb9e9a94c2484334c`, based on accepted main
`786003df8223139546dc8ef68ed6adc493bb68f8`.
Subsequent delivery adds documentation/evidence only. Rust/Cargo inputs are
identical from implementation `33ade52` through the final runtime source; the
binary was rebuilt on the latter and retained the same digest.

[Operator contract and reproduction](../MCP_HTTPS_GET.md),
[machine-readable aggregate](MCP_HTTPS_GET_2026-10-15.json),
[immutable raw reports/logs](MCP_HTTPS_GET_2026-10-15.raw.tar.gz),
[archive member verification](MCP_HTTPS_GET_2026-10-15.raw-manifest.json).

## Final results

| Check | Result |
| --- | --- |
| Real stdio MCP/daemon/HTTPS matrix | 48 passed, 0 failed, 0 skipped |
| Linux Agent unit tests | 269 passed, 0 failed, 0 ignored |
| Linux native endpoint tests | 49 passed, 0 failed, 0 ignored |
| Complete Rust workspace tests | 1,111 passed, 0 failed, 9 ignored |
| Strict workspace/all-target Clippy and formatting | passed |
| Complete Python scripts suite | 565 run: 539 passed, 26 environment skips |
| Python benchmark-driver controls | 44 run: 26 passed, 18 environment skips |
| Final HTTPS fixture/grader controls | 24 passed, 0 failed |
| Workflow actionlint and local Markdown links | passed |

The Rust workspace checks ran on the identical production/Cargo inputs at
`33ade52`; the final binary and complete HTTPS matrix ran at `2831084`.
The complete Python scripts suite was repeated after the final driver changes.
Skipped/ignored cases are retained in their logs and are not counted as positive
acceptance. No external model or provider request was made.

The positive platform was Linux aarch64, kernel `6.12.76-linuxkit`, overlayfs,
Rust 1.98.1, Python 3.11.2 and OpenSSL 3.0.20. Actual runtime ran as UID/GID 65532
with zero effective capabilities, `NoNewPrivs: 1`, seccomp, and Docker
`--network=none`. Only owned loopback receivers were reachable. The container,
all 48 private case fixtures and temporary CA were removed.

Agent SHA-256:
`043baf5b7051e057ab63cb3b4ebc81f022b2adff4c31300ff4a356897a37c971`.
Image ID:
`sha256:8837b0ac3f566cc131f2f1d621e8bc302fc229f2e8e582a8c6344a44d98c918e`.
The retained 796-file input manifest SHA-256 is
`867ee6cb72f2467d9b4ac270ca8cec24947da0748724533ff8293d4fbb27e52c`.
Driver, receiver, helper, registry, policy and certificate identities are
recorded beside each observation. Runtime source was clean before and after,
and the binary digest remained stable.

## Independently observable effects

The 48 cases opened 56 native sessions. Independent receiver processes recorded
97 TCP connections and 93 HTTP GETs at the approved primary endpoint. Secondary
and poisoned-proxy receivers each recorded **zero connections and requests**.
The four TLS rejection cases account for connections that never became HTTP
requests. The discovery MCP child never received a tool invocation.

Seven deliberately useful admitted fetch replies matched exact independent
receiver body hashes/byte counts and actual native released-frame hashes.
There were zero false interruptions among these seven synthetic permitted
calls; this is not a held-out classifier accuracy rate. All 97 completed HTTPS
values/errors correlate with their real native Allow, original arguments/host
ID, session, call and binding. All 48 useful read continuations match actual
native result release. Ordinary supported errors continue in the same session;
unsupported schema/protocol calls and cancellation end the affected collector
and recover in a fresh session.

The matrix proves the following within this owned profile:

- Native Deny, unconfirmed Ask and classifier Deny/Ask issue zero requests and
  open zero target connections. URL/path/query/host/port, credential and native
  authority substitutions cannot reach an unauthorized receiver.
- Default loopback installation without an exact exception fails at daemon
  startup. The separate real DNS-mismatch case obtains authentic native Allow
  but refuses before any TCP connection. Static regressions also cover private,
  metadata, reserved and embedded-address forms and connection-authority changes.
- Redirect capture makes one primary GET and no second-origin connection.
  Proxy environment poisoning and a prior Set-Cookie do not alter requests.
  Wrong hostname, untrusted, expired and invalid TLS each make one connection
  and zero HTTP requests, with honest `request_issued: false` errors.
- Timeout, oversized body/headers, invalid UTF-8/JSON, compression, unsupported
  content/charset/status, transfer encoding, interim response, truncation and
  duplicate Content-Length return inspected errors without a partial document.
  Unit tests independently exercise the exact 4,096-byte document limit and
  actual encrypted socket-read cap. Successful receipts retain observed
  encrypted and plaintext byte counts.
- Seventy consecutive invalid-UTF-8 responses complete 70 correlated native
  errors, followed by a useful read in the same session. Capacity does not leak.
- A privileged-role payload containing an actual newline is withheld by native
  result inspection. Original document text is its own MCP text block rather
  than a nested escaped JSON string. The receiver's GET remains recorded;
  withholding its result cannot undo the request.

## Cancellation, session isolation and replay

Two transport fixtures hold a genuine upstream Allow while the client queues
cancellation or overlap. The real session ends before that held receipt is
released. Neither case opens a target connection; a fresh session performs a
useful read. A proxy BrokenPipe after this deliberate downstream cancellation
is retained and narrowly distinguished from upstream admission failure. A
fabricated or missing Allow cannot satisfy the grading condition.

The additional active-cancellation case first waits for the independent
receiver to record one verified-TLS GET. Cancellation is queued 10.583 ms after
that observation. The original collector ends its native session, returns no
fetch result, produces no execution-completion event and requires no forced
cleanup. A fresh collector then completes a native-admitted useful read with
exact released bytes and clean EOF. The one issued GET is honestly retained.

The process cross-session fixture substitutes an already ended session and
retains the real daemon's HTTP 409. The affected collector ends without a fake
MCP reply; a third session proves useful recovery. Duplicate original JSON-RPC
IDs are refused. Separate real native-router tests exercise live session/epoch
bindings, cross-session result grants, spent-result replay, host IDs and
contract downgrade. These are specific supported-boundary proofs, not a new
generic parent URL-grant protocol or arbitrary server sandbox.

## Original red results and independent review

The initial Linux check lacked a registry cache. A later strict Clippy run
reported a collapsible nested condition, which was repaired without a warning
allowance. A parallel full-workspace link exhausted Docker memory; the first
runtime driver terminated with signal 9 during that build. The runtime run has only a partial log,
not a passing full report. Sequential workspace checking and standalone runtime
execution passed. Original setup/Clippy/resource-exhaustion logs remain in the
archive.

The next complete 47-case report originally graded **1 passed / 46 failed**:
its strengthened checker incorrectly demanded native registry identity on
ordinary MCP audit entries. All 402 native entries in that capture match their
installed registry; 54 ordinary MCP entries have a different shape. Additional
driver repairs preserve actual schema/session refusal instead of expecting
fabricated ordinary replies, use the executor's actual error codes, and account
for a held-receipt downstream disconnect after cancellation.

The original report is unchanged. A separate read-only regrade of that capture
records 47 passing existing cases, explicitly without claiming full acceptance
of the added 48th case. The final clean **48-case re-execution** above, rather
than a relabeled earlier report, is the current passing result.

An independent agent reviewed the production contract/transport and the
acceptance grader. Two early P1 findings led to raw text-block inspection and
byte counting below HTTP parsing. The reviewer independently regraded all 48
final cases, checked committed driver identities and manually verified active
cancellation, cleanup and useful recovery. No actionable findings remain in
that reviewed scope. This is not maintainer approval; hosted CI and peer review
on the final PR head remain required.

Raw archive SHA-256:
`1b894c57f20ad50653f827184efc678b03e2489fcbf93d7f8475a303155934a9`.
All 26 archive members were re-read and checked against their byte counts and
SHA-256 manifest. Original final report SHA-256:
`0976432cc72315584674aee7eb1a4a77f8c6049aacf14d71e50613ae514e515a`.
