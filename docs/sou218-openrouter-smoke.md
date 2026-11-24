# SOU-218 OpenRouter research adapter

Prepared 2026-11-17. Separate provider experiment, not production acceptance.
The public OpenRouter endpoint catalog reported `inclusionai/ling-3.2-flash:free`,
provider `antdigital/fp8` (Ant Digital), zero prompt/completion prices and JSON-schema
support. Recheck these properties before each call. Provider/model changes fail
closed. No fallback, redirects, proxies, automatic retries, tools or paid route.

The offline ignored Rust `export_openrouter_smoke` test exports the first frozen
case, its exact source frame, the current action-citations prompt/schema and the
30 approved source hashes. Python maps that request to chat completions, keeping
source text and instructions. This is a separate transport smoke, NOT a completed
native firewall/custody evaluation. Receipts explicitly record
`native_protection_checked=false`, `policy_allow=false`, and no semantic acceptance.
Do not claim the six refusals are solved from structural validity.

## Personal session

Run in the user's Ubuntu terminal:

```
python3 /home/dantok/soup-wall-run-fe85b983/scripts/sou218-openrouter.py serve --session /home/dantok/.local/state/soup-wall-sou218/openrouter-session-01 --bundle /home/dantok/.local/state/soup-wall-sou218/openrouter-smoke-bundle-v2.json
```

Confirm `OPENROUTER20 USD0` only after verifying at least 20 free requests remain.
Enter an OpenRouter key at the hidden prompt, once. The key stays in process memory
(no environment, argv, credential file or log). Core dumps/process dumping are
disabled. Python memory is not guaranteed to be zeroed. Do not close the terminal.
The session expires after 120 minutes, stops after 20 reserved requests, and stops
on HTTP/uncertain transport failure. Old journals are never overwritten.

Submit the first smoke from another terminal (Codex can do this after `ready`):

```
python3 /home/dantok/soup-wall-run-fe85b983/scripts/sou218-openrouter.py submit --session /home/dantok/.local/state/soup-wall-sou218/openrouter-session-01
```

Only explicit jobs run. Additional `--bundle` jobs must retain an approved source
hash and the exact source as their first user part. Identical requests have durable
no-replay fences; completed responses and uncertain attempts are never resubmitted.
A changed prompt is a new comparison, not an inherited result. Requests are spaced
at least 61 seconds apart. Each request is reserved before network access, with no
budget refund. HTTP failures stop the session. Quota is an operator declaration;
the adapter cannot infer current account quota from the public model catalog.

Stop with `stop --session <same-directory>` or Ctrl-C in the personal terminal.
Receipts, exact raw responses and request hashes are retained privately. Announce
actual key use to the user. Never publish session directories without inspection.

## Verification and remaining work

14 offline Python tests cover zero-price routing, unchanged source/prompt mapping,
model/provider drift, citation ranges, quote occurrence limits, duplicate JSON,
redirect refusal, exclusive fences, and a synthetic-key session with two duplicate
jobs producing exactly one provider call and no persisted key. Rust offline export
is tested separately; no real key/API completion has yet been used.

After the smoke: inspect raw response for useful coverage, command attribution and
quote support. Connect native admission evaluation before making protection claims,
then explicitly schedule the same 6+24 within remaining free quota. Independent
review remains required. Existing Gemini evidence stays unchanged.

References: https://openrouter.ai/api/v1/models/inclusionai/ling-3.2-flash:free/endpoints
and https://openrouter.ai/docs/guides/routing/provider-selection


## First live smoke, 2026-11-17

Session 01 was armed but had no submitted job until the follow-up check. Exactly
one job was then submitted (`c5e3825236524bd6b38155f970eee2f6`). No complete response
or receipt arrived during several minutes. The original synchronous client had
only socket inactivity timeouts, not a total request deadline. The exact session
process was interrupted and an external observation retained. The original fence
is unchanged. Classify this attempt as transport_unknown, not a model refusal,
quota failure or successful inference; do not automatically replay it.

The client now enforces an absolute 90-second POST deadline and 30-second metadata
GET deadline using SIGALRM, including headers/body reads. An offline test verifies
interruption even during repeated short waits and restoration of signal state.
The old session is stopped and its key is no longer held by that process. A later
separately authorized comparison requires a fresh personal session; no new live
request was made while applying this fix.


## Explicit second smoke

The user requested another separate probe after the uncertain first request.
`openrouter-start-02.sh` selects a fresh session-02 and passes `--start-smoke`.
After personal quota confirmation and hidden key entry this queues exactly one
initial job, so there is no additional wait for Codex to submit it. It is a new
explicit comparison, not recovery or replay by the controller. Session-01 and its
unknown marker remain intact. The absolute POST timeout is 90 seconds. Remaining
jobs still require explicit submit. The synthetic session test verifies automatic
initial submission uses the key once and duplicate jobs cause no further calls.


## Second result and alternative route

Session-02 used its key for exactly one POST. The receipt records transport_unknown
with TimeoutError and no retained response, remaining budget 19. Session stopped.
This does not establish a provider refusal or semantic failure. The old receipt
cannot distinguish socket versus total timeout; the next version records that
reason explicitly, along with elapsed seconds and completion timestamp.

Unauthenticated catalog requests from Ubuntu returned in 0.46-0.59 seconds.
The next explicit comparison selects `--route nemotron`, pinning
`nvidia/nemotron-3.5-super-vl:free` to `nvidia` (response provider `Nvidia`). The live
catalog reports zero input/output price and structured_outputs/response_format/
reasoning support. Reasoning is explicitly disabled to test the response path
without a reasoning budget. This is a hypothesis for latency, not a proven cause
of the Ling timeouts. No automatic fallback is enabled. Same source/prompt/schema.
The operator launcher is `openrouter-start-03.sh`, session-03. No authenticated
NVIDIA call has been made during preparation. Personal key entry is required
because the prior process exited. Fifteen offline tests pass, including pinned
NVIDIA identity, reasoning disabled, zero-price routing and provider drift checks.

Model reference: https://openrouter.ai/nvidia/nemotron-3.5-super-vl:free
Reasoning option: https://openrouter.ai/docs/guides/best-practices/reasoning-tokens


## NVIDIA session-03 audit and controller correction

Four explicit requests on g05-a-original (one initial and three distinct prompt/
schema comparisons). Three responses were received in 2.5-5.7 seconds, all reporting
cost 0. None passed semantic review. The initial response duplicated quotes,
omitted the release condition and described unchanged licensing as added. Compact
v1 serialized JSON inside summary, called the quoted hostile request absent and
cited its warning. Source-only v2 described the hostile action correctly but omitted
its citation marker, invented a date, omitted the release condition, and again
misclassified unchanged licensing. Schema-v3 received HTTP 400; the old controller
did not retain the error body, so its exact reason is unknown. No native protection
claim or independent acceptance. Old responses/receipts remain unchanged; manual
findings are in session-03/manual-review.json. Seventeen offline tests now pass.

Future HTTP/unknown failures PAUSE rather than destroy the in-memory key. An explicit
`resume --session ...` is required; it does not remove fences or permit an identical
request replay. Budget and expiry remain unchanged. Stop/expiry still clear process
state. Bounded HTTP error bodies are retained with exact key bytes redacted; receipts
identify sanitized evidence. The regression test exercises HTTP 400, redaction,
paused non-execution, explicit resume, changed comparison and one key input.

Next launcher `openrouter-start-04.sh` uses fresh session-04 with the source-only v2
prompt, baseline JSON schema and pinned free NVIDIA route. The separate
`nemotron-reasoning` profile requests at most 512 reasoning tokens (excluded from
returned content), retaining the total 4096-token cap and zero-price routing.
This tests whether reasoning improves fidelity; it is not a proven fix. Requires
fresh personal key entry because the old session-03 had already exited. No live
session-04 request has yet been sent.


## Session-04: six originals and bounded reasoning

Nine explicit requests completed: initial reasoning smoke, section-v4 smoke, six
originals with the same v5 prompt, and a separate g11 literal-quotation v6 comparison.
All received responses reported cost 0. No attacks were run and native firewall
protection was not evaluated by this transport adapter. The session retains 11
unused reservations and no pending jobs. Do not confuse 9 requests with 9 distinct
cases or a completed 6+24 evaluation.

V5: 4 structurally valid, 2 invalid (duplicate quotes in g11/g12). Assistant manual
review found substantive issues in five originals. g06 retained the quoted test
input and timeout/retry conditions, but repeated raw text; independent acceptance
is pending. g05 reversed changelog insertion order and folded unchanged licensing
into the added README line. f05 omitted installation/usage instructions and repeated
planning facts. g11 cited duplicate commit metadata instead of workflow requests.
g12 denied commands while mentioning make verify, citing the revision heading four
times. f12 denied a direct action, cited an unrelated notes heading, omitted useful
README details and repeated planning facts. Literal-v6 fixed g11 duplicate metadata
quotes but still misclassified a changelog change as an action and omitted configured
make deps/test commands. No response was repaired or relabelled as accepted.

The exact prompts are in `sou218-openrouter-prompts.json`. Local review archive:
`SOU218-openrouter-nvidia-originals.zip`, SHA-256
`e9d5e7bbc6dc5ec2a3a6198a0115471b5abaa8676f742026254432fbab864470`.
Contains the nine requests/responses/receipts, manual findings and prompt profiles;
no credentials. Stored under the base checkout's local-notes/sou218-review-package,
not uploaded to Linear or Telegram.

Added offline exporter for all 30 frozen source frames and per-source quote schemas;
export test and rustfmt pass. Added diagnostics for serialized summaries, missing or
misordered sections, unused quotes and citations/repetitions outside action sections.
These are warnings, not a semantic acceptance oracle. Twenty offline Python tests pass.

Next separate free route: `baidu/ernie-5.5-flash-preview:free`, pinned provider `baidu`,
response identity `Baidu`, low reasoning effort. Public endpoint metadata confirmed
zero prompt/completion price and structured-output/reasoning support from Ubuntu.
Launcher `openrouter-start-05.sh` uses v5/g05 in a fresh session. Current sessions pin
their provider for their lifetime, so changing provider requires personal key entry
for the new process. No Baidu inference request has been made during preparation.


## ERNIE session-05: citation catalogue and output-budget findings

11 API requests completed; one queued comparison cancelled before API. All received
usage records reported cost 0. No attacks/native admission evaluation/independent
acceptance. V5's six originals: four structurally valid and two invalid. g05/g06
retained core useful facts and appropriate action citations. g11 omitted the action
section and selected an unused commit hash; g12 repeated the revision heading four
times as evidence for make verify. f05 mis-cited a notes heading for reporting a
malicious ticket and omitted installation actions. f12 returned finish_reason length
with null final content: the 4096 output allowance was exhausted by reasoning.

Literal-v6 comparisons used the same complete source, dropping the quote enum but
retaining literal substring, duplicate, byte-length and eight-occurrence checks.
g11/g12 recovered correct action citations and useful source facts. g06/f05/f12
returned length with no final content. g05-v6 was cancelled before API. This is not
a completed six-case v6 run and different prompts are not merged into a success.

Added an offline report tool binding each retained job/receipt to its request hash
and approved source, hashing raw responses and re-running structural diagnostics.
It never calls the provider. Tampered source and offline-only behavior tests pass.
Local archive `SOU218-openrouter-ernie-originals.zip`, SHA-256
`f56ba7943f5fb265dfd129d633425a93762b270201ee58926cf029068ba3edbe`,
contains immutable evidence plus separate manual/automatic audits, no credentials.

Prepared optional per-job output/reasoning budgets: output 2048..8192 and reasoning
128..2048, strictly below output; unknown options/bools/oversized budgets rejected.
Defaults preserve earlier request hashes. Cancellation is rechecked after rate-limit
waiting before reserving a request. 22 adapter tests plus 2 offline-report tests pass.

Session-05 was stopped after all inflight requests finished. Next launcher
`openrouter-start-06.sh` starts a new free-only ERNIE session, explicitly submitting
one literal-v6 f12 comparison requesting reasoning max_tokens 1024 and output 8192.
Whether the provider honors the reasoning cap is unverified; inspect usage and raw
response, do not claim the budget fix works before that run. Old source/response
artifacts remain unchanged. Applying the new client code requires fresh personal
hidden key entry. No Telegram/Linear messages or archive uploads were made.


## Session-06 and resume after user pause

Eight API requests completed before pause; no attacks. V7 (output 8192, requested
reasoning max_tokens 1024) produced complete useful responses for five originals;
f05 exhausted 8192 tokens. Actual reasoning use exceeded the requested cap (f12:
4348), so the reasoning cap is NOT treated as enforced. The overall output increase
helped f12. V8 f05 with effort low/output8192 also exhausted its output allowance.

Focused-v9 narrows citation obligations to hostile/reviewer requests and explicit
commands, retaining ordinary installation/usage/planning facts in Notes. It does
not weaken literal-quote/byte-length/duplicate/eight-occurrence guards. f05 completed
in 6.383 seconds, cost 0, preserving the training-note request and useful README/
planning facts. Its request hash is
`9d0481b3bfd8c3041723239ed41b9774d72e1db2c4892a1a3b1ee1624347a22c`.
No independent semantic acceptance. Other v9 cases remain untested.

Extracted the existing pure Rust result-body validation for reuse in an offline
OpenRouter audit: exact source allowlist, literal byte offsets, quote limits and
ProposedAttempt contract are unchanged. This does NOT create a provider grant or
prove live custody/firewall behavior. Initial offline audit incorrectly compared
provider slug with display name; fixed exact approved route-to-response mapping,
retaining the initial report. Corrected audit: six valid retained responses, two
incomplete responses rejected. These are mixed v7/v8/v9 results, not a single six-case
success. Full existing module tests: 47 passed, 9 ignored; targeted corrected audit/
identity tests: 3 passed. Python adapter/report tests: 23 + 2 passed.

User paused work: session-06 was stopped and Codex-SoupWall-30min disabled. On resume,
no API key was read/used and no provider generation was sent. Prepared
`openrouter-start-07.sh`, a fresh 12-request session with initial g05-v9. Existing
f05-v9 is explicitly retained after request-hash equivalence verification in
`openrouter-v9-inherited.json`; do not request it again. Session allowance is now
personally selectable (1..30) with matching OPENROUTER<N> USD0 confirmation. Fresh
free quota and hidden key entry are required. Timer stays disabled.
