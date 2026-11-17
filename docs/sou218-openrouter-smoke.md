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
