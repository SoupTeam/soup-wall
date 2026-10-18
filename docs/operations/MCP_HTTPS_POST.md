# Constrained native MCP HTTPS POST

SOU-73 adds the Linux-only `sw-native/resources/6` contract and the separate
`sw-native/https-post/linux-pinned/1` executor. It starts from accepted main
`afa00125264b227cdc3e249c1cd010a9c59d65a3`. Existing GET, read and create contracts
are unchanged. This is a candidate for review, not release acceptance.

The [sanitized exact-source report](evidence/SOU73_HTTPS_POST_2026-10-17.json)
records 55/55 passing owned Linux scenarios at
`78906f3580dedbb070cb0ea5cd5614ec760e5266`, with zero skips. The same workflow
passed 386 native unit tests (two existing ignored tests), 115 native router
tests, clippy, and 21 evidence/receiver controls. It retains the earlier failed
fixture run separately. Documentation-only successors do not change the tested
executor, driver or fixture. This evidence does not replace independent review.

## Supported call and operator authority

The original MCP tool is `https_post`; arguments contain exactly `url` and `body`.
The body is a UTF-8 string of at most 4096 **bytes**, including whitespace. JSON
bodies are validated but never normalized or serialized again. An operator fixes
the content type to `text/plain` or `application/json`. Caller-supplied methods,
headers, credentials, cookies, files, multipart and streaming are unsupported.

```json
{"jsonrpc":"2.0","id":"post-1","method":"tools/call","params":{"name":"https_post","arguments":{"url":"https://receiver.example/inbox?item=7","body":"{\"widgets\":7}\n"}}}
```

The exact schema is `native::resource::https_post_schema()`:

```json
{"type":"object","properties":{"url":{"type":"string","minLength":1,"maxLength":2048},"body":{"type":"string","maxLength":4096}},"required":["url","body"],"additionalProperties":false}
```

The registry declares `action_class: network`, untrusted result provenance,
one required `/url` `url_host` egress selector, and one required `/url` `url`
resource selector without aliases/defaults. The exact allowed URL, schema hash,
executor profile hash and selected classifier hash are pinned as in the GET
profile. The resource policy contains `post`, never `network` or `execution`:

```json
{"post":{"endpoint":{"exact_url":"https://receiver.example/inbox?item=7","approved_addresses":["93.184.216.34"]},"content_type":"application/json","max_body_bytes":4096}}
```

This fragment is illustrative, not a public test destination or a complete
installation. `registry()` in `scripts/verify-sou73-https-post.py` creates a full
owned-loopback sample with a disposable CA and an exact private identity/address
exception. It hashes the actual schema, classifier and executor profile.
Tool descriptions are untrusted and cannot grant authority. The unchanged rule
baseline recognizes this supported form as `send_data`; unknown still blocks.

## Admission and execution

The POST binding adds method, content type, body SHA-256 and byte length to exact
policy, argument, authority and executor hashes. The normal authenticated native
session, parent scope, registry, MCP call identity and one-use result binding
remain required. The daemon recomputes this binding; the broker checks it again
after genuine Allow. Deny, unapproved Ask, secret/PII and egress floors remain in
the existing policy path. This profile does not add an approval UI or redeem an
Ask automatically.

The executor shares the reviewed GET URL canonicalization, current-DNS checks,
exact socket pinning, private/metadata restrictions, verified TLS and bounded
response parser. It performs one POST without redirects, proxies, ambient auth,
cookies, retries, secondary destinations or detached workers. Connection timeout
is 3 seconds; total dispatch timeout is 5 seconds. Response limits are 4096 body
bytes, 8192 header bytes, 16384 plaintext HTTP bytes and 65536 encrypted received
bytes. Only a single HTTP 200, Content-Length, UTF-8 text/JSON response is supported.
The bounded URL and fixed headers also bound the request framing. MCP IDs, tool
names and original arguments are retained. The discovery child executes no POST.

## Effects, cancellation and result release

`mcp_https_post_progress` records attempted transmission and bytes accepted by the
local TLS writer even when the execution future is cancelled. These counters
**do not prove receiver commit**: `receiver_observed` remains `unknown`. A process
crash can also interrupt audit publication. Never resend an ambiguous POST
automatically. Resolve its effect through the receiver's independent ledger.

Cancellation before dispatch prevents transmission. Cancellation after some
bytes or a full payload may leave a receiver-side effect. Refusing an injected
response, losing the daemon or closing the client cannot undo that effect.
The existing single-flight protocol closes a session on unsupported pipelining,
cancellation or replay; recovery uses a fresh session. Result inspection remains
mandatory before MCP response release.

The production write helper also has a deterministic partial-write cancellation
test: after a body prefix is accepted, dropping the pending write preserves the
prefix count and performs no resend. This is a bounded-writer unit test; the real
TLS cancellation case separately verifies cancellation after receiver commit.

## Reproduction

Build a clean committed candidate on Linux with Python 3 and OpenSSL available:

```sh
cargo build --locked -p agentfw --bin agentfw
python3 -B scripts/verify-sou73-https-post.py --run --repo "$PWD" \
  --agentfw "$PWD/target/debug/agentfw" --expected-commit "$(git rev-parse HEAD)" \
  --output /tmp/sou73-post-results.json
```

Use a fresh output path. Without `--run`, no processes start. The report retains
exact source and binary identities, actual native gates, original client frames,
independent receiver payload digests and counts, child ledgers, cleanup and useful
continuation. Exit 0 requires complete passing evidence; 1 indicates a failed
check and 2 incomplete/unsupported evidence. Windows compilation and synthetic
grader controls do not establish Linux execution acceptance.

A private append-only `.partial.jsonl` checkpoint retains each completed case
while the driver runs. Its header always says incomplete and never grants
acceptance; only the complete final report can pass.

The `Constrained MCP HTTPS POST` workflow retains failed/incomplete runs as well
as successful ones. Its controls deliberately falsify receiver, payload, policy,
session, content-release and cleanup observations to ensure absence of evidence
cannot be reported as success. No external model access or paid traffic is used.
