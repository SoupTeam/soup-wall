# Interrupted CI evidence reads (SOU-175)

The trusted admission verifier must read complete current GitHub evidence.
A broken response is neither a failed product test nor successful admission.
The observed [run 40747512117, job 123025126432](https://github.com/SoupTeam/soup-wall/actions/runs/40747512117/job/123025126432)
raised `http.client.IncompleteRead` while reading selected run-attempt jobs.
The exception escaped the previous HTTPError/URLError retry boundary after
the verifier had published its initial checking status.

## Bounded recovery

The client now retries interrupted **GET** reads only. Every attempt starts a
new response and discards the old partial body. Incomplete Content-Length or
chunked bodies, disconnect/reset, body timeout and the existing transient HTTP
429/500/502/503/504 responses can recover within the existing three-attempt,
20-second socket/attempt and 2/4-second backoff envelope (66 seconds per GET).
Body receives use a decreasing deadline, so a slow stream cannot restart the
body timeout on every byte. Complete JSON input is bounded to 8 MiB and 64
nesting levels before parsing. This is a bound on evidence input, not a change
to product limits, CI resource limits or the admission polling deadline.

The reader uses CPython urllib's HTTPResponse socket-backed BufferedReader
for HTTP/HTTPS to decrease receive timeouts. An unsupported wrapper refuses
instead of falling back to an unbounded read. The real local HTTP fixture
exercises that path, including chunked disconnect and slow-body controls.

Malformed complete JSON, response limits and malformed schemas do not gain a
transport retry. Authorization errors retain their blocking outcome without
retry. Exhausted reads leave an explained blocking Pending result when an
already verified status target is known. Routing/initial-read failure without
a verified target fails the trusted job without guessing a status target.
Logs and status descriptions contain finite reason codes, never credentials,
response bodies, private URLs or arbitrary upstream exception messages.

POST is attempted once. A lost or malformed status-write response does not
establish whether GitHub committed the write. The verifier fails with
`status_write_unconfirmed`; it does not retry that POST or send a compensating
status. An already posted checking status remains blocking and the job log
explains the uncertain write. No success is inferred from it.

## Complete current evidence

The selected `/actions/runs/ID/attempts/ATTEMPT/jobs` path is unchanged.
Paginated keyed endpoints must supply a consistent bounded `total_count`.
Each page contains at most 100 objects; identities cannot repeat across pages.
A short page must agree with the total and cannot advertise a next page.
Malformed/contradictory Link metadata is refused; URLs in Link are never
followed. Full pages retain the existing next-page read, and the existing
30-page limit refuses rather than returning a partial inventory. Unkeyed PR
file lists retain the independent `changed_files` comparison and additionally
refuse duplicate file identities.

Current head/base/test-merge parents, exact run/attempt and direct job detail,
selected matrix members, required skips, five CodeQL analyses, fresh run
listings and the final PR state/source checks remain mandatory. Successful
transport recovery never restores authority to a changed head/base, new
attempt, Draft PR, missing member or failed check. No old green result, empty
fallback or evidence cache is used. SOU-160 reuse remains OFF.

## Development reproduction and operator action

Run focused real-loopback regressions and existing gate controls:

```sh
python3 -B -m unittest discover -s scripts/tests -p 'test_ci_*.py' -v
```

The opt-in reproduction compares the accepted predecessor
`37b82bea3bfcab31941d9e142c15e37e64b258a8` with the current client:

```sh
python3 -B scripts/qualify-ci-admission-transport.py
python3 -B scripts/qualify-ci-admission-transport.py --run \
  --output /absolute/private-directory/new-transport-report.json
```

It uses the real urllib/http.client path against an owned loopback HTTP server,
public synthetic data and a fake repository identity. Authorization is not
forwarded to the fixture. It performs **zero real GitHub requests/status
writes**. The bounded report retains baseline/current file hashes, commit
identity and whether the client matches that commit; request/backoff/elapsed
counts; old IncompleteRead; new outage recovery/exhaustion; invalid complete
responses; uncertain POST; and controlled candidate refusal after recovery.
Transport rows use real 2/4-second backoff. Candidate-fixture rows explicitly
virtualize only backoff and are not trusted GitHub qualification.

For an actual outage, inspect the finite reason and the required candidate
status. After GitHub evidence reads recover, rerun only trusted admission on
the current candidate; do not rerun a successful product matrix merely to
repair an evidence read. Keep the original failure and distinguish a Pending
candidate from a successfully admitted one. Do not manually forge success,
change required names/rulesets, enable reuse or extend global deadlines.
Final same-source trusted qualification, Ready, review and merge are TL-owned.
