# Cumulative quotas for one installed edit run

Native Linux x86_64 operators can explicitly select two additional ceilings:
`--max-mutations` (0–64) and `--max-write-bytes` (0–262144). Supply both or neither.
They count **admitted mutation attempts** and full proposed UTF-8 payload bytes,
respectively. They also cap committed effects. Counts and byte reservations never
refill during the run, including after known staging failures or lost results.

```sh
agentfw edit-session preview \
  --home /absolute/agent-home --claude /absolute/claude \
  --root /absolute/private-output --private-sole-writer \
  --read report.txt --create report.txt \
  --max-mutations 2 --max-write-bytes 128

agentfw edit-session prepare --apply --out /absolute/plans/bounded-plan \
  --home /absolute/agent-home --claude /absolute/claude \
  --root /absolute/private-output --private-sole-writer \
  --read report.txt --create report.txt \
  --max-mutations 2 --max-write-bytes 128
```

Preview is read-only and shows the exact limits without raw contents or secrets.
Explicit quotas use profile `sw-installed-edit-session/2` and a strict
`sw-installed-edit-mutation-quota/1` declaration. Omitting both flags keeps the
legacy v1 profile and its existing semantics; it does not silently add defaults.
Missing, null, unknown, negative, fractional, overflowed or duplicate budget
fields are rejected. Zero mutation credits prevent every mutation. Zero byte
credits can still permit an explicitly authorized empty-file mutation, consuming
one operation; they do not mean read-only authority.

Run the displayed immutable plan digest with the existing
[installed edit-session run and Ask commands](INSTALLED_EDIT_SESSION.md).
Quotas only narrow already selected targets and operations. All schema/path/root,
classifier, independent policy floors and exact single-use Ask checks precede
reservation. The broker reserves atomically before any staging or mutation can
dispatch. Per-file 4096-byte, private/direct-child/single-link and sole-writer
rules, deadlines and Ask lifetimes are unchanged. A quota cannot turn create
into replace or authorize an unselected path.

## Accounting and exhaustion

One admitted mutation reserves one credit and the entire proposed payload byte
count permanently. Refused schema/path/policy/Ask requests and failed quota
reservations consume zero. An accepted attempt that later fails still consumes
its credits: this conservative rule also bounds detached staging workers.
The report distinguishes these charges from known commits and their bytes,
known noncommits, pending preparation and indeterminate publications.

Publication enters an indeterminate state immediately before the existing
publication syscall. The confirmed outcome is recorded synchronously before
result inspection/delivery. Result loss cannot refund a confirmed commit. An
interruption after publication begins remains indeterminate unless completion
was observed; neither result refusal nor a missing receipt proves no write.

Exhaustion returns `edit_quota_mutation_limit` or `edit_quota_write_byte_limit`,
with safe numeric observations and remaining credits. Terminal run JSON retains
the same quota accounting. `edit_quota_state_unavailable` means counts are
unknown and further mutations refuse, not that a fresh empty budget exists.
No active-run reset, top-up or automatic retry is provided. Inspect actual output
before deciding to start another explicitly authorized run. Changed limits or
bindings require ordinary explicit preparation of a new immutable plan/digest.
Every run has new epoch/Ask authority. Unchanged eligible plans can be selected
again explicitly; this is per-run accounting, not a user/host/cross-run budget.

## Scope, compatibility and qualification

Refreshing an eligible immutable quota-v2 plan preserves the exact quota
contract and limits. It publishes a new inactive plan and never refills a live
run. Using that plan requires an explicit new run and fresh exact Ask authority.
Changing limits requires explicit preparation; refresh cannot increase them.
Quota and descriptive refresh lineage have separate validation and digest
binding. Old approvals cannot cross epochs.

Read-only status consumes retained quota metadata through a strict bounded
schema, checks it against the selected profile, and rejects contradictory or
unknown fields. Those counters remain local bookkeeping. They do not establish
authenticated commit, host delivery or model consumption, including when an
optional output check observes the expected bytes.

The existing selected resource transport still refuses unsupported overlapping
requests. It is not upgraded to a parallel executor. The finite installed
qualification issues an actual two-tool host batch and verifies at most one
effect at the last credit; the native Rust barrier control independently races
two real creators against the same ledger and requires exactly one winner.

`python3 -B scripts/qualify-edit-quota.py` is inert. Explicit `--run` qualification
uses the actual installed Agent/component, genuine pinned restricted Claude and
an owned scripted loopback provider outside read-only source. Its fixed inventory
covers useful create/replace/readback, exact and over-limit cases, rejected/no
approval, replay, independent runs and fresh-run recovery. Disposable fault
libraries withhold transport after actual publication or SIGSTOP the Agent
after the successful publication syscall; an independent controller observes
exact output bytes and kills that stopped owner. These negative witnesses do
not substitute for positive installed workflows. All attempts, exact source and
binary/profile identities, zero over-budget effects and owned cleanup must be
retained. No paid inference or model-effectiveness claim. Final shared Ready
qualification, admission and main delivery remain reviewer-owned.

On implementation `66e126486ea9b21f0104051a3f97a65561ee21ea`, native Linux passed
all 23 quota scenarios and all 23 legacy installed scenarios, plus 53 focused
Rust tests. Exact source/binary/profile correlation, all failed/incomplete
attempts and independent effect checks are retained in
[SOU-170 evidence](evidence/sou-170/README.md).
