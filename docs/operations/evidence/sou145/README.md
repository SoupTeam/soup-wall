# SOU-145 retained readiness evidence

Current native execution: source `6deafacf3854666cb1e5874d4cfcf152e4f7a6b2`,
tree `b3ad2d4b4f44139d9c4c96fc40ced4eee5adceb0`, based on accepted main
`8ead460e7460a8168459e0f02ea25c1eb2d8f7d4`. The runtime crates match that main.
Later evidence/reporting commits do not change this executed source identity.

- [Selection](attempt-4-selection.json): exact original ZIP/member hashes and
  explicit execution-context links for the existing `pilot_dossier` verifier.
- [Sanitized original outcomes](attempt-4-summary.json): all seven inventories,
  full denominators, actual binary/producer/profile/policy/classifier hashes,
  first-pending measurements, per-case errors and cleanup.
- [Independent verification](attempt-4-verification.json): NOT_READY dossier
  hashes/blockers and separate project result/cleanup checks.
- [Retained attempts](retained-attempts.json): every failed/partial setup and
  runtime attempt, with immutable artifact identifiers and archive digests.
- [Historical October 25 selection](attempt-1-selection.json) and
  [historical result](attempt-1-summary.json): unchanged prior-owner evidence.

The original current-run ZIP is GitHub artifact `12848988005`, run
`40759076732`, SHA-256
`28e11ff63d19e063f50602793a63963ef1c0ee8ab815e00fa6c80845d18f7013`.
It is retained privately as the original archive; no extraction or runtime
execution of downloaded artifacts was used for parent-side verification.
GitHub artifact retention is 30 days. Retain the original ZIP privately before
expiry; a future missing archive is incomplete evidence, not a passing result.

**NOT_READY** is the measured pilot result. Installed 12/12, Ask 15/15 and
prepared 12/12 passed; matched remains 10/12 benign and 8/8 refusals, and each
realistic project records 6/9 passed cases with three useful `git_show` failures.
All inventory slots and confirmed per-stage cleanup are retained. WSL2 was not
executed. Different scoped profiles/policy variants and omitted legacy identity
fields remain explicit dossier blockers; they are never collapsed into one
identity to force GO.

See the [English operator guide](../../SOU145_INSTALLED_READINESS.md) for the
executable verification command, exact reproduction and ownership boundaries.
