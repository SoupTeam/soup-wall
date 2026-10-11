# SOU-13 pilot dataset card (candidate / NOT approved)

**2026-10-11 checkpoint.** This is a candidate dataset card for review, not a release, training license, approved gold dataset, or claim of general MCP tool safety.

## Task and target
Evaluate semantic action classification of tool calls against the SOU-10 v0.4 taxonomy: five orthogonal actions (`read`, `write`, `delete`, `send_data`, `change_permissions`) plus separate Boolean `unknown`. Each action target may be `true`, `false`, or `null`; `null` is masked, not treated as negative. Includes mixed effects, misleading metadata, opaque and partially known behavior, and held-out tool/server families.

## Data composition and split
- Total: 252 synthetic candidate cases grouped into 45 tool/server families.
- Frozen partitions: train 90 / validation 54 / calibration 54 / sealed test 54; group whole families, aliases and near-duplicate templates together.
- Development records: 19 legacy CP1 plus 179 new CP2. The 179 CP2 development cases comprise train 71, validation 54 and calibration 54.
- Test: 54 cases / 9 sealed families, never distributed to model authors and never included in public PR or open development logs.

## Generation, evidence and limitations
CP2 cases use an AI-assisted synthetic semantics registry, a closed declarative program and in-memory interpreter with typed access audit. Real MCP servers, host operating-system effects and external HTTP communications were **not** executed. The same synthetic design process generated programs, traces and provisional labels; consistency does **not** independently establish correctness. `false` means absent in the fully executed and audited declared synthetic semantics only. Tool names, descriptions, string contents and URL paths do not alone determine effects. Unknown/opaque effects remain indeterminate.

## Label and review status
The immutable source is **173 provisional + six pending** new CP2 labels (six Q-FUTURE archive-family cases). No source labels are `confirmed`. The owner has an 11-case **working human-annotation draft** across two development families, not independent adjudication or permission to promote the whole split. Technical verifier self-consistency passed 179/179 cases and an additional read-only structural audit reported zero findings; neither replaces review against source/evidence and SOU-10 semantics. Legacy CP1 review remains separately governed by the documented protocol.

## Provenance and licensing
CP2 synthetic generated specifically for this project; no customer payload or real network destination is claimed. CP1 historical provenance is tracked separately. **Dataset license remains pending an explicit review/decision (Q-LICENSE).** The repository's Apache-2.0 code license does not automatically authorize use of an experimental dataset or outside material.

## Integrity and reproducibility
Family-split freeze: 2026-10-11T11:36:04+05:00. Logical full manifest SHA-256: `1a42b39ed6efb2efb63692aec738647ed25e4fdc9d04150dd45a5b577a170a1b`. The immutable development handoff ZIP SHA-256 is `6393170dc1cacc8546be2a929a271e4b8b50ab81d6e09abe18551798df1f9bc9`. Cryptographic authenticity requires owner-signature verification with an independently pinned public key; self-checks and file hashes alone are insufficient. Review decisions must be emitted as versioned addenda rather than rewriting the signed snapshot.

## Gating and remaining decisions
1. Q-ADMISSION: whether the synthetic tool registry is admitted as a synthetic evidence assumption.
2. Q-CP2-DECL-EVIDENCE: whether closed declarative absence supports negative gold targets.
3. Q-FUTURE: archive/read/write/delete semantics in six pending cases.
4. Q-LICENSE: explicit dataset provenance and license signoff.
5. Independent review/adjudication of disputed labels and review protocol adherence.
6. Independent custodian acknowledgement and sealed test review/one-shot model evaluation ledger.

**No official held-out metrics, training authorization or production readiness claim.** Review coverage and metric denominators must exclude unresolved/pending labels and be reported by known-mask and by family, including uncertainty.

See [SOU-13 task](https://linear.app/soup-wall/issue/SOU-13/task-8-build-a-reviewed-pilot-dataset-and-family-held-out-evaluation) and [checkpoint](sou13_candidate_review_checkpoint_2026-10-11.md).
