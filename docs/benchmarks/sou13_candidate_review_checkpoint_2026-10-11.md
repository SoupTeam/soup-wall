# SOU-13 candidate pilot: freeze and review checkpoint (2026-10-11)

> **Candidate evidence only.** This document does not approve human gold labels, the dataset license, training data, or a completed SOU-13 issue.

## Scope and frozen data

- SOU-13 pilot comprises **252 cases / 45 whole tool/server families**: train 90, validation 54, calibration 54, sealed test 54. The first three splits include 19 CP1 development cases and 179 new CP2 development cases.
- Freeze was recorded at **2026-10-11 11:36:04 UTC+05:00** by `@aisarasd` with an owner-signed external anchor. Logical full-split manifest SHA-256: `1a42b39ed6efb2efb63692aec738647ed25e4fdc9d04150dd45a5b577a170a1b`.
- Sealed test (54 cases / nine families) is **not included in this PR**; inputs/labels and restricted family information must remain with the designated independent custodian and outside model-author access.
- The development review handoff has SHA-256 `6393170dc1cacc8546be2a929a271e4b8b50ab81d6e09abe18551798df1f9bc9`. The freeze anchor and public verification procedure are part of the existing separate handoff.

## Technical review checkpoint

- The standalone handoff verifier re-executed **179/179** CP2 dev records with `self_consistency=PASS`, `errors=[]`. This is a **mechanical self-consistency** check, not proof that synthetic labels are objectively correct.
- The independent source-authenticity check requires a pinned owner public key and signature. The owner separately recorded a successful authenticated verification on their workstation; this PR does not reproduce that cryptographic check.
- An additional read-only cross-check over the 179 CP2 records found **zero mechanical issues** in case/queue ID alignment, proposed label values, known/null masks, declared audit cleanliness, recorded review state and absence of test records.
- Counts in the original frozen package: **173 provisional**, **six pending** (all in `fam.mixed.record_archive`, blocked by Q-FUTURE); **zero human-confirmed gold labels**.
- The owner has an **11-case human-annotation working draft across two dev families**; that draft is not independent adjudication and does not change the signed source labels.
- Main remaining semantic risks: conditional/no-op actions; unknown/opaque calls and null action labels; misleading metadata; Q-FUTURE archive semantics; support for negative labels under closed synthetic execution.

## Evidence, provenance and scope limits

The CP2 semantics registry is a synthetic, AI-assisted fixture model. A clean interpreter trace is an internal consistency witness, not independent evidence about behavior of an arbitrary real MCP server. Per-label `false` applies only to absence in declared closed synthetic semantics after a complete audited execution. `null` action labels remain masked. Tool names, descriptions, URLs and inert payload text cannot independently establish an action. SOU-10 v0.4, D01-D10 supplies the semantic contract.

Synthetic provenance is recorded, but **dataset licensing remains pending owner/coordinator review**. The repository's Apache-2.0 workspace license must not be assumed to cover the experimental dataset without an explicit approval.

## Open acceptance items

- **AC1:** Candidate size, strata and examples assembled; publication does not attest final human gold.
- **AC2:** Independent reviewer adjudication and evidence acceptance remain incomplete; Q-ADMISSION and Q-CP2-DECL-EVIDENCE open. Do not bulk-promote provisional labels.
- **AC3:** Family-disjoint split freeze technically completed; official metric denominators and custody must use approved gold labels and a separate sealed-test custodian.
- **AC4:** Dataset card, annotation guide, provenance and license decision, public-safe reproducible integration artifacts and final reviewable implementation PR are not yet fully approved.

### Requested review / decisions
1. SOU-13 owner and named reviewer: explicit Q-ADMISSION and Q-CP2-DECL-EVIDENCE acceptance, with narrow synthetic limitations and decisions recorded independently of AI assistance.
2. Contract owner: Q-FUTURE adjudication for six pending archive cases.
3. Authorized reviewer/coordinator: dataset provenance and licensing sign-off.
4. Test custodian: acknowledge private receipt/verification of sealed test package, retain a one-shot shared run ledger and restrict model-author access.

## Safe publication boundary

This checkpoint deliberately includes **no sealed test gold, restricted-family names, private signing key, unapproved raw training dataset or simulated human confirmations**. Do not change or regenerate the frozen split or rewrite the signed ZIP to incorporate later review. Later approvals should be versioned addenda with explicit digests and review references.

**Linked task:** https://linear.app/soup-wall/issue/SOU-13/task-8-build-a-reviewed-pilot-dataset-and-family-held-out-evaluation
