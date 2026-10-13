# SOU-13 gold development export (owner workflow)

**Status (2026-10-13): approved Gold Addendum v1 and export authorization privately issued for 179 CP2 development cases; signed export delivered and independently verified by @KAZDANTOK. No public dataset release.** This page
continues to document the reusable owner-only workflow for future releases. Every step runs on the owner workstation. No step reads the
sealed test split.

The tools never create, default or infer an approval, a status or a label. They bind the decisions that people
have already recorded to the frozen evidence, and they refuse to continue when anything is missing or
inconsistent. They add no governance roles or approval requirements. Where a public record leaves a human
decision open, the tools report it as a release blocker and never treat it as approved.


## Recorded private CP2 release and handoff (2026-10-12)

The approved Gold Addendum v1 and export authorization were issued **outside Git**, confirming 179 CP2 development cases (train 71 / validation 54 / calibration 54). The 19 historical CP1 cases and all 54 sealed-test cases were excluded. Public code/validators are in [PR #85](https://github.com/SoupTeam/soup-wall/pull/85), with the path-scope fix from [PR #87](https://github.com/SoupTeam/soup-wall/pull/87).

- Export ZIP SHA-256: `24611b702c7242ad25bcf5e0d8bf4baecd8c19714fc014977976a9caadfa6237`.
- Export manifest SHA-256 (communicated outside the ZIP): `78f0f539b80ebaee886f322fc71c530d18a1bb824f0de7edf96c5a08e832080d`.
- Owner-reported final strict private validation: 445 tests / 441 passed / 0 failed / 0 errors / 4 expected Windows skips.
- Independent recipient verification: signed digest checked against previously pinned owner key, `self_consistency=PASS` and `anchored_integrity=PASS`. The recipient preserved tri-state masks, original inputs and leakage groups for [SOU-16](https://linear.app/soup-wall/issue/SOU-16); see the [SOU-13 handoff comment](https://linear.app/soup-wall/issue/SOU-13).
- Permitted use: internal training/evaluation only, under `SOU13-USAGE-2026-10-12`. Public publication, licensing and redistribution remain unauthorized.

These are recorded release results, not a claim that the public repository includes the private addendum, reviewer decisions, source data, label rows or test gold. The protocol below remains relevant to **future** releases; a verifier proves package identity and citations, not the truth/authority of the cited human decisions.

## Documents

| Document | Written by | Schema | Purpose |
| --- | --- | --- | --- |
| Reviewer submission | the independent reviewer, or transcribed from the reviewer's completed review queue by `submission_from_review_queue.py` | [`gold_reviewer_submission`](../../../eval/sou13/schema/gold_reviewer_submission.schema.json) | The reviewer's own label vector for each case |
| Owner decisions | the dataset owner | [`gold_owner_decisions`](../../../eval/sou13/schema/gold_owner_decisions.schema.json) | Approval records copied verbatim (with their real decision ids) and per-case transitions |
| Gold addendum | drafted by `draft_gold_addendum.py` | [`gold_addendum`](../../../eval/sou13/schema/gold_addendum.schema.json): the `bdd1f92` contract plus the **accepted** artifact-bound batch attestation (below) | Append-only, hash-chained label decisions bound to the frozen rows |
| Export authorization | the license owner and the dataset owner | [`gold_export_authorization`](../../../eval/sou13/schema/gold_export_authorization.schema.json) | Licensing, provenance, training use and release, plus the recorded decisions cited for each release question (traceability), bound to one chain and one gold set |
| Gold export | built by `build_gold_dev_export.py` | — | Gold rows, label-free model inputs, the addenda, the authorization and a standalone verifier |

Name the private working files `reviewer_submission*.json`, `owner_decisions*.json`, `addendum-v<n>.json` and
`EXPORT_AUTHORIZATION*.json`. The repository `.gitignore` ignores these names anywhere in a checkout as a
second guard. Keep them in a private folder outside every Git checkout.

## Rules enforced

The per-case addendum rules from `bdd1f92` apply unchanged (`sou13gold/addendum.py`, `chain_errors`):

- Base digests must match.
- The hash chain must run 1..n with no gaps.
- Each entry is bound to the frozen row's label digest and its input, argument and definition digests.
- `from_status` must equal the case's current status.
- `confirmed` needs `independent_human` adjudication, a referenced `independent_reviewer` approval, and the
  reviewer's own labels equal to the confirmed labels.
- Only supported dataset versions are accepted.
- No test-split rows.

An export additionally requires (`strict_errors`):

- **Approved chain.** Every addendum in the chain is `approved`. Drafts still validate in the default mode but
  are never exported.
- **Approval integrity.** A decision id names one record across the chain and the authorization. Placeholder
  values (`TODO`, `TBD`, `EXAMPLE`, `<...>`) are rejected.
- **Independence.** An `independent_reviewer` approver is never also a `dataset_owner` approver: owner review
  cannot confirm a label. The reviewer *may* hold the contract-owner role. SOU-10 names its contract owner,
  who also gave the development sign-off.
- **Gold eligibility.** Only rows evaluated as plain classification can be gold. Technical-error,
  admission-rejection and set-valued-oracle rows cannot be expressed by the gold label vector.
- **Reviewer evidence.** `plan` and `build` require the reviewer's submission files. Every confirmation must
  carry exactly the labels of one submitted case under the reviewer decision it cites. Drafting takes
  `reviewer_labels` only from the submission. When they differ from the current labels, the owner must record
  an explicit, equal `label_change`.

**Release blockers** are release-level, not per-case adjudication. A release question is:

- every frozen `open_question` of a gold row (every CP2 case carries Q-ADMISSION; the six pending train
  cases also carry Q-FUTURE);
- **Q-CP2-DECL-EVIDENCE** for every gold row with a `false` action label (a closed-world negative). The
  development sign-off did not resolve it; a later scoped clarification did, for the 179 CP2 cases only (see
  below).

The export authorization's `release_blockers_resolved` must cite, for each question, decision ids that are
recorded approvals, in the addendum chain or in the authorization. A question with no cited, recorded decision
blocks the export; nothing is approved by default. Cite an existing decision where one exists: the recorded
development sign-off covers Q-FUTURE, so it is cited, and the code requires no new adjudication. The tooling
does not decide *who* may resolve a question. The alternative is to exclude the affected cases
(`to_status: excluded`) or leave them non-gold.

`release_blockers_resolved` is **traceability metadata**. The tools check only that each cited id exists as a
recorded approval record. They never check what the decision says, and a cited id is not proof that the
question is resolved. `plan`, the strict validator and the export manifest list the release questions with case
counts. The shipped verifier repeats the presence check from the exported rows and reports
`release_blockers: CITED_ONLY`.

### Mandatory human release check

Before step 8 (build) and again before hand-off, the dataset owner, or a delegate named in the release
decision, must confirm for every entry in `release_blockers_resolved`:

1. **Content.** Read the cited decision record itself. Confirm that its content actually resolves that
   question for the cited cases and the labels being released. For example, a Q-CP2-DECL-EVIDENCE decision
   must address closed-world `false` labels, and a Q-ADMISSION decision must state that its scope covers gold
   labels.
2. **Authority.** The decision was made by someone entitled to make it under the recorded SOU-10 / SOU-13
   process.
3. **Currency.** The decision has not been superseded or withdrawn.

Record this confirmation in the release decision referenced by `release_decision_ids`. No tool performs or
replaces this check.

**Training use** comes only from the export authorization. A `license_owner` (or any other) approval recorded in
an addendum is allowed, but it authorises nothing. The authorization must:

- be `approved`, with `training_use_authorized: true`;
- reference recorded `license_owner` and `dataset_owner` approvals;
- name exactly the base, the addendum chain (length and head SHA-256), the gold-set digest and the per-split
  counts that `--plan` prints.

A gold row in a split the authorization does not permit refuses the whole build.

**Source and leakage gates.**

- The development review package is accepted only when sha256(`MANIFEST.json`) equals
  `package_manifest_sha256.dev_review_package` in the owner-signed freeze anchor. That anchor is verified
  against the independently pinned owner key.
- Every consumed file must match the package manifest and `EXPORT_MANIFEST.json`.
- Every row's family must be assigned to that row's split by the FROZEN public split view, which equals the
  anchor's `public_view_sha256`. Leakage groups must match the view.
- No group, family or input digest may span two splits, and every model input must reproduce its digests.
- Any test or custodian file name, or any row marked `test`, fails the build.
- The sealed test split is never read.

**Output.**

- The build is written to a hidden `.<name>.partial` folder, checked with the shipped verifier, then renamed.
  An interrupted build never leaves a folder under the final name.
- A leftover partial folder blocks the next build until the owner removes it.
- Existing outputs are never overwritten, and outputs inside a Git work tree are refused.
- Builds are byte-for-byte deterministic.

**Signature namespace.** The export digest statement is signed in the SSH namespace `sou13-gold-export`. This
is **technical domain separation only**: it prevents a signature made for the freeze anchor
(`sou13-cp2-freeze`) from being replayed as an export attestation, and vice versa. It is not a governance
approval and adds no approval requirement. The owner key's `allowed_signers` entry must permit it, for example
`namespaces="sou13-cp2-freeze,sou13-gold-export"`.

## Accepted: artifact-bound batch attestation (PR #85)

**The additive `independent_human_batch` contract was approved and merged in [PR #85](https://github.com/SoupTeam/soup-wall/pull/85) after the file-scope repair in [PR #87](https://github.com/SoupTeam/soup-wall/pull/87).** It does not claim individual per-case human review; the per-case mode and all other rules remain unchanged.

Use it when the independent reviewer approved an exact, hash-identified artifact as a whole, for example "all
179 CP2 development cases of package X are gold", without filling in per-case review rows. The addendum then
records a `batch_attestations` entry copied from the reviewer's decision record. Each covered case is confirmed
with adjudication `independent_human_batch`. The mode claims no per-case review and invents no reviewer labels.

The validator enforces these invariants (`sou13gold.addendum.batch_errors`, `batch_artifact_errors`):

1. **Recorded decision.** The attestation's decision is a recorded `independent_reviewer` approval in the same
   addendum. Each batch entry cites exactly one attestation. The reviewer is never also a dataset-owner
   approver.
2. **No label changes, no claimed per-case review.** A batch entry only confirms: `label_change` and
   `reviewer_labels` are null, and the case's current labels must still be its frozen labels. Any disagreement
   needs the per-case mode.
3. **Exact case set.** The confirmed cases match the attestation exactly:
   - their count equals the reviewer's stated `case_count`;
   - the SHA-256 of the sorted `[{id, label_sha256}]` (frozen label digests) equals `case_set_sha256`;
   - for `all_cp2_development_cases`, they are all and only the CP2 development rows;
   - `excluded.cp1_cases` equals the remaining development rows.

   An incomplete, extended or substituted set fails.
4. **Exact artifact.** The anchored development package digest (sha256 of `MANIFEST.json`) must be among the
   attestation's `reviewed_artifacts`. This is checked by `validate_gold_addendum.py --strict` with the anchor,
   by the export, and again by the shipped verifier.
5. **Stated labels hold.** Every label the reviewer stated explicitly for a question (`label_assertions`, for
   example Q-FUTURE: read+write+delete, unknown false) must equal the frozen labels of each confirmed case
   carrying that question, and the number of such cases must match. Otherwise drafting fails and those cases
   stay blocked.
6. **Separate provenance.** Gold rows are counted per channel (`confirmation_channels` in the plan, the export
   manifest and the verifier), as `REVIEW_PROTOCOL.md` requires.

A batch attestation resolves no release question by itself. Q-CP2-DECL-EVIDENCE, Q-ADMISSION and every other
open question still need a cited, recorded decision and the mandatory human release check.

### Recorded clarifications (scoped)

Nari AB, the independent reviewer and SOU-10 contract owner, clarified two questions. Each is resolved **only
within the stated scope**:

| Question | Clarification | Scope limit |
| --- | --- | --- |
| Q-CP2-DECL-EVIDENCE | Known `false` labels are confirmed for the closed-program semantics of the approved 179 CP2 development cases only, where the absence of side effects is supported by the scenario audit; no generalization to external calls. | The 179 CP2 development cases only. No CP1, no sealed test, no external calls. |
| Q-ADMISSION | The limited technical approval applies within the agreed synthetic fixtures, including DEV09 / opaque admission; semantic labels confirmed. | Semantic labels of the approved cases. It does not add DEV09 or any other CP1 case to the gold scope. |

The gold scope stays the 179 CP2 development cases. Nothing here extends it to CP1 or the sealed test. The
batch attestation's `all_cp2_development_cases` scope and CP2-only rule enforce this in code.

These clarifications are recorded outside the repository. Their decision id(s), date and source are **not
reproduced here** and must be copied from the record. To cite them in the export authorization:

- add each clarification's approval record (real decision id, approver, role `contract_owner` or
  `independent_reviewer` as recorded, date, statement) to the authorization's `approvals` (or to the addendum's
  approvals);
- set `release_blockers_resolved` for `Q-CP2-DECL-EVIDENCE` and `Q-ADMISSION` to those ids.

The mandatory human release check then confirms that each cited record's content matches this scope. Without a
recorded decision id, both questions still block the export.

**Owner input.** Put a `batch_attestation` object in the owner decisions. Copy each field from the reviewer's
recorded decision; never assume one:

- `decision_id`;
- `reviewed_artifacts`: the name and SHA-256 of each reviewed artifact;
- `scope_kind`: `all_cp2_development_cases`;
- `scope_statement`: the reviewer's words;
- `expected_case_count`: the count the reviewer stated, for example 179;
- `excluded`: for example 19 CP1 and 54 sealed-test cases;
- `label_assertions`: labels the reviewer stated explicitly, for example Q-FUTURE with `case_count` 6.

Drafting then derives the case set from the export and fails if anything disagrees. No reviewer submission is
needed for batch-confirmed cases.

## Owner-only sequence

**Owner-only workflow prerequisites (human decisions, not code).** For any new export, each must be recorded
with a real decision id, or affected cases must remain non-gold:

1. The development sign-off decision: reviewer per-case label submissions, **or** the accepted exact-artifact
   independent-human batch attestation with a recorded decision and matching frozen case/label hashes.
2. Q-CP2-DECL-EVIDENCE: **clarified** for the 179 CP2 cases (see
   [recorded clarifications](#recorded-clarifications-scoped)). Still needed: the clarification's decision id,
   approver and date, copied from the record.
3. Q-ADMISSION: **clarified** (same section). Still needed: its decision id, approver and date, copied from the
   record.
4. Any other open question on a case to be confirmed (`ACCEPTANCE.md`: resolved, or explicitly excluded).
5. The training-use decision. **Recorded:** `SOU13-USAGE-2026-10-12` (lead authorization, Telegram Soup Wall
   message 653, 2026-10-12 11:43 UTC+5) authorizes internal model training and evaluation only. Still to
   confirm from the record itself: the approver's name, and that the issuer holds the license-owner
   responsibility. Provenance confirmation is also still open. A semantic sign-off is not a license.
6. The dataset owner's release decision for the named recipient.
7. A freeze anchor that records the development package digest. If the existing anchor does not, a new
   owner-signed anchor is needed.

```powershell
$Repo    = '<checkout of the reviewed commit>'
$Private = '<private-root>'
$Gold    = '<private gold working folder, outside every Git checkout>'
$Pkg     = "$Private\handoff\dev_review_package"
$Tools   = "$Repo\eval\sou13\scripts_cp2"
$Anchor  = @('--anchor', '<anchor.json outside every repository>', '--allowed-signers', '<allowed_signers>',
             '--trusted-key-fpr', '<pinned owner key fingerprint, SHA256:...>', '--signer', '<signer identity>')
$Review  = @('--reviewer-submission', "$Gold\reviewer_submission.json")
```

1. **Validate the source.** Run the [private validation](PRIVATE_VALIDATION.md) on this exact commit. Stop
   unless it passes.
2. **Verify the development package against the anchor.** Stop unless `result` is `PASS`.
   ```powershell
   python -I "$Pkg\verify_package.py" @Anchor
   ```
3. **Transcribe the review, then draft.** If the independent review was recorded in the package's review queue,
   transcribe the queue exactly as the reviewer returned it. Copy the reviewer name, decision id and date from
   the recorded decision; never assume them.
   - Only `accept` rows with evidence confirmed `Y` are included. `agree` resolves to the proposed value,
     which must equal the frozen label. A blank decision fails.
   - `--expect-cases 179` fails unless all 179 development cases were accepted.

   If the review is instead an explicit batch approval of an exact artifact, use the
   [accepted batch attestation](#accepted-artifact-bound-batch-attestation-pr-85), and skip the transcription. Never derive per-case reviewer labels from frozen labels.
   ```powershell
   python -B "$Tools\submission_from_review_queue.py" --queue '<queue returned by the reviewer>' `
       --exports "$Pkg\exports" --reviewer '<reviewer name as recorded>' --decision-id '<recorded decision id>' `
       --submitted-at '<YYYY-MM-DD>' --expect-cases 179 --out "$Gold\reviewer_submission.json"
   ```
   Then draft with `"status": "draft"` in the owner decisions. `blocking` lists every rule that still prevents
   approval. The report prints counts, digests and errors only.
   ```powershell
   python -B "$Tools\draft_gold_addendum.py" --exports "$Pkg\exports" @Anchor `
       --submission "$Gold\reviewer_submission.json" --decisions "$Gold\owner_decisions.json" `
       --out "$Gold\draft\addendum-v1.json"
   ```
4. **Issue.** Once the approvals are recorded, set `"status": "approved"` and draft again into
   `$Gold\addendum-v1.json`. For a later addendum, pass the issued chain with `--previous`.
5. **Validate at export grade.** It must print `PASS`, and it lists the release questions the authorization
   must resolve.
   ```powershell
   python -B "$Tools\validate_gold_addendum.py" --strict --exports "$Pkg\exports" @Anchor `
       --addendum "$Gold\addendum-v1.json" @Review
   ```
6. **Plan.** This prints the base, the chain head, the gold-set digest, the counts and the release questions.
   It writes nothing and prints no labels.
   ```powershell
   python -B "$Tools\build_gold_dev_export.py" --dev-package $Pkg @Anchor --addendum "$Gold\addendum-v1.json" @Review --plan
   ```
7. **Authorize.** The license owner and the dataset owner record `$Gold\EXPORT_AUTHORIZATION.json`:
   - the plan values;
   - their real decision ids;
   - the license identifier and terms reference, the recipient and any restrictions;
   - `release_blockers_resolved`: for each release question, the recorded decisions cited for it. Then
     complete the [mandatory human release check](#mandatory-human-release-check).
8. **Build.** This writes `sou13-gold-export-v1\` and `sou13-gold-export-v1.digest.json`.
   ```powershell
   python -B "$Tools\build_gold_dev_export.py" --dev-package $Pkg @Anchor --addendum "$Gold\addendum-v1.json" @Review `
       --authorization "$Gold\EXPORT_AUTHORIZATION.json" --out "$Gold\sou13-gold-export-v1"
   ```
9. **Sign the digest statement** in the export namespace:
   ```powershell
   ssh-keygen -Y sign -n sou13-gold-export -f '<owner private key>' "$Gold\sou13-gold-export-v1.digest.json"
   ```
10. **Verify as the recipient will.** It must print `PASS` with exit code 0.
    ```powershell
    python -I "$Gold\sou13-gold-export-v1\verify_gold_export.py" --statement "$Gold\sou13-gold-export-v1.digest.json" `
        --allowed-signers '<allowed_signers>' --trusted-key-fpr '<SHA256:...>' --signer '<signer identity>'
    ```
11. **Check for leaks.** `git status` must show no new file under the repository.
    ```powershell
    git -C $Repo status --short --ignored
    python "$Tools\check_release_privacy.py" --git $Repo `
        --deny-digests "$Private\data\freeze.json" "$Pkg\MANIFEST.json"
    ```
12. **Hand off** only the export folder, the digest statement and its `.sig`, through the approved channel.
    Publicly, record only the source commit, the counts and, if authorised, the addendum and manifest digests.
    Never record labels, case ids, private paths or logs.

The recipient runs the shipped `verify_gold_export.py`. It uses the standard library only, plus `ssh-keygen`
for the signed statement. Exit code 0 means self-consistent and authenticated, 3 means self-consistent but
unauthenticated, and 1 means failed.

## Recording the internal-use authorization

The export authorization's licensing fields must reflect `SOU13-USAGE-2026-10-12` and nothing broader:

| Field | Value |
| --- | --- |
| `permitted_use.training_use_authorized` | `true`, internal use only |
| `permitted_use.license_id` | `SOU13-USAGE-2026-10-12 (internal use only; no public license)` |
| `permitted_use.terms_reference` | `Telegram Soup Wall message 653, 2026-10-12 11:43 UTC+5` |
| `permitted_use.restrictions` | at least: internal model training and evaluation only; no publication; no redistribution outside the project; the sealed test is never included or requested |
| `license_decision_ids` | `["SOU13-USAGE-2026-10-12"]` |
| matching `approvals` record | `decision_id` `SOU13-USAGE-2026-10-12`; `role` `license_owner`, **only if** the issuer holds that responsibility; `approver`, `approved_at` and `statement` copied from the record, never filled in by assumption |

If the issuer is not the license owner, stop. A license-owner decision is then still missing, and the export
cannot be built.

## Known limitations

- The addendum schema cannot record *which* recorded approval resolves *which* open question. That mapping
  lives in the export authorization (`release_blockers_resolved`), so the license and dataset owners cite it at
  release time, not inside the label chain. The tooling checks only that every cited id is a recorded approval
  record. It cannot check what a decision says; that is the mandatory human release check.
- The verifier's `anchored_integrity` authenticates the export manifest as the one the owner signed or
  published. Approval records inside the export are unsigned text, so their approvers are not authenticated
  by any tool. `label_correctness` is reported as not verified: it rests on the recorded human review.
- Approver independence is compared by name, not cryptographically. Reviewer submissions are unsigned files.
  Authenticity of the export rests on the owner's signature over its manifest digest.
