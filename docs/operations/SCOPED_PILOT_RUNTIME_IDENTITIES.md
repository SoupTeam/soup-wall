# Scoped pilot runtime identities (SOU-176)

The existing pilot dossier owns the readiness decision. Complete identities are
necessary evidence, never a replacement for useful-work, refusal, timing,
source-integrity, WSL or cleanup gates. A producer's nonzero exit, failed useful
Git result, missing stage or unconfirmed cleanup stays **NOT_READY**.

## Reviewed plan and actual inputs

The coordinator `scripts/qualify-sou145-readiness.py` freezes
`sw-pilot-runtime-plan/1` before starting any producer. It binds the clean Git
commit/tree, selected file hashes, reviewed scope-template bytes, producer and
classifier source hashes, and literal policy bytes. The template is
`scripts/benchmarks/pilot-readiness-scopes-v1.json`. Its policies copy the
existing producer bytes; they do not change enforcement.

| Stage | Required runtime scopes |
| --- | --- |
| installed | One installed launch |
| matched | One installed launch shared by the unchanged 40 arms |
| Ask | Fifteen original cases and two explicit resumed restart launches |
| prepared | Selection, seven lifecycle launches and five Stop launches |
| each of three projects | Selection and initial, operator-edit, cancel, daemon-loss, recovery |

All seven stages and all 50 scopes are mandatory. Ask's existing filesystem/Git
policies and 20/30-second TTL variants have distinct predeclared scopes. Prepared
Ask retains its original 120-second TTL. The 5000 ms first-pending bound, existing
wait deadlines, byte limits, labels and result-inspection rules are unchanged.
The original launcher uses its Git classifier for both collectors in Ask and
prepared/project runs; the scope template records that actual behavior.

Each producer submits paths to the coordinator's private Unix socket. A
coordinator-owned reader independently opens those bytes, rather than trusting
producer-supplied hashes. Linux `SO_PEERCRED` requires the currently launched
producer's PID and UID, and every request names its stage and scope. The reader
retains descriptors across the scope, checks actual configuration/policy/registry
bytes, verifies both profiles with the existing production generation verifier,
hashes binaries, classifiers, package trees and native libraries, then checks
descriptor/path stability at completion. Concurrent prepared Stop runs retain
separate captures. Interrupted or failed capture cannot become complete.

Configuration is compared to the reviewed scope, allowing only the owned
runtime paths and chosen loopback port to vary. No posthoc policy exception or
global-profile equality rule is used. A selection scope explicitly has no
daemon configuration. Runtime scopes must provide the actual daemon config.

`runtime-plan.json`, seven `*-identities.json` custody reports and the original
seven producer reports form a private artifact. Each original report includes
additive `sw-pilot-runtime-claims/1` links. Custody binds the exact original
report SHA-256, plan, source, stage and independent namespace cleanup record.
The dossier recomputes scope identities from retained bytes and checks all links,
scope completeness and any original digest claims. Changing a report requires
new evidence; relabeling an old report cannot repair it.

This is trusted, fixed-source harness custody inside an owned enclosure. It is
not a cryptographic attestation service or a boundary against malicious producer
code. The operator-selected immutable archive digest is the external trust root.
Raw input snapshots contain private runtime paths and remain private. Publish
only sanitized metadata, hashes, counts and explicit failed outcomes.

## Execute and verify

Build and execute the target with read-only source, scratch-only writes, nonroot
identity, dropped capabilities, an owned PID namespace and loopback-only network.
Acquisition of pinned public dependencies happens separately. Use the existing
[complete seven-stage procedure](SOU145_INSTALLED_READINESS.md), selecting the
new exact source commit. The coordinator automatically enables custody for its
children; standalone producer commands retain their existing behavior.

Use `sw-pilot-dossier-selection/2`, with one candidate per stage, an explicit
`runtime_plan` reference and an `identity_context` reference for each candidate.
All references select SHA-256-bound members of one explicit bounded ZIP. The
support index and workload come from that candidate's Git objects. Run the
existing verification entry point:

```sh
python3 -B scripts/verify-sou145-evidence.py \
  --selection /private/scoped-selection.json \
  --archive /private/original-artifact.zip --output /private/new-verification
```

The output parent must exist and the output must be new. This command never
extracts or executes archive code. It invokes `pilot_dossier` and the existing
matched gate, producing private `dossier.json` and `scorecard.md`. Exit 0 means
READY, exit 1 means a retained NOT_READY result, exit 2 means invalid verification
input. A green execution workflow only means inventory invocations finished.

## Migration and negative controls

Version-1 dossier selections and original producer schemas remain readable.
Historical results keep their observations and denominators, but cannot satisfy
the new identity contract: `legacy_identity_contract_unqualified` is explicit.
No missing legacy policy, profile, configuration or classifier hash is backfilled.
Only a fresh complete run can supply version-2 candidate evidence.

`scripts/tests/test_pilot_runtime_identity.py` contains synthetic contract
controls for complete scopes, legitimate Ask variants, stale/changed plans,
forged input digests, duplicate/cross-stage/missing scopes, unsupported contracts,
changed/restored/replaced files, altered original reports, failed useful work
with complete identities and incomplete cleanup. These tests are not original
server evidence and do not establish pilot readiness. Native execution evidence
must be identified separately by its exact source, archive and member hashes.

## Private custody transport

Raw configuration snapshots and owned runtime paths must not be uploaded in
plaintext to a public repository. The diagnostic execution workflow is separate
from this change and seals its bounded original ZIP using CMS AES-256-GCM with
RSA-OAEP-SHA256 before artifact upload. Only the public recipient certificate is
provided to the runner. The private decryption key stays with the operator and
must never be committed, logged or included in the artifact.

The public envelope records both ciphertext and plaintext ZIP hashes, the
recipient certificate hash and selected member hashes. The operator downloads
the immutable artifact, checks its archive and ciphertext hashes, decrypts to a
new private file, checks the plaintext ZIP hash, then uses the existing verifier
above. Decryption failure must discard any partial plaintext. The original
archive remains unchanged; negative controls use separately labelled copies.
Local round-trip and tampering checks validate this transport, not runtime
readiness. Code and final native qualification are reported separately.

## Retained exact-source execution

The complete fresh execution uses source
`69b88976f5a68db5ebb5781589c3ee8556317ad7`, tree
`e0a0adfca8907ab3b8c0fa48a9c0df03d165f573`, based on accepted main
`7530c4c559b8f7fad95d6d8178f2816475184b17`. Its tracked-byte digest is
`055a5a24f0e6ef6cb513590b58a42976691173271b12c5a69975d16302dc0486`.
Later documentation/evidence commits do not replace this executed source.

The owner-only PRIVATE repository `Nari-Ab/soup-wall-evidence-private` retains
run `40857968501`, diagnostic workflow commit
`a0f633c096abdcd4c50dc53d80eba13901156da2`, and artifact `12891518932`.
The immutable encrypted artifact ZIP SHA-256 is
`c3b0e4224ba9f79e720c137fdf5c05c7974413eb6959e5b60371816aa555f3c4`.
Authenticated decryption recovers the unchanged original 25-member ZIP with SHA-256
`f47b5386d452fb3a0759ad445f5f1acc0b6e680cf8628aabee15c70fd272dee8`.
The private artifact also retains encrypted exact copies of earlier attempts.
Original public raw artifacts were removed after their hashes and exact private
copies were checked. The attempt ledger keeps the failure and cancellation
history; no partial attempt is used as final qualification.

| Original stage | Producer exit | Verified scopes | Independent namespace cleanup |
| --- | --- | --- | --- |
| installed | 0 | 1 | all stopped |
| matched | 1 | 1 | all stopped |
| Ask | 0 | 17 | all stopped |
| prepared | 0 | 13 | all stopped |
| docs-code | 1 | 6 | all stopped |
| unicode-spaces | 1 | 6 | all stopped |
| local-history | 1 | 6 | all stopped |

All seven original inventories ran on unchanged source and selected binaries.
All 50 input lifetimes completed. Eighteen identity unit/adversarial controls
also passed on native Linux with no skips. The job-scoped sandbox profile and
binary were removed (`removed-owned-profile-and-binary`). No paid API was used.
The workflow's success means complete execution, not a READY pilot.

The existing verifier independently recomputed all 50 bindings from retained
bytes and candidate Git objects, with zero identity blockers. It returned
**exit 1 / NOT_READY**: matched useful work remains 10/12, and each project's
initial, operator-edit and recovery cases retain `useful_original_result_failed`
(useful work 0/3). Their corresponding incomplete refusal/lifecycle assertions
remain failed in the original reconciliation. WSL stays unqualified. Installed
cases pass 12/12 and Ask passes 15/15; these do not override failed areas.

Use the committed [explicit selection](evidence/sou176/attempt-4-selection.json)
with the original privately decrypted ZIP and the existing verifier command
above. Public, sanitized records are the
[scope summary](evidence/sou176/native-identity-summary.json),
[verification receipt](evidence/sou176/verification-receipt.json),
[attempt ledger](evidence/sou176/retained-attempts.json) and
[local validation](evidence/sou176/local-validation.json).
The private key and raw snapshots are absent from this PR.

Two separately labelled synthetic copies of this same native archive retain
all 50 identity snapshots. An altered original report is rejected with
`runtime_identity_mismatch`; an unconfirmed cleanup is rejected with
`runtime_custody_cleanup_unconfirmed`. Both remain NOT_READY through the same
verification entry point. Their exact archive, selection and dossier hashes are
in [negative controls](evidence/sou176/negative-controls.json). They are mutation
controls, not additional original-server runs. Transport round-trip, tamper
rejection and partial-plaintext disposal are recorded in the
[private custody control](evidence/sou176/private-custody-control.json).

The PR stays Draft. The team lead owns final shared CI, Ready/admission and merge.
