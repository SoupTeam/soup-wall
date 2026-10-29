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
