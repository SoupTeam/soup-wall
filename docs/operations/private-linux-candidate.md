# Private Linux candidate kit

This development command prepares an unpublished Linux x86-64 GNU candidate
from a clean commit. It does not qualify a release, promote an artifact, or
provide byte-for-byte compiler reproducibility. Original packaging and inventory
work remains in the branch's retained history (PRs #185 and #239).

Use the existing native pilot prerequisites and the repository-pinned Rust
1.99.1 build contract in `rust-toolchain.toml`. Historical evidence keeps its
original toolchain and source identities.
Supply the reviewed bubblewrap 0.13.1 binary and its previously recorded digest;
there is no ambient PATH sandbox fallback. Python 3.11 or newer, glibc and ELF
inspection tools remain explicit host requirements. The classifier uses only
Python's standard library. The filesystem server and Node are staged assets.

```bash
export CANDIDATE_BWRAP=/private/prepared/bwrap
export CANDIDATE_BWRAP_SHA256=<recorded-binary-sha256>
export CANDIDATE_NODE_ARCHIVE=/private/cache/node-v22.23.5-linux-x64.tar.xz
export CANDIDATE_BWRAP_ARCHIVE=/private/cache/bubblewrap-0.13.1.tar.xz
bash scripts/build-candidate.sh
```

If archive inputs are omitted, preparation downloads the exact pinned archives
and verifies their SHA-256 before use. Ordinary protected operation does not
download. Existing output is refused and retained. Builds use one affected Agent
binary, the selected compiler and locked Cargo inputs. The manifest records the
compiler, source commit/tree, Cargo digest and every staged file. npm lifecycle
scripts are disabled. The kit retains original upstream notices, transitive npm
package/license metadata and the sandbox's exact source archive and notice.

From a clean unprivileged Linux location, run:

```bash
CANDIDATE_EVIDENCE_DIR=/private/evidence/unique-attempt \
  bash scripts/validate-candidate-offline.sh /private/candidate.tar.gz
```

The validator rejects unsafe archive paths, links, special files, duplicates,
unsafe modes, excessive expansion, missing components, altered hashes or
incomplete notice coverage before extraction. Node and sandbox source archives
also match independent reviewed pins. A new private directory is required.
Installation reuses the shipped filesystem installer with networking unavailable.
The harness then runs useful original-server reads, unsupported-write zero-effect
checks, a result-injection refusal, unrelated setup-error controls and daemon loss.

The result refusal must have the exact protocol frame and a fresh matching
`native_call`/`native_result` pair from the owned daemon's audit sink, including
call ID, session, binding, registry, phase, verdict and reason. Pre-existing
records, collector stderr markers and generic errors cannot satisfy it. This
uses an isolated, sequential local test daemon; it is not authentication against
another process with the operator's UID. Retained evidence stays private.

Run parser and counterfeit-evidence regressions independently of a native kit:

```bash
python3 -B -m unittest discover -s scripts/tests -p 'test_candidate_*.py' -v
```

Native installed success, scanner completeness and final source admission are
separate evidence. Final independent review, Ready qualification and merge belong
to the maintainer. Source corrections may be reviewed and merged after the normal Ready CI,
CodeQL, approval and exact-candidate admission requirements pass. A source
merge does not admit the complete installed runtime. Keep its full candidate
and release task open, retain unresolved native findings and the nonzero
inventory result, and refuse a qualified handoff until all runtime gates finish.

See [installed runtime inventory](installed-runtime-inventory.md) for the complete
two-server dependency and advisory scope.
