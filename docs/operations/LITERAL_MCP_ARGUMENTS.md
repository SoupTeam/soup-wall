# Literal arguments in the original filesystem MCP profile (SOU-110)

The explicitly installed `sw-mcp/filesystem-readonly/1` profile treats its
validated path and search fields as data when computing native invocation action
classes. A filename such as `/workspace/bin/rm.sh` does not execute `rm`; the
`search_files` pattern `rm -rf` does not run a shell. This changes invocation
interpretation, not the classifier model, result detectors or execution sandbox.

## Reproduction and boundary

Public synthetic reproductions start at accepted main
`731d8c4c3cd921117cdb1934587d5aa97c80d6a7` (a descendant of the task's accepted
`df5809167c34edc0866fb406f59f8ac7e4f79a5b`). With the unmodified original schemas,
classifier and filesystem policy:

| Invocation data | Classifier | Previous native action / policy | Correct native interpretation |
| --- | --- | --- | --- |
| `read_text_file`, path `/workspace/bin/rm.sh` | known `read` | side effect / `filesystem-profile-deny-write` | literal path, read |
| `read_multiple_files`, paths containing `rm.sh` and `chmod.sh` | known `read` | privilege / `filesystem-profile-deny-privilege` | literal path array, read |
| `search_files`, pattern `rm -rf` | known `read` | destructive / `filesystem-profile-deny-destructive` | literal pattern, read |
| `read_text_file`, path `/workspace/bin/send_report.py` | known `read` | read / allowed on this main | unchanged; no reproduced native defect |

These are B20/B38-shaped public cases, not copies of private PMF cases. The
previous refusals occurred before dispatch; they were not result-policy failures.

The daemon derives field roles from the immutable installed registry and exact
shipped original schema/profile. It independently validates the complete argument
envelope, including workspace spelling, traversal, field types, bounds and
unknown fields. Only then can the library omit reviewed fields from *command
pattern upgrades*. There is no new request flag, caller annotation or description
that selects these roles. Unreviewed fields remain command-bearing in the library;
they are refused outright by the selected profile's closed argument validator.

Reviewed literal fields are `path`, `paths`, `pattern`, and `excludePatterns`,
according to the particular original tool's pinned schema. Other selected options
remain subject to their existing schema constraints. Actual write/edit/move,
unknown tools, generic native tools, Bash and split-argv commands keep the existing
command scanning. Installed effect baselines can never be reduced by a field role.
The original Git profile is unchanged by this increment.

## Constraints retained

The complete original event is still inspected for injection, secrets, sensitive
paths, egress destinations and provenance overlap. All existing hard Deny, Ask,
incomplete-history and delegated resource/authority constraints remain active.
Literal data can therefore still be refused for another valid reason.

Session/owner/epoch, typed host call IDs, original arguments and schema identities
remain in the existing exact receipt/approval binding. Policy reevaluation and
hook/native decisions use the same validated semantic boundary. The accepted Ask
state machine, single-use redemption and original result release are unchanged.

Selected execution remains opt-in and supported on Linux x86-64. Native unit
checks on macOS/Windows do not prove original-server execution. Classifier
uncertainty is not bypassed: the existing unsupported `directory_tree` classifier
Ask is explicitly retained. SOU-109 owns result-framing false positives; this
change neither edits those detectors nor treats a withheld result as success.

## Reproducible Linux acceptance

Build the exact clean source with `cargo build --locked -p agentfw --bins`.
Use the accepted installer prerequisites: pinned official Node 22.22.0, its npm,
and bubblewrap 0.13.1 with `--ro-bind-fd`. Then run:

```bash
python3 -B -m unittest discover -s scripts/tests -p test_sou110_literal_arguments.py -v
python3 -B scripts/verify-sou110-literal-arguments.py --run \
  --agentfw "$PWD/target/debug/agentfw" \
  --node /path/to/pinned/node --npm /path/to/pinned/npm \
  --bwrap /path/to/bwrap --strace /usr/bin/strace \
  --expected-commit "$(git rev-parse HEAD)" --output /new/outside-checkout/evidence
```

The required Linux filesystem CI job runs this separately from existing acceptance
labels and denominators. It requires six useful original read/search cases and
twelve paired refusal cases, accepted classifier bytes, an enforcing daemon, exact
original discovery/results, actual successful target-open syscalls, unchanged
workspace metadata/content and an independently calibrated egress receiver. Useful
follow-ups continue after refusals. Existing real command policy controls run too.

Evidence retains clean source before/after, implementation/config/runtime hashes,
classifier predictions, typed responses, dispatch observations, filtered syscall
witnesses and independent descendant/daemon cleanup. Failed/late evidence remains
failed. Private raw syscall traces and installed private homes are excluded from
exported artifacts. Missing Linux prerequisites fail; they never pass by skipping
or replacing the original server. Local witness-failure controls do not constitute
native Linux coverage.
