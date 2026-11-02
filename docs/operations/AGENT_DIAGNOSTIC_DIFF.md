# Offline diagnostic diff

Compare two existing `sw-agent-doctor-support/1` directories. Keep this script beside the accepted `agent-audit-report.py` reader and its platform helpers when installing it outside a checkout.

```sh
python3 -B agent-diagnostic-diff.py BEFORE AFTER --json-out PRIVATE/diff.json --markdown-out PRIVATE/diff.md
```

On Linux, PRIVATE must be owned by the operator with mode 0700. Both outputs must be new files. The existing audit reader enforces private output and refuses linked input path components. Report bytes are checked against the manifest SHA-256 and byte count before comparison. This verifies local consistency; it does not authenticate the producer.

The reader accepts only the two fixed JSON filenames; archives are unsupported. Each input is limited to 128 KiB and 16 JSON nesting levels, with at most 256 checks per scope. Duplicate JSON keys, nonfinite numbers, missing scope, corrupt artifacts and duplicate report content are refused. Other directory members are never opened. Output contains fixed field names, check identity hashes, value hashes and change states. Imported explanations, prompts, paths and results are excluded.

Missing observations are marked missing. All observations remain historical. No cross-bundle session or call correlation is inferred. Current source, transport and cleanup remain unavailable when this export does not establish them. Review changed checks privately and collect fresh doctor evidence before retrying.

Identity observations come from the accepted exporter's `checks` and `pilot.checks`. Public check IDs identify configuration, installed packages, classifier, policy, profiles and authenticated runtime observations. Unknown IDs are hashed. Checks are matched by ID, so reordering them does not create a change. Incident projections include only bounded source, boundary, completeness and execution fields; explanations and raw incident content are excluded. The JSON result marks `historical: true`, `execution_observed: false` and lists changed fields separately. Missing observations remain explicit. Provider transport and storage cleanup remain unavailable because this exporter does not establish them.

Qualification status: parser/projection tests pass on Windows using a substituted file reader. Native private-file behavior and installed use require the dedicated Linux qualification; these tests do not establish native acceptance.
