# Current-main evidence reconciliation

Selected main: `c1a6918a05ae22cd89be6d98bfb13bbf9456a781`.
Tree: `09d67510e1bac3e3b871cbaf7369e646e9b62ca4`.
Reporter implementation: `d2a18eb695901c9d0538e6ff75deaa8fc6fb4e0a`;
the output also records exact reporter/dependency hashes.
Final accepted reporter SHA remains unavailable pending review/admission.

[Selection](selection.json), [scorecard](dossier/scorecard.md),
[blocker ledger](dossier/dossier.json).

## Outcome and explicit blockers

Reconciliation exits **1 / NOT_READY**, with output retained. No runtime was run.

- SOU-106: the retained `ce4f76d` measurement remains 10/12 benign with two Ask
  interruptions (`search-read-status`, `search-exclusion`). Its 8/8 refusal
  variants and zero forbidden effects are historical, not current-main coverage.
- SOU-112: the selected report committed on this main has the old Ask denominator;
  it cannot satisfy the required 15 cases, including `git/collector_term`.
- SOU-116: the selected prepared report has the old denominator; it cannot satisfy
  the required 11 cases, including `host-crash`. Install/start, daemon-loss and
  cancellation/cleanup therefore lack qualifying selected evidence.
- Environment: kernel identity is unknown and retained environment/source
  bindings do not qualify this candidate. Expected asset identities explicitly
  retain the SOU-106 selection, not newly built current-main binaries.
- SOU-115 / TL platform owner: no exact bound Linux runtime observation; WSL is
  not qualified by the selected support index. Windows/macOS combined-pilot
  and live-model effectiveness remain outside this selected scope.

This refresh reads only the explicitly selected public files at current main.
Newer external reports were not supplied or silently substituted. The 15/11
requirement is preserved; historical reports are not rewritten to meet it.
Ready for review concerns the tooling increment, not pilot acceptance. TL owns
CI admission and integration. No policy, timeout, authority or expectation changed.

## Reproduce

Use the PR checkout containing the reporter and this selection, with the selected
main Git objects available. From the repository root, materialize only the seven
explicitly selected public blobs into a new scratch directory (no directory scan):

```sh
python3 - <<'PY'
import json, subprocess
from pathlib import Path
selection = Path('docs/operations/evidence/sou129/main-c1a6918/selection.json')
m = json.loads(selection.read_text(encoding='utf-8'))
root = Path('target/sou129-main-c1a6918-inputs')
root.mkdir(parents=True, exist_ok=False)
refs = [m['support_index'], m['workload']] + [e['file'] for e in m['evidence']]
for ref in refs:
    raw = subprocess.check_output(['git', 'show', m['candidate']['commit'] + ':' + ref['path']])
    destination = root / ref['path']
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
PY
python3 -B scripts/pilot_dossier.py \
  --selection docs/operations/evidence/sou129/main-c1a6918/selection.json \
  --root target/sou129-main-c1a6918-inputs --repo . \
  --candidate c1a6918a05ae22cd89be6d98bfb13bbf9456a781 \
  --output target/sou129-main-c1a6918-reproduced
```

Expected exit: **1**, not 0. Output must not already exist. The reporter verifies
selected byte hashes and candidate support/workload Git identities itself.
Compare candidate, selection hash, reporter/dependency hashes, evidence and ledger.
Original selections and dossiers remain retained separately.
