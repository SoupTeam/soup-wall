"""Offline report only: never loads a model or changes production outcomes."""
import collections
import hashlib
import json
from pathlib import Path
import shutil
import statistics
import sys

root = Path(__file__).resolve().parents[1]
run = Path(sys.argv[1])
dest = root / 'docs/operations/evidence/sou157-nli'
protocol = json.loads((dest/'protocol.json').read_text(encoding='utf-8'))
def lines(name):
    return [json.loads(x) for x in (run/name).read_text(encoding='utf-8').splitlines()]
observations = lines('observations.jsonl')
summary = lines('summary.jsonl')[0]
events = lines('events.jsonl')
identity = lines('identity.jsonl')[0]
assert identity['protocol_sha256'] == hashlib.sha256((dest/'protocol.json').read_bytes()).hexdigest()
assert len(observations) == len(protocol['rows']) == len({x['id'] for x in observations})
assert {x['id'] for x in observations} == {x['id'] for x in protocol['rows']}
baseline = json.loads((dest.parent/'sou157-destructive/report.json').read_text(encoding='utf-8'))
base = {x['case_id']: x for x in baseline['cases']}
obs = {x['id']: x for x in observations}
rows = []
for item in protocol['rows']:
    before = base.get(item['id'])
    if before:
        assert item['expected'] == before['label']
        assert item['original_sha256'] == baseline['identities']['payloads'][item['id']]
    rows.append(dict(item_id=item['id'], expected=item['expected'], group=item['class'],
                     before=before, production_after='unchanged; no integration or runtime replay',
                     shadow=obs[item['id']]))
groups = {}
for group in ('semantic', 'technical', 'supplemental'):
    selected = [r for r in rows if r['group'] == group]
    groups[group] = {'total':len(selected), 'assessments':dict(collections.Counter(r['shadow']['assessment'] for r in selected)),
                     'reasons':dict(collections.Counter(r['shadow']['reason'] for r in selected)),
                     'by_expected': {label:dict(collections.Counter(r['shadow']['assessment'] for r in selected if r['expected']==label)) for label in sorted({r['expected'] for r in selected})}}
assert sum(g['total'] for g in groups.values()) == 65
peak = max([e.get('job_peak_committed_bytes', 0) for e in events] +
           [o.get('job_peak_committed_bytes', 0) for o in observations] +
           [e.get('cleanup', {}).get('job_peak_committed_bytes', 0) for e in events])
report = dict(claim='Diagnostic shadow only. No production fix or held-out efficacy claim.',
              summary=summary, groups=groups, peak_committed_bytes=peak,
              baseline_identities=baseline['identities'], identity=identity, events=events, cases=rows)
timed = [o for o in observations if o.get('attempted') and 'roundtrip_ms' in o]
ready = next((e for e in events if e.get('ready')), {})
report['timing'] = {'cold_startup_ms':ready.get('startup_ms'), 'first_case':timed[0] if timed else None,
                    'subsequent_case_count':max(0,len(timed)-1),
                    'subsequent_roundtrip_median_ms':statistics.median(o['roundtrip_ms'] for o in timed[1:]) if len(timed)>1 else None,
                    'subsequent_roundtrip_max_ms':max((o['roundtrip_ms'] for o in timed[1:]),default=None)}
for name in ('identity.jsonl','events.jsonl','observations.jsonl','stages.jsonl','summary.jsonl','stderr.txt'):
    if (run/name).exists(): shutil.copyfile(run/name, dest/name)
(dest/'comparison.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
text = ['# Single authorized NLI shadow: observed results', '',
        f"Source frozen before inference: `{identity['source']}`.",
        'Original production results are retained from the prior additive detector run; no new runtime or production-policy run is implied.', '',
        f"Total {summary['total']}; attempted {summary['attempted']}; elapsed {summary['wall_seconds']:.3f} s; failure `{summary['failure']}`.",
        f"Whole worker-tree peak committed memory: {peak} bytes ({peak/1024**3:.3f} GiB), limit 8 GiB. This is not RSS.", '',
        f"Cold startup: {ready.get('startup_ms')} ms. No warmup; individual subsequent-case times appear below and aggregate in comparison.json.", '',
        '## Complete denominators', '', '```json', json.dumps(groups,indent=2), '```', '',
        '## All original and supplemental cases', '',
        '| Case | Expected | Original production outcome | Shadow assessment | Reason | Roundtrip ms |',
        '|---|---|---|---|---|---:|']
for r in rows:
    o=r['shadow']; before=r['before']
    text.append(f"| {r['item_id']} | {r['expected']} | {before['outcome'] if before else 'supplement only'} | {o['assessment']} | {o['reason']} | {o.get('roundtrip_ms',0):.1f} |")
text += ['', 'Unknown is retained in every denominator. A diagnostic instruction is not proof of prevented execution, and benign_evidence does not grant production permission.',
         'Full raw logits, token counts, timing, identity, stderr and lifecycle journals are alongside this report. No replay, threshold tuning or replacement model was used.']
(dest/'results.md').write_text('\n'.join(text)+'\n',encoding='utf-8')
print(json.dumps({'summary':summary,'groups':groups,'peak_committed_bytes':peak},indent=2))
