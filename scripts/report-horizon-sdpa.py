# SPDX-License-Identifier: Apache-2.0
import argparse,json,hashlib
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('--notes',type=Path,required=True)
args=parser.parse_args()
p=args.notes
repo=Path(__file__).resolve().parents[1]
def lines(path):return [json.loads(x) for x in path.read_text(encoding='utf-8').splitlines()]
old={x['request_id']:x for x in lines(p/'sou109-horizon-run-v1/observations.jsonl')}
runs={}
for name,folder,fixture in [('global','sou109-sdpa-global-v1','sou109-sdpa-fixture.json'),('local','sou109-sdpa-local-v1','sou109-sdpa-local-fixture.json'),('boundary','sou109-sdpa-boundary-v2','sou109-sdpa-boundary-fixture.json')]:
    d=p/folder; rows=lines(d/'observations.jsonl'); journal=lines(d/'journal.jsonl'); identity=lines(d/'identity.jsonl')[0]
    assert identity['fixture_sha256']==hashlib.sha256((p/fixture).read_bytes()).hexdigest()
    assert journal==[v for r in rows for v in [{'id':r['id'],'state':'started'},{'id':r['id'],'state':'completed'}]]
    runs[name]={'identity':identity,'observations':rows,'stages':lines(d/'stages.jsonl'),'startups':lines(d/'startups.jsonl'),
                'fixture':json.loads((p/fixture).read_text(encoding='utf-8'))}
assert [r['id'] for r in runs['global']['observations']]==['r0010','r0028','r0029','r0038','r0041','r0043','r0048','r0049','r0050','r0055']
assert len(runs['local']['observations'])==18 and len(runs['boundary']['observations'])==6
for name,run in runs.items():
    for row in run['observations']:
        stages=[s['stage'] for s in run['stages'] if s['id']==row['id']]
        assert stages==(['infer_started','infer_completed','serialize_completed'] if row.get('logits') else ['infer_started'])
    if name!='global':
        assert run['fixture']['rows'][:10]==runs['global']['fixture']['rows'] or all(
            a['ids']==b['ids'] and a['offsets']==b['offsets'] and a['envelope_sha256']==b['envelope_sha256']
            for a,b in zip(run['fixture']['rows'][:10],runs['global']['fixture']['rows']))
comparisons=[]
for r in runs['global']['observations']:
    prior=old[r['id']];a=prior.get('logits');b=r.get('logits')
    error=max(abs(x-y) for x,y in zip(a,b)) if a and b else None
    comparisons.append({'id':r['id'],'onnx_logits':a,'sdpa_logits':b,'max_abs_error':error,
                        'numerical_parity':error<=.0001 if error is not None else None,
                        'same_decision':prior['assessment']==r['assessment'] if a and b else None})
weights=json.loads((p/'sou109-sdpa-weight-comparison.json').read_text())
assert weights['unmatched_native']==weights['unmatched_onnx']==[]
out={'production_authority':False,'runs':runs,'comparisons':comparisons,'weights':weights,
     'limitations':['Targeted development diagnostics, not held-out qualification.',
       'Preencoded inputs: encode timings separate; roundtrip is not full pipeline latency.',
       'RSS is cumulative actual-worker process peak, not per-input incremental allocation.',
       'Original ONNX missing memory remains missing; no historical repair.',
       'Two startup attempts failed serializing empty loading-info sets after synthetic warmup, before any corpus inference.',
       'First boundary control was too short to cross a window. Retained; separate longer control frozen in c8a5abe.',
       'Windows reset positions and cannot establish full-context equivalence; low local scores never authorize release.',
       'No original-server useful/refusal witnesses or SOU146 native rerun performed.']}
(repo/'docs/operations/evidence/sou109-sdpa-targeted.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps(comparisons,indent=2))
for name in runs:
    print(name,[(r['id'],r['assessment'],round(r['roundtrip_ms']), r.get('memory',{}).get('process_peak_rss_bytes',r.get('memory_at_failure',{}).get('process_peak_rss_bytes'))) for r in runs[name]['observations']])
