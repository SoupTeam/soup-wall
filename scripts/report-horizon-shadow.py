#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate retained Horizon predictions, source coverage, and comparisons; no inference."""
import argparse
from collections import Counter
import importlib.util
import json
import math
from pathlib import Path
import statistics

spec=importlib.util.spec_from_file_location('horizon',Path(__file__).with_name('evaluate-horizon-shadow.py'))
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)


def read(path):return json.loads(path.read_text(encoding='utf-8'))
def lines(path):return [json.loads(x) for x in path.read_text(encoding='utf-8').splitlines()]
def latency(values):
    values=sorted(values)
    if not values:return {'n':0}
    return {'n':len(values),'median_ms':statistics.median(values),'p95_ms_nearest_rank':values[math.ceil(.95*len(values))-1],
            'max_ms':values[-1],'sum_ms':sum(values)}


def build(run,prepared,assets):
    from tokenizers import Tokenizer
    identity=read(run/'identity.json');summary=read(run/'summary.json')
    if identity['source_script_sha256']!='502f08ddb9af34cd35850f9b333353638c265bcd8670e7a788bd791a8b900c9a':
        raise ValueError('this historical exporter targets the frozen v1 runner only')
    if not summary['complete'] or summary['observations']!=58:raise ValueError('incomplete run')
    for name,expected in [('requests.jsonl',h.REQUEST_SHA),('references.jsonl',h.REFERENCE_SHA)]:
        if h.owned.digest(prepared/name)!=expected:raise ValueError('source changed')
    if h.owned.digest(assets/'tokenizer.json')!=identity['assets']['files']['tokenizer.json']['sha256']:raise ValueError('tokenizer changed')
    tokenizer=Tokenizer.from_file(str(assets/'tokenizer.json'));tokenizer.no_truncation();tokenizer.no_padding()
    requests=lines(prepared/'requests.jsonl');refs=lines(prepared/'references.jsonl');observations=lines(run/'observations.jsonl')
    if [r['request_id'] for r in observations]!=[r['request_id'] for r in requests] or len({r['request_id'] for r in observations})!=58:raise ValueError('coverage identity')
    expected_journal=[{'request_id':r['request_id'],'state':state} for r in requests for state in ('started','completed')]
    journal=lines(run/'journal.jsonl')
    if journal!=expected_journal:raise ValueError('incomplete journal')
    cases=[];counts=Counter();reasons=Counter();misses=[];flags=[];source_full=[]
    for request,ref,obs in zip(requests,refs,observations):
        if not request['input_sha256']==ref['input_sha256']==obs['input_sha256']:raise ValueError('hash mismatch')
        text,spans=h.envelope(request['input']['untrusted_text_channels'])
        encoded=tokenizer.encode(text,add_special_tokens=True)
        if obs['assessment']!='unknown':
            label,score=h.assessment(obs['logits'])
            if label!=obs['assessment'] or score!=obs['score']:raise ValueError('raw score mismatch')
            if len(encoded.ids)>8192 or not obs['coverage_complete'] or obs['tokens']!=len(encoded.ids):raise ValueError('incomplete full coverage')
            if obs['source_spans']!=spans or obs['offsets']!=[list(x) for x in encoded.offsets]:raise ValueError('offset mismatch')
            if obs['input_envelope_sha256']!=h.hashlib.sha256(text.encode('utf-8')).hexdigest():raise ValueError('envelope mismatch')
        elif obs['reason']=='unsupported_full_context':
            if len(encoded.ids)<=8192 or obs['tokens']!=len(encoded.ids):raise ValueError('false context error')
        elif obs['reason']=='timeout':
            if obs['score'] is not None or obs['roundtrip_ms']<10000:raise ValueError('false timeout')
        else:raise ValueError('unexpected error; explicit validation required')
        counts[ref['expected']+'->'+obs['assessment']]+=1;reasons[obs['reason']]+=1
        if ref['expected']=='attack' and obs['assessment']=='data':misses.append(obs['request_id'])
        if ref['expected']=='benign' and obs['assessment']=='instruction':flags.append(obs['request_id'])
        if len(encoded.ids)<=2048 and obs['assessment']!='unknown':source_full.append(obs['roundtrip_ms'])
        cases.append({'reference':ref,'source_tokens':len(encoded.ids),'observation':obs})
    baseline_path=h.ROOT/'docs/operations/evidence/sou109-full-corpus-0698af7.json'
    baseline=read(baseline_path);old_false={c['case_id'] for c in baseline['cases'] if c['outcome']=='false_refusal'}
    paired=[{'case_id':c['reference']['origin'].split('/')[-1],'request_id':c['reference']['request_id'],
             'horizon_assessment':c['observation']['assessment'],'reason':c['observation']['reason']}
            for c in cases if c['reference']['origin'].startswith('sou123/') and c['reference']['origin'].split('/')[-1] in old_false]
    if len(paired)!=10:raise ValueError('original-ten identity mismatch')
    startups=lines(run/'startups.jsonl')
    memory=[x['memory']['process_peak_rss_bytes'] for x in startups]
    for o in observations:
        if o.get('memory'):memory.append(o['memory']['process_peak_rss_bytes'])
        if o.get('memory_at_failure'):memory.append(o['memory_at_failure']['process_peak_rss_bytes'])
    return {'candidate':'Horizon-Labs/prompt-injection-guard-base','protocol_source_commit':'0fee481',
      'production_authority':False,'identity':identity,'summary':summary,'counts':dict(counts),'reasons':dict(reasons),
      'semantic_miss_ids':misses,'false_instruction_ids':flags,'raw_startups':startups,'journal':journal,
      'latency_all_including_unknown':latency([o['roundtrip_ms'] for o in observations]),
      'latency_successful_full':latency([o['roundtrip_ms'] for o in observations if o['assessment']!='unknown']),
      'latency_successful_full_at_most_2048_tokens':latency(source_full),
      'max_launcher_peak_rss_bytes':max(memory),'model_worker_peak_rss_bytes':None,
      'memory_measurement_error':'v1 measured Windows venv launcher, not model worker; model RSS unavailable; no replay',
      'original_ten_false_refusals':paired,
      'original_ten_horizon_counts':dict(Counter(c['horizon_assessment'] for c in paired)),
      'dev_screen':'reject' if misses else 'requires_review_not_production',
      'source_sha256':{name:h.owned.digest(run/name) for name in ('identity.json','observations.jsonl','journal.jsonl','startups.jsonl','summary.json')},
      'production_baseline_sha256':h.owned.digest(baseline_path),'cases':cases,
      'limitations':['Known public development examples, not independent held-out efficacy.',
        'No inference replay during report generation; no produced quotes.',
        'Offsets delimit input coverage, not attack attribution.',
        'Recorded v1 RSS belongs to the Windows venv launcher; model/runtime RSS was not captured. Do not use it for a model memory comparison.',
        'Unknowns do not count as correct negatives; no production changes.']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for n in ('run','prepared','assets','output'):parser.add_argument('--'+n,type=Path,required=True)
    a=parser.parse_args();result=build(a.run,a.prepared,a.assets)
    with a.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k in ('counts','reasons','semantic_miss_ids','false_instruction_ids','latency_all_including_unknown','latency_successful_full_at_most_2048_tokens','max_process_peak_rss_bytes','original_ten_horizon_counts','summary')},ensure_ascii=True))
