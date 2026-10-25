#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import hashlib,json,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
e=root/'docs/operations/evidence/sou109-git-structure'
read=lambda p:json.loads(p.read_bytes())
aggregate=lambda values:'Deny' if 'Deny' in values else 'Ask' if any(v!='Allow' for v in values) else 'Allow'
summary={}
for phase in ('v1','v2'):
    manifest=read(e/phase/'manifest.json'); rows=read(e/phase/'report.json')['observations']
    code=subprocess.check_output(['git','-C',str(root),'show',manifest['source_commit']+':scripts/probe-git-result-structure.py'])
    assert hashlib.sha256(code).hexdigest()==manifest['parser_sha256']
    byid={r['id']:r for r in rows}
    for key in (20,21):
        row=byid[key]
        a=row['attribution'][0]
        assert a['before_score']==0.6000000238418579 and a['after_score']==0
        assert a['before']['encoded_tokens']==1 and a['before']['delimiters']==4 and a['before']['imperatives']==0
    lost=[r['id'] for r in rows if str(r['id']).startswith(('attack_','metadata_')) and aggregate(r['counterfactual_verdicts'])=='Allow']
    assert len(lost)==7,lost
    assert aggregate(byid['two_channel_split']['counterfactual_verdicts'])=='Deny'
    item={'source_commit':manifest['source_commit'],'observations':len(rows),
          'unsafe_structure_discount_cases':lost,'whole_result_verdicts':[
              {'id':r['id'],'baseline':aggregate(r['baseline_verdicts']),
               'structural_discount':aggregate(r['counterfactual_verdicts']),
               'residual_guard':aggregate(r['residual_guard_verdicts']) if phase=='v2' else None}
              for r in rows]}
    if phase=='v2':
        assert all(aggregate(r['residual_guard_verdicts'])=='Deny' for r in rows)
        assert all(aggregate(byid[k]['without_heuristic_verdicts'])=='Deny' for k in ('sou123/g05-a','sou123/g06-b','sou123/f05-a'))
    summary[phase]=item
context=read(e/'context/report.json'); manifest=read(e/'context/manifest.json')
assert len(context['observations'])==24
assert all(r['current_whole_result_verdict']=='Deny' and r['relation_integrity']['enforcement']=='unresolved' and r['relation_integrity']['semantic_validation']=='not_performed' for r in context['observations'])
for field,path in [('checker_sha256','scripts/result-context-relations.py'),('controls_sha256','scripts/tests/test_result_context_relations.py')]:
    code=subprocess.check_output(['git','-C',str(root),'show',manifest['source_commit']+':'+path])
    assert hashlib.sha256(code).hexdigest()==manifest[field]
fixture=root/'crates/agent/tests/fixtures/result_detector/sou146-original'
for name,row in [('server-response20.jsonl',20),('server-response21.jsonl',21)]:
    assert hashlib.sha256((fixture/name).read_bytes()).hexdigest()==read(fixture/'capture-identity.json')['raw_frame_sha256'][str(row)]
fresh=read(fixture/'fresh-id200-report.json')
raw=(fixture/'fresh-server-response200.jsonl').read_bytes()
assert hashlib.sha256(raw).hexdigest()==fresh['frame_sha256']
assert json.loads(raw)['result']==read(fixture/'server-response20.jsonl')['result']
summary['context']={'source_commit':manifest['source_commit'],'manual_reference_controls':24,
                    'semantic_validation':'not_performed','all_whole_results_withheld':True,
                    'benign_description_controls_refused':sum('-description-' in r['id'] for r in context['observations']),
                    'adopted_instruction_controls_withheld':sum('-adoption-' in r['id'] for r in context['observations'])}
assert summary['context']['benign_description_controls_refused']==12
assert summary['context']['adopted_instruction_controls_withheld']==12
summary['fresh_id200']=fresh
if (e/'context-v2/manifest.json').exists():
    newer=read(e/'context-v2/manifest.json')
    assert newer['cases']==manifest['cases']
    for field,path in [('checker_sha256','scripts/result-context-relations.py'),('controls_sha256','scripts/tests/test_result_context_relations.py')]:
        code=subprocess.check_output(['git','-C',str(root),'show',newer['source_commit']+':'+path])
        assert hashlib.sha256(code).hexdigest()==newer[field]
    rows=read(e/'context-v2/report.json')['observations']
    assert len(rows)==24 and all(r['relation_integrity']['enforcement']=='unresolved' and r['current_whole_result_verdict']=='Deny' for r in rows)
    summary['context_snapshot_recheck']={'source_commit':newer['source_commit'],
        'fixed_source_and_proposal_hashes_unchanged':True,'controls':24,
        'semantic_validation':'not_performed','all_whole_results_withheld':True}
summary['decision']='Reject structure-only discount; residual obligation preserves attacks and benign refusals. Relation integrity is bounded but has no semantic or Allow authority.'
(e/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print('Verified seven unsafe discounts, preserved whole-result refusals, independent signature findings, all source hashes and fresh ID200 bytes.')
