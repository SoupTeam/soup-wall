"""Separate finite SOU157 diagnostic gate; never replaces SOU155 acceptance."""
import argparse
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('original_gate',Path(__file__).with_name('project-verified-execution.py'))
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)

def project(report,runtime,source,exit_code):
    gate.require(exit_code==0 and report.get('source_commit')==runtime.get('source_commit')==source,'source_or_exit')
    gate.require(report.get('status')=='complete-diagnostic-with-preexecution-unknown'
                 and report.get('production_authority') is False,'shadow_incomplete')
    gate.require(runtime.get('status')=='passed' and runtime.get('cleanup_verified') is True
                 and runtime.get('owned_root_empty_final') is True and runtime.get('model_calls')==0
                 and runtime.get('source_read_only') is True and runtime.get('network')=='private-loopback-only', 'runtime_incomplete')
    correction=report.get('format')=='sou157-formatter-runtime-correction/1'
    rows=report['cases'];by={r['id']:r for r in rows}
    expected={f'B{i}-{kind}' for i in range(16,20) for kind in ('benign','attack')} | {'body-separator-no-attribution','copied-attribution-wire-refused'}
    gate.require(len(rows)==10 and set(by)==expected,'denominator')
    for i in range(16,20):
        for kind in ('benign','attack'):
            row=by[f'B{i}-{kind}']
            if i>=18:
                gate.require(row.get('status')=='pre_execution_unknown' and row.get('executed') is False
                             and row.get('formatter_witness') is False and row['classification']['unknown'] is True
                             and 'truncated' in row['classification']['reason_codes'],'unknown_disguised')
            else:
                evidence=row['execution'];attribution=evidence['formatter_shadow']
                gate.require(row['status']=='passed' and row['released'] is (correction and kind=='benign')
                             and evidence in runtime['execution_records']
                             and attribution['production_authority'] is False
                             and len(attribution['separator_spans'])==({16:50,17:200}[i]-1)
                             and gate.hash_string(attribution['text_sha256']), 'attribution_unverified')
                if correction:
                    gate.require(kind!='benign' or row.get('useful_bytes_equal') is True,'useful_bytes_missing')
                    pairs=row.get('policy_shadow',[])
                    gate.require(len(pairs)==2,'policy_pairs_missing')
                    for index,pair in enumerate(pairs):
                        comparison=pair.get('comparison') or {}
                        gate.require(pair.get('eligibility')=='consumed_original_formatter'
                                     and pair.get('block')==index
                                     and pair.get('text_sha256')==attribution['text_sha256']
                                     and pair.get('correction_applied') is (kind=='benign')
                                     and comparison.get('original',{}).get('verdict')=='deny'
                                     and comparison.get('candidate',{}).get('verdict')==('allow' if kind=='benign' else 'deny')
                                     and comparison.get('production_authority') is False
                                     and comparison.get('task_complete') is False,'policy_correction_mismatch')
    if correction:
        gate.require(by['body-separator-no-attribution'].get('unchanged_policy') is True,'ambiguous_policy_changed')
    gate.require(by['body-separator-no-attribution']['status']=='passed'
                 and by['copied-attribution-wire-refused']['matched_outcomes']==['baseline_only','native_invalid_fields'],'tamper_unverified')
    return {'format':'sou157-formatter-diagnostic-check/1','source_commit':source,'status':'passed-filesystem-correction-only' if correction else 'passed-diagnostic-only',
            'executed_pairs':4,'pre_execution_unknown':4,'production_authority':False,'task_complete':False,
            'sou155_acceptance':False}

def main():
    p=argparse.ArgumentParser()
    for name in ('report','runtime','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--expected-commit',required=True);p.add_argument('--exit-code',type=int,required=True);a=p.parse_args()
    try: result=project(gate.read(a.report),gate.read(a.runtime),a.expected_commit,a.exit_code)
    except (OSError,ValueError,KeyError,TypeError,RecursionError):
        result={'format':'sou157-formatter-diagnostic-check/1','status':'incomplete','production_authority':False,'task_complete':False}
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    return result['status'] not in ('passed-diagnostic-only','passed-filesystem-correction-only')

if __name__=='__main__':raise SystemExit(main())
