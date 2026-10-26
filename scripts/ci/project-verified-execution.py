#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Finite exact-source acceptance gate; a diagnostic/status string is insufficient."""
import argparse,json,os,re,stat
from pathlib import Path

CASES={
 'actual-original-useful-read','executable-formatter-replacement-after-capture',
 'concurrent-original-call-correlation','deny-zero-workspace-effect',
 'copied-source-metadata-wire-forgery','actual-original-cancel-with-useful-followup',
 'retired-child-authority-replay','executable-replacement-before-capture',
 'identical-schema-alternate-formatter-with-new-tree-hash',
 'daemon-restart-old-authority-refused-new-read-useful','exact-original-ask-approved-once',
 'strong-body-refusal-with-useful-followup','bounded-evidence-overflow-with-useful-followup'}
META={'contract','daemon_instance_id','catalogue_sha256','closure_sha256','process_generation_sha256',
      'channel_generation_sha256','session_epoch_sha256','native_call_id','invocation_sha256',
      'original_result_sha256','original_result_bytes','domain_witness'}

def read(path):
 # The candidate produces these files; cap the read before allocating, and
 # never follow a substituted path out of the owned evidence directory.
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as stream:
    info=os.fstat(stream.fileno())
    require(stat.S_ISREG(info.st_mode) and info.st_size<=131072,'report_over_cap_or_type')
    raw=stream.read(131073)
 if len(raw)>131072:raise ValueError('report_over_cap')
 def unique(pairs):
    value={}
    for key,item in pairs:
       if key in value:raise ValueError('duplicate_report_key')
       value[key]=item
    return value
 value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False,'invalid_json_constant'))
 require(isinstance(value,dict),'report_object_required')
 return value
def require(value,code):
 if not value:raise ValueError(code)
def hash_string(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None

def project(report,build,expected,exit_code):
 require(re.fullmatch('[0-9a-f]{40}',expected) is not None,'source_invalid')
 require(exit_code==0 and report.get('format')=='sou155-native-execution/1'
    and report.get('source_commit')==build.get('source_commit')==expected,'same_source_or_exit_invalid')
 require(report.get('status')=='passed' and report.get('acceptance_pass') is True
    and build.get('status')=='passed' and build.get('runtime_qualification') is False,'runtime_or_build_incomplete')
 require(report.get('model_calls')==0 and report.get('source_read_only') is True
    and report.get('network')=='private-loopback-only'
    and report.get('writes')=='isolated-scratch-and-owned-delegation-only','isolation_unverified')
 require(report.get('binary_sha256')==build.get('binary_sha256') and hash_string(report.get('binary_sha256')),
    'candidate_binary_mismatch')
 require(report.get('cleanup_verified') is True and report.get('owned_root_empty_final') is True,'cleanup_unverified')
 rows=report.get('cases');require(isinstance(rows,list) and len(rows)==len(CASES)
    and {row.get('case') for row in rows}==CASES and all(row.get('status')=='passed' for row in rows),'denominator_incomplete')
 by_name={row['case']:row for row in rows}
 require(by_name['concurrent-original-call-correlation'].get('calls')==4,'concurrency_denominator_invalid')
 require(by_name['actual-original-cancel-with-useful-followup'].get('original_reader_seen') is True
    and by_name['actual-original-cancel-with-useful-followup'].get('cancelled_result_released') is False
    and by_name['actual-original-cancel-with-useful-followup'].get('effects_rolled_back') is False,'cancellation_unverified')
 require(by_name['exact-original-ask-approved-once'].get('approval_replay_refused') is True,'ask_unverified')
 for name in ('strong-body-refusal-with-useful-followup','bounded-evidence-overflow-with-useful-followup'):
    require(by_name[name].get('refused') is True and by_name[name].get('useful_followup') is True,'result_floor_unverified')
 require(by_name['bounded-evidence-overflow-with-useful-followup'].get('incomplete_deny') is True,'overflow_unverified')
 for name in ('executable-replacement-before-capture','identical-schema-alternate-formatter-with-new-tree-hash'):
    require(by_name[name].get('endpoint_started') is False,'substitution_unverified')
 metadata=report.get('execution_records');require(isinstance(metadata,list) and len(metadata)==13
    and report.get('original_results')==13,'result_denominator_incomplete')
 for row in metadata:
    require(set(row)==META and row['contract']=='sw-mcp/verified-original-execution/1'
       and row['domain_witness'] is None and type(row['original_result_bytes']) is int
       and 0<row['original_result_bytes']<=1048576,'metadata_shape_invalid')
    require(all(hash_string(row[name]) for name in META if name.endswith('_sha256')),'metadata_digest_invalid')
    require(isinstance(row['native_call_id'],str) and 0<len(row['native_call_id'])<=128
       and isinstance(row['daemon_instance_id'],str) and 0<len(row['daemon_instance_id'])<=128,'metadata_identity_invalid')
 require(len({row['native_call_id'] for row in metadata})==13
    and len({row['invocation_sha256'] for row in metadata})==13,'call_reuse_detected')
 require(len({row['daemon_instance_id'] for row in metadata})==3
    and len({row['process_generation_sha256'] for row in metadata})==3
    and len({row['channel_generation_sha256'] for row in metadata})==3,'generation_reuse_detected')
 require(len({row['closure_sha256'] for row in metadata})==1,'original_closure_changed')
 require(len(build.get('steps',[]))==5 and all(step.get('status')=='passed' and step.get('exit_code')==0 for step in build.get('steps',[]))
    and {step.get('label') for step in build['steps']}=={'native-build','native-closure-unit','native-execution-unit','native-owner-unit','native-clippy'},'build_denominator_invalid')
 return {'format':'sou155-native-acceptance/1','status':'passed','acceptance_pass':True,
     'source_commit':expected,'binary_sha256':report['binary_sha256'],'cases':sorted(CASES),
     'original_results':13,'daemon_generations':3,'cleanup_verified':True,'model_calls':0,
     'execution_records':metadata,'policy_or_limits_relaxed':False,'production_relief_enabled':False}

def main():
 p=argparse.ArgumentParser()
 for name in ('report','build','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--expected-commit',required=True);p.add_argument('--exit-code',type=int,required=True);a=p.parse_args()
 try:result=project(read(a.report),read(a.build),a.expected_commit,a.exit_code)
 except (OSError,ValueError,KeyError,TypeError,RecursionError):
    result={'format':'sou155-native-acceptance/1','status':'incomplete','acceptance_pass':False,'source_commit':a.expected_commit,'reason':'native_controls_unverified'}
 a.output.write_text(json.dumps(result,indent=2)+'\n');return result['acceptance_pass'] is not True
if __name__=='__main__':raise SystemExit(main())
