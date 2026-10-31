import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
import os
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
S=load('shadow','scripts/ci/formatter-shadow-controls.py')
C=load('classifier','rule_baseline/rule_baseline.py')
G=load('projection','scripts/ci/project-formatter-shadow.py')
TOOLS=json.loads((ROOT/'profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json').read_text())['result']['tools']

class Controller(unittest.TestCase):
    def test_refusal_predicates_isolate_each_failure_without_payloads(self):
        cl={'unknown':True,'reason_codes':['partial_unknown','truncated','private']}
        reply={'result':{'isError':True,'content':[{'type':'text','text':S.UNKNOWN_REFUSAL}]}}
        self.assertTrue(all(S.refusal_diagnostics(cl,reply,[])['predicates'].values()))
        variants=[({'unknown':False,'reason_codes':['truncated']},reply,[],'classifier_unknown'),
                  ({'unknown':True,'reason_codes':[]},reply,[],'classifier_truncated'),
                  (cl,reply,[{'execution':True}],'zero_execution_records'),
                  (cl,{'error':{'code':-32603,'message':'classifier_invalid PRIVATE'}},[],'tool_error')]
        for c,r,rows,predicate in variants:
            d=S.refusal_diagnostics(c,r,rows)
            self.assertFalse(d['predicates'][predicate])
            self.assertNotIn('PRIVATE',json.dumps(d))
            self.assertNotIn('private',json.dumps(d))
        d=S.classification_diagnostic({'event':'mcp_classification','host_call_id':'shadow-201-False',
            'classification':{'unknown':True,'actions':['read'],'reason':'SECRET'},'authoritative_verdict':'ask'})
        self.assertEqual(d,{'case_id':'shadow-201-False','unknown':True,'verdict':'ask','read_only':True})
        self.assertIsNone(S.classification_diagnostic({'event':'mcp_classification','host_call_id':'private'}))

    def test_selected_unknown_reason_requires_exact_original_server_contract(self):
        cl={'unknown':True,'reason_codes':['partial_unknown','truncated']}
        for text in (S.UNKNOWN_REFUSAL,
                     'Soup Wall withheld MCP invocation (policy_unconfirmed_ask)',
                     'Soup Wall withheld MCP invocation (classifier_deny)',
                     'Soup Wall withheld MCP invocation (native_approval_timeout)',
                     S.UNKNOWN_REFUSAL+' unrelated',
                     'Soup Wall withheld MCP invocation (classifier_ask)'):
            reply={'result':{'isError':True,'content':[{'type':'text','text':text}]}}
            d=S.refusal_diagnostics(cl,reply,[])
            self.assertEqual(all(d['predicates'].values()),text==S.UNKNOWN_REFUSAL)
        source=(ROOT/'crates/agentfw/src/mcp/admission/real_server.rs').read_text()
        guard=source.split('assessment.known_read_only',1)[1].split('let mut boundary',1)[0]
        self.assertIn('collector.config.approval.is_some()',guard)
        self.assertIn('"classifier_unknown_approval_unsupported"',guard)

    def ordinary(self,wrong_error=False):
        sessions={};seen=[]
        def call(event,fields=None,session=None):
            seen.append((session,event,copy.deepcopy(fields)))
            if event=='session_start': sessions[session]=0;return {'release':True}
            if event=='session_end': sessions.pop(session);return {'release':True}
            if event=='call':
                sessions[session]+=1
                return {'release':True,'call_id':session+'-receipt'}
            self.assertEqual(fields['call_id'],session+'-receipt')
            self.assertTrue({'tool','args','call_id','content','result_kind','delivery'}<=set(fields))
            if 'execution' in fields:
                e=urllib.error.HTTPError('http://localhost',400,'refused',{},None)
                e.native_error_code='native_call_unknown' if wrong_error else 'native_invalid_fields'
                raise e
            return {'release':True}
        return call,sessions,seen

    def test_complete_matched_wire_control_requires_specific_refusal_and_cleans_up(self):
        invocation={'id':'read','params':{'name':'read_text_file','arguments':{'path':'/workspace/notes.txt'}}}
        for wrong in (False,True):
            call,sessions,seen=self.ordinary(wrong)
            if wrong:
                with self.assertRaisesRegex(RuntimeError,'wrong_refusal'):S.copied_control(call,'a'*64,invocation,'{}',{'copied':True})
            else:
                self.assertEqual(S.copied_control(call,'a'*64,invocation,'{}',{'copied':True}),['baseline_only','native_invalid_fields'])
            self.assertEqual(sessions,{})
            results=[(session,fields) for session,event,fields in seen if event=='result']
            self.assertEqual(len({r[0] for r in results}),2)
            a,b=[r[1] for r in results];a.pop('call_id');b.pop('call_id');b.pop('execution')
            self.assertEqual(a,b)

    def test_real_classifier_and_controller_keep_201_256_before_execution(self):
        definition=next(t for t in TOOLS if t['name']=='read_multiple_files')
        for count in S.SIZES:
            classification=C.classify({'tool_name':'read_multiple_files','raw_arguments':{'paths':[f'/workspace/shadow-{i}.txt' for i in range(count)]},
                                       'server_id':'filesystem','tool_schema':definition['inputSchema'],'tool_description':definition['description']})
            self.assertEqual(classification['actions'],['read'])
            self.assertEqual(classification['unknown'],count>200)
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp);workspace=out/'workspace';workspace.mkdir();S.prepare(workspace)
            audit=[]
            class Selected:
                def exchange(_,request):
                    paths=request['params']['arguments']['paths']
                    if len(paths)>200:
                        return {'result':{'isError':True,'content':[{'type':'text','text':S.UNKNOWN_REFUSAL}]}},b''
                    parts=[f'{p}:\n{(workspace/Path(p).name).read_text()}\n' for p in paths];text='\n---\n'.join(parts)
                    evidence={'closure_sha256':'a'*64}
                    if request['id']!='shadow-ambiguous':
                        offset=0;spans=[]
                        for part in parts[:-1]:offset+=len(part.encode());spans.append({'start':offset,'end':offset+5});offset+=5
                        evidence['formatter_shadow']={'production_authority':False,'separator_spans':spans,'complete_text_bytes':len(text.encode()),'text_sha256':hashlib.sha256(text.encode()).hexdigest()}
                    attack=request['id'].endswith('True')
                    pairs=[{'correction_applied':not attack,'eligibility':'consumed_original_formatter','block':i,'text_sha256':hashlib.sha256(text.encode()).hexdigest(), 'comparison':{'contract':'sw-mcp/policy-shadow/1','production_authority':False,'task_complete':False,'original':{'verdict':'deny'},'candidate':{'verdict':'deny' if attack else 'allow'}}} for i in range(2)]
                    if request['id']=='shadow-ambiguous':
                        for pair in pairs:
                            pair['correction_applied']=False
                            pair['eligibility']='baseline_no_bound_formatter'
                            pair['comparison']['original']={'verdict':'allow'}
                            pair['comparison']['candidate']={'verdict':'allow'}
                    audit.append({'event':'native_result','execution':evidence,'released':not attack,'verdict':'deny' if attack else 'allow','policy_shadow':pairs})
                    return ({'result':{'isError':True}} if attack else {'result':{'content':[{'type':'text','text':text}],'structuredContent':{'content':text}}}),b''
            ordinary,_,_=self.ordinary()
            S.exercise(Selected(),lambda:audit,{'runtime':{'closure_sha256':'a'*64}},ordinary,out,'b'*40,'c'*64,
                       {'id':'read','params':{'name':'read_text_file','arguments':{'path':'/workspace/notes.txt'}}},'{}',C.classify,TOOLS)
            report=json.loads((out/'formatter-shadow.json').read_text())
            self.assertEqual(len(audit),5)
            self.assertEqual(sum(r['status']=='pre_execution_unknown' for r in report['cases']),4)
            runtime={'source_commit':'b'*40,'status':'passed','cleanup_verified':True,'owned_root_empty_final':True,'model_calls':0,
                     'source_read_only':True,'network':'private-loopback-only','execution_records':[r['execution'] for r in audit]}
            self.assertFalse(G.project(report,runtime,'b'*40,0)['task_complete'])
            for mutate in ('unknown','row','exit','release','candidate','custody','bytes'):
                changed=copy.deepcopy(report)
                if mutate=='unknown':changed['cases'][4]['status']='passed'
                if mutate=='row':changed['cases'].pop()
                if mutate=='release':changed['cases'][1]['released']=True
                if mutate=='candidate':changed['cases'][1]['policy_shadow'][0]['comparison']['candidate']['verdict']='allow'
                if mutate=='custody':changed['cases'][0]['policy_shadow'][0]['eligibility']='copied'
                if mutate=='bytes':changed['cases'][0]['useful_bytes_equal']=False
                with self.assertRaises(ValueError):G.project(changed,runtime,'b'*40,1 if mutate=='exit' else 0)

    def test_workflow_explicit_opt_in_forwarding_and_failure_artifact(self):
        workflow=(ROOT/'.github/workflows/sou79-resource-budgets.yml').read_text()
        self.assertIn('formatter_shadow:',workflow)
        self.assertIn('shadow_args+=(--formatter-shadow)',workflow)
        self.assertIn('"${shadow_args[@]}" || status=$?',workflow)
        self.assertIn('project-formatter-shadow.py',workflow)
        retention=workflow.split('name: Retain finite SOU155 native runtime evidence')[1].split('retention-days: 30')[0]
        self.assertIn('if: always()',retention)
        self.assertIn('/formatter-shadow.json',retention)
        self.assertIn('/formatter-shadow-acceptance.json',retention)

    def test_actual_shell_flag_selection_is_off_by_default(self):
        bash=shutil.which('bash') if os.name!='nt' else 'C:/Program Files/Git/bin/bash.exe'
        if not bash or not Path(bash).exists(): self.skipTest('bash unavailable')
        workflow=(ROOT/'.github/workflows/sou79-resource-budgets.yml').read_text()
        snippet=workflow.split('          shadow_args=()')[1].split('          sudo systemd-run')[0]
        script='shadow_args=()'+snippet+'\nprintf "%s" "${shadow_args[*]}"\n'
        for value,expected in [('', ''),('false',''),('true','--formatter-shadow')]:
            result=subprocess.run([bash,'-c',script],env=dict(os.environ,FORMATTER_SHADOW=value),capture_output=True,text=True,check=True)
            self.assertEqual(result.stdout,expected)

    def test_first_transport_failure_retains_case_but_never_exception_payload(self):
        class Broken:
            def exchange(self,request): raise ValueError('private credential and raw body')
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                S.exercise(Broken(),lambda:[],{},None,Path(temp),'a'*40,None,None,None,C.classify,TOOLS)
            raw=(Path(temp)/'formatter-shadow.json').read_text()
            report=json.loads(raw)
            self.assertEqual(report['status'],'incomplete')
            self.assertEqual(report['cases'],[])
            self.assertEqual(report['first_failure'],{'case':'B16-benign','phase':'original_exchange','exception_type':'ValueError'})
            self.assertNotIn('private credential',raw)

if __name__=='__main__':unittest.main()
