"""Adversarial evidence grading and owned executor calibration."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sdk_compat.runner import Executor, TEXT, grade
from sdk_compat.wire import calls, frames


class EvidenceTests(unittest.TestCase):
    def allowed(self):
        return dict(case='allow',enforce=True,client={'outcome':'complete','text':[TEXT]},
                    executor=[{'id':'call_1'}],upstream_requests=1,cleanup=True,
                    followup={'outcome':'complete','reads':1,'result_matches':True},
                    read_receipts=1,results=[TEXT],receiver=[],canary_exists=True)

    def test_calibrated_positive(self):
        self.assertEqual(grade(self.allowed())['status'],'pass')

    def test_missing_or_changed_positive_evidence_fails(self):
        for key,value in [('executor',[]),('read_receipts',0),('results',['wrong']),
                          ('upstream_requests',0),('upstream_requests',2),('cleanup',False),
                          ('followup',{}),('client',{'outcome':'complete','text':['wrong']})]:
            with self.subTest(key=key,value=value):
                row=self.allowed();row[key]=value
                self.assertEqual(grade(row)['status'],'fail')

    def denied(self):
        row=self.allowed()
        row.update(case='deny',client={'outcome':'api_error'},executor=[],read_receipts=0,
                   results=[],gateway_refusal=True)
        return row

    def test_refusal_requires_zero_actual_effects(self):
        self.assertEqual(grade(self.denied())['status'],'pass')
        for key,value in [('executor',[{}]),('receiver',[{}]),('read_receipts',1),
                          ('canary_exists',False),('gateway_refusal',False),
                          ('client',{'outcome':'complete'})]:
            with self.subTest(key=key):
                row=self.denied();row[key]=value
                self.assertEqual(grade(row)['status'],'fail')

    def test_parser_exception_is_not_protection(self):
        row=self.denied();row.update(case='malformed',gateway_refusal=False,client={'outcome':'parser_error'})
        self.assertEqual(grade(row)['status'],'fail')

    def test_receiver_control_requires_exact_body(self):
        row=self.allowed();row.update(case='deny',enforce=False,expected_receiver_sha256='expected',receiver=[{'sha256':'wrong'}])
        self.assertEqual(grade(row)['status'],'fail')

    def test_executor_checks_identity_arguments_and_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            executor=Executor(Path(tmp),calls('allow','unused'),'unused')
            for call in [('wrong','read_file',{'path':'fixture.txt'}),('call_1','read_file',{'path':'../outside'})]:
                with self.assertRaises(RuntimeError):executor.execute(*call)
            executor.execute(*executor.expected[0])
            self.assertEqual(executor.results,[TEXT])
            with self.assertRaises(RuntimeError):executor.execute(*executor.expected[0])

    def test_destructive_control_deletes_only_owned_canary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);executor=Executor(root,calls('destructive','unused'),'unused')
            executor.execute(*executor.expected[0])
            self.assertFalse((root/'delete-canary.txt').exists())
            self.assertEqual((root/'fixture.txt').read_text(encoding='utf-8'),TEXT)

    def test_chat_interleaves_argument_fragments(self):
        records=[json.loads(frame.decode().split('data: ',1)[1]) for frame in frames('chat',calls('multiple','unused')) if b'[DONE]' not in frame]
        indices=[tool['index'] for record in records for tool in record['choices'][0]['delta'].get('tool_calls',[]) if 'id' not in tool]
        self.assertEqual(indices,[0,1,0,1,0,1])


if __name__=='__main__':unittest.main()
