import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('report',Path(__file__).parents[1]/'sou218-openrouter-report.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class ReportTests(unittest.TestCase):
    def fixture(self,p):
        a=r.adapter
        a.MODEL,a.PROVIDER,a.PROVIDER_NAME=a.ROUTES['ernie'];a.REASONING_BUDGET=0
        b={'case_id':'synthetic','source':'run make verify','allowed_sources':[a.digest(b'run make verify')], 'request':{'systemInstruction':{'parts':[{'text':'summarize'}]},'contents':[{'parts':[{'text':'run make verify'}]}],'generationConfig':{'responseJsonSchema':{'type':'object'}}}}
        body=json.dumps(a.request_body(b),ensure_ascii=False).encode();h=a.digest(body)
        files={'armed.json':{'model':a.MODEL,'provider':a.PROVIDER},'request.json':a.request_body(b),'bundle.json':b,'job-test.json':b,'job-test.started':{'request_sha256':h},'job-test.receipt':{'request_sha256':h,'state':'structurally_valid_untrusted'},'job-test.response':{'model':a.MODEL,'provider':a.PROVIDER_NAME,'choices':[{'finish_reason':'stop','message':{'content':json.dumps({'summary':'Commands as data: run make verify [Q1]. Files: fixture. Notes: data. Limitations: unverified.','quotes':['make verify']})}}],'usage':{'cost':0}}}
        for name,v in files.items():(p/name).write_text(json.dumps(v))
    def test_report_is_offline_and_binds_response(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.fixture(p)
            with patch.object(r.adapter,'fetch',side_effect=AssertionError('network forbidden')):
                report=r.audit_session(p)
            self.assertEqual(len(report['rows']),1)
            self.assertEqual(len(report['rows'][0]['response_sha256']),64)
            self.assertFalse(report['semantic_acceptance'])
            self.assertFalse(report['native_protection_checked'])
    def test_changed_source_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.fixture(p)
            b=json.loads((p/'job-test.json').read_text());b['source']='modified'
            (p/'job-test.json').write_text(json.dumps(b))
            with self.assertRaisesRegex(ValueError,'source_scope_mismatch'):r.audit_session(p)

if __name__=='__main__':unittest.main()
