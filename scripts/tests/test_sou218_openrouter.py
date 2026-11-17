import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('adapter', Path(__file__).parents[1] / 'sou218-openrouter.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

class AdapterTests(unittest.TestCase):
    def bundle(self):
        return {'allowed_sources':[a.digest(b'make verify')], 'source':'make verify', 'request':{'systemInstruction':{'parts':[{'text':'instructions'}]},'contents':[{'parts':[{'text':'make verify'},{'text':'untrusted index'}]}],'generationConfig':{'responseJsonSchema':{'type':'object'}}}}
    def raw(self, summary='Run make verify (Q1)', quotes=None, **changes):
        value={'model':a.MODEL,'provider':'Ant Digital','choices':[{'finish_reason':'stop','message':{'content':json.dumps({'summary':summary,'quotes':quotes or ['make verify']})}}]}
        value.update(changes)
        return json.dumps(value).encode()
    def test_free_exact_routing(self):
        b=a.request_body(self.bundle())
        self.assertEqual(b['model'],a.MODEL)
        self.assertFalse(b['provider']['allow_fallbacks'])
        self.assertEqual(b['provider']['max_price'],{'prompt':0,'completion':0})
        self.assertEqual(b['provider']['only'],[a.PROVIDER])
        self.assertTrue(b['provider']['require_parameters'])
    def test_body_preserves_source_and_prompt(self):
        b=a.request_body(self.bundle())
        self.assertEqual(b['messages'][0]['content'],'instructions')
        self.assertEqual(b['messages'][1]['content'],'make verify\n\nuntrusted index')
    def test_valid_is_never_semantic_or_policy_acceptance(self):
        result=a.inspect_response(self.raw(),self.bundle())
        self.assertFalse(result['semantic_acceptance'])
        self.assertFalse(result['policy_allow'])
        self.assertFalse(result['native_protection_checked'])
    def test_bad_references(self):
        for text in ['Q0','Q2','Q12']:
            with self.assertRaises(ValueError): a.inspect_response(self.raw(text),self.bundle())
    def test_quote_not_in_source(self):
        with self.assertRaises(ValueError): a.inspect_response(self.raw(quotes=['invented']),self.bundle())
    def test_repeated_quote_budget(self):
        b=self.bundle(); b['source']='make verify '*9
        with self.assertRaises(ValueError): a.inspect_response(self.raw(),b)
    def test_duplicate_quotes(self):
        with self.assertRaises(ValueError): a.inspect_response(self.raw(quotes=['make verify']*2),self.bundle())
    def test_model_and_provider_drift(self):
        for change in [{'model':'paid/model'},{'provider':'other'}]:
            with self.assertRaises(ValueError): a.inspect_response(self.raw(**change),self.bundle())
    def test_no_overwrite_fence(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'fence';a.save(p,b'first')
            with self.assertRaises(FileExistsError):a.save(p,b'second')
            self.assertEqual(p.read_bytes(),b'first')
    def test_free_metadata(self):
        v={'data':{'id':a.MODEL,'endpoints':[{'tag':a.PROVIDER,'pricing':{'prompt':'0','completion':'0'},'supported_parameters':['structured_outputs','response_format']}]}}
        a.check_catalog(v)
        v['data']['endpoints'][0]['pricing']['completion']='0.01'
        with self.assertRaises(ValueError):a.check_catalog(v)
    def test_redirect_refused(self):
        with self.assertRaises(ValueError):a.NoRedirect().redirect_request(None,None,None,None,None,None)

    def test_duplicate_json_refused(self):
        with self.assertRaises(ValueError): a.strict_json('{"a":1,"a":2}')
    def test_session_key_once_and_duplicate_fence(self):
        from unittest.mock import patch, Mock
        catalog={'data':{'id':a.MODEL,'endpoints':[{'tag':a.PROVIDER,'pricing':{'prompt':'0','completion':'0'},'supported_parameters':['structured_outputs','response_format']}]}}
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); session=root/'session'; bundle=root/'bundle.json'
            bundle.write_text(json.dumps(self.bundle()))
            calls=[]
            def fetch(path, body=None, key=None):
                if body is None: return json.dumps(catalog).encode()
                calls.append(key)
                return self.raw()
            def sleep(seconds):
                if not (session/'job-a.json').exists():
                    a.save(session/'job-a.json',bundle.read_bytes())
                    a.save(session/'job-b.json',bundle.read_bytes())
                elif (session/'job-b.started').exists():
                    a.save(session/'stop',b'stop')
            libc=Mock();libc.prctl.return_value=0
            with patch.object(a.ctypes,'CDLL',return_value=libc), patch.object(a.resource,'setrlimit'), patch('builtins.input',return_value='OPENROUTER20 USD0'), patch.object(a.getpass,'getpass',return_value='sk-or-synthetic-test-only') as getkey, patch.object(a,'fetch',side_effect=fetch), patch.object(a.time,'sleep',side_effect=sleep):
                a.serve(session,bundle)
            self.assertEqual(getkey.call_count,1)
            self.assertEqual(calls,['sk-or-synthetic-test-only'])
            self.assertEqual(json.loads((session/'job-a.receipt').read_text())['remaining_budget'],19)
            for file in session.iterdir():
                self.assertNotIn(b'sk-or-synthetic-test-only',file.read_bytes())

if __name__=='__main__': unittest.main()
