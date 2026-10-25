# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import time
import unittest

spec=importlib.util.spec_from_file_location('horizon',Path(__file__).parents[1]/'evaluate-horizon-shadow.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)


class HorizonTests(unittest.TestCase):
    def test_channel_bytes_order_and_empty_boundary(self):
        channels=['текст\n[end channel c0]','', 'attack after separator']
        text,spans=h.envelope(channels)
        self.assertEqual(len(spans),3)
        for original,span in zip(channels,spans):
            self.assertEqual(text[span['start_char']:span['end_char']],original)
            self.assertEqual(span['source_end_byte'],len(original.encode('utf-8')))
        self.assertLess(spans[0]['end_char'],spans[2]['start_char'])

    def test_fixed_threshold_and_invalid_logits(self):
        self.assertEqual(h.assessment([0,0]),('instruction',.5))
        self.assertEqual(h.assessment([5,0])[0],'data')
        for logits in ([float('nan'),0],[0],[0,float('inf')]):
            with self.assertRaises(ValueError):h.assessment(logits)

    def test_full_context_and_no_prefix_execution(self):
        class Tokenizer:
            def encode(self,text,add_special_tokens):
                self.text=text
                return SimpleNamespace(ids=list(range(8193)),attention_mask=[1]*8193)
        class Session:
            def run(self,*a):raise AssertionError('oversize must not infer a prefix')
        tokenizer=Tokenizer();channels=['x'*9000,'last channel retained']
        result=h.infer(Session(),tokenizer,channels)
        self.assertEqual(result['assessment'],'unknown')
        self.assertEqual(result['tokens'],8193)
        self.assertIn(channels[-1],tokenizer.text)
        self.assertFalse(result['coverage_complete'])

    def test_complete_model_input_and_raw_score(self):
        class Tokenizer:
            def encode(self,text,add_special_tokens):
                return SimpleNamespace(ids=[1,23,45,2],attention_mask=[1]*4,offsets=[(0,0),(0,1),(1,2),(0,0)])
        class Session:
            def get_inputs(self):return [SimpleNamespace(name='input_ids'),SimpleNamespace(name='attention_mask')]
            def run(self,_,feed):
                self.feed=feed
                return [[[0.,2.]]]
        session=Session();result=h.infer(session,Tokenizer(),['ab'])
        self.assertEqual(session.feed['input_ids'].tolist(),[[1,23,45,2]])
        self.assertEqual(result['assessment'],'instruction')
        self.assertEqual(result['logits'],[0.,2.])
        self.assertEqual(result['token_range'],[0,4])

    def test_real_hanging_worker_is_killed(self):
        worker=h.Worker(Path('.'),test=True);begun=time.monotonic()
        try:
            with self.assertRaises(TimeoutError):worker.receive(.15)
        finally:worker.close()
        self.assertIsNotNone(worker.owned.p.poll())
        self.assertFalse(any(t.is_alive() for t in worker.readers))
        self.assertLess(time.monotonic()-begun,5)


if __name__=='__main__':unittest.main()
