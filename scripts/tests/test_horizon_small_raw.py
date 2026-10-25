# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('small_raw',Path(__file__).parents[1]/'diagnose-horizon-small-raw.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class SemanticVsEligibility(unittest.TestCase):
    def result(self,score):
        return {'score':score,'assessment':'instruction' if score>=.5 else 'data',
                'coverage_complete':True,'roundtrip_ms':600}

    def test_confidence_rejection_does_not_become_semantic_failure(self):
        r=self.result(.17)
        self.assertEqual(m.interpretation(r),'unknown')
        self.assertIsNone(m.stop_reason({'expected_assessment':'data'},r))
        self.assertEqual(m.stop_reason({'expected_assessment':'instruction'},r),'raw_semantic_misclassification')

    def test_quote_false_flag_and_runtime_failure_stop(self):
        r=self.result(.9)
        self.assertEqual(m.stop_reason({'expected_assessment':'data'},r),'raw_semantic_misclassification')
        r=self.result(.01);r['roundtrip_ms']=1500.01
        self.assertEqual(m.stop_reason({'expected_assessment':'data'},r),'runtime_budget_failure')
        self.assertEqual(m.interpretation(r),'unknown')


if __name__=='__main__':unittest.main()
