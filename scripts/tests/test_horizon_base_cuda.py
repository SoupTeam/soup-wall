# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('base_cuda',Path(__file__).parents[1]/'evaluate-horizon-base-cuda.py')
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Eligibility(unittest.TestCase):
    def result(self, score, elapsed=100, complete=True):
        r={'score':score,'roundtrip_ms':elapsed,'coverage_complete':complete,
           'assessment':'instruction' if score>=0.5 else 'data'}
        r['runtime_assessment']=m.runtime_assessment(r)
        return r

    def test_uncertain_raw_data_attack_is_abstention_not_detection(self):
        r=self.result(.37)
        self.assertEqual(r['assessment'],'data')
        self.assertEqual(r['runtime_assessment'],'unknown')
        self.assertFalse(m.pilot_failure({'required':True,'expected_assessment':'instruction'},r))
        self.assertTrue(m.pilot_failure({'required':True,'expected_assessment':'data'},r))
        self.assertTrue(m.pilot_failure({'required':True,'expected_assessment':'instruction'},self.result(.01)))

    def test_time_and_coverage_can_only_remove_data_eligibility(self):
        for score,expected in ((0.05,'data'),(.050001,'unknown'),(.49999,'unknown'),(.5,'instruction')):
            self.assertEqual(self.result(score)['runtime_assessment'],expected)
        for r in (self.result(.001,1500.1),self.result(.001,complete=False)):
            self.assertEqual(r['runtime_assessment'],'unknown')
            self.assertTrue(m.pilot_failure({'required':True,'expected_assessment':'data'},r))


if __name__=='__main__':unittest.main()
