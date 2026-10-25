# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('sdpa',Path(__file__).parents[1]/'diagnose-horizon-sdpa.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)

class WindowCoverage(unittest.TestCase):
    def test_every_token_survives_with_fixed_overlap(self):
        for n in (0,1,253,254,255,444,445,8190):
            ids=[2]+list(range(100,100+n))+[1]
            chunks=d.windows(ids); covered=set()
            for i,w in enumerate(chunks):
                self.assertLessEqual(len(w['ids']),256)
                self.assertEqual(w['ids'],[2]+ids[w['start']:w['end']]+[1])
                covered.update(range(w['start'],w['end']))
                if i:self.assertEqual(chunks[i-1]['end']-w['start'],64)
            self.assertEqual(covered,set(range(1,len(ids)-1)))

    def test_cross_boundary_sequence_is_not_dropped(self):
        ids=[2]+list(range(1000))+[1]
        chunks=d.windows(ids)
        for start in range(1,990):
            self.assertTrue(any(w['start']<=start and w['end']>=start+10 for w in chunks))

if __name__=='__main__':unittest.main()
