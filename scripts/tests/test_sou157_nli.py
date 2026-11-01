import importlib.util
from pathlib import Path
import tempfile
import unittest
import json
import os

spec=importlib.util.spec_from_file_location('nli',Path(__file__).parents[1]/'sou157_nli.py')
nli=importlib.util.module_from_spec(spec);spec.loader.exec_module(nli)


class Protocol(unittest.TestCase):
    def test_negative_entailment_ambiguity_and_nonfinite_never_benign(self):
        for scores in ([.01,.01,.01],[.99,.99,.01],[.5,.01,.99],[],[float('nan'),0,1]):
            self.assertEqual(nli.assessment(scores),'unknown')
        self.assertEqual(nli.assessment([.01,.99,.01]),'benign_evidence')
        self.assertEqual(nli.assessment([.99,.01,.01]),'instruction')

    def test_frozen_inputs_complete_and_unique_no_labels_in_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'protocol.json';nli.prepare(path)
            p=json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(len(p['rows']),65)
            self.assertEqual(len({r['id'] for r in p['rows']}),65)
            self.assertEqual(sum(r['class']=='semantic' for r in p['rows']),48)
            for row in p['rows']:
                text=nli.envelope(row['channels'])
                for channel in row['channels']:self.assertIn(channel,text)
            with self.assertRaises(FileExistsError):nli.prepare(path)

    @unittest.skipUnless(os.name=='nt','actual Windows Job ownership')
    def test_owned_tree_memory_limit_timeout_and_cleanup(self):
        job=nli.Job(['--stub'],memory=256*1024**2)
        try:
            ready=job.receive(10)
            self.assertTrue(ready['ready'])
            memory=job.memory()
            self.assertEqual(memory['job_limit_bytes'],256*1024**2)
            self.assertGreater(memory['job_peak_committed_bytes'],32*1024**2)
            with self.assertRaises(TimeoutError):job.receive(.1)
        finally:
            cleanup=job.close()
        self.assertEqual(cleanup['active_processes_after'],0)


if __name__=='__main__':unittest.main()
