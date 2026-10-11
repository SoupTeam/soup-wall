"""Handoff packages: the dev package carries no test fingerprints; the guard rejects injected leaks."""
import json
import tempfile
import unittest
from pathlib import Path

from sou13cp2 import ROOT
from sou13cp2.handoff import DEV, RESTRICTED, HandoffError, build_packages, scan, test_fingerprints
from sou13cp2.pipeline import FULL_MANIFEST_FILE, load_records
from sou13cp2.taxonomy import families
from _testsupport import CP1_DATA, CP2_PUBLIC, SEALED_COMMITTED, requires


@requires(CP1_DATA, CP2_PUBLIC, SEALED_COMMITTED)
class Packages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name)
        cls.result = build_packages(cls.out)
        cls.fams = families()
        cls.manifest = json.loads((ROOT / FULL_MANIFEST_FILE).read_text(encoding='utf-8'))
        cls.records = load_records(ROOT, cls.fams, cls.manifest)
        cls.fps = test_fingerprints(cls.fams, cls.manifest, cls.records)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_dev_package_has_no_test_records_or_fingerprints(self):
        dev = self.out / DEV
        for p in dev.rglob('*.jsonl'):
            for line in p.read_text(encoding='utf-8').splitlines():
                self.assertNotEqual(json.loads(line).get('split'), 'test', p)
        test_family_ids = {f for f, s in self.manifest['family_split'].items() if s == 'test'}
        text = '\n'.join(p.read_text(encoding='utf-8', errors='replace') for p in dev.rglob('*') if p.is_file())
        self.assertFalse([f for f in test_family_ids if f in text])
        self.assertEqual(self.result['fingerprint_hits'], 0)
        self.assertFalse((dev / 'exports' / 'model_inputs' / 'test.jsonl').exists())

    def test_restricted_package_is_complete(self):
        rows = (self.out / RESTRICTED / 'labels' / 'test_labels.jsonl').read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(rows), 54)
        man = json.loads((self.out / DEV / 'manifest' / 'split_manifest.PUBLIC_VIEW.json').read_text(encoding='utf-8'))
        self.assertEqual(man['test']['cases'], 54)
        self.assertTrue(man['test']['identities'].startswith('withheld'))

    def test_guard_detects_injected_indirect_leak(self):
        dev = self.out / DEV
        test_tool = next(t for f in self.fams if self.manifest['family_split'][f['family_id']] == 'test'
                         for _, t in f['identities'])
        p = dev / 'notes.md'
        p.write_text(f'Remember to look at {test_tool} later.', encoding='utf-8')
        try:
            self.assertIn('notes.md', scan(dev, self.fps))
        finally:
            p.unlink()

    def test_builder_refuses_leaky_package(self):
        import sou13cp2.handoff as H
        original = H.DEV_README
        test_desc = next(d for f in self.fams if self.manifest['family_split'][f['family_id']] == 'test'
                         for d in f['descriptions'])
        H.DEV_README = original + '\n' + test_desc
        try:
            with tempfile.TemporaryDirectory() as tmp, self.assertRaises(HandoffError):
                build_packages(Path(tmp))
        finally:
            H.DEV_README = original


if __name__ == '__main__':
    unittest.main()
