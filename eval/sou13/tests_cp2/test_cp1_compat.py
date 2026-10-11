import json
import os
import unittest
from pathlib import Path

from sou13.build import ROOT as CP1_ROOT
from sou13.build import source_hashes
from sou13.hashing import file_sha
from sou13cp2 import ROOT
from sou13cp2.pipeline import rebuild_differences, validate
from sou13cp2.v02_analysis import analyse
from _testsupport import (CP1_DATA, CP1_FREEZE, CP1_REVIEW, CP2_PUBLIC, FULL_MANIFEST, OPEN_QUESTIONS, requires,
                          requires_owner_anchor, strict)

# Archived v0.2 pilot material is owner-local; there is deliberately no default path.
V02_DATA = Path(os.environ['SOU13_V02_DATA']) if os.environ.get('SOU13_V02_DATA') else None


@requires(CP1_FREEZE, CP1_DATA, CP1_REVIEW)
class Checkpoint1Untouched(unittest.TestCase):
    def test_cp1_artefacts_match_freeze(self):
        freeze = json.loads((ROOT / 'data' / 'freeze.json').read_text(encoding='utf-8'))
        for rel, digest in freeze['files_sha256'].items():
            self.assertEqual(file_sha(ROOT / rel), digest, rel)

    def test_no_file_added_or_changed_in_cp1_source_globs(self):
        freeze = json.loads((ROOT / 'data' / 'freeze.json').read_text(encoding='utf-8'))
        self.assertEqual(source_hashes(CP1_ROOT), freeze['source_sha256_lf_normalised'])


@requires(CP1_DATA, CP1_FREEZE, CP1_REVIEW, OPEN_QUESTIONS, CP2_PUBLIC)
class Cp2Pipeline(unittest.TestCase):
    def test_stored_artefacts_are_deterministic_rebuild(self):
        self.assertEqual(rebuild_differences(ROOT), [])

    @requires_owner_anchor()
    def test_validator_passes_including_cp1_validator(self):
        report = validate(ROOT, run_cp1=True)  # anchor configuration from the environment
        self.assertEqual(report['errors'], [])
        self.assertEqual(report['result'], 'PASS')
        self.assertEqual(report['cp1_validator'], 'PASS')
        self.assertTrue(report['frozen'])  # the full manifest is FROZEN (was asserted DRAFT before the freeze)
        self.assertEqual(report['trust_anchor'], 'verified against the pinned owner key')
        self.assertEqual(report['records']['confirmed'], 0)

    @requires(FULL_MANIFEST)
    def test_frozen_manifest_without_owner_anchor_fails(self):
        report = validate(ROOT, run_cp1=False, rebuild=False, anchor_cfg={})
        self.assertEqual(report['result'], 'FAIL')
        self.assertTrue(any('FROZEN manifest is not authenticated' in e for e in report['errors']), report['errors'])


@unittest.skipUnless(strict() or (V02_DATA and (V02_DATA / 'pilot_candidates.jsonl').exists()),
                     'PRIVATE ARTIFACT MISSING: v0.2 pilot data (set SOU13_V02_DATA)')
class V02SourceMaterial(unittest.TestCase):
    def test_v02_split_is_flagged_as_leaky(self):
        report = analyse(V02_DATA)
        self.assertEqual(report['records'], 288)
        self.assertIn('description', report['cross_split_links_by_edge'])
        self.assertGreater(report['computed_groups_spanning_splits'], 0)
        self.assertIn('NOT leakage-safe', report['verdict'])


if __name__ == '__main__':
    unittest.main()
