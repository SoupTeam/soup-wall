"""Audit F1: case ids must not be predictable from (guessed) family ids. Regression attack + positive control."""
import json
import secrets
import shutil
import tempfile
import unittest
from pathlib import Path

from sou13cp2 import ROOT, restricted
from sou13cp2.case_ids import (ID_RE, MAP_KIND, PUBLIC_MAP, TEST_MAP, CaseIdError, allocate, case_id, key,
                               legacy_case_id, map_errors)
from sou13cp2.catalog import get_catalog
from _testsupport import CP2_PUBLIC, CP2_PUBLIC_VIEW, RESTRICTED_FAMILIES, requires


def _rows(rel):
    p = ROOT / rel
    return [json.loads(x) for x in p.read_text(encoding='utf-8').splitlines() if x] if p.exists() else []


def attack(ids, family_ids, max_index=50):
    """The original exploit: recompute sha256(family|i) for candidate families and match ids."""
    table = {legacy_case_id(f, i): f for f in family_ids for i in range(max_index)}
    return {i: table[i] for i in ids if i in table}


@requires(CP2_PUBLIC_VIEW)
class LegacyExploit(unittest.TestCase):
    def setUp(self):
        view = json.loads((ROOT / 'cp2/manifests/split_manifest.PUBLIC_VIEW.json').read_text(encoding='utf-8'))
        self.public_fams = sorted(view['family_split'])

    def test_positive_control_legacy_ids_are_fully_predictable(self):
        legacy_ids = {legacy_case_id(f, i): f for f, e in get_catalog().items() if f in self.public_fams
                      for i in range(e['n_new'])}
        mapped = attack(legacy_ids, self.public_fams)
        self.assertEqual(len(mapped), len(legacy_ids))  # 100 % of families recovered from ids alone
        self.assertTrue(all(mapped[i] == f for i, f in legacy_ids.items()))

    @requires(CP2_PUBLIC)
    def test_current_public_ids_resist_the_attack(self):
        ids = [r['id'] for r in _rows('cp2/data/candidates.jsonl')]
        ids += [r['id'] for s in ('train', 'validation', 'calibration')
                for r in _rows(f'cp2/exports/model_inputs/{s}.jsonl') if r['id'].startswith('S13C2-')]
        self.assertGreater(len(ids), 300)
        self.assertEqual(attack(ids, self.public_fams), {})
        self.assertTrue(all(ID_RE.match(i) for i in ids))  # 128-bit random ids

    @requires(RESTRICTED_FAMILIES, ('cp2_sealed/model_inputs_test.jsonl',))
    def test_test_ids_resist_even_a_perfect_family_dictionary(self):
        test_ids = [r['id'] for r in _rows('cp2_sealed/model_inputs_test.jsonl')]
        self.assertEqual(len(test_ids), 54)
        worst_case_dictionary = restricted.family_ids() + self.public_fams  # attacker guessed every true name
        self.assertEqual(attack(test_ids, worst_case_dictionary), {})


class PersistedMaps(unittest.TestCase):
    @requires(CP2_PUBLIC)
    def test_maps_valid_and_separated(self):
        self.assertEqual(map_errors(ROOT), [])
        public = json.loads((ROOT / PUBLIC_MAP).read_text(encoding='utf-8'))['ids']
        self.assertFalse(any(k.rsplit('|', 1)[0] in restricted.family_ids() for k in public))
        self.assertFalse(any(k.startswith(f) for k in public for f in restricted.family_ids()))

    def test_missing_id_is_an_error_not_a_silent_allocation(self):
        # Runs on a populated SYNTHETIC map in an isolated root. Without a map every lookup fails, so an absent
        # repository map would make this pass for the wrong reason; the positive control rules that out.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            present = 'S13C2-' + secrets.token_hex(16).upper()
            p = root / PUBLIC_MAP
            p.parent.mkdir(parents=True)
            p.write_text(json.dumps({'map_kind': MAP_KIND, 'note': 'TEST-ONLY synthetic map',
                                     'ids': {key('fam.read.http_get', 0): present}}), encoding='utf-8')
            before = p.read_bytes()
            self.assertFalse(restricted.available(root))
            self.assertEqual(case_id('fam.read.http_get', 0, root=root), present)  # lookup works
            with self.assertRaisesRegex(CaseIdError, r'no persisted case id for fam\.read\.http_get\|999'):
                case_id('fam.read.http_get', 999, root=root)
            self.assertEqual(p.read_bytes(), before)  # nothing allocated or written
            self.assertEqual(sorted(q.relative_to(root).as_posix() for q in root.rglob('*') if q.is_file()),
                             [PUBLIC_MAP])

    @requires(CP2_PUBLIC)
    def test_allocation_never_rewrites_existing_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            dst = Path(tmp) / PUBLIC_MAP
            dst.parent.mkdir(parents=True)
            shutil.copy(ROOT / PUBLIC_MAP, dst)
            before = json.loads(dst.read_text(encoding='utf-8'))['ids']
            keys = list(before) + [key('fam.read.http_get', 999)]
            self.assertEqual(allocate(keys, root=Path(tmp)), 1)
            after = json.loads(dst.read_text(encoding='utf-8'))['ids']
            self.assertEqual({k: after[k] for k in before}, before)
            self.assertTrue(ID_RE.match(after[key('fam.read.http_get', 999)]))

    @requires(CP2_PUBLIC)
    def test_legacy_id_in_map_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dst = Path(tmp) / PUBLIC_MAP
            dst.parent.mkdir(parents=True)
            data = json.loads((ROOT / PUBLIC_MAP).read_text(encoding='utf-8'))
            k = sorted(data['ids'])[0]
            fid, i = k.rsplit('|', 1)
            data['ids'][k] = legacy_case_id(fid, int(i))
            dst.write_text(json.dumps(data), encoding='utf-8')
            errors = map_errors(Path(tmp))
            self.assertTrue(any('predictable legacy id' in e for e in errors), errors)
            self.assertTrue(any('malformed id' in e for e in errors), errors)


if __name__ == '__main__':
    unittest.main()
