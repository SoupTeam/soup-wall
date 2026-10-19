"""Custody guard, adapter pins, and isolation from frozen SOU-13 sources."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from _util import ROOT, toys

from sou35 import SOU13_ROOT, adapters, guard


class Guard(unittest.TestCase):
    def test_trips_on_a_root_with_sealed_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'cp2_sealed').mkdir()
            with self.assertRaises(guard.CustodyError):
                guard.check(tmp)

    def test_passes_on_this_checkout(self):
        self.assertEqual(guard.sealed_paths_present(SOU13_ROOT), [])

    def test_sou13_restricted_loader_sees_nothing(self):
        from sou13cp2 import restricted
        self.assertFalse(restricted.available())


class AdapterPins(unittest.TestCase):
    def test_labels_from_execution_is_the_sou13_function(self):
        from sou13cp2.generate import labels_from_execution
        rec = adapters.execute([{'op': 'read', 'store': 'toy', 'key': '$k'},
                                {'op': 'opaque', 'component': 'toy-component'}], {'k': 'toy-key'})
        targets, unknown, ev = adapters.labels_from_execution(rec, 'x' * 64)
        self.assertEqual((targets, unknown, ev), labels_from_execution(rec, 'x' * 64))
        self.assertEqual(targets, {'read': True, 'write': None, 'delete': None, 'send_data': None,
                                   'change_permissions': None})
        self.assertTrue(unknown)

    def test_leakage_adapter_drops_placeholder_group(self):
        decls, _ = toys()
        item = adapters.leakage_item(adapters.to_leakage_family(decls[0]))
        self.assertNotIn(('leakage_group', None), item['features'])
        self.assertIn(('family', decls[0]['family_id']), item['features'])

    def test_splits_assign_rejects_multimode(self):
        """Documents why SOU-35 does not call splits.assign (frozen class tuples)."""
        splits = adapters.splits_module()
        fam = {'family_id': 'f35.multimode.toy_x', 'exposure': 'none', 'behavior_class': 'multimode',
               'coverage_stratum': 'multimode', 'coverage_eligible': True, 'planned_cases': 1,
               'alias_group_id': 'ag35.toy_x', 'identities': [['toy-fixture-x', 'toy_x']], 'normalized_names': ['toy x'],
               'descriptions': [], 'templates': []}
        with self.assertRaises(ValueError):
            splits.assign([fam])

    def test_interpreter_digests_match_frozen_pins(self):
        import sys
        sys.path.insert(0, str(SOU13_ROOT / 'tests_cp2'))
        from test_freeze_inventory import CP2_DEV_PACKAGE_RAW
        from sou13.hashing import file_sha
        for rel in ('sou13cp2/semantics.py', 'sou13cp2/compute.py'):
            self.assertEqual(file_sha(SOU13_ROOT / rel), CP2_DEV_PACKAGE_RAW[rel][1])


class Isolation(unittest.TestCase):
    def _git(self, *args):
        return subprocess.run(['git', *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout

    def test_no_sou13_file_modified_or_added(self):
        self.assertEqual(self._git('status', '--porcelain', '--', str(SOU13_ROOT)).strip(), '')

    def test_private_workspace_is_ignored(self):
        for rel in ('private/pool/x.json', 'sealed/x.json', 'data/x.jsonl'):
            out = subprocess.run(['git', 'check-ignore', '-q', str(ROOT / rel)], cwd=ROOT)
            self.assertEqual(out.returncode, 0, rel)

    def test_no_dataset_family_in_public_tree(self):
        for p in ROOT.rglob('*.json'):
            if 'private' in p.parts or 'sealed' in p.parts:
                continue
            doc = json.loads(p.read_text(encoding='utf-8'))
            if isinstance(doc, dict) and doc.get('declaration_kind') == 'sou35_family_declaration':
                self.assertIs(doc.get('artificial_toy'), True, p)
                self.assertIn('.toy_', doc['family_id'], p)


if __name__ == '__main__':
    unittest.main()
