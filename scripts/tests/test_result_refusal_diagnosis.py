import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('diagnosis', Path(__file__).parents[1] / 'diagnose-result-refusals.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AttributionValidation(unittest.TestCase):
    def test_roundtrip_is_not_custody_and_cannot_rename_paths(self):
        case = {'tool': 'read_multiple_files', 'arguments': {'paths': ['/tmp/sou123/ws/a', '/tmp/sou123/ws/b']}}
        payload = b'/tmp/sou123/ws/a:\none\n\n---\n/tmp/sou123/ws/b:\ntwo\n'
        recipe = MODULE.formatter_recipe(case, payload)
        self.assertEqual(recipe['status'], 'selected_namespace_mismatch')
        self.assertTrue(recipe['offline_formatter_roundtrip_equal'])
        self.assertFalse(recipe['original_returned_bytes_verified'])
        self.assertFalse(recipe['live_custody'])
        renamed = {'tool': case['tool'], 'arguments': {'paths': ['/workspace/a', '/workspace/b']}}
        self.assertEqual(MODULE.formatter_recipe(renamed, payload)['status'], 'formatter_bytes_mismatch')
        self.assertEqual(MODULE.formatter_recipe(case, payload + b'\n---\nextra')['status'], 'ambiguous_formatter_boundaries')
        self.assertEqual(MODULE.formatter_recipe(case, payload[:-1])['status'], 'formatter_bytes_mismatch')

    def test_frozen_inventory_retains_all_ten_refusals_without_inventing_custody(self):
        import json
        root = Path(__file__).resolve().parents[2]
        manifest = json.loads((root / 'eval/sou123/manifest.json').read_text(encoding='utf-8'))
        results = json.loads((root / 'docs/operations/evidence/sou157-02d3495a-policy-pairs/adapter.stdout.json').read_text(encoding='utf-8'))['results']
        mapped = MODULE.reproduction_map(manifest, results, root / 'eval/sou123/payloads')
        self.assertEqual(len(mapped['cases']), 51)
        refused = [r for r in mapped['cases'] if r['false_refusal']]
        self.assertEqual(len(refused), 10)
        self.assertEqual(sum(r['recipe']['status'] == 'different_tool_no_separator_correction' for r in refused), 8)
        self.assertEqual([r['case_id'] for r in refused if r['recipe']['status'] == 'selected_namespace_mismatch'], ['f05-a', 'f12-a'])
        self.assertFalse(any(r['eligible'] for r in mapped['cases']))
        self.assertEqual(mapped['live_executions'], 0)

    def test_rejects_duplicate_missing_and_foreign_results(self):
        manifest = {'cases': [{'case_id': 'a'}, {'case_id': 'b'}]}
        for ids in [('a', 'a'), ('a',), ('a', 'c')]:
            with self.assertRaises(ValueError):
                MODULE.validate_results(manifest, [{'case_id': i} for i in ids], Path('.'))

    def test_requires_real_utf8_byte_boundaries_and_complete_attribution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'a.txt').write_bytes('яx'.encode('utf-8'))
            manifest = {'cases': [{'case_id': 'a'}]}
            for finding in [{'label': 'missing span'}, {'span': None},
                            {'label': 'bad', 'span': {'start': 0, 'end': 4}},
                            {'label': 'bad', 'span': {'start': 1, 'end': 2}}]:
                with self.assertRaises((ValueError, UnicodeDecodeError)):
                    MODULE.validate_results(manifest, [{'case_id': 'a', 'findings': [finding]}], root)
            MODULE.validate_results(manifest, [{'case_id': 'a', 'findings': [
                {'label': 'actual', 'span': {'start': 0, 'end': 2}},
                {'label': 'aggregate', 'span': None}]}], root)


if __name__ == '__main__':
    unittest.main()
