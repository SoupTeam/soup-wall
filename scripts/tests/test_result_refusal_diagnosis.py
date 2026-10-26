import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('diagnosis', Path(__file__).parents[1] / 'diagnose-result-refusals.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AttributionValidation(unittest.TestCase):
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
