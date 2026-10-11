import json
import tempfile
import unittest
from pathlib import Path

from sou13cp2.exports import (LABEL_BEARING_KEYS, MODEL_INPUT_KEYS, SEALED_INPUTS, SEALED_NAME, ExportError,
                              export_errors, label_row, write_exports)
from _util import base, by_id, mutant
from _testsupport import CP1_DATA, RESTRICTED_FAMILIES, requires


def _rows(p):
    return [json.loads(x) for x in Path(p).read_text(encoding='utf-8').splitlines() if x.strip()]


# The isolation mutant is moved into a real 'test' family, which only the restricted taxonomy defines.
@requires(CP1_DATA, RESTRICTED_FAMILIES)
class LabelSeparatedExports(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base_dir = Path(self.tmp.name)
        self.out, self.sealed = base_dir / 'exports', base_dir / 'sealed'
        _, manifest, records = base()
        # one in-memory test-split mutant so isolation is exercised (not a dataset case)
        test_family = next(f for f, s in sorted(manifest['family_split'].items()) if s == 'test')
        self.test_rec = mutant(by_id(records, 'S13V03-DEV-12'), 'MUT-TEST-1', family=test_family, manifest=manifest,
                               input_changes={'raw_arguments': {'text': 'held out sentence'}})
        self.records = records + [self.test_rec]
        write_exports(self.records, self.out, self.sealed)

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_exports_pass(self):
        self.assertEqual(export_errors(self.out, self.sealed, self.records), [])

    def test_layout(self):
        self.assertFalse((self.out / 'labels' / 'test.jsonl').exists())
        self.assertFalse((self.out / 'model_inputs' / 'test.jsonl').exists())  # test inputs are custodian-only
        self.assertEqual([r['id'] for r in _rows(self.sealed / SEALED_NAME)], ['MUT-TEST-1'])
        for r in _rows(self.sealed / SEALED_INPUTS):
            self.assertEqual(sorted(r), sorted(MODEL_INPUT_KEYS))
            self.assertFalse(LABEL_BEARING_KEYS & set(r))
        m = json.loads((self.out / 'EXPORT_MANIFEST.json').read_text(encoding='utf-8'))
        self.assertNotIn('MUT-TEST-1', json.dumps(m))
        self.assertNotIn('test', m['record_counts'])

    def test_test_inputs_in_exports_detected(self):
        (self.out / 'model_inputs' / 'test.jsonl').write_bytes((self.sealed / SEALED_INPUTS).read_bytes())
        try:
            self.assertTrue(any('must not be exported' in e for e in export_errors(self.out, self.sealed, self.records)))
        finally:
            (self.out / 'model_inputs' / 'test.jsonl').unlink()

    def test_sealed_dir_inside_exports_refused(self):
        with self.assertRaises(ExportError):
            write_exports(self.records, self.out, self.out / 'sealed')

    def test_test_labels_copied_into_exports_detected(self):
        (self.out / 'labels' / 'test.jsonl').write_bytes((self.sealed / SEALED_NAME).read_bytes())
        (self.out / SEALED_NAME).write_bytes(b'')
        errors = export_errors(self.out, self.sealed, self.records)
        self.assertTrue(any('unexpected files' in e for e in errors), errors)
        self.assertTrue(any('inside the export directory' in e for e in errors), errors)

    def test_test_row_in_train_labels_detected(self):
        p = self.out / 'labels' / 'train.jsonl'
        p.write_text(p.read_text(encoding='utf-8') + json.dumps(label_row(self.test_rec)) + '\n', encoding='utf-8')
        errors = export_errors(self.out, self.sealed, self.records)
        self.assertTrue(any('is a test record' in e for e in errors), errors)
        self.assertTrue(any('digest mismatch' in e for e in errors), errors)

    def test_labels_leaking_into_model_inputs_detected(self):
        p = self.out / 'model_inputs' / 'train.jsonl'
        rows = _rows(p)
        rows[0]['annotation'] = {'unknown': False}
        rows[1]['family_id'] = 'fam.read.http_get'
        p.write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')
        errors = export_errors(self.out, self.sealed, self.records)
        self.assertEqual(sum('beyond the label-free view' in e for e in errors), 2, errors)

    def test_tampered_label_detected(self):
        p = self.out / 'labels' / 'train.jsonl'
        rows = _rows(p)
        rows[0]['unknown'] = not rows[0]['unknown']
        p.write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows), encoding='utf-8')
        self.assertTrue(any('does not match its record' in e for e in export_errors(self.out, self.sealed, self.records)))

    def test_missing_sealed_labels_detected(self):
        (self.sealed / SEALED_NAME).unlink()
        self.assertTrue(any('test_labels.jsonl is missing' in e
                            for e in export_errors(self.out, self.sealed, self.records)))


if __name__ == '__main__':
    unittest.main()
