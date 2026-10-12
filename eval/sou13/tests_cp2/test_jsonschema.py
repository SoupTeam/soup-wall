"""Draft 2020-12 JSON Schema regressions with the real jsonschema.Draft202012Validator."""
import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sou13cp2 import ROOT
from sou13cp2.records import load_cp1_records
from sou13cp2.schemas import CP1_FIXED_SCHEMA, CP1_ORIGINAL_SCHEMA, CP2_SCHEMA
from _util import base
from _testsupport import CP1_DATA, CP2_PUBLIC, requires


def _load(rel):
    return json.loads((Path(ROOT) / rel).read_text(encoding='utf-8'))


class SchemasAreValidDraft202012(unittest.TestCase):
    def test_check_schema(self):
        for rel in (CP2_SCHEMA, CP1_FIXED_SCHEMA, CP1_ORIGINAL_SCHEMA):
            Draft202012Validator.check_schema(_load(rel))

    def test_cp1_schema_file_untouched_and_fix_is_minimal(self):
        orig, fixed = _load(CP1_ORIGINAL_SCHEMA), _load(CP1_FIXED_SCHEMA)
        self.assertNotIn('properties', orig['$defs']['actions5'])  # CP1 file still carries the defect
        diff = copy.deepcopy(fixed)
        del diff['$defs']['actions5']['properties']
        for k in ('$id', 'title', 'description'):
            diff[k] = orig[k]
        self.assertEqual(diff, orig)  # the only semantic change is actions5.properties


@requires(CP1_DATA)
class DefectReproduction(unittest.TestCase):
    """Independent reproduction of the reviewer's finding on the unchanged CP1 records."""

    def setUp(self):
        self.raw = [r for _, r in load_cp1_records(ROOT)]

    def test_original_cp1_schema_rejects_18_of_19(self):
        v = Draft202012Validator(_load(CP1_ORIGINAL_SCHEMA))
        rejected = sorted(r['id'] for r in self.raw if not v.is_valid(r))
        self.assertEqual(len(self.raw), 19)
        self.assertEqual(len(rejected), 18)
        self.assertNotIn('S13V03-SUP-S2', rejected)  # null annotation: the only record that slipped through

    def test_fixed_cp1_schema_accepts_all_19(self):
        v = Draft202012Validator(_load(CP1_FIXED_SCHEMA))
        self.assertEqual([r['id'] for r in self.raw if not v.is_valid(r)], [])


@requires(CP1_DATA, CP2_PUBLIC)
class Cp2SchemaRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from sou13cp2.pipeline import assemble
        fams, manifest, cp1, new = assemble()
        cls.records = cp1 + new
        cls.v = Draft202012Validator(_load(CP2_SCHEMA))

    def rec(self, rid=None, kind=None):
        return copy.deepcopy(next(r for r in self.records if (rid is None or r['id'] == rid)
                                  and (kind is None or r['source_material']['kind'] == kind)))

    def assertRejected(self, r, needle=''):
        def walk(errors):  # include oneOf/allOf sub-errors (the specific reason lives in error.context)
            for e in errors:
                yield e.message
                yield from walk(e.context)
        msgs = list(walk(self.v.iter_errors(r)))
        self.assertTrue(msgs, 'mutant was accepted')
        if needle:
            self.assertTrue(any(needle in m for m in msgs), msgs)

    def test_every_record_valid(self):
        bad = {r['id']: [e.message for e in self.v.iter_errors(r)][:2] for r in self.records if not self.v.is_valid(r)}
        self.assertEqual(bad, {})
        kinds = {r['source_material']['kind'] for r in self.records}
        self.assertEqual(kinds, {'sou13_v03_cp1_record', 'cp1_record_revised', 'new_cp2_case'})

    def test_missing_required_action_field(self):
        for field in ('per_action_targets', 'known_mask', 'label_evidence'):
            r = self.rec('S13V03-DEV-01')
            r['annotation'][field].pop('send_data')
            self.assertRejected(r, "'send_data' is a required property")

    def test_invalid_known_mask_values(self):
        for bad in (2, '1', True, None, -1):
            r = self.rec(kind='new_cp2_case')
            r['annotation']['known_mask']['read'] = bad
            self.assertRejected(r)

    def test_invalid_label_evidence(self):
        mutations = [lambda e: e.pop('refs'), lambda e: e.update(refs=[]), lambda e: e.update(basis='vibes'),
                     lambda e: e.update(strength='strong'), lambda e: e.update(value='yes'),
                     lambda e: e.update(note='extra key')]
        for mutate in mutations:
            r = self.rec(kind='new_cp2_case')
            mutate(r['annotation']['label_evidence']['write'])
            self.assertRejected(r)

    def test_undeclared_action_names(self):
        for field, value in (('per_action_targets', True), ('known_mask', 1),
                             ('label_evidence', {'value': True, 'basis': 'controlled_execution_trace',
                                                 'strength': 'execution', 'refs': ['trace#1']})):
            r = self.rec('S13V03-DEV-02')
            r['annotation'][field]['exec'] = value
            self.assertRejected(r, "Additional properties are not allowed ('exec'")
        r = self.rec('S13V03-DEV-02')
        r['annotation']['contract_view']['actions'].append('exec')
        self.assertRejected(r)

    def test_unexpected_properties(self):
        for target in ('top', 'annotation', 'evaluation', 'technical_review', 'input', 'hashes'):
            r = self.rec('S13V03-DEV-06')
            {'top': r, 'annotation': r['annotation'], 'evaluation': r['evaluation'],
             'technical_review': r['technical_reviews'][0], 'input': r['input'], 'hashes': r['hashes']}[target]['x'] = 1
            self.assertRejected(r, 'Additional properties are not allowed')

    def test_cross_field_rules(self):
        r = self.rec('S13V03-SUP-S1')  # pending record cannot be in the pilot export
        r['evaluation']['in_pilot_export'] = True
        self.assertRejected(r)
        r = self.rec('S13V03-SUP-S3')  # set-valued oracle needs its accepted outputs
        del r['evaluation']['accepted_outputs']
        self.assertRejected(r, "'accepted_outputs' is a required property")
        r = self.rec('S13V03-DEV-09')  # admission test is never in semantic accuracy
        r['evaluation']['in_semantic_accuracy'] = True
        self.assertRejected(r)
        r = self.rec('S13V03-DEV-06')  # a technical review never confirms labels
        r['technical_reviews'][0]['confirms_labels'] = True
        self.assertRejected(r)
        r = self.rec(kind='new_cp2_case')
        r['evidence']['executed_real_tool'] = True
        self.assertRejected(r)


if __name__ == '__main__':
    unittest.main()
