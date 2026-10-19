"""The SOU-35 case schema reuses the CP2 label/input contract verbatim and differs only where intended."""
import json
import unittest

from _util import ROOT, toys

from sou35 import SOU13_ROOT, adapters, records

CP2 = json.loads((SOU13_ROOT / 'schema' / 'cp2_case.schema.json').read_text(encoding='utf-8'))
S35 = json.loads((ROOT / 'schema' / 'sou35_case.schema.json').read_text(encoding='utf-8'))
SHARED = ('input_profile', 'input', 'hashes', 'expected_outcome', 'technical_error', 'annotation',
          'technical_reviews', 'evaluation_group', 'scenario_tags', 'evidence_strength', 'open_questions', 'contract')


class SchemaCompatibility(unittest.TestCase):
    def test_shared_defs_identical(self):
        self.assertEqual(S35['$defs'], CP2['$defs'])

    def test_shared_subschemas_identical(self):
        for key in SHARED:
            with self.subTest(key=key):
                self.assertEqual(S35['properties'][key], CP2['properties'][key])

    def test_cp2_required_fields_kept(self):
        self.assertEqual(set(S35['required']) - set(CP2['required']), {'evidence_tier'})
        self.assertLessEqual(set(CP2['required']), set(S35['required']))

    def test_intended_differences(self):
        p = S35['properties']
        self.assertNotIn('confirmed', p['label_status']['enum'])
        self.assertEqual(p['evidence_tier']['properties']['human_semantic_approval'], {'const': None})
        self.assertEqual(p['evidence_tier']['properties']['inherited_decisions']['maxItems'], 0)
        self.assertEqual(p['exposure']['enum'], ['none', 'restricted_test', 'candidate_undetermined'])
        self.assertIn('multimode', p['family_id']['pattern'])
        self.assertTrue(p['id']['pattern'].startswith('^S35-'))

    def test_schemas_are_valid_draft_2020_12(self):
        import jsonschema
        jsonschema.Draft202012Validator.check_schema(S35)
        jsonschema.Draft202012Validator.check_schema(
            json.loads((ROOT / 'schema' / 'sou35_family.schema.json').read_text(encoding='utf-8')))

    def test_toy_records_validate_against_both_shared_parts(self):
        import jsonschema
        _, recs = toys()
        for r in recs:
            self.assertEqual(records.schema_errors(r), [])
            for key in ('input', 'hashes', 'annotation'):  # the shared parts also satisfy the CP2 subschemas
                sub = dict(CP2['properties'][key], **{'$defs': CP2['$defs']})
                jsonschema.Draft202012Validator(sub).validate(r[key])

    def test_contract_binding_matches_checkout(self):
        self.assertEqual(adapters.contract_errors(), [])


if __name__ == '__main__':
    unittest.main()
