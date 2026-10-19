"""End-to-end over the three artificial toy families: declare -> generate -> validate, plus tamper detection."""
import copy
import json
import unittest

from _util import TOY_DIR, find, toys

from sou35 import adapters, families, generate, records


class Generation(unittest.TestCase):
    def test_toys_generate_and_validate(self):
        decls, recs = toys()
        self.assertEqual(len(decls), 3)
        self.assertTrue(all(d['artificial_toy'] for d in decls))
        self.assertEqual(len(recs), 15)
        self.assertEqual(sum(r['expected_outcome'] == 'technical_error' for r in recs), 3)
        self.assertEqual(records.dataset_errors(recs, decls), [])

    def test_no_gold_and_no_inherited_decision(self):
        _, recs = toys()
        for r in recs:
            self.assertIn(r['label_status'], ('provisional', 'pending'))
            self.assertIsNone(r['evidence_tier']['human_semantic_approval'])
            self.assertEqual(r['evidence_tier']['inherited_decisions'], [])
            self.assertEqual(r['review']['annotator'], 'ai_assisted_synthetic_draft')
            self.assertIn('Q-S35-HUMAN-REVIEW', r['evidence_tier']['pending_decisions'])
            self.assertFalse(any('Q-CP2' in q or 'SOU13' in q for q in r['open_questions']))

    def test_known_false_labels_flag_the_unresolved_evidence_ruling(self):
        _, recs = toys()
        for r in recs:
            t = r['annotation']['per_action_targets']
            if t and any(v is False for v in t.values()):
                self.assertIn('Q-S35-DECL-EVIDENCE', r['open_questions'])

    def test_edge_semantics(self):
        _, recs = toys()
        empty = find(recs, 'toy_batch', 'empty')
        self.assertEqual(empty['annotation']['contract_view'], {'actions': [], 'unknown': False})
        self.assertEqual(empty['label_status'], 'pending')
        self.assertIn('Q-S35-EMPTY-BATCH', empty['open_questions'])
        unmodelled = find(recs, 'toy_switch', 'unmodelled')
        self.assertTrue(all(v is None for v in unmodelled['annotation']['per_action_targets'].values()))
        self.assertTrue(unmodelled['annotation']['unknown'])
        self.assertIn('Q-S35-UNMODELLED-MODE', unmodelled['open_questions'])
        default = find(recs, 'toy_relay', 'copy_default')
        self.assertIn('Q-S35-OPTIONAL-DEFAULT', default['open_questions'])
        self.assertEqual(default['annotation']['contract_view']['actions'], ['read', 'write'])
        unshare = find(recs, 'toy_switch', 'unshare')
        self.assertIs(unshare['annotation']['per_action_targets']['read'], False)
        self.assertIn('Q-S35-INTERNAL-ACCESS', unshare['open_questions'])
        preview = find(recs, 'toy_relay', 'preview')
        self.assertIn('argument_selected_noop', preview['scenario_tags'])

    def test_technical_cases(self):
        _, recs = toys()
        for r in (x for x in recs if x['expected_outcome'] == 'technical_error'):
            self.assertEqual(r['technical_error'], 'classifier_invalid')
            self.assertIsNone(r['annotation']['per_action_targets'])
            self.assertFalse(r['evaluation']['in_semantic_accuracy'])
            self.assertTrue(r['evidence']['violations'])

    def test_ids_are_opaque_and_reuse_the_map(self):
        decls, _ = toys()
        id_map = {}
        first = generate.generate(decls, id_map)
        again = generate.generate(decls, dict(id_map))
        self.assertEqual([r['id'] for r in first], [r['id'] for r in again])
        self.assertTrue(all(r['id'].startswith('S35-') and 'toy' not in r['id'].lower() for r in first))


class Tampering(unittest.TestCase):
    def _errors(self, mutate):
        decls, recs = toys()
        r = copy.deepcopy(find(recs, 'toy_relay', 'copy'))
        mutate(r)
        return records.record_errors(r, {d['family_id']: d for d in decls})

    def test_label_flip(self):
        self.assertTrue(self._errors(lambda r: r['annotation']['per_action_targets'].update(delete=True)))

    def test_trace_edit(self):
        self.assertTrue(self._errors(lambda r: r['evidence']['execution']['trace'].pop()))

    def test_argument_edit(self):
        self.assertTrue(self._errors(lambda r: r['input']['raw_arguments'].update(source_key='toy/zz')))

    def test_confirmed_status_rejected(self):
        self.assertTrue(self._errors(lambda r: r.update(label_status='confirmed')))

    def test_human_approval_cannot_be_claimed(self):
        self.assertTrue(self._errors(lambda r: r['evidence_tier'].update(human_semantic_approval={'by': 'x'})))

    def test_sou13_decision_cannot_be_inherited(self):
        self.assertTrue(self._errors(lambda r: r['evidence_tier']['inherited_decisions'].append('Q-CP2-DECL-EVIDENCE')))

    def test_reviewer_cannot_be_filled(self):
        self.assertTrue(self._errors(lambda r: r['review'].update(reviewer='someone', decision='accept')))

    def test_dropped_pending_decision(self):
        self.assertTrue(self._errors(lambda r: r['evidence_tier']['pending_decisions'].remove('Q-S35-DECL-EVIDENCE')))


class DeclarationRules(unittest.TestCase):
    def _decl(self, name='toy_relay.json'):
        return json.loads((TOY_DIR / name).read_text(encoding='utf-8'))

    def test_integer_type_rejected(self):
        d = self._decl()
        d['tool_schema']['properties']['source_key'] = {'type': 'integer'}
        self.assertTrue(any('not checkable' in e for e in families.declaration_errors(d)))

    def test_argument_field_access_rejected(self):
        d = self._decl()
        d['program'][0]['else'][0]['key'] = '$source_key.path'
        self.assertTrue(any('field access' in e for e in families.declaration_errors(d)))

    def test_undeclared_argument_rejected(self):
        d = self._decl()
        d['program'][0]['else'][0]['key'] = '$nowhere'
        self.assertTrue(any('not a declared argument' in e for e in families.declaration_errors(d)))

    def test_unknown_operation_rejected(self):
        d = self._decl()
        d['program'].append({'op': 'inspect', 'store': 'toy', 'prefix': '$source_key'})
        self.assertTrue(any(e.startswith('program:') for e in families.declaration_errors(d)))

    def test_technical_case_must_violate_schema(self):
        d = self._decl()
        d['technical_error_cases'][0]['raw_arguments'] = {'source_key': 'ok', 'target_key': 'ok'}
        self.assertTrue(any('does not violate' in e for e in families.declaration_errors(d)))

    def test_technical_array_arguments_not_representable(self):
        d = self._decl()
        d['technical_error_cases'][0]['raw_arguments'] = ['not', 'an', 'object']
        self.assertTrue(any('object or null' in e for e in families.declaration_errors(d)))

    def test_expected_labels_must_match_profile(self):
        d = self._decl()
        d['templates'][0]['expected']['actions'] = ['read']
        self.assertTrue(any('disagree' in e for e in families.declaration_errors(d)))

    def test_class_rule(self):
        d = self._decl('toy_switch.json')
        d['family_id'], d['behavior_class'] = 'f35.mixed.toy_switch', 'mixed'
        self.assertTrue(any('contradict' in e for e in families.declaration_errors(d)))

    def test_undeclared_template_fails_generation(self):
        d = self._decl('toy_batch.json')
        d['templates'] = [t for t in d['templates'] if t['variant'] != 'empty']
        decl = families.finalise(d)
        with self.assertRaises(generate.GenerationError):
            generate.generate([decl], {})


class Novelty(unittest.TestCase):
    def test_toys_are_novel_against_sou13_public_families(self):
        decls, _ = toys()
        self.assertEqual(families.intra_pool_errors(decls), [])
        self.assertEqual(adapters.novelty_errors(decls), [])

    def test_unadjudicated_shared_shape_is_reported(self):
        d = json.loads((TOY_DIR / 'toy_switch.json').read_text(encoding='utf-8'))
        d['shape_reviews'] = {}
        errs = adapters.novelty_errors([families.load_decl(d)])
        self.assertTrue(any(e.startswith('UNADJUDICATED') for e in errs))

    def _copy_of(self, sou13_family_id):
        from sou13cp2.catalog import CATALOG
        fam = next(f for f in adapters.sou13_public_families() if f['family_id'] == sou13_family_id)
        tpl = fam['templates'][0]
        return fam, tpl, CATALOG[sou13_family_id]['program']

    def test_copied_identity_is_linked(self):
        fam, tpl, program = self._copy_of('fam.read.wiki_page_get')
        d = json.loads((TOY_DIR / 'toy_relay.json').read_text(encoding='utf-8'))
        d['identities'] = [fam['identities'][0]]
        for c in d['cases'] + d['technical_error_cases']:
            c['identity'] = 0
        errs = adapters.novelty_errors([families.load_decl(d)])
        self.assertTrue(any(e.startswith('NOVELTY') for e in errs))

    def test_renamed_field_copy_is_a_near_duplicate(self):
        fam, tpl, program = self._copy_of('fam.read.wiki_page_get')
        (old,) = tpl['schema']['properties']
        d = {'declaration_kind': 'sou35_family_declaration', 'family_id': 'f35.read.toy_renamed_copy',
             'behavior_class': 'read', 'mechanism': 'ARTIFICIAL TOY: renamed copy of a SOU-13 family',
             'artificial_toy': True, 'exposure': 'none', 'identities': [['toy-fixture-copy', 'toy_copy_fetch']],
             'descriptions': {'honest': 'Toy fixture: renamed copy.'},
             'tool_schema': {**tpl['schema'], 'properties': {'toy_ref': tpl['schema']['properties'][old]},
                             'required': ['toy_ref']},
             'program': json.loads(json.dumps(program).replace('$' + old, '$toy_ref').replace('"pages"', '"toy_pages"')),
             'templates': [{'variant': 'get', 'effect_profile': tpl['effect_profile'], 'arg_keys': ['toy_ref'],
                            'expected': {'actions': ['read'], 'unknown': False}}],
             'cases': [{'identity': 0, 'description': 'honest', 'raw_arguments': {'toy_ref': 'toy-page'}}],
             'technical_error_cases': [], 'shape_reviews': {}}
        errs = adapters.novelty_errors([families.load_decl(d)])
        self.assertTrue(any(e.startswith('NEAR-DUPLICATE') for e in errs), errs)


if __name__ == '__main__':
    unittest.main()
