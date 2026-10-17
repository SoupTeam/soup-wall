"""Custody -> manifest -> freeze -> development export, on ARTIFICIAL toy families only.

Positive paths use the three toy declarations plus one more toy defined here; negative paths cover tampered
manifests, cross-split leakage, unfrozen exports, missing approvals, private-test exposure, malformed commitments and
invalid custody transitions. Nothing here touches the private candidate pool."""
import copy
import json
import shutil
import unittest
import uuid

from _util import ROOT, TOY_DIR

from sou35 import check_pool, custody, export, families, feasibility, generate, rulings
from sou35 import manifest as M

SEED = 'ab' * 32
OTHER_SEED = 'cd' * 32
REQ = feasibility.default_requirements({'technical_error'})  # toy pools cannot meet the full requirement set
COUNTS = {'train': 1, 'validation': 1, 'calibration': 1, 'test': 1}
APPROVAL = dict(approved_by='toy-approver', approved_at='2026-10-16T00:00:00Z', decision_ref='TOY-DECISION-1')
TOY_VAULT = {
    'declaration_kind': 'sou35_family_declaration', 'family_id': 'f35.multimode.toy_vault', 'behavior_class': 'multimode',
    'mechanism': 'ARTIFICIAL TOY (not a dataset family): read one toy slot to keep it, or discard it',
    'artificial_toy': True, 'exposure': 'none',
    'identities': [['toy-fixture-delta', 'toy_delta_vault'], ['toy-fixture-delta-mirror', 'toy_delta_vault']],
    'descriptions': {'honest': 'Toy fixture: read a toy slot when keeping it, otherwise discard it.',
                     'misleading': 'Toy fixture: reports the toy slot size.'},
    'tool_schema': {'type': 'object', 'properties': {'box': {'type': 'string'}, 'slot': {'type': 'string'},
                                                     'keep': {'type': 'boolean'}},
                    'required': ['box', 'slot', 'keep'], 'additionalProperties': False},
    'program': [{'op': 'when', 'arg': 'keep', 'equals': True,
                 'then': [{'op': 'read', 'store': 'toy_box', 'key': ['$box', '/', '$slot']}],
                 'else': [{'op': 'delete', 'store': 'toy_box', 'key': ['$box', '/', '$slot']}]}],
    'templates': [{'variant': 'keep', 'effect_profile': ['store_read'], 'arg_keys': ['box', 'keep', 'slot'],
                   'expected': {'actions': ['read'], 'unknown': False}},
                  {'variant': 'discard', 'effect_profile': ['store_delete'], 'arg_keys': ['box', 'keep', 'slot'],
                   'expected': {'actions': ['delete'], 'unknown': False}}],
    'cases': [{'identity': 0, 'description': 'honest', 'raw_arguments': {'box': 'b1', 'slot': 's1', 'keep': True}},
              {'identity': 1, 'description': 'null', 'raw_arguments': {'box': 'b1', 'slot': 's2', 'keep': False}},
              {'identity': 0, 'description': 'misleading', 'raw_arguments': {'box': 'b2', 'slot': 's3', 'keep': False}}],
    'technical_error_cases': [{'identity': 0, 'description': 'honest', 'raw_arguments': {'box': 'b1', 'slot': 's1'}}],
    'shape_reviews': {}}


def relay_copy():
    """Same tool behaviour as toy_relay re-admitted under other identities: linked through template signatures."""
    d = json.loads((TOY_DIR / 'toy_relay.json').read_text(encoding='utf-8'))
    d['family_id'] = 'f35.mixed.toy_relay_copy'
    d['identities'] = [['toy-fixture-epsilon', 'toy_epsilon_copy'], ['toy-fixture-epsilon-2', 'toy_epsilon_copy']]
    d['descriptions'] = {'honest': 'Toy fixture: a re-admitted copy of the toy relay.', 'misleading': 'Toy fixture: idle.'}
    return d


def pool(extra=()):
    decls = families.load_dir(TOY_DIR) + [families.load_decl(TOY_VAULT)] + [families.load_decl(d) for d in extra]
    recs = generate.generate(decls, {})
    return decls, recs, feasibility.group_table(recs), M._groups(recs)


def _row_digest(row):
    from sou35 import adapters
    return adapters.sha(row)


def rulings_for(decls, recs=None, *, rejected=(), bases=None, statuses=None):
    """Artificial toy v2 ledger; NOT approvals for real cases. Classification rows default to an
    `interface_supported` basis (the mechanical ceiling still applies); `bases`/`statuses` map case id -> override."""
    if recs is None:
        recs = generate.generate(decls, {})
    bases, statuses = bases or {}, statuses or {}
    questions = sorted({q for r in recs for q in r['open_questions']})

    def case(r):
        technical = r['expected_outcome'] == 'technical_error'
        return {'id': r['id'], 'row_sha256': _row_digest(r), 'status': statuses.get(r['id'], 'accepted'),
                'evidence_basis': None if technical else bases.get(r['id'], 'interface_supported'),
                'reviewed_by': 'toy-human-reviewer', 'reviewer_kind': 'human', 'independent_of_generation': True,
                'reviewed_at': '2026-10-16T01:00:00Z', 'decision_ref': 'TOY-CASE-REVIEW',
                'questions_considered': list(r['open_questions']), 'ai_technical_review_refs': []}
    return {'version': rulings.VERSION_V2, 'scope': rulings.SCOPE,
            'pool_digest': custody.pool_digest(decls),
            'record_inventory_sha256': M.record_inventory_digest(recs),
            'eligibility_policy': rulings.ELIGIBILITY_POLICY,
            'decisions': [{'question_id': q, 'status': 'rejected' if q in rejected else 'accepted',
                           'reviewed_by': 'toy-human-reviewer', 'reviewer_kind': 'human',
                           'reviewed_at': '2026-10-16T01:00:00Z',
                           'decision_ref': 'TOY-EXTERNAL-DECISION'} for q in questions],
            'reviewed_cases': [case(r) for r in recs]}


def ledger_for(decls, recs, **kw):
    """The validated toy ledger (rulings.load) that every stratum-level API requires."""
    return rulings.load(rulings_for(decls, recs, **kw), decls, recs)


def rulings_v1_for(decls, recs=None, *, rejected=()):
    """The preserved v1 toy register shape (no evidence basis); NOT approvals for real cases."""
    if recs is None:
        recs = generate.generate(decls, {})
    questions = sorted({q for r in recs for q in r['open_questions']})
    return {'version': rulings.VERSION_V1, 'scope': rulings.SCOPE,
            'pool_digest': custody.pool_digest(decls),
            'decisions': [{'question_id': q, 'status': 'rejected' if q in rejected else 'accepted',
                           'reviewed_by': 'toy-human-reviewer', 'reviewed_at': '2026-10-16T01:00:00Z',
                           'decision_ref': 'TOY-EXTERNAL-DECISION'} for q in questions],
            'reviewed_cases': [{'id': r['id'], 'row_sha256': _row_digest(r), 'status': 'accepted',
                                'reviewed_by': 'toy-human-reviewer', 'reviewed_at': '2026-10-16T01:00:00Z',
                                'decision_ref': 'TOY-CASE-REVIEW'} for r in recs]}


def proof(priv, decls, recs):
    return {'test_families': priv['test_families'], 'nonce': priv['nonce'],
            'rulings_register': rulings_for(decls, recs)}


TOY_TOOLING = {'tooling_commit': '2' * 40, 'tooling_source_dirty': False, 'note': 'toy export tooling'}


def toy_provenance(decls, recs, **over):
    """Artificial ORIGINAL generation provenance; deliberately differs from the toy export tooling commit."""
    g = {'generator_version': recs[0]['source_material']['generator'], 'source_commit': '1' * 40,
         'command': 'python -m sou35.check_pool --pool <toy> --out <toy>', 'generated_at': '2026-10-15T00:00:00Z',
         'recorded_by': 'toy-owner', 'pool_digest': custody.pool_digest(decls),
         'record_inventory_sha256': M.record_inventory_digest(recs), **over}
    return {'provenance_version': export.PROVENANCE_VERSION, 'original_generation': g}


def export_extra(decls, recs):
    return {'generation_provenance': toy_provenance(decls, recs), 'export_tooling': dict(TOY_TOOLING)}


def export_proof(priv, decls, recs):
    return {**proof(priv, decls, recs), **export_extra(decls, recs)}


def drawn(decls, table, groups, counts=COUNTS, req=REQ, seed=SEED, recs=None):
    st = custody.declare(decls, 'toy-custodian', req, counts)
    st, _ = custody.commit(st, table, req, counts, seed, rulings_sha256=rulings.digest(rulings_for(decls, recs)), test_exclusions=())
    return custody.draw(st, table, req, counts, seed, groups, test_exclusions=())


def accepted(st):
    return custody.accept(st, custodian='toy-custodian', accepted_at='2026-10-16T01:00:00Z', decision_ref='TOY-CUSTODY-1')


def frozen_setup():
    decls, recs, table, groups = pool()
    st, priv = drawn(decls, table, groups, recs=recs)
    st = accepted(st)
    draft = M.build_draft(decls, recs, st, priv['test_families'], priv['nonce'], COUNTS, REQ, 'toy-salt', rulings_register=rulings_for(decls, recs))
    m = M.freeze(draft, decls, recs, st, priv['test_families'], priv['nonce'], rulings_register=rulings_for(decls, recs), **APPROVAL)
    auth = {'scope': export.EXPORT_SCOPE, 'authorized_by': 'toy-authorizer', 'authorized_at': '2026-10-16T02:00:00Z',
            'decision_ref': 'TOY-EXPORT-1', 'manifest_sha256': m['manifest_sha256'],
            'rulings_sha256': m['rulings_sha256']}
    return decls, recs, st, priv, m, auth


def resign(m):
    body = {k: v for k, v in m.items() if k != 'manifest_sha256'}
    from sou35 import adapters
    return {**body, 'manifest_sha256': adapters.sha(body)}


class Custody(unittest.TestCase):
    def test_lifecycle_and_public_states(self):
        decls, recs, table, groups = pool()
        st = custody.declare(decls, 'toy-custodian', REQ, COUNTS)
        self.assertEqual(custody.public_state_errors(st), [])
        st, private = custody.commit(st, table, REQ, COUNTS, SEED, rulings_sha256=rulings.digest(rulings_for(decls, recs)), test_exclusions=())
        self.assertEqual(custody.public_state_errors(st), [])
        self.assertNotIn(SEED, json.dumps(st))
        st, private = custody.draw(st, table, REQ, COUNTS, SEED, groups, test_exclusions=())
        self.assertEqual(custody.public_state_errors(st), [])
        for f in private['test_families']:
            self.assertNotIn(f, json.dumps(st))
        self.assertTrue(custody.verify_test_set(st, private['test_families'], private['nonce']))
        self.assertFalse(custody.verify_test_set(st, ['f35.write.toy_batch_x'], private['nonce']))
        st = accepted(st)
        self.assertEqual(st['state'], 'custody_accepted')
        self.assertEqual(custody.public_state_errors(st), [])

    def test_draw_is_deterministic_for_a_seed(self):
        decls, recs, table, groups = pool()
        self.assertEqual(drawn(decls, table, groups, recs=recs)[1], drawn(decls, table, groups, recs=recs)[1])

    def test_invalid_transitions(self):
        decls, recs, table, groups = pool()
        st = custody.declare(decls, 'toy-custodian', REQ, COUNTS)
        with self.assertRaises(custody.CustodyError):
            custody.draw(st, table, REQ, COUNTS, SEED, groups, test_exclusions=())       # draw before commit
        with self.assertRaises(custody.CustodyError):
            accepted(st)                                              # accept before draw
        committed, _ = custody.commit(st, table, REQ, COUNTS, SEED, rulings_sha256=rulings.digest(rulings_for(decls, recs)), test_exclusions=())
        with self.assertRaises(custody.CustodyError):
            custody.commit(committed, table, REQ, COUNTS, SEED, rulings_sha256=rulings.digest(rulings_for(decls, recs)), test_exclusions=())      # commit twice
        done, _ = custody.draw(committed, table, REQ, COUNTS, SEED, groups, test_exclusions=())
        with self.assertRaises(custody.CustodyError):
            custody.draw(done, table, REQ, COUNTS, SEED, groups, test_exclusions=())     # draw twice
        with self.assertRaises(custody.CustodyError):
            custody.accept(done, custodian='someone-else', accepted_at='t', decision_ref='r')
        with self.assertRaises(custody.CustodyError):
            custody.accept(done, custodian='toy-custodian', accepted_at='', decision_ref='r')
        with self.assertRaises(custody.CustodyError):
            custody.declare(decls, '  ', REQ, COUNTS)                 # unnamed custodian

    def test_malformed_and_wrong_commitments(self):
        decls, recs, table, groups = pool()
        st = custody.declare(decls, 'toy-custodian', REQ, COUNTS)
        for bad in ('xyz', SEED.upper(), SEED[:-2], 7):
            with self.assertRaises(custody.CustodyError):
                custody.commit(st, table, REQ, COUNTS, bad, rulings_sha256=rulings.digest(rulings_for(decls, recs)), test_exclusions=())
        committed, _ = custody.commit(st, table, REQ, COUNTS, SEED, rulings_sha256=rulings.digest(rulings_for(decls, recs)), test_exclusions=())
        with self.assertRaises(custody.CustodyError):
            custody.draw(committed, table, REQ, COUNTS, OTHER_SEED, groups, test_exclusions=())  # seed does not open the commitment
        tampered = dict(committed, commitment='not-a-digest')
        self.assertTrue(custody.public_state_errors(tampered))
        with self.assertRaises(custody.CustodyError):
            custody.draw(tampered, table, REQ, COUNTS, SEED, groups, test_exclusions=())
        leaky = dict(committed, seed=SEED)
        self.assertTrue(any('private material' in e for e in custody.public_state_errors(leaky)))
        smaller = {g: v for g, v in table.items() if g != sorted(table)[0]}
        with self.assertRaises(custody.CustodyError):
            custody.draw(committed, smaller, REQ, COUNTS, SEED, groups, test_exclusions=())      # pool changed after commitment
        with self.assertRaises(custody.CustodyError):
            custody.commit(st, table, REQ, dict(COUNTS, train=2), SEED, rulings_sha256=rulings.digest(rulings_for(decls, recs)), test_exclusions=())       # rule differs from the declaration

    def test_impossible_requirements_are_not_relaxed(self):
        decls, recs, table, _ = pool()
        full = feasibility.default_requirements()
        st = custody.declare(decls, 'toy-custodian', full, COUNTS)
        with self.assertRaisesRegex(custody.CustodyError, 'IMPOSSIBLE'):
            custody.commit(st, table, full, COUNTS, SEED, rulings_sha256=rulings.digest(rulings_for(decls, recs)), test_exclusions=())


class Manifest(unittest.TestCase):
    def test_draft_is_valid_deterministic_and_bound_to_custody(self):
        decls, recs, table, groups = pool()
        st, priv = drawn(decls, table, groups, recs=recs)
        m1 = M.build_draft(decls, recs, st, priv['test_families'], priv['nonce'], COUNTS, REQ, 'toy-salt', rulings_register=rulings_for(decls, recs))
        m2 = M.build_draft(decls, recs, st, priv['test_families'], priv['nonce'], COUNTS, REQ, 'toy-salt', rulings_register=rulings_for(decls, recs))
        self.assertEqual(m1, m2)
        self.assertEqual(M.manifest_errors(m1, decls, recs, st, **proof(priv, decls, recs)), [])
        self.assertEqual(sorted(f for f, s in m1['family_split'].items() if s == 'test'), priv['test_families'])
        self.assertEqual(m1['requirements_profile'], 'custom')  # a reduced requirement set is never silent
        with self.assertRaises(M.ManifestError):
            M.build_draft(decls, recs, st, ['f35.write.toy_batch'] if priv['test_families'] != ['f35.write.toy_batch']
                          else ['f35.mixed.toy_relay'], priv['nonce'], COUNTS, REQ, 'toy-salt', rulings_register=rulings_for(decls, recs))

    def test_tampered_manifests(self):
        decls, recs, st, priv, m, _ = frozen_setup()
        self.assertEqual(M.manifest_errors(m, decls, recs, st, **proof(priv, decls, recs)), [])
        unsigned = copy.deepcopy(m)
        unsigned['salt'] = 'other'
        self.assertTrue(any('tampered' in e for e in M.manifest_errors(unsigned, decls, recs, st)))
        dev = [f for f, s in m['family_split'].items() if s != 'test']
        moved = copy.deepcopy(m)
        moved['family_split'][dev[0]], moved['family_split'][dev[1]] = m['family_split'][dev[1]], m['family_split'][dev[0]]
        self.assertTrue(any('changed after freeze' in e for e in M.manifest_errors(resign(moved), decls, recs, st)))
        swapped_test = copy.deepcopy(m)
        t = priv['test_families'][0]
        swapped_test['family_split'][t], swapped_test['family_split'][dev[0]] = 'train', 'test'
        self.assertTrue(any('committed custody draw' in e for e in
                            M.manifest_errors(resign(swapped_test), decls, recs, st, **proof(priv, decls, recs))))
        other_custody = dict(st, commitment='0' * 64)
        self.assertTrue(any('bound' in e for e in M.manifest_errors(m, decls, recs, other_custody)))

    def test_cross_split_leakage_rejected(self):
        decls, recs, table, groups = pool(extra=[relay_copy()])
        linked = groups[next(g for g, fs in groups.items() if 'f35.mixed.toy_relay_copy' in fs)]
        self.assertEqual(linked, ['f35.mixed.toy_relay', 'f35.mixed.toy_relay_copy'])
        counts = {'train': 2, 'validation': 1, 'calibration': 1, 'test': 1}
        st, priv = drawn(decls, table, groups, counts=counts, recs=recs)
        m = M.build_draft(decls, recs, st, priv['test_families'], priv['nonce'], counts, REQ, 'toy-salt', rulings_register=rulings_for(decls, recs))
        self.assertEqual(M.manifest_errors(m, decls, recs, st, **proof(priv, decls, recs)), [])
        self.assertEqual(m['family_split']['f35.mixed.toy_relay'], m['family_split']['f35.mixed.toy_relay_copy'])
        leak = copy.deepcopy(m)
        other = next(f for f, s in m['family_split'].items() if s == 'validation')
        leak['family_split']['f35.mixed.toy_relay_copy'], leak['family_split'][other] = 'validation', \
            m['family_split']['f35.mixed.toy_relay_copy']
        errs = M.manifest_errors(resign(leak), decls, recs, st)
        self.assertTrue(any('split across' in e for e in errs))
        self.assertTrue(any(e.startswith('LEAK') for e in errs))

    def test_freeze_requires_approval_and_accepted_custody(self):
        decls, recs, table, groups = pool()
        st, priv = drawn(decls, table, groups, recs=recs)
        draft = M.build_draft(decls, recs, st, priv['test_families'], priv['nonce'], COUNTS, REQ, 'toy-salt', rulings_register=rulings_for(decls, recs))
        args = (draft, decls, recs)
        with self.assertRaisesRegex(M.ManifestError, 'custody must be accepted'):
            M.freeze(*args, st, priv['test_families'], priv['nonce'], rulings_register=rulings_for(decls, recs), **APPROVAL)
        ok = accepted(st)
        for missing in ('approved_by', 'approved_at', 'decision_ref'):
            with self.assertRaises(M.ManifestError):
                M.freeze(*args, ok, priv['test_families'], priv['nonce'], rulings_register=rulings_for(decls, recs), **dict(APPROVAL, **{missing: ''}))
        with self.assertRaisesRegex(M.ManifestError, 'AI-assisted annotator'):
            M.freeze(*args, ok, priv['test_families'], priv['nonce'],
                     rulings_register=rulings_for(decls, recs),
                     **dict(APPROVAL, approved_by='ai_assisted_synthetic_draft'))
        frozen = M.freeze(*args, ok, priv['test_families'], priv['nonce'], rulings_register=rulings_for(decls, recs), **APPROVAL)
        with self.assertRaises(M.ManifestError):
            M.freeze(frozen, decls, recs, ok, priv['test_families'], priv['nonce'], rulings_register=rulings_for(decls, recs), **APPROVAL)  # no re-freeze

    def test_public_view_withholds_test_material(self):
        decls, recs, st, priv, m, _ = frozen_setup()
        view = M.public_view(m, decls, recs, st, **proof(priv, decls, recs))
        test_tokens = list(priv['test_families'])
        for d in decls:
            if d['family_id'] in priv['test_families']:
                test_tokens += [x for ident in d['identities'] for x in ident] + [d['descriptions']['honest']]
        test_tokens += [priv['nonce'], SEED]
        self.assertEqual(M.public_view_errors(view, forbidden=test_tokens), [])
        self.assertEqual(view['test']['families'], 1)
        exposed = resign(dict(view, family_split=dict(view['family_split'], **{priv['test_families'][0]: 'test'})))
        self.assertTrue(M.public_view_errors(exposed))
        named = resign(dict(view, note=priv['test_families'][0]))
        self.assertTrue(any('restricted' in e for e in M.public_view_errors(named, forbidden=test_tokens)))


class DevelopmentExport(unittest.TestCase):
    def setUp(self):
        self.private_existed = (ROOT / 'private').exists()
        self.out = ROOT / 'private' / f'_test_export_{uuid.uuid4().hex}'

    def tearDown(self):
        if self.out.exists():
            shutil.rmtree(self.out)
        if not self.private_existed and (ROOT / 'private').exists() and not any((ROOT / 'private').iterdir()):
            (ROOT / 'private').rmdir()  # leave a public checkout exactly as it was

    def test_export_is_gated_deterministic_and_excludes_test(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        summary = export.write_export(recs, decls, m, st, auth, self.out, **export_proof(priv, decls, recs))
        test_ids = [r['id'] for r in recs if r['family_id'] in priv['test_families']]
        self.assertTrue(test_ids)
        self.assertEqual(export.verify_export(self.out, test_ids), [])
        dev_records = sum(r['family_id'] not in priv['test_families'] for r in recs)
        self.assertEqual(sum(c['scored'] + c['not_scored'] for c in summary['record_counts'].values()), dev_records)
        self.assertEqual(sum(sum(c['by_stratum'].values()) for c in summary['record_counts'].values()), dev_records)
        # Regression: strata are computed on the stored record, so reviewed primary rows are actually exported.
        self.assertGreater(sum(c['scored'] for c in summary['record_counts'].values()), 0)
        labels = [json.loads(line) for p in (self.out / 'labels').glob('*.jsonl')
                  for line in p.read_text(encoding='utf-8').splitlines()]
        self.assertEqual({x['id'] for x in labels}, set(summary['case_reviews']))
        again = export.plan_export(recs, decls, m, st, auth, **export_proof(priv, decls, recs))
        for rel, data in again.items():
            self.assertEqual((self.out / rel).read_bytes(), data, rel)
        text = ''.join(p.read_text(encoding='utf-8') for p in self.out.rglob('*') if p.is_file())
        for f in priv['test_families']:
            self.assertNotIn(f, text)

    def test_unfrozen_manifest_refused(self):
        decls, recs, table, groups = pool()
        st, priv = drawn(decls, table, groups, recs=recs)
        draft = M.build_draft(decls, recs, st, priv['test_families'], priv['nonce'], COUNTS, REQ, 'toy-salt', rulings_register=rulings_for(decls, recs))
        auth = {'scope': export.EXPORT_SCOPE, 'authorized_by': 'x', 'authorized_at': 't', 'decision_ref': 'r',
                'manifest_sha256': draft['manifest_sha256'], 'rulings_sha256': draft['rulings_sha256']}
        with self.assertRaisesRegex(export.ExportError, 'FROZEN'):
            export.plan_export(recs, decls, draft, accepted(st), auth, **export_proof(priv, decls, recs))

    def test_authorization_required_and_bound(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        for bad in (None, {}, dict(auth, decision_ref=''), dict(auth, scope='publish'),
                    dict(auth, manifest_sha256='0' * 64), dict(auth, authorized_by='ai_assisted_synthetic_draft')):
            with self.subTest(bad=bad), self.assertRaises(export.ExportError):
                export.plan_export(recs, decls, m, st, bad, **export_proof(priv, decls, recs))

    def test_tampered_or_unaccepted_inputs_refused(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        tampered = copy.deepcopy(m)
        tampered['counts']['train'] = 9
        with self.assertRaises(export.ExportError):
            export.plan_export(recs, decls, tampered, st, auth, **export_proof(priv, decls, recs))
        drawn_only = {k: v for k, v in st.items() if k != 'acceptance'}
        drawn_only['state'] = 'drawn'
        with self.assertRaises(export.ExportError):
            export.plan_export(recs, decls, m, drawn_only, auth, **export_proof(priv, decls, recs))
        changed = copy.deepcopy(decls)
        changed[0]['descriptions'] = dict(changed[0]['descriptions'], honest='Toy fixture: re-described.')
        with self.assertRaises(export.ExportError):
            export.plan_export(recs, changed, m, st, auth, **export_proof(priv, decls, recs))

    def test_output_must_be_ignored_private_path(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        with self.assertRaises(check_pool.PrivacyError):
            export.write_export(recs, decls, m, st, auth, ROOT / 'tests' / 'export_out', **export_proof(priv, decls, recs))
        self.assertFalse((ROOT / 'tests' / 'export_out').exists())


class ReleaseSafeguardRegressions(unittest.TestCase):
    """Adversarial toy-only checks for P0-A/B/C; no private SOU-35 records used."""

    def test_reject_incomplete_case_set_and_misclassified_technical_row(self):
        from sou35 import records as record_validation
        decls, recs, _, _ = pool()
        duplicate = copy.deepcopy(recs)
        one = next(r for r in duplicate if r['expected_outcome'] == 'classification')
        other = next(r for r in duplicate if r['expected_outcome'] == 'classification'
                     and r['family_id'] == one['family_id'] and r['id'] != one['id'])
        other['source_material']['case_index'] = one['source_material']['case_index']
        self.assertTrue(any('duplicate declared case index' in err for err in
                            record_validation.dataset_errors(duplicate, decls)))
        missing = copy.deepcopy(recs[:-1])
        self.assertTrue(any('complete bijection' in err for err in
                            record_validation.dataset_errors(missing, decls)))
        bad_outcome = copy.deepcopy(recs)
        technical = next(r for r in bad_outcome if r['expected_outcome'] == 'technical_error')
        technical['expected_outcome'] = 'classification'
        self.assertTrue(record_validation.dataset_errors(bad_outcome, decls))

    def test_rulings_are_pool_bound_and_unapproved_cases_are_not_scored(self):
        decls, recs, table, groups = pool()
        register = rulings_for(decls, recs)
        self.assertEqual(rulings.errors(register, decls, recs), [])
        self.assertTrue(all(rulings.is_admissible(r, register) for r in recs))
        question = next(q for d in register['decisions'] for q in [d['question_id']])
        pending = copy.deepcopy(register)
        next(d for d in pending['decisions'] if d['question_id'] == question)['status'] = 'pending'
        affected = [r for r in recs if question in r['open_questions']]
        self.assertTrue(affected)
        self.assertTrue(all(not export.scored(r, rulings.load(pending, decls, recs)) for r in affected))
        removed = copy.deepcopy(register)
        removed['decisions'] = [d for d in removed['decisions'] if d['question_id'] != question]
        self.assertTrue(all(not export.scored(r, rulings.load(removed, decls, recs)) for r in affected))
        wrong_pool = copy.deepcopy(register)
        wrong_pool['pool_digest'] = '0' * 64
        self.assertTrue(rulings.errors(wrong_pool, decls, recs))
        forged = copy.deepcopy(register)
        forged['decisions'][0]['reviewed_by'] = 'ai_assisted_synthetic_draft'
        self.assertTrue(rulings.errors(forged, decls, recs))
        self.assertFalse(feasibility.record_features(affected[0], rulings.load(pending, decls, recs)))

    def test_freeze_and_export_need_rulings_custody_proof_and_exact_records(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        kwargs = proof(priv, decls, recs)
        self.assertEqual(M.manifest_errors(m, decls, recs, st, **kwargs), [])
        self.assertTrue(any('proof' in e for e in M.manifest_errors(
            m, decls, recs, st, rulings_register=kwargs['rulings_register'])))
        with self.assertRaises((TypeError, export.ExportError)):
            export.plan_export(recs, decls, m, st, auth)  # library does not accept an unproved draw
        with self.assertRaises((TypeError, M.ManifestError)):
            M.public_view(m)  # public view cannot bypass the custodial proof
        mutated = copy.deepcopy(recs)
        mutated[0]['annotation']['unknown'] = not mutated[0]['annotation']['unknown'] if \
            mutated[0]['annotation']['unknown'] is not None else True
        errors = M.manifest_errors(m, decls, mutated, st, **kwargs)
        self.assertTrue(any('inventory' in e for e in errors))
        with self.assertRaises(export.ExportError):
            export.plan_export(mutated, decls, m, st, auth, **kwargs, **export_extra(decls, mutated))
        reidentified = copy.deepcopy(recs)
        reidentified[0]['id'] = 'S35-' + 'E' * 32
        self.assertTrue(any('inventory' in e for e in
                            M.manifest_errors(m, decls, reidentified, st, **kwargs)))
        bad_auth = dict(auth, rulings_sha256='0' * 64)
        with self.assertRaises(export.ExportError):
            export.plan_export(recs, decls, m, st, bad_auth, **kwargs, **export_extra(decls, recs))
        changed_rulings = copy.deepcopy(kwargs['rulings_register'])
        changed_rulings['decisions'][0]['decision_ref'] = 'OTHER-TOY-DECISION'
        with self.assertRaises(export.ExportError):
            export.plan_export(recs, decls, m, st, auth,
                               test_families=priv['test_families'], nonce=priv['nonce'],
                               rulings_register=changed_rulings, **export_extra(decls, recs))

    def test_library_export_rejects_resigned_test_swap(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        tampered = copy.deepcopy(m)
        t = priv['test_families'][0]
        dev = next(f for f, s in m['family_split'].items() if s == 'train')
        tampered['family_split'][t], tampered['family_split'][dev] = 'train', 'test'
        tampered['freeze_record']['frozen_assignment'] = copy.deepcopy(tampered['family_split'])
        from sou35 import adapters
        tampered['freeze_record']['frozen_assignment_sha256'] = adapters.sha(tampered['family_split'])
        tampered = resign(tampered)
        forged_auth = dict(auth, manifest_sha256=tampered['manifest_sha256'])
        with self.assertRaisesRegex(export.ExportError, 'custody draw'):
            export.plan_export(recs, decls, tampered, st, forged_auth, **export_proof(priv, decls, recs))

    def test_export_refuses_stale_files(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        original = ROOT / 'private'
        original_existed = original.exists()
        out = original / f'_test_sou35_stale_{uuid.uuid4().hex}'
        try:
            out.mkdir(parents=True)
            (out / 'leftover.txt').write_text('stale', encoding='utf-8')
            with self.assertRaisesRegex(export.ExportError, 'empty'):
                export.write_export(recs, decls, m, st, auth, out, **export_proof(priv, decls, recs))
        finally:
            shutil.rmtree(out, ignore_errors=True)
            if not original_existed and original.exists() and not any(original.iterdir()):
                original.rmdir()


class SearchHelpers(unittest.TestCase):
    def test_feasible_test_sets_and_allocation(self):
        R = 'pos:read'
        t = {'a': (1, frozenset({R})), 'b': (1, frozenset({R})), 'c': (1, frozenset({R})), 'd': (1, frozenset())}
        req = feasibility.default_requirements({R})
        counts = {'train': 1, 'validation': 1, 'calibration': 1, 'test': 1}
        self.assertEqual(feasibility.feasible_test_sets(t, req, counts), [('a',), ('b',), ('c',)])
        allowed = {'a': ('test',), 'b': M.DEV_SPLITS, 'c': M.DEV_SPLITS, 'd': M.DEV_SPLITS}
        alloc = feasibility.find_allocation(t, req, counts, allowed, ['d', 'c', 'b', 'a'])
        self.assertEqual(alloc, {'d': 'train', 'c': 'validation', 'b': 'calibration', 'a': 'test'})
        self.assertIsNone(feasibility.find_allocation(t, req, counts, {'d': ('test',)}, ['d', 'c', 'b', 'a']))


if __name__ == '__main__':
    unittest.main()
