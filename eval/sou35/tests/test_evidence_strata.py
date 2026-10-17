"""Evidence strata, v2 case ledger, validation boundary and handoff provenance; ARTIFICIAL toy families only.

Positive, negative and adversarial checks that primary eligibility needs an accepted human review AND an
interface-supported basis AND the mechanical safeguards, that only a fully validated immutable Ledger can yield a
stratum, that every non-primary stratum stays distinguishable and out of coverage and export, and that the export
keeps the original generation source separate from the current tooling. Toy ledgers are artificial placeholders,
never approvals for real cases. No private pool is read."""
import copy
import json
import shutil
import unittest
import uuid

from _util import ROOT, TOY_DIR, find
from test_release_workflow import (APPROVAL, COUNTS, REQ, TOY_TOOLING, accepted, drawn, export_extra, export_proof,
                                   frozen_setup, ledger_for, pool, proof, rulings_for, rulings_v1_for,
                                   toy_provenance)

from sou35 import adapters, export, families, feasibility, generate, rulings
from sou35 import manifest as M

AI_NAMES = (' ai_assisted_synthetic_draft', 'AI_Assisted reviewer', 'AI-assisted bot', 'Claude', 'codex-bot',
            'gpt reviewer')


def relay(default=None):
    """toy_relay, optionally with a schema `default` on the optional `preview` flag."""
    d = json.loads((TOY_DIR / 'toy_relay.json').read_text(encoding='utf-8'))
    if default is not None:
        d['tool_schema']['properties']['preview']['default'] = default
    decls = [families.load_decl(d)]
    recs = generate.generate(decls, {})
    return decls, recs, find(recs, 'toy_relay', 'copy_default')


def stratum_with(decls, recs, row, **kw):
    return rulings.evidence_stratum(row, ledger_for(decls, recs, **kw))


class MechanicalCeiling(unittest.TestCase):
    def test_hidden_default_is_capped_even_when_a_human_claims_interface_support(self):
        decls, recs, row = relay()
        self.assertIn('Q-S35-OPTIONAL-DEFAULT', row['open_questions'])
        self.assertEqual(rulings.mechanical_ceiling(row), 'program_only')
        reg = ledger_for(decls, recs)  # every toy basis claims interface_supported
        self.assertEqual(rulings.evidence_stratum(row, reg), rulings.PROGRAM_ONLY)
        self.assertFalse(export.scored(row, reg))
        self.assertEqual(feasibility.record_features(row, reg), set())

    def test_conflicting_schema_default_is_still_hidden(self):
        _, _, row = relay(default=True)  # an applying executor would take `then`; the execution took `else`
        self.assertEqual(rulings.mechanical_ceiling(row), 'program_only')

    def test_consistent_schema_default_only_lifts_the_cap_never_the_basis(self):
        decls, recs, row = relay(default=False)
        self.assertEqual(rulings.mechanical_ceiling(row), 'interface_supported')
        self.assertEqual(stratum_with(decls, recs, row), rulings.PRIMARY)
        # The schema annotation alone never classifies: the human basis still decides.
        self.assertEqual(stratum_with(decls, recs, row, bases={row['id']: 'program_only'}), rulings.PROGRAM_ONLY)
        self.assertEqual(stratum_with(decls, recs, row, statuses={row['id']: 'pending'}), rulings.UNREVIEWED)

    def test_cases_with_the_flag_present_are_not_capped(self):
        _, recs, _ = relay()
        present = [r for r in recs if r['expected_outcome'] == 'classification'
                   and 'preview' in r['input']['raw_arguments']]
        self.assertTrue(present)
        self.assertTrue(all(rulings.mechanical_ceiling(r) == 'interface_supported' for r in present))

    def test_reachability_follows_argument_selected_control_flow(self):
        hidden = {'op': 'when', 'arg': 'flag', 'equals': True, 'then': [], 'else': []}
        program = [{'op': 'switch', 'on': '$mode', 'cases': {'a': [hidden], 'b': []}}]

        def ceiling(args, prog=program):
            return rulings.mechanical_ceiling({'expected_outcome': 'classification', 'evidence': {'program': prog},
                                               'input': {'raw_arguments': args,
                                                         'tool_schema': {'properties': {}}}})
        self.assertEqual(ceiling({'mode': 'a'}), 'program_only')
        self.assertEqual(ceiling({'mode': 'b'}), 'interface_supported')      # unreached optional step
        self.assertEqual(ceiling({'mode': 'zz'}), 'interface_supported')     # unmodelled: execution stops
        self.assertEqual(ceiling({}, [{'op': 'opaque', 'component': 'x'}, hidden]), 'interface_supported')
        unresolvable = [{'op': 'switch', 'on': '@v', 'cases': {'a': [hidden]}}]
        self.assertEqual(ceiling({}, unresolvable), 'program_only')          # conservative: explore every case
        self.assertEqual(ceiling({'xs': []}, [{'op': 'foreach', 'arg': 'xs', 'as': 'v', 'do': [hidden]}]),
                         'interface_supported')                             # empty batch: body never runs
        self.assertEqual(ceiling({'xs': [1]}, [{'op': 'foreach', 'arg': 'xs', 'as': 'v', 'do': [hidden]}]),
                         'program_only')


class Strata(unittest.TestCase):
    def setUp(self):
        self.decls, self.recs, self.table, self.groups = pool()
        self.cls = next(r for r in self.recs if r['expected_outcome'] == 'classification'
                        and not rulings.excluded_from_primary_scoring(r)
                        and rulings.mechanical_ceiling(r) == 'interface_supported')

    def test_strata_stay_distinguishable(self):
        reg = ledger_for(self.decls, self.recs)
        seen = {rulings.evidence_stratum(r, reg) for r in self.recs}
        self.assertTrue({rulings.PRIMARY, rulings.TECHNICAL, rulings.DISPUTED, rulings.PROGRAM_ONLY} <= seen)
        r = self.cls['id']
        for kw, expected in (({'bases': {r: 'information_limited'}}, rulings.INFORMATION_LIMITED),
                             ({'bases': {r: 'program_only'}}, rulings.PROGRAM_ONLY),
                             ({'statuses': {r: 'pending'}}, rulings.UNREVIEWED),
                             ({'statuses': {r: 'rejected'}}, rulings.REJECTED),
                             ({'statuses': {r: 'disputed'}}, rulings.DISPUTED)):
            with self.subTest(kw=kw):
                self.assertEqual(stratum_with(self.decls, self.recs, self.cls, **kw), expected)
                self.assertFalse(feasibility.record_features(self.cls, ledger_for(self.decls, self.recs, **kw)))

    def test_weaker_basis_wins_over_the_ceiling(self):
        decls, recs, row = relay()
        self.assertEqual(stratum_with(decls, recs, row, bases={row['id']: 'information_limited'}),
                         rulings.INFORMATION_LIMITED)

    def test_unaccepted_ruling_is_unresolved_not_primary(self):
        q = self.cls['open_questions'][0]
        raw = rulings_for(self.decls, self.recs)
        next(d for d in raw['decisions'] if d['question_id'] == q)['status'] = 'pending'
        self.assertEqual(rulings.evidence_stratum(self.cls, rulings.load(raw, self.decls, self.recs)),
                         rulings.UNRESOLVED)

    def test_review_status_change_moves_the_stratum_and_the_digest(self):
        before = ledger_for(self.decls, self.recs)
        after = ledger_for(self.decls, self.recs, statuses={self.cls['id']: 'disputed'})
        self.assertNotEqual(before.digest, after.digest)
        self.assertEqual(rulings.evidence_stratum(self.cls, before), rulings.PRIMARY)
        self.assertEqual(rulings.evidence_stratum(self.cls, after), rulings.DISPUTED)

    def test_record_changed_after_review_is_unreviewed(self):
        reg = ledger_for(self.decls, self.recs)
        mutated = copy.deepcopy(self.cls)
        mutated['annotation']['rationale'] += ' (edited)'
        self.assertEqual(rulings.evidence_stratum(mutated, reg), rulings.UNREVIEWED)

    def test_ai_technical_review_refs_never_admit(self):
        raw = rulings_for(self.decls, self.recs, statuses={self.cls['id']: 'pending'})
        entry = next(c for c in raw['reviewed_cases'] if c['id'] == self.cls['id'])
        entry.update(ai_technical_review_refs=['TOY-AI-TECH-REVIEW'], evidence_basis='interface_supported')
        self.assertEqual(rulings.evidence_stratum(self.cls, rulings.load(raw, self.decls, self.recs)),
                         rulings.UNREVIEWED)

    def test_v1_malformed_statuses_are_validation_errors_not_crashes(self):
        for value in (['accepted'], {'status': 'accepted'}, None, 1):
            raw = rulings_v1_for(self.decls, self.recs)
            raw['decisions'][0]['status'] = value
            with self.subTest(decision_status=value):
                self.assertIn('invalid semantic decision status', rulings.errors(raw, self.decls))
            raw = rulings_v1_for(self.decls, self.recs)
            raw['reviewed_cases'][0]['status'] = value
            with self.subTest(case_status=value):
                self.assertIn('reviewed case entry must be accepted', rulings.errors(raw, self.decls))

    def test_v1_register_is_preserved_but_never_primary(self):
        raw = rulings_v1_for(self.decls, self.recs)
        self.assertEqual(raw['version'], 'sou35-semantic-rulings-v1')
        self.assertEqual(rulings.errors(raw, self.decls), [])
        self.assertEqual(rulings.errors(raw, self.decls, self.recs), [])
        reg = rulings.load(raw, self.decls)
        for r in self.recs:
            s = rulings.evidence_stratum(r, reg)
            self.assertNotEqual(s, rulings.PRIMARY)
            if r['expected_outcome'] == 'technical_error':
                self.assertEqual(s, rulings.TECHNICAL)
            elif not rulings.excluded_from_primary_scoring(r):
                self.assertEqual(s, rulings.BASIS_UNRECORDED)
                self.assertEqual(feasibility.record_features(r, reg), set())


class LedgerV2Validation(unittest.TestCase):
    def setUp(self):
        self.decls, self.recs, _, _ = pool()
        self.reg = rulings_for(self.decls, self.recs)
        self.cls_id = next(r['id'] for r in self.recs if r['expected_outcome'] == 'classification')
        self.tech_id = next(r['id'] for r in self.recs if r['expected_outcome'] == 'technical_error')

    def errs(self, mutate):
        reg = copy.deepcopy(self.reg)
        mutate(reg)
        return rulings.errors(reg, self.decls, self.recs)

    def entry(self, reg, rid=None):
        return next(c for c in reg['reviewed_cases'] if c['id'] == (rid or self.cls_id))

    def test_valid_ledger_and_record_binding(self):
        self.assertEqual(rulings.errors(self.reg, self.decls, self.recs), [])
        self.assertTrue(rulings.errors(self.reg, self.decls))  # v2 cannot be validated without the inventory

    def test_exact_row_digest_is_required_for_every_entry(self):
        other = next(c for c in self.reg['reviewed_cases'] if c['id'] != self.cls_id)['row_sha256']
        for status in ('accepted', 'pending', 'rejected', 'disputed'):
            for digest in ('0' * 64, other):  # well-formed, but not the digest of this exact record
                def wrong(r, status=status, digest=digest):
                    self.entry(r).update(status=status, row_sha256=digest)
                with self.subTest(status=status, digest=digest[:8]):
                    self.assertIn('reviewed case digest does not match its exact record', self.errs(wrong))
                    reg = copy.deepcopy(self.reg)
                    wrong(reg)
                    with self.assertRaises(rulings.RulingsError):
                        rulings.load(reg, self.decls, self.recs)

    def test_timestamps_are_real_datetimes(self):
        for bad in ('2026-99-99T99:99Z', '2026-02-30T10:00Z', '2026-10-16T25:00Z', '2026-10-16T01:00:00',
                    '2026-10-16', 'yesterday', '2026-10-16T01:00:00+25:00'):
            with self.subTest(reviewed_at=bad):
                self.assertTrue(self.errs(lambda r: self.entry(r).__setitem__('reviewed_at', bad)))
                self.assertTrue(self.errs(lambda r: r['decisions'][0].__setitem__('reviewed_at', bad)))
        for good in ('2026-10-16T01:00Z', '2026-10-16T01:00:00.5+05:00', '2026-10-16T01:00:00-03:30'):
            with self.subTest(reviewed_at=good):
                self.assertEqual(self.errs(lambda r: self.entry(r).__setitem__('reviewed_at', good)), [])

    def test_invalid_versions_and_policy_are_refused(self):
        for v in ('sou35-semantic-rulings-v3', 'SOU35-SEMANTIC-RULINGS-V2', None):
            with self.subTest(version=v):
                self.assertTrue(self.errs(lambda r: r.__setitem__('version', v)))
        self.assertTrue(self.errs(lambda r: r.__setitem__('eligibility_policy', 'anything-goes')))
        self.assertTrue(self.errs(lambda r: r.__setitem__('record_inventory_sha256', '0' * 64)))

    def test_eligibility_escalation_is_refused(self):
        for basis in ('Interface_Supported', 'primary', '', 'observed_real_tool'):
            with self.subTest(basis=basis):
                self.assertTrue(self.errs(lambda r: self.entry(r).__setitem__('evidence_basis', basis)))
        self.assertTrue(self.errs(lambda r: self.entry(r).__setitem__('evidence_basis', None)))
        self.assertTrue(self.errs(lambda r: self.entry(r, self.tech_id).__setitem__('evidence_basis',
                                                                                     'interface_supported')))
        self.assertTrue(self.errs(lambda r: self.entry(r).__setitem__('status', 'confirmed')))
        self.assertTrue(self.errs(lambda r: self.entry(r).__setitem__('independent_of_generation', False)))

    def test_malformed_json_types_are_validation_errors_not_crashes(self):
        """Unhashable or non-string JSON values must be reported, never raise TypeError."""
        for value in (['accepted'], {'status': 'accepted'}, None, 1, True):
            with self.subTest(case_status=value):
                self.assertIn('invalid case review status',
                              self.errs(lambda r: self.entry(r).__setitem__('status', value)))
            with self.subTest(decision_status=value):
                self.assertIn('invalid semantic decision status',
                              self.errs(lambda r: r['decisions'][0].__setitem__('status', value)))
        for value in (['interface_supported'], {'basis': 'x'}, 1):
            with self.subTest(basis=value):
                self.assertIn('invalid evidence basis',
                              self.errs(lambda r: self.entry(r).__setitem__('evidence_basis', value)))
        for bad in ([['Q-S35-HUMAN-REVIEW']], [{'q': 1}], [None], [1]):
            def considered(r, bad=bad):
                entry = self.entry(r)
                entry['questions_considered'] = list(entry['questions_considered']) + bad
            with self.subTest(questions_considered=bad):
                self.assertIn('accepted case review does not consider every open question of its record',
                              self.errs(considered))
        for version in (['sou35-semantic-rulings-v2'], {'v': 2}, 2):
            with self.subTest(version=version):
                reg = copy.deepcopy(self.reg)
                reg['version'] = version
                reg['decisions'][0]['status'] = ['accepted']  # would crash the preserved v1 validator
                self.assertTrue(rulings.errors(reg, self.decls, self.recs))

    def test_ai_and_non_human_reviewers_are_refused(self):
        for name in AI_NAMES:
            with self.subTest(name=name):
                self.assertTrue(self.errs(lambda r: self.entry(r).__setitem__('reviewed_by', name)))
                self.assertTrue(self.errs(lambda r: r['decisions'][0].__setitem__('reviewed_by', name)))
        self.assertTrue(self.errs(lambda r: self.entry(r).__setitem__('reviewer_kind', 'ai_assisted')))
        self.assertTrue(self.errs(lambda r: r['decisions'][0].pop('reviewer_kind')))
        self.assertFalse(rulings.is_ai_identity('toy-human-reviewer'))
        self.assertFalse(rulings.is_ai_identity('toy-aide'))

    def test_review_metadata_is_required_and_checked(self):
        self.assertTrue(self.errs(lambda r: self.entry(r).__setitem__('decision_ref', ' ')))
        self.assertTrue(self.errs(lambda r: self.entry(r).__setitem__('questions_considered', [])))
        self.assertTrue(self.errs(lambda r: self.entry(r).__setitem__('ai_technical_review_refs', 'TOY')))
        self.assertTrue(self.errs(lambda r: self.entry(r).__setitem__('row_sha256', 'not-a-digest')))
        # A disputed or rejected decision is a human decision too.
        self.assertTrue(self.errs(lambda r: self.entry(r).update(status='disputed', reviewed_by='Claude')))

    def test_pending_entries_need_no_fabricated_reviewer(self):
        def pend(r):
            self.entry(r).update(status='pending', evidence_basis=None, reviewed_by=None, reviewer_kind=None,
                                 reviewed_at=None, decision_ref=None, questions_considered=[])
        self.assertEqual(self.errs(pend), [])

    def test_duplicate_and_stale_entries_are_refused(self):
        def dup(r):
            clone = dict(self.entry(r), evidence_basis='program_only')
            r['reviewed_cases'].append(clone)
        self.assertTrue(self.errs(dup))
        self.assertTrue(self.errs(lambda r: r['reviewed_cases'].append(
            dict(self.entry(r), id='S35-' + '0' * 32))))


class ValidationBoundary(unittest.TestCase):
    """Stratum-level public APIs accept only a fully validated, immutable Ledger."""

    def setUp(self):
        self.decls, self.recs, _, _ = pool()
        self.raw = rulings_for(self.decls, self.recs)
        self.row = next(r for r in self.recs if r['expected_outcome'] == 'classification'
                        and rulings.mechanical_ceiling(r) == 'interface_supported'
                        and not rulings.excluded_from_primary_scoring(r))

    def test_raw_register_is_refused_by_every_stratum_api(self):
        calls = {'evidence_stratum': lambda: rulings.evidence_stratum(self.row, self.raw),
                 'primary_scoring_admissible': lambda: rulings.primary_scoring_admissible(self.row, self.raw),
                 'scored': lambda: export.scored(self.row, self.raw),
                 'record_features': lambda: feasibility.record_features(self.row, self.raw),
                 'group_table': lambda: feasibility.group_table(self.recs, self.raw),
                 'report': lambda: feasibility.report(self.recs, REQ, [COUNTS], rulings_register=self.raw)}
        for name, call in calls.items():
            with self.subTest(api=name), self.assertRaises(TypeError):
                call()

    def test_invalid_registers_cannot_become_a_ledger(self):
        def entry(reg):
            return next(c for c in reg['reviewed_cases'] if c['id'] == self.row['id'])

        def bad(mutate):
            reg = copy.deepcopy(self.raw)
            mutate(reg)
            return reg
        for name, reg in (('ai reviewer', bad(lambda r: entry(r).__setitem__('reviewed_by', 'Claude'))),
                          ('inventory', bad(lambda r: r.__setitem__('record_inventory_sha256', '0' * 64))),
                          ('policy', bad(lambda r: r.pop('eligibility_policy'))),
                          ('digest', bad(lambda r: entry(r).__setitem__('row_sha256', '0' * 64))),
                          ('date', bad(lambda r: entry(r).__setitem__('reviewed_at', '2026-99-99T99:99Z')))):
            with self.subTest(name=name):
                ledger, errs = rulings.validate(reg, self.decls, self.recs)
                self.assertIsNone(ledger)
                self.assertTrue(errs)
                with self.assertRaises(rulings.RulingsError):
                    rulings.load(reg, self.decls, self.recs)
        self.assertIsNone(rulings.validate(self.raw, self.decls)[0])  # v2 needs the record inventory

    def test_ledger_is_an_immutable_snapshot(self):
        ledger = rulings.load(self.raw, self.decls, self.recs)
        self.assertEqual(ledger.digest, rulings.digest(self.raw))
        with self.assertRaises(AttributeError):
            ledger.version = rulings.VERSION_V1
        with self.assertRaises(TypeError):
            rulings.Ledger(self.raw)
        entry = next(c for c in self.raw['reviewed_cases'] if c['id'] == self.row['id'])
        entry['evidence_basis'] = 'program_only'  # editing the source dict after load changes nothing
        ledger.entry(self.row['id'])['evidence_basis'] = 'program_only'  # nor does editing a returned copy
        self.assertEqual(rulings.evidence_stratum(self.row, ledger), rulings.PRIMARY)

    def test_manifest_and_export_paths_fail_closed_on_an_invalid_register(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        reg = rulings_for(decls, recs)
        reg['reviewed_cases'][0]['reviewed_by'] = 'AI_Assisted reviewer'
        errs = M.manifest_errors(m, decls, recs, st, priv['test_families'], priv['nonce'], rulings_register=reg)
        self.assertIn('missing, invalid or out-of-scope semantic rulings register', errs)
        self.assertTrue(any('coverage requirement not met' in e for e in errs))  # never the raw features
        with self.assertRaises(M.ManifestError):
            M.build_draft(decls, recs, st, priv['test_families'], priv['nonce'], COUNTS, REQ, 'toy-salt',
                          rulings_register=reg)
        with self.assertRaises(export.ExportError):
            export.plan_export(recs, decls, m, st, auth, test_families=priv['test_families'], nonce=priv['nonce'],
                               rulings_register=reg, **export_extra(decls, recs))


class Feasibility(unittest.TestCase):
    def setUp(self):
        self.decls, self.recs, self.raw, _ = pool()

    def test_filtered_coverage_is_monotone_and_never_overstated(self):
        reg = ledger_for(self.decls, self.recs)
        filtered = feasibility.group_table(self.recs, reg)
        for g, (n, feats) in filtered.items():
            self.assertEqual(n, self.raw[g][0])
            self.assertLessEqual(feats, self.raw[g][1])
        for req in (REQ, feasibility.default_requirements()):
            self.assertLessEqual(feasibility.count_allocations(filtered, req, COUNTS),
                                 feasibility.count_allocations(self.raw, req, COUNTS))

    def test_diagnostic_cases_never_satisfy_coverage(self):
        req = {s: frozenset({'pos:read'}) if s == 'validation' else frozenset() for s in feasibility.SPLITS}
        self.assertGreater(feasibility.count_allocations(self.raw, req, COUNTS), 0)
        diag = ledger_for(self.decls, self.recs, bases={r['id']: 'program_only' for r in self.recs
                                                         if r['expected_outcome'] == 'classification'})
        table = feasibility.group_table(self.recs, diag)
        self.assertEqual(feasibility.count_allocations(table, req, COUNTS), 0)
        self.assertTrue(feasibility.necessary_condition_errors(table, req))

    def test_reports_name_their_evidence_policy(self):
        raw = feasibility.report(self.recs, REQ, [COUNTS])
        ledger = ledger_for(self.decls, self.recs)
        policy = feasibility.report(self.recs, REQ, [COUNTS], rulings_register=ledger)
        self.assertEqual(raw['evidence_policy'], feasibility.RAW_POLICY)
        self.assertNotIn('rulings_sha256', raw)
        self.assertEqual(policy['evidence_policy'], rulings.ELIGIBILITY_POLICY)
        self.assertEqual(policy['rulings_sha256'], ledger.digest)


class ExportStrata(unittest.TestCase):
    def setUp(self):
        self.private_existed = (ROOT / 'private').exists()
        self.out = ROOT / 'private' / f'_test_strata_export_{uuid.uuid4().hex}'

    def tearDown(self):
        if self.out.exists():
            shutil.rmtree(self.out)
        if not self.private_existed and (ROOT / 'private').exists() and not any((ROOT / 'private').iterdir()):
            (ROOT / 'private').rmdir()

    def test_only_primary_rows_are_exported_and_counts_are_dev_only(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        reg = ledger_for(decls, recs)
        summary = export.write_export(recs, decls, m, st, auth, self.out, **export_proof(priv, decls, recs))
        self.assertEqual(set(summary['record_counts']), set(M.DEV_SPLITS))
        self.assertIs(summary['id_map_verified'], False)  # no id map declared: nothing is claimed
        self.assertEqual(summary['eligibility_policy'], rulings.ELIGIBILITY_POLICY)
        dev = [r for r in recs if r['family_id'] not in priv['test_families']]
        excluded = [r['id'] for r in dev if rulings.evidence_stratum(r, reg) != rulings.PRIMARY]
        test_ids = [r['id'] for r in recs if r['family_id'] in priv['test_families']]
        self.assertTrue(excluded)
        self.assertEqual(export.verify_export(self.out, test_ids, excluded), [])
        for s, c in summary['record_counts'].items():
            self.assertEqual(set(c['by_stratum']), set(rulings.STRATA))
            self.assertEqual(c['scored'], c['by_stratum'][rulings.PRIMARY])
        for rid, ref in summary['case_reviews'].items():
            self.assertEqual(ref['status'], 'accepted')
            self.assertEqual(ref['evidence_basis'], 'interface_supported')
            self.assertEqual(ref['reviewer_kind'], 'human')
            self.assertFalse(summary['ai_technical_reviews'][rid]['confirms_labels'])
        text = (self.out / 'EXPORT_MANIFEST.json').read_text(encoding='utf-8')
        for secret in list(priv['test_families']) + test_ids + [priv['nonce']]:
            self.assertNotIn(secret, text)
        view = json.dumps(M.public_view(m, decls, recs, st, **proof(priv, decls, recs)))
        self.assertNotIn('stratum', view)
        self.assertNotIn('by_stratum', view)

    def test_verify_export_catches_injected_ids_and_review_mismatch(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        reg = ledger_for(decls, recs)
        summary = export.write_export(recs, decls, m, st, auth, self.out, **export_proof(priv, decls, recs))
        dev = [r for r in recs if r['family_id'] not in priv['test_families']]
        excluded = [r['id'] for r in dev if rulings.evidence_stratum(r, reg) != rulings.PRIMARY]
        test_ids = [r['id'] for r in recs if r['family_id'] in priv['test_families']]
        path = self.out / 'EXPORT_MANIFEST.json'
        original = path.read_text(encoding='utf-8')
        for injected, test_list, excluded_list, msg in (
                (excluded[0], (), excluded, 'non-primary'), (test_ids[0], test_ids, (), 'test record')):
            with self.subTest(msg=msg):
                tampered = json.loads(original)
                tampered['note'] = injected
                path.write_text(json.dumps(tampered), encoding='utf-8')
                self.assertTrue(any(msg in e for e in export.verify_export(self.out, test_list, excluded_list)))
        tampered = json.loads(original)
        tampered['case_reviews'].pop(next(iter(summary['case_reviews'])))
        path.write_text(json.dumps(tampered), encoding='utf-8')
        self.assertTrue(any('case-review' in e for e in export.verify_export(self.out)))

    def test_original_generation_provenance_is_required_bound_and_kept_separate(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        base = proof(priv, decls, recs)
        files = export.plan_export(recs, decls, m, st, auth, **base, **export_extra(decls, recs))
        summary = json.loads(files['EXPORT_MANIFEST.json'])
        self.assertEqual(summary['generation_provenance']['original_generation']['source_commit'], '1' * 40)
        self.assertEqual(summary['export_tooling']['tooling_commit'], '2' * 40)
        self.assertIn('not authenticated', summary['generation_provenance_limits'])
        bad = (None, {}, toy_provenance(decls, recs, generator_version='sou35-other-generator'),
               toy_provenance(decls, recs, source_commit='HEAD'),
               toy_provenance(decls, recs, record_inventory_sha256='0' * 64),
               toy_provenance(decls, recs, pool_digest='0' * 64),
               toy_provenance(decls, recs, command=''))
        for prov in bad:
            with self.subTest(prov=prov), self.assertRaises(export.ExportError):
                export.plan_export(recs, decls, m, st, auth, **base, generation_provenance=prov,
                                   export_tooling=dict(TOY_TOOLING))
        with self.assertRaises(export.ExportError):
            export.plan_export(recs, decls, m, st, auth, **base, generation_provenance=toy_provenance(decls, recs),
                               export_tooling=None)

    def test_declared_id_map_is_verified_against_the_actual_file(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        id_map = {generate.id_key(r['family_id'], r['source_material']['case_kind'],
                                  r['source_material']['case_index']): r['id'] for r in recs}
        good = json.dumps(id_map, indent=1, sort_keys=True).encode('utf-8')

        def plan(data, declared):
            prov = toy_provenance(decls, recs, id_map_sha256=declared)
            return export.plan_export(recs, decls, m, st, auth, **proof(priv, decls, recs),
                                      generation_provenance=prov, export_tooling=dict(TOY_TOOLING),
                                      id_map_bytes=data)
        files = plan(good, adapters.sha_bytes(good))
        self.assertIs(json.loads(files['EXPORT_MANIFEST.json'])['id_map_verified'], True)
        retired = 'f35.retired.toy|classification|0'
        stale = json.dumps(dict(id_map, **{retired: 'S35-' + 'F' * 32})).encode('utf-8')
        plan(stale, adapters.sha_bytes(stale))  # append-only maps may keep keys of retired cases
        first, second = sorted(id_map)[:2]
        swapped = json.dumps(dict(id_map, **{first: id_map[second], second: id_map[first]})).encode('utf-8')
        claimed = json.dumps(dict(id_map, **{retired: id_map[first]})).encode('utf-8')
        for name, data, declared in (('file missing', None, adapters.sha_bytes(good)),
                                     ('other bytes', good + b' ', adapters.sha_bytes(good)),
                                     ('swapped ids', swapped, adapters.sha_bytes(swapped)),
                                     ('id claimed twice', claimed, adapters.sha_bytes(claimed)),
                                     ('not json', b'not json', adapters.sha_bytes(b'not json')),
                                     ('json list', b'[]', adapters.sha_bytes(b'[]')),
                                     ('digest syntax', good, 'not-a-digest')):
            with self.subTest(name=name), self.assertRaises(export.ExportError):
                plan(data, declared)
        for value in ([], ['S35-X'], {'id': 'S35-X'}, None, 7):  # malformed values: unhashable or non-string
            bad_map = json.dumps(dict(id_map, **{retired: value})).encode('utf-8')
            with self.subTest(value=value), self.assertRaisesRegex(export.ExportError, 'string record ids'):
                plan(bad_map, adapters.sha_bytes(bad_map))

    def test_export_tooling_needs_a_full_current_commit(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        base = dict(proof(priv, decls, recs), generation_provenance=toy_provenance(decls, recs))
        for tooling in ({}, {'note': 'anything'}, dict(TOY_TOOLING, tooling_commit=None),
                        dict(TOY_TOOLING, tooling_commit='HEAD'), dict(TOY_TOOLING, tooling_commit='abc1234'),
                        dict(TOY_TOOLING, tooling_commit='A' * 40), dict(TOY_TOOLING, tooling_source_dirty=None),
                        dict(TOY_TOOLING, tooling_source_dirty='no')):
            with self.subTest(tooling=tooling), self.assertRaisesRegex(export.ExportError, 'export_tooling'):
                export.plan_export(recs, decls, m, st, auth, **base, export_tooling=tooling)
        # The current tooling revision is recorded separately; it never replaces the original source revision.
        summary = json.loads(export.plan_export(recs, decls, m, st, auth, **base,
                                                export_tooling=dict(TOY_TOOLING))['EXPORT_MANIFEST.json'])
        self.assertEqual(summary['export_tooling']['tooling_commit'], '2' * 40)
        self.assertEqual(summary['generation_provenance']['original_generation']['source_commit'], '1' * 40)

    def test_ai_authorizer_and_approver_variants_are_refused(self):
        decls, recs, st, priv, m, auth = frozen_setup()
        for name in AI_NAMES:
            with self.subTest(name=name), self.assertRaises(export.ExportError):
                export.plan_export(recs, decls, m, st, dict(auth, authorized_by=name), **export_proof(priv, decls, recs))
        decls, recs, table, groups = pool()
        st, priv = drawn(decls, table, groups, recs=recs)
        st = accepted(st)
        reg = rulings_for(decls, recs)
        draft = M.build_draft(decls, recs, st, priv['test_families'], priv['nonce'], COUNTS, REQ, 'toy-salt',
                              rulings_register=reg)
        for name in AI_NAMES:
            with self.subTest(approver=name), self.assertRaises(M.ManifestError):
                M.freeze(draft, decls, recs, st, priv['test_families'], priv['nonce'], rulings_register=reg,
                         **dict(APPROVAL, approved_by=name))


if __name__ == '__main__':
    unittest.main()
