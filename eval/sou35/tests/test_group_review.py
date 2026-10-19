"""Grouped human evidence import; artificial toy approvals, never private labels."""
import copy
import io
import json
import contextlib
import tempfile
from pathlib import Path
import unittest
import zipfile

from _util import ROOT
from test_release_workflow import (pool, rulings_for, COUNTS, REQ, SEED, APPROVAL,
                                   accepted, export_extra)
from sou35 import adapters, check_pool, custody, export, feasibility, group_review as G, rulings
from sou35 import manifest as M
from sou35.manifest import record_inventory_digest


def packet_for(decls, recs, reviewer='toy-human-reviewer'):
    docs, mappings = {}, []
    for family in sorted({r['family_id'] for r in recs}):
        did = 'TOY-GROUP-' + family
        bindings = []
        for row in [r for r in recs if r['family_id'] == family]:
            technical = row['expected_outcome'] == 'technical_error'
            excluded = rulings.excluded_from_primary_scoring(row)
            basis = None if technical or excluded else 'interface_supported'
            disposition = rulings.TECHNICAL if technical else rulings.DISPUTED if excluded else 'primary_candidate'
            bindings.append({'id': row['id'], 'row_sha256': adapters.sha(row),
                             'outcome': row['expected_outcome'], 'original_target_unchanged': row['annotation']['contract_view']})
            mappings.append({'id': row['id'], 'row_sha256': adapters.sha(row), 'family_id': family,
                             'human_decision_id': did, 'outcome': row['expected_outcome'],
                             'strict_D04_ai_disposition': disposition, 'strict_D04_ai_basis': basis,
                             'selected_separate_profile_disposition': disposition, 'selected_separate_profile_basis': basis})
        docs[did + '.json'] = {'format': 'sou35-human-family-rule-decision/1', 'status': 'accepted_family_rules',
                              'decision_id': did, 'family_id': family, 'reviewer': reviewer, 'reviewer_kind': 'human',
                              'decision_ref': {'human_reply': 'TOY yes'}, 'rules': ['TOY reviewed synthetic rules'],
                              'record_bindings': bindings}
    packet = {'format': 'sou35-completed-human-family-review/1', 'status': 'human_family_rule_review_complete',
              'reviewer': reviewer, 'reviewer_kind': 'human',
              'source': {'record_inventory_sha256': record_inventory_digest(recs)},
              'case_mapping': mappings}
    return docs, packet


def archive(docs, packet):
    data = io.BytesIO()
    raw_docs = {k: json.dumps(v).encode() for k, v in docs.items()}
    packet = dict(packet, group_decision_files={k: adapters.sha_bytes(v) for k, v in raw_docs.items()})
    with zipfile.ZipFile(data, 'w') as z:
        for name, raw in raw_docs.items():
            z.writestr(name, raw)
        z.writestr('SOU35-completed-human-family-review.private.json', json.dumps(packet))
    return data.getvalue()


def auth_for(plan):
    return {'version': G.AUTH_VERSION, 'plan_sha256': plan['plan_sha256'], 'review_method': G.METHOD,
            'reviewed_by': plan['reviewer'], 'reviewer_kind': 'human', 'reviewed_at': '2026-10-18T12:00:00Z',
            'decision_ref': 'TOY-EXTERNAL-GROUP-MAPPING-ACCEPTANCE', 'independent_of_generation': True,
            'adopt_exact_group_mapping': True, 'eligibility_policy': plan['eligibility_policy']}


class GroupReview(unittest.TestCase):
    def setUp(self):
        self.decls, self.recs, _, _ = pool()
        self.reg = rulings_for(self.decls, self.recs, statuses={r['id']: 'pending' for r in self.recs})
        for entry in self.reg['reviewed_cases']:
            for key in ('reviewed_by', 'reviewed_at', 'reviewer_kind', 'decision_ref', 'independent_of_generation', 'evidence_basis'):
                entry[key] = None
        self.docs, self.packet = packet_for(self.decls, self.recs)
        self.plan = self.prepare()
        self.auth = auth_for(self.plan)

    def prepare(self, policy=rulings.ELIGIBILITY_POLICY):
        data = archive(self.docs, self.packet)
        return G.prepare(self.reg, self.decls, self.recs, data, adapters.sha_bytes(data), policy=policy)

    def apply(self):
        return G.apply(self.reg, self.decls, self.recs, self.plan, self.auth)

    def test_preparation_never_admits_or_changes_source(self):
        before = copy.deepcopy(self.reg)
        self.prepare()
        self.assertEqual(before, self.reg)
        ledger = rulings.load(self.reg, self.decls, self.recs)
        self.assertFalse(any(export.scored(r, ledger) for r in self.recs))
        self.assertTrue(G.authorization_errors(self.plan, None))

    def test_single_attestation_imports_exact_groups_through_existing_gate(self):
        result = self.apply()
        ledger = rulings.load(result, self.decls, self.recs)
        self.assertTrue(any(export.scored(r, ledger) for r in self.recs))
        self.assertTrue(all(r['status'] == 'pending' for r in self.reg['reviewed_cases']))
        for entry in result['reviewed_cases']:
            self.assertEqual(entry['review_method'], G.METHOD)
            self.assertEqual(entry['group_review_plan_sha256'], self.plan['plan_sha256'])
        self.assertEqual(ledger.digest, rulings.digest(result))

    def test_missing_or_false_human_attestations_never_admit(self):
        for field, value in [('independent_of_generation', False), ('adopt_exact_group_mapping', False),
                             ('reviewer_kind', 'ai'), ('reviewed_by', 'Claude'), ('reviewed_at', 'not-a-time'),
                             ('decision_ref', ''), ('plan_sha256', '0' * 64), ('review_method', 'manual'),
                             ('eligibility_policy', rulings.SCHEMA_SEMANTICS_POLICY)]:
            with self.subTest(field=field):
                bad = dict(self.auth, **{field: value})
                with self.assertRaises(G.GroupReviewError):
                    G.apply(self.reg, self.decls, self.recs, self.plan, bad)

    def test_different_ledger_or_inventory_refuses_stale_plan(self):
        for mutate in (lambda r: r['decisions'][0].update(decision_ref='TOY newer decision'),
                       lambda r: r['reviewed_cases'][0].update(ai_technical_review_refs=['TOY newer evidence'])):
            changed = copy.deepcopy(self.reg)
            mutate(changed)
            with self.assertRaises(G.GroupReviewError):
                G.apply(changed, self.decls, self.recs, self.plan, self.auth)

    def test_wrong_archive_hash_and_duplicate_members_are_refused(self):
        data = archive(self.docs, self.packet)
        with self.assertRaises(G.GroupReviewError):
            G.prepare(self.reg, self.decls, self.recs, data, '0' * 64)
        raw = io.BytesIO(data)
        with zipfile.ZipFile(raw, 'a') as z:
            z.writestr('nested/SOU35-completed-human-family-review.private.json', '{}')
        with self.assertRaises(G.GroupReviewError):
            G.prepare(self.reg, self.decls, self.recs, raw.getvalue(), adapters.sha_bytes(raw.getvalue()))

    def test_tampered_id_family_row_target_and_missing_binding_are_refused(self):
        original = copy.deepcopy(self.docs)
        doc_name = next(iter(self.docs))
        for mutation in (lambda d: d['record_bindings'][0].update(id='TOY absent'),
                         lambda d: d.update(family_id='TOY different family'),
                         lambda d: d['record_bindings'][0].update(row_sha256='0' * 64),
                         lambda d: d['record_bindings'][0].update(original_target_unchanged={'actions': ['delete']}),
                         lambda d: d['record_bindings'].pop(),
                         lambda d: d['record_bindings'].append(copy.deepcopy(d['record_bindings'][0]))):
            self.docs = copy.deepcopy(original)
            mutation(self.docs[doc_name])
            with self.assertRaises(G.GroupReviewError):
                self.prepare()

    def test_ai_or_unaccepted_family_document_is_not_human_evidence(self):
        first = self.docs[next(iter(self.docs))]
        for key, value in [('reviewer', 'Claude'), ('reviewer_kind', 'ai'), ('status', 'proposed')]:
            old = first[key]
            first[key] = value
            with self.assertRaises(G.GroupReviewError):
                self.prepare()
            first[key] = old

    def test_semantic_pending_is_not_resolved_by_case_approval(self):
        self.reg['decisions'][0]['status'] = 'pending'
        self.plan = self.prepare()
        self.auth = auth_for(self.plan)
        result = self.apply()
        self.assertEqual(result['decisions'][0]['status'], 'pending')
        ledger = rulings.load(result, self.decls, self.recs)
        qid = result['decisions'][0]['question_id']
        for row in self.recs:
            if qid in row['open_questions'] and not rulings.excluded_from_primary_scoring(row):
                self.assertEqual(rulings.evidence_stratum(row, ledger), rulings.UNRESOLVED)

    def test_explicit_human_semantic_decision_can_be_transcribed(self):
        self.reg['decisions'][0]['status'] = 'pending'
        self.plan = self.prepare()
        self.auth = auth_for(self.plan)
        decision = {k: self.auth[k] for k in ('reviewed_by', 'reviewer_kind', 'reviewed_at', 'decision_ref')}
        self.auth['semantic_decisions'] = [dict(decision, question_id=self.reg['decisions'][0]['question_id'], status='accepted')]
        self.assertEqual(self.apply()['decisions'][0]['status'], 'accepted')

    def test_prior_rejected_disputed_and_accepted_decisions_are_preserved(self):
        for status in ('rejected', 'disputed', 'accepted'):
            reg = rulings_for(self.decls, self.recs, statuses={r['id']: 'pending' for r in self.recs})
            reg['reviewed_cases'][0]['status'] = status
            data = archive(self.docs, self.packet)
            plan = G.prepare(reg, self.decls, self.recs, data, adapters.sha_bytes(data))
            result = G.apply(reg, self.decls, self.recs, plan, auth_for(plan))
            self.assertEqual(result['reviewed_cases'][0], reg['reviewed_cases'][0])

    def test_diagnostic_and_mechanical_floors_survive_group_review(self):
        ledger = rulings.load(self.apply(), self.decls, self.recs)
        self.assertTrue(any(rulings.excluded_from_primary_scoring(r) for r in self.recs))
        for row in self.recs:
            if rulings.excluded_from_primary_scoring(row):
                self.assertEqual(rulings.evidence_stratum(row, ledger), rulings.DISPUTED)
                self.assertFalse(feasibility.record_features(row, ledger))
            elif row['expected_outcome'] == 'classification' and rulings.mechanical_ceiling(row) == 'program_only':
                self.assertEqual(rulings.evidence_stratum(row, ledger), rulings.PROGRAM_ONLY)
                self.assertFalse(export.scored(row, ledger))

    def test_default_full_coverage_is_not_relaxed(self):
        ledger = rulings.load(self.apply(), self.decls, self.recs)
        table = feasibility.group_table(self.recs, ledger)
        req = feasibility.default_requirements()
        self.assertEqual({len(req[s]) for s in feasibility.HELD_OUT}, {13})
        self.assertEqual(feasibility.count_allocations(table, req), 0)  # toy lacks real full coverage

    def test_named_schema_profile_is_explicit_and_does_not_change_default(self):
        plan = self.prepare(rulings.SCHEMA_SEMANTICS_POLICY)
        result = G.apply(self.reg, self.decls, self.recs, plan, auth_for(plan))
        ledger = rulings.load(result, self.decls, self.recs)
        self.assertEqual(ledger.eligibility_policy, rulings.SCHEMA_SEMANTICS_POLICY)
        self.assertEqual(self.reg['eligibility_policy'], rulings.ELIGIBILITY_POLICY)
        self.assertEqual(feasibility.report(self.recs, candidate_patterns=[], rulings_register=ledger)['evidence_policy'],
                         rulings.SCHEMA_SEMANTICS_POLICY)

    def test_schema_profile_and_grouped_method_cannot_drop_the_receipt(self):
        for policy in rulings.ELIGIBILITY_POLICIES:
            plan = self.prepare(policy)
            result = G.apply(self.reg, self.decls, self.recs, plan, auth_for(plan))
            result.pop('group_review_import')
            self.assertTrue(rulings.errors(result, self.decls, self.recs))

    def test_reload_rejects_method_basis_or_authorization_tampering(self):
        result = self.apply()
        mutations = [lambda d: d['reviewed_cases'][0].pop('review_method'),
                     lambda d: d['reviewed_cases'][0].update(evidence_basis='information_limited'),
                     lambda d: d['group_review_import']['authorization'].update(independent_of_generation=False),
                     lambda d: d['group_review_import']['plan']['entries'].pop()]
        for mutate in mutations:
            broken = copy.deepcopy(result)
            mutate(broken)
            self.assertTrue(rulings.errors(broken, self.decls, self.recs))

    def test_export_references_preserve_grouped_method(self):
        ledger = rulings.load(self.apply(), self.decls, self.recs)
        row = next(r for r in self.recs if export.scored(r, ledger))
        reference = export._case_review_ref(row, ledger)
        self.assertEqual(reference['review_method'], G.METHOD)
        self.assertEqual(reference['group_review_plan_sha256'], self.plan['plan_sha256'])
        self.assertTrue(reference['independent_of_generation'])

    def test_grouped_schema_profile_survives_custody_manifest_and_full_export(self):
        plan = self.prepare(rulings.SCHEMA_SEMANTICS_POLICY)
        raw = G.apply(self.reg, self.decls, self.recs, plan, auth_for(plan))
        ledger = rulings.load(raw, self.decls, self.recs)
        table = feasibility.group_table(self.recs, ledger)
        groups = M._groups(self.recs)
        state = custody.declare(self.decls, 'toy-custodian', REQ, COUNTS)
        state, _ = custody.commit(state, table, REQ, COUNTS, SEED,
                                  rulings_sha256=ledger.digest, test_exclusions=())
        state, private = custody.draw(state, table, REQ, COUNTS, SEED, groups, test_exclusions=())
        state = accepted(state)
        draft = M.build_draft(self.decls, self.recs, state, private['test_families'], private['nonce'],
                              COUNTS, REQ, 'toy-salt', rulings_register=raw)
        manifest = M.freeze(draft, self.decls, self.recs, state, private['test_families'], private['nonce'],
                            rulings_register=raw, **APPROVAL)
        auth = {'scope': export.EXPORT_SCOPE, 'authorized_by': 'toy-authorizer',
                'authorized_at': '2026-10-18T13:00:00Z', 'decision_ref': 'TOY-SEPARATE-EXPORT',
                'manifest_sha256': manifest['manifest_sha256'], 'rulings_sha256': ledger.digest}
        files = export.plan_export(self.recs, self.decls, manifest, state, auth,
                                   test_families=private['test_families'], nonce=private['nonce'],
                                   rulings_register=raw, **export_extra(self.decls, self.recs))
        summary = json.loads(files['EXPORT_MANIFEST.json'])
        self.assertEqual(summary['eligibility_policy'], rulings.SCHEMA_SEMANTICS_POLICY)
        self.assertTrue(summary['case_reviews'])
        self.assertTrue(all(x['review_method'] == G.METHOD for x in summary['case_reviews'].values()))
        # A changed/missing receipt cannot reuse this frozen manifest/export authorization.
        broken = copy.deepcopy(raw)
        broken.pop('group_review_import')
        with self.assertRaises(export.ExportError):
            export.plan_export(self.recs, self.decls, manifest, state, auth,
                               test_families=private['test_families'], nonce=private['nonce'],
                               rulings_register=broken, **export_extra(self.decls, self.recs))

    def test_private_output_is_new_and_never_overwrites(self):
        (ROOT / 'private').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / 'private') as root:
            target = Path(root) / 'plan.json'
            G._write_new(target, self.plan)
            before = target.read_bytes()
            with self.assertRaises(FileExistsError):
                G._write_new(target, {'changed': True})
            self.assertEqual(target.read_bytes(), before)
        with self.assertRaises(check_pool.PrivacyError):
            G._write_new(ROOT / 'tests/SHOULD-NOT-EXIST.json', self.plan)

    def test_cli_rejects_missing_human_authorization_without_printing_case_data(self):
        # A usage-shaped refusal before any private pool is opened.
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            rc = G.main(['apply', '--pool', 'missing', '--records', 'missing', '--rulings', 'missing',
                         '--out', str(ROOT / 'tests/SHOULD-NOT-EXIST.json')])
        self.assertEqual(rc, 1)
        for row in self.recs:
            self.assertNotIn(row['id'], stdout.getvalue() + stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
