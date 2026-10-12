# SPDX-License-Identifier: Apache-2.0
"""Export-grade gold addenda, drafting and the gold development export, on a SYNTHETIC world only.

No real case, label, decision, package, anchor or export is created: see _goldworld.py. Keys are generated in
temporary folders; every output is written below a temporary directory outside the repository."""
import copy
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import _goldworld as W
from _sshkeys import SSH_KEYGEN, allowed_signers, fingerprint, make_key, sign
from sou13.hashing import file_sha, sha
from sou13cp2 import ROOT
from sou13gold import export as gx
from sou13gold.addendum import (AddendumError, apply_addenda, apply_addenda_strict, chain_errors, gold_rows,
                                release_blocker_errors, release_questions, strict_errors)
from sou13gold.draft import draft_addendum, submission_binding_errors
from sou13gold.files import GoldFileError, read_export, test_material

SIGNER = 'owner@sou13-gold-test'
# Raw SHA-256 of schema/gold_addendum.schema.json at bdd1f92: the authoritative, unchanged addendum baseline.
BASELINE_ADDENDUM_SCHEMA_SHA256 = '527ee1fb89f80e1b9276dca235eaef1b68d10836d818633824fc294c03bdf6f5'


def run_cli(module, argv):
    out = io.StringIO()
    with redirect_stdout(out):
        code = module.main([str(x) for x in argv])
    return code, json.loads(out.getvalue())


def has(errors, needle):
    return any(needle in e for e in errors)


class World(unittest.TestCase):
    """Rows, an export directory and an approved addendum drafted from synthetic decisions."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.rows, self.inputs = W.rows_and_inputs()
        self.exports = W.write_exports(self.dir / 'exports', self.rows, self.inputs)
        self.base = W.base_for(self.exports)
        self.by_id = {r['id']: r for r in self.rows}

    def tearDown(self):
        self.tmp.cleanup()

    def draft(self, previous=(), sub=None, dec=None):
        return draft_addendum(self.rows, self.base, list(previous), sub or W.submission(self.rows),
                              dec or W.decisions(self.rows))

    def v1(self):
        return self.draft()[0]


class StrictRules(World):
    def test_addendum_schema_change_is_additive_over_the_baseline(self):
        # The proposed batch mode (pending maintainer review) only adds an optional field and an adjudication
        # value; the bdd1f92 baseline's required fields and values are unchanged.
        self.assertNotEqual(file_sha(ROOT / 'schema' / 'gold_addendum.schema.json'), BASELINE_ADDENDUM_SCHEMA_SHA256)
        schema = json.loads((ROOT / 'schema' / 'gold_addendum.schema.json').read_text(encoding='utf-8'))
        self.assertEqual(schema['required'], ['addendum_kind', 'addendum_version', 'previous_addendum_sha256', 'status',
                                              'created_at', 'base', 'scope', 'approvals', 'entries'])
        entry = schema['properties']['entries']['items']
        self.assertEqual(entry['required'], ['case_id', 'split', 'evidence', 'from_status', 'to_status', 'label_change',
                                             'reviewer_labels', 'decision_ids', 'adjudication', 'rationale'])
        self.assertTrue({'independent_human', 'owner_inspected', 'owner_batch', 'owner_rule_propagated'}
                        <= set(entry['properties']['adjudication']['enum']))
        a = self.v1()  # a per-case addendum uses only baseline fields
        self.assertEqual(set(a), set(schema['required']))

    def test_drafted_chain_is_export_grade_and_confirms_only_reviewed_cases(self):
        a = self.v1()
        self.assertEqual(strict_errors([a], self.rows, self.base), [])
        view = apply_addenda_strict(self.rows, [a], self.base)
        self.assertEqual(sorted(v['id'] for v in gold_rows(view)), sorted(W.case(n) for n in W.GOLD))
        self.assertFalse({v['id']: v for v in view}[W.case(6)]['gold'])

    def test_draft_addendum_stays_valid_but_cannot_back_an_export(self):
        a = dict(self.v1(), status='draft')
        self.assertEqual(chain_errors([a], self.rows, self.base), [])
        self.assertTrue(has(strict_errors([a], self.rows, self.base), 'cannot back an export'))

    def test_contract_owner_may_also_be_the_independent_reviewer(self):
        # SOU-10 names its contract owner; the same person may give the independent development sign-off.
        con = {'decision_id': 'SYN-CON-1', 'approver': 'Synthetic Reviewer', 'role': 'contract_owner',
               'approved_at': '2026-10-11', 'statement': W.STATEMENT}
        dec = W.decisions(self.rows)
        dec['approvals'].append(con)
        dec['transitions'][0]['decision_ids'] = ['SYN-CON-1', 'SYN-REV-1']
        a = self.draft(dec=dec)[0]
        self.assertEqual(strict_errors([a], self.rows, self.base), [])

    def test_independent_reviewer_cannot_also_be_a_dataset_owner(self):
        own = dict(W.OWN, approver='synthetic   REVIEWER')
        with self.assertRaises(AddendumError) as ctx:
            self.draft(dec=W.decisions(self.rows, approvals=(W.REV, own)))
        self.assertTrue(has(ctx.exception.errors, 'independence'))

    def test_license_owner_approval_may_be_recorded_in_an_addendum(self):
        dec = W.decisions(self.rows, approvals=(W.REV, W.OWN, W.LIC))
        a = self.draft(dec=dec)[0]
        self.assertEqual(strict_errors([a], self.rows, self.base), [])  # it grants nothing: see GoldExport

    def test_placeholder_approvals_are_rejected(self):
        for field, value in (('approver', '<reviewer name>'), ('statement', 'TBD'), ('decision_id', 'EXAMPLE-REV-1')):
            with self.subTest(field=field):
                rev = dict(W.REV, **{field: value})
                dec = W.decisions(self.rows, approvals=(rev, W.OWN))
                sub = W.submission(self.rows, reviewer=rev['approver'], decision=rev['decision_id'])
                for t in dec['transitions']:
                    t['decision_ids'] = [rev['decision_id']]
                with self.assertRaises(AddendumError) as ctx:
                    self.draft(sub=sub, dec=dec)
                self.assertTrue(has(ctx.exception.errors, 'placeholder'))

    def test_a_decision_id_names_one_record_across_the_chain(self):
        v1 = self.draft(sub=W.submission(self.rows, cases=(1,)), dec=W.decisions(self.rows, confirm=(1,)))[0]
        rev = dict(W.REV, statement='Synthetic fixture: a different statement under the same id.')
        dec = W.decisions(self.rows, confirm=(2,), approvals=(rev, W.OWN))
        with self.assertRaises(AddendumError) as ctx:
            self.draft(previous=[v1], sub=W.submission(self.rows, cases=(2,)), dec=dec)
        self.assertTrue(has(ctx.exception.errors, 'names a different record'))

    def test_pending_q_future_case_is_confirmed_by_a_versioned_entry_citing_the_existing_sign_off(self):
        rest = tuple(n for n in W.GOLD if n != 3)
        v1 = self.draft(sub=W.submission(self.rows, cases=rest), dec=W.decisions(self.rows, confirm=rest))[0]
        self.assertFalse({v['id']: v for v in apply_addenda_strict(self.rows, [v1], self.base)}[W.case(3)]['gold'])
        v2, report = self.draft(previous=[v1], sub=W.submission(self.rows, cases=(3,)),
                                dec=W.decisions(self.rows, confirm=(3,)))
        self.assertEqual(report['transitions'], {'pending->confirmed': 1})
        self.assertEqual(v2['entries'][0]['decision_ids'], ['SYN-REV-1'])  # no additional adjudication
        view = {v['id']: v for v in apply_addenda_strict(self.rows, [v1, v2], self.base)}
        self.assertTrue(view[W.case(3)]['gold'])
        self.assertEqual(view[W.case(3)]['frozen_label_status'], 'pending')  # the frozen row is unchanged
        self.assertEqual(self.by_id[W.case(3)]['label_status'], 'pending')

    def test_only_classification_rows_can_be_gold(self):
        with self.assertRaises(AddendumError) as ctx:
            self.draft(sub=W.submission(self.rows, cases=W.GOLD + (6,)),
                       dec=W.decisions(self.rows, confirm=W.GOLD + (6,)))
        self.assertTrue(has(ctx.exception.errors, "is not 'classification'"))

    def test_excluded_cases_stay_non_gold(self):
        a = self.draft(sub=W.submission(self.rows, cases=(1,)),
                       dec=W.decisions(self.rows, confirm=(1,), exclude=(2,)))[0]
        view = {v['id']: v for v in apply_addenda_strict(self.rows, [a], self.base)}
        self.assertEqual((view[W.case(2)]['status'], view[W.case(2)]['gold']), ('excluded', False))

    def test_stale_evidence_digest_is_rejected(self):
        a = self.v1()
        a['entries'][0]['evidence']['label_sha256'] = sha('stale')
        self.assertTrue(has(strict_errors([a], self.rows, self.base), 'label_sha256 does not match'))

    def test_wrong_version_chain_is_rejected(self):
        v1 = self.draft(sub=W.submission(self.rows, cases=(1,)), dec=W.decisions(self.rows, confirm=(1,)))[0]
        v2 = self.draft(previous=[v1], sub=W.submission(self.rows, cases=(2,)),
                        dec=W.decisions(self.rows, confirm=(2,)))[0]
        for broken, needle in (([v2], 'expected 1'),
                               ([v1, dict(v2, previous_addendum_sha256=sha('x'))], 'does not chain'),
                               ([v1, dict(v2, addendum_version=3)], 'expected 2')):
            with self.subTest(needle=needle):
                self.assertTrue(has(strict_errors(broken, self.rows, self.base), needle))

    def test_unsupported_dataset_revision_is_rejected(self):
        base = dict(self.base, dataset_version='0.5-unreviewed')
        self.assertTrue(has(strict_errors([self.v1()], self.rows, base), 'not supported'))


class ReleaseBlockers(World):
    def test_release_questions_cover_open_questions_and_closed_world_negatives(self):
        questions = release_questions(apply_addenda(self.rows, [self.v1()], self.base), self.rows)
        self.assertEqual(questions['Q-ADMISSION'], sorted(W.case(n) for n in W.GOLD))
        self.assertEqual(questions['Q-FUTURE'], [W.case(3)])
        self.assertEqual(questions['Q-CP2-DECL-EVIDENCE'], sorted(W.case(n) for n in (1, 3, 4, 5)))  # not 2

    def test_unresolved_or_unrecorded_resolutions_block_the_release(self):
        questions = release_questions(apply_addenda(self.rows, [self.v1()], self.base), self.rows)
        records = {d: {} for d in ('SYN-ADM-1', 'SYN-DECL-1', 'SYN-REV-1')}
        self.assertEqual(release_blocker_errors(questions, W.RESOLVED, records), [])
        for q in W.RESOLVED:
            with self.subTest(missing=q):
                resolved = {k: v for k, v in W.RESOLVED.items() if k != q}
                self.assertTrue(has(release_blocker_errors(questions, resolved, records), f'release blocker {q}'))
        unrecorded = dict(W.RESOLVED, **{'Q-ADMISSION': ['SYN-ADM-9']})
        self.assertTrue(has(release_blocker_errors(questions, unrecorded, records), 'are not recorded approvals'))

    def test_excluding_closed_world_negatives_removes_the_decl_evidence_blocker(self):
        a = self.draft(sub=W.submission(self.rows, cases=(2,)),
                       dec=W.decisions(self.rows, confirm=(2,), exclude=(1, 4, 5)))[0]
        questions = release_questions(apply_addenda(self.rows, [a], self.base), self.rows)
        self.assertNotIn('Q-CP2-DECL-EVIDENCE', questions)


class ReviewerEvidence(World):
    def test_reviewer_labels_are_proven_against_the_submission_files(self):
        sub = W.submission(self.rows)
        a = self.draft(sub=sub)[0]
        self.assertEqual(submission_binding_errors([a], [sub], self.rows), [])
        self.assertTrue(has(submission_binding_errors([a], [], self.rows), 'reviewer_labels are not the labels'))
        forged = copy.deepcopy(a)
        forged['entries'][0]['reviewer_labels']['unknown'] = not forged['entries'][0]['reviewer_labels']['unknown']
        self.assertTrue(has(submission_binding_errors([forged], [sub], self.rows), 'reviewer_labels are not'))
        partial = dict(sub, cases=sub['cases'][1:])
        self.assertTrue(has(submission_binding_errors([a], [partial], self.rows), 'reviewer_labels are not'))
        self.assertTrue(has(submission_binding_errors([a], [sub, sub], self.rows), 'exactly one'))
        stranger = dict(sub, reviewer='Someone Else')
        self.assertTrue(has(submission_binding_errors([a], [stranger], self.rows), 'reviewer differs'))


class Drafting(World):
    def test_entries_bind_frozen_evidence_and_the_reviewers_own_labels(self):
        sub = W.submission(self.rows)
        a, report = self.draft(sub=sub)
        self.assertEqual((a['status'], a['previous_addendum_sha256']), ('approved', None))
        self.assertEqual(report['reviewer_submission_sha256'], sha(sub))
        reviewed = {c['case_id']: c['reviewer_labels'] for c in sub['cases']}
        for entry in a['entries']:
            r = self.by_id[entry['case_id']]
            self.assertEqual(entry['evidence'], {'label_sha256': r['label_sha256'], **r['hashes']})
            self.assertEqual(entry['from_status'], r['label_status'])
            self.assertEqual(entry['reviewer_labels'], reviewed[entry['case_id']])
        self.assertTrue(report['ready_for_approval'])
        self.assertNotIn('per_action_targets', json.dumps(report))

    def test_drafting_is_deterministic(self):
        sub, dec = W.submission(self.rows), W.decisions(self.rows)
        shuffled = copy.deepcopy(dec)
        shuffled['transitions'].reverse()
        shuffled['approvals'].reverse()
        self.assertEqual(json.dumps(self.draft(sub=sub, dec=dec)[0], sort_keys=True),
                         json.dumps(self.draft(sub=sub, dec=shuffled)[0], sort_keys=True))

    def test_confirmation_without_reviewer_labels_is_rejected(self):
        with self.assertRaises(AddendumError) as ctx:
            self.draft(sub=W.submission(self.rows, cases=(1, 2)))
        self.assertTrue(has(ctx.exception.errors, "without the independent reviewer's own labels"))

    def test_reviewer_disagreement_needs_an_explicit_equal_label_change(self):
        sub = W.submission(self.rows)
        changed = sub['cases'][0]['reviewer_labels']
        changed['per_action_targets']['write'] = None
        changed['known_mask']['write'] = 0
        with self.assertRaises(AddendumError) as ctx:
            self.draft(sub=sub)
        self.assertTrue(has(ctx.exception.errors, 'differ from the current labels'))
        dec = W.decisions(self.rows)
        dec['transitions'][0]['label_change'] = copy.deepcopy(changed)
        a = self.draft(sub=sub, dec=dec)[0]
        view = {v['id']: v for v in apply_addenda_strict(self.rows, [a], self.base)}
        self.assertEqual(view[W.case(1)]['labels'], changed)
        dec['transitions'][0]['label_change']['per_action_targets']['read'] = False
        with self.assertRaises(AddendumError):
            self.draft(sub=sub, dec=dec)

    def test_reviewer_submission_must_match_a_recorded_reviewer_decision(self):
        for sub, needle in ((W.submission(self.rows, decision='SYN-REV-9'), 'is not a recorded independent_reviewer'),
                            (W.submission(self.rows, reviewer='Someone Else'), 'reviewer differs from the approver')):
            with self.subTest(needle=needle), self.assertRaises(AddendumError) as ctx:
                self.draft(sub=sub)
            self.assertTrue(has(ctx.exception.errors, needle))

    def test_reviewer_submission_cannot_name_unknown_cases_or_wrong_splits(self):
        sub = W.submission(self.rows)
        sub['cases'][0]['split'] = 'validation'
        sub['cases'].append(dict(sub['cases'][1], case_id=W.case(99)))
        with self.assertRaises(AddendumError) as ctx:
            self.draft(sub=sub)
        self.assertTrue(has(ctx.exception.errors, 'differs from the case split'))
        self.assertTrue(has(ctx.exception.errors, 'no such development case'))

    def test_declared_approval_is_refused_while_rules_block_it_and_a_draft_lists_them(self):
        dec = W.decisions(self.rows, approvals=(W.REV, dict(W.OWN, approver='Synthetic Reviewer')))
        with self.assertRaises(AddendumError):
            self.draft(dec=dec)
        a, report = self.draft(dec=dict(dec, status='draft'))
        self.assertEqual(a['status'], 'draft')
        self.assertFalse(report['ready_for_approval'])
        self.assertTrue(has(report['blocking'], 'independence'))

    def test_previous_chain_must_be_export_grade(self):
        v1 = self.draft(dec=dict(W.decisions(self.rows, confirm=(1,)), status='draft'),
                        sub=W.submission(self.rows, cases=(1,)))[0]
        with self.assertRaises(AddendumError) as ctx:
            self.draft(previous=[v1], sub=W.submission(self.rows, cases=(2,)), dec=W.decisions(self.rows, confirm=(2,)))
        self.assertTrue(has(ctx.exception.errors, 'existing chain'))

    def test_cli_writes_outside_git_only_and_never_overwrites(self):
        from scripts_cp2 import draft_gold_addendum as cli
        sub = W.write(self.dir / 'sub.json', json.dumps(W.submission(self.rows)))
        dec = W.write(self.dir / 'dec.json', json.dumps(W.decisions(self.rows)))
        argv = ['--exports', self.exports, '--split-manifest-sha256', W.SPLIT_SHA, '--submission', sub,
                '--decisions', dec, '--out']
        code, report = run_cli(cli, argv + [self.dir / 'out' / 'addendum-v1.json'])
        self.assertEqual((code, report['result'], report['status']), (0, 'WRITTEN', 'approved'))
        self.assertNotIn('per_action_targets', json.dumps(report))
        code, report = run_cli(cli, argv + [self.dir / 'out' / 'addendum-v1.json'])
        self.assertEqual(code, 1)
        self.assertTrue(has(report['errors'], 'refusing to overwrite'))
        code, report = run_cli(cli, argv + [ROOT / 'never-written-addendum.json'])
        self.assertEqual(code, 1)
        self.assertTrue(has(report['errors'], 'inside a Git work tree'))
        self.assertFalse((ROOT / 'never-written-addendum.json').exists())


class ExportFiles(unittest.TestCase):
    def test_test_material_is_detected_by_name_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            for rel in ('labels/train.jsonl', 'non_pilot/labels/test.jsonl', 'sealed/x.json',
                        'model_inputs/test.jsonl'):
                W.write(Path(tmp) / rel, '')
            self.assertEqual(test_material(tmp), ['model_inputs/test.jsonl', 'non_pilot/labels/test.jsonl', 'sealed',
                                                  'sealed/x.json'])

    def test_export_reader_refuses_test_labels_anywhere(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows, inputs = W.rows_and_inputs()
            exports = W.write_exports(Path(tmp) / 'e', rows, inputs)
            W.write(exports / 'non_pilot' / 'labels' / 'test.jsonl', '')
            _, _, _, errors = read_export(exports)
            self.assertTrue(has(errors, 'non_pilot/labels/test.jsonl: test or custodian material'))


@unittest.skipUnless(SSH_KEYGEN, 'ssh-keygen with -Y sign/verify is required')
class GoldExport(unittest.TestCase):
    """Anchored package -> addendum -> authorization -> export -> standalone verification."""

    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        k = Path(cls.keys.name)
        cls.owner_key = make_key(k, 'owner')
        cls.signers = allowed_signers(k, SIGNER, cls.owner_key)
        cls.pin = fingerprint(cls.signers)
        evil = make_key(k, 'evil')
        cls.evil_signers = allowed_signers(k, SIGNER, evil, filename='evil_signers')
        # The export digest statement is signed in its own namespace (technical domain separation only).
        pub = Path(str(cls.owner_key) + '.pub').read_text(encoding='utf-8').split()
        cls.export_signers = W.write(k / 'export_signers',
                                     f'{SIGNER} namespaces="sou13-gold-export" {pub[0]} {pub[1]}\n')

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.trust = self.dir / 'trust'
        self.make(*W.rows_and_inputs())

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, rows, inputs, view=None):
        self.rows, self.inputs = rows, inputs
        if (self.dir / 'pkg').exists():
            shutil.rmtree(self.dir / 'pkg')
        self.pkg = W.write_package(self.dir / 'pkg', rows, inputs, view)
        self.sign_anchor()
        self.base = W.base_for(self.pkg / 'exports')

    def sign_anchor(self, **overrides):
        view = json.loads((self.pkg / 'manifest' / 'split_manifest.PUBLIC_VIEW.json').read_text(encoding='utf-8'))
        doc = {'anchor_kind': 'sou13_cp2_freeze_anchor', 'namespace': 'sou13-cp2-freeze',
               'full_manifest_sha256': W.SPLIT_SHA, 'public_view_sha256': view['manifest_sha256'],
               'package_manifest_sha256': {'dev_review_package': file_sha(self.pkg / 'MANIFEST.json')}, **overrides}
        self.anchor = W.write(self.trust / 'anchor.json', json.dumps(doc, sort_keys=True))
        sign(self.owner_key, self.anchor)

    def cfg(self, signers=None):
        return {'anchor': str(self.anchor), 'signature': str(self.anchor) + '.sig',
                'allowed_signers': str(signers or self.signers), 'trusted_key_fpr': self.pin, 'signer': SIGNER}

    def anchor_argv(self):
        return ['--anchor', self.anchor, '--allowed-signers', self.signers, '--trusted-key-fpr', self.pin,
                '--signer', SIGNER]

    def src(self):
        return gx.load_sources(self.pkg, self.cfg(), untrusted_roots=[ROOT])

    def addenda(self, confirm=W.GOLD, approvals=(W.REV, W.OWN), exclude=()):
        self.subs = [W.submission(self.rows, cases=confirm)]
        a = draft_addendum(self.rows, self.base, [], self.subs[0],
                           W.decisions(self.rows, confirm=confirm, approvals=approvals, exclude=exclude))[0]
        return [W.write(self.dir / 'in' / 'addendum-v1.json', json.dumps(a, indent=2, sort_keys=True))]

    def load(self, paths):
        return [json.loads(Path(x).read_text(encoding='utf-8')) for x in paths]

    def auth(self, paths, name='auth.json', **overrides):
        p = gx.plan(self.src(), self.load(paths), self.subs)
        return W.write(self.dir / 'in' / name, json.dumps(W.authorization(p, **overrides), indent=2, sort_keys=True))

    def build(self, out='export', paths=None, auth=None):
        paths = paths or self.addenda()
        return gx.build(self.src(), paths, self.subs, auth or self.auth(paths), self.dir / 'out' / out,
                        repo_root=ROOT.parents[1])

    def assert_refused(self, fn, needle, exc=gx.ExportError):
        with self.assertRaises(exc) as ctx:
            fn()
        errors = getattr(ctx.exception, 'errors', [str(ctx.exception)])
        self.assertTrue(has(errors, needle), errors)
        self.assertFalse((self.dir / 'out' / 'export').exists())

    # ---- happy path ------------------------------------------------------------------------------------------
    def test_plan_names_the_gold_set_and_the_release_questions(self):
        p = gx.plan(self.src(), self.load(self.addenda()), self.subs)
        self.assertEqual(p['counts'], {'train': 3, 'validation': 1, 'calibration': 1})
        self.assertEqual(p['base'], self.base)
        self.assertEqual(p['release_questions'], {'Q-ADMISSION': 5, 'Q-CP2-DECL-EVIDENCE': 4, 'Q-FUTURE': 1})

    def test_build_exports_only_gold_development_rows_and_verifies_standalone(self):
        result = self.build()
        out = self.dir / 'out' / 'export'
        self.assertEqual(result['counts'], {'train': 3, 'validation': 1, 'calibration': 1})
        files = sorted(p.relative_to(out).as_posix() for p in out.rglob('*') if p.is_file())
        self.assertEqual(files, ['GOLD_EXPORT_MANIFEST.json', 'README.md', 'addenda/addendum-v1.json',
                                 'authorization/EXPORT_AUTHORIZATION.json', 'labels/calibration.jsonl',
                                 'labels/train.jsonl', 'labels/validation.jsonl', 'model_inputs/calibration.jsonl',
                                 'model_inputs/train.jsonl', 'model_inputs/validation.jsonl', 'verify_gold_export.py'])
        exported = {json.loads(x)['id'] for s in ('train', 'validation', 'calibration')
                    for x in (out / 'labels' / f'{s}.jsonl').read_text(encoding='utf-8').splitlines()}
        self.assertEqual(exported, {W.case(n) for n in W.GOLD})  # never the technical-error row
        man = json.loads((out / 'GOLD_EXPORT_MANIFEST.json').read_text(encoding='utf-8'))
        self.assertEqual(man['release_blockers_resolved'], W.RESOLVED)
        self.assertEqual(test_material(out), [])
        verifier = gx.load_verifier()
        report = verifier.verify(out, result['gold_export_manifest_sha256'])
        self.assertEqual(report['result'], 'PASS')
        # A PASS never claims that cited decisions resolve their questions, or that labels are correct.
        self.assertTrue(report['release_blockers'].startswith('CITED_ONLY'))
        self.assertTrue(report['label_correctness'].startswith('NOT VERIFIED'))
        self.assertEqual(verifier.verify(out)['result'], 'UNVERIFIED')
        self.assertEqual(verifier.verify(out, sha('other'))['result'], 'FAIL')
        statement = self.dir / 'out' / 'export.digest.json'
        self.assertEqual(json.loads(statement.read_text(encoding='utf-8'))['gold_export_manifest_sha256'],
                         result['gold_export_manifest_sha256'])
        sign(self.owner_key, statement, namespace='sou13-gold-export')
        argv = [out, '--statement', statement, '--allowed-signers', self.export_signers, '--trusted-key-fpr',
                self.pin, '--signer', SIGNER]
        code, report = run_cli(verifier, argv)
        self.assertEqual((code, report['result']), (0, 'PASS'))
        self.assertNotIn('per_action_targets', json.dumps(report))
        code, report = run_cli(verifier, argv[:4] + [self.signers] + argv[5:])  # freeze-only namespace
        self.assertEqual((code, report['anchored_integrity']), (1, 'FAIL'))
        code, report = run_cli(verifier, argv[:4] + [self.evil_signers] + argv[5:])
        self.assertEqual((code, report['anchored_integrity']), (1, 'FAIL'))

    def test_builds_are_byte_identical(self):
        paths = self.addenda()
        auth = self.auth(paths)
        r1 = self.build('a', paths, auth)
        r2 = self.build('b', paths, auth)
        self.assertEqual(r1['gold_export_manifest_sha256'], r2['gold_export_manifest_sha256'])
        for p in (self.dir / 'out' / 'a').rglob('*'):
            if p.is_file():
                rel = p.relative_to(self.dir / 'out' / 'a')
                self.assertEqual(p.read_bytes(), (self.dir / 'out' / 'b' / rel).read_bytes(), rel)

    # ---- release blockers ------------------------------------------------------------------------------------
    def test_unresolved_release_questions_block_the_export(self):
        paths = self.addenda()
        for q in ('Q-CP2-DECL-EVIDENCE', 'Q-ADMISSION', 'Q-FUTURE'):
            with self.subTest(unresolved=q):
                resolved = {k: v for k, v in W.RESOLVED.items() if k != q}
                approvals = [x for x in (W.LIC, W.REL, W.ADM, W.DECL)
                             if x['decision_id'] in {d for ids in resolved.values() for d in ids}
                             or x['role'] in ('license_owner', 'dataset_owner')]
                auth = self.auth(paths, f'{q}.json', release_blockers_resolved=resolved, approvals=approvals)
                self.assert_refused(lambda: self.build(paths=paths, auth=auth), f'release blocker {q}')

    def test_resolution_citing_an_unrecorded_decision_is_refused(self):
        paths = self.addenda()
        resolved = dict(W.RESOLVED, **{'Q-ADMISSION': ['SYN-ADM-9']})
        approvals = [W.LIC, W.REL, W.DECL]
        auth = self.auth(paths, release_blockers_resolved=resolved, approvals=approvals)
        self.assert_refused(lambda: self.build(paths=paths, auth=auth), 'are not recorded approvals')

    def test_excluded_closed_world_negatives_need_no_decl_evidence_resolution(self):
        paths = self.addenda(confirm=(2,), exclude=(1, 4, 5))
        resolved = {'Q-ADMISSION': ['SYN-ADM-1']}
        auth = self.auth(paths, release_blockers_resolved=resolved, approvals=[W.LIC, W.REL, W.ADM])
        self.assertEqual(self.build(paths=paths, auth=auth)['counts'], {'train': 1, 'validation': 0, 'calibration': 0})

    # ---- authorization gates ---------------------------------------------------------------------------------
    def test_license_approval_in_an_addendum_never_authorises_training(self):
        paths = self.addenda(approvals=(W.REV, W.OWN, W.LIC))
        p = gx.plan(self.src(), self.load(paths), self.subs)
        use = dict(W.authorization(p)['permitted_use'], training_use_authorized=False)
        self.assert_refused(lambda: self.build(paths=paths, auth=self.auth(paths, permitted_use=use)),
                            'training use is not authorised')

    def test_authorization_gates(self):
        paths = self.addenda()
        base_approvals = [W.LIC, W.REL, W.ADM, W.DECL]
        cases = [
            ({'status': 'draft'}, 'cannot release an export'),
            ({'license_decision_ids': ['SYN-REL-1']}, 'is not a recorded license_owner approval'),
            ({'approvals': [W.REL, W.ADM, W.DECL, dict(W.LIC, role='dataset_owner')]},
             'is not a recorded license_owner approval'),
            ({'approvals': [W.REL, W.ADM, W.DECL, dict(W.LIC, approver='TODO')]}, 'placeholder'),
            ({'approvals': base_approvals + [dict(W.LIC, decision_id='SYN-LIC-2')]}, 'recorded but not referenced'),
            ({'addendum_chain': {'length': 1, 'head_sha256': sha('another chain')}}, 'different addendum chain'),
            ({'base': dict(self.base, export_manifest_sha256=sha('stale'))}, 'base differs'),
            ({'approvals': [dict(W.REL, decision_id='SYN-OWN-1'), W.LIC, W.ADM, W.DECL],
              'release_decision_ids': ['SYN-OWN-1']}, 'names a different record'),
        ]
        for n, (override, needle) in enumerate(cases):
            with self.subTest(needle=needle):
                self.assert_refused(lambda: self.build(paths=paths, auth=self.auth(paths, f'a{n}.json', **override)),
                                    needle)

    def test_partial_coverage_is_refused(self):
        paths = self.addenda()
        full_subs = self.subs
        stale_auth = self.auth(self.addenda(confirm=(1, 2)), 'small.json')  # approved a smaller gold set
        paths = self.addenda()
        self.subs = full_subs
        self.assert_refused(lambda: self.build(paths=paths, auth=stale_auth), 'different gold set')

    def test_gold_rows_in_an_unauthorised_split_are_refused(self):
        paths = self.addenda()
        p = gx.plan(self.src(), self.load(paths), self.subs)
        use = dict(W.authorization(p)['permitted_use'], splits=['train', 'validation'])
        self.assert_refused(lambda: self.build(paths=paths, auth=self.auth(paths, permitted_use=use)),
                            'calibration, which is not authorised')

    def test_reviewer_submissions_are_required_and_must_match(self):
        paths = self.addenda()
        self.assert_refused(lambda: gx.plan(self.src(), self.load(paths), []), 'no reviewer submission')
        forged = copy.deepcopy(self.subs[0])
        forged['cases'][0]['reviewer_labels']['unknown'] = not forged['cases'][0]['reviewer_labels']['unknown']
        self.assert_refused(lambda: gx.plan(self.src(), self.load(paths), [forged]), 'reviewer evidence')

    # ---- source and anchor gates -----------------------------------------------------------------------------
    def test_wrong_owner_key_is_refused(self):
        self.assert_refused(lambda: gx.load_sources(self.pkg, self.cfg(self.evil_signers)), 'anchor:')

    def test_tampered_package_file_is_refused(self):
        p = self.pkg / 'exports' / 'labels' / 'train.jsonl'
        p.write_text(p.read_text(encoding='utf-8') + '\n', encoding='utf-8')
        self.assert_refused(self.src, 'differs from MANIFEST.json')

    def test_package_not_named_by_the_anchor_is_refused(self):
        (self.pkg / 'README_RU.md').write_text('changed\n', encoding='utf-8')
        W.reseal_package(self.pkg)
        self.assert_refused(self.src, 'MANIFEST.json differs from the owner-signed anchor')

    def test_anchor_without_a_package_digest_is_refused(self):
        self.sign_anchor(package_manifest_sha256={})
        self.assert_refused(self.src, 'records no digest for dev_review_package')

    def test_held_out_test_material_in_the_package_is_refused(self):
        W.write(self.pkg / 'exports' / 'labels' / 'test.jsonl', '')
        W.reseal_package(self.pkg)
        self.sign_anchor()
        self.assert_refused(self.src, 'test or custodian material')

    def test_row_marked_test_inside_a_development_file_is_refused(self):
        rel = 'exports/labels/validation.jsonl'
        rows = [json.loads(x) for x in (self.pkg / rel).read_text(encoding='utf-8').splitlines()]
        rows[0]['split'] = 'test'
        W.write(self.pkg / rel, ''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows))
        man_path = self.pkg / 'exports' / 'EXPORT_MANIFEST.json'
        man = json.loads(man_path.read_text(encoding='utf-8'))
        man['files_sha256']['labels/validation.jsonl'] = file_sha(self.pkg / rel)
        W.write(man_path, json.dumps(man, indent=2, sort_keys=True) + '\n')
        W.reseal_package(self.pkg)
        self.sign_anchor()  # even an owner-signed package cannot smuggle a test row into the export
        self.assert_refused(self.src, "split 'test' is not a development split")

    def test_family_assigned_to_another_split_is_refused(self):
        rows, inputs = W.rows_and_inputs()
        fs = {W.family(k): s for k, s in W.FAMILY.items()}
        fs[W.family('train-2')] = 'validation'
        self.make(rows, inputs, W.public_view(rows, fs))
        self.assert_refused(self.src, 'family is not assigned to train')

    def test_family_missing_from_the_public_view_is_refused(self):
        rows, inputs = W.rows_and_inputs()
        fs = {W.family(k): s for k, s in W.FAMILY.items() if k != 'calibration-1'}
        self.make(rows, inputs, W.public_view(rows, fs))
        self.assert_refused(self.src, 'family is not assigned to calibration')

    def test_same_input_in_two_splits_is_refused(self):
        rows, inputs = W.rows_and_inputs()
        dup = {r['id']: r for r in rows}[W.case(1)]['hashes']
        for r in rows:
            if r['id'] == W.case(4):
                r['hashes'] = dict(dup)
        for m in inputs:
            if m['id'] == W.case(4):
                m['input'] = copy.deepcopy({x['id']: x for x in inputs}[W.case(1)]['input'])
                m['hashes'] = dict(dup)
        self.make(rows, inputs)
        self.assert_refused(self.src, 'the same input appears in two splits')

    def test_model_input_that_does_not_reproduce_its_digests_is_refused(self):
        rows, inputs = W.rows_and_inputs()
        inputs[0]['input']['raw_arguments'] = {'n': 'changed'}
        self.make(rows, inputs)
        self.assert_refused(self.src, 'does not reproduce its digests')

    def test_addendum_bound_to_another_split_manifest_is_refused(self):
        sub = W.submission(self.rows)
        a = draft_addendum(self.rows, W.base_for(self.pkg / 'exports', split_sha=sha('other split manifest')), [],
                           sub, W.decisions(self.rows))[0]
        self.assert_refused(lambda: gx.plan(self.src(), [a], [sub]), 'base.split_manifest_sha256 does not match')

    def test_draft_chain_cannot_be_exported(self):
        a = self.load(self.addenda())[0]
        self.assert_refused(lambda: gx.plan(self.src(), [dict(a, status='draft')], self.subs), 'cannot back an export')

    # ---- output safety ---------------------------------------------------------------------------------------
    def test_interrupted_export_leaves_no_export_behind(self):
        paths = self.addenda()
        auth = self.auth(paths)
        with mock.patch.object(gx, 'load_verifier', side_effect=RuntimeError('simulated interruption')):
            with self.assertRaises(RuntimeError):
                self.build(paths=paths, auth=auth)
        self.assertEqual(sorted(p.name for p in (self.dir / 'out').iterdir()), [])
        self.build(paths=paths, auth=auth)  # a clean retry succeeds

    def test_leftover_partial_build_is_never_reused_or_deleted(self):
        partial = self.dir / 'out' / '.export.partial'
        W.write(partial / 'marker', 'left by a crash')
        self.assert_refused(self.build, 'partial build', exc=GoldFileError)
        self.assertTrue((partial / 'marker').exists())

    def test_existing_export_is_never_overwritten(self):
        paths = self.addenda()
        auth = self.auth(paths)
        self.build(paths=paths, auth=auth)
        with self.assertRaises(GoldFileError):
            self.build(paths=paths, auth=auth)

    def test_export_inside_the_repository_is_refused(self):
        paths = self.addenda()
        with self.assertRaises(GoldFileError):
            gx.build(self.src(), paths, self.subs, self.auth(paths), ROOT / 'never-written-export',
                     repo_root=ROOT.parents[1])
        self.assertFalse((ROOT / 'never-written-export').exists())
        self.assertFalse((ROOT / '.never-written-export.partial').exists())

    # ---- receiving-team verifier -----------------------------------------------------------------------------
    def test_verifier_detects_tampering_and_injected_test_material(self):
        result = self.build()
        out = self.dir / 'out' / 'export'
        verify = gx.load_verifier().verify
        digest = result['gold_export_manifest_sha256']
        labels = out / 'labels' / 'train.jsonl'
        original = labels.read_text(encoding='utf-8')
        rows = [json.loads(x) for x in original.splitlines()]
        rows[0]['per_action_targets']['read'] = False
        labels.write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows), encoding='utf-8')
        self.assertEqual(verify(out, digest)['self_consistency'], 'FAIL')
        # Rewriting the label file and its manifest digest still breaks the gold digest and the binding to the
        # reviewer's recorded labels; and any rewrite of the manifest fails against the anchored digest.
        man = json.loads((out / 'GOLD_EXPORT_MANIFEST.json').read_text(encoding='utf-8'))
        man['files_sha256']['labels/train.jsonl'] = file_sha(labels)
        (out / 'GOLD_EXPORT_MANIFEST.json').write_text(json.dumps(man), encoding='utf-8')
        report = verify(out, digest)
        self.assertEqual((report['result'], report['anchored_integrity']), ('FAIL', 'FAIL'))
        self.assertTrue(has(report['errors'], 'gold_label_sha256 does not recompute'))
        labels.write_text(original, encoding='utf-8')
        W.write(out / 'labels' / 'test.jsonl', '')
        self.assertTrue(has(verify(out)['errors'], 'labels/test.jsonl: test or custodian material'))

    def test_verifier_detects_an_unresolved_release_blocker(self):
        self.build()
        out = self.dir / 'out' / 'export'
        auth_path = out / 'authorization' / 'EXPORT_AUTHORIZATION.json'
        auth = json.loads(auth_path.read_text(encoding='utf-8'))
        del auth['release_blockers_resolved']['Q-CP2-DECL-EVIDENCE']
        auth['approvals'] = [a for a in auth['approvals'] if a['decision_id'] != 'SYN-DECL-1']
        auth_path.write_text(json.dumps(auth), encoding='utf-8')
        man = json.loads((out / 'GOLD_EXPORT_MANIFEST.json').read_text(encoding='utf-8'))
        man['files_sha256']['authorization/EXPORT_AUTHORIZATION.json'] = file_sha(auth_path)
        man['authorization']['sha256'] = sha(auth)
        (out / 'GOLD_EXPORT_MANIFEST.json').write_text(json.dumps(man), encoding='utf-8')
        report = gx.load_verifier().verify(out)
        self.assertTrue(has(report['errors'], 'release blocker Q-CP2-DECL-EVIDENCE'))
        self.assertEqual(report['self_consistency'], 'FAIL')

    # ---- command-line tools ----------------------------------------------------------------------------------
    def test_build_cli_plan_then_build(self):
        from scripts_cp2 import build_gold_dev_export as cli
        paths = self.addenda()
        sub = W.write(self.dir / 'in' / 'reviewer_submission.json', json.dumps(self.subs[0]))
        common = ['--dev-package', self.pkg, '--addendum', paths[0], '--reviewer-submission', sub] + self.anchor_argv()
        code, report = run_cli(cli, common + ['--plan'])
        self.assertEqual((code, report['result']), (0, 'PLAN'))
        self.assertEqual(report['release_questions'], {'Q-ADMISSION': 5, 'Q-CP2-DECL-EVIDENCE': 4, 'Q-FUTURE': 1})
        self.assertNotIn('per_action_targets', json.dumps(report))
        auth = W.write(self.dir / 'in' / 'cli-auth.json', json.dumps(W.authorization(
            {'base': report['base'], 'addendum_chain': report['addendum_chain'],
             'gold_set_sha256': report['gold_set']['sha256'], 'counts': report['gold_set']['counts']})))
        code, report = run_cli(cli, common + ['--authorization', auth, '--out', self.dir / 'out' / 'export'])
        self.assertEqual((code, report['result']), (0, 'PASS'))
        self.assertNotIn('per_action_targets', json.dumps(report))

    def test_validator_strict_mode_requires_and_checks_the_anchor(self):
        from scripts_cp2 import validate_gold_addendum as cli
        paths = self.addenda()
        exports = self.pkg / 'exports'
        code, report = run_cli(cli, ['--strict', '--exports', exports, '--split-manifest-sha256', W.SPLIT_SHA,
                                     '--addendum', paths[0]])
        self.assertEqual(code, 1)
        self.assertTrue(has(report['errors'], '--strict requires the owner trust anchor'))
        code, report = run_cli(cli, ['--strict', '--exports', exports, '--addendum', paths[0]] + self.anchor_argv())
        self.assertEqual((code, report['result'], report['mode']), (0, 'PASS', 'strict'))
        self.assertEqual(report['release_questions_to_cite_in_authorization'],
                         {'Q-ADMISSION': 5, 'Q-CP2-DECL-EVIDENCE': 4, 'Q-FUTURE': 1})
        sub = W.write(self.dir / 'in' / 'reviewer_submission.json', json.dumps(self.subs[0]))
        code, report = run_cli(cli, ['--strict', '--exports', exports, '--addendum', paths[0],
                                     '--reviewer-submission', sub] + self.anchor_argv())
        self.assertEqual((code, report['result']), (0, 'PASS'))
        other = W.write(self.dir / 'in' / 'other_submission.json',
                        json.dumps(W.submission(self.rows, cases=(1, 2))))
        code, report = run_cli(cli, ['--strict', '--exports', exports, '--addendum', paths[0],
                                     '--reviewer-submission', other] + self.anchor_argv())
        self.assertEqual(code, 1)
        code, report = run_cli(cli, ['--strict', '--exports', exports, '--split-manifest-sha256', sha('wrong'),
                                     '--addendum', paths[0]] + self.anchor_argv())
        self.assertEqual(code, 1)
        self.assertTrue(has(report['errors'], 'differs from the full_manifest_sha256'))
        code, report = run_cli(cli, ['--strict', '--exports', exports, '--addendum', paths[0], '--anchor',
                                     self.anchor, '--allowed-signers', self.evil_signers, '--trusted-key-fpr',
                                     self.pin, '--signer', SIGNER])
        self.assertEqual(code, 1)
        self.assertTrue(has(report['errors'], 'anchor:'))


class ValidatorCli(World):
    def test_test_labels_anywhere_in_the_export_refuse_validation(self):
        from scripts_cp2 import validate_gold_addendum as cli
        path = W.write(self.dir / 'a.json', json.dumps(self.v1()))
        W.write(self.exports / 'non_pilot' / 'labels' / 'test.jsonl', '')
        code, report = run_cli(cli, ['--exports', self.exports, '--split-manifest-sha256', W.SPLIT_SHA,
                                     '--addendum', path])
        self.assertEqual(code, 1)
        self.assertTrue(has(report['errors'], 'test or custodian material'))

    def test_default_mode_still_accepts_a_draft(self):
        from scripts_cp2 import validate_gold_addendum as cli
        path = W.write(self.dir / 'a.json', json.dumps(dict(self.v1(), status='draft')))
        code, report = run_cli(cli, ['--exports', self.exports, '--split-manifest-sha256', W.SPLIT_SHA,
                                     '--addendum', path])
        self.assertEqual((code, report['mode'], report['statuses']), (0, 'legacy', ['draft']))

    def test_unsupported_export_revision_is_rejected(self):
        from scripts_cp2 import validate_gold_addendum as cli
        man = json.loads((self.exports / 'EXPORT_MANIFEST.json').read_text(encoding='utf-8'))
        man['cp2_version'] = '0.5-unreviewed'
        (self.exports / 'EXPORT_MANIFEST.json').write_text(json.dumps(man), encoding='utf-8')
        path = W.write(self.dir / 'a.json', json.dumps(self.v1()))
        code, report = run_cli(cli, ['--exports', self.exports, '--split-manifest-sha256', W.SPLIT_SHA,
                                     '--addendum', path])
        self.assertEqual(code, 1)
        self.assertTrue(has(report['errors'], 'not supported'))


if __name__ == '__main__':
    unittest.main()
