# SPDX-License-Identifier: Apache-2.0
"""PROPOSED batch attestation (`independent_human_batch`, pending maintainer review), on a SYNTHETIC world only.

An independent reviewer's explicit batch approval of an exact, hash-identified artifact confirms the frozen
labels of exactly the attested CP2 case set, without per-case reviewer labels. These tests check that the mode
claims no per-case review, changes no label, cannot be partial, substituted or mis-scoped, and keeps
explicitly stated labels (Q-FUTURE) blocking when the frozen labels differ. No real decision, artifact or label is
used; see _goldworld.py."""
import copy
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import _goldworld as W
from _sshkeys import SSH_KEYGEN, allowed_signers, fingerprint, make_key, sign
from sou13.hashing import file_sha, sha
from sou13cp2 import ROOT
from sou13gold import export as gx
from sou13gold.addendum import (AddendumError, apply_addenda_strict, batch_case_set_sha256, chain_errors,
                                confirmation_channels, strict_errors)
from sou13gold.draft import draft_addendum

SIGNER = 'owner@sou13-gold-batch-test'
CP2 = (1, 2, 3, 4, 5)  # row 6 carries a historical CP1-style id in this world
Q_FUTURE = {'question_id': 'Q-FUTURE', 'case_count': 1, 'actions': ['read', 'write', 'delete'], 'unknown': False}


def has(errors, needle):
    return any(needle in e for e in errors)


def batch_decisions(rows, package_sha=sha('synthetic reviewed package'), count=len(CP2), cp1=1, assertions=None,
                    decision='SYN-REV-1', approvals=(W.REV, W.OWN), status='approved'):
    d = W.decisions(rows, confirm=(), approvals=approvals, status=status)
    d['batch_attestation'] = {
        'decision_id': decision,
        'reviewed_artifacts': [{'name': 'reviewed development package MANIFEST.json', 'sha256': package_sha},
                               {'name': 'reviewed delta', 'sha256': sha('synthetic reviewed delta')}],
        'scope_kind': 'all_cp2_development_cases',
        'scope_statement': 'Synthetic fixture: all CP2 development cases approved as gold; not a real decision.',
        'expected_case_count': count, 'excluded': {'cp1_cases': cp1, 'sealed_test_cases': 1},
        'label_assertions': [dict(Q_FUTURE)] if assertions is None else assertions}
    return d


class BatchRules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.make()

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, spec=W.SPEC):
        self.rows, inputs = W.rows_and_inputs(spec, cp1=(6,))
        exports = W.write_exports(Path(self.tmp.name) / f'e{id(spec)}', self.rows, inputs)
        self.base = W.base_for(exports)
        self.by_id = {r['id']: r for r in self.rows}

    def draft(self, decisions=None, previous=(), submission=None):
        return draft_addendum(self.rows, self.base, list(previous), submission,
                              decisions or batch_decisions(self.rows))

    def errors(self, addendum, previous=()):
        return strict_errors(list(previous) + [addendum], self.rows, self.base)

    # ---- the honest path -------------------------------------------------------------------------------------
    def test_batch_confirms_exactly_the_attested_cp2_set_without_claiming_per_case_review(self):
        a, report = self.draft()
        self.assertEqual(self.errors(a), [])
        self.assertEqual((report['batch_confirmations'], report['reviewer_submission_sha256']), (len(CP2), None))
        for entry in a['entries']:
            self.assertEqual((entry['adjudication'], entry['reviewer_labels'], entry['label_change']),
                             ('independent_human_batch', None, None))
        att = a['batch_attestations'][0]
        self.assertEqual(att['case_count'], len(CP2))
        self.assertEqual(att['case_set_sha256'], batch_case_set_sha256(
            (W.case(n), self.by_id[W.case(n)]['label_sha256']) for n in CP2))
        view = apply_addenda_strict(self.rows, [a], self.base)
        gold = {v['id']: v for v in view if v['gold']}
        self.assertEqual(set(gold), {W.case(n) for n in CP2})
        for cid, v in gold.items():  # gold labels are the frozen labels, unchanged
            self.assertEqual(v['labels'], W.labels_of(self.by_id[cid]))
        self.assertEqual(confirmation_channels(view), {'independent_human_batch': len(CP2)})
        self.assertEqual(self.by_id[W.case(3)]['label_status'], 'pending')  # frozen rows are never edited

    def test_per_case_mode_is_unchanged(self):
        sub = W.submission(self.rows, cases=CP2)
        a = self.draft(W.decisions(self.rows, confirm=CP2), submission=sub)[0]
        self.assertEqual(self.errors(a), [])
        self.assertNotIn('batch_attestations', a)
        self.assertEqual(confirmation_channels(apply_addenda_strict(self.rows, [a], self.base)),
                         {'independent_human': len(CP2)})

    # ---- incomplete ------------------------------------------------------------------------------------------
    def test_incomplete_coverage_is_rejected(self):
        a = self.draft()[0]
        a['entries'] = a['entries'][1:]
        errors = self.errors(a)
        for needle in ('confirms 4 case(s); the reviewer attested 5', 'differ from the attested case set',
                       'covers 4 of 5 CP2 development cases'):
            self.assertTrue(has(errors, needle), needle)

    def test_stated_case_count_must_match_the_export(self):
        with self.assertRaises(AddendumError) as ctx:
            self.draft(batch_decisions(self.rows, count=179))
        self.assertTrue(has(ctx.exception.errors, 'the reviewer stated 179 case(s)'))

    # ---- mismatched ------------------------------------------------------------------------------------------
    def test_mismatched_case_set_or_label_digest_is_rejected(self):
        a = self.draft()[0]
        bad = copy.deepcopy(a)
        bad['batch_attestations'][0]['case_set_sha256'] = sha('another case set')
        self.assertTrue(has(self.errors(bad), 'differ from the attested case set'))
        bad = copy.deepcopy(a)
        bad['entries'][0]['evidence']['label_sha256'] = sha('another label')
        self.assertTrue(has(self.errors(bad), 'label_sha256 does not match the frozen label row'))

    def test_label_changes_and_reviewer_labels_are_rejected_in_batch_mode(self):
        a = self.draft()[0]
        changed = copy.deepcopy(a)
        labels = W.labels_of(self.by_id[changed['entries'][0]['case_id']])
        labels['per_action_targets']['read'] = not labels['per_action_targets']['read']
        changed['entries'][0]['label_change'] = labels
        self.assertTrue(has(self.errors(changed), 'approves the frozen labels as they are'))
        claimed = copy.deepcopy(a)
        claimed['entries'][0]['reviewer_labels'] = W.labels_of(self.by_id[claimed['entries'][0]['case_id']])
        self.assertTrue(has(self.errors(claimed), 'claims no per-case review'))

    def test_a_case_relabelled_earlier_cannot_be_batch_confirmed(self):
        sub = W.submission(self.rows, cases=(1,))
        changed = sub['cases'][0]['reviewer_labels']
        changed['per_action_targets']['write'], changed['known_mask']['write'] = None, 0
        dec = W.decisions(self.rows, confirm=(1,))
        dec['transitions'][0]['label_change'] = copy.deepcopy(changed)
        v1 = self.draft(dec, submission=sub)[0]
        with self.assertRaises(AddendumError) as ctx:
            self.draft(batch_decisions(self.rows), previous=[v1])
        self.assertTrue(has(ctx.exception.errors, 'relabelled earlier'))

    def test_batch_adjudication_cannot_record_other_transitions(self):
        a = self.draft()[0]
        a['entries'][0]['to_status'] = 'excluded'
        self.assertTrue(has(chain_errors([a], self.rows, self.base), 'is used only to confirm'))

    # ---- substituted -----------------------------------------------------------------------------------------
    def test_attestation_must_be_a_recorded_independent_reviewer_decision(self):
        for decision, approvals, needle in (
                ('SYN-OWN-1', (W.REV, W.OWN), 'not a recorded independent_reviewer approval'),
                ('SYN-REV-2', (W.REV, W.OWN), 'not a recorded independent_reviewer approval')):
            with self.subTest(decision=decision), self.assertRaises(AddendumError) as ctx:
                self.draft(batch_decisions(self.rows, decision=decision, approvals=approvals))
            self.assertTrue(has(ctx.exception.errors, needle))

    def test_each_batch_entry_cites_exactly_one_attestation(self):
        a = self.draft()[0]
        second = dict(a['batch_attestations'][0], decision_id='SYN-REV-2')
        a['batch_attestations'].append(second)
        a['approvals'].append(dict(W.REV, decision_id='SYN-REV-2'))
        a['entries'][0]['decision_ids'] = ['SYN-REV-1', 'SYN-REV-2']
        self.assertTrue(has(chain_errors([a], self.rows, self.base), 'must cite exactly one batch attestation'))

    def test_the_reviewer_cannot_also_be_the_dataset_owner(self):
        own = dict(W.OWN, approver='Synthetic Reviewer')
        with self.assertRaises(AddendumError) as ctx:
            self.draft(batch_decisions(self.rows, approvals=(W.REV, own)))
        self.assertTrue(has(ctx.exception.errors, 'independence'))

    # ---- incorrectly scoped ----------------------------------------------------------------------------------
    def test_cp1_cases_cannot_enter_a_batch_attestation(self):
        a = self.draft()[0]
        cp1 = self.by_id[W.cp1_case(6)]
        entry = dict(a['entries'][0], case_id=cp1['id'], split=cp1['split'],
                     evidence={'label_sha256': cp1['label_sha256'], **cp1['hashes']}, from_status='provisional')
        a['entries'].append(entry)
        errors = self.errors(a)
        self.assertTrue(has(errors, 'batch attestations cover CP2 development cases only'))
        self.assertTrue(has(errors, 'and 1 other case(s)'))

    def test_stated_exclusions_must_match_the_export(self):
        with self.assertRaises(AddendumError) as ctx:
            self.draft(batch_decisions(self.rows, cp1=19))
        self.assertTrue(has(ctx.exception.errors, 'states 19 excluded CP1 case(s)'))

    # ---- explicitly stated labels (Q-FUTURE) -----------------------------------------------------------------
    def test_q_future_cases_with_other_frozen_labels_stay_blocked(self):
        spec = [s if s[0] != 3 else (3, 'train', 'train-2', (True, True, False, False, False), 'pending',
                                     ['Q-ADMISSION', 'Q-FUTURE'], 'classification') for s in W.SPEC]
        self.make(spec)
        with self.assertRaises(AddendumError) as ctx:
            self.draft()
        self.assertTrue(has(ctx.exception.errors, 'differ from the labels the reviewer stated; the case stays blocked'))
        with self.assertRaises(AddendumError):  # an evidence mismatch: not even a draft is written
            self.draft(batch_decisions(self.rows, status='draft'))

    def test_stated_q_future_count_must_match(self):
        with self.assertRaises(AddendumError) as ctx:
            self.draft(batch_decisions(self.rows, assertions=[dict(Q_FUTURE, case_count=6)]))
        self.assertTrue(has(ctx.exception.errors, '1 confirmed case(s) carry Q-FUTURE; the reviewer stated 6'))

    def test_unknown_or_unlisted_actions_in_a_statement_must_match_exactly(self):
        for assertion in (dict(Q_FUTURE, unknown=True), dict(Q_FUTURE, actions=['read', 'write'])):
            with self.subTest(assertion=assertion), self.assertRaises(AddendumError):
                self.draft(batch_decisions(self.rows, assertions=[assertion]))


@unittest.skipUnless(SSH_KEYGEN, 'ssh-keygen with -Y sign/verify is required')
class BatchExport(unittest.TestCase):
    """Anchored package -> batch addendum -> authorization -> export -> standalone verification."""

    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        k = Path(cls.keys.name)
        cls.owner_key = make_key(k, 'owner')
        cls.signers = allowed_signers(k, SIGNER, cls.owner_key)
        cls.pin = fingerprint(cls.signers)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.rows, inputs = W.rows_and_inputs(cp1=(6,))
        self.pkg = W.write_package(self.dir / 'pkg', self.rows, inputs)
        view = json.loads((self.pkg / 'manifest' / 'split_manifest.PUBLIC_VIEW.json').read_text(encoding='utf-8'))
        self.package_sha = file_sha(self.pkg / 'MANIFEST.json')
        self.anchor = W.write(self.dir / 'trust' / 'anchor.json', json.dumps(
            {'anchor_kind': 'sou13_cp2_freeze_anchor', 'namespace': 'sou13-cp2-freeze',
             'full_manifest_sha256': W.SPLIT_SHA, 'public_view_sha256': view['manifest_sha256'],
             'package_manifest_sha256': {'dev_review_package': self.package_sha}}, sort_keys=True))
        sign(self.owner_key, self.anchor)
        self.base = W.base_for(self.pkg / 'exports')

    def tearDown(self):
        self.tmp.cleanup()

    def src(self):
        return gx.load_sources(self.pkg, {'anchor': str(self.anchor), 'signature': str(self.anchor) + '.sig',
                                          'allowed_signers': str(self.signers), 'trusted_key_fpr': self.pin,
                                          'signer': SIGNER}, untrusted_roots=[ROOT])

    def addendum(self, package_sha=None):
        a = draft_addendum(self.rows, self.base, [], None,
                           batch_decisions(self.rows, package_sha=package_sha or self.package_sha))[0]
        return W.write(self.dir / 'in' / 'addendum-v1.json', json.dumps(a, indent=2, sort_keys=True))

    def test_batch_export_builds_and_verifies_without_reviewer_submissions(self):
        path = self.addendum()
        p = gx.plan(self.src(), [json.loads(path.read_text(encoding='utf-8'))], [])
        self.assertEqual(p['confirmation_channels'], {'independent_human_batch': len(CP2)})
        auth = W.write(self.dir / 'in' / 'auth.json', json.dumps(W.authorization(p)))
        result = gx.build(self.src(), [path], [], auth, self.dir / 'out' / 'export', repo_root=ROOT.parents[1])
        out = self.dir / 'out' / 'export'
        exported = {json.loads(x)['id'] for s in ('train', 'validation', 'calibration')
                    for x in (out / 'labels' / f'{s}.jsonl').read_text(encoding='utf-8').splitlines()}
        self.assertEqual(exported, {W.case(n) for n in CP2})  # never the CP1 row
        man = json.loads((out / 'GOLD_EXPORT_MANIFEST.json').read_text(encoding='utf-8'))
        self.assertEqual(man['confirmation_channels'], {'independent_human_batch': len(CP2)})
        report = gx.load_verifier().verify(out, result['gold_export_manifest_sha256'])
        self.assertEqual(report['result'], 'PASS', report['errors'])
        self.assertTrue(report['label_correctness'].startswith('NOT VERIFIED'))

    def test_attestation_of_a_substituted_artifact_is_refused(self):
        path = self.addendum(package_sha=sha('a different package'))
        with self.assertRaises(gx.ExportError) as ctx:
            gx.plan(self.src(), [json.loads(path.read_text(encoding='utf-8'))], [])
        self.assertTrue(has(ctx.exception.errors, 'not among the reviewed artifacts'))
        from scripts_cp2 import validate_gold_addendum as cli
        argv = ['--strict', '--exports', self.pkg / 'exports', '--addendum', path, '--anchor', self.anchor,
                '--allowed-signers', self.signers, '--trusted-key-fpr', self.pin, '--signer', SIGNER]
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main([str(x) for x in argv])
        self.assertEqual(code, 1)
        self.assertTrue(has(json.loads(buf.getvalue())['errors'], 'not among the reviewed artifacts'))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main([str(x) for x in argv[:4] + [self.addendum()] + argv[5:]]), 0)

    def test_verifier_detects_a_rewritten_attestation(self):
        path = self.addendum()
        p = gx.plan(self.src(), [json.loads(path.read_text(encoding='utf-8'))], [])
        auth = W.write(self.dir / 'in' / 'auth.json', json.dumps(W.authorization(p)))
        gx.build(self.src(), [path], [], auth, self.dir / 'out' / 'export', repo_root=ROOT.parents[1])
        out = self.dir / 'out' / 'export'
        apath = out / 'addenda' / 'addendum-v1.json'
        a = json.loads(apath.read_text(encoding='utf-8'))
        a['entries'] = [x for x in a['entries'] if x['case_id'] != W.case(1)] + [
            x for x in a['entries'] if x['case_id'] == W.case(1)]
        a['batch_attestations'][0]['case_count'] = len(CP2) + 1
        apath.write_text(json.dumps(a), encoding='utf-8')
        man = json.loads((out / 'GOLD_EXPORT_MANIFEST.json').read_text(encoding='utf-8'))
        man['files_sha256']['addenda/addendum-v1.json'] = file_sha(apath)
        man['addenda'][0]['sha256'] = sha(a)
        (out / 'GOLD_EXPORT_MANIFEST.json').write_text(json.dumps(man), encoding='utf-8')
        report = gx.load_verifier().verify(out)
        self.assertTrue(has(report['errors'], 'confirmed cases differ from the attested case set'))
        self.assertEqual(report['self_consistency'], 'FAIL')
        shutil.rmtree(out)


if __name__ == '__main__':
    unittest.main()
