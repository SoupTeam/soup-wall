"""Freeze CLI (scripts_cp2/freeze_manifest.py, sou13cp2/freeze_cli.py) on ISOLATED temporary copies only, plus the
anchor-verification attempt log. The repository's real DRAFT manifests must be byte-identical before and after."""
import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sou13.hashing import sha
from sou13cp2 import ROOT
from sou13cp2 import freeze_cli
from sou13cp2.freeze_cli import FULL_MANIFEST_FILE, LOG_NAME, run
from sou13cp2.splits import build_manifest, is_frozen, manifest_errors
from sou13cp2.taxonomy import families
from _testsupport import CP2_PUBLIC_VIEW, FULL_MANIFEST, RESTRICTED_FAMILIES, missing, requires

REAL = [ROOT / FULL_MANIFEST_FILE, ROOT / 'cp2/manifests/split_manifest.PUBLIC_VIEW.json']
OK = dict(approved_by='@test_owner', approved_at='2026-10-11T09:00:00+05:00', decision_ref='TEST-ONLY-not-an-approval')
_before = {}


def setUpModule():
    if missing(FULL_MANIFEST, CP2_PUBLIC_VIEW):
        return  # every class below is skipped (or, in strict mode, errors on the missing file)
    _before.update({p: hashlib.sha256(p.read_bytes()).hexdigest() for p in REAL})


def tearDownModule():
    for p, digest in _before.items():
        assert hashlib.sha256(p.read_bytes()).hexdigest() == digest, f'{p} was modified by the tests'


@requires(FULL_MANIFEST, CP2_PUBLIC_VIEW, RESTRICTED_FAMILIES)
class FreezeCli(unittest.TestCase):
    """The CLI on an independently built DRAFT manifest in an isolated root. The repository manifest is already
    FROZEN (owner freeze), so it cannot serve as the draft input; it is only copied for the refusal check."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.root = base / 'repo_copy'
        (self.root / FULL_MANIFEST_FILE).parent.mkdir(parents=True)
        draft = build_manifest(families())
        assert not is_frozen(draft) and manifest_errors(draft, families()) == []
        (self.root / FULL_MANIFEST_FILE).write_bytes(freeze_cli.dump(draft))
        self.path = self.root / FULL_MANIFEST_FILE
        self.original = self.path.read_bytes()
        self.backup = base / 'backup_outside'
        self.log = base / 'dryrun_log.jsonl'

    def tearDown(self):
        self.tmp.cleanup()

    def log_lines(self, p):
        return Path(p).read_text(encoding='utf-8').splitlines() if Path(p).exists() else []

    def test_dry_run_is_default_and_writes_nothing(self):
        code, rep = run(root=self.root, log_path=self.log, **OK)
        self.assertEqual(code, 0)
        self.assertIn('would_freeze', rep['result'])
        self.assertTrue(rep['family_split_unchanged'])
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(json.loads(self.log_lines(self.log)[-1])['mode'], 'dry-run')

    def test_invalid_approvals_refused(self):
        bad = [dict(OK, approved_by=''), dict(OK, approved_by='owner'), dict(OK, approved_at='2026-10-11T09:00:00'),
               dict(OK, approved_at='yesterday'), dict(OK, approved_at='2099-01-01T00:00:00+00:00'),
               dict(OK, decision_ref=''), dict(OK, decision_ref='x')]
        for args in bad:
            code, rep = run(root=self.root, execute=True, backup_dir=self.backup, **args)
            self.assertEqual((code, rep['result']), (2, 'refused'), args)
            self.assertEqual(self.path.read_bytes(), self.original)
        records = [json.loads(x) for x in self.log_lines(self.backup / LOG_NAME)]
        self.assertEqual(len(records), len(bad))
        self.assertTrue(all(r['result'] == 'refused' and r['errors'] for r in records))

    def test_execute_requires_backup_outside_repository(self):
        code, rep = run(root=self.root, execute=True, **OK)
        self.assertEqual(code, 2)
        self.assertTrue(any('--backup-dir' in e for e in rep['errors']))
        code, rep = run(root=self.root, execute=True, backup_dir=self.root / 'inside', **OK)
        self.assertEqual(code, 2)
        self.assertTrue(any('outside the repository' in e for e in rep['errors']))
        self.assertFalse((self.root / 'inside').exists())
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_execute_freezes_isolated_copy_and_preserves_assignment(self):
        draft = json.loads(self.original)
        code, rep = run(root=self.root, execute=True, backup_dir=self.backup, **OK)
        self.assertEqual((code, rep['result']), (0, 'frozen'), rep)
        new = json.loads(self.path.read_text(encoding='utf-8'))
        self.assertTrue(is_frozen(new))
        self.assertEqual(manifest_errors(new, families()), [])
        self.assertEqual(new['family_split'], draft['family_split'])
        self.assertEqual(new['freeze_record']['approved_by'], '@test_owner')
        self.assertEqual(Path(rep['backup']).read_bytes(), self.original)
        self.assertEqual(json.loads(self.log_lines(self.backup / LOG_NAME)[-1])['result'], 'frozen')
        self.assertFalse(list(self.path.parent.glob('*.freeze-tmp')))

    def test_repeated_execution_refused(self):
        self.assertEqual(run(root=self.root, execute=True, backup_dir=self.backup, **OK)[0], 0)
        frozen_bytes = self.path.read_bytes()
        code, rep = run(root=self.root, execute=True, backup_dir=self.backup, **OK)
        self.assertEqual(code, 2)
        self.assertTrue(any('already FROZEN' in e for e in rep['errors']))
        self.assertEqual(self.path.read_bytes(), frozen_bytes)

    def test_incomplete_or_tampered_manifest_refused(self):
        draft = json.loads(self.original)
        mutants = []
        m = copy.deepcopy(draft)
        m['family_split'].pop(sorted(m['family_split'])[0])  # incomplete
        mutants.append(m)
        m = copy.deepcopy(draft)
        m['family_split']['fam.read.wiki_page_get'] = 'calibration'  # assignment edited, sha not recomputed
        mutants.append(m)
        m = copy.deepcopy(draft)
        m['family_split']['fam.read.wiki_page_get'] = 'calibration'
        m['manifest_sha256'] = sha({k: v for k, v in m.items() if k != 'manifest_sha256'})  # sha recomputed
        mutants.append(m)
        for mutant in mutants:
            data = json.dumps(mutant, indent=2, sort_keys=True).encode('utf-8')
            self.path.write_bytes(data)
            code, rep = run(root=self.root, execute=True, backup_dir=self.backup, **OK)
            self.assertEqual(code, 2, rep)
            self.assertTrue(any('invalid or incomplete' in e for e in rep['errors']), rep)
            self.assertEqual(self.path.read_bytes(), data)

    def test_interrupted_atomic_replace_restores_original(self):
        with mock.patch.object(freeze_cli.os, 'replace', side_effect=OSError('simulated crash during replace')):
            code, rep = run(root=self.root, execute=True, backup_dir=self.backup, **OK)
        self.assertEqual((code, rep['result'], rep['original_restored']), (1, 'failed', True))
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertFalse(list(self.path.parent.glob('*.freeze-tmp')))
        self.assertEqual(json.loads(self.log_lines(self.backup / LOG_NAME)[-1])['result'], 'failed')

    def test_failed_post_write_verification_restores_original(self):
        with mock.patch.object(freeze_cli, '_post_write_check', side_effect=RuntimeError('simulated verify failure')):
            code, rep = run(root=self.root, execute=True, backup_dir=self.backup, **OK)
        self.assertEqual((code, rep['result']), (1, 'failed'))
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertFalse(is_frozen(json.loads(self.original)))

    def test_audit_log_is_append_only(self):
        run(root=self.root, execute=True, backup_dir=self.backup, **dict(OK, approved_by='bad'))
        first = self.log_lines(self.backup / LOG_NAME)
        run(root=self.root, execute=True, backup_dir=self.backup, **OK)
        run(root=self.root, execute=True, backup_dir=self.backup, **OK)  # repeated -> refused, still logged
        lines = self.log_lines(self.backup / LOG_NAME)
        self.assertEqual(lines[:len(first)], first)
        self.assertEqual([json.loads(x)['result'] for x in lines], ['refused', 'frozen', 'refused'])

    def test_copy_of_the_frozen_repository_manifest_is_refused(self):
        shutil.copy(ROOT / FULL_MANIFEST_FILE, self.path)
        frozen_bytes = self.path.read_bytes()
        self.assertTrue(is_frozen(json.loads(frozen_bytes)))
        code, rep = run(root=self.root, execute=True, backup_dir=self.backup, **OK)
        self.assertEqual((code, rep['result']), (2, 'refused'))
        self.assertTrue(any('already FROZEN' in e for e in rep['errors']))
        self.assertEqual(self.path.read_bytes(), frozen_bytes)

    def test_dry_run_log_inside_repository_refused(self):
        code, rep = run(root=self.root, log_path=self.root / 'log.jsonl', **OK)
        self.assertEqual(code, 2)
        self.assertFalse((self.root / 'log.jsonl').exists())


@requires(FULL_MANIFEST, CP2_PUBLIC_VIEW)
class AnchorAttemptLog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from _sshkeys import SSH_KEYGEN
        if not SSH_KEYGEN:
            raise unittest.SkipTest('ssh-keygen required')

    def setUp(self):
        from _sshkeys import allowed_signers, fingerprint, make_key, sign
        from sou13cp2.anchor import anchor_document
        from sou13cp2.pipeline import current_artefact_digests
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.draft = json.loads((ROOT / FULL_MANIFEST_FILE).read_text(encoding='utf-8'))
        self.view = json.loads((ROOT / 'cp2/manifests/split_manifest.PUBLIC_VIEW.json').read_text(encoding='utf-8'))
        key = make_key(d, 'owner')
        self.signers = allowed_signers(d, 'owner@test', key)
        self.anchor = d / 'anchor.json'
        self.anchor.write_text(json.dumps(anchor_document(
            full_manifest=self.draft, public_view=self.view, artefact_digests=current_artefact_digests(ROOT),
            approved_by='@test', approved_at='2026-10-11T00:00:00+05:00', decision_ref='TEST-ONLY')), encoding='utf-8')
        self.sig = sign(key, self.anchor)
        self.cfg = {'anchor': str(self.anchor), 'signature': str(self.sig), 'allowed_signers': str(self.signers),
                    'trusted_key_fpr': fingerprint(self.signers), 'signer': 'owner@test', 'attempt_log': None}
        self.log = d / 'anchor_attempts.jsonl'

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, cfg):
        from sou13cp2.pipeline import trust_anchor_check
        return trust_anchor_check(ROOT, 'full', self.draft, self.view, cfg)

    def test_successful_attempt_recorded(self):
        status, errors = self.check(self.cfg)
        self.assertEqual(errors, [])
        rec = [json.loads(x) for x in self.log.read_text(encoding='utf-8').splitlines()]
        self.assertEqual(len(rec), 1)
        self.assertTrue(rec[0]['ok'])

    def test_failed_attempt_recorded_not_discarded(self):
        bad = dict(self.cfg, trusted_key_fpr='SHA256:' + 'A' * 43)
        status, errors = self.check(bad)
        self.assertEqual(status, 'FAILED')
        self.check(dict(self.cfg, signer='someone-else'))
        rec = [json.loads(x) for x in self.log.read_text(encoding='utf-8').splitlines()]
        self.assertEqual([r['ok'] for r in rec], [False, False])
        self.assertTrue(all(r['errors'] and r['anchor_sha256'] and r['signature_sha256'] for r in rec))
        self.assertTrue(self.anchor.exists() and self.sig.exists())  # failed anchor/signature are kept

    def test_attempt_log_inside_repository_refused(self):
        inside = ROOT / 'cp2' / 'anchor_attempts.TEST.jsonl'
        status, errors = self.check(dict(self.cfg, attempt_log=str(inside)))
        self.assertTrue(any('attempt log must be outside the repository' in e for e in errors), errors)
        self.assertFalse(inside.exists())


if __name__ == '__main__':
    unittest.main()
