"""Audit F6: coordinated program/label/manifest forgery. Self-consistency cannot catch it; a MANIFEST digest obtained
from outside the package (owner-signed anchor or published value) does. Label correctness is never claimed."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sou13.hashing import sha
from sou13cp2 import ROOT, restricted
from _testsupport import CP1_DATA, CP2_PUBLIC, SEALED_COMMITTED, requires
from sou13cp2.anchor import NAMESPACE
from _sshkeys import SSH_KEYGEN, allowed_signers, fingerprint, make_key, sign

A = ('read', 'write', 'delete', 'send_data', 'change_permissions')


def run_verifier(pkg, *args):
    p = subprocess.run([sys.executable, '-I', '-B', 'verify_package.py', *args], cwd=pkg, capture_output=True,
                       text=True)
    return p.returncode, json.loads(p.stdout)


def rewrite_manifest(pkg):
    man = json.loads((pkg / 'MANIFEST.json').read_text(encoding='utf-8'))
    man['files_sha256'] = {k: hashlib.sha256((pkg / k).read_bytes()).hexdigest() for k in man['files_sha256']}
    (pkg / 'MANIFEST.json').write_text(json.dumps(man, indent=2, sort_keys=True) + '\n', encoding='utf-8')


@requires(CP1_DATA, CP2_PUBLIC, SEALED_COMMITTED)
class PackageIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from sou13cp2.handoff import DEV, build_packages
        cls.tmp = tempfile.TemporaryDirectory()
        out = Path(cls.tmp.name) / 'handoff'
        cls.result = build_packages(out)
        cls.clean = out / DEV
        cls.expected = cls.result['package_manifest_sha256']['dev_review_package']

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def copy(self, name):
        dst = Path(self.tmp.name) / name
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(self.clean, dst)
        return dst

    def forge(self, pkg, update_digest=True, update_registry=True, whole_family=True):
        """Turn a proven no-op family into 'delete'. A fully coordinated attacker rewrites every record of the family,
        the registry and MANIFEST.json; whole_family=False forges a single record only."""
        sys.path.insert(0, str(pkg / 'tools'))
        try:
            from semantics import execute
        finally:
            sys.path.pop(0)
        data = pkg / 'data' / 'candidates.jsonl'
        rows = [json.loads(x) for x in data.read_text(encoding='utf-8').splitlines() if x]
        family = [x for x in rows if x['family_id'] == 'fam.no_effect.json_validate']
        for r in (family if whole_family else family[:1]):
            r['evidence']['program'] = r['evidence']['program'] + [{'op': 'delete', 'store': 'docs', 'key': 'forged'}]
            if update_digest:
                r['evidence']['semantics_sha256'] = sha(r['evidence']['program'])
            r['evidence']['execution'] = execute(r['evidence']['program'], r['input']['raw_arguments'])
            r['annotation']['per_action_targets'] = {x: x == 'delete' for x in A}
            r['annotation']['known_mask'] = {x: 1 for x in A}
            r['annotation']['contract_view'] = {'actions': ['delete'], 'unknown': False}
        data.write_text(''.join(json.dumps(x, sort_keys=True, ensure_ascii=False) + '\n' for x in rows),
                        encoding='utf-8')
        if update_registry:
            reg_p = pkg / 'SEMANTICS_REGISTRY.json'
            reg = json.loads(reg_p.read_text(encoding='utf-8'))
            reg['program_sha256'][family[0]['family_id']] = family[0]['evidence']['semantics_sha256']
            reg_p.write_text(json.dumps(reg, indent=1, sort_keys=True) + '\n', encoding='utf-8')
        rewrite_manifest(pkg)

    def test_partial_forgery_caught_by_registry(self):
        pkg = self.copy('forged_partial')
        self.forge(pkg, whole_family=False)  # one record forged, registry updated: siblings now disagree
        code, out = run_verifier(pkg)
        self.assertEqual((code, out['self_consistency']), (1, 'FAIL'))
        self.assertTrue(any('not the registered semantics' in e for e in out['errors']))

    def test_clean_package_unanchored_is_not_a_pass(self):
        code, out = run_verifier(self.copy('clean1'))
        self.assertEqual((code, out['self_consistency'], out['anchored_integrity'], out['result']),
                         (3, 'PASS', 'UNVERIFIED', 'UNVERIFIED'))
        self.assertTrue(out['label_correctness'].startswith('NOT_VERIFIED'))

    def test_clean_package_with_trusted_digest_passes(self):
        code, out = run_verifier(self.copy('clean2'), '--expect-manifest-sha256', self.expected)
        self.assertEqual((code, out['result'], out['anchored_integrity']), (0, 'PASS', 'PASS'))
        self.assertTrue(out['label_correctness'].startswith('NOT_VERIFIED'))

    def test_reproduce_F6_coordinated_forgery_is_self_consistent(self):
        pkg = self.copy('forged1')
        self.forge(pkg)
        code, out = run_verifier(pkg)
        self.assertEqual(out['self_consistency'], 'PASS')  # the audit finding: self-checks are rewritten together
        self.assertEqual(code, 3)

    def test_coordinated_forgery_fails_against_trusted_digest(self):
        pkg = self.copy('forged2')
        self.forge(pkg)
        code, out = run_verifier(pkg, '--expect-manifest-sha256', self.expected)
        self.assertEqual((code, out['anchored_integrity'], out['result']), (1, 'FAIL', 'FAIL'))

    def test_program_changed_without_digest_fails_self_consistency(self):
        pkg = self.copy('forged3')
        self.forge(pkg, update_digest=False, update_registry=False)
        code, out = run_verifier(pkg)
        self.assertEqual((code, out['self_consistency']), (1, 'FAIL'))
        self.assertTrue(any('semantics_sha256 does not match the stored program' in e for e in out['errors']))

    def test_program_not_in_registry_fails_self_consistency(self):
        pkg = self.copy('forged4')
        self.forge(pkg, update_digest=True, update_registry=False)
        code, out = run_verifier(pkg)
        self.assertEqual(code, 1)
        self.assertTrue(any('not the registered semantics' in e for e in out['errors']))

    @unittest.skipUnless(SSH_KEYGEN, 'ssh-keygen required')
    def test_signed_anchor_path(self):
        keys = Path(self.tmp.name) / 'owner_keys'
        keys.mkdir(exist_ok=True)
        key = make_key(keys, 'owner')
        signers = allowed_signers(keys, 'owner@test', key)
        anchor = keys / 'anchor.json'
        anchor.write_text(json.dumps({'anchor_kind': 'sou13_cp2_freeze_anchor', 'namespace': NAMESPACE,
                                      'package_manifest_sha256': {'dev_review_package': self.expected}}),
                          encoding='utf-8')
        sign(key, anchor)
        trust = ['--anchor', str(anchor), '--allowed-signers', str(signers), '--trusted-key-fpr', fingerprint(signers),
                 '--signer', 'owner@test']
        code, out = run_verifier(self.copy('clean3'), *trust)
        self.assertEqual((code, out['result']), (0, 'PASS'))
        forged = self.copy('forged5')
        self.forge(forged)
        code, out = run_verifier(forged, *trust)
        self.assertEqual((code, out['anchored_integrity']), (1, 'FAIL'))
        inside = self.copy('clean4')
        inside_signers = allowed_signers(inside, 'owner@test', key)
        trust_inside = trust[:2] + ['--allowed-signers', str(inside_signers)] + trust[4:]
        code, out = run_verifier(inside, *trust_inside)
        self.assertEqual(code, 1)
        self.assertIn('must not come from inside the package', out['anchor_error'])


if __name__ == '__main__':
    unittest.main()
