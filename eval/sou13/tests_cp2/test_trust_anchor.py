"""Audit F2: coordinated manifest tampering defeats internal self-hashes; an owner-signed anchor verified against an
independently PINNED owner key detects it. Test keys are generated in temporary directories only."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from sou13.hashing import sha
from sou13cp2 import ROOT
from _testsupport import SEALED_COMMITTED, requires
from sou13cp2.anchor import anchor_digest_errors, anchor_document, verify_anchor
from sou13cp2.pipeline import commitments, current_artefact_digests, trust_anchor_check
from sou13cp2.splits import _sign, build_manifest, freeze, manifest_errors, public_view
from sou13cp2.taxonomy import families
from _sshkeys import SSH_KEYGEN, allowed_signers, fingerprint, make_key, sign

APPROVAL = dict(approved_by='TEST-ONLY owner', approved_at='2026-10-11T00:00:00+05:00', decision_ref='unit test')
SIGNER = 'owner@sou13-test'


def coordinated_tamper(frozen, a='fam.read.wiki_page_get', b='fam.read.object_stat'):
    """Swap two families' splits and recompute EVERY internal hash an attacker can reach."""
    t = copy.deepcopy(frozen)
    sa, sb = t['family_split'][a], t['family_split'][b]
    t['family_split'][a], t['family_split'][b] = sb, sa
    for g in t['groups']:
        if a in g['families']:
            g['split'] = sb
        elif b in g['families']:
            g['split'] = sa
    t['freeze_record']['frozen_assignment'] = dict(sorted(t['family_split'].items()))
    t['freeze_record']['frozen_assignment_sha256'] = sha(dict(sorted(t['family_split'].items())))
    return _sign(t)


@unittest.skipUnless(SSH_KEYGEN, 'ssh-keygen with -Y sign/verify is required')
@requires(SEALED_COMMITTED)  # setUpClass builds the public view from the custodian commitments
class TrustAnchor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        cls.fams = families()
        cls.frozen = freeze(build_manifest(cls.fams), cls.fams, **APPROVAL)
        cls.view = public_view(cls.frozen, cls.fams, commitments(ROOT))
        cls.owner_key = make_key(cls.dir, 'owner')
        cls.signers = allowed_signers(cls.dir, SIGNER, cls.owner_key)
        cls.pin = fingerprint(cls.signers)
        cls.anchor = cls.dir / 'anchor.json'
        cls.anchor.write_text(json.dumps(anchor_document(
            full_manifest=cls.frozen, public_view=cls.view, artefact_digests=current_artefact_digests(ROOT),
            **APPROVAL), sort_keys=True), encoding='utf-8')
        cls.sig = sign(cls.owner_key, cls.anchor)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def cfg(self, **kw):
        base = {'anchor': str(self.anchor), 'signature': str(self.sig), 'allowed_signers': str(self.signers),
                'trusted_key_fpr': self.pin, 'signer': SIGNER}
        return {**base, **kw}

    def test_reproduce_F2_internal_hashes_accept_coordinated_tampering(self):
        tampered = coordinated_tamper(self.frozen)
        self.assertNotEqual(tampered['family_split'], self.frozen['family_split'])
        self.assertEqual(manifest_errors(tampered, self.fams), [])  # the audit finding: self-hashes are not enough

    def test_honest_anchor_verifies_against_pinned_owner_key(self):
        anchor, errors = verify_anchor(self.cfg(), [ROOT])
        self.assertEqual(errors, [])
        self.assertEqual(anchor_digest_errors(anchor, full_manifest=self.frozen, public_view=self.view), [])

    def test_coordinated_tampering_detected_by_signed_anchor(self):
        anchor, _ = verify_anchor(self.cfg(), [ROOT])
        errors = anchor_digest_errors(anchor, full_manifest=coordinated_tamper(self.frozen))
        self.assertTrue(any('full manifest differs' in e for e in errors), errors)
        self.assertTrue(any('frozen assignment differs' in e for e in errors), errors)

    def test_attacker_resigned_anchor_rejected(self):
        evil_dir = self.dir / 'evil'
        evil_dir.mkdir(exist_ok=True)
        evil_key = make_key(evil_dir, 'attacker')
        forged = evil_dir / 'anchor.json'
        doc = json.loads(self.anchor.read_text(encoding='utf-8'))
        doc['full_manifest_sha256'] = coordinated_tamper(self.frozen)['manifest_sha256']
        forged.write_text(json.dumps(doc, sort_keys=True), encoding='utf-8')
        evil_sig = sign(evil_key, forged)
        _, errors = verify_anchor(self.cfg(anchor=str(forged), signature=str(evil_sig)), [ROOT])
        self.assertTrue(any('does not verify against the pinned owner key' in e for e in errors), errors)

    def test_edited_anchor_with_original_signature_rejected(self):
        edited = self.dir / 'edited.json'
        doc = json.loads(self.anchor.read_text(encoding='utf-8'))
        doc['full_manifest_sha256'] = '0' * 64
        edited.write_text(json.dumps(doc, sort_keys=True), encoding='utf-8')
        _, errors = verify_anchor(self.cfg(anchor=str(edited)), [ROOT])
        self.assertTrue(errors)

    def test_trust_config_inside_verified_root_rejected(self):
        pkg = self.dir / 'package_under_verification'
        pkg.mkdir(exist_ok=True)
        inside = allowed_signers(pkg, SIGNER, self.owner_key)  # even the REAL key is refused from inside the package
        _, errors = verify_anchor(self.cfg(allowed_signers=str(inside)), [pkg])
        self.assertTrue(any('must not come from the repository/package' in e for e in errors), errors)

    def test_substituted_external_signers_file_fails_pin(self):
        evil_dir = self.dir / 'evil2'
        evil_dir.mkdir(exist_ok=True)
        evil_key = make_key(evil_dir, 'attacker2')
        evil_signers = allowed_signers(evil_dir, SIGNER, evil_key)
        evil_anchor = evil_dir / 'anchor.json'
        evil_anchor.write_text(self.anchor.read_text(encoding='utf-8'), encoding='utf-8')
        evil_sig = sign(evil_key, evil_anchor)
        _, errors = verify_anchor(self.cfg(anchor=str(evil_anchor), signature=str(evil_sig),
                                           allowed_signers=str(evil_signers)), [ROOT])
        self.assertTrue(any('do not match the pinned owner key' in e for e in errors), errors)

    def test_wrong_namespace_rejected(self):
        other = self.dir / 'ns.json'
        other.write_text(self.anchor.read_text(encoding='utf-8'), encoding='utf-8')
        ns_sig = sign(self.owner_key, other, namespace='some-other-namespace')
        _, errors = verify_anchor(self.cfg(anchor=str(other), signature=str(ns_sig)), [ROOT])
        self.assertTrue(errors)

    def test_frozen_manifest_without_anchor_is_an_error(self):
        empty = {k: None for k in ('anchor', 'signature', 'allowed_signers', 'trusted_key_fpr', 'signer')}
        status, errors = trust_anchor_check(ROOT, 'full', self.frozen, self.view, empty)
        self.assertEqual(status, 'FAILED')
        self.assertTrue(any('do not authenticate the owner' in e for e in errors), errors)

    def test_draft_without_anchor_is_reported_unanchored(self):
        empty = {k: None for k in ('anchor', 'signature', 'allowed_signers', 'trusted_key_fpr', 'signer')}
        draft = build_manifest(self.fams)
        status, errors = trust_anchor_check(ROOT, 'full', draft, self.view, empty)
        self.assertEqual(errors, [])
        self.assertTrue(status.startswith('unanchored DRAFT'))


if __name__ == '__main__':
    unittest.main()
