"""sou35.release CLI on ARTIFICIAL toy families: full custodian flow plus every refusal path.

Runs in a uniquely named, git-ignored sealed/ workspace that is removed afterwards."""
import contextlib
import hashlib
import io
import json
import shutil
import unittest
import uuid
import zipfile

from _util import ROOT, TOY_DIR
from test_release_workflow import TOY_VAULT, rulings_for

from sou35 import custody, export, families, generate, release

COUNTS = '1/1/1/1'


class ReleaseCli(unittest.TestCase):
    def setUp(self):
        self.sealed_existed = (ROOT / 'sealed').exists()
        self.private_existed = (ROOT / 'private').exists()
        self.ws = ROOT / 'sealed' / f'_test_cli_{uuid.uuid4().hex}'
        self.out = ROOT / 'private' / f'_test_cli_export_{uuid.uuid4().hex}'
        pool = self.ws / 'pool'
        pool.mkdir(parents=True)
        for p in TOY_DIR.glob('*.json'):
            shutil.copy(p, pool / p.name)
        (pool / 'toy_vault.json').write_text(json.dumps(TOY_VAULT), encoding='utf-8')
        decls = families.load_dir(pool)
        self.recs = generate.generate(decls, {})
        self.register_file = self.ws / 'toy_rulings.json'
        self.register_file.write_text(json.dumps(rulings_for(decls, self.recs)), encoding='utf-8')
        # Artificial reviewer supplement: the CLI must verify the actual archive,
        # not just trust a mutable first-commit policy file.
        banned_toy = 'f35.write.toy_batch'
        group = next(r['leakage_group_id'] for r in self.recs if r['family_id'] == banned_toy)
        self.toy_review_package = self.ws / 'toy_review_supplement.zip'
        restriction = {'test_allowed': False, 'family_count': 1, 'leakage_group_count': 1,
                       'families': [{'family_id': banned_toy, 'leakage_group_id': group}]}
        with zipfile.ZipFile(self.toy_review_package, 'w') as archive:
            archive.writestr('near_transfer_test_exclusions.PRIVATE.json', json.dumps(restriction))
        review_sha = hashlib.sha256(self.toy_review_package.read_bytes()).hexdigest()
        self.exclusion_policy = self.ws / 'toy_test_exclusions.json'
        self.exclusion_policy.write_text(json.dumps({
            'policy_version': 'sou35-test-exclusions-v1',
            'pool_digest': custody.pool_digest(decls),
            'source_review_package_sha256': review_sha,
            'source_review_package_path': str(self.toy_review_package),
            'excluded_family_ids': [banned_toy],
        }), encoding='utf-8')
        self.records = self.ws / 'records.jsonl'
        self.records.write_text(''.join(json.dumps(r) + '\n' for r in self.recs), encoding='utf-8')
        self.common = ['--workspace', str(self.ws), '--pool', str(pool), '--records', str(self.records), '--rulings', str(self.register_file), '--test-exclusions', str(self.exclusion_policy)]

    def tearDown(self):
        for path, existed in ((self.ws, None), (self.out, None)):
            if path.exists():
                shutil.rmtree(path)
        for name, existed in (('sealed', self.sealed_existed), ('private', self.private_existed)):
            d = ROOT / name
            if not existed and d.exists() and not any(d.iterdir()):
                d.rmdir()

    def cli(self, command, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = release.main([command, *self.common, *extra])
        return code, out.getvalue(), err.getvalue()

    def ok(self, command, *extra):
        code, out, err = self.cli(command, *extra)
        self.assertEqual(code, 0, f'{command}: {err}')
        return out

    def refused(self, command, *extra):
        code, out, err = self.cli(command, *extra)
        self.assertEqual(code, 1, f'{command} should be refused')
        self.assertIn('REFUSED', err)
        for fid in self.test_families():
            self.assertNotIn(fid, err)  # refusals never name a test family
        return err

    def test_families(self):
        p = self.ws / release.PRIVATE
        return json.loads(p.read_text(encoding='utf-8')).get('test_families') or [] if p.exists() else []

    def to_drawn(self):
        self.ok('declare', '--custodian', 'toy-custodian', '--counts', COUNTS, '--held-out-features', 'technical_error')
        self.ok('commit')
        self.ok('draw', '--confirm')

    def accept(self):
        self.ok('accept', '--custodian', 'toy-custodian', '--accepted-at', '2026-10-16T00:00:00Z',
                '--decision-ref', 'TOY-CUSTODY-1')

    def freeze(self):
        return self.cli('freeze', '--approved-by', 'toy-approver', '--approved-at', '2026-10-16T01:00:00Z',
                        '--decision-ref', 'TOY-FREEZE-1', '--confirm')

    def auth(self, **over):
        m = json.loads((self.ws / release.FULL).read_text(encoding='utf-8'))
        a = {'scope': export.EXPORT_SCOPE, 'authorized_by': 'toy-authorizer', 'authorized_at': '2026-10-16T02:00:00Z',
             'decision_ref': 'TOY-EXPORT-1', 'manifest_sha256': m['manifest_sha256'],
             'rulings_sha256': m['rulings_sha256'], **over}
        p = self.ws / f'auth_{uuid.uuid4().hex}.json'
        p.write_text(json.dumps(a), encoding='utf-8')
        return str(p)

    def test_full_custodian_flow_and_boundaries(self):
        self.to_drawn()
        self.accept()
        self.ok('build-manifest', '--salt', 'toy-salt')
        self.assertEqual(self.freeze()[0], 0)
        self.ok('validate-manifest')
        self.ok('public-view')
        printed = self.ok('export', '--authorization', self.auth(), '--out', str(self.out))
        private = json.loads((self.ws / release.PRIVATE).read_text(encoding='utf-8'))
        test_ids = [r['id'] for r in self.recs if r['family_id'] in private['test_families']]
        secrets = private['test_families'] + test_ids + [private['seed'], private['nonce']]
        view = (self.ws / release.PUBLIC).read_text(encoding='utf-8')
        exported = ''.join(p.read_text(encoding='utf-8') for p in self.out.rglob('*') if p.is_file())
        for text, where in ((view, 'public view'), (exported, 'export'), (printed, 'stdout')):
            for s in secrets:
                self.assertNotIn(s, text, where)
            self.assertNotIn('frozen_assignment', text, where)  # the FULL manifest never leaves custody
        self.assertEqual(export.verify_export(self.out, test_ids), [])

    def test_refusals_before_freeze(self):
        self.refused('commit')                                    # nothing declared
        self.to_drawn()
        self.refused('draw', '--confirm')                         # already drawn
        self.ok('build-manifest', '--salt', 'toy-salt')
        self.refused('export', '--authorization', self.auth(), '--out', str(self.out))   # draft manifest
        code, _, err = self.freeze()
        self.assertEqual(code, 1)
        self.assertIn('custody must be accepted', err)           # missing custody acceptance
        self.accept()
        self.refused('freeze', '--approved-by', 'toy-approver', '--approved-at', 't', '--decision-ref', 'r')  # no --confirm

    def test_refusals_after_freeze(self):
        self.to_drawn()
        self.accept()
        self.ok('build-manifest', '--salt', 'toy-salt')
        self.assertEqual(self.freeze()[0], 0)
        out = ['--out', str(self.out)]
        self.refused('export', '--authorization', str(self.ws / 'missing.json'), *out)        # no authorization
        self.refused('export', '--authorization', self.auth(scope='sou35_test_export'), *out)  # restricted scope
        self.refused('export', '--authorization', self.auth(manifest_sha256='0' * 64), *out)   # other manifest
        self.refused('export', '--authorization', self.auth(authorized_by='ai_assisted_synthetic_draft'), *out)
        self.refused('export', '--authorization', self.auth(), '--out', str(ROOT / 'tests' / 'cli_out'))  # public path
        self.assertFalse((ROOT / 'tests' / 'cli_out').exists())
        self.assertFalse(self.out.exists())
        full = self.ws / release.FULL
        m = json.loads(full.read_text(encoding='utf-8'))
        m['salt'] = 'tampered'
        full.write_text(json.dumps(m), encoding='utf-8')                                     # tampered hash
        self.refused('validate-manifest')
        self.refused('public-view')
        self.refused('export', '--authorization', self.auth(), *out)

    def test_draw_requires_confirmation_and_records_must_match(self):
        self.ok('declare', '--custodian', 'toy-custodian', '--counts', COUNTS, '--held-out-features', 'technical_error')
        self.ok('commit')
        self.refused('draw')                                      # no --confirm
        lines = self.records.read_text(encoding='utf-8').splitlines()
        r = json.loads(lines[0])
        r['annotation']['unknown'] = not r['annotation']['unknown']
        self.records.write_text('\n'.join([json.dumps(r)] + lines[1:]) + '\n', encoding='utf-8')
        self.refused('draw', '--confirm')                         # tampered records are refused first

    def test_full_requirements_on_toys_are_impossible_not_relaxed(self):
        self.ok('declare', '--custodian', 'toy-custodian', '--counts', COUNTS)
        err = self.refused('commit')
        self.assertIn('IMPOSSIBLE', err)

    def test_explicit_private_test_exclusion_policy_is_required(self):
        common = list(self.common)
        self.common = [x for x in common if x not in ('--test-exclusions', str(self.exclusion_policy))]
        try:
            self.refused('declare', '--custodian', 'toy-custodian', '--counts', COUNTS,
                         '--held-out-features', 'technical_error')
        finally:
            self.common = common

    def test_private_test_exclusions_integrated_and_bound_after_commit(self):
        policy = json.loads(self.exclusion_policy.read_text(encoding='utf-8'))
        # Toy-only: one existing family restricted from test.
        policy['excluded_family_ids'] = ['f35.write.toy_batch']
        self.exclusion_policy.write_text(json.dumps(policy), encoding='utf-8')
        self.ok('declare', '--custodian', 'toy-custodian', '--counts', COUNTS,
                '--held-out-features', 'technical_error')
        self.ok('commit')
        policy['excluded_family_ids'] = []
        self.exclusion_policy.write_text(json.dumps(policy), encoding='utf-8')
        self.refused('draw', '--confirm')
        policy['excluded_family_ids'] = ['f35.write.toy_batch']
        self.exclusion_policy.write_text(json.dumps(policy), encoding='utf-8')
        self.ok('draw', '--confirm')
        self.assertNotIn('f35.write.toy_batch', self.test_families())

    def test_cannot_commit_against_empty_or_wrong_private_ban_list(self):
        saved = json.loads(self.exclusion_policy.read_text(encoding='utf-8'))
        for wrong in ([], ['f35.multimode.toy_switch']):
            changed = dict(saved, excluded_family_ids=wrong)
            self.exclusion_policy.write_text(json.dumps(changed), encoding='utf-8')
            self.refused('declare', '--custodian', 'toy-custodian', '--counts', COUNTS,
                         '--held-out-features', 'technical_error')
        self.exclusion_policy.write_text(json.dumps(saved), encoding='utf-8')

    def test_missing_or_tampered_original_review_package_is_refused(self):
        original = self.toy_review_package.read_bytes()
        self.toy_review_package.write_bytes(b'corrupted')
        try:
            self.refused('declare', '--custodian', 'toy-custodian', '--counts', COUNTS,
                         '--held-out-features', 'technical_error')
        finally:
            self.toy_review_package.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
