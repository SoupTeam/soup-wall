# SPDX-License-Identifier: Apache-2.0
"""Custody and local publication-spy controls; never product acceptance."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import validate_candidate as gate
from roadmap_support import Invalid


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / 'dist'
        self.dist.mkdir()
        self.bundle = self.root / 'bundle'
        self.bundle.mkdir()
        self.source = 'a' * 40
        self.tag = 'v0.3.0'
        self.recpath = self.root / 'record.json'
        self.apipath = self.root / 'api.json'
        self.manpath = self.dist / 'candidate-manifest.json'
        self.indexpath = self.bundle / 'readiness-index.json'
        self.indexpath.write_bytes(b'{}')
        self.approval = self.root / 'approval.json'
        self.approval.write_bytes(b'{}')
        sums = []
        for name in gate.names(self.tag):
            raw = ('synthetic custody fixture: ' + name).encode()
            (self.dist / name).write_bytes(raw)
            sums.append(hashlib.sha256(raw).hexdigest() + '  ' + name)
        self.man = {'tag': self.tag, 'source_sha': self.source, 'run_attempt': '1', 'checksums': sums}
        self.rec = {'decision': 'approved', 'run_id': '123', 'run_attempt': '1', 'artifact_id': '999',
            'artifact_digest': 'b' * 64, 'source_sha': self.source, 'checksums': sums.copy(),
            'evidence_ref': 'synthetic-verifier-control',
            'gates': {'product': 'passed', 'operator': 'passed', 'license': 'passed'},
            'readiness': {'artifact_id': '888', 'archive_sha256': 'c' * 64,
                          'index_sha256': hashlib.sha256(b'{}').hexdigest()}}
        self.api = {'run_id': '123', 'run_attempt': '1', 'workflow_path': '.github/workflows/release.yml',
            'event': 'push', 'repository': 'SoupTeam/soup-wall', 'prepare_job_status': 'success',
            'artifact_id': '999', 'status': 'completed', 'conclusion': 'success',
            'head_sha': self.source, 'head_branch': self.tag}
        self.write()

    def write(self):
        for path, value in ((self.recpath, self.rec), (self.apipath, self.api), (self.manpath, self.man)):
            path.write_text(json.dumps(value), encoding='utf-8')

    def args(self):
        return [self.recpath, self.manpath, self.tag, self.source, self.apipath, 'full',
                self.indexpath, self.bundle, self.approval, ROOT]

    def refused(self, expected):
        """Both owned spies stay uncalled when the real validator refuses."""
        registry, release = Mock(name='owned_registry_spy'), Mock(name='owned_release_spy')
        with self.assertRaisesRegex(Invalid, expected):
            gate.validate(*self.args())
            registry()
            release()
        registry.assert_not_called()
        release.assert_not_called()

    def test_api_only_is_explicitly_not_publication_admission(self):
        result = gate.validate(*self.args()[:5], mode='api-only')
        self.assertEqual(result['status'], 'identity-verified')
        self.assertIn('publication not admitted', result['meaning'])

    def test_positive_custody_seam_and_repeated_changed_bytes_refusal(self):
        # The mocked readiness seam proves custody only, not real product readiness.
        with patch('publication_readiness.verify', return_value={'status': 'admitted', 'blockers': []}) as verifier:
            result = gate.validate(*self.args())
            self.assertEqual(result['artifact_count'], 11)
            verifier.assert_called_once()
            (self.dist / gate.names(self.tag)[0]).write_bytes(b'changed after review')
            self.refused('artifact_checksum_mismatch')

    def test_all_original_api_identity_boundaries_and_stale_attempt(self):
        original = copy.deepcopy(self.api)
        changes = {'workflow_path': '.github/workflows/other.yml', 'repository': 'other/repo',
                   'event': 'pull_request', 'prepare_job_status': 'skipped', 'status': 'in_progress',
                   'conclusion': 'failure', 'head_sha': 'd' * 40, 'head_branch': 'v9.0.0',
                   'run_id': '456', 'run_attempt': '2', 'artifact_id': '777'}
        for key, value in changes.items():
            with self.subTest(key=key):
                self.api = dict(original, **{key: value})
                self.write()
                self.refused('untrusted_preparation_event' if key == 'event' else 'api_' + key + '_mismatch')
        for status in ('failure', 'missing', 'cancelled'):
            self.api = dict(original, prepare_job_status=status)
            self.write()
            self.refused('api_prepare_job_status_mismatch')

    def test_approval_and_three_gates_remain_required(self):
        original = copy.deepcopy(self.rec)
        for key in ('product', 'operator', 'license'):
            self.rec = copy.deepcopy(original)
            self.rec['gates'][key] = 'failed'
            self.write()
            self.refused('required_gate_not_passed')
        for key in ('decision', 'evidence_ref', 'artifact_digest', 'run_attempt'):
            self.rec = copy.deepcopy(original)
            del self.rec[key]
            self.write()
            self.refused('acceptance_record_fields')
        self.rec = dict(original, decision='rejected')
        self.write()
        self.refused('candidate_not_approved')

    def test_exact_inventory_alias_traversal_duplicate_extra_and_control_bytes(self):
        original = copy.deepcopy(self.man)
        cases = [original['checksums'][:-1], original['checksums'] + ['a' * 64 + '  extra.txt']]
        for replacement in (original['checksums'][0], 'a' * 64 + '  ../soup-wall-image.tar',
                'a' * 64 + '  unpublished-soup-wall-image.tar', 'a' * 64 + '  soup-wall-image.tar\nextra',
                'a' * 64 + '  soup-wall-image.tar\r', 'a' * 64 + '  soup-wall-image.tar\\alias'):
            cases.append(original['checksums'][:-1] + [replacement])
        for sums in cases:
            with self.subTest(sums=sums[-1]):
                self.man = dict(original, checksums=sums)
                self.rec['checksums'] = sums
                self.write()
                self.refused('exact_eleven|unsafe_or_duplicate|canonical_artifact|invalid_checksum')

    def test_manifest_stale_missing_attempt_wrong_source_and_approved_hashes(self):
        original = copy.deepcopy(self.man)
        for attempt in ('0', '2', None):
            self.man = dict(original, run_attempt=attempt)
            self.write()
            self.refused('manifest_attempt_mismatch')
        self.man = dict(original)
        del self.man['run_attempt']
        self.write()
        self.refused('manifest_fields')
        self.man = dict(original, source_sha='e' * 40)
        self.write()
        self.refused('manifest_source_or_tag_mismatch')
        self.man = copy.deepcopy(original)
        self.man['checksums'][0] = 'e' * 64 + '  ' + gate.names(self.tag)[0]
        self.write()
        self.refused('approved_checksums_mismatch')

    def test_missing_record_api_artifact_and_readiness(self):
        self.recpath.unlink()
        with self.assertRaises(OSError):
            gate.validate(*self.args())
        self.write()
        self.apipath.unlink()
        with self.assertRaises(OSError):
            gate.validate(*self.args())
        self.write()
        del self.rec['readiness']
        self.write()
        self.refused('readiness_attachment_required')

    def test_symlink_hardlink_and_missing_artifact_refuse(self):
        target = self.dist / gate.names(self.tag)[0]
        raw = target.read_bytes()
        target.unlink()
        with self.assertRaises(OSError):
            gate.validate(*self.args())
        other = self.root / 'other'
        other.write_bytes(raw)
        os.link(other, target)
        self.refused('unsafe_artifact_file')
        target.unlink()
        try:
            target.symlink_to(other)
        except OSError:
            return  # Native Windows may lack symlink privilege; hardlink control ran.
        self.refused('unsafe_artifact_file')

    def test_strict_json_duplicate_keys_unknown_fields_and_bounds(self):
        original = self.recpath.read_bytes()
        self.recpath.write_bytes(original[:-1] + b',"decision":"approved"}')
        with self.assertRaisesRegex(Invalid, 'duplicate JSON key'):
            gate.record(self.recpath)
        self.write()
        self.rec['unexpected'] = True
        self.write()
        self.refused('acceptance_record_fields')
        self.recpath.write_bytes(b' ' * (gate.MAX_JSON + 1))
        with self.assertRaisesRegex(Invalid, 'byte limit'):
            gate.record(self.recpath)

    def test_unknown_mode_missing_bundle_and_fake_passed_index_refuse(self):
        with self.assertRaisesRegex(Invalid, 'unsupported_validation_mode'):
            gate.validate(*self.args()[:5], mode='inventory-only')
        with self.assertRaisesRegex(Invalid, 'readiness_inputs_required'):
            gate.validate(*self.args()[:6])
        self.indexpath.write_bytes(b'{"status":"passed"}')
        self.refused('approved_readiness_index_mismatch')
        self.rec['readiness']['index_sha256'] = hashlib.sha256(self.indexpath.read_bytes()).hexdigest()
        self.write()
        self.refused('readiness_refused')

    def test_cli_failure_is_finite_json_without_private_paths(self):
        with patch('sys.stdout', new_callable=io.StringIO) as output:
            code = gate.main([str(p) for p in self.args()])
        self.assertEqual(code, 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'blocked')
        self.assertNotIn(str(self.root), output.getvalue())


class ArchiveTests(unittest.TestCase):
    def run_archive(self, members, admitted):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / 'bundle.zip'
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(archive, 'w') as stream:
                    for name, data in members:
                        if type(name) is str and '\\' in name:
                            original = name
                            name = zipfile.ZipInfo('crafted')
                            name.filename = original
                        stream.writestr(name, data)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if admitted:
                gate.extract(archive, root / 'out', digest, readiness=True)
                self.assertEqual((root / 'out/a.json').read_bytes(), b'{}')
            else:
                with self.assertRaises(Invalid):
                    gate.extract(archive, root / 'out', digest, readiness=True)
                self.assertFalse((root / 'out').exists())

    def test_owned_plain_bundle_extraction(self):
        self.run_archive([('a.json', b'{}')], True)

    def test_duplicate_traversal_absolute_backslash_conflict_and_links(self):
        for names in (['a.json', 'a.json'], ['../outside'], ['/outside'], ['a\\b'], ['a', 'a/b']):
            with self.subTest(names=names):
                self.run_archive([(name, b'{}') for name in names], False)
        link = zipfile.ZipInfo('link')
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        self.run_archive([(link, b'outside')], False)

    def test_directory_count_is_bounded_before_zipinfo_allocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'many.zip'
            with zipfile.ZipFile(archive, 'w') as output:
                for number in range(257):
                    output.writestr(str(number), b'')
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            with patch.object(gate.zipfile, 'ZipFile') as parser:
                with self.assertRaisesRegex(Invalid, 'archive_member_limit'):
                    gate.extract(archive, Path(temporary) / 'out', digest, True)
                parser.assert_not_called()


class WorkflowPublicationSpies(unittest.TestCase):
    """Execute the actual final workflow Bash with owned publisher functions.

    API refresh is replaced by a local helper running the real offline validator
    over controlled API bytes. No network or genuine publisher is invoked.
    """

    setUp = CandidateTests.setUp
    write = CandidateTests.write
    args = CandidateTests.args

    def scripts(self):
        source = (ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8')
        scripts = []
        for title in ('Load and Push Container', 'Publish GitHub Release (P1 Strict Upload)'):
            block = source.split('      - name: ' + title + '\n', 1)[1]
            run = block.split('        run: |\n', 1)[1].split('\n      - ', 1)[0]
            scripts.append('\n'.join(line[10:] if line.startswith('          ') else line
                                     for line in run.splitlines()))
        return scripts

    def shell(self):
        bash = shutil.which('bash') if os.name != 'nt' else 'C:/Program Files/Git/bin/bash.exe'
        if not bash or not Path(bash).is_file():
            self.skipTest('Bash is required for executing workflow publication controls')
        return bash

    def execute_step(self, script, *, positive=False, dry_run=False, view_status=0):
        helper = self.root / 'promotion-admission.sh'
        if positive:
            helper.write_text('#!/bin/bash\nexit 0\n', encoding='utf-8', newline='\n')
        else:
            # Absolute explicit test interpreter; no PATH fallback in the control.
            command = [Path(sys.executable).as_posix(), (ROOT / 'scripts/validate_candidate.py').as_posix()]
            command += [p.as_posix() if isinstance(p, Path) else str(p) for p in self.args()]
            helper.write_text('#!/bin/bash\nexec ' + shlex.join(command) + '\n',
                              encoding='utf-8', newline='\n')
        spy = self.root / 'publish-attempts.txt'
        spy.unlink(missing_ok=True)
        owned = '''
function docker() { printf 'docker %s\\n' "$*" >> "$SPY_FILE"; }
function skopeo() {
  if [[ "$1" == copy ]]; then printf 'skopeo %s\\n' "$*" >> "$SPY_FILE"; fi
}
function gh() {
  if [[ "$1 $2" == 'release view' ]]; then return "$VIEW_STATUS"; fi
  printf 'gh %s\\n' "$*" >> "$SPY_FILE"
}
'''
        script = script.replace('${{ steps.ref.outputs.sha }}', self.source)
        script = script.replace('${{ env.DRY_RUN }}', 'true' if dry_run else 'false')
        script = script.replace('${{ steps.files.outputs.validated_files }}', ' '.join(gate.names(self.tag)))
        self.assertNotIn('${{', script)
        env = dict(os.environ, SPY_FILE=spy.as_posix(), VIEW_STATUS=str(view_status),
                   TAG=self.tag, GH_TOKEN='synthetic-unusable', GITHUB_ACTOR='owned-spy',
                   GITHUB_REPOSITORY='SoupTeam/soup-wall')
        result = subprocess.run([self.shell(), '--noprofile', '--norc', '-c', owned + script],
                                cwd=self.root, env=env, capture_output=True, text=True, timeout=25)
        return result, spy.read_text() if spy.exists() else ''

    def test_real_write_steps_make_zero_attempts_on_offline_refusals(self):
        original_api = copy.deepcopy(self.api)
        original_record = copy.deepcopy(self.rec)
        for scenario in ('invalid_readiness', 'stale_attempt', 'wrong_source', 'changed_bytes'):
            self.api = copy.deepcopy(original_api)
            self.rec = copy.deepcopy(original_record)
            if scenario == 'stale_attempt':
                self.api['run_attempt'] = '2'
            elif scenario == 'wrong_source':
                self.api['head_sha'] = 'e' * 40
            elif scenario == 'changed_bytes':
                (self.dist / gate.names(self.tag)[0]).write_bytes(b'changed')
            self.write()
            for number, script in enumerate(self.scripts()):
                with self.subTest(scenario=scenario, step=number):
                    result, attempts = self.execute_step(script)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(attempts, '')

    def test_spies_are_live_on_both_release_paths_and_container_tags(self):
        # Explicit no-op admission is a spy calibration, never a readiness claim.
        container, release = self.scripts()
        result, attempts = self.execute_step(container, positive=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(attempts.count('skopeo copy'), 2)
        self.assertEqual(attempts.count('docker login'), 1)
        for view_status, action in ((0, 'upload'), (1, 'create')):
            result, attempts = self.execute_step(release, positive=True, view_status=view_status)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(attempts.count('gh release ' + action), 1)

    def test_dry_run_executes_admission_but_makes_no_publish_attempts(self):
        for script in self.scripts():
            result, attempts = self.execute_step(script, positive=True, dry_run=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(attempts, '')
            refused, attempts = self.execute_step(script, dry_run=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(attempts, '')


if __name__ == '__main__':
    unittest.main()
