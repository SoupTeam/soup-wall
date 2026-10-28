# SPDX-License-Identifier: Apache-2.0
"""Synthetic lifecycle fixtures; genuine installed qualification is separate."""
import errno
import base64
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('edit_archive_tested', ROOT / 'scripts/edit-run-archive.py')
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)
SECRET = 'raw-evidence-secret-canary-DO-NOT-EXPORT'


class Projection(unittest.TestCase):
    def test_only_allowlisted_projection_enters_archive(self):
        raw = E.S.encoded({'event': 'native_call', 'verdict': 'allow', 'shadow': False, 'session': SECRET,
                          'tool': SECRET, 'args': {'content': SECRET}, 'token': SECRET, 'findings': []}) + b'\n'
        exported = E.projection(raw)
        self.assertEqual(exported['counts'], {'records': 1, 'projected': 1, 'unsupported': 0})
        self.assertNotIn(SECRET.encode(), E.S.encoded(exported))
        self.assertIs(exported['full_forensic_backup'], False)
        future = json.loads(raw);future['contract_version'] = 'future'
        self.assertEqual(E.projection(E.S.encoded(future) + b'\n')['counts']['unsupported'], 1)

    def test_partial_or_malformed_raw_audit_never_becomes_complete_export(self):
        for raw in (b'{', b'{}', b'{"x":1,"x":2}\n', b'x' * (E.REPORT.MAX_LINE_BYTES + 1)):
            with self.subTest(raw_bytes=len(raw)), self.assertRaises(E.S.Refusal):
                E.projection(raw)


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux descriptor/lifecycle primitives')
class CleanupBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.parent, self.destination = self.base / 'runs', self.base / 'archives'
        self.parent.mkdir(mode=0o700);self.destination.mkdir(mode=0o700)
        self.run = self.parent / ('edit-' + str(uuid.uuid4()));self.run.mkdir(mode=0o700)
        self.home = self.run / ('h' * 43);self.home.mkdir(mode=0o700)
        self.record = {'format': 'sw-installed-edit-session/1', 'run': str(self.run), 'home': str(self.home),
                       'profile_sha256': 'a' * 64, 'host_session': str(uuid.uuid4()), 'instance_id': 'i' * 43}
        self.terminal = {'format': self.record['format'], 'state': 'host_completed', 'reason': 'host_completed',
                         'run': str(self.run), 'profile_sha256': self.record['profile_sha256'],
                         'cleanup': {'cleaned': True, 'reaped': True, 'exit_success': True, 'graceful_observed': False,
                                     'ownership': 'unix_process_group', 'failure': None}, 'daemon_clean': True,
                         'mutation_dispatches': 0,
                         'effect_status': 'consult-native-audit; interrupted-or-withheld-result-is-indeterminate; no-automatic-retry'}
        for name in ('host-home', 'host-tmp', 'host-path'):
            (self.run / name).mkdir(mode=0o755)
        self.write(self.run / 'run.json', E.S.encoded(self.record), 0o400)
        self.write(self.run / 'terminal.json', E.S.encoded(self.terminal), 0o400)
        claim = {'contract_version': 'sw-child-authority/1', 'host_session': self.record['host_session'],
                 'server_id': 'private-output', 'nonce': self.record['instance_id'] + '.owned-fixture',
                 'granted_resources': [str(self.base / 'private-output/result.txt')]}
        authority = base64.urlsafe_b64encode(E.S.encoded(claim)).decode().rstrip('=')
        transport = {'mcpServers': {'private-output': {'command': '/owned/agentfw', 'env': {},
                     'args': ['edit-session', 'relay', '--home', str(self.home), '--host-session', self.record['host_session'],
                              '--child-authority', authority, '--profile-sha256', self.record['profile_sha256']]}}}
        self.write(self.run / 'mcp.json', E.S.encoded(transport))
        for name in ('host-settings.json', 'host-bun.toml', 'host-stdout.json', 'host-stderr.json'):
            self.write(self.run / name, SECRET.encode())
        self.write(self.home / 'token', SECRET.encode())
        raw = E.S.encoded({'event': 'native_call', 'verdict': 'allow', 'shadow': False, 'session': 'owned',
                          'args': {'secret': SECRET}, 'findings': []}) + b'\n'
        self.write(self.home / 'audit.jsonl', raw)
        self.target = self.base / 'private-output/result.txt';self.target.parent.mkdir(mode=0o700)
        self.target.write_bytes(b'preserved output')

    @staticmethod
    def write(path, raw, mode=0o600):
        if path.exists(): path.chmod(0o600)
        path.write_bytes(raw);path.chmod(mode)

    def plan(self):
        return E.preview(self.run, self.destination)

    def test_explicit_archive_preserves_source_then_acknowledged_exact_cleanup_is_repeatable(self):
        plan = self.plan()
        with self.assertRaisesRegex(E.S.Refusal, 'explicit_raw_evidence_loss_consent_required'):
            E.cleanup(plan, False)
        self.assertTrue(self.run.is_dir())
        self.assertEqual(E.archive(plan)['outcome'], 'archived_source_retained')
        body = (self.destination / E.archive_name(plan)).read_bytes()
        self.assertNotIn(SECRET.encode(), body)
        self.assertTrue(self.run.is_dir())
        self.assertEqual(E.cleanup(plan, True)['outcome'], 'archived_and_cleaned')
        self.assertFalse(self.run.exists())
        self.assertEqual(self.target.read_bytes(), b'preserved output')
        self.assertEqual(E.cleanup(plan, True)['outcome'], 'already_cleaned')
        self.assertEqual(E.recover(plan, E.journal_name(plan))['outcome'], 'already_cleaned')

    def test_live_inode_lock_missing_terminal_and_incomplete_cleanup_refuse(self):
        import fcntl
        with E.S.Directory(self.run) as live:
            fcntl.flock(live.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(E.S.Refusal, 'edit_run_active'): self.plan()
        self.terminal['cleanup']['cleaned'] = False
        self.write(self.run / 'terminal.json', E.S.encoded(self.terminal), 0o400)
        with self.assertRaises(E.S.Refusal): self.plan()
        (self.run / 'terminal.json').unlink()
        with self.assertRaises(FileNotFoundError): self.plan()

    def test_foreign_instance_cannot_borrow_terminal_cleanup_claims(self):
        self.record['instance_id'] = 'f' * 43
        self.write(self.run / 'run.json', E.S.encoded(self.record), 0o400)
        with self.assertRaisesRegex(E.S.Refusal, 'edit_instance_binding_invalid'): self.plan()

    def test_changed_inventory_and_destination_refuse_before_detachment(self):
        plan = self.plan()
        self.write(self.home / 'token', b'changed')
        with self.assertRaisesRegex(E.S.Refusal, 'edit_plan_changed'): E.archive(plan)
        self.assertTrue(self.run.is_dir())
        self.destination.rename(self.base / 'old-archives');self.destination.mkdir(mode=0o700)
        with self.assertRaisesRegex(E.S.Refusal, 'archive_destination_changed'): E.archive(plan)

    def test_symlink_hardlink_fifo_and_foreign_extra_state_refuse(self):
        path = self.run / 'host-bun.toml'
        path.unlink();path.symlink_to(self.target)
        with self.assertRaises(E.S.Refusal): self.plan()
        path.unlink();os.link(self.target, path)
        with self.assertRaises(E.S.Refusal): self.plan()
        path.unlink();os.mkfifo(path, 0o600)
        with self.assertRaises(E.S.Refusal): self.plan()
        path.unlink();self.write(path, b'')
        self.write(self.run / 'foreign.txt', b'foreign')
        with self.assertRaises(E.S.Refusal): self.plan()

    def test_failed_archive_keeps_all_source_and_partial_cleanup_stays_incomplete(self):
        plan = self.plan()
        with patch.object(E.A, 'publish', side_effect=OSError(errno.ENOSPC, 'controlled no space')):
            with self.assertRaises(OSError): E.archive(plan)
        self.assertTrue(self.run.exists())
        E.archive(plan)
        original = E.A.remove_member
        calls = 0
        def interrupted(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2: raise InterruptedError('controlled removal interruption')
            return original(*args, **kwargs)
        with patch.object(E.A, 'remove_member', side_effect=interrupted):
            self.assertEqual(E.cleanup(plan, True)['outcome'], 'incomplete')
        result = E.recover(plan, E.journal_name(plan))
        self.assertEqual(result['outcome'], 'incomplete')
        self.assertEqual(result['source'], 'quarantined')
        self.assertIs(result['archive_verified'], True)
        with self.assertRaisesRegex(E.S.Refusal, 'cleanup_completion_unconfirmed'): E.cleanup(plan, True)

    def test_archive_padding_and_meta_injection_never_authorize_removal(self):
        plan = self.plan();E.archive(plan)
        path = self.destination / E.archive_name(plan)
        raw = path.read_bytes()
        for bad in (raw + SECRET.encode(), SECRET.encode() + raw):
            with self.assertRaises(E.S.Refusal): E.verify_archive(bad, plan)
        self.assertTrue(self.run.exists())

    def test_nested_project_and_immutable_plan_are_retained_before_any_archive_write(self):
        for marker in ('.git', 'profile.json', 'profile.sha256'):
            path = self.run / 'host-home' / marker
            self.write(path, b'preserved project or immutable plan')
            with self.assertRaisesRegex(E.S.Refusal, 'project_or_immutable_plan_retained'): self.plan()
            self.assertEqual(path.read_bytes(), b'preserved project or immutable plan')
            self.assertEqual(list(self.destination.iterdir()), [])
            path.unlink()

    def test_output_claim_cannot_overlap_selected_run_state(self):
        path = self.run / 'mcp.json'
        value = json.loads(path.read_bytes())
        args = value['mcpServers']['private-output']['args']
        claim = json.loads(base64.urlsafe_b64decode(args[7] + '=' * (-len(args[7]) % 4)))
        claim['granted_resources'] = [str(self.run / 'result.txt')]
        args[7] = base64.urlsafe_b64encode(E.S.encoded(claim)).decode().rstrip('=')
        self.write(path, E.S.encoded(value))
        with self.assertRaisesRegex(E.S.Refusal, 'edit_output_state_overlap'): self.plan()
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertTrue(self.run.is_dir())


if __name__ == '__main__':
    unittest.main()
