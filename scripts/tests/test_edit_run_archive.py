# SPDX-License-Identifier: Apache-2.0
"""Synthetic lifecycle fixtures; genuine installed qualification is separate."""
import errno
import base64
import copy
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
# Public synthetic bytes, never a credential. Native qualification separately
# checks that its genuine disposable run tokens never enter the sanitized ZIP.
RAW_CANARY = 'owned-raw-exclusion-marker-v1'


class QuotaContracts(unittest.TestCase):
    @staticmethod
    def limits():
        return {'contract_version': 'sw-installed-edit-mutation-quota/1',
                'max_mutations': 2, 'max_write_bytes': 4096}

    @classmethod
    def profile(cls, version=2):
        pin = {'path': '/owned/agentfw', 'sha256': 'a' * 64}
        result = {'format': f'sw-installed-edit-session/{version}',
                  'exclusion': 'operator-private-sole-writer+directory-flock/1',
                  'root': '/owned/output', 'root_identity': {'device': 1, 'inode': 2},
                  'agent': pin, 'claude': pin, 'policy_sha256': 'b' * 64,
                  'component': {'home': '/owned/component', 'id': 'c' * 64,
                                'source_commit': 'd' * 40, 'source_tree': 'e' * 40,
                                'python': pin, 'classifier': pin, 'python_version': '3.12'},
                  'targets': [{'name': 'result.txt', 'read': True, 'create': True, 'replacement': None}]}
        if version == 2: result['mutation_quota'] = cls.limits()
        return result

    @classmethod
    def usage(cls):
        return {'limits': cls.limits(), 'admitted_mutation_attempts': 1, 'charged_write_bytes': 8,
                'known_committed_mutations': 1, 'known_committed_write_bytes': 8,
                'known_not_committed_mutations': 0, 'indeterminate_publications': 0,
                'pending_prepublication_attempts': 0, 'remaining_mutations': 1,
                'remaining_write_bytes': 4088}

    def test_v2_profile_accepts_exact_limits_and_preserves_v1(self):
        E.profile_snapshot(self.profile(1))
        E.profile_snapshot(self.profile())
        for mutations, size in [(0, 0), (64, 64 * 4096)]:
            value = self.profile();value['mutation_quota'].update(max_mutations=mutations, max_write_bytes=size)
            E.profile_snapshot(value)

    def test_invalid_profile_quota_versions_null_unknown_boolean_and_overflow_refuse(self):
        cases = [None, {}, {**self.limits(), 'contract_version': 'future'},
                 {**self.limits(), 'max_mutations': True}, {**self.limits(), 'max_mutations': -1},
                 {**self.limits(), 'max_mutations': 65}, {**self.limits(), 'max_mutations': 2**64},
                 {**self.limits(), 'max_write_bytes': False}, {**self.limits(), 'max_write_bytes': 262145},
                 {**self.limits(), 'unexpected': 1}]
        for quota in cases:
            value = self.profile();value['mutation_quota'] = quota
            with self.subTest(quota=quota), self.assertRaises(E.S.Refusal): E.profile_snapshot(value)
        for value in [self.profile(3), {k:v for k,v in self.profile().items() if k != 'mutation_quota'},
                      {**self.profile(1), 'mutation_quota': self.limits()}]:
            with self.assertRaises(E.S.Refusal): E.profile_snapshot(value)

    def test_usage_and_exact_profile_limits_are_required_together(self):
        value = self.usage()
        E.quota_binding(self.profile(), {'state':'host_completed', 'mutation_quota':value})
        E.quota_binding(self.profile(1), {'state':'host_completed'})
        E.quota_binding(None, {'state':'host_completed'})
        changed = copy.deepcopy(value);changed['limits']['max_mutations'] = 3;changed['remaining_mutations'] = 2
        for profile, ended in [(self.profile(), {'state':'host_completed'}),
                               (self.profile(), {'state':'host_completed', 'mutation_quota':changed}),
                               (self.profile(1), {'state':'host_completed', 'mutation_quota':value}),
                               (None, {'state':'host_completed', 'mutation_quota':value})]:
            with self.assertRaises(E.S.Refusal): E.quota_binding(profile, ended)

    def test_malformed_or_contradictory_counters_never_authorize_archival(self):
        original = self.usage()
        cases = [None, {}, {**original, 'future':1}, {**original, 'limits':None},
                 {**original, 'remaining_mutations':0}, {**original, 'remaining_write_bytes':4096},
                 {**original, 'known_committed_mutations':0}, {**original, 'charged_write_bytes':4097},
                 {**original, 'known_committed_write_bytes':9}]
        for name in set(original) - {'limits'}:
            for bad in [True, -1, 2**64]: cases.append({**original, name:bad})
        excessive = copy.deepcopy(original)
        excessive.update(charged_write_bytes=4097, known_committed_write_bytes=4097, remaining_write_bytes=4095)
        excessive['limits']['max_write_bytes'] = 8192;cases.append(excessive)
        for value in cases:
            with self.subTest(usage=value), self.assertRaises(E.S.Refusal):
                E.quota_binding(self.profile(), {'state':'host_completed', 'mutation_quota':value})

    def test_unavailable_or_unsettled_quota_is_retained_even_with_cleanup_claims(self):
        unavailable = {'error_code':'edit_quota_state_unavailable', 'counts_known':False}
        pending = self.usage();pending.update(known_committed_mutations=0, known_committed_write_bytes=0,
                                            pending_prepublication_attempts=1)
        uncertain = {**pending, 'pending_prepublication_attempts':0, 'indeterminate_publications':1}
        for state in ['host_completed', 'failed']:
            for value in [unavailable, {**unavailable, 'counts_known':True},
                          {**unavailable, 'error_code':'future'}, pending, uncertain]:
                with self.subTest(state=state, usage=value), self.assertRaises(E.S.Refusal):
                    E.quota_binding(self.profile(), {'state':state, 'mutation_quota':value})


class Projection(unittest.TestCase):
    def test_only_allowlisted_projection_enters_archive(self):
        raw = E.S.encoded({'event': 'native_call', 'verdict': 'allow', 'shadow': False, 'session': RAW_CANARY,
                          'tool': RAW_CANARY, 'args': {'content': RAW_CANARY}, 'token': RAW_CANARY, 'findings': []}) + b'\n'
        exported = E.projection(raw)
        self.assertEqual(exported['counts'], {'records': 1, 'projected': 1, 'unsupported': 0})
        self.assertNotIn(RAW_CANARY.encode(), E.S.encoded(exported))
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
            self.write(self.run / name, RAW_CANARY.encode())
        self.write(self.home / 'token', RAW_CANARY.encode())
        raw = E.S.encoded({'event': 'native_call', 'verdict': 'allow', 'shadow': False, 'session': 'owned',
                          'args': {'content': RAW_CANARY}, 'findings': []}) + b'\n'
        self.write(self.home / 'audit.jsonl', raw)
        self.target = self.base / 'private-output/result.txt';self.target.parent.mkdir(mode=0o700)
        self.target.write_bytes(b'preserved output')

    @staticmethod
    def write(path, raw, mode=0o600):
        if path.exists(): path.chmod(0o600)
        path.write_bytes(raw);path.chmod(mode)

    def plan(self):
        return E.preview(self.run, self.destination)

    def snapshots(self, quota=False):
        pin = {'path': '/owned/agentfw', 'sha256': 'a' * 64}
        profile = {'format': self.record['format'], 'exclusion': 'operator-private-sole-writer+directory-flock/1',
                   'root': str(self.target.parent), 'root_identity': {'device': self.target.stat().st_dev, 'inode': 5},
                   'agent': pin, 'claude': pin, 'policy_sha256': 'b' * 64,
                   'component': {'home': '/owned/component', 'id': 'c' * 64, 'source_commit': 'd' * 40,
                                 'source_tree': 'e' * 40, 'python': pin, 'classifier': pin, 'python_version': '3.12'},
                   'targets': [{'name': self.target.name, 'read': True, 'create': True, 'replacement': None}]}
        if quota:
            profile.update(format=E.PROFILE_V2, mutation_quota=QuotaContracts.limits())
            self.terminal['mutation_quota'] = QuotaContracts.usage()
        raw = E.S.encoded(profile)
        self.record['profile_sha256'] = self.terminal['profile_sha256'] = E.S.sha(raw)
        self.write(self.run / 'run.json', E.S.encoded(self.record), 0o400)
        self.write(self.run / 'terminal.json', E.S.encoded(self.terminal), 0o400)
        transport = json.loads((self.run / 'mcp.json').read_bytes())
        transport['mcpServers']['private-output']['args'][-1] = self.record['profile_sha256']
        self.write(self.run / 'mcp.json', E.S.encoded(transport))
        self.write(self.run / 'profile.json', raw, 0o400)
        self.write(self.run / 'profile.sha256', self.record['profile_sha256'].encode(), 0o400)
        owner = {'pid': 123, 'start_ticks': 456, 'boot_id': str(uuid.uuid4()), 'uid': os.getuid()}
        context = {**self.record, 'format': 'sw-installed-edit-diagnostic-context/1',
                   'config_sha256': 'f' * 64, 'listener': {'fd': 7, 'inode': 8, 'device': 9},
                   'started_at_ms': 1, 'owner': owner}
        self.write(self.run / 'diagnostic-context.json', E.S.encoded(context), 0o400)
        self.write(self.run / 'host-process.json', E.S.encoded({**owner, 'pid': 124}), 0o400)
        return profile, context

    def test_v2_archive_cleanup_requires_exact_quota_and_preserves_target_and_plan(self):
        self.snapshots(quota=True)
        before = (self.target.read_bytes(), self.target.stat().st_ino)
        external = self.base / 'immutable-plan';external.mkdir(mode=0o700)
        for name in ('profile.json', 'profile.sha256'):
            self.write(external / name, (self.run / name).read_bytes(), 0o400)
        original_plan = {p.name: (p.read_bytes(), p.stat().st_ino) for p in external.iterdir()}
        terminal_path = self.run / 'terminal.json';original_terminal = terminal_path.read_bytes()
        wrong = copy.deepcopy(self.terminal)
        wrong['mutation_quota']['limits']['max_mutations'] = 3
        wrong['mutation_quota']['remaining_mutations'] = 2
        self.write(terminal_path, E.S.encoded(wrong), 0o400)
        with self.assertRaisesRegex(E.S.Refusal, 'edit_quota_profile_mismatch'): self.plan()
        self.assertTrue(self.run.exists());self.assertEqual(list(self.destination.iterdir()), [])
        self.write(terminal_path, original_terminal, 0o400)
        plan = self.plan();self.assertEqual(plan['terminal']['mutation_quota'], QuotaContracts.usage())
        E.archive(plan)
        with self.assertRaisesRegex(E.S.Refusal, 'explicit_raw_evidence_loss_consent_required'): E.cleanup(plan, False)
        self.assertTrue(self.run.exists())
        self.assertEqual(E.cleanup(plan, True)['outcome'], 'archived_and_cleaned')
        self.assertEqual(E.cleanup(plan, True)['outcome'], 'already_cleaned')
        self.assertEqual((self.target.read_bytes(), self.target.stat().st_ino), before)
        self.assertEqual({p.name: (p.read_bytes(), p.stat().st_ino) for p in external.iterdir()}, original_plan)

    def test_terminal_quota_without_bound_snapshot_or_with_null_cannot_archive_legacy_run(self):
        for value in [None, QuotaContracts.usage()]:
            self.terminal['mutation_quota'] = value
            self.write(self.run / 'terminal.json', E.S.encoded(self.terminal), 0o400)
            with self.assertRaisesRegex(E.S.Refusal, 'edit_quota_profile_mismatch'): self.plan()
            self.assertTrue(self.run.exists());self.assertEqual(list(self.destination.iterdir()), [])

    def test_quota_terminal_changed_after_validation_is_retained_without_archive(self):
        self.snapshots(quota=True)
        original = E.quota_binding
        changed = copy.deepcopy(self.terminal)
        changed['mutation_quota']['admitted_mutation_attempts'] = True
        def replace_after_validation(profile, ended):
            original(profile, ended)
            self.write(self.run / 'terminal.json', E.S.encoded(changed), 0o400)
        with patch.object(E, 'quota_binding', replace_after_validation):
            with self.assertRaisesRegex(E.S.Refusal, 'edit_terminal_changed_during_inventory'): self.plan()
        self.assertEqual((self.run / 'terminal.json').read_bytes(), E.S.encoded(changed))
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_current_main_snapshots_are_exact_root_copies_and_external_plan_is_preserved(self):
        self.snapshots()
        external = self.base / 'immutable-plan';external.mkdir(mode=0o700)
        before_target = self.target.read_bytes()
        for name in ('profile.json', 'profile.sha256'):
            self.write(external / name, (self.run / name).read_bytes(), 0o400)
        before = {p.name: (p.read_bytes(), p.stat().st_ino) for p in external.iterdir()}
        plan = self.plan();self.assertTrue(E.SNAPSHOTS <= set(plan['inventory']['files']))
        E.archive(plan)
        with self.assertRaisesRegex(E.S.Refusal, 'explicit_raw_evidence_loss_consent_required'): E.cleanup(plan, False)
        self.assertTrue(self.run.exists())
        self.assertEqual(E.cleanup(plan, True)['outcome'], 'archived_and_cleaned')
        self.assertEqual({p.name: (p.read_bytes(), p.stat().st_ino) for p in external.iterdir()}, before)
        self.assertEqual(self.target.read_bytes(), before_target)

    def test_snapshot_schemas_digests_instances_modes_and_unknown_fields_refuse(self):
        profile, context = self.snapshots()
        cases = [('diagnostic-context.json', {**context, 'instance_id': 'z' * 43}),
                 ('diagnostic-context.json', {**context, 'owner': {**context['owner'], 'start_ticks': True}}),
                 ('diagnostic-context.json', {**context, 'listener': {**context['listener'], 'fd': -1}}),
                 ('diagnostic-context.json', {**context, 'future': 1}),
                 ('host-process.json', {**context['owner'], 'pid': 124, 'uid': os.getuid() + 1}),
                 ('profile.json', {**profile, 'mutation_quota': {}}),
                 ('profile.json', {**profile, 'root': '/foreign/output'}),
                 ('profile.json', {**profile, 'format': 'sw-installed-edit-session/2'}),
                 ('profile.json', {**profile, 'targets': [{**profile['targets'][0], 'read': 1}]})]
        for name, value in cases:
            path = self.run / name;original = path.read_bytes()
            with self.subTest(name=name, value=value):
                self.write(path, E.S.encoded(value), 0o400)
                with self.assertRaises(E.S.Refusal): self.plan()
                self.assertTrue(path.exists());self.assertEqual(list(self.destination.iterdir()), [])
            self.write(path, original, 0o400)
        path = self.run / 'profile.sha256';original = path.read_bytes()
        for raw in (b'0' * 64, original + b'\n'):
            self.write(path, raw, 0o400)
            with self.assertRaises(E.S.Refusal): self.plan()
        self.write(path, original, 0o600)
        with self.assertRaisesRegex(E.S.Refusal, 'edit_snapshot_mode_invalid'): self.plan()
        self.write(path, original, 0o400)
        path.unlink()
        with self.assertRaisesRegex(E.S.Refusal, 'edit_snapshot_set_incomplete'): self.plan()

    def test_snapshot_links_nested_copies_and_validation_read_races_are_retained(self):
        self.snapshots();path = self.run / 'profile.json';original = path.read_bytes()
        alias = self.base / 'external-profile';self.write(alias, original, 0o400)
        path.unlink();os.link(alias, path)
        with self.assertRaises(E.S.Refusal): self.plan()
        self.assertEqual(alias.read_bytes(), original)
        path.unlink();self.write(path, original, 0o400)
        nested = self.run / 'host-home/profile.json';self.write(nested, original, 0o400)
        with self.assertRaisesRegex(E.S.Refusal, 'project_or_immutable_plan_retained'): self.plan()
        nested.unlink()
        real = E.descriptive_snapshots
        def changed(*args):
            result = real(*args)
            self.write(path, b'{}', 0o400)
            return result
        with patch.object(E, 'descriptive_snapshots', changed):
            with self.assertRaisesRegex(E.S.Refusal, 'edit_snapshot_changed'): self.plan()
        self.assertTrue(path.exists());self.assertEqual(list(self.destination.iterdir()), [])

    def test_explicit_archive_preserves_source_then_acknowledged_exact_cleanup_is_repeatable(self):
        plan = self.plan()
        with self.assertRaisesRegex(E.S.Refusal, 'explicit_raw_evidence_loss_consent_required'):
            E.cleanup(plan, False)
        self.assertTrue(self.run.is_dir())
        self.assertEqual(E.archive(plan)['outcome'], 'archived_source_retained')
        body = (self.destination / E.archive_name(plan)).read_bytes()
        self.assertNotIn(RAW_CANARY.encode(), body)
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
        with E.S.Directory(self.home) as live:
            fcntl.flock(live.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Stop can still transact on metadata while the lifecycle lock
            # refuses archival even with an injected completed terminal.
            with E.S.Directory(self.run) as metadata:
                fcntl.flock(metadata.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
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
        for bad in (raw + RAW_CANARY.encode(), RAW_CANARY.encode() + raw):
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

    def test_known_optional_control_state_is_inventoried_without_becoming_inactive_proof(self):
        self.write(self.home / 'config.yaml', b'owned fixture configuration', 0o400)
        self.write(self.home / 'native-token', RAW_CANARY.encode())
        control = {'contract': E.CONTROL_FORMATS['control.json'],
                   'run_sha256': E.S.sha((self.run / 'run.json').read_bytes()),
                   'run_identity': [self.run.stat().st_dev, self.run.stat().st_ino],
                   'home_identity': [self.home.stat().st_dev, self.home.stat().st_ino],
                   'launcher_pid': 123, 'launcher_start': 456, 'manifest_fd': 7,
                   'config_sha256': E.S.sha((self.home / 'config.yaml').read_bytes()),
                   'native_token_sha256': E.S.sha(RAW_CANARY.encode()),
                   **{key: self.record[key] for key in ('instance_id', 'profile_sha256', 'host_session')}}
        self.write(self.run / 'control.json', E.S.encoded(control), 0o400)
        receipt = {'contract': E.CONTROL_FORMATS['stop-receipt.json'],
                   'control_sha256': E.S.sha((self.run / 'control.json').read_bytes()), 'request_sha256': None,
                   'authority_revoked': True, 'cleanup_confirmed': True, 'reason': 'host_completed',
                   'signature': 'm' * 43}
        self.write(self.run / 'stop-receipt.json', E.S.encoded(receipt))
        control['launcher_pid'] = True
        self.write(self.run / 'control.json', E.S.encoded(control), 0o400)
        with self.assertRaisesRegex(E.S.Refusal, 'edit_control_identity_invalid'): self.plan()
        control['launcher_pid'] = 123
        self.write(self.run / 'control.json', E.S.encoded(control), 0o400)
        plan = self.plan();E.archive(plan)
        self.assertIn('control.json', plan['inventory']['files'])
        self.assertEqual(E.cleanup(plan, True)['outcome'], 'archived_and_cleaned')

    def test_optional_control_without_terminal_never_confirms_inactivity(self):
        self.write(self.run / 'control.json', E.S.encoded({'contract': E.CONTROL_FORMATS['control.json']}), 0o400)
        (self.run / 'terminal.json').unlink()
        with self.assertRaises(FileNotFoundError): self.plan()
        self.write(self.run / 'terminal.json', E.S.encoded(self.terminal), 0o400)
        with self.assertRaisesRegex(E.S.Refusal, 'edit_control_incomplete'): self.plan()


if __name__ == '__main__':
    unittest.main()
