# SPDX-License-Identifier: Apache-2.0
"""Finite archive and native private-publication controls, not product qualification."""
import copy
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import pilot_configuration_backup as C


class ConfigurationFixture:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.source = self.root / 'source'
        self.source.mkdir(mode=0o700)
        for name in ('generation', 'workspaces', 'assets'):
            (self.root / name).mkdir(mode=0o700)
        self.binary = self.root / 'agentfw'
        self.policy_raw = b'accepted synthetic baseline\n'
        self.policy = self.root / 'selected-policy.yaml'
        self.policy.write_bytes(self.policy_raw)
        self.policy.chmod(0o600)
        self.selection = self.root / 'generation' / 'selection.json'
        self.commit = 'a' * 40
        self.binding = {'source_commit': self.commit, 'selection_sha256': 'a' * 64,
            'source': {'commit': self.commit, 'tree': '2' * 40, 'dirty': False, 'files_sha256': '3' * 64},
            'selection_path': str(self.selection),
            'files': {role: {'path': str(self.root / role), 'sha256': 'b' * 64}
                      for role in C.PREP.PILOT.ROLES},
            'profiles': {kind: {'profile': {'path': str(self.root / kind / 'profile.json'),
                                           'sha256': 'c' * 64},
                'registry_sha256': 'd' * 64, 'package_tree_sha256': 'e' * 64}
                for kind in ('filesystem', 'git')}}
        self.projection = {'version': C.PROJECTION, 'kind': 'config', 'status': 'projected',
            'config': {'bind': '127.0.0.1', 'port': 8787, 'enforce': True, 'audit': None,
                'capture_unknown_raw': False, 'max_record_bytes': 1048576,
                'provenance': dict(zip(('per_session_bytes', 'total_bytes', 'max_sessions',
                    'max_input_bytes', 'max_source_bytes', 'max_literal_bytes', 'max_session_id_bytes'),
                    (8388608, 67108864, 512, 262144, 1024, 4096, 256))),
                'deterministic_timeout_ms': 1000, 'max_body_bytes': 1048576,
                'native': None, 'audit_retention': None},
            'references': {'policy': str(self.policy), 'registry': None, 'audit_directory': None}}
        self.document = {'format': C.CONFIGURATION, 'projection': copy.deepcopy(self.projection),
            'source_home': str(self.source), 'source_config': {'sha256': 'f' * 64, 'bytes': 100},
            'runtime_binding': self.binding, 'policy': {'path': str(self.policy),
                'sha256': C.sha(self.policy_raw), 'semantic_sha256': '1' * 64,
                'bytes': len(self.policy_raw)}, 'registry': None, 'audit_directory_role': None}
        self.current = {'binding': self.binding, 'policy_raw': self.policy_raw,
            'policy_projection': {'policy_sha256': '1' * 64}, 'tools': [],
            'binary': self.binary, 'selection': {}, 'selection_raw': b'{}',
            'preserved_roots': [str(self.root / 'generation'), str(self.root / 'workspaces'),
                                str(self.root / 'assets')]}
        self.archive = self.root / 'configuration.tar'
        self.destination = self.root / 'fresh-home'

    def load(self, raw):
        with patch.object(C, 'private_read', return_value=(raw, [1] * 8)):
            return C.load_archive(self.archive)

    def fake_project(self, _binary, raw, *, policy=False, expected_sha256=None):
        if policy:
            return {'version': C.PROJECTION, 'kind': 'policy', 'status': 'projected', 'policy_sha256': '1' * 64}
        cfg = json.loads(raw)
        refs = {'policy': cfg.pop('policy'), 'registry': None, 'audit_directory': None}
        if cfg['native'] is not None:
            refs['registry'] = cfg['native'].pop('registry_path')
        if cfg['audit_retention'] is not None:
            refs['audit_directory'] = cfg['audit_retention'].pop('directory')
        return {'version': C.PROJECTION, 'kind': 'config', 'status': 'projected',
                'config': cfg, 'references': refs}

    def write_archive(self):
        self.archive.write_bytes(C.archive_bytes(self.document))
        self.archive.chmod(0o600)


class ConfigurationControls(ConfigurationFixture, unittest.TestCase):
    def test_exact_roundtrip_has_only_declarative_json_not_home_dump(self):
        raw = C.archive_bytes(self.document)
        document, _, _ = self.load(raw)
        self.assertEqual(document, self.document)
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            self.assertEqual(archive.getnames(), list(C.MEMBERS))
        self.assertNotIn(self.policy_raw, raw)
        self.assertIn('session-authority', C.EXCLUDED)

    def test_corrupt_member_or_header_refuses(self):
        raw = bytearray(C.archive_bytes(self.document))
        for index in (0, 512, 1700):
            changed = raw.copy()
            changed[index] ^= 1
            with self.subTest(index=index), self.assertRaises((ValueError, tarfile.TarError)):
                self.load(bytes(changed))

    def test_missing_duplicate_extra_link_and_extension_members_refuse(self):
        original = C.archive_bytes(self.document)
        with tarfile.open(fileobj=io.BytesIO(original)) as archive:
            bodies = [(m.name, archive.extractfile(m).read()) for m in archive]
        cases = [bodies[:1], bodies + bodies[:1], bodies + [('token', b'secret-canary')],
                 [('../manifest.json', bodies[0][1]), bodies[1]],
                 [('/manifest.json', bodies[0][1]), bodies[1]]]
        for rows in cases:
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name, raw in rows:
                    member = tarfile.TarInfo(name)
                    member.size, member.mode = len(raw), 0o600
                    archive.addfile(member, io.BytesIO(raw))
            with self.subTest(rows=[row[0] for row in rows]), self.assertRaises((ValueError, tarfile.TarError)):
                self.load(output.getvalue())
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.GNUTYPE_LONGNAME):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w') as archive:
                member = tarfile.TarInfo('manifest.json')
                member.type, member.linkname = kind, 'outside'
                archive.addfile(member)
            with self.subTest(kind=kind), self.assertRaises((ValueError, tarfile.TarError)):
                self.load(output.getvalue())

    def test_compressed_oversized_and_trailing_data_archives_refuse(self):
        raw = C.archive_bytes(self.document)
        for changed in (b'\x1f\x8b' + raw[2:], raw + b'x' * 512, b'\0' * (C.MAX_ARCHIVE + 512)):
            with self.subTest(size=len(changed)), self.assertRaises((ValueError, tarfile.TarError)):
                self.load(changed)

    def test_secret_or_undeclared_archive_sections_refuse_even_rehashed(self):
        mutations = [lambda d: d.update(token='secret-canary'),
            lambda d: d['projection']['config'].update(judge={'endpoint': 'secret-canary'}),
            lambda d: d['projection']['config']['provenance'].update(session_history='secret-canary'),
            lambda d: d['runtime_binding']['files'].update(provider={'path': 'secret-canary', 'sha256': 'a' * 64}),
            lambda d: d['runtime_binding']['profiles']['git'].update(provider_configuration='secret-canary'),
            lambda d: d['projection']['config'].update(capture_unknown_raw=True)]
        for mutation in mutations:
            document = copy.deepcopy(self.document)
            mutation(document)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.load(C.archive_bytes(document))

    def test_duplicate_json_key_in_member_refuses(self):
        raw = C.archive_bytes(self.document)
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            manifest = archive.extractfile('manifest.json').read()
            configuration = archive.extractfile('configuration.json').read()
        configuration = configuration.replace(b'{', b'{"format":"bad",', 1)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as archive:
            for name, body in zip(C.MEMBERS, (manifest, configuration)):
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(body), 0o600
                archive.addfile(member, io.BytesIO(body))
        with self.assertRaises(ValueError):
            self.load(output.getvalue())

    def test_export_requires_consent_before_capture(self):
        with patch.object(C, 'capture') as capture, self.assertRaisesRegex(ValueError, 'consent'):
            C.backup(self.source, self.selection, self.binary, self.commit, self.archive)
        capture.assert_not_called()

    def test_unsupported_platform_reports_finite_result_without_reads(self):
        with patch.object(C.sys, 'platform', 'win32'), patch.object(C, 'load_archive') as loading, \
                patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(C.main(['inspect', '--archive', str(self.archive)]), 5)
            self.assertEqual(json.loads(output.getvalue())['blockers'], ['linux_required'])
            loading.assert_not_called()

    def test_projector_refusal_is_finite_without_raw_private_diagnostics(self):
        from types import SimpleNamespace
        for reason in ('configuration_invalid', 'configuration_judge_unsupported',
                       'configuration_execution_unsupported'):
            value = {'version': C.PROJECTION, 'kind': 'config', 'status': 'refused', 'reason': reason}
            result = SimpleNamespace(returncode=2, stdout=C.canonical(value), stderr=b'private-path-secret-canary')
            with self.subTest(reason=reason), self.assertRaisesRegex(C.Refusal, '^' + reason + '$'):
                C.projected_result(result)
        result.stdout = C.canonical({**value, 'reason': 'private-path-secret-canary'})
        with self.assertRaisesRegex(C.Refusal, '^authoritative_configuration_refused$'):
            C.projected_result(result)

    def test_write_all_handles_real_short_writes_and_refuses_no_progress(self):
        original = os.write
        with tempfile.TemporaryFile() as output:
            with patch.object(C.os, 'write', side_effect=lambda fd, raw: original(fd, raw[:3])):
                C.write_all(output.fileno(), b'complete-journal-record')
            output.seek(0)
            self.assertEqual(output.read(), b'complete-journal-record')
            with patch.object(C.os, 'write', return_value=0), \
                    self.assertRaisesRegex(C.Refusal, 'write_incomplete'):
                C.write_all(output.fileno(), b'incomplete')


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux private descriptor/publication controls')
class NativeConfigurationControls(ConfigurationFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.runtime_patch = patch.object(C, 'runtime', return_value=self.current)
        self.project_patch = patch.object(C, 'projection', side_effect=self.fake_project)
        self.runtime_patch.start(); self.project_patch.start()
        self.addCleanup(self.runtime_patch.stop); self.addCleanup(self.project_patch.stop)
        self.write_archive()

    def preview(self, port=None):
        return C.restore_preview(self.archive, self.selection, self.binary, self.commit, self.destination, port)

    def restored(self, token, *, port=None, recovery=False):
        return C.restore(self.archive, self.selection, self.binary, self.commit, self.destination,
                         confirm_plan=token, port=port, recovery=recovery)

    def test_preview_writes_nothing_and_explicit_port_rebinding_changes_plan(self):
        before = sorted(p.name for p in self.root.iterdir())
        old, changed = self.preview(), self.preview(9999)
        self.assertEqual(before, sorted(p.name for p in self.root.iterdir()))
        self.assertNotEqual(old['plan_sha256'], changed['plan_sha256'])
        self.assertEqual(changed['changes']['old_port'], 8787)
        self.assertEqual(changed['changes']['new_port'], 9999)
        self.assertFalse(self.destination.exists())

    def test_fresh_restore_never_copies_tokens_and_never_starts_daemon(self):
        (self.source / 'token').write_text('old-token-secret-canary')
        report = self.restored(self.preview()['plan_sha256'])
        self.assertEqual(report['status'], 'restored')
        self.assertEqual({p.name for p in self.destination.iterdir()},
                         {'config.yaml', 'policy.yaml', 'configuration-restored.json'})
        for path in self.destination.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn(b'old-token-secret-canary', path.read_bytes())
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o700)
        self.assertEqual(report['observed_protection'], 'unverified')
        self.assertEqual((self.source / 'token').read_text(), 'old-token-secret-canary')
        self.assertFalse((self.destination / 'token').exists())
        self.assertIn('fresh_authority_required', report['readiness_blockers'])

    def test_old_confirmation_after_runtime_or_port_change_refuses(self):
        old = self.preview()['plan_sha256']
        with self.assertRaisesRegex(ValueError, 'explicit_current_plan'):
            self.restored(old, port=9999)
        self.current['binding'] = copy.deepcopy(self.current['binding'])
        self.current['binding']['selection_sha256'] = '2' * 64
        with self.assertRaisesRegex(ValueError, 'explicit_current_plan'):
            self.restored(old)
        self.assertFalse(self.destination.exists())

    def test_existing_or_redirected_destination_preserved(self):
        token = self.preview()['plan_sha256']
        external = self.root / 'external'
        external.mkdir(mode=0o700)
        sentinel = external / 'untouched'
        sentinel.write_bytes(b'unchanged')
        self.destination.symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'fresh_destination_required'):
            self.restored(token)
        self.assertEqual(sentinel.read_bytes(), b'unchanged')
        self.assertEqual(sorted(p.name for p in external.iterdir()), ['untouched'])

    def test_partial_member_publication_and_after_rename_recover_with_same_plan(self):
        for point in ('member_published', 'before_publication', 'after_publication'):
            with self.subTest(point=point):
                self.destination = self.root / ('fresh-' + point)
                token = self.preview()['plan_sha256']
                with patch.object(C, 'fault', side_effect=lambda actual: (_ for _ in ()).throw(
                        OSError('injected')) if actual == point else None):
                    self.assertEqual(self.restored(token)['status'], 'incomplete')
                result = self.restored(token, recovery=True)
                self.assertEqual(result['status'], 'restored')
                self.assertEqual(result['observed_protection'], 'unverified')
                with self.assertRaises(ValueError):
                    self.restored(token)

    def test_recovery_refuses_tampered_stage_without_removing_it(self):
        token = self.preview()['plan_sha256']
        with patch.object(C, 'fault', side_effect=OSError('injected')):
            self.assertEqual(self.restored(token)['status'], 'incomplete')
        prepared = C.plan(self.archive, self.selection, self.binary, self.commit, self.destination)
        stage, _ = C.names(prepared)
        sentinel = self.root / stage / 'foreign'
        sentinel.write_bytes(b'preserve-me')
        sentinel.chmod(0o600)
        self.assertEqual(self.restored(token, recovery=True)['status'], 'incomplete')
        self.assertEqual(sentinel.read_bytes(), b'preserve-me')
        self.assertFalse(self.destination.exists())

    def test_substituted_stage_at_publication_hook_is_never_published(self):
        token = self.preview()['plan_sha256']
        prepared = C.plan(self.archive, self.selection, self.binary, self.commit, self.destination)
        stage, _ = C.names(prepared)
        moved = self.root / 'held-original-stage'
        def substitute(point):
            if point == 'before_publication':
                (self.root / stage).rename(moved)
                (self.root / stage).mkdir(mode=0o700)
                sentinel = self.root / stage / 'unrelated'
                sentinel.write_bytes(b'preserved')
                sentinel.chmod(0o600)
        with patch.object(C, 'fault', side_effect=substitute):
            self.assertEqual(self.restored(token)['status'], 'incomplete')
        self.assertFalse(self.destination.exists())
        self.assertEqual((self.root / stage / 'unrelated').read_bytes(), b'preserved')
        self.assertTrue(moved.is_dir())

    def test_journal_substitution_at_retirement_is_preserved(self):
        token = self.preview()['plan_sha256']
        prepared = C.plan(self.archive, self.selection, self.binary, self.commit, self.destination)
        _, journal = C.names(prepared)
        moved = self.root / 'original-journal'
        def substitute(point):
            if point == 'before_journal_retirement':
                (self.root / journal).rename(moved)
                (self.root / journal).write_bytes(b'foreign-private-canary')
                (self.root / journal).chmod(0o600)
        with patch.object(C, 'fault', side_effect=substitute):
            self.assertEqual(self.restored(token)['status'], 'incomplete')
        self.assertEqual((self.root / journal).read_bytes(), b'foreign-private-canary')
        self.assertTrue(moved.is_file())

    def test_runtime_workspace_and_generation_overlap_refused_without_writes(self):
        before = sorted(p.name for p in self.root.iterdir())
        for root in self.current['preserved_roots']:
            self.destination = Path(root) / 'fresh-home'
            with self.subTest(root=root), self.assertRaisesRegex(ValueError, 'overlaps_runtime_or_workspace'):
                self.preview()
        self.assertEqual(before, sorted(p.name for p in self.root.iterdir()))

    def test_export_under_workspace_or_source_refuses_without_writes(self):
        for target in (self.source / 'backup.tar', self.root / 'workspaces' / 'backup.tar'):
            with self.subTest(target=target), patch.object(C, 'capture', return_value=self.document), \
                    self.assertRaises(ValueError):
                C.backup(self.source, self.selection, self.binary, self.commit, target, consent=True)
            self.assertFalse(target.exists())

    def test_journal_publication_failure_retains_truthful_orphan_without_deleting_it(self):
        token = self.preview()['plan_sha256']
        with patch.object(C.EXCHANGE, '_publish_private', side_effect=C.EXCHANGE.Refusal('exchange_publication_unavailable')):
            report = self.restored(token)
        self.assertEqual(report['status'], 'incomplete')
        self.assertIn('restore_journal_not_published', report['blockers'])
        self.assertIn('manual_inspection', report['recovery'])
        self.assertFalse(self.destination.exists())
        prepared = C.plan(self.archive, self.selection, self.binary, self.commit, self.destination)
        stage, journal = C.names(prepared)
        self.assertTrue((self.root / stage).is_dir())
        self.assertFalse((self.root / journal).exists())
        with self.assertRaisesRegex(ValueError, 'fresh_destination'):
            self.restored(token)
        report = self.restored(token, recovery=True)
        self.assertEqual(report['status'], 'incomplete')
        self.assertTrue((self.root / stage).is_dir())

    def test_source_change_during_export_refuses_before_publication(self):
        with patch.object(C, 'capture', side_effect=[self.document, {**self.document, 'source_config': {}}]), \
                self.assertRaisesRegex(ValueError, 'source_changed'):
            C.backup(self.source, self.selection, self.binary, self.commit,
                     self.root / 'changed.tar', consent=True)
        self.assertFalse((self.root / 'changed.tar').exists())

    def test_private_export_is_create_new_and_link_inputs_refuse(self):
        with patch.object(C, 'capture', return_value=self.document):
            path = self.root / 'new.tar'
            self.assertEqual(C.backup(self.source, self.selection, self.binary,
                             self.commit, path, consent=True)['status'], 'backed-up')
            before = path.read_bytes()
            with self.assertRaises(C.EXCHANGE.Refusal):
                C.backup(self.source, self.selection, self.binary, self.commit, path, consent=True)
            self.assertEqual(path.read_bytes(), before)
            linked = self.root / 'linked.tar'
            linked.symlink_to(path)
            with self.assertRaises((ValueError, OSError)):
                C.load_archive(linked)


if __name__ == '__main__':
    unittest.main()
