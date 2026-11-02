# SPDX-License-Identifier: Apache-2.0
"""Named installed Linux budget presets: storage, selection and per-run revalidation (SOU-210)."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


B = load('budget_preset_tests', 'pilot_budget_presets.py')
P = load('budget_preset_project_tests', 'pilot_project_presets.py')
PROFILES = load('budget_preset_profiles_tests', 'pilot_provider_profiles.py')
RUN = load('budget_preset_run_tests', 'pilot-run.py')
POSIX = unittest.skipUnless(os.name == 'posix', 'POSIX descriptor-store logic; installed command is Linux-only')
ROOT_A = '/sys/fs/cgroup/operator-owned/pilot-a'
ROOT_B = '/sys/fs/cgroup/operator-owned/pilot-b'
IDENTITIES = {ROOT_A: {'device': 1, 'inode': 10, 'uid': os.getuid()},
              ROOT_B: {'device': 1, 'inode': 11, 'uid': os.getuid()}}


def config(root=ROOT_A, **limits):
    value = {'format': B.CONFIG_FORMAT, 'delegationRoot': root, 'memoryMaxBytes': 268_435_456,
             'pidsMax': 64, 'cpuQuotaMicros': 100_000, 'wallMillis': 30_000}
    value.update(limits)
    return value


def fields(baseline='accepted-bounds', **kwargs):
    value = config(**kwargs)
    return {'baseline': baseline, 'config': value, 'config_sha256': B.config_identity(value),
            'root': dict(IDENTITIES[value['delegationRoot']])}


def fake_root_identity(path):
    return dict(IDENTITIES[str(path)])


class Base(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name).resolve() / 'owned'
        self.home.mkdir(mode=0o700)
        patcher = patch.object(B, 'root_identity', side_effect=fake_root_identity)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.catalog = self.home / B.DIRECTORY / 'catalog.json'


@POSIX
class StoreBoundaries(Base):
    def test_exact_update_remove_and_stale_confirmation(self):
        with B.Store(self.home, create=True) as store:
            a = store.write('create', 'one', fields())
            b = store.write('create', 'two', fields(root=ROOT_B))
            changed = store.write('update', 'one', fields(pidsMax=32), B.record_digest(a))
            self.assertNotEqual(changed['version'], a['version'])
            self.assertEqual(store.read()['records']['two'], b)
            with self.assertRaisesRegex(ValueError, 'version_stale'):
                store.write('update', 'one', fields(pidsMax=48), B.record_digest(a))
            with self.assertRaisesRegex(ValueError, 'version_stale'):
                store.write('remove', 'one', expected=B.record_digest(a))
            store.write('remove', 'one', expected=B.record_digest(changed))
            self.assertEqual(list(store.read()['records']), ['two'])

    def test_recreated_identical_record_has_a_new_version(self):
        with B.Store(self.home, create=True) as store:
            old = store.write('create', 'one', fields())
            store.write('remove', 'one', expected=B.record_digest(old))
            new = store.write('create', 'one', fields())
        self.assertNotEqual(B.record_digest(old), B.record_digest(new))

    def test_limits_names_and_unknown_schema_refuse(self):
        with B.Store(self.home, create=True) as store:
            for i in range(B.LIMIT):
                store.write('create', 'p' + str(i), fields())
            for name in ('p0', 'extra'):
                with self.assertRaisesRegex(ValueError, 'exists_or_limit'):
                    store.write('create', name, fields())
        for name in ('../other', 'UPPER', 'a b', ''):
            with B.Store(self.home) as store, self.assertRaisesRegex(ValueError, 'name_invalid'):
                store.write('create', name, fields())
        value = json.loads(self.catalog.read_bytes())
        value['extra'] = True
        self.catalog.write_bytes(B.encoded(value))
        with B.Store(self.home) as store, self.assertRaisesRegex(ValueError, 'store_invalid'):
            store.read()

    def test_record_with_wrong_identity_or_extra_field_refuses(self):
        with B.Store(self.home, create=True) as store:
            store.write('create', 'one', fields())
        for mutate in (lambda r: r.update(config_sha256='0' * 64), lambda r: r.update(token='x'),
                       lambda r: r['root'].update(extra=1), lambda r: r.update(baseline='unknown'),
                       lambda r: r['config'].update(pidsMax=True)):
            value = json.loads(self.catalog.read_bytes())
            original = B.encoded(value)
            mutate(value['records']['one'])
            self.catalog.write_bytes(B.encoded(value))
            with B.Store(self.home) as store, self.assertRaises(ValueError):
                store.read()
            self.catalog.write_bytes(original)

    def test_missing_linked_hardlinked_and_oversize_catalog_refuse(self):
        with B.Store(self.home, create=True) as store:
            store.write('create', 'one', fields())
        raw = self.catalog.read_bytes()
        self.catalog.unlink()
        with B.Store(self.home) as store, self.assertRaisesRegex(ValueError, 'catalog_missing'):
            store.read()
        outside = self.home / 'outside'
        outside.write_bytes(raw)
        outside.chmod(0o600)
        for kind in ('link', 'hardlink', 'large', 'shared'):
            if kind == 'link':
                self.catalog.symlink_to(outside)
            elif kind == 'hardlink':
                os.link(outside, self.catalog)
            elif kind == 'large':
                self.catalog.write_bytes(b'x' * (B.CAP + 1))
                self.catalog.chmod(0o600)
            else:
                self.catalog.write_bytes(raw)
                self.catalog.chmod(0o640)
            with B.Store(self.home) as store, self.assertRaisesRegex(ValueError, 'private_file_required'):
                store.read()
            self.catalog.unlink()
        self.assertEqual(outside.read_bytes(), raw)

    def test_redirected_store_and_replaced_home_refuse_without_touching_the_other(self):
        with B.Store(self.home, create=True) as store:
            store.write('create', 'one', fields())
            old = self.home / B.DIRECTORY
            old.rename(self.home / 'held')
            old.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, 'store_changed'):
                store.read()
            self.assertEqual(list(old.iterdir()), [])
        shared = self.home.parent / 'shared'
        shared.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, 'private_directory_required'):
            B.Store(shared)
        link = self.home.parent / 'link'
        link.symlink_to(self.home)
        with self.assertRaises((ValueError, OSError)):
            B.Store(link)

    def test_unexpected_store_entries_refuse(self):
        with B.Store(self.home, create=True):
            pass
        (self.home / B.DIRECTORY / 'surprise').write_bytes(b'x')
        with B.Store(self.home) as store, self.assertRaisesRegex(ValueError, 'store_inventory_invalid'):
            store.read()

    def test_killed_writer_leaves_old_catalog_and_next_writer_resumes(self):
        with B.Store(self.home, create=True) as store:
            old = store.write('create', 'one', fields())
        leftover = self.home / B.DIRECTORY / ('.next-' + 'a' * 32)
        leftover.write_bytes(b'half written')
        leftover.chmod(0o600)
        with B.Store(self.home) as store:
            self.assertEqual(store.read()['records']['one'], old)
            current = store.write('update', 'one', fields(pidsMax=32), B.record_digest(old))
        self.assertFalse(leftover.exists())
        self.assertEqual(sorted(p.name for p in (self.home / B.DIRECTORY).iterdir()), ['catalog.json'])
        self.assertEqual(json.loads(self.catalog.read_bytes())['records']['one'], current)

    def test_interrupted_first_creation_never_leaves_a_half_store(self):
        stage = self.home / ('.stage-' + 'b' * 32)
        stage.mkdir(mode=0o700)
        (stage / 'catalog.json').write_bytes(b'partial')
        with self.assertRaisesRegex(ValueError, 'store_missing'):
            B.Store(self.home)
        with B.Store(self.home, create=True) as store:
            self.assertEqual(store.read()['records'], {})
        self.assertFalse(stage.exists())

    def test_cancellation_before_publication_preserves_catalog_and_removes_temporary(self):
        with B.Store(self.home, create=True) as store:
            old = store.write('create', 'one', fields())
            before = self.catalog.read_bytes()

            def cancelled():
                raise KeyboardInterrupt

            with self.assertRaises(KeyboardInterrupt):
                store.write('update', 'one', fields(pidsMax=32), B.record_digest(old), revalidate=cancelled)
            self.assertEqual(self.catalog.read_bytes(), before)
            self.assertEqual(sorted(p.name for p in (self.home / B.DIRECTORY).iterdir()), ['catalog.json'])

    def test_concurrent_writers_serialize_and_only_one_consumes_a_digest(self):
        with B.Store(self.home, create=True) as store:
            old = store.write('create', 'one', fields())
        expected = B.record_digest(old)
        entered, release, outcomes = threading.Event(), threading.Event(), []

        def holder():
            with B.Store(self.home) as store:
                def hold():
                    entered.set()
                    release.wait(10)
                store.write('update', 'one', fields(pidsMax=32), expected, revalidate=hold)
            outcomes.append('saved')

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(entered.wait(10))
        with B.Store(self.home) as contender, self.assertRaisesRegex(ValueError, 'store_busy'):
            contender.write('update', 'one', fields(pidsMax=48), expected)
        release.set()
        thread.join(10)
        self.assertEqual(outcomes, ['saved'])
        with B.Store(self.home) as loser, self.assertRaisesRegex(ValueError, 'version_stale'):
            loser.write('update', 'one', fields(pidsMax=48), expected)

    def test_catalog_holds_no_secret_or_authority_fields(self):
        with B.Store(self.home, create=True) as store:
            store.write('create', 'one', fields())
        text = self.catalog.read_text()
        for word in ('token', 'secret', 'grant', 'owner', 'active', 'password'):
            self.assertNotIn(word, text)


class Validation(unittest.TestCase):
    def test_accepted_bounds_mirror_the_engine_source(self):
        source = (ROOT / 'crates/agentfw/src/mcp/linux_budget.rs').read_text()
        self.assertIn('(64 * 1024 * 1024..=16 * 1024 * 1024 * 1024).contains(&self.memory_max_bytes)', source)
        self.assertIn('self.memory_max_bytes.is_multiple_of(65_536)', source)
        self.assertIn('(16..=4_096).contains(&self.pids_max)', source)
        self.assertIn('(1_000..=1_600_000).contains(&self.cpu_quota_micros)', source)
        self.assertIn('(1_000..=3_600_000).contains(&self.wall_millis)', source)
        self.assertIn("pub(crate) const FORMAT: &str = \"" + B.CONFIG_FORMAT + '";', source)
        top = B.BASELINES['accepted-bounds']
        self.assertEqual((B.FLOORS['memoryMaxBytes'], top['memoryMaxBytes'], B.MEMORY_STEP),
                         (64 * 1024 * 1024, 16 * 1024 * 1024 * 1024, 65_536))
        self.assertEqual((B.FLOORS['pidsMax'], top['pidsMax']), (16, 4_096))
        self.assertEqual((B.FLOORS['cpuQuotaMicros'], top['cpuQuotaMicros']), (1_000, 1_600_000))
        self.assertEqual((B.FLOORS['wallMillis'], top['wallMillis']), (1_000, 3_600_000))

    def test_prepared_default_baseline_matches_the_documented_selection(self):
        documented = json.loads(re.search(r'```json\n(\{"format":"sw-mcp/linux-cgroup-budget/1".*?\})\n```',
            (ROOT / 'docs/operations/PREPARED_PILOT_LINUX_BUDGETS.md').read_text(), re.S).group(1))
        top = B.BASELINES['prepared-pilot-default']
        self.assertEqual({k: documented[k] for k in B.FIELDS}, top)

    def test_floors_ceilings_steps_and_baselines(self):
        B.validate_config(config(), 'accepted-bounds')
        B.validate_config(config(), 'prepared-pilot-default')
        for field in B.FIELDS:
            B.validate_config(config(**{field: B.FLOORS[field]}), 'accepted-bounds')
            B.validate_config(config(**{field: B.BASELINES['accepted-bounds'][field]}), 'accepted-bounds')
            with self.assertRaisesRegex(ValueError, 'limit_out_of_range'):
                B.validate_config(config(**{field: B.FLOORS[field] - 1}), 'accepted-bounds')
            with self.assertRaisesRegex(ValueError, 'limit_out_of_range'):
                B.validate_config(config(**{field: B.BASELINES['accepted-bounds'][field] + 1}), 'accepted-bounds')
            with self.assertRaisesRegex(ValueError, 'limit_exceeds_baseline'):
                B.validate_config(config(**{field: B.BASELINES['prepared-pilot-default'][field] + (65_536 if field == 'memoryMaxBytes' else 1)}),
                                  'prepared-pilot-default')
        with self.assertRaisesRegex(ValueError, 'limit_out_of_range'):
            B.validate_config(config(memoryMaxBytes=268_435_457), 'accepted-bounds')
        with self.assertRaisesRegex(ValueError, 'baseline_unknown'):
            B.validate_config(config(), 'self-selected')

    def test_unsupported_shapes_and_roots_refuse(self):
        for bad in (config(pidsMax=True), config(pidsMax='64'), config(pidsMax=64.0), config(root='/tmp/cgroup'),
                    config(root='/sys/fs/cgroup'), config(root='/sys/fs/cgroup/'), config(root='/sys/fs/cgroup/a/../b'),
                    config(root='/sys/fs/cgroup/a//b'), config(root='/sys/fs/cgroup/a/'), config(root='/sys/fs/cgroup/é'),
                    config(root='/sys/fs/cgroup/a\\b'), config(root='/sys/fs/cgroup/a b'),
                    dict(config(), extra=1), {k: v for k, v in config().items() if k != 'wallMillis'},
                    dict(config(), format='sw-mcp/linux-cgroup-budget/2'), []):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                B.validate_config(bad, 'accepted-bounds')

    def test_identity_vector_matches_the_pinned_engine_vector(self):
        source = (ROOT / 'crates/agentfw/src/mcp/linux_budget.rs').read_text()
        vector = 'ea97fe06939ad1d00dd922f38f30a3a0dfdb731ecc3830238abd5a1dc9d15fcf'
        self.assertIn(vector, source)
        self.assertEqual(B.config_identity(config()), vector)

    def test_identity_is_compact_sorted_json_digest(self):
        value = config()
        self.assertEqual(B.config_identity(value), B.digest(
            b'{"cpuQuotaMicros":100000,"delegationRoot":"' + ROOT_A.encode() + b'","format":"sw-mcp/linux-cgroup-budget/1",'
            b'"memoryMaxBytes":268435456,"pidsMax":64,"wallMillis":30000}'))
        self.assertNotEqual(B.config_identity(value), B.config_identity(config(root=ROOT_B)))


@POSIX
class PerRunResolution(Base):
    def setUp(self):
        super().setUp()
        with B.Store(self.home, create=True) as store:
            self.record = store.write('create', 'one', fields())
        self.digest = B.record_digest(self.record)

    def test_exact_digest_returns_the_canonical_bytes_to_freeze(self):
        raw, record = B.resolve(self.home, 'one', self.digest)
        self.assertEqual(json.loads(raw), config())
        self.assertEqual(record, self.record)
        self.assertEqual(raw, B.encoded(config()))

    def test_stale_missing_absent_and_malformed_confirmations_never_fall_back(self):
        for expected, code in (('0' * 64, 'stale'), (None, 'confirmation_required'), ('abc', 'confirmation_required')):
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, code):
                B.resolve(self.home, 'one', expected)
        with self.assertRaisesRegex(ValueError, 'missing'):
            B.resolve(self.home, 'two', self.digest)
        with self.assertRaisesRegex(ValueError, 'name_invalid'):
            B.resolve(self.home, '../one', self.digest)
        with self.assertRaisesRegex(ValueError, 'store_missing'):
            B.resolve(self.home.parent, 'one', self.digest)

    def test_update_or_remove_invalidates_future_runs_but_not_bytes_already_frozen(self):
        frozen, _ = B.resolve(self.home, 'one', self.digest)
        with B.Store(self.home) as store:
            changed = store.write('update', 'one', fields(pidsMax=32), self.digest)
        self.assertEqual(json.loads(frozen)['pidsMax'], 64)
        with self.assertRaisesRegex(ValueError, 'stale'):
            B.resolve(self.home, 'one', self.digest)
        self.assertEqual(json.loads(B.resolve(self.home, 'one', B.record_digest(changed))[0])['pidsMax'], 32)
        with B.Store(self.home) as store:
            store.write('remove', 'one', expected=B.record_digest(changed))
        with self.assertRaisesRegex(ValueError, 'missing'):
            B.resolve(self.home, 'one', B.record_digest(changed))

    def test_replaced_delegation_root_refuses(self):
        for replacement in ({'device': 1, 'inode': 99, 'uid': os.getuid()}, {'device': 2, 'inode': 10, 'uid': os.getuid()},
                            {'device': 1, 'inode': 10, 'uid': os.getuid() + 1}):
            with patch.object(B, 'root_identity', return_value=replacement), \
                    self.assertRaisesRegex(ValueError, 'root_changed'):
                B.resolve(self.home, 'one', self.digest)
        with patch.object(B, 'root_identity', side_effect=ValueError('budget_preset_root_invalid')), \
                self.assertRaisesRegex(ValueError, 'root_invalid'):
            B.resolve(self.home, 'one', self.digest)

    def test_corrupt_catalog_refuses_resolution(self):
        self.catalog.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'store_invalid'):
            B.resolve(self.home, 'one', self.digest)

    def test_selection_reference_is_digest_bound(self):
        self.assertEqual(B.reference(self.home, 'one'), {'preset': 'one', 'digest': self.digest})


class FakeEngine:
    def __init__(self, busy=False, refuse=False):
        self.calls, self.busy, self.refuse = [], busy, refuse

    def __call__(self, words, **kwargs):
        config_path = Path(words[words.index('--config') + 1])
        value = json.loads(config_path.read_bytes())
        self.calls.append(('--probe' in words, value))
        assert kwargs['stdin'] == -3 and kwargs['env'] == {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
        probe = '--probe' in words
        if self.refuse or (probe and self.busy):
            return types.SimpleNamespace(returncode=1, stdout=b'', stderr=b'pilot_budget_root_busy' if self.busy else b'mcp_budget_config_invalid')
        return types.SimpleNamespace(returncode=0, stderr=b'', stdout=json.dumps({
            'format': 'sw-prepared-pilot-budget/1', 'budget_sha256': B.config_identity(value),
            'status': 'available-not-active' if probe else 'selected-not-active',
            'scope': 'per-original-server-process-tree', 'protected_children_started': False}).encode())


@POSIX
class Command(Base):
    def setUp(self):
        super().setUp()
        self.agentfw = self.home.parent / 'agentfw'
        self.agentfw.write_bytes(b'#!/bin/sh\n')
        self.agentfw.chmod(0o700)
        self.front = types.SimpleNamespace(PROG='owned', PROJECT_HOME=self.home, platform_reason=lambda: None,
                                           provider_profiles=lambda: PROFILES,
                                           load=lambda name, filename: load(name, filename))
        self.engine = FakeEngine()

    def call(self, words, code=0, engine=None):
        out = io.StringIO()
        with patch.object(B.sys, 'platform', 'linux'), patch.object(B.subprocess, 'run', engine or self.engine), \
                patch.object(P.sys, 'platform', 'linux'), contextlib.redirect_stdout(out):
            self.assertEqual(B.main(words, self.front), code, out.getvalue())
        return json.loads(out.getvalue())

    def limits(self, root=ROOT_A, **overrides):
        values = {'--memory-max-bytes': 268_435_456, '--pids-max': 64, '--cpu-quota-micros': 100_000, '--wall-millis': 30_000}
        values.update(overrides)
        words = ['--agentfw', str(self.agentfw), '--root', root]
        for key, value in values.items():
            words += [key, str(value)]
        return words

    def create(self, name='one', **kwargs):
        sha = B.config_identity(config(**kwargs))
        return self.call(['create', '--name', name, *self.limits(**kwargs), '--expected-config-sha256', sha, '--apply'])

    def test_preview_is_inert_and_requires_no_directory(self):
        preview = self.call(['create', '--name', 'one', *self.limits()])
        self.assertEqual((preview['status'], preview['mutates'], preview['authority'], preview['executed']),
                         ('preview', False, False, False))
        self.assertEqual(preview['new_config_sha256'], B.config_identity(config()))
        self.assertEqual(list(self.home.iterdir()), [])
        self.assertEqual([probe for probe, _ in self.engine.calls], [False])
        self.assertEqual(self.call(['inspect'])['presets'], [])
        self.assertEqual(list(self.home.iterdir()), [])

    def test_apply_needs_the_exact_previewed_configuration_digest(self):
        for wrong in (None, '0' * 64):
            words = ['create', '--name', 'one', *self.limits(), '--apply'] + ([] if wrong is None else ['--expected-config-sha256', wrong])
            self.assertEqual(self.call(words, 2)['reason'], 'budget_preset_confirmation_required')
        self.assertFalse((self.home / B.DIRECTORY).exists())

    def test_create_probes_delegation_then_publishes_one_configured_record(self):
        saved = self.create()
        self.assertEqual((saved['status'], saved['delegation'], saved['states']),
                         ('saved', 'verified-idle', {'configured': True, 'probed': False, 'witnessed_active': False}))
        self.assertEqual([probe for probe, _ in self.engine.calls], [False, True])
        listed = self.call(['inspect'])['presets']
        self.assertEqual([(p['name'], p['limits']['pidsMax'], p['baseline']) for p in listed], [('one', 64, 'accepted-bounds')])
        self.assertEqual(listed[0]['digest'], saved['digest'])

    def test_unverified_or_busy_delegation_and_engine_refusal_publish_nothing(self):
        sha = B.config_identity(config())
        words = ['create', '--name', 'one', *self.limits(), '--expected-config-sha256', sha, '--apply']
        self.assertEqual(self.call(words, 2, FakeEngine(busy=True))['reason'], 'budget_preset_delegation_busy')
        self.assertEqual(self.call(words, 2, FakeEngine(refuse=True))['reason'], 'budget_preset_engine_refused')
        self.assertFalse((self.home / B.DIRECTORY).exists())

    def test_validator_never_runs_for_values_outside_the_accepted_bounds(self):
        for override in ({'--pids-max': 15}, {'--pids-max': 4097}, {'--memory-max-bytes': 1}, {'--wall-millis': 0}):
            result = self.call(['create', '--name', 'one', *self.limits(**override)], 2)
            self.assertEqual(result['reason'], 'budget_preset_limit_out_of_range')
        self.assertEqual(self.call(['create', '--name', 'one', '--baseline', 'prepared-pilot-default',
                                    *self.limits(**{'--pids-max': 65})], 2)['reason'], 'budget_preset_limit_exceeds_baseline')
        self.assertEqual(self.engine.calls, [])

    def test_unverified_or_unowned_delegation_root_refuses(self):
        with patch.object(B, 'root_identity', side_effect=ValueError('budget_preset_root_invalid')):
            self.assertEqual(self.call(['create', '--name', 'one', *self.limits()], 2)['reason'], 'budget_preset_root_invalid')
        self.assertEqual(self.engine.calls, [])

    def test_update_confirms_old_record_and_new_configuration(self):
        old = self.create()
        sha = B.config_identity(config(pidsMax=32))
        base = ['update', '--name', 'one', *self.limits(**{'--pids-max': 32})]
        preview = self.call(base + ['--expected-version', old['digest']])
        self.assertEqual((preview['old_digest'], preview['new_config_sha256'], preview['status']),
                         (old['digest'], sha, 'preview'))
        self.assertEqual(self.call(base + ['--expected-version', '0' * 64, '--expected-config-sha256', sha, '--apply'], 2)['reason'],
                         'budget_preset_version_stale')
        self.assertEqual(self.call(base + ['--expected-version', old['digest'], '--apply'], 2)['reason'],
                         'budget_preset_confirmation_required')
        saved = self.call(base + ['--expected-version', old['digest'], '--expected-config-sha256', sha, '--apply'])
        self.assertNotEqual(saved['digest'], old['digest'])
        self.assertEqual(self.call(base + ['--expected-version', old['digest'], '--expected-config-sha256', sha, '--apply'], 2)['reason'],
                         'budget_preset_version_stale')

    def test_no_op_update_is_refused(self):
        old = self.create()
        words = ['update', '--name', 'one', *self.limits(), '--expected-version', old['digest']]
        self.assertEqual(self.call(words, 2)['reason'], 'budget_preset_unchanged')

    def test_update_of_a_busy_unchanged_root_is_allowed_but_a_busy_new_root_is_not(self):
        old = self.create()
        sha = B.config_identity(config(pidsMax=32))
        words = ['update', '--name', 'one', *self.limits(**{'--pids-max': 32}), '--expected-version', old['digest'],
                 '--expected-config-sha256', sha, '--apply']
        saved = self.call(words, 0, FakeEngine(busy=True))
        self.assertEqual(saved['delegation'], 'busy-root-unchanged')
        moved_sha = B.config_identity(config(ROOT_B, pidsMax=32))
        moved = ['update', '--name', 'one', *self.limits(ROOT_B, **{'--pids-max': 32}), '--expected-version', saved['digest'],
                 '--expected-config-sha256', moved_sha, '--apply']
        self.assertEqual(self.call(moved, 2, FakeEngine(busy=True))['reason'], 'budget_preset_delegation_busy')
        self.assertEqual(self.call(['inspect', '--name', 'one'])['presets'][0]['digest'], saved['digest'])

    def test_check_reports_configured_then_probed_without_claiming_activity(self):
        self.create()
        plain = self.call(['check', '--name', 'one', '--agentfw', str(self.agentfw)])
        self.assertEqual((plain['resource_budget'], plain['status'], plain['observed_protection']),
                         ('selected-not-validated', 'configured-not-active', 'not-observed'))
        self.assertEqual(plain['states'], {'configured': True, 'probed': False, 'witnessed_active': False})
        probed = self.call(['check', '--name', 'one', '--agentfw', str(self.agentfw), '--probe'])
        self.assertEqual((probed['resource_budget'], probed['states']['probed'], probed['states']['witnessed_active']),
                         ('available-not-active', True, False))
        self.assertEqual(self.call(['check', '--name', 'one', '--agentfw', str(self.agentfw), '--probe'], 2,
                                   FakeEngine(busy=True))['reason'], 'budget_preset_delegation_busy')
        self.assertEqual(self.call(['check', '--name', 'two', '--agentfw', str(self.agentfw)], 2)['reason'], 'budget_preset_missing')

    def test_check_refuses_replaced_root_and_untrusted_engine(self):
        self.create()
        with patch.object(B, 'root_identity', return_value={'device': 9, 'inode': 9, 'uid': os.getuid()}):
            self.assertEqual(self.call(['check', '--name', 'one', '--agentfw', str(self.agentfw)], 2)['reason'], 'budget_preset_root_changed')
        self.agentfw.chmod(0o722)
        self.assertEqual(self.call(['check', '--name', 'one', '--agentfw', str(self.agentfw)], 2)['reason'], 'budget_preset_agentfw_invalid')
        self.agentfw.chmod(0o700)
        link = self.home.parent / 'agentfw-link'
        link.symlink_to(self.agentfw)
        self.assertEqual(self.call(['check', '--name', 'one', '--agentfw', str(link)], 2)['reason'], 'budget_preset_agentfw_invalid')

    def test_engine_disagreement_on_identity_refuses(self):
        self.create()

        def lying(words, **kwargs):
            result = FakeEngine()(words, **kwargs)
            value = json.loads(result.stdout)
            value['budget_sha256'] = '1' * 64
            result.stdout = json.dumps(value).encode()
            return result

        self.assertEqual(self.call(['check', '--name', 'one', '--agentfw', str(self.agentfw)], 2, lying)['reason'],
                         'budget_preset_engine_refused')

    def test_remove_previews_then_requires_exact_digest_and_unused_preset(self):
        old = self.create()
        self.create('two', root=ROOT_B)
        preview = self.call(['remove', '--name', 'one', '--expected-version', old['digest']])
        self.assertEqual((preview['status'], preview['mutates']), ('preview', False))
        self.assertEqual(self.call(['remove', '--name', 'one', '--expected-version', '0' * 64, '--apply'], 2)['reason'],
                         'budget_preset_version_stale')
        done = self.call(['remove', '--name', 'one', '--expected-version', old['digest'], '--apply'])
        self.assertEqual(done['status'], 'removed')
        self.assertEqual([p['name'] for p in self.call(['inspect'])['presets']], ['two'])

    def test_selected_preset_cannot_be_removed_but_can_be_updated_which_stales_the_project(self):
        old = self.create()
        used = types.SimpleNamespace(load=lambda *_: types.SimpleNamespace(
            Store=lambda *_: contextlib.nullcontext(types.SimpleNamespace(read=lambda: {'records': {
                'proj': {'binding': {'budget': {'preset': 'one', 'digest': old['digest']}}},
                'other': {'binding': {'budget': None}}}}))), provider_profiles=lambda: None)
        self.front.load, self.front.provider_profiles = used.load, used.provider_profiles
        result = self.call(['remove', '--name', 'one', '--expected-version', old['digest'], '--apply'], 2)
        self.assertEqual(result['reason'], 'budget_preset_in_use')
        self.assertEqual(self.call(['inspect', '--name', 'one'])['presets'][0]['digest'], old['digest'])
        preview = self.call(['update', '--name', 'one', *self.limits(**{'--pids-max': 32}), '--expected-version', old['digest']])
        self.assertEqual(preview['selected_by'], ['proj'])

    def test_non_linux_and_hostile_names_refuse_before_any_state(self):
        out = io.StringIO()
        with patch.object(B.sys, 'platform', 'darwin'), contextlib.redirect_stdout(out):
            self.assertEqual(B.main(['inspect'], self.front), 2)
        self.assertEqual(json.loads(out.getvalue())['reason'], 'budget_preset_native_linux_required')
        self.assertEqual(self.call(['check', '--name', '../x', '--agentfw', str(self.agentfw)], 2)['reason'], 'budget_preset_name_invalid')
        self.assertEqual(list(self.home.iterdir()), [])

    def test_two_independent_presets_keep_separate_roots_and_identities(self):
        self.create('one')
        self.create('two', root=ROOT_B)
        presets = {p['name']: p for p in self.call(['inspect'])['presets']}
        self.assertNotEqual(presets['one']['root_identity'], presets['two']['root_identity'])
        self.assertNotEqual(presets['one']['config_sha256'], presets['two']['config_sha256'])


@POSIX
class ProjectSelection(Base):
    def binding(self, budget):
        return {'selection': {'path': '/owned/selection.json', 'sha256': 'a' * 64}, 'commit': 'b' * 40, 'tree': 'b' * 40,
                'runtime_profiles_sha256': 'c' * 64,
                'workspaces': {k: {'path': '/owned/' + k, 'device': 1, 'inode': 2, 'uid': os.getuid()} for k in ('filesystem', 'git')},
                'snapshot_sha256': 'c' * 64, 'provider': {'name': 'owned', 'version': 'd' * 32, 'sha256': 'e' * 64},
                'budget': budget, 'state_root': {'path': '/owned/runs', 'identity': [1, 2, os.getuid()]}}

    def test_binding_accepts_exact_forms_only(self):
        for good in (None, {'path': '/owned/b.json', 'sha256': 'a' * 64}, {'preset': 'one', 'digest': 'a' * 64}):
            P.validate_binding(self.binding(good))
        for bad in ({'preset': 'one'}, {'preset': 'ONE', 'digest': 'a' * 64}, {'preset': 'one', 'digest': 'a' * 64, 'path': '/x'},
                    {'preset': 'one', 'digest': 'z' * 64}, {'path': '/owned/b.json', 'digest': 'a' * 64}, 'one', []):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'binding_invalid'):
                P.validate_binding(self.binding(bad))
        selection = self.binding(None)
        selection['selection'] = {'preset': 'one', 'digest': 'a' * 64}
        with self.assertRaisesRegex(ValueError, 'binding_invalid'):
            P.validate_binding(selection)

    def test_existing_unbudgeted_and_file_budget_catalogs_remain_valid(self):
        with P.Store(self.home, PROFILES, create=True) as store:
            store.write('create', 'plain', self.binding(None))
            store.write('create', 'filed', self.binding({'path': '/owned/b.json', 'sha256': 'a' * 64}))
            store.write('create', 'named', self.binding({'preset': 'one', 'digest': 'a' * 64}))
            self.assertEqual(sorted(store.read()['records']), ['filed', 'named', 'plain'])

    def run_words(self, budget):
        front = types.SimpleNamespace(PROG='owned', PROJECT_HOME=self.home, INSTALLED_HOME=None, provider_profiles=lambda: PROFILES,
                                      platform_reason=lambda: None, PYTHON_FLAGS=['-I'], RUNNER=Path('/owned/pilot-run.py'))
        with P.Store(self.home, PROFILES, create=True) as store:
            store.write('create', 'one', self.binding(budget))
            version = P.digest(P.encoded(store.read()['records']['one']))
        seen = []
        with patch.object(P.sys, 'platform', 'linux'), patch.object(P, 'verify'), \
                patch.object(P.os, 'execve', side_effect=lambda _exe, words, _env: seen.append(words)), \
                contextlib.redirect_stdout(io.StringIO()):
            P.main(['run', '--name', 'one', '--expected-version', version, '--apply'], front)
        return seen[0]

    def test_named_run_passes_the_preset_name_digest_and_home_never_a_budget_file(self):
        words = self.run_words({'preset': 'one', 'digest': 'a' * 64})
        for flag, value in (('--budget-preset', 'one'), ('--expected-budget-preset-digest', 'a' * 64),
                            ('--budget-preset-home', str(self.home))):
            self.assertEqual(words[words.index(flag) + 1], value)
        self.assertNotIn('--linux-budget', words)

    def test_file_budget_run_is_unchanged_and_unbudgeted_run_stays_unbudgeted(self):
        words = self.run_words({'path': '/owned/b.json', 'sha256': 'a' * 64})
        self.assertIn('--linux-budget', words)
        self.assertFalse(any(w.startswith('--budget-preset') for w in words))
        self.home.joinpath(P.DIRECTORY, 'catalog.json').unlink()
        (self.home / P.DIRECTORY).rmdir()
        plain = self.run_words(None)
        self.assertFalse(any('budget' in w for w in plain))

    def test_check_refuses_a_stale_or_removed_preset_before_any_launch(self):
        with B.Store(self.home, create=True) as store:
            record = store.write('create', 'one', fields())
        digest = B.record_digest(record)
        binding = self.binding({'preset': 'one', 'digest': digest})
        loaded = types.SimpleNamespace(resolve=B.resolve)
        with patch.object(P, 'budgets', return_value=B), patch.object(P, 'snapshot', return_value=binding):
            P.verify(binding, self.home, None, PROFILES)
            with B.Store(self.home) as store:
                changed = store.write('update', 'one', fields(pidsMax=32), digest)
            with self.assertRaisesRegex(ValueError, 'budget_preset_stale'):
                P.verify(binding, self.home, None, PROFILES)
            with B.Store(self.home) as store:
                store.write('remove', 'one', expected=B.record_digest(changed))
            with self.assertRaisesRegex(ValueError, 'budget_preset_missing'):
                P.verify(binding, self.home, None, PROFILES)
        del loaded

    def test_file_and_preset_selection_conflict_refuses(self):
        front = types.SimpleNamespace(PROG='owned', PROJECT_HOME=self.home, platform_reason=lambda: None,
                                      provider_profiles=lambda: PROFILES)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            P.main(['create', '--name', 'x', '--selection', '/a', '--provider-name', 'p', '--provider-version', 'v',
                    '--state-root', '/s', '--linux-budget', '/b', '--budget-preset', 'one'], front)


@POSIX
class PreparedRunIntegration(Base):
    """pilot-run revalidates the preset itself, whichever launcher path selected it."""

    def setUp(self):
        super().setUp()
        patcher = patch.object(RUN.BUDGET_PRESETS, 'root_identity', side_effect=fake_root_identity)
        patcher.start()
        self.addCleanup(patcher.stop)
        with B.Store(self.home, create=True) as store:
            self.record = store.write('create', 'one', fields())
        self.digest = B.record_digest(self.record)

    def args(self, root, digest=None):
        selection = root / 'generations' / ('a' * 32) / 'selection.json'
        return types.SimpleNamespace(selection=selection, expected_commit='b' * 40, run=False, state_root=root, port=0,
                                     timeout_seconds=30, ask_wait_seconds=0, prompt='owned control', linux_budget=None,
                                     budget_preset='one', budget_preset_home=self.home,
                                     expected_budget_preset_digest=digest or self.digest, expected_budget_sha256=None)

    def test_budget_selection_helpers_never_treat_a_preset_as_unbudgeted(self):
        args = self.args(self.home)
        self.assertTrue(RUN.budget_requested(args))
        self.assertEqual(json.loads(RUN.budget_bytes(args)), config())
        self.assertFalse(RUN.budget_requested(types.SimpleNamespace(linux_budget=None)))

    def test_stale_changed_removed_or_relocated_preset_refuses_every_run(self):
        args = self.args(self.home)
        with B.Store(self.home) as store:
            changed = store.write('update', 'one', fields(pidsMax=32), self.digest)
        with self.assertRaisesRegex(ValueError, 'stale'):
            RUN.budget_bytes(args)
        args = self.args(self.home, B.record_digest(changed))
        with patch.object(RUN.BUDGET_PRESETS, 'root_identity', return_value={'device': 7, 'inode': 7, 'uid': os.getuid()}), \
                self.assertRaisesRegex(ValueError, 'root_changed'):
            RUN.budget_bytes(args)
        with B.Store(self.home) as store:
            store.write('remove', 'one', expected=B.record_digest(changed))
        with self.assertRaisesRegex(ValueError, 'missing'):
            RUN.budget_bytes(args)

    def test_changed_preset_refuses_before_daemon_or_host_and_never_retries_without_a_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = load('budget_preset_run_fixture', 'tests/test_pilot_run.py') if False else None
            del fixture
            args = self.args(root)
            selection = {'format': 'sw-installed-pilot-selection/2', 'source': {'commit': args.expected_commit}, 'files': {}}
            with B.Store(self.home) as store:
                store.write('update', 'one', fields(pidsMax=32), self.digest)
            with patch.object(RUN.PREP, 'supported_platform'), \
                    patch.object(RUN, 'selected', return_value=(selection, {}, {})), \
                    patch.object(RUN, 'environment', return_value={}), \
                    patch.object(RUN, 'budget_cli') as probe, patch.object(RUN.subprocess, 'Popen') as spawn:
                with self.assertRaises(Exception) as caught:
                    RUN.run(args, {})
                self.assertIn('stale', str(caught.exception))
                probe.assert_not_called()
                spawn.assert_not_called()
            self.assertFalse(list(root.glob('soup-wall-run-*')))

    def test_preset_and_file_budget_cannot_be_combined_and_plan_never_executes(self):
        argv = ['pilot-run', '--selection', '/x/generations/' + 'a' * 32 + '/selection.json', '--expected-commit', 'b' * 40,
                '--budget-preset', 'one', '--budget-preset-home', str(self.home),
                '--expected-budget-preset-digest', self.digest]
        out = io.StringIO()
        with patch.object(RUN.sys, 'argv', argv + ['--linux-budget', '/owned/budget.json']), \
                patch.object(RUN.subprocess, 'Popen') as spawn, contextlib.redirect_stdout(out):
            self.assertEqual(RUN.main(), 1)
        self.assertEqual(json.loads(out.getvalue())['reason'], 'budget_preset_selection_conflict')
        for partial in (argv[:7], argv[:9]):
            out = io.StringIO()
            with patch.object(RUN.sys, 'argv', partial), contextlib.redirect_stdout(out):
                self.assertEqual(RUN.main(), 1)
            self.assertEqual(json.loads(out.getvalue())['reason'], 'budget_preset_selection_conflict')
        spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
