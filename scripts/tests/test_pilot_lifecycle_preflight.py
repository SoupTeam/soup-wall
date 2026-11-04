# SPDX-License-Identifier: Apache-2.0
"""Independent kernel fixtures and zero-effect early-refusal controls (SOU-225)."""
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

M = load('preflight_controls', 'pilot_lifecycle_preflight.py')


def process_stat(pid=41, start=100, state='S'):
    return (str(pid) + ' (private canary (worker)) ' + state + ' ' + ' '.join(['0'] * 18 + [str(start)])).encode()


class Kernel:
    def __init__(self):
        self.data = {'/etc/os-release': b'ID=ubuntu\nVERSION_ID="24.04"\n',
            '/proc/sys/kernel/osrelease': b'6.18-generic', '/proc/sys/user/max_user_namespaces': b'1000',
            '/proc/sys/kernel/unprivileged_userns_clone': b'1',
            '/proc/self/uid_map': b'         0          0 4294967295\n',
            '/proc/self/mountinfo': b'1 0 0:1 / /proc rw,nosuid,nodev,noexec - proc proc rw\n',
            '/proc/41/stat': process_stat(), '/proc/41/status': b'Uid:\t1001 1001 1001 1001\n', '/proc/41/cmdline': b'secret-command-canary\0/private/workspace\0',
            '/proc/41/environ': b'PRIVATE_CREDENTIAL=secret-value-canary\0',
            '/proc/41/maps': b'private-memory-map-canary'}
        self.links = {'/proc/self/ns/user': 'user:[4026531837]', **{
            '/proc/41/' + leaf: '/private/workspace-canary' for leaf in ('cwd', 'exe', 'root')}}
        self.inventory = {'/proc': ['self', '41'], '/proc/41/fd': []}
        self.errors = {}
        self.stat_reads = 0
        self.reuse = False
        self.disappeared = False
        self.meta_count = 0
        self.uid_changed = False

    def read(self, path, cap):
        if path in self.errors:
            raise self.errors[path]
        if path == '/proc/41/stat':
            self.stat_reads += 1
            if self.stat_reads > 1 and self.reuse:
                return process_stat(start=101)
        value = self.data[path]
        if len(value) > cap:
            raise M.Unavailable('individual_read_bound')
        return value

    def link(self, path):
        if path in self.errors:
            raise self.errors[path]
        return self.links[path]

    def metadata(self, path, *, follow=True):
        if self.disappeared and not follow:
            raise FileNotFoundError(errno.ENOENT, 'gone')
        self.meta_count += 1
        return SimpleNamespace(st_uid=1001 if not self.uid_changed or self.meta_count == 1 else 1002,
                               st_ino=41, st_dev=1)

    def verify_procfs(self):
        pass

    def names(self, path, cap):
        values = self.inventory[path]
        for i, value in enumerate(values):
            if i >= cap:
                raise M.Unavailable('process_inventory_bound')
            yield value


def observe(kernel):
    return M.inspect(_reader=kernel, _system='Linux', _machine='x86_64', _uid=1001, _pid=99)


class KernelControls(unittest.TestCase):
    def setUp(self):
        self.kernel = Kernel()

    def codes(self, report):
        return {r['reason_code'] for r in report['checks']}

    def test_complete_current_visibility_is_never_runtime_or_removal_authority(self):
        report = observe(self.kernel)
        self.assertEqual((report['setup'], report['protected_run'], report['removal']),
                         ('satisfied', 'unknown', 'satisfied'))
        self.assertFalse(report['removal_authorized'])
        self.assertEqual(report['future_inactivity'], 'not_proven')
        raw = json.dumps(report)
        for private in ('41', 'secret-command-canary', 'secret-value-canary', 'workspace-canary', 'memory-map-canary'):
            self.assertNotIn(private, raw)

    def test_eacces_does_not_relabel_setup_or_protected_runs(self):
        self.kernel.errors['/proc/41/cwd'] = PermissionError(errno.EACCES, '/private/canary')
        report = observe(self.kernel)
        self.assertEqual((report['setup'], report['protected_run'], report['removal']),
                         ('satisfied', 'unknown', 'blocked'))
        self.assertIn('process_evidence_inaccessible', self.codes(report))
        self.assertNotIn('canary', json.dumps(report))

    def test_root_owned_proc_objects_do_not_hide_same_uid_process(self):
        original = self.kernel.metadata
        def root_owned(path, **options):
            value = original(path, **options)
            value.st_uid = 0
            return value
        self.kernel.metadata = root_owned
        self.kernel.errors['/proc/41/cwd'] = PermissionError(errno.EACCES, 'private')
        self.assertEqual(observe(self.kernel)['removal'], 'blocked')
        self.kernel.data['/proc/41/status'] = b'Uid: 0 0 0 0\n'
        self.assertEqual(observe(self.kernel)['removal'], 'satisfied')
        self.kernel.errors['/proc/41/status'] = PermissionError(errno.EACCES, 'private')
        self.assertEqual(observe(self.kernel)['removal'], 'blocked')

    def test_hidden_proc_and_nonproc_mount_never_report_complete(self):
        for value in (b'1 0 0:1 / /proc rw - proc proc rw,hidepid=2\n',
                      b'1 0 0:1 / /proc rw - proc proc rw,subset=pid\n',
                      b'1 0 0:1 / /proc rw - tmpfs none rw\n'):
            self.kernel.data['/proc/self/mountinfo'] = value
            report = observe(self.kernel)
            self.assertEqual(report['removal'], 'unknown')
            self.assertIn('proc_inventory_hidden_or_unverified', self.codes(report))

    def test_pid_reuse_and_inconsistent_identity_are_unknown(self):
        self.kernel.reuse = True
        self.assertIn('process_identity_inconsistent', self.codes(observe(self.kernel)))
        self.kernel = Kernel()
        self.kernel.data['/proc/41/stat'] = process_stat(pid=42)
        self.assertEqual(observe(self.kernel)['removal'], 'unknown')
        self.kernel = Kernel(); self.kernel.uid_changed = True
        self.assertEqual(observe(self.kernel)['removal'], 'unknown')

    def test_zombie_identity_is_also_rechecked(self):
        self.kernel.data['/proc/41/stat'] = process_stat(state='Z')
        self.kernel.reuse = True
        self.assertEqual(observe(self.kernel)['removal'], 'unknown')

    def test_only_confirmed_disappearance_is_disregarded(self):
        self.kernel.errors['/proc/41/cwd'] = FileNotFoundError(errno.ENOENT, 'gone')
        self.assertEqual(observe(self.kernel)['removal'], 'unknown')
        self.kernel.disappeared = True
        self.assertEqual(observe(self.kernel)['removal'], 'satisfied')

    def test_namespace_unknown_and_nonhost_are_distinct(self):
        self.kernel.data['/proc/self/uid_map'] = b'garbage'
        self.assertEqual(observe(self.kernel)['removal'], 'unknown')
        self.kernel.data['/proc/self/uid_map'] = b'0 1001 1\n'
        report = observe(self.kernel)
        self.assertEqual((report['setup'], report['removal']), ('satisfied', 'blocked'))
        self.assertIn('removal_host_user_namespace_required', self.codes(report))
        self.kernel.errors['/proc/self/ns/user'] = PermissionError(errno.EACCES, 'private')
        self.assertEqual(observe(self.kernel)['setup'], 'unknown')

    def test_individual_process_fd_and_aggregate_time_bounds_fail_unknown(self):
        for code in ('individual_read_bound', 'process_inventory_bound', 'inspection_budget_exhausted'):
            with self.subTest(code=code):
                self.kernel.errors['/proc/41/maps'] = M.Unavailable(code)
                self.assertEqual(observe(self.kernel)['removal'], 'unknown')
        self.kernel = Kernel()
        self.kernel.inventory['/proc/41/fd'] = ['0'] * (M.MAX_FDS + 1)
        self.kernel.links['/proc/41/fd/0'] = '/private'
        self.assertEqual(observe(self.kernel)['removal'], 'unknown')
        budget = M.Reader()
        with self.assertRaises(M.Unavailable):
            budget.tick(M.MAX_BYTES + 1)
        budget = M.Reader()
        with mock.patch.object(M.time, 'monotonic', return_value=budget.started + M.MAX_SECONDS):
            with self.assertRaises(M.Unavailable):
                budget.tick()

    def test_changed_state_after_good_diagnosis_does_not_supply_new_authority(self):
        first = observe(self.kernel)
        self.assertEqual(first['removal'], 'satisfied')
        self.kernel.errors['/proc/41/exe'] = PermissionError(errno.EACCES, 'private')
        current = observe(self.kernel)
        with self.assertRaises(M.Refusal):
            M.require_preparation(current, removal=True)
        self.assertFalse(first['removal_authorized'])

    def test_namespace_disabled_refuses_setup_while_missing_evidence_is_unknown(self):
        self.kernel.data['/proc/sys/user/max_user_namespaces'] = b'0'
        self.assertEqual(observe(self.kernel)['setup'], 'blocked')
        self.kernel.errors['/proc/sys/user/max_user_namespaces'] = PermissionError(errno.EACCES, 'private')
        self.assertEqual(observe(self.kernel)['setup'], 'unknown')

    def test_removal_only_limit_is_optional_for_setup_but_explicit_requirement_refuses(self):
        report = observe(self.kernel)
        report['removal'] = 'blocked'
        M.require_preparation(report)
        with self.assertRaises(M.Refusal):
            M.require_preparation(report, removal=True)


class EarlyEffects(unittest.TestCase):
    def test_front_door_required_refusal_precedes_plan_and_all_effects(self):
        front = load('early_front', 'pilot.py')
        args = front.parser().parse_args(['prepare', '--apply', '--prefix', '/private/owned-new', '--allow-download'])
        refused = observe(Kernel()); refused['setup'] = 'unknown'
        with mock.patch.object(front.LIFECYCLE, 'inspect', return_value=refused), \
                mock.patch.object(front, 'plan') as plan, mock.patch.object(front, 'child') as child, \
                mock.patch.object(front, 'download') as download, mock.patch.object(Path, 'mkdir') as mkdir:
            with self.assertRaises(front.LIFECYCLE.Refusal):
                front.prepare(args)
        for effect in (plan, child, download, mkdir):
            effect.assert_not_called()

    def test_direct_preparation_required_refusal_precedes_source_and_lock_and_runtime(self):
        prep = load('early_prepare', 'prepare-installed-pilot.py')
        args = SimpleNamespace(wsl_root=None, git_profile=prep.GIT_PROFILES.DEFAULT, require_removal_eligible=True)
        refused = observe(Kernel()); refused['removal'] = 'unknown'
        with mock.patch.object(prep, 'supported_platform'), \
                mock.patch.object(prep.lifecycle_preflight, 'inspect', return_value=refused), \
                mock.patch.object(prep.PILOT, 'source') as source, \
                mock.patch.object(prep, 'private_dir') as mkdir, mock.patch.object(prep.subprocess, 'run') as child:
            with self.assertRaises(prep.lifecycle_preflight.Refusal):
                prep.prepare(args)
        for effect in (source, mkdir, child):
            effect.assert_not_called()

    def test_installed_entry_dispatch_needs_no_checkout_selection_or_child(self):
        front = load('preflight_front', 'pilot.py')
        report = observe(Kernel())
        with mock.patch.object(front.LIFECYCLE, 'inspect', return_value=report), \
                mock.patch.object(front, 'source') as source, mock.patch.object(front, 'child') as child, \
                mock.patch.object(Path, 'mkdir') as mkdir, mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(front.main(['--agent-home', '/private/component', 'preflight', '--json']), 0)
            self.assertEqual(json.loads(out.getvalue()), report)
        for effect in (source, child, mkdir):
            effect.assert_not_called()

class ObservationWitness(unittest.TestCase):
    def test_native_observer_uses_bounded_completed_process_result(self):
        driver = load('native_preflight_observer_controls', 'verify-sou225-lifecycle-preflight.py')
        import subprocess
        expected = subprocess.CompletedProcess([], 0, b'{"result":true}', b'')
        with mock.patch.object(driver.TRACE, 'run_observed', return_value=expected), \
                mock.patch.object(driver.shutil, 'which', return_value='/usr/bin/strace'), \
                mock.patch.object(Path, 'mkdir'):
            actual, trace = driver.observe(['/owned/agentfw'], [Path('/owned/agentfw')], Path('/owned/private'), {}, 'case')
        self.assertIs(actual, expected)
        self.assertEqual(trace.name, 'case.trace')

    def test_syscall_witness_rejects_failed_exec_write_network_and_signal_attempts(self):
        driver = load('native_preflight_trace_controls', 'verify-sou225-lifecycle-preflight.py')
        import tempfile
        baseline = '123 execve("/owned/agentfw", ["agentfw"], 0x0) = 0\n'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'trace'
            path.write_text(baseline)
            self.assertEqual(driver.audit(path, [Path('/owned/agentfw')])['extra_execution_attempts'], 0)
            for extra in ('124 execve("/unselected", [], 0x0) = -1 ENOENT\n',
                          '123 openat(AT_FDCWD, "/private", O_WRONLY|O_CREAT, 0600) = 4\n',
                          '123 connect(3, {}, 0) = -1 EPERM\n', '123 kill(42, SIGTERM) = -1 ESRCH\n',
                          '123 unshare(CLONE_NEWUSER) = -1 EPERM\n'):
                with self.subTest(extra=extra):
                    path.write_text(baseline + extra)
                    with self.assertRaises(ValueError):
                        driver.audit(path, [Path('/owned/agentfw')])


if __name__ == '__main__':
    unittest.main()
