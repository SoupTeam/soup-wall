#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Descriptor handback parser controls; these do not qualify native execution."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('owner_self_loss',
    Path(__file__).parents[1] / 'ci' / 'observe-owner-self-loss.py')
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)
DRIVER_SPEC = importlib.util.spec_from_file_location('owner_loss_driver',
    Path(__file__).parents[1] / 'ci' / 'native-prepared-budget-host.py')
DRIVER = importlib.util.module_from_spec(DRIVER_SPEC)
DRIVER_SPEC.loader.exec_module(DRIVER)


class PacketTests(unittest.TestCase):
    def fixture(self):
        packet = {'format': 'sw-mcp/linux-crash-owner/1', 'instance': 'a' * 32,
                  'budget': {'budget_sha256': 'b' * 64, 'leaf': 'agentfw-mcp-' + 'c' * 32,
                             'device': 1, 'inode': 2, 'started_monotonic_nanos': 3}}
        return packet

    def parse(self, packet=None, *, header=None, ancillary=None, iovec=None, payload=None):
        packet = self.fixture() if packet is None else packet
        payload = json.dumps(packet).encode() if payload is None else payload
        memory = {100: header if header is not None else struct.pack('<QI4xQQQQI4x', 0, 0, 200, 1, 300, 48, 0),
                  200: iovec if iovec is not None else struct.pack('<QQ', 400, len(payload)),
                  300: ancillary if ancillary is not None else struct.pack('<Qii8i', 48, 1, 1, *range(3, 11)),
                  400: payload}
        def read(address, length):
            return memory[address][:length]
        return OBSERVER.descriptor_packet(read, 100, 'b' * 64)

    def test_exact_eight_descriptor_prepared_message(self):
        self.assertEqual(self.parse(), self.fixture()['budget'])

    def test_descriptor_counts_types_truncation_and_aliases_refuse(self):
        for args in (
            {'header': b''}, {'iovec': b''}, {'ancillary': b''},
            {'header': struct.pack('<QI4xQQQQI4x', 0, 0, 200, 2, 300, 48, 0)},
            {'header': struct.pack('<QI4xQQQQI4x', 0, 0, 200, 1, 300, 80, 0)},
            {'ancillary': struct.pack('<Qii8i', 48, 1, 2, *range(3, 11))},
            {'ancillary': struct.pack('<Qii8i', 48, 1, 1, *([3] * 8))},
            {'iovec': struct.pack('<QQ', 400, OBSERVER.MAX_PACKET + 1)},
        ):
            with self.subTest(args=args), self.assertRaises(OBSERVER.Incomplete):
                self.parse(**args)

    def test_unknown_duplicate_or_unbound_metadata_refuses(self):
        for key, value in (('budget_sha256', 'd' * 64), ('leaf', '../foreign'),
                           ('device', 0), ('inode', True), ('started_monotonic_nanos', 0)):
            packet = self.fixture(); packet['budget'][key] = value
            with self.subTest(key=key), self.assertRaises(OBSERVER.Incomplete):
                self.parse(packet)
        for packet in (dict(self.fixture(), trusted=True), dict(self.fixture(), instance='z' * 32)):
            with self.assertRaises(OBSERVER.Incomplete): self.parse(packet)
        payload = json.dumps(self.fixture()).encode().replace(b'"format":', b'"format":"forged","format":', 1)
        with self.assertRaises(OBSERVER.Incomplete): self.parse(payload=payload)


class OutputCustodyTests(unittest.TestCase):
    def test_case_reports_never_replace_the_enclosing_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            attempt = root / 'budget-runtime-attempt.json'
            rows = []
            def checkpoint(observations):
                rows[:] = observations
                attempt.write_text(json.dumps({'status': 'in-progress', 'cases': len(rows)}))
            checkpoint([])
            def run(label, words, timeout):
                # The enclosing runner writes its checkpoint and private log
                # before invoking the diagnostic. Neither is its result file.
                checkpoint(rows)
                target = Path(words[words.index('--output') + 1])
                self.assertFalse(target.exists())
                self.assertNotEqual(target, attempt)
                (root / (label + '.private.log')).write_text('outer-log')
                target.with_suffix('.collector.private.log').write_text('collector-log')
                target.write_text(json.dumps({'status': 'blocked', 'acceptance_pass': False,
                    'production_cleanup_verified': False, 'observer_cleanup_verified': True}))
            paths = {'agentfw': root / 'agentfw', 'sandbox_tests': root / 'tests'}
            identity = {'binaries': {'agentfw': 'a' * 64, 'sandbox_tests': 'b' * 64}}
            profiles = {server: {'profile': {'path': root / (server + '.json')}}
                        for server in ('filesystem', 'git')}
            observed = DRIVER.owner_loss_controls(root, root, paths, identity, root / 'budget.json',
                profiles, 'c' * 40, run, checkpoint, lambda: None)
            self.assertEqual([row['server'] for row in observed], ['filesystem', 'git'])
            self.assertEqual(json.loads(attempt.read_text()), {'status': 'in-progress', 'cases': 2})
            for server in ('filesystem', 'git'):
                self.assertEqual(json.loads((root / ('owner-self-loss-' + server + '.json')).read_text())['status'],
                                 'blocked')

    def test_actual_observer_setup_keeps_outer_log_and_fork_failure_private(self):
        # Run actual setup through exclusive log creation, stopping before ANY
        # fork. Platform/source/identity observations are explicit component
        # fixtures; this does not claim Linux/cgroup execution on macOS.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); delegated = root / 'delegated'; delegated.mkdir(mode=0o700)
            budget = root / 'budget.json'; budget.write_text(json.dumps({'delegationRoot': str(delegated)}))
            output = root / 'owner-self-loss-filesystem.json'
            outer = output.with_suffix('.private.log'); outer.write_text('outer-runner-log')
            args = SimpleNamespace(source=root, output=output, budget=budget,
                agentfw=root / 'agentfw', test_binary=root / 'tests', profile=root / 'profile.json',
                expected_commit='c' * 40, agentfw_sha256='a' * 64, test_sha256='a' * 64)
            def git(words, **kwargs):
                return b'c' * 40 + b'\n' if 'rev-parse' in words else b''
            with mock.patch.object(OBSERVER.sys, 'platform', 'linux'), \
                 mock.patch.object(OBSERVER.platform, 'machine', return_value='x86_64'), \
                 mock.patch.object(OBSERVER.os, 'geteuid', return_value=42), \
                 mock.patch.object(OBSERVER.os, 'pidfd_open', create=True), \
                 mock.patch.object(OBSERVER.signal, 'pidfd_send_signal', create=True), \
                 mock.patch.object(OBSERVER.os, 'statvfs', return_value=SimpleNamespace(f_flag=os.ST_RDONLY)), \
                 mock.patch.object(OBSERVER.os, 'fstat', return_value=SimpleNamespace(st_uid=42, st_mode=0o40700)), \
                 mock.patch.object(OBSERVER.os, 'scandir', return_value=iter(())), \
                 mock.patch.object(OBSERVER.subprocess, 'check_output', side_effect=git), \
                 mock.patch.object(OBSERVER, 'sha', return_value='a' * 64), \
                 mock.patch.object(OBSERVER, 'Trace'), \
                 mock.patch.object(OBSERVER.os, 'fork', side_effect=OBSERVER.Incomplete('stopped_before_fork')) as fork:
                result = OBSERVER.observe(args)
            fork.assert_called_once()
            self.assertEqual(result['reason'], 'stopped_before_fork')
            self.assertEqual(result['status'], 'incomplete')
            self.assertFalse(result['acceptance_pass'])
            self.assertEqual(outer.read_text(), 'outer-runner-log')
            self.assertTrue(output.with_suffix('.collector.private.log').exists())


if __name__ == '__main__':
    unittest.main()
