import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import os
import sys
import subprocess
import shutil
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('diff', Path(__file__).with_name('agent-diagnostic-diff.py'))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class Controls(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux', 'native private reader required')
    def test_offline_scenario_witnesses(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            a, b = root / 'a', root / 'b'
            self.bundle(a)
            self.bundle(b, 'ready')
            report = json.loads((b / 'report.json').read_text())
            report['checks'] = [
                {'id': 'authenticated_runtime', 'source': 'authenticated_status_nonce_and_bearer',
                 'outcome': 'unknown', 'reason_code': 'daemon_unavailable'},
                {'id': 'configuration', 'source': 'private_config_yaml', 'outcome': 'ready',
                 'reason_code': 'config_valid', 'sha256': 'b' * 64},
            ]
            report['session'] = 'UNRELATED_PRIVATE_SESSION'
            raw = json.dumps(report).encode()
            (b / 'report.json').write_bytes(raw)
            manifest = json.loads((b / 'manifest.json').read_text())
            manifest['files'][0].update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
            (b / 'manifest.json').write_text(json.dumps(manifest))
            output = root / 'private'
            output.mkdir(mode=0o700)
            sibling = root / 'sibling'
            sibling.write_text('PRIVATE_CANARY')
            originals = {p: p.read_bytes() for folder in (a, b) for p in folder.iterdir()}
            args = [str(a), str(b), '--json-out', str(output / 'diff.json'),
                    '--markdown-out', str(output / 'diff.md')]
            with patch('subprocess.Popen', side_effect=AssertionError('unexpected child')), \
                 patch('socket.socket', side_effect=AssertionError('unexpected network')):
                self.assertEqual(tool.main(args), 0)
                self.assertEqual(tool.main([str(a), str(a), *args[2:]]), 2)
            result = json.loads((output / 'diff.json').read_text())
            self.assertEqual(result['correlation'], 'none_no_authenticated_cross_bundle_call_binding')
            self.assertTrue(result['historical'])
            self.assertFalse(result['execution_observed'])
            for name in ('diff.json', 'diff.md'):
                body = (output / name).read_text()
                self.assertNotIn('PRIVATE_CANARY', body)
                self.assertNotIn('UNRELATED_PRIVATE_SESSION', body)
            for path, body in originals.items():
                self.assertEqual(path.read_bytes(), body)
            self.assertEqual(sibling.read_text(), 'PRIVATE_CANARY')

    @unittest.skipUnless(os.environ.get('AGENTFW_TEST_BINARY') and sys.platform == 'linux', 'installed Linux exporter required')
    def test_installed_exporter_outside_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            installed = root / 'installed'
            installed.mkdir(mode=0o700)
            binary = installed / 'agentfw'
            shutil.copy2(os.environ['AGENTFW_TEST_BINARY'], binary)
            home = root / 'profile'
            home.mkdir(mode=0o700)
            config = home / 'config.yaml'
            sibling = root / 'sibling'
            sibling.write_text('PRIVATE_CANARY')
            for label, enforce in (('before', False), ('after', True)):
                config.write_text('enforce: ' + str(enforce).lower() + '\n# PRIVATE_CANARY\n')
                config.chmod(0o600)
                result = subprocess.run([str(binary), 'doctor', '--home', str(home), '--json',
                                         '--support-bundle', str(root / label)], cwd=root,
                                        capture_output=True, timeout=20)
                self.assertIn(result.returncode, (0, 3), result.stderr)
                self.assertTrue((root / label / 'manifest.json').is_file())
            original = {str(p): p.read_bytes() for label in ('before', 'after')
                        for p in (root / label).iterdir()}
            output = root / 'private'
            output.mkdir(mode=0o700)
            self.assertEqual(tool.main([str(root / 'before'), str(root / 'after'),
                                       '--json-out', str(output / 'diff.json'),
                                       '--markdown-out', str(output / 'diff.md')]), 0)
            self.assertNotIn('PRIVATE_CANARY', (output / 'diff.json').read_text())
            self.assertEqual(sibling.read_text(), 'PRIVATE_CANARY')
            for path, body in original.items():
                self.assertEqual(Path(path).read_bytes(), body)

    def test_malformed_pilot_checks_refused(self):
        for checks in (1, None, 'invalid', {}, [1]):
            with self.subTest(checks=checks), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / 'a'
                self.bundle(root)
                report = json.loads((root / 'report.json').read_text())
                report['pilot'] = {'checks': checks}
                raw = json.dumps(report).encode()
                (root / 'report.json').write_bytes(raw)
                manifest = json.loads((root / 'manifest.json').read_text())
                manifest['files'][0].update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
                (root / 'manifest.json').write_text(json.dumps(manifest))
                with patch.object(tool.audit, '_open_input', lambda p: open(p, 'rb')):
                    with self.assertRaises(ValueError):
                        tool.load(root)

    def bundle(self, root, setup='unknown'):
        root.mkdir()
        report = {'schema': 'sw-agent-doctor/1', 'scope': tool.SCOPE, 'observed_at_ms': 1,
                  'setup': setup, 'active_host_call_protection': 'unknown', 'checks': [], 'prompt': 'PRIVATE_CANARY'}
        raw = json.dumps(report).encode()
        (root / 'report.json').write_bytes(raw)
        (root / 'manifest.json').write_text(json.dumps({'schema': 'sw-agent-doctor-support/1',
            'report_schema': 'sw-agent-doctor/1', 'files': [{'name': 'report.json', 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}]}))

    def test_actual_schema_and_private_projection(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b = Path(temp) / 'a', Path(temp) / 'b'
            self.bundle(a)
            self.bundle(b, 'ready')
            with patch.object(tool.audit, '_open_input', lambda p: open(p, 'rb')):
                result = tool.compare(tool.load(a), tool.load(b))
            self.assertEqual(result['rows'][0]['state'], 'changed')
            self.assertTrue(result['historical'])
            self.assertFalse(result['execution_observed'])
            self.assertIn('configuration.setup', result['changed_fields'])
            self.assertNotIn('PRIVATE_CANARY', json.dumps(result))

    def test_corrupt_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            a = Path(temp) / 'a'
            self.bundle(a)
            (a / 'report.json').write_text('{}')
            with patch.object(tool.audit, '_open_input', lambda p: open(p, 'rb')):
                with self.assertRaises(ValueError):
                    tool.load(a)

    def test_duplicate_keys_nonfinite_and_depth(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'[' * 100 + b']' * 100):
            with self.assertRaises(ValueError):
                tool.parse(raw)

    def test_real_exporter_schema_has_useful_named_checks(self):
        report = json.loads((Path(__file__).parents[1] / 'docs/operations/evidence/sou74/doctor-sample.json').read_text())
        fields = {}
        tool.project_checks(report['checks'], 'checks.', fields)
        self.assertEqual(fields['checks.authenticated_runtime.reason_code'], 'daemon_unavailable')
        self.assertEqual(fields['checks.configuration.outcome'], 'ready')
        changed = dict(fields)
        changed['checks.configuration.sha256'] = 'a' * 64
        result = tool.compare({'fields': fields}, {'fields': changed})
        row = next(row for row in result['rows'] if row['field'] == 'checks.configuration.sha256')
        self.assertEqual(row['state'], 'missing')

    def test_pilot_checks_compare_by_identity_not_order(self):
        checks = [
            {'id': 'pilot_policy', 'source': 'validated_selected_policy',
             'outcome': 'ready', 'reason_code': 'selected_policy_identity', 'sha256': 'a' * 64},
            {'id': 'pilot_runtime', 'source': 'authenticated_status_nonce_and_bearer',
             'outcome': 'unknown', 'reason_code': 'daemon_unavailable'},
        ]
        left, right = {}, {}
        tool.project_checks(checks, 'pilot.checks.', left)
        tool.project_checks(list(reversed(checks)), 'pilot.checks.', right)
        self.assertEqual(left, right)
        right['pilot.checks.pilot_policy.sha256'] = 'b' * 64
        result = tool.compare({'fields': left}, {'fields': right})
        self.assertIn('pilot.checks.pilot_policy.sha256', result['changed_fields'])
        self.assertNotIn('a' * 64, json.dumps(result))

    def test_comparison_cannot_launch_or_contact_network(self):
        with patch('subprocess.Popen', side_effect=AssertionError('unexpected child')), \
             patch('socket.socket', side_effect=AssertionError('unexpected network')):
            fields = {'checks.pilot_policy.sha256': 'a' * 64}
            result = tool.compare({'fields': fields}, {'fields': {}})
        self.assertEqual(result['rows'][0]['state'], 'missing')
        self.assertEqual(result['correlation'], 'none_no_authenticated_cross_bundle_call_binding')

    def test_duplicate_check_and_unknown_schema_refused(self):
        check = {'id': 'configuration', 'source': 'private_config_yaml',
                 'outcome': 'ready', 'reason_code': 'config_valid'}
        with self.assertRaises(ValueError):
            tool.project_checks([check, check], 'checks.', {})

    @unittest.skipUnless(sys.platform == 'linux', 'native Linux private reader control')
    def test_native_private_reader_and_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            a, b = root / 'a', root / 'b'
            self.bundle(a)
            self.bundle(b, 'ready')
            output = root / 'private'
            output.mkdir(mode=0o700)
            args = [str(a), str(b), '--json-out', str(output / 'diff.json'), '--markdown-out', str(output / 'diff.md')]
            self.assertEqual(tool.main(args), 0)
            self.assertEqual((output / 'diff.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(tool.main(args), 2)
            linked = root / 'linked'
            linked.symlink_to(a, target_is_directory=True)
            with self.assertRaises((OSError, tool.audit.ReportError)):
                tool.load(linked)


if __name__ == '__main__':
    unittest.main()
