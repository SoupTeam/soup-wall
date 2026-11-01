import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import os
import sys
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('diff', Path(__file__).with_name('agent-diagnostic-diff.py'))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class Controls(unittest.TestCase):
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
            self.bundle(b, 'pass')
            with patch.object(tool.audit, '_open_input', lambda p: open(p, 'rb')):
                result = tool.compare(tool.load(a), tool.load(b))
            self.assertEqual(result['rows'][0]['state'], 'changed')
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

    @unittest.skipUnless(sys.platform == 'linux', 'native Linux private reader control')
    def test_native_private_reader_and_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            a, b = root / 'a', root / 'b'
            self.bundle(a)
            self.bundle(b, 'pass')
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
