import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import shutil
import importlib.util
from unittest.mock import patch

TOOL = Path(__file__).with_name('agent-command-help.py')


class Controls(unittest.TestCase):
    def test_verified_python_bytes_survive_path_replacement(self):
        spec = importlib.util.spec_from_file_location('help_reader', TOOL)
        reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reader)
        with tempfile.TemporaryDirectory() as temp:
            entry = Path(temp) / 'pilot.py'
            original = b"import argparse\ndef parser():\n p=argparse.ArgumentParser()\n p.add_subparsers().add_parser('original-command')\n return p\n"
            changed = original.replace(b'original-command', b'changed-command')
            entry.write_bytes(original)
            expected = hashlib.sha256(original).hexdigest()
            class Hash:
                def hexdigest(self):
                    entry.write_bytes(changed)
                    return expected
            with patch.object(reader.hashlib, 'sha256', return_value=Hash()), patch.object(reader.sys, 'addaudithook'):
                catalog = reader.discover(entry, expected)
            names = [row['command'] for row in catalog['commands']]
            self.assertIn(['original-command'], names)
            self.assertNotIn(['changed-command'], names)

    def test_accepted_pilot_outside_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            scripts = Path(temp) / 'scripts'
            shutil.copytree(TOOL.parent, scripts, ignore=shutil.ignore_patterns('__pycache__'))
            entry = scripts / 'pilot.py'
            result = subprocess.run([sys.executable, '-B', str(scripts / TOOL.name), '--pilot', str(entry), '--sha256', hashlib.sha256(entry.read_bytes()).hexdigest(), 'topic', 'provider', 'update'], capture_output=True, text=True, cwd=temp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--expected-version', result.stdout)

    def test_installed_parser_and_stale_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            entry = Path(temp) / 'pilot.py'
            entry.write_text("import argparse\ndef parser():\n p=argparse.ArgumentParser()\n s=p.add_subparsers()\n c=s.add_parser('preview')\n c.add_argument('--json', action='store_true')\n return p\n")
            digest = hashlib.sha256(entry.read_bytes()).hexdigest()
            base = [sys.executable, '-B', str(TOOL), '--pilot', str(entry), '--sha256', digest]
            result = subprocess.run(base + ['topic', 'preview'], capture_output=True, text=True, cwd=temp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--json', result.stdout)
            for shell in ('bash', 'zsh', 'fish'):
                result = subprocess.run(base + ['completion', '--shell', shell], capture_output=True, text=True, cwd=temp)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('preview', result.stdout)
            entry.write_text(entry.read_text() + '\n')
            self.assertEqual(subprocess.run(base + ['list'], capture_output=True).returncode, 2)

    def test_process_activity_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            entry = Path(temp) / 'pilot.py'
            entry.write_text("import subprocess\nsubprocess.run(['should-not-run'])\n")
            result = subprocess.run([sys.executable, '-B', str(TOOL), '--pilot', str(entry), '--sha256', hashlib.sha256(entry.read_bytes()).hexdigest(), 'list'], capture_output=True)
            self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
