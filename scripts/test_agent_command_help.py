import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import shutil
import importlib.util
import os
from unittest.mock import patch

TOOL = Path(__file__).with_name('agent-command-help.py')


class Controls(unittest.TestCase):
    def test_installed_delegated_catalog_and_refusals(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scripts = root / 'scripts'
            shutil.copytree(TOOL.parent, scripts, ignore=shutil.ignore_patterns('__pycache__'))
            entry = scripts / 'pilot.py'
            helper = scripts / TOOL.name
            base = [sys.executable, '-B', str(helper), '--pilot', str(entry),
                    '--sha256', hashlib.sha256(entry.read_bytes()).hexdigest(),
                    '--update-sha256', hashlib.sha256((scripts / 'pilot_update.py').read_bytes()).hexdigest()]
            sibling = root / 'sibling'
            sibling.write_text('PRIVATE_CANARY')
            result = subprocess.run(base + ['list'], cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('PRIVATE_CANARY', result.stdout)
            rows = {tuple(row['command']): row for row in json.loads(result.stdout)['commands']}
            for operation in ('inventory', 'preview', 'apply', 'rollback', 'recover', 'inspect', 'cleanup'):
                row = rows[('update', operation)]
                self.assertIn('--prefix', [flag['name'] for flag in row['flags']])
            self.assertEqual(rows[('update', 'rollback')]['effects'],
                             'preview_unless_confirm_then_lifecycle_mutation')
            self.assertIn('--expected-version', rows[('provider', 'update')]['confirmation_flags'])
            self.assertIn('--apply', rows[('provider', 'update')]['confirmation_flags'])
            prefix = root / 'absent'
            for command in ([str(entry), 'provider', 'update', '--apply'],
                            [str(entry), 'run'],
                            [str(scripts / 'pilot_update.py'), 'apply', '--prefix', str(prefix)],
                            [str(scripts / 'pilot_update.py'), 'invalid', '--prefix', str(prefix)]):
                result = subprocess.run([sys.executable, '-B', *command], cwd=root,
                                        capture_output=True, text=True, timeout=20)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(prefix.exists())
            self.assertEqual(sibling.read_text(), 'PRIVATE_CANARY')

    @unittest.skipUnless(os.environ.get('AGENTFW_TEST_BINARY') and sys.platform == 'linux', 'installed Rust binary required')
    def test_installed_rust_command_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / 'agentfw'
            shutil.copy2(os.environ['AGENTFW_TEST_BINARY'], binary)
            subprocess.run(['strip', '--strip-debug', str(binary)], check=True, timeout=30)
            result = subprocess.run([sys.executable, '-B', str(TOOL), '--agentfw', str(binary),
                                     '--sha256', hashlib.sha256(binary.read_bytes()).hexdigest(), 'list'],
                                    cwd=temp, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            catalog = json.loads(result.stdout)
            commands = [row['command'] for row in catalog['commands']]
            self.assertIn(['doctor'], commands)
            self.assertTrue(any('lifecycle' in row for row in commands))

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
            result = subprocess.run([sys.executable, '-B', str(scripts / TOOL.name),
                                     '--pilot', str(entry), '--sha256', hashlib.sha256(entry.read_bytes()).hexdigest(),
                                     '--update-sha256', hashlib.sha256((scripts / 'pilot_update.py').read_bytes()).hexdigest(),
                                     'topic', 'update', 'rollback'], capture_output=True, text=True, cwd=temp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--confirm', result.stdout)

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

    def test_shell_completion_uses_command_context(self):
        data = {
            'commands': [
                {'command': ['provider'], 'flags': [{'name': '--transport', 'required': True, 'takes_value': True, 'type': 'string'}]},
                {'command': ['provider', 'preview'], 'flags': [{'name': '--json', 'required': False, 'takes_value': False, 'type': 'boolean'}]},
                {'command': ['status'], 'flags': []},
            ]
        }
        bash = reader_completion(data, 'bash', ['provider'])
        self.assertIn('preview', bash)
        self.assertNotIn('status', bash)
        fish = reader_completion(data, 'fish', ['provider', 'preview'])
        self.assertIn("-l 'json'", fish)
        self.assertNotIn("'transport'", fish)

    def test_imported_completion_candidates_cannot_inject_shell(self):
        for value in ('$(touch marker)', "x'; exit 99; '", 'x\ncommand'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                reader_completion({'commands': [{'command': [value], 'flags': []}]}, 'bash', [])

    def test_completion_lists_only_immediate_children(self):
        data = {'commands': [{'command': [], 'flags': []},
                             {'command': ['provider'], 'flags': []},
                             {'command': ['provider', 'preview'], 'flags': []}]}
        output = reader_completion(data, 'bash', [])
        self.assertIn("'') choices='provider'", output)
        self.assertIn("'provider') choices='preview'", output)

    def test_generated_bash_runs_without_executing_hostile_current_word(self):
        bash = shutil.which('bash')
        if sys.platform == 'win32':
            bash = str(Path('C:/Program Files/Git/bin/bash.exe'))
        if not bash or not Path(bash).is_file():
            self.skipTest('Bash is unavailable')
        data = {'commands': [{'command': [], 'flags': []},
                             {'command': ['provider'], 'flags': []}]}
        script = reader_completion(data, 'bash', [])
        script += '\nCOMP_WORDS=(pilot pro); COMP_CWORD=1; _pilot_help_complete; printf "%s\\n" "${COMPREPLY[@]}"\n'
        script += 'COMP_WORDS=(pilot \'$(touch marker)\'); _pilot_help_complete; test ! -e marker\n'
        with tempfile.TemporaryDirectory() as temp:
            result = subprocess.run([bash, '--noprofile', '--norc'], input=script,
                                    text=True, capture_output=True, cwd=temp, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('provider', result.stdout)
            self.assertFalse((Path(temp) / 'marker').exists())

    def test_native_zsh_completion_context(self):
        shell = shutil.which('zsh')
        if not shell:
            self.skipTest('Zsh is unavailable')
        data = {'commands': [{'command': [], 'flags': []},
                             {'command': ['provider'], 'flags': []},
                             {'command': ['provider', 'preview'], 'flags': []}]}
        script = 'compdef() { :; }; compadd() { print -l -- "$@"; };\n'
        script += reader_completion(data, 'zsh', [])
        script += 'words=(pilot provider pre); CURRENT=3; _pilot_help_complete\n'
        result = subprocess.run([shell, '-f'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('preview', result.stdout)

    def test_native_fish_completion_context(self):
        shell = shutil.which('fish')
        if not shell:
            self.skipTest('Fish is unavailable')
        data = {'commands': [{'command': [], 'flags': []},
                             {'command': ['provider'], 'flags': []},
                             {'command': ['provider', 'preview'], 'flags': []}]}
        script = reader_completion(data, 'fish', [])
        script += "complete -C 'pilot provider pre'\n"
        result = subprocess.run([shell, '--no-config'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('preview', result.stdout)


def reader_completion(data, shell, context):
    spec = importlib.util.spec_from_file_location('help_reader_context', TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.completion(data, shell, context)


if __name__ == '__main__':
    unittest.main()
