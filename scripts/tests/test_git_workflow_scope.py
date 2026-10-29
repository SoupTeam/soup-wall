from pathlib import Path
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(sys.platform.startswith('linux'), 'workflow shell controls require Linux')
class GitWorkflowScopeTests(unittest.TestCase):
    def execute(self, enabled, failure='none'):
        source = (ROOT / '.github/workflows/mcp-real-filesystem.yml').read_text(encoding='utf-8')
        start = source.index('      - name: Targeted existing-project read-only pilot')
        end = source.index('\n      - name:', start + 1)
        body = textwrap.dedent(source[start:end].split('        run: |\n', 1)[1])
        body = body.replace('${{ github.event.inputs.existing_project_only }}', enabled)
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / 'calls'
            prefix = '''
rustfixture() { printf 'rust:%s\\n' "$*" >> "$SCOPE_LOG"; }
git() { printf '%040d\\n' 1; }
strace() { :; }
python3() {
  printf 'python:%s\\n' "$*" >> "$SCOPE_LOG"
  if [[ "$1" == '-c' ]]; then printf '/owned/selection.json\\n'; return 0; fi
  if [[ "$*" == *'scripts/qualify-existing-pilot.py'* ]]; then
    printf 'qualify:%s\\n' "$*" >> "$SCOPE_LOG"
    if [[ "$SCOPE_FAILURE" == legacy && "$*" == *'sou134-qualification'* ]]; then return 1; fi
    if [[ "$SCOPE_FAILURE" == docs-code && "$*" == *'--project-fixture docs-code'* ]]; then return 1; fi
  fi
}
'''
            env = {'PATH': os.environ['PATH'], 'RUNNER_TEMP': temporary, 'SCOPE_LOG': str(log),
                   'SCOPE_FAILURE': failure, 'SOU119_SANDBOX_TESTS': 'rustfixture'}
            result = subprocess.run(['/bin/bash', '-c', prefix + '\n' + body],
                                    env=env, capture_output=True, text=True, timeout=15)
            return result.returncode, log.read_text().splitlines(), result.stderr

    def test_existing_project_mode_does_not_expand_the_preparation_lane(self):
        for enabled, count in (('false', 1), ('true', 4)):
            with self.subTest(enabled=enabled):
                code, rows, errors = self.execute(enabled)
                self.assertEqual(code, 0, errors)
                calls = [row for row in rows if row.startswith('qualify:')]
                self.assertEqual(len(calls), count)
                self.assertEqual(sum('real_server::outcomes::tests::' in row for row in rows),
                                 2 if enabled == 'true' else 0)
                projects = [row.split('--project-fixture ')[1].split()[0]
                            for row in calls if '--project-fixture ' in row]
                self.assertEqual(projects, ['docs-code', 'unicode-spaces', 'local-history'] if enabled == 'true' else [])

    def test_a_failed_legacy_or_project_run_retains_all_project_invocations(self):
        for failure in ('legacy', 'docs-code'):
            with self.subTest(failure=failure):
                code, rows, errors = self.execute('true', failure)
                self.assertEqual(code, 1, errors)
                self.assertEqual(sum(row.startswith('qualify:') for row in rows), 4)
