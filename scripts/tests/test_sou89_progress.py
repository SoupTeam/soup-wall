# SPDX-License-Identifier: Apache-2.0
"""Incomplete selected evidence survives interruption and never becomes a pass."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'sou89_progress_driver', ROOT / 'scripts/verify-sou89-selected-liveness.py')
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class SelectedProgress(unittest.TestCase):
    def test_partial_evidence_cannot_publish_pass_or_mutate_final_state(self):
        report = {'status': 'pass', 'failed': 0, 'selected_production_acceptance': True,
                  'checks': [{'case': 'filesystem_sigkill_reclamation', 'passed': True}],
                  'completed_churn_clients': [{'profile': 'filesystem', 'cycle': 1,
                       'client': {'stdout': {'synthetic_private_detail': 'owned-canary'}}}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            DRIVER.checkpoint_selected_report(path, report, 'churn_filesystem')
            saved = json.loads(path.read_text())
        self.assertEqual(report['status'], 'pass')
        self.assertEqual(report['failed'], 0)
        self.assertEqual(saved['status'], 'incomplete')
        self.assertEqual(saved['failed'], 1)
        self.assertEqual(saved['passed'], 1)
        self.assertEqual(saved['progress']['churn_completed'], {'filesystem': 1, 'git': 0})
        self.assertEqual(saved['completed_churn_clients'], report['completed_churn_clients'])
        with self.assertRaisesRegex(ValueError, '^report_status_not_pass$'):
            DRIVER.grade_selected_report(saved, DRIVER.REQUIRED_PRODUCTION_CASES)
        rendered = DRIVER.summary(saved)
        self.assertEqual(rendered['progress'], saved['progress'])
        self.assertNotIn('owned-canary', json.dumps(rendered))

    def test_failed_replacement_preserves_previous_readable_checkpoint(self):
        report = {'checks': [], 'failed': 0}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            DRIVER.checkpoint_selected_report(path, report, 'before')
            previous = path.read_bytes()
            with patch.object(DRIVER.os, 'replace', side_effect=OSError('owned write interrupted')):
                with self.assertRaisesRegex(OSError, 'owned write interrupted'):
                    DRIVER.checkpoint_selected_report(path, report, 'after')
            self.assertEqual(path.read_bytes(), previous)
            self.assertFalse(path.with_suffix('.checkpoint.tmp').exists())
            self.assertEqual(json.loads(path.read_text())['progress']['phase'], 'before')

    def test_accepted_marker_filter_preserves_previous_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            DRIVER.checkpoint_selected_report(path, {'checks': [], 'failed': 0}, 'safe')
            previous = path.read_bytes()
            report = {'checks': [], 'failed': 0,
                      'unsafe': DRIVER.RESOURCE.MARKERS[0].decode('utf-8')}
            with self.assertRaisesRegex(ValueError, '^unsafe_evidence_payload$'):
                DRIVER.checkpoint_selected_report(path, report, 'unsafe')
            self.assertEqual(path.read_bytes(), previous)
            self.assertFalse(path.with_suffix('.checkpoint.tmp').exists())

    def test_abrupt_process_exit_keeps_incomplete_evidence_without_finalizer(self):
        program = '''import importlib.util, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('owned_driver', sys.argv[1])
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
driver.checkpoint_selected_report(Path(sys.argv[2]), {'checks': [], 'failed': 0}, 'owned_abrupt_exit')
os._exit(137)
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            result = subprocess.run([sys.executable, '-B', '-c', program,
                str(ROOT / 'scripts/verify-sou89-selected-liveness.py'), str(path)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 137, result.stderr)
            saved = json.loads(path.read_text())
        self.assertEqual(saved['status'], 'incomplete')
        self.assertEqual(saved['failed'], 1)
        self.assertEqual(saved['progress']['phase'], 'owned_abrupt_exit')
