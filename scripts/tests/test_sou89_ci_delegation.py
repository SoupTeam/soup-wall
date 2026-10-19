# SPDX-License-Identifier: Apache-2.0
"""Keep the selected liveness CI launch inside the accepted ownership contract."""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'sou89_ci_driver', ROOT / 'scripts/verify-sou89-selected-liveness.py')
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class SelectedLivenessDelegation(unittest.TestCase):
    def test_workflow_unit_reaches_exact_cgroup_ownership_check(self):
        workflow = (ROOT / '.github/workflows/sou86-crash-supervision.yml').read_text()
        step = workflow.split(
            '      - name: Require SOU-89 selected filesystem and Git native liveness and autonomous reclamation\n',
            1)[1].split('      - name:', 1)[0]
        assignment, = re.findall(r'^          (unit=.*)$', step, re.M)
        result = subprocess.run(
            ['bash', '-c', assignment + '\nprintf "%s.service" "$unit"'],
            env={**os.environ, 'GITHUB_RUN_ID': '123456', 'GITHUB_RUN_ATTEMPT': '2'},
            capture_output=True, text=True, check=True, timeout=5)
        # A valid name alone never authorizes host access. The actual helper must
        # still reject an observer outside that exact disposable service.
        with patch.object(DRIVER.SOU86.platform, 'system', return_value='Linux'), \
             patch.object(DRIVER.SOU86.os, 'geteuid', return_value=1000, create=True), \
             patch.object(Path, 'read_text', return_value='0::/system.slice/foreign.service') as membership:
            with self.assertRaisesRegex(ValueError, '^exact_owned_systemd_service_required$'):
                DRIVER.prepare_delegation(result.stdout)
            membership.assert_called_once_with()

    def test_liveness_does_not_expand_accepted_service_namespace(self):
        with patch.object(DRIVER.SOU86.platform, 'system', return_value='Linux'), \
             patch.object(DRIVER.SOU86.os, 'geteuid', return_value=1000, create=True), \
             patch.object(Path, 'read_text') as membership:
            for unit in ('sou89-123456-2.service', 'ssh.service', '../sou86-123456-2.service'):
                with self.subTest(unit=unit), self.assertRaisesRegex(
                        ValueError, '^owned_disposable_unit_required$'):
                    DRIVER.prepare_delegation(unit)
            membership.assert_not_called()
