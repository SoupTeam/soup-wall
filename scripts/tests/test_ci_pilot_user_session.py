# SPDX-License-Identifier: Apache-2.0
"""Only an empty, attested disposable CI user session may be quiesced."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('ci_session_tests', Path(__file__).resolve().parents[1] / 'ci_pilot_user_session.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class SessionScope(unittest.TestCase):
    def fixture(self):
        def row(pid, parent, name, uid):
            return dict(pid=pid, parent=parent, start_ticks=pid+100, comm=name, uids=[uid]*4, tracer_pid=0)
        before = {'1': row(1,0,'systemd',0), '20':row(20,1,'systemd',1001),
                  '21':row(21,20,'(sd-pam)',1001), '99':row(99,1,'python3',1001)}
        unit = dict(User='1001', MainPID='20', ControlGroup='/user.slice/user-1001.slice/user@1001.service', ActiveState='active', SubState='running')
        unavailable = [{'process_identity_sha256':m.identity(before[str(pid)])} for pid in (20,21)]
        return unit, before, unavailable

    def test_only_exact_root_attested_empty_pair_is_eligible(self):
        unit, before, unavailable = self.fixture()
        rows = m.validate_empty_session(1001, unit, {20,21}, before, unavailable, 99)
        self.assertEqual({r['pid'] for r in rows}, {20,21})
        for changed, cohort in (({**unit,'User':'1002'},{20,21}), (unit,{20,21,99})):
            with self.assertRaises(ValueError):
                m.validate_empty_session(1001, changed, cohort, before, unavailable, 99)

    def test_foreign_credentials_trace_unknown_evidence_and_own_ancestry_refuse(self):
        unit, before, unavailable = self.fixture()
        scenarios = []
        for field,value in (('uids',[1001,0,0,0]),('tracer_pid',123),('parent',99),('comm','other')):
            changed=copy.deepcopy(before);changed['21'][field]=value;scenarios.append((changed,unavailable,99))
        changed=copy.deepcopy(before);changed['99']['parent']=20;scenarios.append((changed,unavailable,99))
        scenarios.append((before,unavailable+[{'process_identity_sha256':'f'*64}],99))
        for state,evidence,driver in scenarios:
            with self.assertRaises(ValueError):
                m.validate_empty_session(1001,unit,{20,21},state,evidence,driver)

    def test_scope_refusal_never_reaches_a_user_exit_request(self):
        unit,before,unavailable=self.fixture()
        with mock.patch.object(m.os,'getuid',return_value=1001), mock.patch.object(m,'properties',return_value=unit), mock.patch.object(m,'group_processes',return_value={20,21,99}), \
             mock.patch.object(m,'control') as control:
            with self.assertRaisesRegex(ValueError,'session_not_empty'):
                m.quiesce({'before':{'unavailable':unavailable}}, {'before':before})
            control.assert_not_called()

    def test_local_or_non_disposable_environment_never_runs_systemctl(self):
        denied=mock.Mock();denied.guard.side_effect=RuntimeError('explicit_disposable_github_hosted_linux_only')
        with mock.patch.object(m,'load',return_value=denied),mock.patch.object(m.subprocess,'run') as run, \
             mock.patch.object(sys,'argv',['ci_pilot_user_session.py','--quiesce']),mock.patch('sys.stdout',new_callable=io.StringIO) as output:
            self.assertEqual(m.main(),1);run.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())['status'],'failed')

    def test_user_override_cannot_be_treated_as_a_vendor_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            user_file=Path(directory)/'custom.service';user_file.write_text('[Service]\nExecStop=/owned/job\n')
            with self.assertRaisesRegex(ValueError,'session_nonvendor_user_unit'):
                m.vendor_file(str(user_file))


class UnitCatalog(unittest.TestCase):
    def test_empty_catalog_and_descriptions_do_not_depend_on_json_support(self):
        self.assertEqual(m.unit_rows(''), [])
        self.assertEqual(m.unit_rows('  init.scope loaded active running System and Service Manager\n'),
                         [dict(unit='init.scope', active='active', sub='running')])
        for text in ('null', '[]', '0 units listed.', 'owned.service not-found active running Unknown'):
            with self.assertRaisesRegex(ValueError, 'session_unit_listing_unrecognized'):
                m.unit_rows(text)

    def test_pending_jobs_refuse_before_exit_without_treating_text_as_json(self):
        with mock.patch.object(m,'control',side_effect=['', '1 owned.service start running']), \
             self.assertRaisesRegex(ValueError,'session_user_jobs_pending'):
            m.user_units()


class UserExitBoundary(unittest.TestCase):
    def test_system_or_forced_exit_never_reaches_systemctl(self):
        with mock.patch.object(m.subprocess, 'run') as run:
            for words in (('exit',), ('--system', 'exit'), ('--user', '--force', 'exit')):
                with self.assertRaisesRegex(ValueError, 'session_root_exit_forbidden'):
                    m.control(*words)
            run.assert_not_called()


class ReadOnlyPostCleanup(unittest.TestCase):
    def test_post_cleanup_cannot_enable_quiescence(self):
        with mock.patch.object(m,'load') as load, mock.patch.object(sys,'argv',
                ['ci_pilot_user_session.py','--after-cleanup','--quiesce']), \
                mock.patch('sys.stderr', new_callable=io.StringIO):
            with self.assertRaises(SystemExit): m.main()
            load.assert_not_called()
