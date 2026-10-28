import argparse
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'qualify-prepared-pilot-run.py'
SPEC = importlib.util.spec_from_file_location('prepared_qualification_integration', SOURCE)
QUALIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFIER)


class PreparationReached(Exception):
    pass


class QualificationIntegration(unittest.TestCase):
    def test_generated_workspaces_prepare_without_cli_or_transition_globals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profiles = {}
            for server in ('filesystem', 'git'):
                package = root / server
                (package / 'profile').mkdir(parents=True)
                (package / (server + '-workspace')).mkdir()
                profiles[server] = {'profile': {'path': str(package / 'profile' / 'profile.json')}}
            fs, git, _ = QUALIFIER.prepare_owned_workspaces({}, profiles)
            self.assertTrue((fs / 'notes.txt').is_file())
            self.assertTrue((git / 'tracked.txt').is_file())
            before = (fs / 'notes.txt').read_bytes()
            with self.assertRaisesRegex(ValueError, 'generated_qualification_refuses_existing_project'):
                QUALIFIER.prepare_owned_workspaces({'prepared_workspaces': {}}, profiles)
            self.assertEqual((fs / 'notes.txt').read_bytes(), before)

    def test_optional_transition_is_planned_in_qualification_before_fixture_preparation(self):
        for target in (None, 'reviewed-target'):
            with self.subTest(target=target):
                args = argparse.Namespace(selection=Path('/owned/preparation/generations/id/selection.json'),
                    expected_commit='a' * 40, transition_target=target, validation_timeout_seconds=30)
                with patch.object(QUALIFIER.RUN.PREP.PILOT, 'source',
                        return_value={'dirty': False, 'commit': args.expected_commit}), \
                     patch.object(QUALIFIER.RUN, 'selected', return_value=({}, {}, {})), \
                     patch.object(QUALIFIER.SWITCH, 'plan', return_value=(None, None, None, {'plan_sha256': 'b'*64})) as plan, \
                     patch.object(QUALIFIER, 'prepare_owned_workspaces', side_effect=PreparationReached):
                    with self.assertRaises(PreparationReached):
                        QUALIFIER.qualify(args, Path('/owned/private'), {})
                    if target is None:
                        plan.assert_not_called()
                    else:
                        plan.assert_called_once_with(args.selection.parent.parent.parent, target,
                            QUALIFIER.ROOT, QUALIFIER.ROOT)


if __name__ == '__main__':
    unittest.main()
