# SPDX-License-Identifier: Apache-2.0
"""Owned setup-refusal/restore control; no original pressure claim."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('owned_pressure_control', ROOT / 'scripts/prepared_budget_pressure.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


class Pressure(unittest.TestCase):
    def test_peer_release_requires_classified_original_kernel_refusal(self):
        import copy
        row={'servers':['filesystem'],'original_runtime_seen':True,'errors':[],
            'observer_errors':[],'removed':False,'counter_max':{'oom_kill':0,'pids_max':0}}
        snapshot={'errors':[],'rows':[row]}
        self.assertFalse(P.kernel_refusal(snapshot,'filesystem','memory'))
        row['counter_max']['oom_kill']=1
        self.assertTrue(P.kernel_refusal(snapshot,'filesystem','memory'))
        self.assertFalse(P.kernel_refusal(snapshot,'git','memory'))
        self.assertFalse(P.kernel_refusal(snapshot,'filesystem','pids'))
        row['counter_max']['pids_max']=1
        self.assertTrue(P.kernel_refusal(snapshot,'filesystem','pids'))
        self.assertFalse(P.kernel_refusal(snapshot,'filesystem','wall'))
        row['removed']=True
        self.assertTrue(P.kernel_refusal(snapshot,'filesystem','wall'))
        for change in [lambda v:v['rows'][0].update(original_runtime_seen=False),
                       lambda v:v.update(errors=['unknown']),
                       lambda v:v['rows'][0].update(observer_errors=['unverified'])]:
            bad=copy.deepcopy(snapshot);change(bad)
            self.assertFalse(P.kernel_refusal(bad,'filesystem','memory'))

    def test_finite_peer_finishes_after_release_without_waiting_for_stop_only_barrier(self):
        import threading
        calls=[]
        class Peer:
            provider=SimpleNamespace(release=threading.Event())
            def useful(self): raise AssertionError('finite providers have no post-tool hold barrier')
            def finish(self):
                self_outer.assertTrue(self.provider.release.is_set())
                calls.append('finished');return {'owned_cleanup_verified':True}
            def check_useful(self): calls.append('kernel read and Git status checked')
        self_outer=self
        self.assertEqual(P.finish_useful(Peer()), {'owned_cleanup_verified':True})
        self.assertEqual(calls,['finished','kernel read and Git status checked'])

    def test_refused_peer_setup_preserves_owned_bytes_and_never_claims_pressure_pass(self):
        class Model:
            def __init__(self, _steps): self.server = SimpleNamespace()
            def close(self): pass
        def refused(peer_context, *_args, **_kwargs):
            self.assertTrue(all(isinstance(value, Path) for value in peer_context.paths.values()))
            self.assertIsInstance(peer_context.paths['claude'], Path)
            raise ValueError('owned setup refusal')
        def snapshot(path): return {p.name: p.read_bytes() for p in path.iterdir() if p.is_file()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profiles = {}
            for server in ('filesystem', 'git'):
                workspace = root / server
                workspace.mkdir(mode=0o700)
                (workspace / ('notes.txt' if server == 'filesystem' else 'tracked.txt')).write_text('owned baseline\n')
                profile = root / (server + '.json')
                profile.write_text(json.dumps({'runtimePath': str(root / 'unused-runtime'), 'workspace': str(workspace)}))
                profiles[server] = {'profile': {'path': str(profile)}}
            base = SimpleNamespace(snapshot=snapshot, DEMO=SimpleNamespace(ScriptedModel=Model))
            q = SimpleNamespace(RUN=None, LAUNCH=None, ASK=None, useful_result=None,
                                STOP=SimpleNamespace(Prepared=refused))
            context = SimpleNamespace(BASE=base, RESOURCE=None, ROOT=ROOT, QUALIFIER=q,
                                      budget=root / 'primary-budget', peer_budget=root / 'peer-budget')
            delegation = root / 'delegation'
            delegation.mkdir(mode=0o700)
            with patch.object(P, 'PRESSURE_BYTES', 1024):
                result = P.qualify(context, root / 'unused-selection', {'claude': str(root / 'unused-host')}, profiles, delegation,
                                   root / 'output', 'a' * 40)
            self.assertEqual(result['status'], 'incomplete')
            self.assertTrue(result['workspace_unchanged'])
            self.assertEqual(len(result['attempts']), 6)
            self.assertTrue(all(row['status'] == 'incomplete' for row in result['attempts']))
            self.assertEqual((root / 'git/tracked.txt').read_text(), 'owned baseline\n')
            self.assertFalse((root / 'filesystem/sou142-pressure.txt').exists())


if __name__ == '__main__': unittest.main()
