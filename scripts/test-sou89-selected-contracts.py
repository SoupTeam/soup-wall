#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Local unit, contract, and observer controls for SOU-89 selected liveness harness.

Verifies:
1. Subprocess environment injection and restoration (AGENTFW_NATIVE_LIVENESS, AGENTFW_MCP_SESSION).
2. Stable useful work comparison and semantic divergence detection across incremented IDs.
3. AST verification of run_selected_acceptance (grading calls, client constructors, daemon lifecycle order).
4. Native token path resolution (.agentfw/native-token with fallback).
5. TemporaryDirectory lifetime and private evidence retention before cleanup.
6. Direct execution of all production grading functions on positive baselines and
   adversarial mutations (crash observations, liveness active, renewal, autonomous reclamation,
   normal client close, intentional crash close, report grading).
7. Report summary bounding and projection.
8. Real local daemon contracts:
   - Physical session_id vs genuine native epoch distinction (demonstrating that status
     with physical session_id succeeds with 200 active, while status with epoch returns 404
     native_session_unknown).
   - Scoped bindings remain empty for unscoped collector sessions.
   - Tool calls and result validation under JSON-RPC envelopes with mcp_host delivery.
   - Rejection of invalid result_kind schemas.
   - Precise rejection of replayed results on retired sessions without release.
   - Profile-barrier risk checkpointing.
9. CLI guard (--run plan mode) and deterministic cross-platform early failure report retention
   (Darwin native, Linux native/candidate check, and mocked Linux prerequisite contracts).
"""
from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location('selected_liveness', ROOT / 'scripts/verify-sou89-selected-liveness.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

assert m.SOU86 is not None, "sou86_crash_supervision module must load"


def test_selected_client_env_injection():
    class Capture:
        def __init__(self, *args, **kwargs):
            pass

    class Witness:
        def __init__(self, *args, **kwargs):
            pass

    captured = []

    def popen(command, **kwargs):
        captured.append({'command': command, 'env': kwargs['env']})
        return SimpleNamespace(pid=1234, stdout=None, stderr=None)

    with tempfile.TemporaryDirectory(prefix='sou89-test-env-') as temporary:
        private = Path(temporary)
        rig = SimpleNamespace(
            private=private,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
            original={'runtimePath': '/pinned/node', 'packageRoot': '/pinned/fs'},
            workspace=private,
            binary=Path('/pinned/agentfw'),
            clients=[],
            delegation=None,
        )
        with patch.object(m.SOU86.subprocess, 'Popen', popen), \
             patch.object(m.BASE, 'ProcessWitness', Witness), \
             patch.object(m.RESOURCE, 'Capture', Capture):
            client = m.SelectedLivenessClient(rig, 'test-contract', lease_secs=4, budgeted=False)

    assert len(captured) == 1, "Expected exactly 1 subprocess.Popen call"
    child_env = captured[0]['env']
    assert child_env.get('AGENTFW_NATIVE_LIVENESS') == 'true', "AGENTFW_NATIVE_LIVENESS must be injected"
    assert child_env.get('AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS') == '4', "AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS must be 4"
    assert child_env.get('AGENTFW_MCP_SESSION') == client.session_id, "AGENTFW_MCP_SESSION must be injected with physical session_id"
    assert rig.env.get('AGENTFW_NATIVE_LIVENESS') is None, "rig.env must be restored after client construction"
    assert rig.env.get('AGENTFW_MCP_SESSION') is None, "rig.env must be restored after client construction"
    print("PASS: test_selected_client_env_injection")


def test_useful_stable_comparison_across_incremented_ids():
    class UsefulClient:
        kind = 'filesystem'
        next_id = 10
        direct = False

        def exchange(self, request):
            response = {
                'jsonrpc': '2.0',
                'id': request['id'],
                'result': {
                    'content': [{'type': 'text', 'text': m.RESOURCE.TEXT}],
                    'structuredContent': {'content': m.RESOURCE.TEXT},
                },
            }
            return response, json.dumps(response, separators=(',', ':')).encode('utf-8')

    c = UsefulClient()
    h1 = m.useful(c)
    assert c.next_id == 11, "useful must increment next_id from 10 to 11"
    h2 = m.useful(c)
    assert c.next_id == 12, "useful must increment next_id from 11 to 12"
    assert h1 == h2, f"Useful work hashes must be identical across incremented IDs: {h1} != {h2}"

    # Positive validation against expected_hash
    h3 = m.useful(c, expected_hash=h1)
    assert h3 == h1

    # Verify diverged content is detected and rejected
    class DivergedClient:
        kind = 'filesystem'
        next_id = 10
        direct = False

        def exchange(self, request):
            text = m.RESOURCE.TEXT if request['id'] == 10 else "diverged content"
            response = {
                'jsonrpc': '2.0',
                'id': request['id'],
                'result': {
                    'content': [{'type': 'text', 'text': text}],
                    'structuredContent': {'content': text},
                },
            }
            return response, json.dumps(response, separators=(',', ':')).encode('utf-8')

    dc = DivergedClient()
    h_orig = m.useful(dc)
    try:
        m.useful(dc, expected_hash=h_orig)
    except ValueError as err:
        assert 'original_filesystem_useful_result_changed' in str(err)
    else:
        raise AssertionError("Expected diverged content to raise ValueError")

    print("PASS: test_useful_stable_comparison_across_incremented_ids")


def test_ast_run_selected_acceptance():
    module_ast = ast.parse((ROOT / 'scripts/verify-sou89-selected-liveness.py').read_text())
    run = next(n for n in module_ast.body if isinstance(n, ast.FunctionDef) and n.name == 'run_selected_acceptance')
    calls = [n.func.id for n in ast.walk(run) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]

    assert 'SelectedLivenessClient' in calls, "run_selected_acceptance must call SelectedLivenessClient"
    assert 'ProtectedClient' not in calls, "run_selected_acceptance must NOT construct unleased ProtectedClient"
    assert 'http_post' in calls, "run_selected_acceptance must call http_post"
    assert 'http_get' in calls, "run_selected_acceptance must call http_get"
    assert 'grade_crash_observation' in calls, "run_selected_acceptance must call grade_crash_observation"
    assert 'grade_liveness_active' in calls, "run_selected_acceptance must call grade_liveness_active"
    assert 'grade_liveness_renewal' in calls, "run_selected_acceptance must call grade_liveness_renewal"
    assert 'grade_autonomous_reclamation' in calls, "run_selected_acceptance must call grade_autonomous_reclamation"
    assert 'grade_client_close' in calls, "run_selected_acceptance must call grade_client_close"
    assert 'grade_selected_report' in calls, "run_selected_acceptance must call grade_selected_report"

    # Verify that in restart orchestration, old instance renewal occurs while d2 is running (before stop(d2))
    source = (ROOT / 'scripts/verify-sou89-selected-liveness.py').read_text()
    d2_renew_pos = source.index("'old_instance_renewal_not_rejected'")
    d2_stop_pos = source.rindex('BASE.DEMO.stop(d2)')
    assert d2_renew_pos < d2_stop_pos, "Old instance renewal check must precede BASE.DEMO.stop(d2)"
    print("PASS: test_ast_run_selected_acceptance")


def test_rig_native_token_path():
    with tempfile.TemporaryDirectory(prefix='sou89-test-token-') as temp:
        home = Path(temp)
        dot_agentfw = home / '.agentfw'
        dot_agentfw.mkdir(parents=True, exist_ok=True)
        token_file = dot_agentfw / 'native-token'
        token_file.write_text('test-token-secret-123\n')

        # Test SelectedLivenessRig
        rig = m.SelectedLivenessRig.__new__(m.SelectedLivenessRig)
        rig.home = home
        assert rig.native_token == 'test-token-secret-123', "SelectedLivenessRig must read .agentfw/native-token"

        # Test SelectedLivenessGitRig
        git_rig = m.SelectedLivenessGitRig.__new__(m.SelectedLivenessGitRig)
        git_rig.home = home
        assert git_rig.native_token == 'test-token-secret-123', "SelectedLivenessGitRig must read .agentfw/native-token"

        # Test fallback if token is placed directly at home/native-token
        with tempfile.TemporaryDirectory(prefix='sou89-test-fallback-token-') as temp_fb:
            fb_home = Path(temp_fb)
            (fb_home / 'native-token').write_text('fallback-token-secret-456\n')
            rig_fb = m.SelectedLivenessRig.__new__(m.SelectedLivenessRig)
            rig_fb.home = fb_home
            assert rig_fb.native_token == 'fallback-token-secret-456', "SelectedLivenessRig must support fallback to home/native-token"
    print("PASS: test_rig_native_token_path")


def test_temporary_directory_cleanup_lifetime():
    class Capture:
        def __init__(self, *args, **kwargs):
            pass
        def finish(self):
            return {}

    class Witness:
        def __init__(self, *args, **kwargs):
            pass
        def finish(self):
            return {'all_stopped': True, 'remaining': []}

    # 1. Negative reproduction: close() called after TemporaryDirectory context exits raises FileNotFoundError
    with tempfile.TemporaryDirectory(prefix='sou89-cleanup-repro-') as temp:
        private = Path(temp)
        rig = SimpleNamespace(
            private=private,
            env={'PATH': '/usr/bin:/bin'},
            original={'runtimePath': '/pinned/node', 'packageRoot': '/pinned/fs'},
            workspace=private,
            binary=Path('/pinned/agentfw'),
            clients=[],
            delegation=None,
        )
        process = SimpleNamespace(pid=1234, stdout=None, stderr=None, stdin=None, returncode=0, wait=lambda **kwargs: 0)
        with patch.object(m.SOU86.subprocess, 'Popen', lambda *a, **k: process), \
             patch.object(m.BASE, 'ProcessWitness', Witness), \
             patch.object(m.RESOURCE, 'Capture', Capture):
            client = m.SelectedLivenessClient(rig, 'late-close', budgeted=False)
    # Outside context: private directory is deleted
    try:
        client.close()
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected FileNotFoundError when client.close() is called after TemporaryDirectory cleanup")

    # 2. Positive verification: close() called within TemporaryDirectory context succeeds cleanly
    with tempfile.TemporaryDirectory(prefix='sou89-cleanup-proper-') as temp:
        private = Path(temp)
        rig = SimpleNamespace(
            private=private,
            env={'PATH': '/usr/bin:/bin'},
            original={'runtimePath': '/pinned/node', 'packageRoot': '/pinned/fs'},
            workspace=private,
            binary=Path('/pinned/agentfw'),
            clients=[],
            delegation=None,
        )
        process = SimpleNamespace(pid=1234, stdout=None, stderr=None, stdin=None, returncode=0, wait=lambda **kwargs: 0)
        with patch.object(m.SOU86.subprocess, 'Popen', lambda *a, **k: process), \
             patch.object(m.BASE, 'ProcessWitness', Witness), \
             patch.object(m.RESOURCE, 'Capture', Capture):
            client = m.SelectedLivenessClient(rig, 'proper-close', budgeted=False)
            res = client.close()
            m.grade_client_close(res, 'proper_client')
    print("PASS: test_temporary_directory_cleanup_lifetime")


def valid_source_identity():
    return {
        'source_before': {'commit': 'a' * 40, 'tree': 'b' * 40, 'dirty': False},
        'source_after': {'commit': 'a' * 40, 'tree': 'b' * 40, 'dirty': False},
        'runtime_source_commit': 'a' * 40,
        'binary_unchanged': True,
        **{key: 'c' * 64 for key in (
            'binary_sha256', 'driver_sha256', 'config_sha256', 'git_config_sha256',
            'restart_config_sha256', 'git_binary_sha256', 'git_launcher_sha256',
            'node_binary_sha256', 'bwrap_binary_sha256')},
    }


def test_production_graders_positive_and_adversarial_mutations():
    # 1. grade_crash_observation
    base_crash = {
        'case': 'collector',
        'protection_acceptance': True,
        'armed_before_signal': True,
        'stdin_held_open_at_injection': True,
        'observation_bound_millis': m.ACCEPTANCE_MILLIS,
        'observed_processes': [
            {'pid': 100, 'start_time_ticks': 1000},
            {'pid': 101, 'start_time_ticks': 1001},
            {'pid': 102, 'start_time_ticks': 1002},
        ],
        'protected_work_stopped_within_bound': True,
        'all_identities_gone_within_bound': True,
        'leaf_removed_within_bound': True,
        'live_at_deadline': [],
        'identities_present_at_deadline': [],
        'acceptance_fallback_used': False,
        'target': {'pid': 102, 'signal': 'SIGKILL', 'signal_delivered': True},
        'owner': {
            'format': m.OWNER_FORMAT,
            'instance': 'a' * 32,
            'owner_pid': 100,
            'owner_start_ticks': 1000,
            'sandbox_pid': 101,
            'sandbox_start_ticks': 1001,
            'pid1_pid': 102,
            'pid1_start_ticks': 1002,
        },
        'signal': 'SIGKILL',
        'process_stop_millis': 25,
        'identities_gone_millis': 30,
        'leaf_remove_millis': 35,
        'immediate_native_retirement_claimed': False,
        'previous_effects_rolled_back': False,
        'native_retirement': 'existing_300s_idle_expiry_on_next_authenticated_event',
        'in_flight': False,
        'client': {
            'forced_cleanup': False,
            'exit_code': -9,
            'process': {'all_stopped': True, 'remaining': []},
            'kernel': {
                'leaf': 'test-leaf',
                'leaf_removed': True,
                'remaining': [],
                'error': None,
                'thread_stopped': True,
                'samples': 5,
                'members': [{'pid': 102}],
            },
        },
    }
    # Positive baseline must pass without error
    m.grade_crash_observation(base_crash, 'filesystem')

    # Adversarial mutations must all be rejected by the actual production grader
    crash_mutations = [
        ({'protection_acceptance': False}, 'unarmed_launch_counted_as_protected'),
        ({'acceptance_fallback_used': True}, 'harness_recovery_mislabeled_as_production'),
        ({'protected_work_stopped_within_bound': False}, 'crash_cleanup_incomplete'),
        ({'all_identities_gone_within_bound': False}, 'crash_cleanup_incomplete'),
        ({'live_at_deadline': [{'pid': 9999}]}, 'crash_cleanup_incomplete'),
        ({'identities_present_at_deadline': [{'sub': 'leak'}]}, 'crash_cleanup_incomplete'),
        ({'leaf_removed_within_bound': False}, 'crash_cleanup_incomplete'),
        ({'owner': None}, 'owner_identity_missing'),
        ({'owner': {'format': 'wrong'}}, 'crash_owner_identity_missing'),
        ({'owner': {**base_crash['owner'], 'owner_pid': 0}}, 'trusted_process_not_independently_observed'),
        ({'target': {'pid': 102, 'signal': 'SIGKILL', 'signal_delivered': False}}, 'crash_signal_not_delivered'),
        ({'observation_bound_millis': 0}, 'crash_observer_unbound'),
        ({'observation_bound_millis': float('inf')}, 'crash_observer_unbound'),
        ({'process_stop_millis': -100}, 'crash_cleanup_deadline_exceeded'),
        ({'process_stop_millis': 12000}, 'crash_cleanup_deadline_exceeded'),
        ({'identities_gone_millis': -50}, 'crash_cleanup_deadline_exceeded'),
        ({'leaf_remove_millis': 999999999}, 'crash_cleanup_deadline_exceeded'),
        ({'client': {'forced_cleanup': True, 'exit_code': -9, 'process': {'all_stopped': True, 'remaining': []}}}, 'harness_recovery_mislabeled_as_production'),
        ({'client': {'forced_cleanup': False, 'exit_code': -9, 'process': {'all_stopped': True, 'remaining': []},
                     'kernel': {'error': 'kernel_observation_failed', 'thread_stopped': True, 'leaf_removed': True, 'remaining': [], 'samples': 5, 'members': [{'pid': 102}]}}},
         'kernel_observer_error_kernel_observation_failed'),
        ({'client': {'forced_cleanup': False, 'exit_code': -9, 'process': {'all_stopped': True, 'remaining': []},
                     'kernel': {'error': None, 'thread_stopped': False, 'leaf_removed': True, 'remaining': [], 'samples': 5, 'members': [{'pid': 102}]}}},
         'kernel_thread_not_stopped'),
        ({'client': {'forced_cleanup': False, 'exit_code': -9, 'process': {'all_stopped': True, 'remaining': []},
                     'kernel': {'error': None, 'thread_stopped': True, 'leaf_removed': False, 'remaining': [], 'samples': 5, 'members': [{'pid': 102}]}}},
         'kernel_leaf_not_removed'),
        ({'client': {'forced_cleanup': False, 'exit_code': -9, 'process': {'all_stopped': True, 'remaining': []},
                     'kernel': {'error': None, 'thread_stopped': True, 'leaf_removed': True, 'remaining': [{'pid': 123}], 'samples': 5, 'members': [{'pid': 102}]}}},
         'kernel_processes_remaining'),
    ]
    for mutation, expected_err in crash_mutations:
        mutated = copy.deepcopy(base_crash)
        mutated.update(mutation)
        try:
            m.grade_crash_observation(mutated, 'filesystem')
        except ValueError as err:
            assert expected_err in str(err), f"Expected {expected_err}, got {err}"
        else:
            raise AssertionError(f"Mutation {mutation} should have raised {expected_err}")

    # Explicitly test check_round10 reproducer crash dictionary
    bad_crash_r10 = {
        'protection_acceptance': True,
        'protected_work_stopped_within_bound': True,
        'all_identities_gone_within_bound': True,
        'live_at_deadline': [],
        'identities_present_at_deadline': [],
        'leaf_removed_within_bound': True,
        'acceptance_fallback_used': False,
        'client': {
            'forced_cleanup': False,
            'kernel': {
                'error': 'kernel_observation_failed',
                'thread_stopped': False,
                'remaining': [{'pid': 123}],
                'leaf_removed': False,
            },
        },
    }
    try:
        m.grade_crash_observation(bad_crash_r10, 'bad-kernel-control')
    except ValueError as err:
        pass
    else:
        raise AssertionError("check_round10 bad crash observation must be rejected by grade_crash_observation")

    # Explicitly test check_round11 reproducer crash dictionary
    bad_crash_r11 = {
        'protection_acceptance': True, 'protected_work_stopped_within_bound': True, 'all_identities_gone_within_bound': True,
        'live_at_deadline': [], 'identities_present_at_deadline': [], 'leaf_removed_within_bound': True, 'acceptance_fallback_used': False,
        'owner': {'owner_pid': 0, 'pid1_pid': -1}, 'signal': 'SIGKILL', 'target': {'pid': 9999, 'signal_delivered': False},
        'observation_bound_millis': float('inf'), 'process_stop_millis': -100, 'identities_gone_millis': -999,
        'leaf_remove_millis': 999999999, 'client': {'forced_cleanup': False, 'exit_code': -9, 'process': {'all_stopped': True, 'remaining': []}, 'kernel': None}
    }
    try:
        m.grade_crash_observation(bad_crash_r11, 'unbound-owner-and-signal')
    except ValueError as err:
        pass
    else:
        raise AssertionError("check_round11 bad crash observation must be rejected by grade_crash_observation")

    # Verify missing acceptance_fallback_used or forced_cleanup fields are rejected (not defaulted)
    crash_missing_fallback = copy.deepcopy(base_crash)
    del crash_missing_fallback['acceptance_fallback_used']
    try:
        m.grade_crash_observation(crash_missing_fallback, 'filesystem')
    except ValueError as err:
        pass
    else:
        raise AssertionError("Missing acceptance_fallback_used must raise ValueError")

    crash_missing_forced = copy.deepcopy(base_crash)
    del crash_missing_forced['client']['forced_cleanup']
    try:
        m.grade_crash_observation(crash_missing_forced, 'filesystem')
    except ValueError as err:
        assert 'forced_cleanup_field_missing' in str(err)
    else:
        raise AssertionError("Missing forced_cleanup must raise ValueError")

    # 2. grade_liveness_active
    base_lstatus = {
        'contract_version': m.LIVENESS_CONTRACT,
        'status': 'active',
        'session_id': 'sess-123',
        'instance_id': 'inst-abc',
        'lease_seconds': 4,
        'expires_in_ms': 3500,
    }
    m.grade_liveness_active(base_lstatus, 'sess-123', 'filesystem', expected_instance_id='inst-abc')

    lstatus_mutations = [
        ({'contract_version': 'wrong-contract'}, 'filesystem_liveness_contract_mismatch'),
        ({'status': 'expired'}, 'filesystem_liveness_not_active'),
        ({'session_id': 'wrong-session'}, 'filesystem_session_id_mismatch'),
        ({'instance_id': 'different-inst'}, 'filesystem_instance_id_mismatch'),
        ({'lease_seconds': 0}, 'filesystem_invalid_lease_seconds'),
        ({'lease_seconds': -1}, 'filesystem_invalid_lease_seconds'),
        ({'lease_seconds': 'invalid'}, 'filesystem_invalid_lease_seconds'),
        ({'expires_in_ms': 0}, 'filesystem_expired_lease'),
        ({'expires_in_ms': -50}, 'filesystem_expired_lease'),
    ]
    for mutation, expected_err in lstatus_mutations:
        mutated = copy.deepcopy(base_lstatus)
        mutated.update(mutation)
        try:
            m.grade_liveness_active(mutated, 'sess-123', 'filesystem', expected_instance_id='inst-abc')
        except ValueError as err:
            assert expected_err in str(err), f"Expected {expected_err}, got {err}"
        else:
            raise AssertionError(f"Mutation {mutation} should have raised {expected_err}")

    # 3. grade_liveness_renewal
    base_renew = copy.deepcopy(base_lstatus)
    base_renew['lease_seq'] = 3
    m.grade_liveness_renewal(base_renew, 'sess-123', min_seq=2, kind='filesystem', expected_instance_id='inst-abc')

    renew_mutations = [
        ({'lease_seq': 1}, 'filesystem_lease_did_not_renew'),
        ({'lease_seq': 'invalid'}, 'filesystem_lease_did_not_renew'),
        ({'session_id': 'wrong-session'}, 'filesystem_session_id_mismatch'),
    ]
    for mutation, expected_err in renew_mutations:
        mutated = copy.deepcopy(base_renew)
        mutated.update(mutation)
        try:
            m.grade_liveness_renewal(mutated, 'sess-123', min_seq=2, kind='filesystem', expected_instance_id='inst-abc')
        except ValueError as err:
            assert expected_err in str(err), f"Expected {expected_err}, got {err}"
        else:
            raise AssertionError(f"Mutation {mutation} should have raised {expected_err}")

    # 4. grade_autonomous_reclamation
    base_audit = [
        {'event': 'native_liveness_enrolled', 'session': 'epoch-123'},
        {'event': 'native_session_expired', 'session': 'epoch-123'},
    ]
    m.grade_autonomous_reclamation(404, base_audit, 'epoch-123', 'filesystem')

    reclaim_mutations = [
        (200, base_audit, 'filesystem_session_not_reclaimed_autonomously'),
        (500, base_audit, 'filesystem_session_not_reclaimed_autonomously'),
        (404, [{'event': 'native_session_expired', 'session': 'epoch-123'}], 'filesystem_enrollment_not_audited'),
        (404, [{'event': 'native_liveness_enrolled', 'session': 'epoch-123'}], 'filesystem_autonomous_expiry_not_audited'),
    ]
    for status_code, audit_rows, expected_err in reclaim_mutations:
        try:
            m.grade_autonomous_reclamation(status_code, audit_rows, 'epoch-123', 'filesystem')
        except ValueError as err:
            assert expected_err in str(err), f"Expected {expected_err}, got {err}"
        else:
            raise AssertionError(f"Reclaim condition should have raised {expected_err}")

    # 5. grade_client_close (normal and expected-crash baselines with authentic kernel witness)
    base_kernel = {
        'leaf': 'test-leaf',
        'leaf_removed': True,
        'remaining': [],
        'error': None,
        'thread_stopped': True,
        'samples': 5,
        'members': [{'pid': 1234}],
    }
    base_close_normal = {
        'forced_cleanup': False,
        'exit_code': 0,
        'process': {'all_stopped': True, 'remaining': []},
        'kernel': copy.deepcopy(base_kernel),
    }
    m.grade_client_close(base_close_normal, 'filesystem', require_kernel=True)

    base_close_crash = {
        'forced_cleanup': False,
        'exit_code': -9,
        'process': {'all_stopped': True, 'remaining': []},
        'kernel': copy.deepcopy(base_kernel),
    }
    m.grade_client_close(base_close_crash, 'filesystem', expect_failure=True, expected_signal=signal.SIGKILL, require_kernel=True)

    close_mutations = [
        (base_close_normal, {'forced_cleanup': True}, False, None, 'filesystem_forced_cleanup_used'),
        (base_close_normal, {'exit_code': 1}, False, None, 'filesystem_exit_code_nonzero'),
        (base_close_normal, {'process': {'all_stopped': False, 'remaining': []}}, False, None, 'filesystem_processes_not_all_stopped'),
        (base_close_normal, {'process': {'all_stopped': True, 'remaining': [{'pid': 99}]}}, False, None, 'filesystem_processes_remaining'),
        (base_close_crash, {'exit_code': 0}, True, signal.SIGKILL, 'filesystem_unexpected_signal_exit_0'),
        (base_close_crash, {'exit_code': -15}, True, signal.SIGKILL, 'filesystem_unexpected_signal_exit_-15'),
        (base_close_crash, {'forced_cleanup': True}, True, signal.SIGKILL, 'filesystem_forced_cleanup_used'),
        # KernelObserver authentic schema mutations
        (base_close_crash, {'kernel': {'leaf_removed': False, 'remaining': [], 'error': None, 'thread_stopped': True, 'samples': 5, 'members': [{'pid': 1234}]}}, True, signal.SIGKILL, 'filesystem_kernel_leaf_not_removed'),
        (base_close_crash, {'kernel': {'leaf_removed': True, 'remaining': [{'pid': 9999}], 'error': None, 'thread_stopped': True, 'samples': 5, 'members': [{'pid': 1234}]}}, True, signal.SIGKILL, 'filesystem_kernel_processes_remaining'),
        (base_close_crash, {'kernel': {'leaf_removed': True, 'remaining': [], 'error': 'kernel_observation_failed', 'thread_stopped': True, 'samples': 5, 'members': [{'pid': 1234}]}}, True, signal.SIGKILL, 'filesystem_kernel_observer_error_kernel_observation_failed'),
        (base_close_crash, {'kernel': {'leaf_removed': True, 'remaining': [], 'error': None, 'thread_stopped': False, 'samples': 5, 'members': [{'pid': 1234}]}}, True, signal.SIGKILL, 'filesystem_kernel_thread_not_stopped'),
        (base_close_crash, {'kernel': {'leaf_removed': True, 'remaining': [], 'error': None, 'thread_stopped': True, 'samples': 0, 'members': [{'pid': 1234}]}}, True, signal.SIGKILL, 'filesystem_kernel_samples_zero'),
        (base_close_crash, {'kernel': {'leaf_removed': True, 'remaining': [], 'error': None, 'thread_stopped': True, 'samples': 5, 'members': []}}, True, signal.SIGKILL, 'filesystem_kernel_members_empty'),
    ]
    for template, mutation, exp_fail, exp_sig, expected_err in close_mutations:
        mutated = copy.deepcopy(template)
        mutated.update(mutation)
        try:
            m.grade_client_close(mutated, 'filesystem', expect_failure=exp_fail, expected_signal=exp_sig, require_kernel=True)
        except ValueError as err:
            assert expected_err in str(err), f"Expected {expected_err}, got {err}"
        else:
            raise AssertionError(f"Mutation {mutation} should have raised {expected_err}")

    # Explicitly test reproduction of check_round7 bad kernel close dictionary
    bad_kernel_repro = {
        'forced_cleanup': False,
        'exit_code': -9,
        'process': {'all_stopped': True, 'remaining': []},
        'kernel': {
            'leaf_removed': False,
            'remaining': [{'pid': 9999}],
            'error': 'kernel_observation_failed',
            'thread_stopped': False,
            'members': [],
            'samples': 0,
        },
    }
    try:
        m.grade_client_close(bad_kernel_repro, 'leaking-cgroup', expect_failure=True, expected_signal=signal.SIGKILL)
    except ValueError as err:
        assert 'leaking-cgroup_kernel_thread_not_stopped' in str(err), f"Expected thread_not_stopped error, got {err}"
    else:
        raise AssertionError("Failed check_round7 kernel schema must be rejected by grade_client_close")

    # Explicitly test resource budget grader mutations (effective limits, shutdown_read, peaks)
    budgeted_kernel = {
        'leaf': 'test-leaf',
        'leaf_removed': True,
        'remaining': [],
        'error': None,
        'thread_stopped': True,
        'samples': 5,
        'members': [{'pid': 1234}],
        'first': {
            'memory.max': 512 * 1024 * 1024,
            'memory.swap.max': 0,
            'memory.oom.group': 1,
            'pids.max': 64,
            'cpu.max': [100000, 100000],
        },
        'tasks_peak': 10,
        'memory_peak_bytes': 64 * 1024 * 1024,
        'shutdown_read': {'status': 'resolved', 'resolved_within_deadline': True, 'errno': 2},
    }
    base_budgeted_close = {
        'forced_cleanup': False,
        'exit_code': 0,
        'budgeted': True,
        'process': {'all_stopped': True, 'remaining': []},
        'kernel': copy.deepcopy(budgeted_kernel),
    }
    m.grade_client_close(base_budgeted_close, 'budgeted_test', require_kernel=True)

    # Mutations checking check_graders unbounded resource controls
    budget_mutations = [
        ({'shutdown_read': {'status': 'failed', 'resolved_within_deadline': False}}, 'budgeted_test_kernel_shutdown_uncertainty_unresolved'),
        ({'first': {'memory.max': 'max', 'memory.swap.max': 0, 'memory.oom.group': 1, 'pids.max': 64, 'cpu.max': [100000, 100000]}}, 'budgeted_test_effective_memory_max_mismatch'),
        ({'first': {'memory.max': 512 * 1024 * 1024, 'memory.swap.max': 'max', 'memory.oom.group': 1, 'pids.max': 64, 'cpu.max': [100000, 100000]}}, 'budgeted_test_effective_swap_max_mismatch'),
        ({'first': {'memory.max': 512 * 1024 * 1024, 'memory.swap.max': 0, 'memory.oom.group': 0, 'pids.max': 64, 'cpu.max': [100000, 100000]}}, 'budgeted_test_effective_oom_group_mismatch'),
        ({'first': {'memory.max': 512 * 1024 * 1024, 'memory.swap.max': 0, 'memory.oom.group': 1, 'pids.max': 'max', 'cpu.max': [100000, 100000]}}, 'budgeted_test_effective_pids_max_mismatch'),
        ({'first': {'memory.max': 512 * 1024 * 1024, 'memory.swap.max': 0, 'memory.oom.group': 1, 'pids.max': 64, 'cpu.max': ['max', 100000]}}, 'budgeted_test_effective_cpu_max_mismatch'),
        ({'tasks_peak': 1000000}, 'budgeted_test_kernel_task_bound_failed'),
        ({'memory_peak_bytes': 10**15}, 'budgeted_test_owned_memory_overshoot_exceeded'),
    ]
    for k_mut, exp_err in budget_mutations:
        mutated_close = copy.deepcopy(base_budgeted_close)
        mutated_close['kernel'].update(k_mut)
        try:
            m.grade_client_close(mutated_close, 'budgeted_test', require_kernel=True)
        except ValueError as err:
            assert exp_err in str(err), f"Expected {exp_err}, got {err}"
        else:
            raise AssertionError(f"Budget mutation {k_mut} should have raised {exp_err}")

    # Test grade_rig_cleanup_result
    valid_cleanup = {
        'clients': [{'forced_cleanup': False, 'process': {'all_stopped': True, 'remaining': []}}],
        'daemon_process': {'all_stopped': True, 'remaining': []},
    }
    m.grade_rig_cleanup_result(valid_cleanup, 'test_rig')

    # Explicitly test reproduction of check_round10 malformed cleanups
    for malformed in (None, {}, {'clients': [{}]}):
        try:
            m.grade_rig_cleanup_result(malformed, 'missing-witness')
        except ValueError:
            pass
        else:
            raise AssertionError(f"Malformed cleanup {malformed} must raise ValueError")

    cleanup_mutations = [
        ({'clients': [{'forced_cleanup': True, 'process': {'all_stopped': True, 'remaining': []}}]}, 'test_rig_client_0_forced_cleanup'),
        ({'clients': [{'forced_cleanup': False, 'process': {'all_stopped': False, 'remaining': []}}]}, 'test_rig_client_0_process_not_all_stopped'),
        ({'clients': [{'forced_cleanup': False, 'process': {'all_stopped': True, 'remaining': [{'pid': 123}]}}]}, 'test_rig_client_0_process_remaining'),
        ({'daemon_process': {'all_stopped': False, 'remaining': []}}, 'test_rig_daemon_not_all_stopped'),
        ({'daemon_process': {'all_stopped': True, 'remaining': [{'pid': 456}]}}, 'test_rig_daemon_process_remaining'),
        ({'error': 'cleanup_failed'}, 'test_rig_cleanup_error_cleanup_failed'),
    ]
    for c_mut, exp_err in cleanup_mutations:
        mutated_c = copy.deepcopy(valid_cleanup)
        mutated_c.update(c_mut)
        try:
            m.grade_rig_cleanup_result(mutated_c, 'test_rig')
        except ValueError as err:
            assert exp_err in str(err), f"Expected {exp_err}, got {err}"
        else:
            raise AssertionError(f"Cleanup mutation {c_mut} should have raised {exp_err}")

    # Test grade_restart_risk
    valid_cp = {
        'scoped_hosts': ['host-restart-risk'],
        'provenance': {
            'sessions': [{
                'session': 'host-restart-risk',
                'incomplete': True,
                'fingerprints': [[1, {'source': {'host': 'untrusted.example.test'}}]],
                'literals': [],
            }],
        },
    }
    valid_d2_inst = {
        'provenance': {
            'accounting_revision': 'sw-provenance-storage/1',
            'usage': {
                'sessions': 1,
                'incomplete_sessions': 1,
                'fingerprints': 1,
                'literals': 0,
                'retained_bytes': 1751,
                'max_session_retained_bytes': 795,
            },
        },
    }
    valid_post_end = {
        'provenance': {
            'accounting_revision': 'sw-provenance-storage/1',
            'usage': {
                'sessions': 1,
                'incomplete_sessions': 1,
                'fingerprints': 1,
                'literals': 0,
                'retained_bytes': 1751,
                'max_session_retained_bytes': 795,
            },
        },
    }
    m.grade_restart_risk(valid_cp, valid_cp, valid_d2_inst, valid_post_end, 'host-restart-risk')

    # Explicitly test check_round10 wrong_host reproducer
    wrong_host = copy.deepcopy(valid_d2_inst)
    wrong_host['provenance']['usage'].update(fingerprints=100, incomplete_sessions=2, retained_bytes=999999)
    try:
        m.grade_restart_risk(valid_cp, valid_cp, wrong_host, wrong_host, 'host-restart-risk')
    except ValueError:
        pass
    else:
        raise AssertionError("wrong_host with mismatched aggregate counts must raise ValueError")

    risk_mutations = [
        ({'scoped_hosts': []}, valid_cp, valid_d2_inst, valid_post_end, 'd1_checkpoint_missing_scoped_host'),
        (valid_cp, {'scoped_hosts': []}, valid_d2_inst, valid_post_end, 'd2_checkpoint_missing_scoped_host'),
        ({'scoped_hosts': ['host-restart-risk'], 'provenance': {'sessions': [{'session': 'host-restart-risk', 'incomplete': False, 'fingerprints': [[1, {'source': {'host': 'untrusted.example.test'}}]], 'literals': []}]}}, valid_cp, valid_d2_inst, valid_post_end, 'd1_checkpoint_session_incomplete_false'),
        ({'scoped_hosts': ['host-restart-risk'], 'provenance': {'sessions': [{'session': 'host-restart-risk', 'incomplete': True, 'fingerprints': [], 'literals': []}]}}, valid_cp, valid_d2_inst, valid_post_end, 'd1_checkpoint_fingerprints_empty'),
        (valid_cp, valid_cp, {'provenance': {'accounting_revision': 'sw-provenance-storage/1', 'usage': {'sessions': 1, 'fingerprints': 0, 'incomplete_sessions': 1, 'literals': 0, 'retained_bytes': 1751, 'max_session_retained_bytes': 795}}}, valid_post_end, 'd2_provenance_fingerprints_mismatch'),
        (valid_cp, valid_cp, {'provenance': {'accounting_revision': 'sw-provenance-storage/1', 'usage': {'sessions': 1, 'fingerprints': 1, 'incomplete_sessions': 0, 'literals': 0, 'retained_bytes': 1751, 'max_session_retained_bytes': 795}}}, valid_post_end, 'd2_provenance_incomplete_sessions_mismatch'),
        (valid_cp, valid_cp, {'provenance': {'accounting_revision': 'sw-provenance-storage/1', 'usage': {'sessions': 1, 'fingerprints': 1, 'incomplete_sessions': 1, 'literals': 0, 'retained_bytes': 0, 'max_session_retained_bytes': 0}}}, valid_post_end, 'd2_provenance_retained_bytes_not_positive'),
        (valid_cp, valid_cp, valid_d2_inst, {'provenance': {'accounting_revision': 'sw-provenance-storage/1', 'usage': {'sessions': 1, 'fingerprints': 0, 'incomplete_sessions': 1, 'literals': 0, 'retained_bytes': 1751, 'max_session_retained_bytes': 795}}}, 'risk_fingerprints_laundered_by_session_end'),
    ]
    for cp1, cp2, d2_i, pe_i, exp_err in risk_mutations:
        try:
            m.grade_restart_risk(cp1, cp2, d2_i, pe_i, 'host-restart-risk')
        except ValueError as err:
            assert exp_err in str(err), f"Expected {exp_err}, got {err}"
        else:
            raise AssertionError(f"Risk mutation should have raised {exp_err}")

    # Missing kernel when require_kernel=True must be rejected
    try:
        m.grade_client_close({'forced_cleanup': False, 'exit_code': 0, 'process': {'all_stopped': True, 'remaining': []}},
                             'filesystem', require_kernel=True)
    except ValueError as err:
        assert 'filesystem_missing_kernel_evidence' in str(err)
    else:
        raise AssertionError("Missing kernel evidence when require_kernel=True must raise ValueError")

    try:
        m.grade_client_close(None, 'filesystem')
    except ValueError as err:
        assert 'filesystem_missing_close_result' in str(err)
    else:
        raise AssertionError("None close result should have raised filesystem_missing_close_result")

    # 6. grade_selected_report
    base_report = {
        'status': 'pass',
        'selected_production_acceptance': True,
        'failed': 0,
        'checks': [{'case': c, 'passed': True} for c in m.REQUIRED_PRODUCTION_CASES],
    }
    base_report.update(valid_source_identity())
    m.grade_selected_report(base_report, m.REQUIRED_PRODUCTION_CASES)

    report_mutations = [
        ({'source_before': None}, 'candidate_source_identity_missing'),
        ({'source_after': {'commit': 'd' * 40, 'tree': 'b' * 40, 'dirty': False}}, 'candidate_source_changed'),
        ({'source_after': {'commit': 'a' * 40, 'tree': 'd' * 40, 'dirty': False}}, 'candidate_source_changed'),
        ({'source_before': {'commit': 'a' * 40, 'tree': 'b' * 40, 'dirty': True}}, 'candidate_source_changed'),
        ({'runtime_source_commit': 'd' * 40}, 'candidate_source_changed'),
        ({'binary_unchanged': False}, 'candidate_binary_changed'),
        ({'config_sha256': None}, 'required_identity_missing_config_sha256'),
        ({'restart_config_sha256': 'not-a-digest'}, 'required_identity_missing_restart_config_sha256'),
        ({'status': 'fail'}, 'report_status_not_pass'),
        ({'selected_production_acceptance': False}, 'selected_production_acceptance_false'),
        ({'failed': 1}, 'report_failed_nonzero'),
        ({'checks': [{'case': c, 'passed': True} for c in m.REQUIRED_PRODUCTION_CASES if c != 'old_result_replay_rejected']},
         'required_case_missing_old_result_replay_rejected'),
        ({'checks': [{'case': m.REQUIRED_PRODUCTION_CASES[0], 'passed': False}]},
         f'required_case_missing_{m.REQUIRED_PRODUCTION_CASES[0]}'),
    ]
    for mutation, expected_err in report_mutations:
        mutated = copy.deepcopy(base_report)
        mutated.update(mutation)
        try:
            m.grade_selected_report(mutated, m.REQUIRED_PRODUCTION_CASES)
        except ValueError as err:
            assert expected_err in str(err), f"Expected {expected_err}, got {err}"
        else:
            raise AssertionError(f"Mutation {mutation} should have raised {expected_err}")

    print("PASS: test_production_graders_positive_and_adversarial_mutations")


def test_production_summary_projection():
    sample_report = {
        'format': m.FORMAT,
        'mode': 'selected-production-acceptance',
        'status': 'pass',
        'selected_production_acceptance': True,
        'passed': 11,
        'failed': 0,
        'checks_count': 11,
        'unbounded_secret': 'do_not_leak',
        'checks': [
            {
                'case': 'filesystem_sigkill_reclamation',
                'passed': True,
                'observed_processes': [{'pid': 1, 'cmd': 'sh'}],
                'client': {'forced_cleanup': False},
                'details': {
                    'process_stop_millis': 45.2,
                    'observed_processes': [{'pid': 1}],
                    'client': {'secret': 123},
                },
            }
        ],
    }
    s = m.summary(sample_report)
    assert 'unbounded_secret' not in s, "summary must strip unbounded root keys"
    assert len(s['checks']) == 1
    chk = s['checks'][0]
    assert chk['case'] == 'filesystem_sigkill_reclamation'
    assert chk['passed'] is True
    assert 'observed_processes' not in chk, "summary must strip root observed_processes from check"
    assert 'client' not in chk, "summary must strip root client from check"
    assert 'observed_processes' not in chk['details'], "summary must strip observed_processes from check details"
    assert 'client' not in chk['details'], "summary must strip client from check details"
    assert chk['details']['process_stop_millis'] == 45.2
    print("PASS: test_production_summary_projection")


def test_daemon_api_contracts():
    agentfw_bin = ROOT / 'target/debug/agentfw'
    assert agentfw_bin.is_file(), f"Required candidate binary not found at {agentfw_bin}"

    generic_spec = importlib.util.spec_from_file_location('generic', ROOT / 'scripts/verify-sou89-native-liveness.py')
    generic_m = importlib.util.module_from_spec(generic_spec)
    generic_spec.loader.exec_module(generic_m)

    with tempfile.TemporaryDirectory(prefix='sou89-daemon-api-') as temporary:
        d = generic_m.DaemonFixture(agentfw_bin, Path(temporary))
        d.start()
        try:
            # 1. Instance query
            status, inst = m.http_get(f'http://127.0.0.1:{d.port}/native/v1/instance', d.native_token)
            assert status == 200, f"Instance query failed: {status}"

            # 2. Start unscoped session with physical session_id
            sid = 'contract-physical-session-id'
            start_req = {
                'contract_version': m.NATIVE_CONTRACT,
                'registry_sha256': d.registry_sha256,
                'session_id': sid,
                'liveness': m.LIVENESS_CONTRACT, 'event': 'session_start',
            }
            status, resp = m.http_post(d.native_url, d.native_token, start_req)
            assert status == 200 and resp.get('release') is True, f"session_start failed: {resp}"
            owner_tok = resp['owner_token']

            # 3. Instance query shows unscoped session does NOT create scoped bindings
            status, inst_after = m.http_get(f'http://127.0.0.1:{d.port}/native/v1/instance', d.native_token)
            assert status == 200 and inst_after.get('bindings') == [], "Unscoped session must not appear in scoped bindings"

            # 4. Enroll in liveness using physical session_id
            enroll_req = {
                'contract_version': m.LIVENESS_CONTRACT,
                'registry_sha256': d.registry_sha256,
                'session_id': sid,
                'instance_id': inst['instance_id'],
                'action': 'enroll',
                'owner_token': owner_tok,
                'lease_seconds': 4,
            }
            status, enroll_resp = m.http_post(d.liveness_url, d.native_token, enroll_req)
            assert status == 200, f"Enroll failed: {enroll_resp}"
            enrolled_epoch = enroll_resp['epoch']

            # 5. Verify daemon audit records enrolled epoch as 'session', and physical session_id differs from epoch
            raw_audit = m.read_raw_audit(d)
            audit_epoch = next(r['session'] for r in reversed(raw_audit) if r.get('event') == 'native_session_start')
            assert audit_epoch == enrolled_epoch and audit_epoch != sid, "audit.session must match enrolled epoch and differ from sid"

            # 6. Status query with physical session_id succeeds 200 active
            status_req = {k: v for k, v in enroll_req.items() if k not in ('owner_token', 'lease_seconds')}
            status_req['action'] = 'status'
            status, active_status = m.http_post(d.liveness_url, d.native_token, status_req)
            assert status == 200, f"Status failed: {active_status}"
            m.grade_liveness_active(active_status, sid, 'daemon_unscoped', expected_instance_id=inst['instance_id'])

            # 7. Status query with epoch returns 404 native_session_unknown (reproducing and verifying P1 fix)
            status_wrong, reply_wrong = m.http_post(d.liveness_url, d.native_token, {
                'contract_version': m.LIVENESS_CONTRACT,
                'registry_sha256': d.registry_sha256,
                'session_id': enrolled_epoch,
                'instance_id': inst['instance_id'],
                'action': 'status',
            })
            assert status_wrong == 404 and reply_wrong.get('error_code') == 'native_session_unknown', \
                f"Status with epoch as session_id must return 404 native_session_unknown, got {status_wrong} ({reply_wrong})"

            # 8. Execute first call to test invalid result_kind rejection
            call_req = {
                'contract_version': m.NATIVE_CONTRACT,
                'registry_sha256': d.registry_sha256,
                'session_id': sid,
                'event': 'call',
                'tool': 'read_document',
                'args': {},
                'schema_sha256': generic_m.TOOL_SCHEMA_SHA256,
            }
            status, call_resp1 = m.http_post(d.native_url, d.native_token, call_req)
            assert status == 200 and call_resp1.get('call_id'), f"Call 1 failed: {call_resp1}"
            cid1 = call_resp1['call_id']

            # 9. Rejection of invalid result_kind='text' (spends cid1)
            bad_result = {
                'contract_version': m.NATIVE_CONTRACT,
                'registry_sha256': d.registry_sha256,
                'session_id': sid,
                'event': 'result',
                'call_id': cid1,
                'tool': 'read_document',
                'args': {},
                'result_kind': 'text',
                'content': 'invalid kind',
                'delivery': 'model',
            }
            status, bad_resp = m.http_post(d.native_url, d.native_token, bad_result)
            assert bad_resp.get('error_code') == 'native_result_kind', f"Expected native_result_kind, got {bad_resp}"

            # 10. Execute second call to test accepted valid result
            status, call_resp2 = m.http_post(d.native_url, d.native_token, call_req)
            assert status == 200 and call_resp2.get('call_id'), f"Call 2 failed: {call_resp2}"
            cid2 = call_resp2['call_id']

            good_result = {
                'contract_version': m.NATIVE_CONTRACT,
                'registry_sha256': d.registry_sha256,
                'session_id': sid,
                'event': 'result',
                'call_id': cid2,
                'tool': 'read_document',
                'args': {},
                'result_kind': 'value',
                'content': json.dumps({'jsonrpc': '2.0', 'id': 10, 'result': {'content': [{'type': 'text', 'text': 'good'}]}}),
                'delivery': 'mcp_host',
            }
            status, good_resp = m.http_post(d.native_url, d.native_token, good_result)
            assert status == 200 and good_resp.get('release') is True, f"Valid result failed: {good_resp}"

            # 11. Retire session using physical session_id and epoch
            retire_req = {
                'contract_version': m.LIVENESS_CONTRACT,
                'registry_sha256': d.registry_sha256,
                'session_id': sid,
                'instance_id': inst['instance_id'],
                'action': 'retire',
                'epoch': enrolled_epoch,
                'owner_token': owner_tok,
            }
            status, retire_resp = m.http_post(d.liveness_url, d.native_token, retire_req)
            assert status == 200, f"Retire failed: {retire_resp}"

            # 12. Replay result on retired session is rejected without release
            status, replay_resp = m.http_post(d.native_url, d.native_token, good_result)
            assert status in (404, 409) and replay_resp.get('error_code') in ('native_session_unknown', 'native_session_terminal'), \
                f"Expected session unknown, got {replay_resp}"
            assert replay_resp.get('release') is not True, "Replay must never release"

            # 13. Test profile-barrier continuity activation
            barrier_status, _ = m.http_post(
                f'http://127.0.0.1:{d.port}/native/v1/profile-barrier',
                d.native_token,
                {},
                headers={'x-agentfw-host-session': 'host-test-barrier'},
            )
            assert barrier_status == 200, f"profile-barrier failed: {barrier_status}"
            checkpoint_file = Path(temporary) / '.agentfw/mcp-profiles/risk-checkpoint.json'
            assert checkpoint_file.is_file(), "risk-checkpoint.json must be written on barrier"
            chk = json.loads(checkpoint_file.read_text())
            assert 'host-test-barrier' in chk.get('scoped_hosts', []), "checkpoint must include scoped host"

        finally:
            d.stop()

        # 14. Verify selected registry contracts (mcp_host_call_id requirement and Git args binding)
        git_args = m.GIT.call(10, repo='/workspace')['params']['arguments']
        for kind, installer, tool, args in [
            ('filesystem', m.BASE.INSTALL, 'read_file', {'path': '/workspace/notes.txt'}),
            ('git', m.GIT.INSTALL, 'git_show', git_args),
        ]:
            with tempfile.TemporaryDirectory(prefix=f'sou89-sel-api-{kind}-') as tmp_sel:
                d_sel = generic_m.DaemonFixture(Path('target/debug/agentfw'), Path(tmp_sel))
                registry = installer.registry(json.loads((installer.ASSETS / 'upstream-tools-list.json').read_text()))
                raw = json.dumps(registry, sort_keys=True).encode()
                (d_sel.home / 'registry.json').write_bytes(raw)
                cfg = d_sel.home / 'config.yaml'
                sha = hashlib.sha256(raw).hexdigest()
                cfg.write_text(cfg.read_text().replace(d_sel.registry_sha256, sha))
                d_sel.registry_sha256 = sha
                d_sel.start()
                try:
                    sid_sel = f'test-sel-{kind}'
                    common = {'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': sha, 'session_id': sid_sel}
                    st, r = m.http_post(d_sel.native_url, d_sel.native_token, {**common, 'liveness': m.LIVENESS_CONTRACT, 'event': 'session_start'})
                    assert st == 200 and r.get('release'), f"session_start failed: {r}"
                    t = next(t for t in registry['tools'] if t['name'] == tool)
                    call_without_host_id = {**common, 'event': 'call', 'tool': tool, 'args': args, 'schema_sha256': t['schema_sha256']}
                    st, r = m.http_post(d_sel.native_url, d_sel.native_token, call_without_host_id)
                    assert r.get('error_code') == 'native_host_call_missing_or_invalid', f"Expected native_host_call_missing_or_invalid, got {r}"

                    st, c = m.http_post(d_sel.native_url, d_sel.native_token, {**call_without_host_id, 'mcp_host_call_id': 10})
                    assert st == 200 and c.get('release') and c.get('call_id'), f"Call with host id failed: {c}"

                    if kind == 'git':
                        bad_result = {
                            **common, 'event': 'result', 'tool': tool, 'args': {'repo': '/workspace'},
                            'call_id': c['call_id'], 'result_kind': 'value', 'delivery': 'mcp_host',
                            'content': json.dumps({'jsonrpc': '2.0', 'id': 10, 'result': {'content': [{'type': 'text', 'text': 'test'}]}})
                        }
                        st, r = m.http_post(d_sel.native_url, d_sel.native_token, bad_result)
                        assert r.get('error_code') == 'native_call_binding_mismatch', f"Expected native_call_binding_mismatch, got {r}"
                finally:
                    d_sel.stop()

        # 15. Verify cascade grant scope matching (read_file vs read_text_file)
        with tempfile.TemporaryDirectory(prefix='sou89-cascade-scope-') as tmp_scope:
            d_sc = generic_m.DaemonFixture(agentfw_bin, Path(tmp_scope))
            reg_fs = m.BASE.INSTALL.registry(json.loads((m.BASE.INSTALL.ASSETS / 'upstream-tools-list.json').read_text()))
            raw_fs = json.dumps(reg_fs, sort_keys=True).encode()
            (d_sc.home / 'registry.json').write_bytes(raw_fs)
            sha_fs = hashlib.sha256(raw_fs).hexdigest()
            cfg_fs = d_sc.home / 'config.yaml'
            cfg_fs.write_text(cfg_fs.read_text().replace(d_sc.registry_sha256, sha_fs))
            d_sc.registry_sha256 = sha_fs
            d_sc.start()
            try:
                _, inst_sc = m.http_get(f'http://127.0.0.1:{d_sc.port}/native/v1/instance', d_sc.native_token)
                grant_tool = reg_fs['tools'][0]['name']  # 'read_file'
                useful_req = m.RESOURCE.call(10, '/workspace/notes.txt')
                useful_tool = useful_req['params']['name']  # 'read_text_file'
                assert grant_tool != useful_tool

                env_sc = m.BASE.environment(Path(tmp_scope))
                proof_wrong = subprocess.check_output([
                    str(agentfw_bin), 'child-authority', 'mint',
                    '--session', 'host-cascade-scope', '--server', 'sou86-recovery',
                    '--ttl-seconds', '120', '--tools', grant_tool,
                    '--agent-id', 'orch-p', '--instance-id', inst_sc['instance_id']
                ], env=env_sc, text=True).strip()

                common_sc = {'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': sha_fs, 'session_id': 'sid-cascade-scope'}
                st, start_sc = m.http_post(d_sc.native_url, d_sc.native_token, {
                    **common_sc, 'liveness': m.LIVENESS_CONTRACT, 'event': 'session_start',
                    'host_session': 'host-cascade-scope', 'server_id': 'sou86-recovery',
                    'child_authority': proof_wrong
                })
                assert st == 200 and start_sc.get('release'), f"session_start failed: {start_sc}"

                t_useful = next(t for t in reg_fs['tools'] if t['name'] == useful_tool)
                st, reply_escalate = m.http_post(d_sc.native_url, d_sc.native_token, {
                    **common_sc, 'event': 'call',
                    'tool': useful_tool, 'args': useful_req['params']['arguments'],
                    'schema_sha256': t_useful['schema_sha256'], 'mcp_host_call_id': 10
                })
                assert st != 200 and reply_escalate.get('error_code') == 'native_child_authority_escalation', \
                    f"Expected native_child_authority_escalation, got {reply_escalate}"

                # Minting with useful_tool succeeds
                proof_right = subprocess.check_output([
                    str(agentfw_bin), 'child-authority', 'mint',
                    '--session', 'host-cascade-scope-ok', '--server', 'sou86-recovery',
                    '--ttl-seconds', '120', '--tools', useful_tool,
                    '--agent-id', 'orch-ok', '--instance-id', inst_sc['instance_id']
                ], env=env_sc, text=True).strip()
                st, start_ok = m.http_post(d_sc.native_url, d_sc.native_token, {
                    'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': sha_fs, 'session_id': 'sid-cascade-scope-ok',
                    'liveness': m.LIVENESS_CONTRACT, 'event': 'session_start', 'host_session': 'host-cascade-scope-ok',
                    'server_id': 'sou86-recovery', 'child_authority': proof_right
                })
                assert st == 200 and start_ok.get('release'), f"session_start failed: {start_ok}"
                st, reply_ok = m.http_post(d_sc.native_url, d_sc.native_token, {
                    'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': sha_fs, 'session_id': 'sid-cascade-scope-ok',
                    'event': 'call', 'tool': useful_tool, 'args': useful_req['params']['arguments'],
                    'schema_sha256': t_useful['schema_sha256'], 'mcp_host_call_id': 10
                })
                assert st == 200 and reply_ok.get('release'), f"Call with matching authority failed: {reply_ok}"
            finally:
                d_sc.stop()

        # 16. Verify restart risk policy: barrier + restart preserves hook authority requirement, while native physical session_id is admitted
        with tempfile.TemporaryDirectory(prefix='sou89-restart-risk-') as tmp_risk:
            d_risk = generic_m.DaemonFixture(agentfw_bin, Path(tmp_risk))
            d_risk.start()
            try:
                hook_tok = (d_risk.home / 'token').read_text().strip() if (d_risk.home / 'token').is_file() else (d_risk.home / '.agentfw/token').read_text().strip()
                # PostToolUse taint
                m.http_post(f'http://127.0.0.1:{d_risk.port}/hook', hook_tok, {
                    'session_id': 'host-restart-risk', 'hook_event_name': 'PostToolUse',
                    'tool_name': 'WebFetch', 'tool_input': {'url': 'https://untrusted.example.test'},
                    'tool_response': 'taint'
                })
                bst, _ = m.http_post(f'http://127.0.0.1:{d_risk.port}/native/v1/profile-barrier',
                                     d_risk.native_token, {}, headers={'x-agentfw-host-session': 'host-restart-risk'})
                assert bst == 200
                checkpoint = d_risk.home / '.agentfw/mcp-profiles/risk-checkpoint.json'
                if not checkpoint.is_file():
                    checkpoint = d_risk.home / 'mcp-profiles/risk-checkpoint.json'
                assert checkpoint.is_file()
                d_risk.stop()
                d_risk.start()

                # Native physical session_id is in a different namespace and is admitted
                st, r_nat = m.http_post(d_risk.native_url, d_risk.native_token, {
                    'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': d_risk.registry_sha256,
                    'session_id': 'host-restart-risk', 'liveness': m.LIVENESS_CONTRACT, 'event': 'session_start'
                })
                assert st == 200 and r_nat.get('release') is True, f"Native session_start failed: {r_nat}"

                # Authenticated hook on host-restart-risk without proof is denied
                st, r_hk = m.http_post(f'http://127.0.0.1:{d_risk.port}/hook', hook_tok, {
                    'session_id': 'host-restart-risk', 'hook_event_name': 'PreToolUse',
                    'tool_name': 'Bash', 'tool_input': {'command': 'echo 1'}
                })
                assert st == 200
                out = r_hk.get('hookSpecificOutput', {})
                assert out.get('permissionDecision') == 'deny', f"Expected deny, got {out}"
                assert 'native_hook_authority_required' in out.get('permissionDecisionReason', '')

                # Independent host on hook is allowed
                st, r_ind = m.http_post(f'http://127.0.0.1:{d_risk.port}/hook', hook_tok, {
                    'session_id': 'host-independent', 'hook_event_name': 'PreToolUse',
                    'tool_name': 'Bash', 'tool_input': {'command': 'echo 1'}
                })
                assert st == 200 and r_ind.get('hookSpecificOutput', {}).get('permissionDecision') != 'deny'
            finally:
                d_risk.stop()

    print("PASS: test_daemon_api_contracts")


def test_normal_eof_after_retirement():
    agentfw_bin = ROOT / 'target/debug/agentfw'
    generic_spec = importlib.util.spec_from_file_location('generic', ROOT / 'scripts/verify-sou89-native-liveness.py')
    generic_m = importlib.util.module_from_spec(generic_spec)
    generic_spec.loader.exec_module(generic_m)

    with tempfile.TemporaryDirectory(prefix='sou89-r8-close-') as tmp:
        d = generic_m.DaemonFixture(agentfw_bin, Path(tmp))
        p = None
        d.start()
        try:
            sid = 'contract-clean-retired'
            p, _ = d.spawn_collector('test-close', session_id=sid, lease_secs=60)
            p.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2024-11-05', 'capabilities': {}, 'clientInfo': {'name': 'test-contract', 'version': '1'}}}) + '\n')
            p.stdin.flush()
            line = p.stdout.readline()
            assert line, "Expected initialize response"
            _, inst = m.http_get(f'http://127.0.0.1:{d.port}/native/v1/instance', d.native_token)
            raw_audit = m.read_raw_audit(d)
            enrolled = next(r for r in reversed(raw_audit) if r.get('event') == 'native_liveness_enrolled' and r.get('session_id') == sid)
            st, reply = m.http_post(d.native_url, d.native_token, {'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': d.registry_sha256, 'session_id': sid, 'event': 'session_end'})
            assert st == 200, f"Retire failed: {reply}"
            p.stdin.close()
            code = p.wait(timeout=8)
            assert code == 0, f"Expected clean EOF exit 0, got {code}"
        finally:
            if p is not None and p.poll() is None:
                p.kill()
                p.wait(timeout=5)
            d.stop()
    print("PASS: test_normal_eof_after_retirement")


def test_source_helper_arity():
    # Verify BASE.source takes 0 arguments (real helper signature)
    import inspect
    sig = inspect.signature(m.BASE.source)
    assert len(sig.parameters) == 0, f"BASE.source must take 0 arguments, got {sig.parameters}"
    try:
        m.BASE.source(m.ROOT)
    except TypeError:
        pass
    else:
        raise AssertionError("BASE.source(ROOT) must raise TypeError")
    print("PASS: test_source_helper_arity")


def test_cli_guard_and_report_retention():
    # 1. Test --run plan guard
    proc = subprocess.run(
        [sys.executable, str(ROOT / 'scripts/verify-sou89-selected-liveness.py'),
         '--agentfw', str(ROOT / 'target/debug/agentfw'),
         '--node', '/bin/echo', '--npm', '/bin/echo', '--bwrap', '/bin/echo',
         '--output', '/tmp/disposable-output', '--expected-commit', 'HEAD',
         '--runtime-source-commit', 'HEAD', '--disposable-systemd-unit', 'unit.service',
         '--git', '/bin/echo', '--git-sha256', '0'*64, '--git-launcher', '/bin/echo'],
        capture_output=True, text=True
    )
    assert proc.returncode == 0, f"Plan run must exit 0, got {proc.returncode}"
    plan_out = json.loads(proc.stdout)
    assert plan_out.get('status') == 'plan' and plan_out.get('executed') is False
    assert plan_out.get('required_linux') is True

    # 2. Test report retention on early prerequisite failure on the current host
    with tempfile.TemporaryDirectory(prefix='sou89-test-report-') as temp_dir:
        out_dir = Path(temp_dir) / 'test_run'
        proc_fail = subprocess.run(
            [sys.executable, str(ROOT / 'scripts/verify-sou89-selected-liveness.py'), '--run',
             '--agentfw', str(ROOT / 'target/debug/agentfw'),
             '--node', '/bin/echo', '--npm', '/bin/echo', '--bwrap', '/bin/echo',
             '--output', str(out_dir), '--expected-commit', 'HEAD',
             '--runtime-source-commit', 'HEAD', '--disposable-systemd-unit', 'unit.service',
             '--git', '/bin/echo', '--git-sha256', '0'*64, '--git-launcher', '/bin/echo'],
            capture_output=True, text=True
        )
        assert proc_fail.returncode == 1, "Must exit 1 on prerequisite failure"
        report_file = out_dir / 'report.json'
        assert report_file.is_file(), "report.json must be retained even on early error"
        rep = json.loads(report_file.read_text())
        assert rep.get('status') == 'fail'
        assert rep.get('selected_production_acceptance') is True
        # On Darwin, required_linux_operating_system_missing triggers first; on Linux, candidate source check triggers
        expected_cause = 'required_linux_operating_system_missing' if platform.system() != 'Linux' else 'clean_exact_candidate_source_required'
        assert rep.get('error') == expected_cause, f"Expected {expected_cause}, got {rep.get('error')}"
        # Verify sanitized summary printed
        summary_out = json.loads(proc_fail.stdout)
        assert 'observed_processes' not in summary_out
        assert summary_out.get('status') == 'fail'

    # 3. Deterministically test Linux prerequisite error handling via mock
    with tempfile.TemporaryDirectory(prefix='sou89-test-linux-err-') as temp_linux:
        out_linux = Path(temp_linux) / 'run_linux'
        args_mock = SimpleNamespace(
            output=out_linux,
            expected_commit='HEAD',
            runtime_source_commit='HEAD',
        )
        with patch.object(m.platform, 'system', return_value='Linux'), \
             patch.object(m.platform, 'machine', return_value='x86_64'), \
             patch.object(m.os, 'pidfd_open', lambda *a: None, create=True), \
             patch.object(m.signal, 'pidfd_send_signal', lambda *a: None, create=True), \
             patch.object(m.BASE, 'source', lambda: {'commit': 'a' * 40, 'dirty': False}):
            rc = m.run_selected_acceptance(args_mock)
        assert rc == 1, "Simulated Linux prerequisite failure must return 1"
        rep_linux = json.loads((out_linux / 'report.json').read_text())
        assert rep_linux.get('status') == 'fail'
        assert rep_linux.get('error') == 'clean_exact_candidate_source_required'

    print("PASS: test_cli_guard_and_report_retention")


def test_finalizer_rig_cleanup_grading():
    tree = ast.parse((ROOT / 'scripts/verify-sou89-selected-liveness.py').read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_selected_acceptance')
    owned_final = next(n for n in ast.walk(fn) if isinstance(n, ast.Try) and n.finalbody and
                       any(isinstance(x, ast.Name) and x.id == 'fs' for statement in n.finalbody for x in ast.walk(statement)))
    compiled = compile(ast.Module(body=owned_final.finalbody, type_ignores=[]), 'test_finalizer', 'exec')

    class GoodCleanup:
        def close(self):
            return {
                'clients': [{'forced_cleanup': False, 'process': {'all_stopped': True, 'remaining': []}}],
                'daemon_process': {'all_stopped': True, 'remaining': []},
            }

    class FailedCleanup:
        def close(self):
            return {
                'clients': [{'forced_cleanup': True, 'process': {'all_stopped': False, 'remaining': [{'pid': 123}]}}],
                'daemon_process': {'all_stopped': False, 'remaining': [{'pid': 456}]},
            }

    # Path 1: Positive initial-to-pass transition
    rep1 = {
        'status': 'incomplete',
        'selected_production_acceptance': True,
        'failed': 0,
        'checks': [{'case': c, 'passed': True} for c in m.REQUIRED_PRODUCTION_CASES],
    }
    rep1.update(valid_source_identity())
    env1 = {
        'fs': GoodCleanup(),
        'git': GoodCleanup(),
        'report': rep1,
        'grade_rig_cleanup_result': m.grade_rig_cleanup_result,
        'grade_selected_report': m.grade_selected_report,
        'REQUIRED_PRODUCTION_CASES': m.REQUIRED_PRODUCTION_CASES,
        'BASE': SimpleNamespace(source=lambda: valid_source_identity()['source_after']),
        'args': SimpleNamespace(agentfw=Path('/owned/candidate')),
        'sha': lambda _: 'c' * 64,
        'completed_all_cases': True,
    }
    exec(compiled, env1)
    assert rep1.get('status') == 'pass', f"Expected status 'pass', got {rep1.get('status')}"
    assert rep1.get('passed') == len(m.REQUIRED_PRODUCTION_CASES), f"Expected passed == {len(m.REQUIRED_PRODUCTION_CASES)}, got {rep1.get('passed')}"
    assert rep1.get('failed') == 0, f"Expected failed == 0, got {rep1.get('failed')}"
    assert 'grading_error' not in rep1['fs_cleanup']
    assert 'grading_error' not in rep1['git_cleanup']

    # Path 2: Partial/incomplete run (missing cases)
    rep2 = {
        'status': 'incomplete',
        'selected_production_acceptance': True,
        'failed': 0,
        'checks': [{'case': m.REQUIRED_PRODUCTION_CASES[0], 'passed': True}],
    }
    rep2.update(valid_source_identity())
    env2 = {
        'fs': GoodCleanup(),
        'git': GoodCleanup(),
        'report': rep2,
        'grade_rig_cleanup_result': m.grade_rig_cleanup_result,
        'grade_selected_report': m.grade_selected_report,
        'REQUIRED_PRODUCTION_CASES': m.REQUIRED_PRODUCTION_CASES,
        'BASE': SimpleNamespace(source=lambda: valid_source_identity()['source_after']),
        'args': SimpleNamespace(agentfw=Path('/owned/candidate')),
        'sha': lambda _: 'c' * 64,
    }
    exec(compiled, env2)
    assert rep2.get('status') == 'incomplete', f"Expected status 'incomplete', got {rep2.get('status')}"
    assert rep2.get('failed') == 1, f"Expected failed == 1, got {rep2.get('failed')}"

    # Path 3: Failed case
    rep3 = {
        'status': 'fail',
        'selected_production_acceptance': True,
        'failed': 1,
        'checks': [{'case': c, 'passed': c != m.REQUIRED_PRODUCTION_CASES[0]} for c in m.REQUIRED_PRODUCTION_CASES],
    }
    rep3.update(valid_source_identity())
    env3 = {
        'fs': GoodCleanup(),
        'git': GoodCleanup(),
        'report': rep3,
        'grade_rig_cleanup_result': m.grade_rig_cleanup_result,
        'grade_selected_report': m.grade_selected_report,
        'REQUIRED_PRODUCTION_CASES': m.REQUIRED_PRODUCTION_CASES,
        'BASE': SimpleNamespace(source=lambda: valid_source_identity()['source_after']),
        'args': SimpleNamespace(agentfw=Path('/owned/candidate')),
        'sha': lambda _: 'c' * 64,
    }
    exec(compiled, env3)
    assert rep3.get('status') == 'fail', f"Expected status 'fail', got {rep3.get('status')}"
    assert rep3.get('failed') >= 1

    # Path 4: Cleanup failure preserves returned failure evidence
    rep4 = {
        'status': 'incomplete',
        'selected_production_acceptance': True,
        'failed': 0,
        'checks': [{'case': c, 'passed': True} for c in m.REQUIRED_PRODUCTION_CASES],
    }
    rep4.update(valid_source_identity())
    env4 = {
        'fs': FailedCleanup(),
        'git': GoodCleanup(),
        'report': rep4,
        'grade_rig_cleanup_result': m.grade_rig_cleanup_result,
        'grade_selected_report': m.grade_selected_report,
        'REQUIRED_PRODUCTION_CASES': m.REQUIRED_PRODUCTION_CASES,
        'BASE': SimpleNamespace(source=lambda: valid_source_identity()['source_after']),
        'args': SimpleNamespace(agentfw=Path('/owned/candidate')),
        'sha': lambda _: 'c' * 64,
        'completed_all_cases': True,
    }
    exec(compiled, env4)
    assert rep4.get('status') == 'fail', f"Expected status 'fail', got {rep4.get('status')}"
    assert rep4.get('failed') >= 1, f"Expected failed >= 1, got {rep4.get('failed')}"
    assert 'clients' in rep4['fs_cleanup'], "Cleanup failure must preserve clients evidence"
    assert 'daemon_process' in rep4['fs_cleanup'], "Cleanup failure must preserve daemon_process evidence"
    assert rep4['fs_cleanup']['daemon_process']['remaining'] == [{'pid': 456}]
    assert 'grading_error' in rep4['fs_cleanup'], "Cleanup failure must attach grading_error"

    print("PASS: test_finalizer_rig_cleanup_grading")


def test_source_observer_failure_retains_failed_report():
    tree = ast.parse((ROOT / 'scripts/verify-sou89-selected-liveness.py').read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_selected_acceptance')
    outer = next(n for n in fn.body if isinstance(n, ast.Try) and n.finalbody)
    compiled = compile(ast.Module(body=outer.finalbody, type_ignores=[]), 'source_observer_finalizer', 'exec')
    report = {'status': 'incomplete', 'failed': 0, 'source_before': valid_source_identity()['source_before']}
    written = []

    def unavailable():
        raise OSError('owned checkout disappeared')

    exec(compiled, {'BASE': SimpleNamespace(source=unavailable), 'report': report,
                    'report_file': Path('/owned/output/report.json'),
                    'write': lambda path, value: written.append(copy.deepcopy(value))})
    assert len(written) == 1 and written[0]['status'] == 'fail'
    assert written[0]['error'] == 'source_identity_observer_failed'
    assert written[0]['failed'] == 1
    print('PASS: test_source_observer_failure_retains_failed_report')


def test_production_restart_setup():
    with tempfile.TemporaryDirectory(prefix='sou89-test-restart-setup-') as tmp:
        r_home = Path(tmp).resolve()
        r_env = m.BASE.environment(r_home)
        reg = r_home / 'registry.json'
        TOOL_SCHEMA_SHA256 = '153b97b003a5531d054d5d9c2e0b57e7428e23924bf604ebae8fb79cb7980313'
        reg_content = {
            'contract_version': m.NATIVE_CONTRACT,
            'registry_id': 'sou89-acceptance-registry',
            'tools': [{
                'name': 'read_document',
                'schema_sha256': TOOL_SCHEMA_SHA256,
                'action_class': 'read_only',
                'result_provenance': 'untrusted',
                'egress': [],
            }],
        }
        reg.write_bytes(json.dumps(reg_content, sort_keys=True).encode('utf-8'))
        reg_sha = hashlib.sha256(reg.read_bytes()).hexdigest()
        free_port = m.BASE.DEMO.free_port()
        cfg = m.setup_restart_daemon(r_home, free_port, reg, reg_sha)
        assert (r_home / '.agentfw/config.yaml').is_file(), ".agentfw/config.yaml must exist"
        p = subprocess.Popen([str(ROOT / 'target/debug/agentfw'), 'serve'], env=r_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            assert m.BASE.DEMO.wait_healthy(free_port, p), "Daemon failed to start on assigned port"
            tok = (r_home / '.agentfw/native-token').read_text().strip()
            inst = m.verify_daemon_healthy_and_enforcing(free_port, tok, reg_sha, expected_lease_secs=2)
            assert inst.get('registry_sha256') == reg_sha
        finally:
            m.BASE.DEMO.stop(p)
            p.wait(timeout=5)
    print("PASS: test_production_restart_setup")


def test_collector_fail_closed_on_denied_work():
    binary = ROOT / 'target/debug/agentfw'
    with tempfile.TemporaryDirectory(prefix='sou89-test-denied-work-') as tmp:
        g_spec = importlib.util.spec_from_file_location('g', ROOT / 'scripts/verify-sou89-native-liveness.py')
        g = importlib.util.module_from_spec(g_spec)
        g_spec.loader.exec_module(g)
        d = g.DaemonFixture(binary, Path(tmp))
        d.start()
        p = None
        try:
            sid = 'test-denied-work-sid'
            p, _ = d.spawn_collector('denied-work-collector', session_id=sid, lease_secs=60)
            def rpc(proc, req):
                proc.stdin.write(json.dumps(req) + '\n')
                proc.stdin.flush()
                import select
                readable, _, _ = select.select([proc.stdout], [], [], 5)
                assert readable, "RPC timed out"
                line = proc.stdout.readline()
                return json.loads(line) if line else None
            init = rpc(p, {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2024-11-05', 'capabilities': {}, 'clientInfo': {'name': 'test', 'version': '1'}}})
            assert 'result' in init
            p.stdin.write(json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + '\n')
            p.stdin.flush()
            assert 'result' in rpc(p, {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
            call = {'jsonrpc': '2.0', 'id': 10, 'method': 'tools/call', 'params': {'name': 'read_document', 'arguments': {'name': 'testnote'}}}
            first = rpc(p, call)
            assert first['result']['content'][0]['text'] == 'SOU-89 verified effect: note read.'

            st, inst = m.http_get(d.instance_url, d.native_token)
            enrolled = next(r for r in reversed(m.read_raw_audit(d)) if r.get('event') == 'native_liveness_enrolled' and r.get('session_id') == sid)
            st, r = m.http_post(d.native_url, d.native_token, {'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': d.registry_sha256, 'session_id': sid, 'event': 'session_end'})
            assert st == 200

            call['id'] = 11
            reply = rpc(p, call)
            code = p.wait(timeout=5)
            assert reply is None and code == 1, f"Expected None reply and exit code 1, got {reply}, {code}"
            close_res = {'forced_cleanup': False, 'process': {'all_stopped': True, 'remaining': []}, 'exit_code': code, 'kernel': None}
            m.grade_client_close(close_res, 'cascade_child', expect_failure=True)
        finally:
            if p is not None:
                if not p.stdin.closed:
                    try: p.stdin.close()
                    except OSError: pass
                if p.poll() is None: p.kill(); p.wait(timeout=5)
            d.stop()
    print("PASS: test_collector_fail_closed_on_denied_work")


def test_collector_autonomous_exit_on_renewal_failure():
    binary = ROOT / 'target/debug/agentfw'
    with tempfile.TemporaryDirectory(prefix='sou89-test-auto-exit-') as tmp:
        g_spec = importlib.util.spec_from_file_location('g', ROOT / 'scripts/verify-sou89-native-liveness.py')
        g = importlib.util.module_from_spec(g_spec)
        g_spec.loader.exec_module(g)
        d = g.DaemonFixture(binary, Path(tmp))
        d.start()
        p = None
        try:
            sid = 'test-auto-exit-sid'
            p, _ = d.spawn_collector('auto-exit-collector', session_id=sid, lease_secs=4)
            def rpc(proc, req):
                proc.stdin.write(json.dumps(req) + '\n')
                proc.stdin.flush()
                import select
                readable, _, _ = select.select([proc.stdout], [], [], 5)
                assert readable, "RPC timed out"
                line = proc.stdout.readline()
                return json.loads(line) if line else None
            init = rpc(p, {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2024-11-05', 'capabilities': {}, 'clientInfo': {'name': 'test', 'version': '1'}}})
            assert 'result' in init
            p.stdin.write(json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + '\n')
            p.stdin.flush()
            assert 'result' in rpc(p, {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})

            st, inst = m.http_get(d.instance_url, d.native_token)
            enrolled = next(r for r in reversed(m.read_raw_audit(d)) if r.get('event') == 'native_liveness_enrolled' and r.get('session_id') == sid)
            st, r = m.http_post(d.native_url, d.native_token, {'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': d.registry_sha256, 'session_id': sid, 'event': 'session_end'})
            assert st == 200

            code = p.wait(timeout=6.0)
            assert code == 1, f"Expected autonomous exit code 1, got {code}"
            close_res = {'forced_cleanup': False, 'process': {'all_stopped': True, 'remaining': []}, 'exit_code': code, 'kernel': None}
            m.grade_client_close(close_res, 'cascade_grandchild', expect_failure=True)
        finally:
            if p is not None:
                if not p.stdin.closed:
                    try: p.stdin.close()
                    except OSError: pass
                if p.poll() is None: p.kill(); p.wait(timeout=5)
            d.stop()
    print("PASS: test_collector_autonomous_exit_on_renewal_failure")


def test_cascade_audit_and_timing_extraction():
    binary = ROOT / 'target/debug/agentfw'
    with tempfile.TemporaryDirectory(prefix='sou89-test-cascade-audit-') as tmp:
        g_spec = importlib.util.spec_from_file_location('g', ROOT / 'scripts/verify-sou89-native-liveness.py')
        g = importlib.util.module_from_spec(g_spec)
        g_spec.loader.exec_module(g)
        d = g.DaemonFixture(binary, Path(tmp))
        reg = m.BASE.INSTALL.registry(json.loads((m.BASE.INSTALL.ASSETS / 'upstream-tools-list.json').read_text()))
        rp = d.home / 'registry.json'
        rp.write_text(json.dumps(reg, sort_keys=True))
        sha = m.sha(rp)
        cfg = d.home / 'config.yaml'
        cfg.write_text(cfg.read_text().replace(d.registry_sha256, sha))
        d.registry_sha256 = sha
        d.start()
        try:
            _, inst = m.http_get(d.instance_url, d.native_token)
            info = {}
            for label, lease, parent in [('p', 2, None), ('c', 8, 'p'), ('gc', 4, 'c')]:
                agent = f'test-cascade-{label}'
                cmd = [str(binary), 'child-authority', 'mint', '--session', 'host-test-cascade', '--server', 'sou86-recovery',
                       '--ttl-seconds', '120', '--tools', 'read_text_file', '--agent-id', agent, '--instance-id', inst['instance_id']]
                if parent:
                    cmd += ['--parent-id', f'test-cascade-{parent}', '--parent-binding', info[parent]['binding']]
                proof = subprocess.check_output(cmd, env=m.BASE.environment(d.temp_dir), text=True).strip()
                sid = f'physical-cascade-{label}'
                st, start = m.http_post(d.native_url, d.native_token, {
                    'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': sha,
                    'session_id': sid, 'liveness': m.LIVENESS_CONTRACT, 'event': 'session_start', 'host_session': 'host-test-cascade',
                    'server_id': 'sou86-recovery', 'child_authority': proof
                })
                assert st == 200 and start['release'], start
                st, enroll = m.http_post(d.liveness_url, d.native_token, {
                    'contract_version': m.LIVENESS_CONTRACT, 'registry_sha256': sha,
                    'session_id': sid, 'instance_id': inst['instance_id'], 'action': 'enroll',
                    'lease_seconds': lease, 'owner_token': start['owner_token']
                })
                assert st == 200, enroll
                _, now = m.http_get(d.instance_url, d.native_token)
                binding = next(b['binding_sha256'] for b in now['bindings'] if b['agent_id'] == agent)
                info[label] = {'epoch': enroll['epoch'], 'binding': binding, 'sid': sid}

            time.sleep(2.6)
            for label, v in info.items():
                st, _ = m.http_post(d.liveness_url, d.native_token, {
                    'contract_version': m.LIVENESS_CONTRACT, 'registry_sha256': sha,
                    'session_id': v['sid'], 'instance_id': inst['instance_id'], 'action': 'status'
                })
                assert st == 404, f"Session {label} should be 404 after sweep"

            # Raw audit extraction
            raw = m.read_raw_audit(d)
            for label, v in info.items():
                expiry = [r for r in raw if r.get('session') == v['epoch'] and r.get('event') == 'native_session_expired']
                assert len(expiry) == 1, f"Expected 1 expiry for {label}, got {expiry}"
                assert isinstance(expiry[0].get('at_ms'), int) and expiry[0]['at_ms'] > 0
            p_ms = next(r['at_ms'] for r in raw if r.get('session') == info['p']['epoch'] and r.get('event') == 'native_session_expired')
            c_ms = next(r['at_ms'] for r in raw if r.get('session') == info['c']['epoch'] and r.get('event') == 'native_session_expired')
            gc_ms = next(r['at_ms'] for r in raw if r.get('session') == info['gc']['epoch'] and r.get('event') == 'native_session_expired')
            assert abs(c_ms - p_ms) <= 2000, f"Delta too large: {c_ms - p_ms}"
            assert abs(gc_ms - p_ms) <= 2000, f"Delta too large: {gc_ms - p_ms}"

            # Verify that sanitized Rig.audit projection strips at_ms (proving read_raw_audit is required)
            projected = m.RESOURCE.Rig.audit(SimpleNamespace(home=d.temp_dir))['rows']
            assert all('at_ms' not in r for r in projected), "Sanitized projection must strip at_ms"
            assert not any(r.get('event') == 'native_session_retired' for r in projected), "Expiry records must not be labeled retired"
        finally:
            d.stop()
    print("PASS: test_cascade_audit_and_timing_extraction")


def test_cascade_child_handling_both_scheduling_orders():
    # 1. Exact AST extraction and execution of the production child-if block
    path = ROOT / 'scripts/verify-sou89-selected-liveness.py'
    tree = ast.parse(path.read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_selected_acceptance')
    child_if = next(n for n in ast.walk(fn) if isinstance(n, ast.If) and ast.unparse(n.test) == 'c_c.process.poll() is not None')
    compiled_child_if = compile(ast.Module(body=[child_if], type_ignores=[]), str(path), 'exec')

    class MockProc:
        def __init__(self, poll_code=None, wait_code=1):
            self._poll = poll_code
            self._wait = wait_code
        def poll(self): return self._poll
        def wait(self, timeout=None): return self._wait

    # Scenario 1 (Defect from Round 12): Valid successful useful result and later exit 1 MUST fail
    effects = []
    def exchange_success(request):
        effects.append({'id': request['id'], 'tool': request['params']['name'], 'successful_result': True})
        return {'jsonrpc': '2.0', 'id': request['id'], 'result': {'content': [{'type': 'text', 'text': m.RESOURCE.TEXT}],
                'structuredContent': {'content': m.RESOURCE.TEXT}}}, b'owned-positive-control'

    c_success = SimpleNamespace(kind='filesystem', direct=False, next_id=10,
                                rig=SimpleNamespace(workspace=Path('/test-workspace')),
                                process=MockProc(poll_code=None, wait_code=1), exchange=exchange_success)
    env_success = {'c_c': c_success, 'useful': m.useful, 'require': m.require, 'child_denied_err': None}
    try:
        exec(compiled_child_if, env_success)
    except (AssertionError, ValueError) as ex:
        assert 'descendant_useful_operation_must_be_denied_after_cascade' in str(ex)
    else:
        raise AssertionError("Successful useful operation after cascade must unconditionally fail production check")

    # Scenario 2: Intended refusal and exit 1 MUST pass
    def useful_refusal(client):
        raise ValueError('collector_closed_before_correlated_response')
    c_refusal = SimpleNamespace(process=MockProc(poll_code=None, wait_code=1))
    env_refusal = {'c_c': c_refusal, 'useful': useful_refusal, 'require': m.require, 'child_denied_err': None}
    exec(compiled_child_if, env_refusal)
    assert env_refusal['child_denied_err'] == 'collector_closed_before_correlated_response'
    assert env_refusal['c_c_exit'] == 1

    # Scenario 3: Pre-existing terminal exit MUST pass
    c_terminal = SimpleNamespace(process=MockProc(poll_code=1, wait_code=1))
    env_terminal = {'c_c': c_terminal, 'useful': lambda c: None, 'require': m.require, 'child_denied_err': None}
    exec(compiled_child_if, env_terminal)
    assert env_terminal['child_denied_err'] == 'child_already_terminal_from_renewal_uncertainty'
    assert env_terminal['c_c_exit'] == 1

    # Scenario 4: Race during write (BrokenPipeError or OSError) MUST pass
    def useful_broken_pipe(client):
        raise BrokenPipeError('Broken pipe')
    c_pipe = SimpleNamespace(process=MockProc(poll_code=None, wait_code=1))
    env_pipe = {'c_c': c_pipe, 'useful': useful_broken_pipe, 'require': m.require, 'child_denied_err': None}
    exec(compiled_child_if, env_pipe)
    assert 'broken_pipe_during_call_BrokenPipeError' in env_pipe['child_denied_err']
    assert env_pipe['c_c_exit'] == 1

    # Scenario 5: Malformed / unrelated error MUST fail require
    def useful_unrelated(client):
        raise RuntimeError('unrelated network failure')
    c_unrelated = SimpleNamespace(process=MockProc(poll_code=None, wait_code=1))
    env_unrelated = {'c_c': c_unrelated, 'useful': useful_unrelated, 'require': m.require, 'child_denied_err': None}
    try:
        exec(compiled_child_if, env_unrelated)
    except (AssertionError, ValueError) as ex:
        assert 'unexpected_child_denied_error' in str(ex)
    else:
        raise AssertionError("Unrelated non-denial error must be rejected by production require")

    # Scenario 6: Unexpected exit code != 1 MUST fail
    c_bad_exit = SimpleNamespace(process=MockProc(poll_code=None, wait_code=0))
    env_bad_exit = {'c_c': c_bad_exit, 'useful': useful_refusal, 'require': m.require, 'child_denied_err': None}
    try:
        exec(compiled_child_if, env_bad_exit)
    except (AssertionError, ValueError) as ex:
        assert 'child_fail_closed_exit_code_must_be_1' in str(ex)
    else:
        raise AssertionError("Non-1 exit code must be rejected by production require")

    # Scenario 7: Pre-existing terminal exit with non-1 code MUST fail
    c_bad_term = SimpleNamespace(process=MockProc(poll_code=0, wait_code=0))
    env_bad_term = {'c_c': c_bad_term, 'useful': lambda c: None, 'require': m.require, 'child_denied_err': None}
    try:
        exec(compiled_child_if, env_bad_term)
    except (AssertionError, ValueError) as ex:
        assert 'child_already_terminal_must_exit_1' in str(ex)
    else:
        raise AssertionError("Non-1 terminal exit code must be rejected by production require")

    # 2. Real Daemon collector scheduling checks (Order A and Order B)
    binary = ROOT / 'target/debug/agentfw'
    g_spec = importlib.util.spec_from_file_location('g', ROOT / 'scripts/verify-sou89-native-liveness.py')
    g = importlib.util.module_from_spec(g_spec)
    g_spec.loader.exec_module(g)

    # Order A: Child already terminal after renewal failure (reproducing check_child_pipe)
    with tempfile.TemporaryDirectory(prefix='sou89-child-sched-a-') as tmp:
        d = g.DaemonFixture(binary, Path(tmp))
        d.start()
        p = None
        try:
            sid = 'child-order-a'
            p, _ = d.spawn_collector('child-a', session_id=sid, lease_secs=8)
            p.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2024-11-05', 'capabilities': {}, 'clientInfo': {'name': 'r11', 'version': '1'}}}) + '\n')
            p.stdin.flush()
            import select
            select.select([p.stdout], [], [], 5)
            p.stdout.readline()
            _, inst = m.http_get(d.instance_url, d.native_token)
            enrolled = next(r for r in reversed(m.read_raw_audit(d)) if r.get('event') == 'native_liveness_enrolled' and r.get('session_id') == sid)
            st, r = m.http_post(d.native_url, d.native_token, {'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': d.registry_sha256, 'session_id': sid, 'event': 'session_end'})
            assert st == 200
            assert p.wait(timeout=6) == 1

            # Exact production harness child handling logic
            child_denied_err = None
            if p.poll() is not None:
                c_c_exit = p.poll()
                assert c_c_exit == 1
                child_denied_err = 'child_already_terminal_from_renewal_uncertainty'
            else:
                raise AssertionError("Expected child to be terminal in Order A")
            close_res = {'forced_cleanup': False, 'process': {'all_stopped': True, 'remaining': []}, 'exit_code': c_c_exit, 'kernel': None}
            m.grade_client_close(close_res, 'cascade_child', expect_failure=True)
        finally:
            if p is not None:
                try: p.stdin.close()
                except OSError: pass
                if p.poll() is None: p.kill(); p.wait(timeout=5)
            d.stop()

    # Order B: Child still running when useful operation attempted, receiving refusal
    with tempfile.TemporaryDirectory(prefix='sou89-child-sched-b-') as tmp:
        d = g.DaemonFixture(binary, Path(tmp))
        d.start()
        p = None
        try:
            sid = 'child-order-b'
            p, _ = d.spawn_collector('child-b', session_id=sid, lease_secs=60)
            def rpc(proc, req):
                proc.stdin.write(json.dumps(req) + '\n')
                proc.stdin.flush()
                import select
                readable, _, _ = select.select([proc.stdout], [], [], 5)
                assert readable, "RPC timed out"
                line = proc.stdout.readline()
                return json.loads(line) if line else None
            init = rpc(p, {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2024-11-05', 'capabilities': {}, 'clientInfo': {'name': 'r11', 'version': '1'}}})
            assert 'result' in init
            p.stdin.write(json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + '\n')
            p.stdin.flush()
            rpc(p, {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})

            # Useful call before retirement succeeds
            call = {'jsonrpc': '2.0', 'id': 10, 'method': 'tools/call', 'params': {'name': 'read_document', 'arguments': {'name': 'testnote'}}}
            first = rpc(p, call)
            assert first['result']['content'][0]['text'] == 'SOU-89 verified effect: note read.'

            # Retire session
            _, inst = m.http_get(d.instance_url, d.native_token)
            enrolled = next(r for r in reversed(m.read_raw_audit(d)) if r.get('event') == 'native_liveness_enrolled' and r.get('session_id') == sid)
            m.http_post(d.native_url, d.native_token, {'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': d.registry_sha256, 'session_id': sid, 'event': 'session_end'})

            # Exact production harness child handling logic when still running
            child_denied_err = None
            if p.poll() is not None:
                raise AssertionError("Expected child to still be running in Order B")
            else:
                call['id'] = 11
                reply = rpc(p, call)
                assert reply is None, f"Expected None reply after retirement, got {reply}"
                c_c_exit = p.wait(timeout=5)
                assert c_c_exit == 1
                child_denied_err = 'collector_closed_before_correlated_response'
            close_res = {'forced_cleanup': False, 'process': {'all_stopped': True, 'remaining': []}, 'exit_code': c_c_exit, 'kernel': None}
            m.grade_client_close(close_res, 'cascade_child', expect_failure=True)
        finally:
            if p is not None:
                try: p.stdin.close()
                except OSError: pass
                if p.poll() is None: p.kill(); p.wait(timeout=5)
            d.stop()
    print("PASS: test_cascade_child_handling_both_scheduling_orders")


def test_restart_risk_affected_host_policy_witness_and_independent_context():
    binary = ROOT / 'target/debug/agentfw'
    with tempfile.TemporaryDirectory(prefix='sou89-test-risk-policy-') as tmp:
        r_home = Path(tmp).resolve()
        r_env = m.BASE.environment(r_home)
        reg_data = m.BASE.INSTALL.registry(json.loads((m.BASE.INSTALL.ASSETS / 'upstream-tools-list.json').read_text()))
        rp = r_home / 'registry.json'
        rp.write_text(json.dumps(reg_data, sort_keys=True))
        sha = m.sha(rp)
        port = m.BASE.DEMO.free_port()
        subprocess.run([str(binary), 'install'], env=r_env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
        m.setup_restart_daemon(r_home, port, rp, sha, policy_path=m.BASE.INSTALL.ASSETS / 'policy.yaml')

        p = subprocess.Popen([str(binary), 'serve'], env=r_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert m.BASE.DEMO.wait_healthy(port, p)
        tok = (r_home / '.agentfw/native-token').read_text().strip()
        hook_tok = (r_home / '.agentfw/token').read_text().strip()

        # 1. Post taint on host-restart-risk
        st, _ = m.http_post(f'http://127.0.0.1:{port}/hook', hook_tok, {
            'session_id': 'host-restart-risk', 'hook_event_name': 'PostToolUse', 'tool_name': 'WebFetch',
            'tool_input': {'url': 'https://untrusted.example.test/inventory'},
            'tool_response': 'SOU-89 untrusted text for provenance tracking'
        })
        assert st == 200

        # 2. Profile barrier
        st, _ = m.http_post(f'http://127.0.0.1:{port}/native/v1/profile-barrier', tok, {}, headers={'x-agentfw-host-session': 'host-restart-risk'})
        assert st == 200
        m.BASE.DEMO.stop(p)
        p.wait(timeout=5)

        # 3. Restart daemon (d2)
        p = subprocess.Popen([str(binary), 'serve'], env=r_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert m.BASE.DEMO.wait_healthy(port, p)
        d2_inst = m.verify_daemon_healthy_and_enforcing(port, tok, sha, 2)
        inst_id = d2_inst['instance_id']

        # 4. Unauthenticated SessionEnd on affected host marks incomplete
        st, _ = m.http_post(f'http://127.0.0.1:{port}/hook', hook_tok, {
            'session_id': 'host-restart-risk', 'hook_event_name': 'SessionEnd'
        })
        assert st == 200

        # Create canary .env file on disk
        (r_home / '.env').write_text('PORT=8000\nSECRET_KEY=sou89_test\n')

        # 5. Mint valid child authority for affected host on d2
        cmd_risk = [str(binary), 'child-authority', 'mint', '--session', 'host-restart-risk', '--server', 'sou86-recovery',
                    '--agent-id', 'agent-risk', '--tools', 'read_text_file,write_file', '--instance-id', inst_id, '--ttl-seconds', '120']
        proof_risk = subprocess.check_output(cmd_risk, env=r_env, text=True).strip()

        # Start authenticated native session bound to affected host
        st, start_risk = m.http_post(f'http://127.0.0.1:{port}/native/v1', tok, {
            'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': sha,
            'session_id': 'sess-bound-restart-risk', 'liveness': m.LIVENESS_CONTRACT, 'event': 'session_start',
            'host_session': 'host-restart-risk', 'server_id': 'sou86-recovery',
            'child_authority': proof_risk,
        })
        assert st == 200 and start_risk.get('release') is True

        # 6. Sensitive path call on affected host is held by restored sticky taint/incomplete floor
        st, call_risk_floor = m.http_post(f'http://127.0.0.1:{port}/native/v1', tok, {
            'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': sha,
            'session_id': 'sess-bound-restart-risk', 'event': 'call',
            'tool': 'read_text_file',
            'args': {'path': str(r_home / '.env')},
            'schema_sha256': next(t['schema_sha256'] for t in reg_data['tools'] if t['name'] == 'read_text_file'),
            'mcp_host_call_id': 'call-floor-1',
        })
        assert st == 200
        assert call_risk_floor.get('verdict') == 'ask' and call_risk_floor.get('release') is False
        assert 'taint-history-incomplete' in call_risk_floor.get('reason_codes', [])

        # 7. Side-effecting write_file on affected host is denied by policy
        st, call_risk_write = m.http_post(f'http://127.0.0.1:{port}/native/v1', tok, {
            'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': sha,
            'session_id': 'sess-bound-restart-risk', 'event': 'call',
            'tool': 'write_file',
            'args': {'path': str(r_home / 'test_write.txt'), 'content': 'denied_write'},
            'schema_sha256': next(t['schema_sha256'] for t in reg_data['tools'] if t['name'] == 'write_file'),
        })
        assert st == 200
        assert call_risk_write.get('verdict') == 'deny' and call_risk_write.get('release') is False
        assert 'filesystem-profile-deny-write' in call_risk_write.get('reason_codes', [])

        # 8. On hook, write_file presenting valid x-agentfw-child-authority is denied by policy
        st, hook_write_risk = m.http_post(f'http://127.0.0.1:{port}/hook', hook_tok, {
            'session_id': 'host-restart-risk', 'agent_id': 'agent-risk', 'hook_event_name': 'PreToolUse',
            'tool_name': 'write_file', 'tool_input': {'path': str(r_home / 'test_write.txt'), 'content': 'denied_write'},
        }, headers={'x-agentfw-child-authority': proof_risk})
        assert st == 200
        out_risk = hook_write_risk.get('hookSpecificOutput', {})
        assert out_risk.get('permissionDecision') == 'deny'
        assert 'filesystem-profile-deny-write' in out_risk.get('permissionDecisionReason', '')

        # 9. Independent authenticated host context:
        cmd_ind = [str(binary), 'child-authority', 'mint', '--session', 'host-independent-ctx', '--server', 'sou86-recovery',
                   '--agent-id', 'agent-ind', '--tools', 'read_text_file', '--instance-id', inst_id, '--ttl-seconds', '120']
        proof_ind = subprocess.check_output(cmd_ind, env=r_env, text=True).strip()

        st, start_ind = m.http_post(f'http://127.0.0.1:{port}/native/v1', tok, {
            'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': sha,
            'session_id': 'sess-bound-independent', 'liveness': m.LIVENESS_CONTRACT, 'event': 'session_start',
            'host_session': 'host-independent-ctx', 'server_id': 'sou86-recovery',
            'child_authority': proof_ind,
        })
        assert st == 200 and start_ind.get('release') is True

        # Calling the exact same sensitive path on independent host succeeds (no taint floor)
        st, call_ind_sens = m.http_post(f'http://127.0.0.1:{port}/native/v1', tok, {
            'contract_version': m.NATIVE_CONTRACT, 'registry_sha256': sha,
            'session_id': 'sess-bound-independent', 'event': 'call',
            'tool': 'read_text_file',
            'args': {'path': str(r_home / '.env')},
            'schema_sha256': next(t['schema_sha256'] for t in reg_data['tools'] if t['name'] == 'read_text_file'),
            'mcp_host_call_id': 'call-ind-1',
        })
        assert st == 200
        assert call_ind_sens.get('verdict') == 'allow' and call_ind_sens.get('release') is True
        assert call_ind_sens.get('reason_codes') == []

        m.BASE.DEMO.stop(p)
        p.wait(timeout=5)
    print("PASS: test_restart_risk_affected_host_policy_witness_and_independent_context")


def main():
    test_source_helper_arity()
    test_selected_client_env_injection()
    test_useful_stable_comparison_across_incremented_ids()
    test_ast_run_selected_acceptance()
    test_rig_native_token_path()
    test_temporary_directory_cleanup_lifetime()
    test_production_graders_positive_and_adversarial_mutations()
    test_finalizer_rig_cleanup_grading()
    test_source_observer_failure_retains_failed_report()
    test_production_restart_setup()
    test_collector_fail_closed_on_denied_work()
    test_collector_autonomous_exit_on_renewal_failure()
    test_cascade_audit_and_timing_extraction()
    test_cascade_child_handling_both_scheduling_orders()
    test_restart_risk_affected_host_policy_witness_and_independent_context()
    test_production_summary_projection()
    test_daemon_api_contracts()
    test_normal_eof_after_retirement()
    test_cli_guard_and_report_retention()
    print("\nALL SOU-89 SELECTED CONTRACT CHECKS, OBSERVER CONTROLS, AND DAEMON API CONTRACTS PASSED.")


if __name__ == '__main__':
    main()
