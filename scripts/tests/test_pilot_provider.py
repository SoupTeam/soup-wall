# SPDX-License-Identifier: Apache-2.0
"""Synthetic provider routing, sealed carrier and stream-boundary controls."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("provider_boundary", ROOT / "scripts/pilot_provider.py")
PROVIDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVIDER)


class ProviderBoundary(unittest.TestCase):
    def test_finite_selection_and_missing_access_do_not_fall_back(self):
        self.assertEqual(PROVIDER.selected({"LD_PRELOAD": "owned-loader", "AGENTFW_TOKEN": "native",
            "ANTHROPIC_API_KEY": "provider-key"}), {"ANTHROPIC_API_KEY": "provider-key"})
        for values in ({}, {"ANTHROPIC_API_KEY": ""}, {"HTTP_PROXY": "owned-proxy"}):
            with self.assertRaisesRegex(ValueError, "provider_unavailable"):
                PROVIDER.require_access(values)
        PROVIDER.require_access({"ANTHROPIC_AUTH_TOKEN": "owned-token"})
        for value in ('x\0y', 'x' * 16385):
            with self.assertRaisesRegex(ValueError, "provider_input_invalid"):
                PROVIDER.selected({"ANTHROPIC_API_KEY": value})

    def test_logs_redact_every_split_and_truncated_secret_prefix(self):
        values = {"ANTHROPIC_API_KEY": "owned-key-123456", "ANTHROPIC_AUTH_TOKEN": "owned-token-654321"}
        raw = b'begin owned-key-123456 / owned-token-654321 end\n'
        for split in range(len(raw) + 1):
            redactor = PROVIDER.Redactor(values)
            output = redactor.feed(raw[:split]) + redactor.feed(raw[split:]) + redactor.feed(b'', final=True)
            self.assertEqual(output, b'begin [REDACTED] / [REDACTED] end\n')
        redactor = PROVIDER.Redactor(values)
        self.assertEqual(redactor.feed(b'error owned-key-12') + redactor.feed(b'', final=True),
                         b'error [REDACTED]')

    def test_short_values_and_json_escapes_never_expand_the_output_cap(self):
        import json
        values = {"ANTHROPIC_API_KEY": 'owned-"key"-with-newline\n', "NO_PROXY": "x"}
        raw = (json.dumps(values["ANTHROPIC_API_KEY"])[1:-1] + ' xxx').encode()
        redactor = PROVIDER.Redactor(values)
        result = redactor.feed(raw) + redactor.feed(b'', final=True)
        self.assertLessEqual(len(result), len(raw))
        self.assertNotIn(b'owned-', result)
        self.assertNotIn(b'x', result)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux anonymous sealed carrier required')
    def test_carrier_is_sealed_unnamed_and_inherited_only_when_explicit(self):
        import fcntl
        with PROVIDER.carrier({"ANTHROPIC_API_KEY": "owned-value"}) as descriptor:
            self.assertEqual(os.fstat(descriptor).st_nlink, 0)
            with self.assertRaises(OSError):
                os.write(descriptor, b'changed')
            self.assertNotEqual(fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC, 0)
            code = 'import os,sys; print(os.read(int(sys.argv[1]),16385).decode())'
            clean = {"PATH": "/usr/bin:/bin"}
            result = subprocess.run([sys.executable, '-I', '-c', code, str(descriptor)],
                env=clean, pass_fds=(descriptor,), capture_output=True, check=True)
            self.assertIn(b'owned-value', result.stdout)
            result = subprocess.run([sys.executable, '-I', '-c', code, str(descriptor)],
                env=clean, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
        with self.assertRaises(OSError):
            os.fstat(descriptor)


class IndependentExecEvidence(unittest.TestCase):
    def test_failure_stage_never_exports_executables_arguments_or_environments(self):
        import json
        sys.path.insert(0, str(ROOT / 'scripts'))
        import pilot_provider_witness as witness
        paths = {'claude': Path('/private/client'), 'agentfw': Path('/private/agent'), 'python': Path('/private/python')}
        text = '42 execve("/proc/self/fd/22", ["private-marker"], ["SECRET=private-marker"]) = -1 EACCES (Permission denied)'
        value = witness.failure_stage(text, paths, lambda text: (text.splitlines(), {}))
        self.assertEqual(value['denied_exec_counts'], {'selected-fd:EACCES': 1})
        for private in ('42', '22', '/proc/', 'private-marker', 'SECRET'):
            self.assertNotIn(private, json.dumps(value))

    def test_private_log_observation_detects_removed_redaction_and_descriptor_reuse(self):
        import json
        sys.path.insert(0, str(ROOT / 'scripts'))
        import pilot_provider_witness as witness
        values = {key: 'distinct-owned-' + str(index) for index, key in enumerate(PROVIDER.KEYS)}
        values['ANTHROPIC_API_KEY'] = 'owned-"key"-with-newline\n'
        directory = Path('/owned/run')
        opening = lambda name, fd: ('31 openat(AT_FDCWD, ' + json.dumps(str(directory / name))
            + ', O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = ' + str(fd))
        writing = lambda raw: ('31 write(8, ' + json.dumps(raw.decode()) + ', '
            + str(len(raw)) + ') = ' + str(len(raw)))
        safe = b'Owned rejection [REDACTED] [REDACTED]\n'
        rows = [opening('daemon.private.log', 7), opening('host.private.log', 8), writing(safe),
                '31 close(8) = 0', opening('unrelated.trace', 8), writing(values['ANTHROPIC_API_KEY'].encode())]
        normalize = lambda text: (text.splitlines(), {})
        result = witness.private_log_writes('\n'.join(rows), directory, 31, values, normalize, rejection=True)
        self.assertTrue(result['owned_rejection_redaction_observed'])
        self.assertEqual(result['private_log_bytes'], len(safe))
        # Removing runtime redaction changes precisely these kernel-observed bytes.
        for value in values.values():
            for raw in (value.encode(), json.dumps(value)[1:-1].encode()):
                leaked = rows[:]
                leaked[2] = writing(b'Owned rejection ' + raw + b'\n')
                with self.assertRaisesRegex(ValueError, 'provider_canary_in_private_log'):
                    witness.private_log_writes('\n'.join(leaked), directory, 31, values, normalize, rejection=True)
        absent = rows[:]
        absent[2] = writing(b'generic failure\n')
        with self.assertRaisesRegex(ValueError, 'provider_rejection_redaction_not_observed'):
            witness.private_log_writes('\n'.join(absent), directory, 31, values, normalize, rejection=True)
        truncated = rows[:]
        truncated[2] = '31 write(8, "truncated"..., 100) = 100'
        with self.assertRaisesRegex(ValueError, 'provider_private_log_write_unproven'):
            witness.private_log_writes('\n'.join(truncated), directory, 31, values, normalize)

    def test_private_log_vectors_and_incomplete_observations_fail_closed(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        import pilot_provider_witness as witness
        values = {key: 'distinct-owned-' + str(index) for index, key in enumerate(PROVIDER.KEYS)}
        rows = ['31 openat(AT_FDCWD, "/owned/run/daemon.private.log", O_WRONLY|O_CREAT|O_EXCL, 0600) = 7',
                '31 openat(AT_FDCWD, "/owned/run/host.private.log", O_WRONLY|O_CREAT|O_EXCL, 0600) = 8',
                '31 writev(8, [{iov_base="Owned rejection ", iov_len=16}, '
                '{iov_base="[REDACTED]", iov_len=10}], 2) = 26']
        normalize = lambda text: (text.splitlines(), {})
        self.assertTrue(witness.private_log_writes('\n'.join(rows), Path('/owned/run'), 31,
            values, normalize, rejection=True)['all_selected_values_and_json_forms_absent'])
        with self.assertRaisesRegex(ValueError, 'provider_private_log_write_unproven'):
            witness.private_log_writes('\n'.join(rows), Path('/owned/run'), 31, values,
                lambda text: (text.splitlines(), {'31': 'write(8, unfinished'}))

    def test_retained_scan_checks_nested_stop_audit_and_escaped_values_with_finite_bounds(self):
        import json
        sys.path.insert(0, str(ROOT / 'scripts'))
        import pilot_provider_witness as witness
        values = {key: 'distinct-owned-' + str(index) for index, key in enumerate(PROVIDER.KEYS)}
        values['ANTHROPIC_API_KEY'] = 'owned-"key"-with-newline\n'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'trace.private').write_text(json.dumps(values))
            (root / 'owned-provider-ca-canary.pem').write_text(json.dumps(values))
            nested = root / 'state' / '.agentfw' / 'pilot-runs' / 'owned'
            nested.mkdir(parents=True)
            retained = nested / 'stop.json'
            retained.write_text('{"status":"stopped"}')
            self.assertTrue(witness.retained_artifacts(root, values)['all_selected_values_and_json_forms_absent'])
            for value in values.values():
                for raw in (value.encode(), json.dumps(value)[1:-1].encode()):
                    retained.write_bytes(raw)
                    with self.assertRaisesRegex(ValueError, 'provider_canary_in_retained_artifact'):
                        witness.retained_artifacts(root, values)
            retained.write_bytes(b'clean')
            with retained.open('r+b') as stream:
                stream.truncate(4 * 1024 * 1024 + 1)
            with self.assertRaisesRegex(ValueError, 'provider_retained_artifact_bound'):
                witness.retained_artifacts(root, values)

    def test_real_owned_protocol_observation_never_exports_credentials(self):
        import http.server
        import json
        import threading
        import urllib.request
        from types import SimpleNamespace
        sys.path.insert(0, str(ROOT / 'scripts'))
        import pilot_provider_witness as witness
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{}')
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        values = {key: 'distinct-owned-' + str(index) for index, key in enumerate(PROVIDER.KEYS)}
        evidence = witness.ProtocolEvidence(SimpleNamespace(server=server), values)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            request = urllib.request.Request('http://127.0.0.1:' + str(server.server_port) + '/v1/messages',
                data=b'{}', headers={'x-api-key': values['ANTHROPIC_API_KEY']})
            with opener.open(request, timeout=2) as response:
                self.assertEqual(response.status, 200)
            result = evidence.finish()
            self.assertTrue(result['expected_synthetic_authentication_seen'])
            self.assertFalse(any(value in json.dumps(result) for value in values.values()))
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_kernel_exec_arrays_require_all_roles_and_reject_leaks_and_partial_evidence(self):
        import json
        sys.path.insert(0, str(ROOT / 'scripts'))
        import pilot_provider_witness as witness
        paths = {'claude': Path('/owned/claude'), 'agentfw': Path('/owned/agentfw'),
                 'entry_python':Path('/usr/bin/python3'), 'entry_script':Path('/owned/scripts/pilot-run.py')}
        values = {key: 'distinct-owned-' + str(index) for index, key in enumerate(PROVIDER.KEYS)}
        rows = []
        roles = [('/usr/bin/python3', ['python3', '/owned/scripts/pilot-run.py'], values),
                 ('/owned/claude', ['claude', '--restricted', '-p', 'owned prompt'], values)]
        roles += [('/owned/agentfw', ['agentfw', role], {})
                  for role in ('serve', 'pilot-launch', 'mcp', 'protection-status')]
        roles += [('/mcp-runtime/node', ['node', 'server.js'], {}),
                  ('/owned/python', ['python', 'rule_baseline.py'], {})]
        for index, (path, args, env) in enumerate(roles):
            rows.append(f'{index+10} execve({json.dumps(path)}, {json.dumps(args)}, '
                        + json.dumps([key+'='+value for key,value in env.items()]) + ') = 0')
        normalize = lambda text: (text.splitlines(), {})
        result = witness.observe('\n'.join(rows), paths, values, normalize)
        self.assertEqual(result['unrelated_provider_values'], 0)
        self.assertEqual(result['successful_exec_counts']['classifier'], 1)
        self.assertFalse(any(value in json.dumps(result) for value in values.values()))
        argv_data = '26 execve("/owned/agentfw", ["agentfw", "protection-status", "/owned/scripts/pilot-run.py"], []) = 0'
        self.assertEqual(witness.observe('\n'.join(rows+[argv_data]),paths,values,normalize)['successful_exec_counts']['entry'],1)
        # Clone ancestry remains a finite role label; no PID or argv is emitted.
        import io,contextlib
        emitted=io.StringIO()
        borrowed='25 execve("/owned/claude", ["claude", "--version"], '+json.dumps(['ANTHROPIC_API_KEY='+values['ANTHROPIC_API_KEY']])+') = 0'
        with contextlib.redirect_stderr(emitted), self.assertRaisesRegex(ValueError,'provider_value_in_unrelated_process'):
            witness.observe('\n'.join(rows+['10 clone(child_stack=NULL, flags=SIGCHLD) = 25',borrowed]),paths,values,normalize)
        notice=json.loads(emitted.getvalue())
        self.assertEqual(notice['parent_role'],'entry')
        self.assertNotIn('25',emitted.getvalue())
        helper = f'25 execve("/owned/claude", ["claude", "--helper"], []) = 0'
        self.assertEqual(witness.observe('\n'.join(rows + [helper]), paths, values, normalize)['successful_exec_counts']['other'], 1)
        with self.assertRaisesRegex(ValueError, 'provider_value_in_unrelated_process'):
            witness.observe('\n'.join(rows + [helper.replace('[],', '[],').replace('[]) = 0', json.dumps(['ANTHROPIC_API_KEY='+values['ANTHROPIC_API_KEY']])+') = 0')]), paths, values, normalize)
        leaked = rows[:]
        leaked[2] = leaked[2].replace('[]) = 0', json.dumps(['ANTHROPIC_API_KEY='+values['ANTHROPIC_API_KEY']])+') = 0')
        with self.assertRaisesRegex(ValueError, 'provider_value_in_unrelated_process'):
            witness.observe('\n'.join(leaked), paths, values, normalize)
        with self.assertRaisesRegex(ValueError, 'provider_required_role_not_observed'):
            witness.observe('\n'.join(rows[:2]), paths, values, normalize)
        early = rows[:4] + rows[5:6]
        refusal = witness.observe('\n'.join(early), paths, values, normalize, rejected=True)
        self.assertEqual(refusal['successful_exec_counts']['original'], 0)
        self.assertEqual(refusal['observation_stage'], 'first-request-authentication-refusal')
        with self.assertRaisesRegex(ValueError, 'provider_required_role_not_observed'):
            witness.observe('\n'.join(early), paths, values, normalize)
        with self.assertRaisesRegex(ValueError, 'provider_required_role_not_observed'):
            witness.observe('\n'.join(rows[:2]), paths, values, normalize, rejected=True)
        with self.assertRaisesRegex(ValueError, 'provider_incomplete_exec_observation'):
            witness.observe('', paths, values, lambda text: ([], {'12': 'execve(unfinished'}))
