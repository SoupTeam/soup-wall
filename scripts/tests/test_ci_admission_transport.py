# SPDX-License-Identifier: Apache-2.0
"""Owned HTTP transport witnesses; never contact GitHub or publish real statuses."""
from contextlib import contextmanager, redirect_stdout
from copy import deepcopy
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import ci_admission as gate


class OwnedHTTP:
    """A real urllib/http.client body path with disposable loopback data."""
    def __init__(self, actions=None, route=None):
        self.actions, self.route = list(actions or []), route
        self.requests, self.posts, self.delays = [], [], []
        self.release = threading.Event()
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args): pass
            def do_GET(self): self.respond()
            def do_POST(self): self.respond()
            def respond(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                owner.requests.append((self.command, self.path))
                if self.command == 'POST': owner.posts.append(json.loads(body))
                action = owner.route(self.command, self.path, body) if owner.route else owner.actions.pop(0)
                kind, value = action if isinstance(action, tuple) else (action, {'jobs': [], 'total_count': 0})
                raw = value if isinstance(value, bytes) else json.dumps(value).encode()
                if isinstance(kind, int):
                    self.send_response(kind);self.send_header('Content-Length', '0');self.end_headers();return
                self.send_response(200)
                declared = 8 * 1024 * 1024 + 1 if kind == 'oversize' else len(raw)
                if kind == 'chunk-cut': self.send_header('Transfer-Encoding', 'chunked')
                elif kind != 'no-length': self.send_header('Content-Length', str(declared))
                if kind.startswith('link-'):
                    links = {'link-next': '<https://api.github.com/repos/fixture/repo/jobs?per_page=100&page=2>; rel="next"',
                             'link-foreign': '<https://private.invalid/secret?per_page=100&page=2>; rel="next"',
                             'link-wrong': '<https://api.github.com/repos/fixture/repo/jobs?per_page=100&page=9>; rel="next"'}
                    self.send_header('Link', links[kind])
                self.end_headers()
                try:
                    if kind == 'chunk-cut':
                        self.wfile.write((hex(len(raw))[2:] + '\r\n').encode() + raw[:len(raw) // 2])
                        self.wfile.flush();self.close_connection = True
                    elif kind in ('cut', 'reset'):
                        self.wfile.write(raw[:max(1, len(raw) // 2)]);self.wfile.flush()
                        if kind == 'reset':
                            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                                       struct.pack('HH' if sys.platform == 'win32' else 'ii', 1, 0))
                        self.close_connection = True
                    elif kind == 'timeout':
                        self.wfile.write(raw[:1]);self.wfile.flush();owner.release.wait(2)
                        self.close_connection = True
                    elif kind == 'drip':
                        for byte in raw:
                            self.wfile.write(bytes([byte]));self.wfile.flush()
                            if owner.release.wait(.02): break
                    elif kind != 'oversize': self.wfile.write(raw);self.close_connection = True
                except (BrokenPipeError, ConnectionResetError): pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()

    def open(self, request, timeout):
        # Preserve the production Request method/path/body, but never forward
        # its Authorization header, cookies or arbitrary URLs to the fixture.
        parsed = urlsplit(request.full_url)
        assert parsed.netloc == 'api.github.com' and parsed.path.startswith('/repos/fixture/repo/')
        path = parsed.path.removeprefix('/repos/fixture/repo')
        destination = 'http://127.0.0.1:' + str(self.server.server_port) + path
        if parsed.query: destination += '?' + parsed.query
        return urlopen(Request(destination, data=request.data, method=request.method), timeout=timeout)

    @contextmanager
    def client(self, module=gate, *, real_backoff=False):
        original_sleep = time.sleep
        def delay(seconds):
            self.delays.append(seconds)
            if real_backoff: original_sleep(seconds)
        # Keep real network/body reads; only fast unit-test backoff is virtual.
        with patch.object(module, 'urlopen', side_effect=self.open), patch.object(module.time, 'sleep', side_effect=delay):
            yield module.GitHub('fixture/repo', 'public-fixture-no-authority')

    def close(self):
        self.release.set();self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)


class FixtureTestCase(unittest.TestCase):
    def fixture(self, *actions, route=None):
        server = OwnedHTTP(actions, route);self.addCleanup(server.close);return server


class Transport(FixtureTestCase):
    def test_real_broken_body_recovers_only_from_a_new_complete_response(self):
        complete = {'total_count': 1, 'jobs': [{'id': 7}]}
        fixture = self.fixture(('cut', complete), ('ok', complete))
        with fixture.client() as api:
            self.assertEqual(api.get('/actions/runs/1/attempts/1/jobs'), complete)
            self.assertEqual(api.http_get_attempts, 2)
        self.assertEqual(fixture.delays, [2])

    def test_persistent_broken_body_has_three_attempts_and_no_partial_fallback(self):
        fixture = self.fixture(*[('cut', {'jobs': [], 'total_count': 0})] * 3)
        with fixture.client() as api:
            with self.assertRaisesRegex(gate.EvidenceAPIError, 'body_incomplete'):
                api.get('/actions/runs/1/attempts/1/jobs')
            self.assertEqual(api.http_get_attempts, 3)
        self.assertEqual(fixture.delays, [2, 4])

    def test_timeout_reset_and_transient_http_recover_on_complete_new_response(self):
        for kind in ('timeout', 'reset', 'chunk-cut', 429, 500, 502, 503, 504):
            with self.subTest(kind=kind):
                fixture = self.fixture((kind, {'ok': True}), ('ok', {'ok': True}))
                with fixture.client() as api, patch.object(gate, 'HTTP_TIMEOUT', .08):
                    self.assertEqual(api.get('/evidence'), {'ok': True})
                    self.assertEqual(api.http_get_attempts, 2)
                self.assertEqual(fixture.delays, [2])

    def test_body_timeout_reset_and_chunk_disconnect_exhaust_finitely(self):
        for kind in ('timeout', 'reset', 'chunk-cut'):
            fixture = self.fixture(*[(kind, {'ok': True})] * 3)
            with fixture.client() as api, patch.object(gate, 'HTTP_TIMEOUT', .04):
                with self.assertRaises(gate.EvidenceAPIError): api.get('/evidence')
                self.assertEqual(api.http_get_attempts, 3)
            self.assertEqual(fixture.delays, [2, 4])

    def test_unknown_length_body_is_byte_bounded_and_short_link_pages_refuse(self):
        fixture = self.fixture(('no-length', b'{"value":"' + b'x' * 100 + b'"}'))
        with fixture.client() as api, patch.object(gate, 'MAX_RESPONSE_BYTES', 64):
            with self.assertRaisesRegex(ValueError, 'response_too_large'): api.get('/evidence')
            self.assertEqual(api.http_get_attempts, 1)
        for kind in ('link-next', 'link-foreign', 'link-wrong'):
            fixture = self.fixture((kind, {'total_count': 1, 'jobs': [{'id': 1}]}))
            with fixture.client() as api:
                with self.assertRaises((ValueError, gate.EvidenceAPIError)):
                    api.pages('/actions/runs/9/attempts/2/jobs', 'jobs')

    def test_page_limit_is_not_a_truncated_success(self):
        actions = [('ok', {'total_count': 3000, 'jobs': [{'id': i} for i in range(n * 100 + 1, (n + 1) * 100 + 1)]})
                   for n in range(30)]
        fixture = self.fixture(*actions)
        with fixture.client() as api:
            with self.assertRaisesRegex(gate.EvidenceAPIError, 'pagination_limit_exceeded'):
                api.pages('/actions/runs/9/attempts/2/jobs', 'jobs')
            self.assertEqual(api.http_get_attempts, 30)

    def test_authorization_and_invalid_complete_json_are_never_retried(self):
        for kind, raw, error in [(401, b'', gate.EvidenceAPIError), (403, b'', gate.EvidenceAPIError),
                                  ('ok', b'broken-private-fixture', ValueError),
                                  ('ok', b'\xff', ValueError), ('ok', b'', ValueError),
                                  ('ok', b'[' * 65 + b'0' + b']' * 65, ValueError),
                                  ('oversize', b'', ValueError)]:
            with self.subTest(kind=kind, raw=raw[:10]):
                fixture = self.fixture((kind, raw))
                with fixture.client() as api:
                    with self.assertRaises(error): api.get('/evidence')
                    self.assertEqual(api.http_get_attempts, 1)
                self.assertEqual(fixture.delays, [])

    def test_non_utf8_escape_sequence_cannot_hide_deep_json_from_the_bound(self):
        # Scanning UTF-16 bytes as ASCII can misinterpret the escaped quote,
        # hide the nested value, bypass the bound or overflow older decoders.
        raw = ('["escaped\\\"value",' + '[' * 1100 + '0' + ']' * 1100 + ']').encode('utf-16-le')
        fixture = self.fixture(('ok', raw))
        with fixture.client() as api:
            with self.assertRaises(ValueError): api.get('/evidence')
            self.assertEqual(api.http_get_attempts, 1)

    def test_socket_drip_cannot_reset_the_body_deadline_or_total_budget(self):
        fixture = self.fixture(*[('drip', {'value': 'x' * 100})] * 3)
        started = time.monotonic()
        with fixture.client() as api, patch.object(gate, 'HTTP_TIMEOUT', .08), \
                patch.object(gate, 'HTTP_BUDGET', .18):
            with self.assertRaises(gate.EvidenceAPIError): api.get('/evidence')
            self.assertLessEqual(api.http_get_attempts, 3)
        self.assertLess(time.monotonic() - started, .8)

    def test_uncertain_post_is_not_retried_or_treated_as_evidence(self):
        for kind in ('cut', 'reset', 'timeout', 503, 'ok'):
            raw = b'invalid-private-response' if kind == 'ok' else {'id': 3}
            fixture = self.fixture((kind, raw))
            with fixture.client() as api, patch.object(gate, 'HTTP_TIMEOUT', .08):
                with self.assertRaises(gate.EvidenceAPIError) as caught:
                    api.post('/statuses/' + 'a' * 40, {'state': 'pending'})
                self.assertEqual(caught.exception.method, 'POST')
                self.assertEqual(api.http_post_attempts, 1)
            self.assertEqual(fixture.delays, [])
            self.assertEqual(len(fixture.posts), 1)

    def test_complete_attempt_pagination_retries_only_the_failed_page(self):
        rows = [{'id': i} for i in range(1, 202)]
        fixture = self.fixture(('ok', {'total_count': 201, 'jobs': rows[:100]}),
                               ('cut', {'total_count': 201, 'jobs': rows[100:200]}),
                               ('ok', {'total_count': 201, 'jobs': rows[100:200]}),
                               ('ok', {'total_count': 201, 'jobs': rows[200:]}))
        with fixture.client() as api:
            self.assertEqual(api.pages('/actions/runs/9/attempts/2/jobs', 'jobs'), rows)
            self.assertEqual(api.http_get_attempts, 4)
        self.assertEqual([parse_qs(urlsplit(p).query)['page'] for _, p in fixture.requests],
                         [['1'], ['2'], ['2'], ['3']])
        self.assertTrue(all('/runs/9/attempts/2/jobs?' in p for _, p in fixture.requests))

    def test_short_inconsistent_duplicate_and_missing_metadata_pages_refuse(self):
        first = {'total_count': 101, 'jobs': [{'id': i} for i in range(1, 101)]}
        for responses, error in [([('ok', {'total_count': 2, 'jobs': [{'id': 1}]})], gate.EvidenceAPIError),
                                 ([('ok', first), ('ok', {'total_count': 102, 'jobs': [{'id': 101}]})], gate.EvidenceAPIError),
                                 ([('ok', first), ('ok', {'total_count': 101, 'jobs': [{'id': 1}]})], ValueError),
                                 ([('ok', {'jobs': []})], ValueError),
                                 ([('ok', {'total_count': True, 'jobs': []})], ValueError),
                                 ([('ok', {'total_count': 3001, 'jobs': []})], gate.EvidenceAPIError),
                                 ([('ok', {'total_count': 1, 'jobs': [{'id': True}]})], ValueError),
                                 ([('ok', {'total_count': 1, 'jobs': ['not-a-job']})], ValueError)]:
            fixture = self.fixture(*responses)
            with fixture.client() as api:
                with self.assertRaises(error): api.pages('/actions/runs/9/attempts/2/jobs', 'jobs')


class CandidateTransport(FixtureTestCase):
    """Real client + HTTP body faults composed with the existing gate fixture."""
    def exercise(self, *, fault='cut', persistent=False, mutate=None, fail_final=False, write_fault=False):
        import test_ci_central_admission as baseline
        metadata = baseline.API();faults = [0];pr_reads = [0]
        def route(method, path, body):
            url = urlsplit(path);query = parse_qs(url.query)
            if method == 'POST':
                broken = write_fault is True or write_fault == 'final' and json.loads(body)['state'] == 'success'
                return ('cut' if broken else 'ok', {'id': 17})
            if url.path == '/pulls/1':
                pr_reads[0] += 1
                if fail_final and pr_reads[0] >= 5: return 'cut', metadata.pr
            if '/attempts/' in url.path and url.path.endswith('/jobs') and '/runs/1/' in url.path:
                if persistent or faults[0] == 0:
                    faults[0] += 1
                    if mutate is not None: mutate(metadata)
                    return fault, {'total_count': len(metadata.jobs[1]), 'jobs': metadata.jobs[1]}
            if 'page' in query:
                suffix = url.path
                if url.path == '/actions/runs':
                    suffix += '?event=' + query['event'][0]
                key = 'jobs' if '/attempts/' in url.path else 'workflow_runs' if url.path == '/actions/runs' else ''
                rows = deepcopy(metadata.pages(suffix, key))
                page = int(query['page'][0]);values = rows[(page - 1) * 100:page * 100]
                return 'ok', {key: values, 'total_count': len(rows)} if key else values
            return 'ok', deepcopy(metadata.get(url.path))
        fixture = self.fixture(route=route);output = io.StringIO()
        args = argparse.Namespace(pr=1, wait_seconds=0, dry_run=False)
        with fixture.client() as api, patch.object(gate, 'plan', return_value=baseline.SELECTION), \
                patch.dict(gate.os.environ, {'SOU91_SELECTIVE_CI': '', 'SOU160_ADMISSION_REUSE': ''}), \
                redirect_stdout(output):
            code = gate.admit(api, args, deepcopy(metadata.pr))
        return fixture, code, output.getvalue()

    def test_outage_recovery_preserves_all_five_codeql_and_matrix_checks(self):
        fixture, code, output = self.exercise()
        self.assertEqual(code, 0)
        self.assertEqual([p['state'] for p in fixture.posts], ['pending', 'success'])
        self.assertIn('all five CodeQL', fixture.posts[-1]['description'])
        self.assertNotIn('Traceback', output)

    def test_persistent_body_outage_is_explained_pending_without_success(self):
        fixture, code, output = self.exercise(persistent=True)
        self.assertEqual(code, 0)
        self.assertEqual([p['state'] for p in fixture.posts], ['pending', 'pending'])
        self.assertIn('body_incomplete', fixture.posts[-1]['description'])
        self.assertNotIn('Traceback', output)

    def test_recovered_transport_does_not_recover_authority_for_invalid_candidates(self):
        mutations = [lambda a: a.pr['head'].update(sha='d' * 40),
                     lambda a: a.pr['base'].update(sha='d' * 40),
                     lambda a: a.pr.update(draft=True),
                     lambda a: a.runs[0].update(run_attempt=2),
                     lambda a: a.jobs[1][-1].update(conclusion='failure'),
                     lambda a: a.jobs[1][-1].update(conclusion='skipped'),
                     lambda a: a.jobs[2].pop(),
                     lambda a: a.jobs[1].pop()]
        for mutate in mutations:
            fixture, _, _ = self.exercise(mutate=mutate)
            self.assertNotIn('success', [p['state'] for p in fixture.posts])

    def test_lost_final_freshness_read_downgrades_known_target_without_traceback(self):
        fixture, code, output = self.exercise(fail_final=True)
        self.assertEqual(code, 0)
        self.assertEqual([p['state'] for p in fixture.posts], ['pending', 'pending'])
        self.assertIn('body_incomplete', fixture.posts[-1]['description'])
        self.assertNotIn('Traceback', output)

    def test_main_initial_read_failure_has_finite_diagnostic_and_no_unsafe_target(self):
        fixture = self.fixture(*[('cut', {'private': 'private-upstream-marker'})] * 3)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'event.json'
            path.write_text(json.dumps({'pull_request': {'number': 1, 'base': {'sha': 'a' * 40,
                'repo': {'full_name': 'fixture/repo'}}, 'head': {'sha': 'b' * 40}}}))
            output = io.StringIO()
            with fixture.client() as api, patch.object(gate, 'GitHub', return_value=api), \
                    patch.object(sys, 'argv', ['ci_admission.py']), \
                    patch.dict(gate.os.environ, {'GITHUB_REPOSITORY': 'fixture/repo', 'GITHUB_TOKEN': 'public-only',
                                                'GITHUB_EVENT_PATH': str(path)}), redirect_stdout(output):
                self.assertEqual(gate.main(), 1)
            text = output.getvalue()
            self.assertIn('body_incomplete', text);self.assertIn('GET=3 POST=0', text)
            for excluded in ('private-upstream-marker', 'public-only', 'http://', 'Traceback'):
                self.assertNotIn(excluded, text)
            self.assertEqual(fixture.posts, [])

    def test_uncertain_initial_status_write_has_no_compensating_post(self):
        fixture, code, output = self.exercise(write_fault=True)
        self.assertEqual(code, 1)
        self.assertEqual(len(fixture.posts), 1)
        self.assertIn('status write unconfirmed', output)
        self.assertNotIn('Traceback', output)

    def test_uncertain_final_status_write_is_not_retried_or_claimed_confirmed(self):
        fixture, code, output = self.exercise(write_fault='final')
        self.assertEqual(code, 1)
        self.assertEqual([p['state'] for p in fixture.posts], ['pending', 'success'])
        self.assertIn('status write unconfirmed', output)
        self.assertEqual(sum(method == 'POST' for method, _ in fixture.requests), 2)


if __name__ == '__main__': unittest.main()
