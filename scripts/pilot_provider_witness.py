# SPDX-License-Identifier: Apache-2.0
"""Independent successful-exec environment observations; synthetic inputs only.

Raw strace stays private and is never a support/export artifact. Public evidence
contains counts and booleans, never argv, environment arrays or canary values.
"""
import ast
import re
from pathlib import Path

from pilot_provider import KEYS


def require(value, reason):
    if not value:
        raise ValueError(reason)


def inputs(url, root):
    certificate = root / 'owned-provider-ca-canary.pem'
    certificate.write_text('Owned unused HTTP-only certificate canary.\n')
    certificate.chmod(0o600)
    return dict(zip(KEYS, ('sou143-owned-api-91d2', 'sou143-owned-auth-a4b7', url,
        'http://sou143-http-canary@127.0.0.1:9', 'http://sou143-https-canary@127.0.0.1:9',
        '127.0.0.1,localhost,::1,sou143-owned-no-proxy.invalid', str(certificate))))


def observe(text, paths, values, normalize):
    require(set(values) == set(KEYS) and len(set(values.values())) == len(KEYS),
            'provider_distinct_canaries_required')
    rows, pending = normalize(text)
    require(not any(value.lstrip().startswith('execve(') for value in pending.values()),
            'provider_incomplete_exec_observation')
    counts = {role: 0 for role in ('entry', 'host', 'daemon', 'launcher', 'collector',
                                  'diagnostic', 'original', 'classifier', 'other')}
    for row in rows:
        match = re.match(r'^\d+\s+execve\((.*)\)\s+=\s+0\s*$', row)
        if not match:
            continue
        try:
            executable, arguments, environment = ast.literal_eval('(' + match[1] + ')')
        except (ValueError, SyntaxError):
            raise ValueError('provider_exec_environment_unproven') from None
        require(isinstance(executable, str) and isinstance(arguments, list)
                and isinstance(environment, list) and all(isinstance(item, str) for item in arguments + environment),
                'provider_exec_environment_unproven')
        role = 'other'
        if executable == str(paths['claude']):
            role = 'host'
        elif any(word.endswith('/scripts/pilot-run.py') for word in arguments):
            role = 'entry'
        elif executable == str(paths['agentfw']) and len(arguments) > 1:
            role = {'serve': 'daemon', 'pilot-launch': 'launcher', 'mcp': 'collector',
                    'protection-status': 'diagnostic', 'pilot-approval': 'diagnostic'}.get(arguments[1], 'other')
        elif executable in ('/mcp-runtime/node', '/mcp-runtime/python', '/mcp-runtime/git'):
            role = 'original'
        elif any('rule_baseline.py' in word for word in arguments):
            role = 'classifier'
        counts[role] += 1
        env = dict(item.split('=', 1) for item in environment if '=' in item)
        # Command lines never need a provider credential, even for the host.
        require(not any(value in word for value in values.values() for word in arguments),
                'provider_value_in_argv')
        if role in ('entry', 'host'):
            require(all(env.get(key) == value for key, value in values.items()),
                    'provider_intended_host_input_missing')
        else:
            require(not any(value in word for value in values.values() for word in environment),
                    'provider_value_in_unrelated_process')
    require(all(counts[role] > 0 for role in ('entry', 'host', 'daemon', 'launcher', 'collector', 'diagnostic', 'original')),
            'provider_required_role_not_observed')
    return {'format': 'sw-provider-routing-witness/1', 'successful_exec_counts': counts,
            'all_seven_inputs_in_intended_host': True, 'unrelated_provider_values': 0,
            'provider_values_in_argv': 0, 'raw_environment_exported': False}


class ProtocolEvidence:
    """Owned loopback server independently counts the host's authenticated requests."""
    def __init__(self, model, values, reject=False):
        import threading
        self.lock = threading.Lock()
        self.requests = self.authenticated = 0
        evidence = self
        original = model.server.RequestHandlerClass

        class Observed(original):
            def do_POST(self):
                matched = (self.headers.get('x-api-key') == values['ANTHROPIC_API_KEY']
                    or self.headers.get('Authorization') == 'Bearer ' + values['ANTHROPIC_AUTH_TOKEN'])
                with evidence.lock:
                    evidence.requests += 1
                    evidence.authenticated += int(matched)
                if reject:
                    import json
                    # Deliberately echo only owned synthetic canaries to exercise
                    # the error/log path; never enable this on a real provider.
                    raw = json.dumps({'type': 'error', 'error': {'type': 'authentication_error',
                        'message': 'Owned rejection ' + values['ANTHROPIC_API_KEY']
                            + ' ' + values['ANTHROPIC_AUTH_TOKEN']}}).encode()
                    self.send_response(401)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                return original.do_POST(self)

        model.server.RequestHandlerClass = Observed

    def finish(self):
        with self.lock:
            require(self.requests > 0 and self.authenticated > 0, 'provider_authenticated_request_not_observed')
            return {'owned_loopback_requests': self.requests,
                    'expected_synthetic_authentication_seen': True, 'credential_values_exported': False}
