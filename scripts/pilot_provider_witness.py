# SPDX-License-Identifier: Apache-2.0
"""Independent successful-exec environment observations; synthetic inputs only.

Raw strace stays private and is never a support/export artifact. Public evidence
contains counts and booleans, never argv, environment arrays or canary values.
"""
import ast
import json
import os
import re
import stat
import sys
from pathlib import Path

from pilot_provider import KEYS


def require(value, reason):
    if not value:
        raise ValueError(reason)


def private_patterns(values):
    """Independent forbidden-byte inventory, including both JSON encodings."""
    require(set(values) == set(KEYS), 'provider_all_inputs_required')
    return {encoded for value in values.values() if value for encoded in (
        value.encode(), json.dumps(value, ensure_ascii=True)[1:-1].encode(),
        json.dumps(value, ensure_ascii=False)[1:-1].encode())}


def private_log_writes(text, run_directory, supervisor_pid, values, normalize, rejection=False):
    """Inspect the entry's actual log writes before ordinary cleanup deletes them.

    Exact successful openat results bind each descriptor to its owned log. Close
    observations end that binding, so reused descriptor numbers convey no scope.
    Raw syscall strings and log bytes are never returned as evidence.
    """
    rows, pending = normalize(text)
    names = {str(run_directory / (role + '.private.log')): role for role in ('host', 'daemon')}
    handles, opened = {}, set()
    contents = {role: bytearray() for role in ('host', 'daemon')}
    writes = 0
    quoted = r'("(?:[^"\\]|\\.)*")'
    result = r'(-1 [A-Z][A-Z0-9_]*(?: \([^\n)]*\))?|\d+)'
    for row in rows:
        prefix = re.match(r'^(\d+)\s+(openat|close|write|writev)\(', row)
        if not prefix or int(prefix[1]) != supervisor_pid:
            continue
        opening = re.match(r'^\d+\s+openat\(AT_FDCWD,\s*' + quoted
                           + r',\s*([^\n]*)\)\s*=\s*(\d+)\s*$', row)
        if opening:
            path = ast.literal_eval(opening[1])
            descriptor = int(opening[3])
            handles.pop(descriptor, None)
            if path in names:
                role = names[path]
                require(role not in opened and 'O_WRONLY' in opening[2]
                        and 'O_EXCL' in opening[2], 'provider_private_log_identity_unproven')
                opened.add(role)
                handles[descriptor] = role
            continue
        closing = re.match(r'^\d+\s+close\((\d+)\)\s*=\s*0\s*$', row)
        if closing:
            handles.pop(int(closing[1]), None)
            continue
        writing = re.match(r'^\d+\s+(write|writev)\((\d+),', row)
        if not writing or int(writing[2]) not in handles:
            continue
        role = handles[int(writing[2])]
        single = re.match(r'^\d+\s+write\(\d+,\s*' + quoted
                          + r',\s*(\d+)\)\s*=\s*' + result + r'\s*$', row)
        if single:
            raw, count = ast.literal_eval('b' + single[1]), int(single[2])
            written = 0 if single[3].startswith('-1 ') else int(single[3])
        else:
            vector = re.match(r'^\d+\s+writev\(\d+,\s*\[(.*)\],\s*\d+\)\s*=\s*'
                              + result + r'\s*$', row)
            require(vector is not None, 'provider_private_log_write_unproven')
            pieces = re.findall(r'iov_base=' + quoted + r', iov_len=(\d+)', vector[1])
            require(pieces and vector[1].count('iov_base=') == len(pieces),
                    'provider_private_log_write_unproven')
            decoded = [(ast.literal_eval('b' + piece), int(size)) for piece, size in pieces]
            require(all(len(piece) == size for piece, size in decoded),
                    'provider_private_log_write_unproven')
            raw = b''.join(piece for piece, _ in decoded)
            count = len(raw)
            written = 0 if vector[2].startswith('-1 ') else int(vector[2])
        require(len(raw) == count and 0 <= written <= count, 'provider_private_log_write_unproven')
        contents[role].extend(raw[:written])
        writes += int(written > 0)
        require(sum(map(len, contents.values())) <= 4 * 1024 * 1024, 'provider_private_log_bound')
    require(opened == {'host', 'daemon'} and contents['host'], 'provider_private_logs_not_observed')
    require(not any(int(pid) == supervisor_pid and re.match(r'(?:write|writev|openat|close)\(', call)
                    for pid, call in pending.items()), 'provider_private_log_write_unproven')
    patterns = private_patterns(values)
    require(not any(pattern in content for pattern in patterns for content in contents.values()),
            'provider_canary_in_private_log')
    if rejection:
        # The owned rejection must actually reach the log. This control fails if
        # runtime redaction is removed; checking the entry's outer JSON cannot.
        require(b'Owned rejection ' in contents['host'] and b'[REDACTED]' in contents['host'],
                'provider_rejection_redaction_not_observed')
    return {'observer': 'owned supervisor openat/close/write/writev syscalls',
            'successful_private_log_writes': writes,
            'private_log_bytes': sum(map(len, contents.values())),
            'all_selected_values_and_json_forms_absent': True,
            'owned_rejection_redaction_observed': rejection, 'raw_log_exported': False}


def retained_artifacts(root, values):
    """Bounded no-follow scan of all retained case files, including stop state.

    Only the exact owned raw observer trace and the deliberately supplied CA
    canary are inputs. Every other retained file and symlink payload is checked.
    """
    excluded = {root / 'trace.private', root / 'owned-provider-ca-canary.pem'}
    patterns = private_patterns(values)
    stack, count, total, special = [root], 0, 0, 0
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if path in excluded:
                    continue
                count += 1
                require(count <= 4096, 'provider_retained_artifact_bound')
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    stack.append(path)
                    continue
                if stat.S_ISLNK(info.st_mode):
                    raw = os.fsencode(os.readlink(path))
                elif stat.S_ISREG(info.st_mode):
                    require(info.st_size <= 4 * 1024 * 1024, 'provider_retained_artifact_bound')
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    try:
                        before = os.fstat(descriptor)
                        require((before.st_dev, before.st_ino) == (info.st_dev, info.st_ino),
                                'provider_retained_artifact_changed')
                        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                            raw = stream.read(4 * 1024 * 1024 + 1)
                        after = os.fstat(descriptor)
                        require(len(raw) == before.st_size and (before.st_size, before.st_mtime_ns)
                                == (after.st_size, after.st_mtime_ns), 'provider_retained_artifact_changed')
                    finally:
                        os.close(descriptor)
                else:
                    # Dead runtime sockets/FIFOs retain no file bytes. Never open
                    # them or follow them outside the owned case tree.
                    special += 1
                    continue
                total += len(raw)
                require(total <= 16 * 1024 * 1024, 'provider_retained_artifact_bound')
                require(not any(pattern in raw for pattern in patterns), 'provider_canary_in_retained_artifact')
    return {'retained_entries_checked': count, 'retained_bytes_checked': total,
            'non_file_entries': special, 'intentional_observer_and_input_exclusions': 2,
            'all_selected_values_and_json_forms_absent': True, 'artifact_contents_exported': False}


def inputs(url, root):
    certificate = root / 'owned-provider-ca-canary.pem'
    certificate.write_text('Owned unused HTTP-only certificate canary.\n')
    certificate.chmod(0o600)
    return dict(zip(KEYS, ('sou143-owned-api-91d2', 'sou143-owned-auth-a4b7', url,
        'http://sou143-http-canary@127.0.0.1:9', 'http://sou143-https-canary@127.0.0.1:9',
        '127.0.0.1,localhost,::1,sou143-owned-no-proxy.invalid', str(certificate))))


def failure_stage(text, paths, normalize):
    """Finite denied-exec categories and known refusal codes, never argv/env."""
    require(len(text) <= 64 * 1024 * 1024, 'provider_failure_trace_bound')
    counts = {}
    for row in normalize(text)[0]:
        match = re.match(r'^\d+\s+execve\("([^"\n]+)".*\)\s*=\s*-1\s+(EACCES|EPERM|ENOENT)', row)
        if not match:
            continue
        path, error = match.groups()
        role = 'host' if path == str(paths['claude']) else 'agent' if path == str(paths['agentfw']) else \
            'classifier-interpreter' if path == str(paths['python']) else \
            'original-runtime' if path.startswith('/mcp-runtime/') or path.startswith('/mcp-server/') else \
            'selected-fd' if path.startswith('/proc/self/fd/') else 'system-git' if path in ('/usr/bin/git', '/bin/git') \
            else 'other-helper'
        key = role + ':' + error
        counts[key] = counts.get(key, 0) + 1
    bootstrap = {key:0 for key in ('host_execs','host_metadata','ready_writes','input_reads','code_closed')}
    clients = {}
    for row in normalize(text)[0]:
        m=re.match(r'^(\d+)\s+execve\((.*)\)\s*=\s*0$',row)
        if m:
            try: executable,args,environment=ast.literal_eval('('+m[2]+')')
            except (ValueError,SyntaxError): continue
            if executable==str(paths['claude']) and '--restricted' in args and '-p' in args:
                bootstrap['host_execs']+=1
                env=dict(item.split('=',1) for item in environment if '=' in item)
                channel,code=env.get('AGENTFW_PROVIDER_CHANNEL',''),env.get('AGENTFW_PROVIDER_CODE','')
                if channel.isdecimal() and code.isdecimal():
                    clients[int(m[1])]=(int(channel),int(code));bootstrap['host_metadata']+=1
        m=re.match(r'^(\d+)\s+(write|read|close)\((0x[0-9a-f]+|\d+),?',row)
        if m and int(m[1]) in clients:
            channel,code=clients[int(m[1])];fd=int(m[3],0)
            if m[2]=='write' and fd==channel and 'sw-provider-ready/1' in row:bootstrap['ready_writes']+=1
            if m[2]=='read' and fd==channel:bootstrap['input_reads']+=1
            if m[2]=='close' and fd==code and re.search(r'= 0$',row):bootstrap['code_closed']+=1
    known = ('mcp_owner_startup_failed', 'mcp_owner_spawn_failed', 'mcp_owner_image_unavailable',
             'mcp_budget_membership_unverified', 'classifier_execution_failed', 'classifier_unavailable',
             'provider_host_exec_boundary_unavailable', 'provider_bootstrap_unavailable', 'Permission denied', 'Operation not permitted')
    return {'bootstrap_counts':bootstrap, 'denied_exec_counts': counts, 'known_refusals': [value for value in known if value in text],
            'bootstrap_failure_stages': [stage for stage in ('hooks', 'descriptors', 'ready', 'delivery', 'values')
                if 'sw-provider-bootstrap-failed/' + stage in text]}


def observe(text, paths, values, normalize, rejected=False):
    require(set(values) == set(KEYS) and len(set(values.values())) == len(KEYS),
            'provider_distinct_canaries_required')
    rows, pending = normalize(text)
    require(not any(value.lstrip().startswith('execve(') for value in pending.values()),
            'provider_incomplete_exec_observation')
    counts = {role: 0 for role in ('entry', 'host', 'daemon', 'launcher', 'collector',
                                  'diagnostic', 'original', 'classifier', 'other')}
    hosts, launchers = {}, set()
    for row in rows:
        match = re.match(r'^(\d+)\s+execve\((.*)\)\s+=\s+0\s*$', row)
        if not match:
            continue
        try:
            executable, arguments, environment = ast.literal_eval('(' + match[2] + ')')
        except (ValueError, SyntaxError):
            raise ValueError('provider_exec_environment_unproven') from None
        require(isinstance(executable, str) and isinstance(arguments, list)
                and isinstance(environment, list) and all(isinstance(item, str) for item in arguments + environment),
                'provider_exec_environment_unproven')
        role = 'other'
        if executable == str(paths['claude']) and '--restricted' in arguments and '-p' in arguments:
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
        if role == 'launcher':
            launchers.add(int(match[1]))
        env = dict(item.split('=', 1) for item in environment if '=' in item)
        # Command lines never need a provider credential, even for the host.
        require(not any(value in word for value in values.values() for word in arguments),
                'provider_value_in_argv')
        if role == 'entry':
            require(all(env.get(key) == value for key, value in values.items()),
                    'provider_intended_host_input_missing')
        else:
            if role == 'host':
                channel = env.get('AGENTFW_PROVIDER_CHANNEL', '')
                code = env.get('AGENTFW_PROVIDER_CODE', '')
                require(channel.isdecimal() and code.isdecimal() and int(channel) >= 3
                        and int(code) >= 3 and channel != code
                        and '--preload=data:text/javascript;base64,' in env.get('BUN_OPTIONS', '')
                        and int(match[1]) not in hosts, 'provider_host_channel_unproven')
                hosts[int(match[1])] = int(channel)
            leaked = {word.split('=', 1)[0] for word in environment
                      if any(value in word for value in values.values())}
            if leaked:
                print(json.dumps({'event': 'provider_routing_refusal', 'role': role,
                    'selected_keys': sorted(leaked.intersection(KEYS)),
                    'other_key_count': len(leaked.difference(KEYS))}), file=sys.stderr, flush=True)
            require(not any(value in word for value in values.values() for word in environment),
                    'provider_value_in_unrelated_process')
    pairs, sent, reads, closed = [], [], [], set()
    for row in rows:
        pair = re.match(r'^(\d+)\s+socketpair\(AF_UNIX, SOCK_DGRAM\|SOCK_CLOEXEC, 0, \[(\d+), (\d+)\]\)\s*=\s*0\s*$', row)
        if pair and int(pair[1]) in launchers:
            pairs.append(tuple(map(int, pair.groups())))
        sending = re.match(r'^(\d+)\s+sendto\((\d+),\s*("(?:[^"\\]|\\.)*"),\s*(\d+),\s*(?:0|MSG_NOSIGNAL),\s*NULL,\s*0\)\s*=\s*(\d+)\s*$', row)
        if sending and int(sending[1]) in launchers:
            try:
                raw = ast.literal_eval('b' + sending[3])
                payload = json.loads(raw)
            except (ValueError, SyntaxError, UnicodeError):
                continue
            if payload == values and len(raw) == int(sending[4]) == int(sending[5]):
                sent.append((int(sending[1]), int(sending[2]), len(raw)))
        # Raw read mode retains exact kernel counts without exporting unrelated
        # file contents or expanding source/module reads into huge private logs.
        reading = re.match(r'^(\d+)\s+read\((0x[0-9a-f]+|\d+),\s*0x[0-9a-f]+,\s*(?:0x[0-9a-f]+|\d+)\)\s*=\s*(0x[0-9a-f]+|\d+)\s*$', row)
        if reading and int(reading[1]) not in closed and hosts.get(int(reading[1])) == int(reading[2], 0):
            reads.append((int(reading[1]), int(reading[3], 0)))
        closing = re.match(r'^(\d+)\s+close\((\d+)\)\s*=\s*0\s*$', row)
        if closing and hosts.get(int(closing[1])) == int(closing[2]) and any(pid == int(closing[1]) for pid, _ in reads):
            closed.add(int(closing[1]))
    require(hosts and set(hosts) == closed, 'provider_host_delivery_unproven')
    for pid, channel in hosts.items():
        bound = [(launcher, parent) for launcher, parent, child in pairs if child == channel]
        require(len(bound) == 1, 'provider_host_socket_binding_unproven')
        launcher, parent = bound[0]
        packets = [size for sender, descriptor, size in sent if (sender, descriptor) == (launcher, parent)]
        received = [size for reader, size in reads if reader == pid]
        require(len(packets) == 1 and received == packets, 'provider_host_delivery_unproven')
    # A first-request 401 can terminate Claude before it starts MCP discovery.
    # Still check every actual unrelated exec, and require the complete original
    # graph in every non-rejection run. No missing role is fabricated as seen.
    required = ('entry', 'host', 'daemon', 'launcher', 'diagnostic') if rejected else \
        ('entry', 'host', 'daemon', 'launcher', 'collector', 'diagnostic', 'original')
    require(all(counts[role] > 0 for role in required),
            'provider_required_role_not_observed')
    return {'format': 'sw-provider-routing-witness/1', 'successful_exec_counts': counts,
            'all_seven_inputs_in_intended_host': True, 'authenticated_host_ipc_observed': True,
            'host_initial_exec_provider_values': 0, 'unrelated_provider_values': 0,
            'provider_values_in_argv': 0, 'raw_environment_exported': False,
            'observation_stage': 'first-request-authentication-refusal' if rejected else 'original-server-runtime'}


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
