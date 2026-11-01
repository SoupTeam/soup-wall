import json
import re
import ast
import hashlib


def negative_calls(tree_oid):
    if not isinstance(tree_oid, str) or not re.fullmatch('[0-9a-f]{40}', tree_oid):
        raise ValueError('invalid_negative_tree_oid')
    return [
        ('missing_git_revision', 'git', 'git_show', {'repo_path': '/workspace', 'revision': 'f' * 40}),
        ('unsupported_git_path', 'git', 'git_show', {'repo_path': '/workspace', 'revision': 'HEAD:sou177-nonexistent-path'}),
        ('unsupported_git_expression', 'git', 'git_show', {'repo_path': '/workspace', 'revision': 'HEAD^{tree}'}),
        ('unsupported_git_tree', 'git', 'git_show', {'repo_path': '/workspace', 'revision': tree_oid}),
        ('missing_workspace_file', 'filesystem', 'read_text_file', {'path': '/workspace/sou177-nonexistent-path'}),
    ]


def persist(rows, output, case, writer):
    if case not in ('initial', 'operator-edit', 'cancel', 'daemon-loss', 'recovery'):
        raise ValueError('unsupported_outcome_case')
    if len(rows) > 256 or any(not isinstance(row, dict) or project(row) != row for row in rows):
        raise ValueError('invalid_outcome_inventory')
    files = []
    for offset in range(0, len(rows), 32):
        path = output / f'{case}-outcomes-{offset // 32}.json'
        part = rows[offset:offset + 32]
        writer(path, {'format': 'sw-mcp-call-outcomes/1', 'case': case,
                      'offset': offset, 'records': part})
        files.append({'path': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                      'offset': offset, 'records': len(part)})
    return {'records': len(rows), 'files': files}


def failure_boundaries(rows):
    failures = set()
    for value in rows:
        row = project(value)
        if row is None:
            continue
        stage = row['stage']
        if stage == 'original_response':
            if row['response']['rpc_error']:
                failures.add('original_protocol_error')
            if row['response']['tool_error'] is True:
                failures.add('original_tool_error')
        elif stage in ('call_admission', 'result_inspection') and row['released'] is False:
            failures.add(stage + '_refused')
        elif stage == 'profile_validation' and row['accepted'] is False:
            failures.add('profile_validation_refused')
        elif stage == 'host_delivery' and row['written'] is False:
            failures.add('host_delivery_failed')
    return sorted(failures)


def call_bindings(calls, servers, server, tool, arguments):
    raw = json.dumps(arguments, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    expected = hashlib.sha256(raw).hexdigest()
    return {(hashlib.sha256(json.dumps(call['id'], sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
             call['request_sha256'])
            for call in calls if call['tool'] == tool and call['args_sha256'] == expected
            and servers.get(call['pid']) == server}


def operation_indices(rows, calls, servers, server, tool, arguments):
    bindings = call_bindings(calls, servers, server, tool, arguments)
    return [index for index, row in enumerate(rows) if row.get('collector_server') == server
            and (row['host_call_sha256'], row['request_sha256']) in bindings]


def negative_results(results, indices):
    rows = []
    for index in indices:
        value = results.get(f'toolu_existing_{index}')
        refused = isinstance(value, dict) and value.get('is_error') is True
        error_class = None
        if refused:
            text = json.dumps(value, sort_keys=True)
            error_class = next((code for fragment, code in (
                ('MCP arguments violate the selected input profile', 'input_profile_refused'),
                ('Git local reference or file revision unavailable, unsupported, or its source changed', 'git_reference_refused'),
                ('MCP path refused before execution: it is outside', 'outside_path_refused'),
            ) if fragment in text), 'unclassified_tool_error')
        rows.append({'index': index, 'result_present': value is not None,
                     'passed': refused, 'client_error_class': error_class,
                     'result_sha256': hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
                     if value is not None else None})
    return rows


def project(row):
    if not isinstance(row, dict):
        return None
    if row.get('event') == 'mcp_original_result_delivery_timing':
        if set(row) != {'event', 'version', 'host_call_sha256', 'request_sha256',
                        'response_sha256', 'elapsed_us', 'written', 'authority'}:
            return None
        if type(row['elapsed_us']) is not int or not 0 <= row['elapsed_us'] <= 3600 * 1000000:
            return None
        row = {key: value for key, value in row.items() if key not in ('event', 'elapsed_us')}
        row.update(event='mcp_call_outcome', stage='host_delivery')
    fields = {'event', 'version', 'stage', 'request_sha256', 'host_call_sha256',
              'response_sha256', 'response', 'authority'}
    if 'collector_server' in row:
        fields.add('collector_server')
        if row['collector_server'] not in ('git', 'filesystem'):
            return None
    if row.get('stage') == 'host_delivery':
        fields.remove('response')
        fields.add('written')
        if type(row.get('written')) is not bool:
            return None
    elif row.get('stage') == 'profile_validation':
        fields.add('accepted')
        if type(row.get('accepted')) is not bool:
            return None
    elif row.get('stage') in ('result_inspection', 'call_admission'):
        fields.add('released')
        if type(row.get('released')) is not bool:
            return None
    elif row.get('stage') != 'original_response':
        return None
    if 'reason_codes_sha256' in row:
        fields.add('reason_codes_sha256')
        if not isinstance(row['reason_codes_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['reason_codes_sha256']):
            return None
    if set(row) != fields or row.get('event') != 'mcp_call_outcome' or type(row.get('version')) is not int:
        return None
    if row['version'] != 1 or row['authority'] is not False:
        return None
    for key in ('request_sha256', 'host_call_sha256', 'response_sha256'):
        if not isinstance(row[key], str) or not re.fullmatch('[0-9a-f]{64}', row[key]):
            return None
    if row['stage'] == 'host_delivery':
        return row
    if row['stage'] == 'call_admission' and row['response'] is None:
        return row
    response = row['response']
    if not isinstance(response, dict) or set(response) != {'rpc_error', 'tool_error', 'rpc_code'}:
        return None
    if type(response['rpc_error']) is not bool or (response['tool_error'] is not None and type(response['tool_error']) is not bool):
        return None
    code = response['rpc_code']
    if code is not None and (type(code) is not int or not -(2 ** 63) <= code < 2 ** 63):
        return None
    return row


def collect(trace, pids=None):
    rows = []
    buffers = {}
    discarded = set()
    for line in trace.splitlines():
        if not any(name in line for name in ('write(', 'writev(')) or len(line) > 2 * 1024 * 1024:
            continue
        prefix = re.match(r'^\s*(\d+)\s+(write|writev)\(2,', line)
        if not prefix or (pids is not None and int(prefix[1]) not in pids):
            continue
        result = re.search(r'\)\s*=\s*(\d+)\s*$', line)
        if result is None:
            continue
        quoted = re.findall(r'"(?:[^"\\]|\\.)*"', line)
        try:
            data = b''.join(ast.literal_eval('b' + part) for part in quoted)
        except (ValueError, SyntaxError):
            continue
        written = int(result[1])
        if written > len(data):
            continue
        key = int(prefix[1])
        if key in discarded:
            if b'\n' not in data[:written]:
                continue
            data = data[:written].split(b'\n', 1)[1]
            written = len(data)
            discarded.remove(key)
        text = buffers.get(key, b'') + data[:written]
        buffers[key] = b''
        while b'\n' in text:
            message, text = text.split(b'\n', 1)
            if len(message) > 4096:
                continue
            try:
                row = project(json.loads(message))
            except (ValueError, UnicodeError, RecursionError):
                continue
            if row is not None:
                row.pop('collector_server', None)
                if isinstance(pids, dict):
                    if pids[key] not in ('git', 'filesystem'):
                        continue
                    row['collector_server'] = pids[key]
                rows.append(row)
                if len(rows) >= 256:
                    return rows
        if len(text) <= 4096:
            buffers[key] = text
        else:
            discarded.add(key)
    return rows
