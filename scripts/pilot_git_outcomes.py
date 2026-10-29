import json
import re
import ast


def project(row):
    if not isinstance(row, dict):
        return None
    fields = {'event', 'version', 'stage', 'request_sha256', 'host_call_sha256',
              'response_sha256', 'response', 'authority'}
    if row.get('stage') == 'result_inspection':
        fields.add('released')
        if type(row.get('released')) is not bool:
            return None
    elif row.get('stage') != 'original_response':
        return None
    if set(row) != fields or row.get('event') != 'mcp_call_outcome' or type(row.get('version')) is not int:
        return None
    if row['version'] != 1 or row['authority'] is not False:
        return None
    for key in ('request_sha256', 'host_call_sha256', 'response_sha256'):
        if not isinstance(row[key], str) or not re.fullmatch('[0-9a-f]{64}', row[key]):
            return None
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
            except (ValueError, UnicodeError):
                continue
            if row is not None:
                rows.append(row)
                if len(rows) >= 256:
                    return rows
        if len(text) <= 4096:
            buffers[key] = text
        else:
            discarded.add(key)
    return rows
