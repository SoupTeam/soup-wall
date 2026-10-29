import json
import re


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


def collect(trace):
    rows = []
    for line in trace.splitlines():
        if not any(name in line for name in ('write(', 'writev(')) or len(line) > 2 * 1024 * 1024:
            continue
        for quoted in re.findall(r'"(?:[^"\\]|\\.)*"', line):
            try:
                text = json.loads(quoted)
            except ValueError:
                continue
            for message in text.splitlines():
                if len(message) > 4096:
                    continue
                try:
                    row = project(json.loads(message))
                except ValueError:
                    continue
                if row is not None:
                    rows.append(row)
                    if len(rows) >= 256:
                        return rows
    return rows
