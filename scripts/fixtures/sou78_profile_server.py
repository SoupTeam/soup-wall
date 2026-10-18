#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned stdio fixture; the append-only child ledger independently sees execution."""
import json
import os
from pathlib import Path
import sys

manifest, ledger, environment = map(Path, sys.argv[1:])
with environment.open('a') as out:
    # Values (including the delegated token) are never recorded.
    out.write(json.dumps({'keys': sorted(os.environ)}) + '\n')
for line in sys.stdin:
    request = json.loads(line)
    method = request.get('method')
    if method == 'initialize':
        result = {'protocolVersion': '2024-11-05', 'capabilities': {'tools': {}},
                  'serverInfo': {'name': 'sou78-owned', 'version': '1'}}
    elif method == 'tools/list':
        result = {'tools': json.loads(manifest.read_text())}
    elif method == 'tools/call':
        with ledger.open('a') as out:
            out.write(json.dumps(request) + '\n')
        tool = request['params']['name']
        # The create-file executor must never dispatch to this child.
        result = {'content': [{'type': 'text', 'text':
            'Inventory: 7 red widgets.' if tool.startswith('read_') else 'FORBIDDEN CHILD EXECUTION'}]}
    else:
        continue
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}), flush=True)
