#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify retained public capture consistency; does not rerun the original server."""
import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'crates/agent/tests/fixtures/result_detector/sou113-original'
MANIFEST_SHA = '75e27713be0871c697913965fe3361e4abfe4bf24628172f47cd70490bc4dcf5'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(directory=FIXTURE):
    manifest_bytes = (directory / 'manifest.json').read_bytes()
    assert sha(manifest_bytes) == MANIFEST_SHA, 'original manifest changed'
    manifest = json.loads(manifest_bytes)
    checked = set()
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        expected, name = line.split('  ', 1)
        path = PurePosixPath(name.removeprefix('./'))
        assert not path.is_absolute() and '..' not in path.parts and str(path) not in checked
        assert sha((directory / str(path)).read_bytes()) == expected, str(path)
        checked.add(str(path))
    assert len(checked) == 18
    identity = manifest['identity']
    for kind in ('profile', 'registry', 'policy'):
        suffix = '.yaml' if kind == 'policy' else '.json'
        assert sha((directory / (kind + suffix)).read_bytes()) == identity[kind + '_sha256']
    assert identity['shipped_policy_sha256'] == sha((ROOT / 'profiles/mcp/filesystem-readonly-v1/policy.yaml').read_bytes())
    rows = []
    for n in (2, 3, 4):
        key = str(n)
        server_raw = (directory / f'server-response-{n}files.jsonl').read_bytes()
        host_raw = (directory / f'host-response-{n}files.jsonl').read_bytes()
        request = json.loads((directory / f'request-{n}files.json').read_bytes())
        server, host = json.loads(server_raw), json.loads(host_raw)
        assert server['id'] == host['id'] == request['id'] == 3000 + n
        assert request == manifest['requests'][key]
        assert request['params']['arguments']['paths'] == [f'/workspace/multi{i:02}.txt' for i in range(n)]
        text = server['result']['content'][0]['text']
        assert text == server['result']['structuredContent']['content']
        for i in range(n):
            raw = (directory / f'workspace/multi{i:02}.txt').read_bytes()
            assert len(raw) == 2048 and sha(raw) == manifest['files'][f'multi{i:02}.txt']['sha256']
            assert f'/workspace/multi{i:02}.txt:\n' + raw.decode() in text
        summary = manifest['summary'][key]
        assert sha(server_raw) == summary['server_sha256'] == manifest['server'][key]['raw_sha256']
        assert len(server_raw) == summary['server_bytes'] == manifest['server'][key]['bytes']
        assert sha(host_raw) == summary['host_sha256'] == manifest['host'][key]['raw_sha256']
        calls = manifest['host'][key]['native_call']
        results = manifest['host'][key]['native_result']
        assert len(calls) == len(results) == 1
        call, result = calls[0], results[0]
        assert call['call_id'] == result['call_id'] and call['binding_sha256'] == result['binding_sha256']
        assert call['session'] == result['session'] and call['seq'] < result['seq']
        assert call['verdict'] == 'allow' and call['released'] is True
        assert result['content_sha256'] == sha(server_raw) == summary['daemon_inspected_content_sha256']
        assert result['registry_sha256'] == identity['registry_sha256']
        assert result['shadow'] is False and result['truncated'] is False
        assert result['verdict'] == summary['verdict'] == ('allow' if n < 4 else 'deny')
        assert result['released'] is summary['released'] is (n < 4)
        if n < 4:
            assert host_raw == server_raw
        else:
            assert host['result']['isError'] is True
            assert host['result']['content'][0]['text'] == 'Soup Wall withheld MCP result (filesystem-profile-refuse-result-injection)'
            assert result['reason_codes'] == ['filesystem-profile-refuse-result-injection']
            assert b'SOU_LARGE_OWNED_PAYLOAD' not in host_raw
        rows.append({'files': n, 'frame_bytes': len(server_raw), 'text_bytes': len(text.encode()),
                     'sha256': sha(server_raw), 'captured_verdict': result['verdict']})
    return {'manifest_sha256': MANIFEST_SHA, 'files_verified': len(checked), 'cases': rows,
            'independent_server_rerun': False, 'scope': 'capture consistency and hashes, not execution requalification'}


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2))
