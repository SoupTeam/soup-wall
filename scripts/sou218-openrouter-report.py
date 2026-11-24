#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline receipt/source/response audit. Never opens a network connection."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('openrouter_adapter', Path(__file__).with_name('sou218-openrouter.py'))
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


def audit_session(directory):
    armed = adapter.strict_json((directory / 'armed.json').read_bytes())
    routes = [r for r in adapter.ROUTES.values() if r[:2] == (armed['model'], armed['provider'])]
    if not routes:
        raise ValueError('unknown_route')
    adapter.MODEL, adapter.PROVIDER, adapter.PROVIDER_NAME = routes[0]
    first_request = adapter.strict_json((directory / 'request.json').read_bytes())
    adapter.REASONING_BUDGET = first_request.get('reasoning', {}).get('max_tokens', 0)
    scope = adapter.strict_json((directory / 'bundle.json').read_bytes())
    rows = []
    for job in sorted(directory.glob('job-*.json')):
        b = adapter.strict_json(job.read_bytes())
        request = json.dumps(adapter.request_body(b), ensure_ascii=False).encode()
        source_hash = adapter.digest(b['source'].encode())
        row = {'job': job.stem, 'case_id': b['case_id'], 'source_sha256': source_hash,
               'request_sha256': adapter.digest(request), 'semantic_acceptance': False,
               'native_protection_checked': False}
        if source_hash not in scope['allowed_sources'] or b['request']['contents'][0]['parts'][0]['text'] != b['source']:
            raise ValueError('source_scope_mismatch')
        marker = job.with_suffix('.started')
        if not marker.exists():
            row['state'] = 'queued'
        else:
            try:
                started = adapter.strict_json(marker.read_bytes())
            except ValueError:
                row['state'] = 'refused_before_api'
                rows.append(row)
                continue
            if started['request_sha256'] != row['request_sha256']:
                raise ValueError('request_binding_mismatch')
            receipt = job.with_suffix('.receipt')
            row['state'] = 'started_without_receipt'
            if receipt.exists():
                r = adapter.strict_json(receipt.read_bytes())
                if r['request_sha256'] != row['request_sha256']:
                    raise ValueError('receipt_binding_mismatch')
                row['receipt'] = r
                row['state'] = r['state']
            response = job.with_suffix('.response')
            if response.exists():
                raw = response.read_bytes()
                row['response_sha256'] = adapter.digest(raw)
                try:
                    row['offline_validation'] = adapter.inspect_response(raw, b)
                except (ValueError, KeyError, TypeError) as e:
                    row['offline_validation'] = {'state': 'invalid_response', 'reason': str(e)}
                value = adapter.strict_json(raw)
                row['usage'] = value.get('usage')
        rows.append(row)
    return {'model': armed['model'], 'provider': armed['provider'], 'rows': rows,
            'semantic_acceptance': False, 'native_protection_checked': False,
            'note': 'Structural diagnostics only. Manual factual review and independent acceptance remain required.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--session', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    report = audit_session(a.session)
    adapter.save(a.output, json.dumps(report, ensure_ascii=False, indent=2).encode())
    print('Offline report saved; rows:', len(report['rows']), '; no provider calls.')


if __name__ == '__main__':
    main()
