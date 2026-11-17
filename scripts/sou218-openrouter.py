#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded OpenRouter research smoke/session. No production authorization."""
import argparse
import ctypes
import getpass
import hashlib
import json
import os
from pathlib import Path
import resource
import time
import urllib.request
import urllib.error
import warnings
import signal
from contextlib import contextmanager

MODEL = 'inclusionai/ling-3.2-flash:free'
PROVIDER = 'antdigital/fp8'
PROVIDER_NAME = 'Ant Digital'
REASONING_BUDGET = 0
ROUTES = {
    'ling': ('inclusionai/ling-3.2-flash:free', 'antdigital/fp8', 'Ant Digital'),
    'nemotron': ('nvidia/nemotron-3.5-super-vl:free', 'nvidia', 'Nvidia'),
    'nemotron-reasoning': ('nvidia/nemotron-3.5-super-vl:free', 'nvidia', 'Nvidia'),
}
BASE = 'https://openrouter.ai/api/v1'
LIMIT = 262144


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate_json_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('redirect_refused')


@contextmanager
def total_deadline(seconds):
    # Socket inactivity timeouts can be extended indefinitely by heartbeat bytes.
    # SIGALRM bounds the entire synchronous request, headers and body included.
    def expired(signum, frame):
        raise TimeoutError('total_request_deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def fetch(path, body=None, key=None):
    headers = {'Content-Type': 'application/json'}
    if key:
        headers['Authorization'] = 'Bearer ' + key
    request = urllib.request.Request(BASE + path, data=body, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with total_deadline(90 if body is not None else 30):
        with opener.open(request, timeout=30) as response:
            raw = response.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError('response_limit')
            return raw


def check_catalog(value):
    data = value['data']
    if data['id'] != MODEL:
        raise ValueError('model_drift')
    endpoints = [e for e in data['endpoints'] if e['tag'] == PROVIDER]
    if len(endpoints) != 1:
        raise ValueError('provider_missing')
    e = endpoints[0]
    if any(float(e['pricing'][k]) != 0 for k in ('prompt', 'completion')):
        raise ValueError('not_free')
    if not ({'structured_outputs', 'response_format'} | ({'reasoning'} if PROVIDER == 'nvidia' else set())) <= set(e['supported_parameters']):
        raise ValueError('schema_unsupported')


def request_body(bundle):
    old = bundle['request']
    return {
        'model': MODEL, 'stream': False, 'max_tokens': 4096,
        'temperature': 1,
        **({'reasoning': ({'max_tokens': REASONING_BUDGET, 'exclude': True} if REASONING_BUDGET else {'enabled': False})} if PROVIDER == 'nvidia' else {}),
        'provider': {'only': [PROVIDER], 'allow_fallbacks': False,
                     'require_parameters': True, 'max_price': {'prompt': 0, 'completion': 0}},
        'messages': [
            {'role': 'system', 'content': old['systemInstruction']['parts'][0]['text']},
            {'role': 'user', 'content': '\n\n'.join(p['text'] for p in old['contents'][0]['parts'])}],
        'response_format': {'type': 'json_schema', 'json_schema': {
            'name': 'untrusted_source_summary', 'strict': True,
            'schema': old['generationConfig']['responseJsonSchema']}},
    }


def inspect_response(raw, bundle):
    response = strict_json(raw)
    if response.get('model') != MODEL or response.get('provider') != PROVIDER_NAME:
        raise ValueError('model_or_provider_identity')
    choices = response['choices']
    if len(choices) != 1 or choices[0]['finish_reason'] != 'stop':
        raise ValueError('incomplete')
    message = choices[0]['message']
    if message.get('tool_calls') or message.get('refusal'):
        raise ValueError('nontext_response')
    answer = strict_json(message['content'])
    if set(answer) != {'summary', 'quotes'}:
        raise ValueError('schema')
    if not isinstance(answer['summary'], str) or not 1 <= len(answer['summary'].encode()) <= 2048:
        raise ValueError('summary')
    quotes = answer['quotes']
    if not isinstance(quotes, list) or not 1 <= len(quotes) <= 4:
        raise ValueError('quotes')
    if any(not isinstance(q, str) or not 1 <= len(q.encode()) <= 256 for q in quotes):
        raise ValueError('quote_shape')
    if len(set(quotes)) != len(quotes):
        raise ValueError('duplicate_quotes')
    allowed = bundle['request']['generationConfig']['responseJsonSchema'].get('properties', {}).get('quotes', {}).get('items', {}).get('enum')
    if allowed is not None and any(q not in allowed for q in quotes):
        raise ValueError('quote_not_in_catalog')
    source = bundle['source']
    occurrences = sum(sum(source.startswith(q, i) for i in range(len(source))) for q in quotes)
    if any(q not in source for q in quotes) or occurrences > 8:
        raise ValueError('quote_source_or_occurrences')
    import re
    references = [int(n) for n in re.findall(r'\bQ(\d+)\b', answer['summary'])]
    if any(n < 1 or n > len(quotes) for n in references):
        raise ValueError('citation_reference')
    return {'state': 'structurally_valid_untrusted', 'semantic_acceptance': False,
            'native_protection_checked': False, 'policy_allow': False,
            'quote_occurrences': occurrences}


def serve(directory, bundle_path, start_smoke=False):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
        raise ValueError('cannot_disable_dump')
    raw_bundle = bundle_path.read_bytes()
    bundle = json.loads(raw_bundle)
    allowed_sources = set(bundle['allowed_sources'])
    if digest(bundle['source'].encode()) not in allowed_sources:
        raise ValueError('unapproved_source')
    body = json.dumps(request_body(bundle), ensure_ascii=False).encode()
    catalog = fetch('/models/' + MODEL + '/endpoints')
    check_catalog(json.loads(catalog))
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    save(directory / 'catalog.json', catalog)
    save(directory / 'bundle.json', raw_bundle)
    save(directory / 'request.json', body)
    print('Free-only session: at most 20 requests, 120 minutes; each job is explicitly submitted. Confirm remaining quota >=20.')
    if input('Type OPENROUTER20 USD0: ').strip() != 'OPENROUTER20 USD0':
        raise ValueError('confirmation')
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        key = getpass.getpass('OpenRouter API key (hidden): ')
    key = key.strip()
    if not key.startswith('sk-or-') or not key.isascii() or any(c.isspace() for c in key):
        raise ValueError('key_shape')
    save(directory / 'armed.json', json.dumps({'expires': time.time()+7200, 'budget': 20, 'model': MODEL, 'provider': PROVIDER}).encode())
    if start_smoke:
        save(directory / 'job-smoke.json', raw_bundle)
    print('Key held in memory. ' + ('Starting the explicitly requested smoke.' if start_smoke else 'Waiting for explicit submit;') + ' Do not close this terminal.', flush=True)
    deadline = time.monotonic() + 7200
    remaining = 20
    last_call = 0.0
    paused = False
    resume_seen = set()
    try:
        while time.monotonic() < deadline and remaining > 0 and not (directory / 'stop').exists():
            if paused:
                signals = set(directory.glob('resume-*.json')) - resume_seen
                if not signals:
                    time.sleep(0.5)
                    continue
                resume_seen.update(signals)
                paused = False
            for job in sorted(directory.glob('job-*.json')):
                marker = job.with_suffix('.started')
                if marker.exists():
                    continue
                job_bundle = json.loads(job.read_bytes())
                if digest(job_bundle['source'].encode()) not in allowed_sources:
                    save(marker, b'unapproved_source')
                    continue
                if job_bundle['request']['contents'][0]['parts'][0]['text'] != job_bundle['source']:
                    save(marker, b'source_mismatch')
                    continue
                job_body = json.dumps(request_body(job_bundle), ensure_ascii=False).encode()
                fence = directory / ('fence-' + digest(job_body))
                if fence.exists():
                    save(marker, b'duplicate_refused')
                    continue
                # Recheck public zero-price metadata before every new request.
                check_catalog(json.loads(fetch('/models/' + MODEL + '/endpoints')))
                delay = max(0, 61 - (time.monotonic() - last_call))
                until = time.monotonic() + delay
                while time.monotonic() < until:
                    if (directory / 'stop').exists() or time.monotonic() >= deadline:
                        return
                    time.sleep(0.5)
                if (directory / 'stop').exists() or time.monotonic() >= deadline:
                    return
                save(fence, b'reserved-no-replay')
                save(marker, json.dumps({'request_sha256': digest(job_body), 'time': time.time()}).encode())
                remaining -= 1
                last_call = time.monotonic()
                print('API KEY USE: one OpenRouter request starting. Remaining budget:', remaining, flush=True)
                raw = None
                try:
                    raw = fetch('/chat/completions', job_body, key)
                    save(job.with_suffix('.response'), raw)
                    result = inspect_response(raw, job_bundle)
                except urllib.error.HTTPError as e:
                    result = {'state': 'http_error', 'status': e.code, 'retry': False}
                    try:
                        with total_deadline(3):
                            error_body = e.read(65537)
                        if len(error_body) <= 65536:
                            save(job.with_suffix('.error-body'), error_body.replace(key.encode(), b'[REDACTED]'))
                            result['error_body_sanitized'] = True
                    except Exception:
                        result['error_body_unavailable'] = True
                except Exception as e:
                    result = {'state': 'invalid_response' if raw is not None else 'transport_unknown',
                              'error_type': type(e).__name__, 'reason': ('total_request_deadline' if str(e) == 'total_request_deadline' else 'socket_inactivity_timeout') if isinstance(e, TimeoutError) else (str(e) if isinstance(e, ValueError) else 'inspect_retained_evidence'), 'retry': False}
                result['completed_at'] = time.time()
                result['elapsed_seconds'] = round(time.monotonic() - last_call, 3)
                result['model'] = MODEL
                result['provider'] = PROVIDER
                result['remaining_budget'] = remaining
                result['request_sha256'] = digest(job_body)
                save(job.with_suffix('.receipt'), json.dumps(result).encode())
                print('Job finished. Inspect receipt and raw response; no automatic retry.', flush=True)
                # Preserve the in-memory key but require an explicit resume command.
                # Existing fences still forbid retrying the same request.
                if result['state'] in ('transport_unknown', 'http_error'):
                    paused = True
                    resume_seen.update(directory.glob('resume-*.json'))
                    save(job.with_suffix('.paused'), b'explicit resume required; no automatic retry')
                    print('Paused after failure. Key remains in memory until expiry/stop. Codex must inspect before explicit resume.', flush=True)
                break
            time.sleep(0.5)
    finally:
        key = None
        save(directory / 'stopped', b'closed')


def main():
    global MODEL, PROVIDER, PROVIDER_NAME, REASONING_BUDGET
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['serve', 'submit', 'stop', 'resume'])
    p.add_argument('--session', required=True, type=Path)
    p.add_argument('--bundle', type=Path)
    p.add_argument('--route', choices=sorted(ROUTES), default='ling')
    p.add_argument('--start-smoke', action='store_true', help='Explicitly submit one smoke immediately after hidden key entry.')
    a = p.parse_args()
    MODEL, PROVIDER, PROVIDER_NAME = ROUTES[a.route]
    REASONING_BUDGET = 512 if a.route == 'nemotron-reasoning' else 0
    if a.action == 'serve':
        serve(a.session, a.bundle, a.start_smoke)
    else:
        if not (a.session / 'armed.json').exists() or (a.session / 'stopped').exists():
            raise SystemExit('Session not armed')
        if a.action == 'stop':
            save(a.session / 'stop', b'explicit')
        elif a.action == 'resume':
            import uuid
            save(a.session / ('resume-' + uuid.uuid4().hex + '.json'), b'explicit')
        else:
            import uuid
            bundle_path = a.bundle or (a.session / 'bundle.json')
            raw = bundle_path.read_bytes()
            if len(raw) > 2 * 1024 * 1024:
                raise SystemExit('Bundle too large')
            request_body(json.loads(raw))
            save(a.session / ('job-' + uuid.uuid4().hex + '.json'), raw)


if __name__ == '__main__':
    main()
