#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in restored-outbox transport fixture, never a production dispatcher.

A cfg(test) Rust binary uses native claim/sign/send/fenced-finish functions.
Only this fixture adapts the tenant-event envelope to the existing authenticated
Alertmanager receiver. Production HTTPS, DNS and SSRF rules remain unchanged.
"""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import alert_receiver as receiver
import console_recovery as recovery

TEST = 'tenant_store::recovery_outbox_fixture::restored_outbox_claim_send_and_fenced_finish'
OBJECTIVE_SECONDS = 180


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def http(method, url, body=None, token=None):
    parsed = urlsplit(url)
    if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not parsed.port
            or parsed.username or parsed.password or parsed.fragment):
        raise recovery.RecoveryError('Only the owned loopback receiver is permitted.')
    data = None if body is None else json.dumps(body, separators=(',', ':')).encode()
    request = urllib.request.Request(url, data=data, method=method,
        headers={'Content-Type':'application/json', **({'Authorization':'Bearer '+token} if token else {})})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, json.loads(response.read(256 * 1024))
    except urllib.error.HTTPError as error:
        return error.code, None


def translated_event(event, endpoint):
    labels = {'alertname':'ConsoleRecoveryEvent', 'severity':'warning', 'component':'console',
        'job':'sou49-owned-outbox', 'instance':'owned-loopback', 'source_event':event['event_id']}
    start = datetime.fromtimestamp(event['occurred_at_unix'], timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    alert = {'status':'firing', 'labels':labels, 'annotations':{}, 'startsAt':start,
        'endsAt':'0001-01-01T00:00:00Z', 'generatorURL':endpoint,
        'fingerprint':hashlib.sha256(event['event_id'].encode()).hexdigest()[:16]}
    return {'version':'4', 'receiver':'sou49-owned-recovery', 'status':'firing',
        'groupKey':'owned-recovery', 'groupLabels':{}, 'commonLabels':{}, 'commonAnnotations':{},
        'externalURL':endpoint, 'truncatedAlerts':0, 'alerts':[alert]}


class Adapter(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass

    def do_POST(self):
        status = 400
        try:
            if self.path != '/events' or self.headers.get('Transfer-Encoding'):
                raise ValueError
            size = self.headers.get('Content-Length', '')
            if not size.isdecimal() or not 1 <= int(size) <= 65536:
                raise ValueError
            raw = self.rfile.read(int(size))
            expected = 'sha256=' + hmac.new(self.server.destination_secret.encode(),raw,hashlib.sha256).hexdigest()
            if not hmac.compare_digest(self.headers.get('x-llm-firewall-signature',''),expected):
                status = 401
            else:
                event = recovery.strict_json(raw)
                if (event['event_id'] != self.server.event_id
                        or self.headers.get('x-llm-firewall-delivery') != self.server.delivery_id):
                    raise ValueError
                self.server.attempts += 1
                self.server.body_hashes.append(hashlib.sha256(raw).hexdigest())
                if self.server.phase == 'unavailable':
                    status = 503
                else:
                    code, _ = http('POST', self.server.receiver_endpoint+'/alerts',
                        translated_event(event,self.server.receiver_endpoint),self.server.receiver_token)
                    status = 503 if code == 200 and self.server.phase == 'lost_ack' else code
        except (ValueError, KeyError, OSError, urllib.error.URLError, recovery.RecoveryError):
            status = 400
        self.send_response(status)
        self.send_header('Content-Length','0')
        self.send_header('Connection','close')
        self.end_headers()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--private-dir', type=Path, required=True)
    parser.add_argument('--fixture-helper', type=Path, required=True)
    parser.add_argument('--outbox-test-binary', type=Path, required=True)
    parser.add_argument('--psql', default='psql')
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({'status':'not-run','resources_created':False}))
        return 0
    started = time.monotonic()
    root = recovery.private_directory(args.private_dir)
    manifest = recovery.strict_json(recovery.private_file(root/'fixture-manifest.json').read_bytes())
    working = root/'outbox-fixture'
    working.mkdir(mode=0o700)
    recovery.private_directory(working)
    sqlite_path = os.environ.get('LLM_FW_CONSOLE_RECOVERY_FIXTURE_SQLITE_PATH')
    postgres_url = os.environ.get('LLM_FW_CONSOLE_RECOVERY_FIXTURE_DATABASE_URL')
    if bool(sqlite_path) == bool(postgres_url):
        raise recovery.RecoveryError('Select exactly one restored fixture database.')
    delivery, event = manifest['delivery_id'], manifest['event_id']
    if not re.fullmatch(r'webhook_delivery_[A-Za-z0-9_-]+', delivery):
        raise recovery.RecoveryError('Unexpected fixture delivery identity.')
    pg = (recovery.PostgresBackend(postgres_url, directory=working, psql=args.psql)
          if postgres_url else None)
    if pg:
        parsed = urlsplit(postgres_url)
        if parsed.hostname not in {'127.0.0.1','::1'} or not parsed.path.startswith('/sou49_recovered_'):
            raise recovery.RecoveryError('Only the owned restored PostgreSQL fixture is permitted.')
        pg.require_owned()
    elif recovery.private_file(sqlite_path) != root/'recovered.sqlite':
        raise recovery.RecoveryError('Only the owned restored SQLite fixture is permitted.')

    def row():
        columns = 'status,attempt_count,next_attempt_at_unix,locked_until_unix'
        if pg:
            return recovery.strict_json(pg.sql('SELECT row_to_json(r) FROM (SELECT '+columns+
                " FROM tenant_webhook_deliveries WHERE id='"+delivery+"') r;"))
        with closing(sqlite3.connect(sqlite_path)) as connection:
            values = connection.execute('SELECT '+columns+' FROM tenant_webhook_deliveries WHERE id=?',
                                        (delivery,)).fetchone()
        return dict(zip(columns.split(','),values))

    baseline = row()
    assert baseline['status'] == 'pending' and baseline['attempt_count'] == 1
    # Synthetic stopped-source retry was set +1800s by the seed helper. Advancing
    # that one synthetic due time is a fixture clock control, never reconciliation.
    if pg:
        pg.sql("UPDATE tenant_webhook_deliveries SET next_attempt_at_unix=0 WHERE id='"+delivery+"';")
    else:
        with closing(sqlite3.connect(sqlite_path)) as connection:
            with connection:
                connection.execute('UPDATE tenant_webhook_deliveries SET next_attempt_at_unix=0 WHERE id=?',(delivery,))

    token = secrets.token_urlsafe(32)
    store_dir = working/'receiver'
    store_dir.mkdir(mode=0o700)
    policy = receiver.ReceiverPolicy.from_dict({'receiver':'sou49-owned-recovery',
        'external_url':'http://127.0.0.1:1', 'sources':[{'job':'sou49-owned-outbox',
        'instance':'owned-loopback', 'alerts':[{'alertname':'ConsoleRecoveryEvent',
        'severity':'warning','component':'console'}]}], 'optional_labels':{'source_event':[event]}})
    store = receiver.ReceiptStore(store_dir)
    actual = receiver.AlertReceiverServer(('127.0.0.1',0),token.encode(),policy,store)
    actual_endpoint = 'http://127.0.0.1:'+str(actual.server_address[1])
    # This allowlisted origin belongs only to this temporary server.
    policy.external_url = actual_endpoint
    thread = threading.Thread(target=actual.serve_forever,daemon=True)
    thread.start()
    adapter = ThreadingHTTPServer(('127.0.0.1',0),Adapter)
    adapter.daemon_threads = True
    adapter.destination_secret = manifest['destination_secret']
    adapter.delivery_id, adapter.event_id = delivery,event
    adapter.receiver_endpoint, adapter.receiver_token = actual_endpoint,token
    adapter.attempts, adapter.body_hashes = 0,[]
    adapter_thread = threading.Thread(target=adapter.serve_forever,daemon=True)
    adapter_thread.start()
    checks, outcomes = {},[]
    try:
        checks['receiver-requires-bearer'] = http('GET',actual_endpoint+'/receipts')[0] == 401
        malformed = urllib.request.Request('http://127.0.0.1:'+str(adapter.server_address[1])+'/events',
            data=b'{}',method='POST',headers={'Content-Type':'application/json'})
        try:
            urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(malformed,timeout=3)
            checks['adapter-requires-native-hmac'] = False
        except urllib.error.HTTPError as error:
            checks['adapter-requires-native-hmac'] = error.code == 401
        for index, phase in enumerate(('unavailable','lost_ack','normal')):
            deadline = time.monotonic()+OBJECTIVE_SECONDS
            while row()['next_attempt_at_unix'] > time.time():
                if time.monotonic()>deadline:
                    raise recovery.RecoveryError('Native outbox retry deadline was exceeded.')
                time.sleep(.2)
            adapter.phase = phase
            config = {'schema_version':1,'sqlite_path':sqlite_path,'postgres_url':postgres_url,
                'signing_key':manifest['webhook_signing_key'],
                'receiver_url':'http://127.0.0.1:'+str(adapter.server_address[1])+'/events',
                'delivery_id':delivery,'result_path':str(working/f'attempt-{index}.json')}
            config_file = working/f'config-{index}.json'
            recovery.write_private(config_file,recovery.canonical(config))
            environment = recovery.child_environment({'SOUP_RECOVERY_OUTBOX_CONFIG':str(config_file)},working)
            process = subprocess.run([str(args.outbox_test_binary),TEST,'--ignored','--exact','--test-threads=1'],
                cwd=root,env=environment,capture_output=True,timeout=30)
            recovery.write_private(working/f'native-{index}.log',process.stdout+process.stderr)
            if process.returncode:
                raise recovery.RecoveryError('Native restored-outbox fixture failed; private diagnostics withheld.')
            outcome = recovery.strict_json(recovery.private_file(working/f'attempt-{index}.json').read_bytes())
            outcomes.append(outcome)
            assert outcome['attempt_count'] == index+2 and outcome['completion_owned']
            assert outcome['delivered'] == (phase=='normal')
            if phase == 'unavailable':
                checks['receiver-outage-keeps-pending-and-native-backoff'] = (
                    row()['status']=='pending' and store.receipts()['total_unique_events']==0
                    and row()['next_attempt_at_unix'] > time.time())
            if phase == 'lost_ack':
                checks['ambiguous-ack-retains-one-durable-receipt-and-pending-outbox'] = (
                    row()['status']=='pending' and store.receipts()['total_unique_events']==1)
                actual.shutdown(); actual.server_close(); thread.join(timeout=5); store.close()
                store = receiver.ReceiptStore(store_dir)
                actual = receiver.AlertReceiverServer(('127.0.0.1',int(actual_endpoint.rsplit(':',1)[1])),
                    token.encode(),policy,store)
                thread = threading.Thread(target=actual.serve_forever,daemon=True); thread.start()
                checks['receiver-restart-preserves-durable-receipt'] = store.receipts()['total_unique_events']==1
        receipts = store.receipts()
        checks['same-event-and-body-across-three-native-attempts'] = adapter.attempts==3 and len(set(adapter.body_hashes))==1
        checks['one-receiver-effect-and-one-deduplicated-retry'] = (receipts['total_unique_events']==1
            and receipts['records'][0]['duplicate_count']==1
            and receipts['records'][0]['labels']['source_event']==event)
        checks['native-outbox-delivered-after-four-total-attempts'] = row()['status']=='delivered' and row()['attempt_count']==4
        checks['bounded-webhook-recovery-objective-met'] = time.monotonic()-started <= OBJECTIVE_SECONDS
        if not all(checks.values()):
            raise recovery.RecoveryError('An owned receiver recovery assertion failed.')
        print(json.dumps({'schema_version':1,'status':'passed','checks':checks,
            'attempts':outcomes,'elapsed_seconds':round(time.monotonic()-started,6),
            'predeclared_objective_seconds':OBJECTIVE_SECONDS,
            'transport':'cfg(test) native sender -> HMAC adapter -> existing authenticated Alertmanager receiver',
            'production_external_https_delivery_verified':False,
            'synthetic_due_time_control':True,'exactly_once_network_delivery_claimed':False},sort_keys=True))
    finally:
        adapter.shutdown(); adapter.server_close(); adapter_thread.join(timeout=5)
        actual.shutdown(); actual.server_close(); thread.join(timeout=5); store.close()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (recovery.RecoveryError, OSError, ValueError, KeyError, AssertionError, subprocess.SubprocessError):
        print(json.dumps({'schema_version':1,'status':'failed',
            'reason':'Owned webhook recovery fixture failed; private diagnostics withheld.',
            'production_external_https_delivery_verified':False}))
        raise SystemExit(1)
