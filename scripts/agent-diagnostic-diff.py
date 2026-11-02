#!/usr/bin/env python3
"""Compare two selected doctor exports using private, offline file access."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import math

spec = importlib.util.spec_from_file_location('audit_reader', Path(__file__).with_name('agent-audit-report.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
CAP = 128 * 1024
SCOPE = 'local_setup_and_authenticated_runtime_not_active_host_execution'


def parse(raw):
    if len(raw) > CAP or not audit._bounded_json_depth(raw):
        raise ValueError('JSON exceeds size or depth limit')
    def finite(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError('nonfinite JSON')
        return result
    return json.loads(raw, object_pairs_hook=audit._pair_object, parse_float=finite,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def validate_checks(checks):
    if not isinstance(checks, list) or len(checks) > 256:
        raise ValueError('invalid check list')
    seen = set()
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError('invalid check record')
        name = check.get('id')
        if not isinstance(name, str) or not re.fullmatch('[a-z0-9_-]{1,80}', name) or name in seen:
            raise ValueError('invalid or duplicate check identity')
        seen.add(name)
        for key in ('source', 'outcome', 'reason_code'):
            if not isinstance(check.get(key), str) or len(check[key]) > 256:
                raise ValueError('invalid check field')
        if check.get('sha256') is not None and (not isinstance(check['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', check['sha256'])):
            raise ValueError('invalid check digest')




def project_checks(checks, prefix, fields):
    known = {'configuration', 'installation', 'classifier', 'enforcement', 'registry',
             'authenticated_runtime', 'lifecycle_identity', 'host_connection', 'active_host_call',
             'filesystem_profile', 'git_profile', 'filesystem_schema', 'git_schema',
             'filesystem_package', 'git_package', 'pilot_classifier', 'pilot_config',
             'pilot_registry', 'pilot_policy', 'pilot_binary', 'pilot_runtime', 'pilot_platform'}
    validate_checks(checks)
    for check in checks:
        name = check['id'] if check['id'] in known else 'other_' + digest(check['id'])
        for key in ('outcome', 'reason_code', 'sha256', 'source'):
            fields[prefix + name + '.' + key] = check.get(key)


def load(directory):
    directory = Path(os.path.abspath(directory))
    def read(name):
        with audit._open_input(directory / name) as stream:
            raw = stream.read(CAP + 1)
        return raw, parse(raw)
    _, manifest = read('manifest.json')
    if not isinstance(manifest, dict) or manifest.get('schema') != 'sw-agent-doctor-support/1':
        raise ValueError('unsupported support manifest')
    if manifest.get('report_schema') != 'sw-agent-doctor/1':
        raise ValueError('unsupported report schema')
    raw, report = read('report.json')
    expected = [{'name': 'report.json', 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}]
    if manifest.get('files') != expected:
        raise ValueError('artifact integrity mismatch')
    if not isinstance(report, dict) or report.get('schema') != 'sw-agent-doctor/1' or report.get('scope') != SCOPE:
        raise ValueError('missing or unsupported diagnostic scope')
    if type(report.get('observed_at_ms')) is not int or report['observed_at_ms'] < 0:
        raise ValueError('invalid observation time')
    if report.get('setup') not in ('ready', 'failed', 'unknown', 'unsupported'):
        raise ValueError('invalid setup outcome')
    if not isinstance(report.get('active_host_call_protection'), str):
        raise ValueError('invalid protection scope')
    checks = report.get('checks')
    validate_checks(checks)
    fields = {'configuration.setup': report.get('setup'), 'runtime.protection': report.get('active_host_call_protection')}
    project_checks(checks, 'checks.', fields)
    pilot = report.get('pilot')
    if pilot is not None:
        if not isinstance(pilot, dict):
            raise ValueError('invalid pilot scope')
        validate_checks(pilot.get('checks'))
        if pilot.get('incident') is not None and not isinstance(pilot['incident'], dict):
            raise ValueError('invalid incident scope')
        if pilot.get('schema') != 'sw-agent-doctor-pilot/1':
            raise ValueError('unsupported pilot schema')
        project_checks(pilot['checks'], 'pilot.checks.', fields)
        for key in ('schema', 'setup', 'asset_trust', 'active_host_call_protection'):
            fields['pilot.' + key] = pilot.get(key)
        incident = pilot.get('incident')
        if incident is not None:
            for key in ('source', 'completeness', 'boundary', 'reason_code',
                        'current_instance_binding', 'execution', 'model_consumption'):
                value = incident.get(key)
                if not isinstance(value, str) or not re.fullmatch('[a-z0-9_-]{1,128}', value):
                    raise ValueError('invalid incident field')
                fields['pilot.incident.' + key] = value
    return {'artifact_sha256': hashlib.sha256(raw).hexdigest(), 'observed_at_ms': report['observed_at_ms'], 'fields': fields}


def compare(left, right):
    rows = []
    for name in sorted(left['fields'].keys() | right['fields'].keys()):
        a, b = left['fields'].get(name), right['fields'].get(name)
        state = 'missing' if a is None or b is None else 'unchanged' if a == b else 'changed'
        rows.append({'field': name, 'state': state, 'before_sha256': None if a is None else digest(a),
                     'after_sha256': None if b is None else digest(b)})
        if name.endswith('.outcome') or name == 'configuration.setup':
            public = ('ready', 'failed', 'unknown', 'unsupported')
            rows[-1]['before_outcome'] = a if a in public else None
            rows[-1]['after_outcome'] = b if b in public else None
    changed = [row['field'] for row in rows if row['state'] == 'changed']
    return {'schema': 'sw-agent-diagnostic-diff/1', 'evidence': 'historical_selected_exports',
            'integrity': 'manifest_hash_checked_not_external_authentication',
            'correlation': 'none_no_authenticated_cross_bundle_call_binding',
            'unavailable': ['current_source', 'provider_transport', 'storage_cleanup'],
            'historical': True, 'execution_observed': False, 'changed_fields': changed[:256],
            'rows': rows, 'next_step': 'Review changed checks in the original private bundles. Collect current doctor evidence before retrying through the supported workflow.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    parser.add_argument('--json-out', type=Path, required=True)
    parser.add_argument('--markdown-out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.before.absolute() == args.after.absolute():
            raise ValueError('duplicate input')
        left, right = load(args.before), load(args.after)
        if left['artifact_sha256'] == right['artifact_sha256']:
            raise ValueError('duplicate report content')
        report = compare(left, right)
        report['inputs'] = [{k: v for k, v in item.items() if k != 'fields'} for item in (left, right)]
        body = (json.dumps(report, indent=2, allow_nan=False) + '\n').encode()
        markdown = '# Diagnostic diff\n\nHistorical selected exports; current execution is not established.\n\n'
        markdown += '\n'.join('- ' + row['field'] + ': ' + row['state'] for row in report['rows'])
        markdown += '\n\n' + report['next_step'] + '\n'
        if len(body) > CAP or len(markdown.encode()) > CAP:
            raise ValueError('output exceeds cap')
        for output in (args.json_out, args.markdown_out):
            if output.exists() or output.is_symlink():
                raise ValueError('output already exists')
        audit._private_output(args.json_out.absolute(), body)
        audit._private_output(args.markdown_out.absolute(), markdown.encode())
        return 0
    except (OSError, ValueError, audit.ReportError, audit.WindowsIoError, RecursionError):
        print('error: unsupported, unsafe, corrupt or unavailable diagnostic input/output', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
