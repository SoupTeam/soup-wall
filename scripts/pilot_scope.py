# SPDX-License-Identifier: Apache-2.0
"""Frozen v1 Linux pilot scope: one versioned descriptor over the existing pilot contracts.

The descriptor (`profiles/pilot/linux-v1/scope.json`) names the supported platform, host, servers,
policy, classifiers, enforcement mode and operations, and lists every conditional or excluded
capability with its fail mode. It is selection metadata only: it grants no authority, opens no
capability and never certifies acceptance. Every binding is recomputed from the accepted sources on
each use, so a drifted policy, classifier, registry, profile or pin refuses instead of being trusted.

    python3 -B scripts/pilot_scope.py --check     # recompute and verify every binding
    python3 -B scripts/pilot_scope.py --print     # print the recomputed bindings (maintainers)
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
FORMAT = 'sw-pilot-scope/1'
ID = 'linux-v1'
DOCUMENT = 'profiles/pilot/linux-v1/scope.json'
CAP = 64 * 1024
HEX = re.compile(r'[0-9a-f]{64}\Z')
STATES = ('supported', 'conditional', 'unsupported')
FAIL_MODES = ('refused-before-execution', 'hard-deny-before-execution', 'not-selected-by-this-scope',
              'reports-unavailable-never-protection', 'opt-in-restricts-or-operates-only')
VOCABULARY = ('enforce', 'shadow', 'unavailable', 'unqualified')
EXTENSIONS = {'filesystem_roots': 'filesystem_roots', 'linked_worktree': 'linked_worktree',
              'workspace_snapshot': 'workspace_snapshot'}


class Refusal(ValueError):
    """A finite, stable `scope_*` reason; never raw paths or document text."""


def require(ok, code):
    if not ok:
        raise Refusal('scope_' + code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        found = {}
        for key, value in items:
            require(key not in found, 'document_invalid')
            found[key] = value
        return found

    def invalid(_):
        raise Refusal('scope_document_invalid')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except ValueError as error:
        if isinstance(error, Refusal):
            raise
        raise Refusal('scope_document_invalid') from None


def read_document(root):
    path = Path(root) / DOCUMENT
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise Refusal('scope_document_invalid') from None
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= CAP, 'document_invalid')
        raw = stream.read(CAP + 1)
    require(len(raw) <= CAP, 'document_invalid')
    return raw


def file_sha(root, relative):
    path = Path(root) / relative
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and not path.is_symlink(), 'binding_changed')
        return digest(path.read_bytes())
    except OSError:
        raise Refusal('scope_binding_changed') from None


def registry_file_sha(registry):
    """Hash of the registry.json the accepted installers write (`private_json`)."""
    return digest((json.dumps(registry, indent=2, ensure_ascii=False) + '\n').encode())


def expected_bindings(root, kit):
    """Every identity the scope claims, recomputed from the accepted sources."""
    root = Path(root)
    fs_assets = 'profiles/mcp/filesystem-readonly-v1'
    git_binding = kit.GIT_PROFILES.binding('git-readonly-v1')
    manifest = json.loads((root / fs_assets / 'upstream-tools-list.json').read_bytes())
    fs_registry = kit.FS.registry(manifest)
    git_registry = kit.GIT_PROFILES.registry('git-readonly-v1')
    return {
        'policy': {'selected_by_installed_entry_points': kit.POLICY_SOURCE,
                   'sha256': digest(kit.PILOT_POLICY.encode('utf-8'))},
        'classifiers': {'filesystem': file_sha(root, 'rule_baseline/rule_baseline.py'),
                        'git': file_sha(root, 'rule_baseline/git_readonly_v1/rule_baseline.py')},
        'filesystem_profile': {'id': fs_registry['registry_id'], 'format': 'sw-mcp/filesystem-readonly/1',
                               'upstream_tools_sha256': file_sha(root, fs_assets + '/upstream-tools-list.json'),
                               'upstream_identity_sha256': file_sha(root, fs_assets + '/upstream-identity.json'),
                               'profile_policy_sha256': file_sha(root, fs_assets + '/policy.yaml'),
                               'registry_sha256': registry_file_sha(fs_registry)},
        'git_profile': {'id': git_binding['id'], 'format': git_binding['profile_format'],
                        'selection_binding_sha256': digest(canonical(git_binding)),
                        'profile_policy_sha256': git_binding['policy_sha256'],
                        'registry_sha256': registry_file_sha(git_registry),
                        'classifier_sha256': git_binding['classifier_sha256']},
        'host': {'name': 'Claude Code', 'version': kit.CLAUDE_VERSION.split(' ')[0],
                 'lockfile_sha256': file_sha(root, fs_assets + '/claude-host/package-lock.json')},
        'runtime': {'node_version': kit.NODE_VERSION, 'node_archive_sha256': kit.NODE_ARCHIVE_SHA256},
        'other_documented_policy_presets_not_selected_by_installed_entry_points': {
            'linux-readonly-v1': {'manifest_sha256': file_sha(root, 'profiles/pilot/linux-readonly-v1/manifest.json'),
                                  'policy_sha256': file_sha(root, 'profiles/pilot/linux-readonly-v1/policy.yaml')}},
    }, fs_registry, git_registry


def exact(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), 'document_invalid')
    return value


def text(value, limit=400):
    require(type(value) is str and 1 <= len(value) <= limit and value.isprintable(), 'document_invalid')
    return value


def validate_shape(doc):
    exact(doc, ('format', 'id', 'title', 'claim', 'acceptance', 'bindings', 'platform', 'enforcement', 'status_model',
                'supported_operations', 'refused_operations', 'matrix', 'exclusions'), 'document')
    require(doc['format'] == FORMAT and doc['id'] == ID, 'document_invalid')
    text(doc['title'])
    text(doc['claim'], 800)
    require(doc['acceptance'] == 'not-claimed-by-this-document', 'document_invalid')
    exact(doc['platform'], ('supported', 'unsupported'), 'platform')
    exact(doc['enforcement'], ('mode', 'ask', 'shadow'), 'enforcement')
    require(doc['enforcement']['mode'] == 'enforce', 'document_invalid')
    exact(doc['status_model'], VOCABULARY, 'status_model')
    for key in VOCABULARY:
        text(doc['status_model'][key], 400)
    exact(doc['supported_operations'], ('filesystem', 'git'), 'operations')
    for kind in ('filesystem', 'git'):
        names = doc['supported_operations'][kind]
        require(type(names) is list and names == sorted(set(names)) and names and all(type(n) is str for n in names),
                'document_invalid')
    ids = set()
    for row in doc['matrix']:
        exact(row, ('id', 'area', 'item', 'state', 'fail_mode', 'entry'), 'matrix')
        require(re.fullmatch(r'[a-z0-9-]{1,64}', row['id']) and row['id'] not in ids
                and row['state'] in STATES and row['fail_mode'] in FAIL_MODES, 'document_invalid')
        ids.add(row['id'])
        for key in ('area', 'item', 'entry'):
            text(row[key])
    require(1 <= len(doc['matrix']) <= 96, 'document_invalid')
    seen = set()
    for row in doc['exclusions']:
        exact(row, ('id', 'option', 'applies', 'reason'), 'exclusion')
        require(re.fullmatch(r'[a-z0-9-]{1,64}', row['id']) and row['id'] not in seen
                and re.fullmatch(r'[a-z_]{1,48}', row['option']) and row['applies'] in ('present', 'non-default')
                and row['id'] in ids, 'document_invalid')
        seen.add(row['id'])
        text(row['reason'])
    for row in doc['refused_operations']:
        exact(row, ('server', 'tools', 'why'), 'refused')
        require(row['server'] in ('filesystem', 'git') and type(row['tools']) is list
                and row['tools'] == sorted(set(row['tools'])), 'document_invalid')
        text(row['why'])


def load(root=ROOT, kit=None):
    """Return `(document, document_sha256)` after recomputing and comparing every binding."""
    root = Path(root)
    raw = read_document(root)
    doc = strict(raw)
    validate_shape(doc)
    require(kit is not None, 'document_invalid')
    expected, fs_registry, git_registry = expected_bindings(root, kit)
    require(doc['bindings'] == expected, 'binding_changed')
    # Every registry tool is partitioned: supported (read-only with a result profile) or refused. Nothing is unlisted.
    for kind, registry in (('filesystem', fs_registry), ('git', git_registry)):
        tools = {tool['name']: tool for tool in registry['tools']}
        supported = doc['supported_operations'][kind]
        refused = [name for row in doc['refused_operations'] if row['server'] == kind for name in row['tools']]
        require(not set(supported) & set(refused) and set(supported) | set(refused) == set(tools), 'binding_changed')
        require(all(tools[name]['action_class'] == 'read_only' and tools[name].get('mcp_result_profile')
                    for name in supported), 'binding_changed')
    return doc, digest(raw)


def requested_exclusions(doc, *, git_profile, inputs):
    """Selected options the scope excludes. Empty means the request stays inside v1."""
    found = []
    for row in doc['exclusions']:
        option = row['option']
        value = git_profile if option == 'git_profile' else inputs.get(option)
        if row['applies'] == 'present' and value is not None:
            found.append(row)
        elif row['applies'] == 'non-default' and value not in (None, 'git-readonly-v1'):
            found.append(row)
    return found


def conformance(doc, selection, kit):
    """Does a prepared selection stay inside the scope? Reasons are finite codes, never document text."""
    if not isinstance(selection, dict):
        return {'state': 'nonconforming', 'reasons': ['selection_malformed']}
    reasons = []
    bound = doc['bindings']
    files = selection.get('files') if isinstance(selection.get('files'), dict) else {}

    def pinned(role):
        item = files.get(role)
        return item.get('sha256') if isinstance(item, dict) else None
    if pinned('policy') != bound['policy']['sha256']:
        reasons.append('policy_not_the_v1_policy')
    if pinned('filesystem_classifier') != bound['classifiers']['filesystem']:
        reasons.append('filesystem_classifier_not_v1')
    if pinned('git_classifier') != bound['classifiers']['git']:
        reasons.append('git_classifier_not_v1')
    for key in EXTENSIONS:
        if selection.get(key) is not None:
            reasons.append('excluded_capability_' + key)
    try:
        git_profile = kit.GIT_PROFILES.from_selection(selection)
    except (ValueError, KeyError, TypeError, AttributeError):
        git_profile = None
    if git_profile != 'git-readonly-v1':
        reasons.append('git_profile_not_v1')
    profiles = selection.get('prepared_profiles')
    for kind, key in (('filesystem', 'filesystem_profile'), ('git', 'git_profile')):
        row = profiles.get(kind) if isinstance(profiles, dict) else None
        if not isinstance(row, dict) or row.get('registry_sha256') != bound[key]['registry_sha256'] \
                or row.get('policy_sha256') != bound[key]['profile_policy_sha256'] \
                or row.get('format') != bound[key]['format']:
            reasons.append(kind + '_profile_not_v1')
    return {'state': 'conforming' if not reasons else 'nonconforming', 'reasons': sorted(set(reasons))}


MATRIX_BEGIN = '<!-- scope-matrix:begin (generated from profiles/pilot/linux-v1/scope.json) -->'
MATRIX_END = '<!-- scope-matrix:end -->'


def render_matrix(doc):
    """The support matrix exactly as the documentation shows it, generated from the descriptor."""
    def cell(value):
        return value.replace('|', '\\|')
    lines = [MATRIX_BEGIN, '', '| Area | Item | State | Fail mode | Entry / note |', '| --- | --- | --- | --- | --- |']
    for row in doc['matrix']:
        lines.append('| ' + ' | '.join(cell(row[key]) if key != 'state' else '**' + row[key] + '**'
                                       for key in ('area', 'item', 'state', 'fail_mode', 'entry')) + ' |')
    lines += ['', MATRIX_END]
    return '\n'.join(lines)


GUIDE = 'docs/operations/PILOT_V1_SCOPE.md'


def verify_guide(root, doc):
    """The canonical guide must show exactly the descriptor's matrix and bound identities."""
    raw = (Path(root) / GUIDE).read_text(encoding='utf-8')
    require(render_matrix(doc) in raw, 'guide_stale')
    bound = doc['bindings']
    for value in (bound['policy']['sha256'], bound['classifiers']['filesystem'], bound['classifiers']['git'],
                  bound['filesystem_profile']['registry_sha256'], bound['git_profile']['registry_sha256'],
                  bound['host']['lockfile_sha256'], bound['runtime']['node_archive_sha256']):
        require(value in raw, 'guide_stale')
    for kind in ('filesystem', 'git'):
        require(all('`' + name + '`' in raw for name in doc['supported_operations'][kind]), 'guide_stale')


def summary(doc, document_sha256):
    return {'id': doc['id'], 'document_sha256': document_sha256, 'enforcement': doc['enforcement']['mode'],
            'acceptance': doc['acceptance']}


def main(argv=None):
    import argparse
    import importlib.util
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--check', action='store_true')
    action.add_argument('--print', action='store_true')
    args = parser.parse_args(argv)
    sys.path.insert(0, str(ROOT / 'scripts'))

    def module(name, filename):
        spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        return value
    prep = module('pilot_scope_prepare', 'prepare-installed-pilot.py')
    kit = kit_from(prep)
    if args.print:
        print(json.dumps(expected_bindings(ROOT, kit)[0], indent=2, sort_keys=True))
        return 0
    try:
        doc, document = load(ROOT, kit)
        verify_guide(ROOT, doc)
    except Refusal as error:
        print(json.dumps({'status': 'refused', 'reason': str(error)}))
        return 2
    print(json.dumps({'status': 'verified', **summary(doc, document)}, sort_keys=True))
    return 0


def kit_from(prep, claude_version='2.1.251 (Claude Code)'):
    """The accepted constants and installers the bindings derive from."""
    import types
    pilot = prep.PILOT
    return types.SimpleNamespace(FS=prep.FS, GIT_PROFILES=prep.GIT_PROFILES, PILOT_POLICY=pilot.PILOT_POLICY,
                                 POLICY_SOURCE='scripts/qualify-installed-pilot.py:PILOT_POLICY',
                                 CLAUDE_VERSION=claude_version, NODE_VERSION=prep.FS.NODE_VERSION.lstrip('v'),
                                 NODE_ARCHIVE_SHA256=prep.NODE_ARCHIVE_SHA256)


if __name__ == '__main__':
    raise SystemExit(main())
