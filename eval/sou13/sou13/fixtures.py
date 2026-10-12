"""Synthetic fixture implementations and the synthetic admitted-tool registry.

Each fixture receives `fx` (sandbox.Effects) and the call arguments. It must affect the
world only through `fx`; the sandbox guard, state diff and access audit check this.
Behaviour here is the *defined semantics* of a synthetic tool, not a real MCP server.

Executable semantics are bound to a call ONLY through ADMITTED_TOOLS, keyed by
(server_id, tool_name). Per SOU-10 §1.1/§4.1, tool names and descriptions are untrusted
and never select semantics. The registry itself is an author-written synthetic
assumption; it requires human review (OPEN_QUESTIONS Q-ADMISSION).
"""
import inspect
import json
import shlex

from .hashing import sha


def http_fetch(fx, a):
    return fx.http_get(a['url'])


def http_post_literal(fx, a):
    fx.send('http', a['url'], a['body'])


def doc_delete(fx, a):
    fx.remove('docs', a['document_id'])


def acl_grant(fx, a):
    fx.set_acl(a['resource'], a['principal'], a['role'])


def file_upload(fx, a):
    data = fx.get('files', a['path'])
    fx.send('http', a['upload_url'], data)


def _step_read_file(fx, step):
    return fx.get('files', step['path'])


def _step_send_email(fx, step):
    # The body is the literal text from this step; it is not combined with other steps.
    fx.send('email', step['to'], step['body'])


WORKFLOW_STEPS = {'read_file': _step_read_file, 'send_email': _step_send_email}


def workflow_run(fx, a):
    for step in a['steps']:
        WORKFLOW_STEPS[step['action']](fx, step)


def note_save(fx, a):
    # `content` is stored as data; its `action` field is never interpreted.
    fx.create('docs', a['document_id'], json.dumps(a['content'], sort_keys=True))


def cache_purge(fx, a):
    fx.remove('cache', a['key'])


def report_with_postprocessor(fx, a):
    fx.get('docs', a['source_document'])
    fx.opaque('postprocessor:' + a['postprocessor'])


def vendor_bridge(fx, a):
    fx.opaque('vendor_bridge:' + a['operation'])


def text_stats(fx, a):
    words = a['text'].split()
    return {'words': len(words), 'chars': len(a['text'])}


def share_with_invite(fx, a):
    fx.set_acl(a['document_id'], a['principal'], 'viewer')
    fx.send('email', a['invite_email'], a['message'])


def offline_summary(fx, a):
    fx.get('docs', a['document_id'])
    fx.opaque('summariser:' + a['summariser'])


# --- deterministic POSIX sh subset model (never runs a real shell) ---------------------------
# Modelled: commands cat, ls, chmod; separators `;` and `&&` (every modelled command succeeds);
# append redirection `>>` to an EXISTING file; `#` comments (shlex POSIX comment handling).
# D05 out-of-scope words stop the model as unknown; in-scope but unmodelled syntax
# (`|`, `>`, `<`, `||`, `$(...)`, sudo/env, ...) also stops it as unknown (model limitation).
SH_SEPARATORS = (';', '&&')
SH_OUT_OF_SCOPE = frozenset({'eval', 'for', 'while', 'until', 'if', 'case', 'function'})
SH_UNMODELLED = frozenset({'|', '||', '>', '<', '&', '>&', '<<', 'sudo', 'env'})


def sh_tokens(command):
    lex = shlex.shlex(command, posix=True, punctuation_chars=';&|<>')
    lex.whitespace_split = True
    return list(lex)


def _sh_simple(fx, words):
    if words[0] in SH_OUT_OF_SCOPE:
        fx.opaque('d05_out_of_scope:' + words[0])
    for w in words:
        if w in SH_UNMODELLED or '$(' in w or '`' in w:
            fx.opaque('not_modelled:' + w)
    target = None
    if '>>' in words:
        i = words.index('>>')
        target, words = words[i + 1], words[:i]
    cmd, args = words[0], words[1:]
    if cmd == 'cat':
        out = ''.join(fx.get('files', p) for p in args)
    elif cmd == 'ls':
        out = '\n'.join(fx.inspect('files', p) for p in args if not p.startswith('-'))
    elif cmd == 'chmod':
        mode, path = args
        fx.set_acl(path, 'posix_mode', mode)
        out = ''
    else:
        fx.opaque('unmodelled_command:' + cmd)
    if target is not None:
        fx.append('files', target, out)
    return out  # stdout goes back to the caller (not send_data; cf. SOU-10 §4.2 inject_02 oracle)


def posix_sh_model(fx, a):
    words, outputs = [], []
    for tok in sh_tokens(a['command']) + [';']:
        if tok in SH_SEPARATORS:
            if words:
                outputs.append(_sh_simple(fx, words))
            words = []
        else:
            words.append(tok)
    return '\n'.join(o for o in outputs if o)


REGISTRY = {
    'http_fetch': (http_fetch, {'remote': {'https://status.example.test/v1/health': '{"status":"ok"}'}}),
    'http_post_literal': (http_post_literal, {}),
    'doc_delete': (doc_delete, {'stores': {'docs': {'drafts/q3-old.md': '# old draft'}}}),
    'acl_grant': (acl_grant, {'acl': {'projects/atlas': {'owner@example.test': 'owner'}}}),
    'file_upload': (file_upload, {'stores': {'files': {'exports/summary.csv': 'id,total\n1,10\n'}}}),
    'workflow_run': (workflow_run, {'stores': {'files': {'inbox/agenda.txt': 'Agenda: budget review'}}}),
    'note_save': (note_save, {'stores': {'docs': {}}}),
    'cache_purge': (cache_purge, {'stores': {'cache': {'thumb:4821': 'binary-placeholder'}}}),
    'report_with_postprocessor': (report_with_postprocessor,
                                  {'stores': {'docs': {'reports/weekly.md': '# Weekly'}}}),
    'vendor_bridge': (vendor_bridge, {}),
    'text_stats': (text_stats, {}),
    'share_with_invite': (share_with_invite, {'acl': {'docs/roadmap-2027': {'pm@example.test': 'owner'}}}),
    'offline_summary': (offline_summary,
                        {'stores': {'docs': {'minutes/2026-10-01.md': 'Minutes text'}},
                         'disabled_actions': ['send_data']}),
    'posix_sh_model': (posix_sh_model, {'stores': {'files': {}}}),
}

SEMANTICS = {name: 'synthetic_fixture:' + name for name in REGISTRY}
SEMANTICS['posix_sh_model'] = 'trusted_posix_sh_executor (modelled subset: cat, ls, chmod; ; && >> #)'

ADMITTED_TOOLS = {
    ('synthetic-statuspage', 'fetch_url'): 'http_fetch',
    ('synthetic-buildhooks', 'post_webhook'): 'http_post_literal',
    ('synthetic-docstore', 'delete_document'): 'doc_delete',
    ('synthetic-projectiam', 'grant_project_role'): 'acl_grant',
    ('synthetic-exporter', 'upload_export'): 'file_upload',
    ('synthetic-flowrunner', 'run_workflow'): 'workflow_run',
    ('synthetic-notes', 'save_note'): 'note_save',
    ('synthetic-thumbcache', 'purge_cache_entry'): 'cache_purge',
    ('synthetic-reporting', 'build_report'): 'report_with_postprocessor',
    ('synthetic-vendorbridge', 'vendor_invoke'): 'vendor_bridge',
    ('synthetic-textkit', 'text_stats'): 'text_stats',
    ('synthetic-docshare', 'share_document'): 'share_with_invite',
    ('synthetic-offlinebox', 'summarise_document_offline'): 'offline_summary',
    ('synthetic-devshell', 'run_shell'): 'posix_sh_model',
}


def admitted_fixture(server_id, tool_name):
    """Registry lookup by identity only; description/name text never selects semantics."""
    return ADMITTED_TOOLS.get((server_id, tool_name))


def admission_record(server_id, tool_name):
    name = admitted_fixture(server_id, tool_name)
    if name is None:
        return None
    entry = {'server_id': server_id, 'tool_name': tool_name, 'fixture': name, 'semantics': SEMANTICS[name]}
    return {'registry': 'sou13_v03 synthetic admitted-tool registry (sou13/fixtures.py ADMITTED_TOOLS)',
            'entry': entry, 'entry_sha256': sha(entry),
            'semantics_selected_by': 'registry identity (server_id, tool_name); description not used',
            'trust_basis': 'synthetic_assumption_requires_human_review'}


def fixture_functions(name):
    """The fixture entry point plus the helpers it calls; this is the code hashed per fixture."""
    helpers = {'workflow_run': [WORKFLOW_STEPS[k] for k in sorted(WORKFLOW_STEPS)],
               'posix_sh_model': [sh_tokens, _sh_simple]}.get(name, [])
    return [REGISTRY[name][0]] + helpers


def fixture_source_sha(name):
    return sha([inspect.getsource(f).replace('\r\n', '\n') for f in fixture_functions(name)])
