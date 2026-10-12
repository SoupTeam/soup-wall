"""SOU-13 CP2 family taxonomy (declarative, Phase 1). Rationale: docs/CP2_FAMILY_TAXONOMY.md.

Definitions
  family    ONE implementation of tool behaviour (one fixture / semantics specification), admitted under one
            or more identities (server_id, tool_name). Renamed servers, `_v2`/`_adapter` names and
            re-described copies of the same implementation are the SAME family. Tool name and description
            never define or select a family (SOU-10 §1.1, §4.1).
  alias     every identity and normalised tool name of a family; alias_group_id = 'ag.' + family slug.
  template  a case-construction pattern inside a family (argument shape, world, scenario). Its structural
            signature (identity.template_signature) must be unique across the whole taxonomy: equal
            signatures are near-duplicate templates and must be merged or made genuinely different.

Families with status `cp2_candidate` (Phase 2) get their cases from the declarative catalog (catalog.py,
semantics.py); CP1 families keep their CP1 records and receive extra train cases from a declarative
re-specification of the CP1 fixture. Nothing here is human-reviewed.
"""
import re

from sou13.cases import CASES, schema
from sou13.fixtures import REGISTRY, admitted_fixture
from sou13.labels import ACTIONS

from .catalog import get_catalog
from . import restricted
from .identity import (name_tokens, normalized_description, normalized_name, normalized_server, program_skeleton,
                       shape_signature, template_signature)

TAXONOMY_VERSION = 'cp2-taxonomy-v2-draft'
DECL = 'declarative_semantics_execution'
# Coverage strata used by split assignment: behaviour class, with unknown split by profile.
COVERAGE_STRATA = ('read', 'write', 'delete', 'send_data', 'change_permissions', 'mixed', 'no_effect',
                   'unknown_partial', 'unknown_full', 'shell')
BEHAVIOR_CLASSES = ('read', 'write', 'delete', 'send_data', 'change_permissions', 'mixed', 'no_effect', 'unknown',
                    'shell')
UNKNOWN_PROFILES = ('none', 'partial', 'full')
EXPOSURES = ('none', 'cp1_shared', 'v02_derived', restricted.EXPOSURE)
EVIDENCE_KINDS = ('controlled_execution', 'no_established_semantics', 'input_validation', DECL)
OPAQUE = 'opaque_invoked'
EVENT_ACTION = {
    'http_get': 'read', 'store_read': 'read', 'store_read:metadata': 'read',
    'store_write:create': 'write', 'store_write:set': 'write', 'store_write:append': 'write',
    'store_delete': 'delete',
    'send:http': 'send_data', 'send:email': 'send_data', 'send:chat': 'send_data', 'send:sms': 'send_data',
    'acl_change': 'change_permissions',
}
FAMILY_ID = re.compile(r'^fam\.(%s)\.[a-z0-9_]+$' % '|'.join(BEHAVIOR_CLASSES))


def S(props, required=None):
    return schema(props, list(props) if required is None else required)


# ---- Checkpoint 1 cases -> family/template --------------------------------------------------------------------
# case id -> (family_id, template variant, declared effect profile). The declared profile is checked against
# the stored synthetic execution trace of the CP1 record (records.record_errors).
CP1_TEMPLATES = {
    'S13V03-DEV-01': ('fam.read.http_get', 'status_probe', ['http_get']),
    'S13V03-SUP-S2': ('fam.read.http_get', 'null_arguments_invalid', []),
    'S13V03-DEV-02': ('fam.send_data.webhook_post', 'literal_body', ['send:http']),
    'S13V03-DEV-03': ('fam.delete.document_delete', 'by_id', ['store_delete']),
    'S13V03-DEV-04': ('fam.change_permissions.role_grant', 'project_role', ['acl_change']),
    'S13V03-DEV-05': ('fam.mixed.file_upload', 'local_file_to_url', ['store_read', 'send:http']),
    'S13V03-DEV-06': ('fam.mixed.workflow_steps', 'read_then_email', ['store_read', 'send:email']),
    'S13V03-DEV-07': ('fam.write.note_create', 'nested_action_as_data', ['store_write:create']),
    'S13V03-DEV-08': ('fam.delete.cache_purge', 'misleading_description', ['store_delete']),
    'S13V03-DEV-09': ('fam.unknown.workspace_tidy', 'admission_rejection_test', []),
    'S13V03-DEV-10': ('fam.unknown.report_postprocess', 'read_then_opaque', ['store_read', OPAQUE]),
    'S13V03-DEV-11': ('fam.unknown.vendor_bridge', 'opaque_only', [OPAQUE]),
    'S13V03-DEV-12': ('fam.no_effect.text_stats', 'action_word_in_data', []),
    'S13V03-DEV-13': ('fam.shell.posix_sh', 'cat_append_existing', ['store_read', 'store_write:append']),
    'S13V03-DEV-14': ('fam.shell.posix_sh', 'ls_with_comment', ['store_read:metadata']),
    'S13V03-DEV-15': ('fam.shell.posix_sh', 'chmod_and_ls', ['acl_change', 'store_read:metadata']),
    'S13V03-SUP-S3': ('fam.shell.posix_sh', 'eval_out_of_scope', ['store_read', OPAQUE]),
    'S13V03-DEV-16': ('fam.mixed.share_invite', 'grant_and_literal_invite', ['acl_change', 'send:email']),
    'S13V03-SUP-S1': ('fam.unknown.offline_summary', 'env_declared_negative', ['store_read', OPAQUE]),
}

# planned_cases is derived in _finalise: CP1 cases + catalog n_new (the actual candidate count). It is the
# split-balancing weight; the validator checks that the generated dataset has exactly this many cases.
CP1_FAMILY_META = {
    'fam.read.http_get': dict(mechanism='remote HTTP GET without body',
                              rationale='Remote read; URL alone is not send_data (§2 rule 2). Also hosts the CP1 technical-error template.'),
    'fam.send_data.webhook_post': dict(mechanism='HTTP POST of a literal body',
                                       rationale='Outbound literal transfer without local read (D03).'),
    'fam.delete.document_delete': dict(mechanism='explicit delete by id in a document store',
                                       rationale='Delete without write (D03).'),
    'fam.change_permissions.role_grant': dict(mechanism='ACL grant on a project',
                                              rationale='Permission change without write (D03).'),
    'fam.mixed.file_upload': dict(mechanism='read local file, send its content',
                                  rationale='read + send_data in one implementation (file exfiltration, §2).'),
    'fam.mixed.workflow_steps': dict(mechanism='multi-step workflow interpreter',
                                     rationale='Argument-driven step list; step semantics unresolved.',
                                     open_questions=['Q-DEV06-STEPS']),
    'fam.write.note_create': dict(mechanism='create a new document (no overwrite)',
                                  rationale='Write; nested action-like fields are data (§2 rule 3).'),
    'fam.delete.cache_purge': dict(mechanism='cache entry purge',
                                   rationale='Delete under a misleading read-only description (§4.1, D04).'),
    'fam.unknown.workspace_tidy': dict(mechanism='registry-admitted opaque workspace tool (CP2 replacement of CP1 DEV-09)',
                                       rationale='Admitted opaque semantics: all five actions null, unknown=true. The CP1 DEV-09 '
                                                 'unadmitted identity is kept only as a separate admission-rejection '
                                                 'test (technical review 2026-10-10; contract clarification relayed).',
                                       open_questions=['Q-DEV09-UNADMITTED']),
    'fam.unknown.report_postprocess': dict(mechanism='established read followed by an unmodelled component',
                                           rationale='Partial unknown: read known, rest null (§3.1).'),
    'fam.unknown.vendor_bridge': dict(mechanism='immediately opaque partner integration',
                                      rationale='Full unknown: no action established or excluded (§3.1).'),
    'fam.no_effect.text_stats': dict(mechanism='pure computation over arguments',
                                     rationale='Proven no-op (D07); action words appear only as data.'),
    'fam.shell.posix_sh': dict(mechanism='trusted POSIX sh executor (deterministic subset model)',
                               rationale='One implementation interpreting arbitrary commands; NOT expanded in Phase 1.',
                               open_questions=['Q-SHELL-MODEL', 'Q-CP2-SHELL-SPLIT', 'Q-D05']),
    'fam.mixed.share_invite': dict(mechanism='ACL grant plus literal email invitation',
                                   rationale='change_permissions + send_data without reading the document.'),
    'fam.unknown.offline_summary': dict(mechanism='read then opaque component in a declared no-network environment',
                                        rationale='Environment-declared negative under unknown; pending convention.',
                                        open_questions=['Q-ENV', 'SOU13-CONV-FORBIDDEN-ACTIONS']),
}


# CP1 cases kept only as admission-rejection tests: their identity is NOT admitted (rejected_identities) and their
# labels are outside semantic accuracy (technical review 2026-10-10, DEV-09).
ADMISSION_TEST_CASES = frozenset({'S13V03-DEV-09'})
# Registry-admitted identities (neutral server_id) that replace an admission-test identity for classification.
ADMITTED_REPLACEMENTS = {'fam.unknown.workspace_tidy': {'identities': [['synthetic-workspace', 'tidy_workspace']],
                                                         'decl_profile': [OPAQUE]}}


def _tpl(variant, sch, effect_profile, evidence_kind='controlled_execution', disabled=(), arg_keys=None,
         cp1_cases=()):
    return {'variant': variant, 'schema': sch, 'arg_keys': sorted(arg_keys if arg_keys is not None else sch['properties']),
            'effect_profile': list(effect_profile), 'evidence_kind': evidence_kind,
            'disabled_actions': sorted(disabled), 'cp1_cases': sorted(cp1_cases)}


def _planned(family_id, mechanism, rationale, identities, description, sch, effect_profile,
             open_questions=(), variant='canonical', extra_templates=()):
    """A CP2 family (no CP1 cases). Templates use declarative semantics; extra_templates are
    (variant, effect_profile) pairs for argument-dependent modes of the same implementation."""
    templates = [_tpl(variant, sch, effect_profile, DECL)]
    templates += [_tpl(v, sch, prof, DECL) for v, prof in extra_templates]
    misleading = get_catalog().get(family_id, {}).get('misleading')
    return {'family_id': family_id, 'mechanism': mechanism, 'rationale': rationale,
            'identities': [list(i) for i in identities],
            'descriptions': [description] + ([misleading] if misleading else []),
            'honest_description': description, 'misleading_description': misleading,
            'templates': templates, 'open_questions': list(open_questions), 'status': 'cp2_candidate',
            'source_material': 'new_cp2_design', 'exposure': 'none'}


# ---- CP2 families (cases generated from the declarative catalog) --------------------------------------------------------
PLANNED_FAMILIES = [
    # read
    _planned('fam.read.wiki_page_get', 'get one document by id from a page store',
             'Local store read (contrast: http_get is remote). Second identity is a mirror server alias.',
             [('synthetic-wiki', 'get_page'), ('synthetic-wiki-mirror', 'get_page')],
             'Return the text of a wiki page.', S({'page_id': 'string'}), ['store_read']),
    _planned('fam.read.object_stat', 'metadata-only inspection of a stored object',
             'Read via metadata only (§2 "inspecting metadata"); two tool names alias one implementation.',
             [('synthetic-blobstore', 'stat_object'), ('synthetic-blobstore', 'head_object')],
             'Return size and modification time of a stored object.',
             S({'bucket': 'string', 'object_key': 'string'}), ['store_read:metadata']),
    # write
    _planned('fam.write.audit_append', 'append to an existing entry', 'Write by append (no create, no truncate).',
             [('synthetic-auditlog', 'append_entry')], 'Append a line to an existing audit log.',
             S({'log_id': 'string', 'line': 'string'}), ['store_write:append']),
    _planned('fam.write.migration_apply', 'schema migration with an argument-selected dry-run mode',
             'Argument-dependent behaviour of ONE implementation: dry_run=true is a no-op, otherwise write.',
             [('synthetic-schemactl', 'apply_migration')], 'Apply a schema migration, optionally as a dry run.',
             S({'migration_id': 'string', 'dry_run': 'boolean'}), ['store_write:set'], variant='apply',
             extra_templates=[('dry_run', [])]),
    _planned('fam.write.flag_set', 'boolean configuration overwrite',
             'Write as a toggle of configuration state; boolean argument, no free text.',
             [('synthetic-flags', 'set_feature_flag')], 'Turn a feature flag on or off.',
             S({'flag': 'string', 'enabled': 'boolean'}), ['store_write:set']),
    # delete
    _planned('fam.delete.prefix_remove', 'bulk delete of every key under a prefix',
             'Delete of many objects selected by pattern (contrast: delete by id).',
             [('synthetic-tmpfs', 'remove_prefix')], 'Remove every temporary object under a prefix.',
             S({'prefix': 'string'}), ['store_delete']),
    _planned('fam.delete.queue_ack', 'consume-on-acknowledge queue removal',
             'Delete expressed as acknowledgement; no delete word in name or description.',
             [('synthetic-jobqueue', 'ack_message')], 'Acknowledge a queue message so it is not redelivered.',
             S({'queue': 'string', 'message_id': 'string'}), ['store_delete'], open_questions=['Q-CP2-ACK']),
    # send_data
    _planned('fam.send_data.chat_post', 'post to an external chat channel', 'Outbound literal via chat channel.',
             [('synthetic-chatops', 'post_channel_message')], 'Post a text message to an external chat channel.',
             S({'channel': 'string', 'text': 'string'}), ['send:chat']),
    _planned('fam.send_data.sms_send', 'send a literal text message to a phone number',
             'Outbound literal via SMS channel (phone-number recipient).',
             [('synthetic-smsgate', 'send_sms')], 'Send a text message to a phone number.',
             S({'phone': 'string', 'text': 'string'}), ['send:sms']),
    # change_permissions
    _planned('fam.change_permissions.member_remove', 'revoke membership in a directory group',
             'Permission removal (contrast: grant).', [('synthetic-groupdir', 'remove_group_member')],
             'Remove a principal from a directory group.', S({'group': 'string', 'principal': 'string'}),
             ['acl_change']),
    _planned('fam.change_permissions.link_share', 'enable link-based access',
             'Permission change that widens audience without a named principal; not send_data by itself.',
             [('synthetic-drive', 'enable_link_sharing')], 'Turn on link sharing for a file.',
             S({'file_id': 'string', 'visibility': 'string'}), ['acl_change']),
    # mixed
    _planned('fam.mixed.record_archive', 'move a record into an archive store',
             'read + write + delete (move); archive/mv semantics are in Q-FUTURE.',
             [('synthetic-archiver', 'archive_record')], 'Move a record into the archive store.',
             S({'record_id': 'string', 'archive_id': 'string'}), ['store_read', 'store_write:create', 'store_delete'],
             open_questions=['Q-FUTURE']),
    _planned('fam.mixed.user_offboard', 'revoke access and delete sessions',
             'change_permissions + delete, no write.', [('synthetic-offboard', 'offboard_user')],
             "Revoke a user's access and delete their sessions.", S({'user_id': 'string'}),
             ['acl_change', 'store_delete']),
    _planned('fam.mixed.ticket_reassign', 'update a record field and grant the new owner access',
             'write + change_permissions, no read.', [('synthetic-helpdesk', 'reassign_ticket')],
             'Reassign a ticket to another agent.', S({'ticket_id': 'string', 'assignee': 'string'}),
             ['store_write:set', 'acl_change']),
    # no_effect
    _planned('fam.no_effect.json_validate', 'pure validation of a document against a schema',
             'Proven no-op over structured arguments.', [('synthetic-jsonlint', 'validate_json')],
             'Check a JSON document against a JSON schema.', S({'document': 'string', 'schema': 'object'}), []),
    _planned('fam.no_effect.rollout_plan', 'dry-run planner that returns a plan only',
             'No-op whose name suggests a deploy: hard negative for name-based shortcuts.',
             [('synthetic-deployplan', 'plan_rollout')], 'Compute a rollout plan without applying it.',
             S({'service': 'string', 'version': 'string'}), []),
    # unknown
    _planned('fam.unknown.plugin_job', 'record a job, then run an unmodelled plugin',
             'Partial unknown with a known WRITE (CP1 partial-unknown families only know read).',
             [('synthetic-pluginhost', 'run_plugin_job')], 'Record a job and run the named plugin on it.',
             S({'plugin': 'string', 'job_id': 'string'}), ['store_write:create', OPAQUE]),
    _planned('fam.unknown.notify_render', 'send a literal, then call an unmodelled renderer',
             'Partial unknown with a known SEND_DATA.', [('synthetic-notifier', 'notify_and_render')],
             'Send a notification, then render it with a custom template engine.',
             S({'to': 'string', 'text': 'string', 'engine': 'string'}), ['send:email', OPAQUE]),
    _planned('fam.unknown.partner_rpc', 'remote procedure call into a partner system',
             'Full unknown: effects happen in a system whose semantics are not admitted.',
             [('synthetic-partnerlink', 'call_partner_procedure')], 'Call a procedure on the partner system.',
             S({'procedure': 'string', 'args': 'object'}), [OPAQUE]),
    _planned('fam.unknown.extension_hook', 'trigger a third-party extension hook',
             'Full unknown: extension code is not part of the admitted semantics.',
             [('synthetic-extensions', 'trigger_extension')], 'Trigger an installed extension for an event.',
             S({'extension': 'string', 'event': 'string'}), [OPAQUE]),
    # added after the pre-freeze near-duplicate audit (2026-10-11): partner_rpc joined vendor_bridge (train), which
    # left a held-out split without a full-unknown family. Distinct target domain (managed hardware), distinct
    # argument roles (device, image, reboot flag; no free payload / operation selector).
    _planned('fam.unknown.firmware_flash', 'push a firmware image through a device-management agent',
             'Full unknown: effects happen inside the device firmware updater, whose semantics are not admitted; '
             'no read, write, delete, send or permission change is established or excluded.',
             [('synthetic-devicefleet', 'flash_firmware')], 'Install a firmware image on a managed device.',
             S({'device_id': 'string', 'image_ref': 'string', 'reboot': 'boolean'}), [OPAQUE]),
]


def _cp1_families():
    by_family = {}
    for spec in CASES:
        family_id, variant, profile = CP1_TEMPLATES[spec['id']]
        inp, src = spec['input'], spec['evidence_source']
        kind = {'fixture': 'controlled_execution'}.get(src['kind'], src['kind'])
        fixture = admitted_fixture(inp.get('server_id'), inp['tool_name'])
        world = src.get('world', REGISTRY[fixture][1] if fixture else {})
        args = inp['raw_arguments'] if isinstance(inp['raw_arguments'], dict) else {}
        fam = by_family.setdefault(family_id, {
            'family_id': family_id, **{k: v for k, v in CP1_FAMILY_META[family_id].items() if k != 'open_questions'},
            'identities': [], 'rejected_identities': [], 'descriptions': [], 'templates': [],
            'open_questions': list(CP1_FAMILY_META[family_id].get('open_questions', [])),
            'status': 'cp1_existing', 'source_material': 'sou13_v03_cp1', 'exposure': 'cp1_shared'})
        ident = [inp.get('server_id'), inp['tool_name']]
        bucket = fam['rejected_identities'] if spec['id'] in ADMISSION_TEST_CASES else fam['identities']
        if ident not in bucket:
            bucket.append(ident)
        if inp.get('tool_description') is not None and inp['tool_description'] not in fam['descriptions']:
            fam['descriptions'].append(inp['tool_description'])
        fam['templates'].append(_tpl(variant, inp['tool_schema'], profile, kind, world.get('disabled_actions', ()),
                                     arg_keys=list(args), cp1_cases=[spec['id']]))
    # New CP2 cases of a CP1 family use the declarative re-specification: one extra template per family with the
    # same schema/arguments/effect profile as its classification CP1 template but a different evidence kind.
    for fid, fam in by_family.items():
        repl = ADMITTED_REPLACEMENTS.get(fid, {})
        fam['identities'] += [i for i in repl.get('identities', []) if i not in fam['identities']]
        if get_catalog().get(fid, {}).get('n_new'):
            base = next((t for t in fam['templates'] if t['evidence_kind'] == 'controlled_execution'),
                        fam['templates'][0])
            fam['templates'].append(_tpl('decl', base['schema'], repl.get('decl_profile', base['effect_profile']),
                                         DECL, arg_keys=base['arg_keys']))
        desc = fam['descriptions']
        fam['honest_description'] = desc[0] if desc else None
        fam['misleading_description'] = None
    return list(by_family.values())


def _finalise(fam):
    fam = dict(fam)
    slug = fam['family_id'][len('fam.'):]
    fam['behavior_class'] = fam['family_id'].split('.')[1]
    fam['alias_group_id'] = 'ag.' + slug
    fam['identities'] = sorted(fam['identities'])
    fam['rejected_identities'] = sorted(fam.get('rejected_identities', []))
    fam['descriptions'] = sorted(fam['descriptions'])
    fam['normalized_names'] = sorted({normalized_name(t) for _, t in fam['identities'] + fam['rejected_identities']})
    fam['cp1_cases'] = sorted(c for t in fam['templates'] for c in t['cp1_cases'])
    templates = []
    for t in fam['templates']:
        t = dict(t)
        t['template_id'] = f"tpl.{slug}.{t['variant']}"
        t['signature'] = template_signature(t['schema'], t['arg_keys'], t['effect_profile'], t['evidence_kind'],
                                            t['disabled_actions'])
        t['shape_signature'] = shape_signature(t['schema'], t['effect_profile'], t['evidence_kind'],
                                               t['disabled_actions'])
        t['established_actions'] = sorted({EVENT_ACTION[e] for e in t['effect_profile'] if e in EVENT_ACTION},
                                          key=ACTIONS.index)
        t['unknown_profile'] = ('full' if t['evidence_kind'] == 'no_established_semantics'
                                or (OPAQUE in t['effect_profile'] and not t['established_actions'])
                                else 'partial' if OPAQUE in t['effect_profile'] else 'none')
        templates.append(t)
    fam['templates'] = sorted(templates, key=lambda t: t['template_id'])
    entry = get_catalog().get(fam['family_id'], {})
    fam['new_cases'] = entry.get('n_new', 0)
    fam['planned_cases'] = len(fam['cp1_cases']) + fam['new_cases']
    fam['pending_reasons'] = sorted(entry.get('pending') or [])
    fam['open_questions'] = sorted(set(fam['open_questions']) | set(fam['pending_reasons']))
    profiles = {t['unknown_profile'] for t in templates if t['evidence_kind'] != 'input_validation'}
    fam['coverage_stratum'] = (('unknown_full' if profiles == {'full'} else 'unknown_partial')
                               if fam['behavior_class'] == 'unknown' else fam['behavior_class'])
    # families whose new cases are pending (blocking open question) never count towards held-out coverage
    fam['coverage_eligible'] = not fam['pending_reasons']
    fam['program_skeleton'] = program_skeleton(entry.get('program'))  # None for families without a catalog program
    return fam


def families():
    """All families (CP1-backed + planned), finalised and sorted by family_id. `near_duplicates` lists the families
    adjudicated as field-renamed near-duplicates; leakage.family_item links them into one leakage component."""
    return attach_near_duplicates(sorted(
        (_finalise(f) for f in _cp1_families() + PLANNED_FAMILIES + restricted.declarations()),
        key=lambda f: f['family_id']))


def attach_near_duplicates(fams):
    reviews = shape_reviews(fams)
    for f in fams:
        f['near_duplicates'] = sorted(b if a == f['family_id'] else a for (a, b), r in reviews.items()
                                      if f['family_id'] in (a, b) and r['verdict'] == NEAR_DUPLICATE)
    return fams


# ---- Field-renamed near-duplicate review (pre-freeze near-duplicate audit, 2026-10-11) ----------------------------
# template_signature contains argument NAMES, so a re-described copy with renamed fields escapes it. Every pair of
# families sharing a shape_signature (types + effect profile + evidence kind, names ignored) must be adjudicated:
#   near_duplicate -> same tool behaviour re-described; linked into ONE leakage component (never split apart);
#   distinct       -> same class-level shape but a different tool (other object/target domain); rationale required.
# Shape alone never links: unrelated tools of one behaviour class routinely share it. Pairs involving a test family
# are adjudicated only in the custodian-only restricted file (declaration key `shape_review`).
NEAR_DUPLICATE, DISTINCT = 'near_duplicate', 'distinct'
_D = DISTINCT
SHAPE_REVIEW = {
    ('fam.unknown.partner_rpc', 'fam.unknown.vendor_bridge'): {
        'verdict': NEAR_DUPLICATE,
        'rationale': 'Same tool behaviour re-described: both programs are a single opaque call keyed by an operation '
                     'selector into the partner system (rpc:<procedure> / vendor_bridge:<operation>); the object '
                     'payload is forwarded and never modelled; schemas {procedure,args} and {operation,payload} differ '
                     'only in field names; descriptions are synonymous (call a procedure on the partner system / invoke '
                     'an operation on the partner integration).'},
    ('fam.change_permissions.link_share', 'fam.change_permissions.member_remove'): {
        'verdict': _D, 'rationale': 'acl_set enabling anyone-with-link access on a drive file vs acl_revoke of a '
                                    'principal from a directory group: different operation and domain.'},
    ('fam.delete.cache_purge', 'fam.delete.document_delete'): {
        'verdict': NEAR_DUPLICATE,
        'rationale': 'Owner decision 2026-10-11 (P-2, SAME_TEMPLATE): both programs are one delete of a single '
                     'argument key; schemas, effects and labels are identical; only the store constant, the field name '
                     'and the domain wording differ, which do not establish independence. Both stay in train.'},
    ('fam.delete.cache_purge', 'fam.delete.prefix_remove'): {
        'verdict': _D, 'rationale': 'Single cache key delete vs bulk delete_prefix over temporary objects: different '
                                    'operation (one key vs every key under a prefix).'},
    ('fam.delete.document_delete', 'fam.delete.prefix_remove'): {
        'verdict': _D, 'rationale': 'Document delete by id vs bulk delete_prefix: different operation and store.'},
    ('fam.write.flag_set', 'fam.write.migration_apply'): {
        'verdict': _D, 'rationale': 'Boolean feature-flag overwrite vs schema migration whose boolean selects a no-op '
                                    'dry-run plan: different store, mechanism and argument role.'},
}


def _pair(a, b):
    return tuple(sorted((a, b)))


def shape_reviews(fams):
    """{(family_a, family_b): {'verdict', 'rationale'}} from the public registry and restricted declarations."""
    out = {k: dict(v) for k, v in SHAPE_REVIEW.items()}
    for f in fams:
        for other, r in sorted((f.get('shape_review') or {}).items()):
            out[_pair(f['family_id'], other)] = dict(r)
    return out


def shape_candidates(fams):
    """Pairs of different families that share at least one template shape_signature."""
    owners = {}
    for f in fams:
        for t in f['templates']:
            owners.setdefault(t['shape_signature'], set()).add(f['family_id'])
    return sorted({_pair(a, b) for fs in owners.values() for a in fs for b in fs if a < b})


def same_skeleton(fa, fb):
    return fa.get('program_skeleton') is not None and fa.get('program_skeleton') == fb.get('program_skeleton')


def shape_review_errors(fams):
    """Every shared shape must be adjudicated. Owner rule (2026-10-11): equal shape AND equal execution-program
    skeleton is the same behavioural template; names, constants and domain wording alone never justify 'distinct'."""
    errors, ids = [], {f['family_id'] for f in fams}
    by_id = {f['family_id']: f for f in fams}
    reviews, cands = shape_reviews(fams), shape_candidates(fams)
    for a, b in cands:
        r = reviews.get((a, b))
        if r is None:
            errors.append(f'{a} and {b} share a field-name-insensitive template shape: adjudicate as '
                          f'{NEAR_DUPLICATE!r} or {DISTINCT!r} (unreviewed field-renamed near-duplicate candidate)')
        elif r.get('verdict') not in (NEAR_DUPLICATE, DISTINCT) or len(r.get('rationale') or '') < 20:
            errors.append(f'{a} / {b}: shape review needs a valid verdict and a rationale')
        elif r['verdict'] == DISTINCT and same_skeleton(by_id[a], by_id[b]):
            errors.append(f'{a} / {b}: same template shape AND same execution-program skeleton; differences in names, '
                          f'constants or domain do not establish independence: verdict must be {NEAR_DUPLICATE!r}')
    for a, b in reviews:
        if a in ids and b in ids and (a, b) not in cands and reviews[(a, b)].get('verdict') == DISTINCT:
            errors.append(f'{a} / {b}: stale shape review (no shared shape any more)')
    return errors


def _class_errors(fam):
    """The behaviour class must match what the family's templates establish."""
    cls, fid = fam['behavior_class'], fam['family_id']
    errors = []
    behavioural = [t for t in fam['templates'] if t['evidence_kind'] != 'input_validation']  # tech-error: no behaviour
    for t in behavioural:
        acts, unk = set(t['established_actions']), t['unknown_profile']
        # single-action classes may contain an argument-selected no-op mode (e.g. dry_run), never another action
        ok = {'shell': True,
              'unknown': unk != 'none',
              'no_effect': not acts and unk == 'none',
              'mixed': len(acts) >= 2 and unk == 'none'}.get(cls, acts <= {cls} and unk == 'none')
        if not ok:
            errors.append(f'{fid}: template {t["template_id"]} ({sorted(acts)}, unknown={unk}) contradicts class {cls}')
    if cls in ACTIONS and not any(set(t['established_actions']) == {cls} for t in behavioural):
        errors.append(f'{fid}: no template establishes {cls}')
    return errors


def taxonomy_errors(fams):
    """Structural and distinctness checks over the whole taxonomy (empty list = OK)."""
    errors = []
    ids = [f['family_id'] for f in fams]
    if len(ids) != len(set(ids)):
        errors.append('duplicate family_id')
    owners = {}
    for f in fams:
        fid = f['family_id']
        if not FAMILY_ID.match(fid):
            errors.append(f'{fid}: family_id must match fam.<behavior_class>.<slug>')
        if f['exposure'] not in EXPOSURES:
            errors.append(f'{fid}: invalid exposure {f["exposure"]}')
        if f['cp1_cases'] and f['exposure'] != 'cp1_shared':
            errors.append(f'{fid}: family with CP1 cases must have exposure cp1_shared')
        if not f['identities'] or not f['templates']:
            errors.append(f'{fid}: family needs at least one identity and one template')
        if not isinstance(f['planned_cases'], int) or f['planned_cases'] < max(1, len(f['cp1_cases'])):
            errors.append(f'{fid}: planned_cases must cover its CP1 cases')
        errors += _class_errors(f)
        for t in f['templates']:
            if t['evidence_kind'] not in EVIDENCE_KINDS:
                errors.append(f'{t["template_id"]}: invalid evidence_kind')
            unknown_events = [e for e in t['effect_profile'] if e not in EVENT_ACTION and e != OPAQUE]
            if unknown_events:
                errors.append(f'{t["template_id"]}: effect events outside the sandbox vocabulary: {unknown_events}')
        # every alias-defining value may belong to one family only
        rejected = f.get('rejected_identities', [])
        if any(i in f['identities'] for i in rejected):
            errors.append(f'{fid}: an identity cannot be both admitted and rejected')
        values = [('identity', '|'.join(map(str, i))) for i in f['identities'] + rejected]
        values += [('server', normalized_server(s)) for s, _ in f['identities'] + rejected if s]
        values += [('name', n) for n in f['normalized_names']]
        values += [('description', normalized_description(d)) for d in f['descriptions']]
        values += [('template_id', t['template_id']) for t in f['templates']]
        values += [('template_signature', t['signature']) for t in f['templates']]
        seen_here = set()
        for v in values:
            if v in seen_here and v[0] == 'template_signature':
                errors.append(f'{fid}: two templates with the same structural signature (near-duplicate inside family)')
            seen_here.add(v)
            if v[1] is None:
                continue
            other = owners.setdefault(v, fid)
            if other != fid:
                errors.append(f'{fid} and {other} share {v[0]}={v[1]!r}: aliases/near-duplicates must be one family')
    for f in fams:
        if not any(name_tokens(t) for _, t in f['identities']):
            errors.append(f'{f["family_id"]}: tool names normalise to nothing')
    return errors + shape_review_errors(fams)


def taxonomy_document(fams=None):
    from sou13.hashing import sha
    fams = sorted(families() if fams is None else fams, key=lambda f: f['family_id'])
    body ={'taxonomy_version': TAXONOMY_VERSION, 'behavior_classes': list(BEHAVIOR_CLASSES),
            'event_action_map': EVENT_ACTION, 'families': fams}
    return {**body, 'taxonomy_sha256': sha(body)}
