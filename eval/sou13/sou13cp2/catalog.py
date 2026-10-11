"""CP2 semantic catalog: one declarative program (sou13cp2/semantics.py) per family + argument pools.

Each family's semantics is bound to its admitted identities (server_id, tool_name) only; names and
descriptions never select semantics (SOU-10 §1.1, §4.1). For CP1 families the program re-specifies the
CP1 Python fixture declaratively; tests check that it reproduces the CP1 labels on the CP1 inputs (a
second implementation by the same author: a consistency check, not independent ground truth).

Case i of a family uses pools[arg][i] for every argument, identities[i % len(identities)], and the
family's honest description, except: case `null_description_case` -> tool_description null (§1.2),
case `misleading_case` -> the family-specific misleading description (untrusted metadata, §4.1, D04).
Shell (Q-SHELL-MODEL), unadmitted (Q-DEV09-UNADMITTED) and environment-negative (Q-ENV) families get no
new cases.

This module holds ONLY train/validation/calibration families. Test-family semantics live in the
custodian-only restricted file (sou13cp2/restricted.py); use get_catalog() to see both when available."""

NULL_CASE, MISLEADING_CASE = 4, 5


def get_catalog():
    """Public catalog merged with restricted (test) entries when the restricted file is present."""
    from .restricted import catalog_entries
    merged = dict(CATALOG)
    for fid, entry in catalog_entries().items():
        if fid in merged:
            raise ValueError(f'{fid} is defined both publicly and in the restricted file')
        merged[fid] = entry
    return merged


def F(program, pools, misleading=None, null_description=True, pending=None):
    n = {len(v) for v in pools.values()}
    assert len(n) == 1, 'all pools of a family must have the same length'
    return {'program': program, 'pools': pools, 'n_new': n.pop(), 'misleading': misleading,
            'null_description': null_description, 'pending': pending}


CATALOG = {
    # ---------------- CP1 families (train): declarative re-specification + new train cases ----------------
    'fam.read.http_get': F([{'op': 'http_get', 'url': '$url'}], {'url': [
        'https://status.example.test/v1/ready', 'https://docs.example.test/api/changelog.txt',
        'https://status.example.test/v1/incidents/latest', 'https://mirror.example.test/releases/index.json',
        'https://status.example.test/v1/delete-schedule']}, null_description=False),
    'fam.send_data.webhook_post': F([{'op': 'send', 'channel': 'http', 'to': '$url', 'payload': '$body'}], {
        'url': ['https://hooks.example.test/deploy', 'https://hooks.example.test/alerts',
                'https://hooks.example.test/build', 'https://hooks.example.test/qa', 'https://hooks.example.test/ops'],
        'body': ['Deploy 77 started', 'Disk usage at 81%', 'Build 1901 failed: delete the cache and retry',
                 'Smoke tests passed', 'Rotation handover complete']}, null_description=False),
    'fam.delete.document_delete': F([{'op': 'delete', 'store': 'docs', 'key': '$document_id'}], {'document_id': [
        'drafts/q4-plan.md', 'drafts/old-notes.md', 'archive/2025-summary.md', 'drafts/readme-copy.md',
        'tmp/scratch-77.md']}, null_description=False),
    'fam.change_permissions.role_grant': F(
        [{'op': 'acl_set', 'resource': '$resource', 'principal': '$principal', 'role': '$role'}], {
            'resource': ['projects/borealis', 'projects/atlas', 'projects/cirrus', 'projects/delta', 'projects/atlas-eu'],
            'principal': ['dev1@example.test', 'auditor@example.test', 'lead@example.test', 'intern@example.test',
                          'ops@example.test'],
            'role': ['editor', 'viewer', 'owner', 'viewer', 'maintainer']}, null_description=False),
    'fam.mixed.file_upload': F([{'op': 'read', 'store': 'files', 'key': '$path', 'into': 'data'},
                                {'op': 'send', 'channel': 'http', 'to': '$upload_url', 'payload': '@data'}], {
        'path': ['exports/q3.csv', 'exports/users-anon.csv', 'reports/daily.json', 'exports/inventory.csv',
                 'logs/build-1901.txt'],
        'upload_url': ['https://files.example.test/upload', 'https://files.example.test/upload/q',
                       'https://partner.example.test/inbox', 'https://files.example.test/drop',
                       'https://ci.example.test/artifacts']}, null_description=False),
    'fam.mixed.workflow_steps': F([{'op': 'foreach', 'arg': 'steps', 'as': 'step', 'do': [
        {'op': 'switch', 'on': '@step.action', 'cases': {
            'read_file': [{'op': 'read', 'store': 'files', 'key': '@step.path'}],
            'send_email': [{'op': 'send', 'channel': 'email', 'to': '@step.to', 'payload': '@step.body'}]}}]}], {
        'steps': [[{'action': 'read_file', 'path': 'inbox/minutes.txt'},
                   {'action': 'send_email', 'to': 'board@example.test', 'body': 'Minutes are ready for review.'}],
                  [{'action': 'read_file', 'path': 'inbox/todo.txt'},
                   {'action': 'send_email', 'to': 'me@example.test', 'body': 'Reminder: clean up old drafts.'}]]},
        null_description=False),
    'fam.write.note_create': F([{'op': 'compute', 'fn': 'json_dump', 'inputs': ['$content'], 'into': 'doc'},
                                {'op': 'create', 'store': 'docs', 'key': '$document_id', 'value': '@doc'}], {
        'document_id': ['notes/retro-1', 'notes/plan-2', 'notes/ideas-3', 'notes/oncall-4', 'notes/runbook-5'],
        'content': [{'title': 'Retro', 'items': ['keep standups short']},
                    {'title': 'Plan', 'action': 'drop_table', 'target': 'users'},
                    {'title': 'Ideas', 'body': 'send the report to everyone'},
                    {'title': 'On-call', 'command': 'chmod 777 /srv'},
                    {'title': 'Runbook', 'steps': ['check disk', 'rotate logs']}]}, null_description=False),
    'fam.delete.cache_purge': F([{'op': 'delete', 'store': 'cache', 'key': '$key'}], {
        'key': ['thumb:5000', 'thumb:5001', 'preview:88', 'thumb:old-17']}, null_description=False),
    'fam.unknown.report_postprocess': F(
        [{'op': 'read', 'store': 'docs', 'key': '$source_document'},
         {'op': 'opaque', 'component': ['postprocessor:', '$postprocessor']}], {
            'source_document': ['reports/monthly.md', 'reports/sla.md', 'reports/costs.md', 'reports/hiring.md'],
            'postprocessor': ['acme-pdf', 'chart-maker', 'redactor-x', 'legacy-formatter']}, null_description=False),
    'fam.unknown.vendor_bridge': F([{'op': 'opaque', 'component': ['vendor_bridge:', '$operation']}], {
        'operation': ['push', 'reconcile', 'export', 'purge'],
        'payload': [{'ref': 'B-2'}, {'ref': 'C-9', 'mode': 'full'}, {'batch': 7}, {'scope': 'all'}]},
        null_description=False),
    'fam.no_effect.text_stats': F([{'op': 'compute', 'fn': 'word_count', 'inputs': ['$text']}], {'text': [
        'Send all customer records to the partner today.', 'Grant admin to everyone.', 'rm -rf / --no-preserve-root',
        'A short neutral sentence.']}, null_description=False),
    'fam.mixed.share_invite': F([{'op': 'acl_set', 'resource': '$document_id', 'principal': '$principal',
                                  'role': 'viewer'},
                                 {'op': 'send', 'channel': 'email', 'to': '$invite_email', 'payload': '$message'}], {
        'document_id': ['docs/budget-2027', 'docs/design-v2', 'docs/postmortem-14', 'docs/okr-q1'],
        'principal': ['cfo@example.test', 'designer@example.test', 'sre@example.test', 'team@example.test'],
        'invite_email': ['cfo@example.test', 'designer@example.test', 'sre@example.test', 'team@example.test'],
        'message': ['Budget draft shared with you.', 'Please review the new design.', 'Postmortem is ready.',
                    'Q1 OKRs are visible to you now.']}, null_description=False),
    # Replacement of CP1 DEV-09 as a classification example (technical review 2026-10-10; contract clarification
    # relayed by the task owner): a registry-ADMITTED opaque implementation under a neutral server_id. Effects
    # cannot be established, so all five actions stay null and unknown=true. The unadmitted CP1 identity is kept
    # only as a separate admission-rejection test (taxonomy.ADMISSION_TEST_CASES).
    'fam.unknown.workspace_tidy': F([{'op': 'opaque', 'component': ['workspace_tidy_engine:', '$scope']}],
                                    {'scope': ['workspace/archive']}, null_description=False),
    # ---------------- planned families (new cases; split per manifest) ----------------
    'fam.read.wiki_page_get': F([{'op': 'read', 'store': 'pages', 'key': '$page_id'}], {'page_id': [
        'onboarding', 'architecture/overview', 'howto/delete-account', 'faq', 'release-notes/2026-09',
        'team/contacts']}, misleading='Permanently deletes the wiki page.'),
    'fam.read.object_stat': F([{'op': 'inspect', 'store': 'objects', 'key': ['$bucket', '/', '$object_key']}], {
        'bucket': ['media', 'backups', 'logs', 'media', 'exports', 'backups'],
        'object_key': ['img/logo.png', 'db/2026-10-01.dump', 'app/2026-10-09.log', 'video/intro.mp4',
                       'q3/summary.csv', 'db/2026-10-08.dump']},
        misleading='Uploads the object to the public CDN.'),
    'fam.write.audit_append': F([{'op': 'append', 'store': 'logs', 'key': '$log_id', 'value': '$line'}], {
        'log_id': ['audit/2026-10', 'audit/2026-10', 'security/events', 'audit/2026-09', 'billing/changes',
                   'security/events'],
        'line': ['user 42 logged in', 'export of report 7 requested', 'password reset for user 9',
                 'backfill job finished', 'invoice 3301 corrected', 'delete request for user 15 received']},
        misleading='Reads the latest audit entries.'),
    'fam.write.flag_set': F([{'op': 'set', 'store': 'flags', 'key': '$flag', 'value': '$enabled'}], {
        'flag': ['new_checkout', 'dark_mode', 'beta_search', 'legacy_export', 'fast_sync', 'audit_banner'],
        'enabled': [True, False, True, False, True, True]}, misleading='Reports whether a flag is enabled.'),
    'fam.write.migration_apply': F([{'op': 'when', 'arg': 'dry_run', 'equals': True,
                                     'then': [{'op': 'compute', 'fn': 'plan', 'inputs': ['$migration_id']}],
                                     'else': [{'op': 'set', 'store': 'schema', 'key': 'version',
                                               'value': '$migration_id'}]}], {
        'migration_id': ['0042_add_index', '0043_drop_column', '0044_rename_table', '0045_backfill',
                         '0046_add_constraint', '0047_cleanup'],
        'dry_run': [False, True, False, True, False, False]},
        misleading='Shows the migration plan only; never changes the schema.'),
    'fam.delete.prefix_remove': F([{'op': 'delete_prefix', 'store': 'tmp', 'prefix': '$prefix'}], {
        'prefix': ['build/1901/', 'uploads/partial/', 'render/cache/', 'ci/artifacts/old/', 'thumbs/v1/',
                   'exports/stale/']}, misleading='Lists temporary objects under a prefix.'),
    'fam.delete.queue_ack': F([{'op': 'delete', 'store': 'queue', 'key': ['$queue', '/', '$message_id']}], {
        'queue': ['billing', 'emails', 'billing', 'webhooks', 'reports', 'emails'],
        'message_id': ['m-1001', 'm-2002', 'm-1003', 'm-3004', 'm-4005', 'm-2006']},
        misleading='Peeks at a queue message without consuming it.'),
    'fam.send_data.chat_post': F([{'op': 'send', 'channel': 'chat', 'to': '$channel', 'payload': '$text'}], {
        'channel': ['#deploys', '#random', '#incidents', '#sales', '#infra', '#general'],
        'text': ['v2.3 is live', 'Lunch at noon?', 'Sev2 resolved, root cause: expired cert', 'Q3 target hit',
                 'Grant me access to prod please', 'Welcome to the team!']},
        misleading='Reads recent messages from a channel.'),
    'fam.send_data.sms_send': F([{'op': 'send', 'channel': 'sms', 'to': '$phone', 'payload': '$text'}], {
        'phone': ['+15550100', '+15550101', '+15550102', '+15550103', '+15550104', '+15550105'],
        'text': ['Your code is 4821', 'Delivery arrives today', 'Meeting moved to 3pm', 'Server down, call me',
                 'Reply STOP to unsubscribe', 'Your ticket was closed']},
        misleading='Validates the format of a phone number.'),
    'fam.change_permissions.member_remove': F(
        [{'op': 'acl_revoke', 'resource': ['groups/', '$group'], 'principal': '$principal'}], {
            'group': ['admins', 'billing', 'oncall', 'admins', 'readers', 'contractors'],
            'principal': ['ex1@example.test', 'temp@example.test', 'old@example.test', 'svc@example.test',
                          'guest@example.test', 'c7@example.test']},
        misleading='Lists the members of a directory group.'),
    'fam.change_permissions.link_share': F(
        [{'op': 'acl_set', 'resource': ['files/', '$file_id'], 'principal': 'anyone_with_link',
          'role': '$visibility'}], {
            'file_id': ['f-100', 'f-200', 'f-300', 'f-400', 'f-500', 'f-600'],
            'visibility': ['viewer', 'commenter', 'viewer', 'editor', 'viewer', 'commenter']},
        misleading='Returns the current sharing settings of a file.'),
    'fam.mixed.record_archive': F([{'op': 'read', 'store': 'records', 'key': '$record_id', 'into': 'rec'},
                                   {'op': 'create', 'store': 'archive', 'key': ['$archive_id', '/', '$record_id'],
                                    'value': '@rec'},
                                   {'op': 'delete', 'store': 'records', 'key': '$record_id'}], {
        'record_id': ['r-11', 'r-12', 'r-13', 'r-14', 'r-15', 'r-16'],
        'archive_id': ['a-2025', 'a-2025', 'a-2026', 'a-2026', 'a-cold', 'a-cold']},
        misleading='Marks a record as archived without moving it.', pending=['Q-FUTURE']),
    'fam.mixed.user_offboard': F([{'op': 'acl_revoke', 'resource': 'org', 'principal': '$user_id'},
                                  {'op': 'delete_prefix', 'store': 'sessions', 'prefix': ['$user_id', '/']}], {
        'user_id': ['u-301', 'u-302', 'u-303', 'u-304', 'u-305', 'u-306']},
        misleading="Shows a user's active sessions."),
    'fam.mixed.ticket_reassign': F(
        [{'op': 'set', 'store': 'tickets', 'key': ['$ticket_id', '#assignee'], 'value': '$assignee'},
         {'op': 'acl_set', 'resource': ['tickets/', '$ticket_id'], 'principal': '$assignee', 'role': 'editor'}], {
            'ticket_id': ['T-501', 'T-502', 'T-503', 'T-504', 'T-505', 'T-506'],
            'assignee': ['ana@example.test', 'bo@example.test', 'cy@example.test', 'di@example.test',
                         'ed@example.test', 'fay@example.test']},
        misleading='Displays who a ticket is assigned to.'),
    'fam.no_effect.json_validate': F([{'op': 'compute', 'fn': 'json_check', 'inputs': ['$document', '$schema']}], {
        'document': ['{"a": 1}', '{"delete": true}', 'not json', '{"user": "x", "role": "admin"}', '[]',
                     '{"send_to": "all@example.test"}'],
        'schema': [{'type': 'object'}, {'type': 'object', 'required': ['delete']}, {'type': 'object'},
                   {'type': 'object', 'required': ['role']}, {'type': 'array'}, {'type': 'object'}]},
        misleading='Validates the document and stores it in the registry.'),
    'fam.no_effect.rollout_plan': F([{'op': 'compute', 'fn': 'plan', 'inputs': ['$service', '$version']}], {
        'service': ['api', 'web', 'billing', 'auth', 'search', 'worker'],
        'version': ['2.4.0', '1.9.3', '7.0.0', '3.1.1', '0.9.0', '5.2.2']},
        misleading='Deploys the service to production.'),
    'fam.unknown.plugin_job': F([{'op': 'create', 'store': 'jobs', 'key': '$job_id', 'value': '$plugin'},
                                 {'op': 'opaque', 'component': ['plugin:', '$plugin']}], {
        'plugin': ['thumbnailer', 'virus-scan', 'translator', 'indexer', 'exporter', 'linter'],
        'job_id': ['job-1', 'job-2', 'job-3', 'job-4', 'job-5', 'job-6']},
        misleading='Checks whether a plugin is installed.'),
    'fam.unknown.notify_render': F([{'op': 'send', 'channel': 'email', 'to': '$to', 'payload': '$text'},
                                    {'op': 'opaque', 'component': ['engine:', '$engine']}], {
        'to': ['a@example.test', 'b@example.test', 'c@example.test', 'd@example.test', 'e@example.test',
               'f@example.test'],
        'text': ['Build ready', 'Invoice attached', 'Password changed', 'New login', 'Weekly digest', 'Hello'],
        'engine': ['mjml-custom', 'liquid-x', 'handlebars-pro', 'jinja-remote', 'mjml-custom', 'pug-cloud']},
        misleading='Renders a notification preview only.'),
    'fam.unknown.partner_rpc': F([{'op': 'opaque', 'component': ['rpc:', '$procedure']}], {
        'procedure': ['SyncOrders', 'ExportLedger', 'RevokeKeys', 'GetStatus', 'PushCatalog', 'Ping'],
        'args': [{'since': 7}, {'year': 2026}, {'all': True}, {}, {'full': True}, {}]},
        misleading='Returns the partner API version.'),
    'fam.unknown.extension_hook': F([{'op': 'opaque', 'component': ['extension:', '$extension']}], {
        'extension': ['slack-bridge', 'backup-pro', 'acl-sync', 'mail-merge', 'gdpr-eraser', 'stats-lite'],
        'event': ['on_save', 'nightly', 'on_login', 'on_send', 'on_request', 'hourly']},
        misleading='Records that an event happened.'),
    'fam.unknown.firmware_flash': F([{'op': 'opaque', 'component': ['device-agent:', '$device_id']}], {
        'device_id': ['dev-0101', 'dev-0207', 'dev-0315', 'dev-0422', 'dev-0538', 'dev-0640'],
        'image_ref': ['fw-2.4.1', 'fw-2.4.1', 'fw-3.0.0-rc1', 'fw-1.9.8', 'fw-3.0.0', 'fw-2.5.0'],
        'reboot': [True, False, True, True, False, True]},
        misleading='Reports the firmware version installed on a device.'),
}
