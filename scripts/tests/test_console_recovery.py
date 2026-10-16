# SPDX-License-Identifier: Apache-2.0
"""Real SQLite/age controls plus pre-execution PostgreSQL target guards."""
import io
import json
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import console_recovery as recovery

ROOT = Path(__file__).resolve().parents[2]
AGE = shutil.which('age')
KEYGEN = shutil.which('age-keygen')


def native_sqlite_schema():
    """Exercise accepted native DDL, not a competing test-local schema."""
    source = (ROOT / 'crates/proxy/src/tenant_store.rs').read_text()
    start = source.index('CREATE TABLE IF NOT EXISTS tenants (')
    result = source[start:source.index('\n                ",', start)]
    for filename, first in [('agent_enrollment.rs', 'managed_agent_enrollments'),
                            ('managed_policy.rs', 'managed_agent_revisions')]:
        source = (ROOT / 'crates/proxy/src/tenant_store' / filename).read_text()
        start = source.index('CREATE TABLE IF NOT EXISTS ' + first + ' (')
        result += '\n' + source[start:source.index(';",', start) + 1]
    return result


def native_group_schema():
    source = (ROOT / 'crates/proxy/src/tenant_store/managed_policy.rs').read_text()
    start = source.index('CREATE TABLE IF NOT EXISTS managed_agent_groups (')
    end = source.index(');",', start) + 2
    return source[start:end]


@contextmanager
def local_database(path):
    connection = sqlite3.connect(path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


@unittest.skipUnless(os.name == 'posix', 'owner-only POSIX recovery is explicit supported scope')
class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        os.chmod(self.directory, 0o700)
        self.work = self.directory / 'work'
        self.work.mkdir(mode=0o700)
        self.source = self.directory / 'source.sqlite'
        with local_database(self.source) as db:
            db.executescript(native_sqlite_schema())
            db.execute("INSERT INTO tenants VALUES ('tenant_a','Tenant A',1,1)")
            db.execute("INSERT INTO tenants VALUES ('tenant_b','Tenant B',1,1)")
            for label, active in [('retained', 1), ('revoked', 0)]:
                db.execute('INSERT INTO tenant_tokens VALUES (?,?,?,?,?,?,?)',
                           (label, 'tenant_a', bytes([active]) * 32, label, active, 1, None if active else 2))
            db.execute("INSERT INTO tenant_audit VALUES (999,'tenant_a',1,'/controlled','allowed',200,1)")
            db.execute('DELETE FROM tenant_audit WHERE id=999')
        os.chmod(self.source, 0o600)
        self.identity = self.directory / 'identity.age'
        self.archive = self.directory / 'backup.age'
        self.target = self.directory / 'recovered.sqlite'

    def age_identity(self, path=None):
        if not AGE or not KEYGEN:
            self.skipTest('native age and age-keygen required for encrypted recovery controls')
        path = path or self.identity
        subprocess.run([KEYGEN, '-o', str(path)], check=True, capture_output=True)
        os.chmod(path, 0o600)
        return subprocess.run([KEYGEN, '-y', str(path)], check=True, capture_output=True,
                              text=True).stdout.strip()

    def backup(self):
        return recovery.backup_sqlite(self.source, self.archive, self.age_identity(),
                                      workdir=self.work, age=AGE)

    def restore(self, target=None, identity=None):
        return recovery.restore_sqlite(self.archive, target or self.target,
            identity or self.identity, workdir=self.work, age=AGE)

    def rewrite_archive(self, mutate):
        plain = subprocess.run([AGE, '-d', '-i', str(self.identity), str(self.archive)],
                               capture_output=True, check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
            members = {member.name: archive.extractfile(member).read() for member in archive}
        mutate(members)
        contents = io.BytesIO()
        with tarfile.open(fileobj=contents, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, data in members.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        recipient = subprocess.run([KEYGEN, '-y', str(self.identity)], capture_output=True,
                                   text=True, check=True).stdout.strip()
        encrypted = subprocess.run([AGE, '-e', '-r', recipient], input=contents.getvalue(),
                                   capture_output=True, check=True).stdout
        self.archive.write_bytes(encrypted)

    def test_roundtrip_preserves_private_rows_revocation_sequences_and_source(self):
        source_bytes = self.source.read_bytes()
        before = recovery.inspect_sqlite(self.source)
        backed = self.backup()
        restored = self.restore()
        self.assertEqual(recovery.canonical(before), recovery.canonical(recovery.inspect_sqlite(self.target)))
        self.assertEqual(source_bytes, self.source.read_bytes())
        self.assertEqual(backed['private_state_sha256'], restored['private_state_sha256'])
        self.assertEqual(restored['tables_verified'], 43)
        self.assertFalse(restored['operator_signing_and_trust_restored'])
        self.assertEqual(list(self.work.iterdir()), [])
        with local_database(self.target) as connection:
            self.assertEqual(connection.execute('SELECT id,active,revoked_at_unix FROM tenant_tokens ORDER BY id').fetchall(),
                             [('retained', 1, None), ('revoked', 0, 2)])
            self.assertEqual(connection.execute("SELECT seq FROM sqlite_sequence WHERE name='tenant_audit'").fetchone(), (999,))
            connection.execute("INSERT INTO tenant_audit(tenant_id,created_at_unix,path,outcome,status_code,latency_ms) "
                               "VALUES ('tenant_a',1,'/after','allowed',200,1)")
            self.assertEqual(connection.execute('SELECT id FROM tenant_audit').fetchone(), (1000,))
        for path in (self.archive, self.target, self.identity):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b'Tenant A', self.archive.read_bytes())
        self.assertNotIn('tenant_a', json.dumps(restored))

    def test_public_cli_roundtrip_preserves_rows_sequences_and_revocation(self):
        recipient = self.age_identity()
        before = recovery.canonical(recovery.inspect_sqlite(self.source))
        source_bytes = self.source.read_bytes()
        common = ['--backend', 'sqlite', '--archive', str(self.archive),
                  '--workdir', str(self.work), '--age', AGE]
        commands = [
            ['backup', *common, '--database', str(self.source), '--recipient', recipient],
            ['restore', *common, '--database', str(self.target), '--identity', str(self.identity)],
        ]
        receipts = []
        for arguments in commands:
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/console-recovery.py'),
                *arguments], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd=self.directory,
                env=recovery.child_environment({}, self.work), timeout=30)
            # Never include captured diagnostics or private rows in failures.
            self.assertEqual(result.returncode, 0, 'Public recovery CLI failed.')
            self.assertEqual(result.stderr, b'', 'Public recovery CLI emitted diagnostics.')
            value = recovery.strict_json(result.stdout)
            self.assertEqual(set(value), {'format_version', 'status', 'phase', 'backend',
                'duration_seconds', 'inventory_sha256', 'operator_signing_and_trust_restored',
                'plaintext_temporary_cleaned', 'private_state_sha256', 'tables_verified',
                'sequences_verified', 'encrypted_archive_sha256'})
            self.assertEqual(value['format_version'], 1)
            self.assertEqual(value['status'], 'passed')
            self.assertEqual(value['phase'], arguments[0])
            self.assertEqual(value['backend'], 'sqlite')
            self.assertEqual(value['tables_verified'], 43)
            self.assertTrue(value['plaintext_temporary_cleaned'])
            self.assertFalse(value['operator_signing_and_trust_restored'])
            self.assertGreaterEqual(value['duration_seconds'], 0)
            self.assertNotIn('tenant_a', result.stdout.decode())
            self.assertNotIn('Tenant A', result.stdout.decode())
            receipts.append(value)
        self.assertEqual(receipts[0]['private_state_sha256'], receipts[1]['private_state_sha256'])
        self.assertEqual(receipts[0]['encrypted_archive_sha256'], receipts[1]['encrypted_archive_sha256'])
        self.assertEqual(before, recovery.canonical(recovery.inspect_sqlite(self.target)))
        self.assertEqual(source_bytes, self.source.read_bytes())
        self.assertEqual(list(self.work.iterdir()), [])
        with local_database(self.target) as connection:
            self.assertEqual(connection.execute(
                'SELECT id,active,revoked_at_unix FROM tenant_tokens ORDER BY id').fetchall(),
                [('retained', 1, None), ('revoked', 0, 2)])
            self.assertEqual(connection.execute(
                "SELECT seq FROM sqlite_sequence WHERE name='tenant_audit'").fetchone(), (999,))
            connection.execute("INSERT INTO tenant_audit(tenant_id,created_at_unix,path,outcome,status_code,latency_ms) "
                               "VALUES ('tenant_a',1,'/after-cli','allowed',200,1)")
            self.assertEqual(connection.execute('SELECT id FROM tenant_audit').fetchone(), (1000,))
        for path in (self.archive, self.target, self.identity):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_online_backup_includes_committed_wal(self):
        with local_database(self.source) as connection:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('PRAGMA wal_autocheckpoint=0')
            connection.execute("INSERT INTO tenants VALUES ('wal_tenant','WAL tenant',1,3)")
            connection.commit()
            self.assertTrue(Path(str(self.source) + '-wal').exists())
            self.backup()
            self.restore()
            with local_database(self.target) as target:
                self.assertEqual(target.execute("SELECT name FROM tenants WHERE id='wal_tenant'").fetchone(), ('WAL tenant',))

    def test_existing_empty_populated_source_symlink_and_sidecar_targets_refused(self):
        self.backup()
        original = self.source.read_bytes()
        for kind in ('empty', 'populated', 'source', 'symlink', 'sidecar'):
            with self.subTest(kind=kind):
                target = self.directory / ('target-' + kind)
                if kind == 'empty':
                    target.write_bytes(b'')
                elif kind == 'populated':
                    target.write_bytes(b'owned populated sentinel')
                elif kind == 'source':
                    target = self.source
                elif kind == 'symlink':
                    target.symlink_to(self.source)
                else:
                    Path(str(target) + '-wal').write_bytes(b'sentinel')
                with self.assertRaises(recovery.RecoveryError):
                    self.restore(target)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.work.iterdir()), [])

    def test_wrong_key_and_ciphertext_corruption_never_create_target(self):
        self.backup()
        other = self.directory / 'wrong.age'
        self.age_identity(other)
        with self.assertRaises(recovery.RecoveryError):
            self.restore(identity=other)
        data = bytearray(self.archive.read_bytes())
        data[-30] ^= 1
        self.archive.write_bytes(data)
        with self.assertRaises(recovery.RecoveryError):
            self.restore()
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.work.iterdir()), [])

    def test_incomplete_tampered_schema_inventory_and_path_traversal_refused_before_write(self):
        self.backup()
        valid = self.archive.read_bytes()
        def change_manifest(members, field, value):
            manifest = json.loads(members['manifest.json'])
            manifest[field] = value
            members['manifest.json'] = recovery.canonical(manifest)
        mutations = {
            'missing': lambda members: members.pop('state.json'),
            'dump-integrity': lambda members: members.__setitem__('database.dump', b'bad dump'),
            'schema': lambda members: change_manifest(members, 'schema_version', recovery.inventory()['postgres_schema_version'] + 1),
            'inventory': lambda members: members.__setitem__('inventory.json', b'{}'),
            'path': lambda members: members.__setitem__('../outside', b'not extracted'),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.archive.write_bytes(valid)
                self.rewrite_archive(mutate)
                with self.assertRaises(recovery.RecoveryError):
                    self.restore()
                self.assertFalse(self.target.exists())
                self.assertFalse((self.directory / 'outside').exists())
                self.assertEqual(list(self.work.iterdir()), [])

    def test_archive_no_overwrite_and_failed_encryption_cleanup(self):
        self.backup()
        original = self.archive.read_bytes()
        with self.assertRaises(recovery.RecoveryError):
            recovery.backup_sqlite(self.source, self.archive, 'age1' + 'a' * 58,
                                  workdir=self.work, age=AGE)
        self.assertEqual(self.archive.read_bytes(), original)
        self.archive.unlink()
        with self.assertRaises(recovery.RecoveryError):
            recovery.backup_sqlite(self.source, self.archive, 'age1' + 'a' * 58,
                                  workdir=self.work, age='/nonexistent/age')
        self.assertFalse(self.archive.exists())
        self.assertEqual(list(self.work.iterdir()), [])

    def test_native_schema_future_column_or_disabled_immutability_refused(self):
        with local_database(self.source) as connection:
            connection.execute('DROP TRIGGER tenant_policy_versions_no_update')
        with self.assertRaisesRegex(recovery.RecoveryError, 'schema objects'):
            recovery.inspect_sqlite(self.source)
        with local_database(self.source) as connection:
            connection.executescript(native_sqlite_schema())
            connection.execute('ALTER TABLE tenants ADD COLUMN future_field TEXT')
        with self.assertRaises(recovery.RecoveryError):
            recovery.inspect_sqlite(self.source)

    def test_permissions_and_file_aliases_fail_closed(self):
        os.chmod(self.work, 0o755)
        with self.assertRaises(recovery.RecoveryError):
            recovery.private_directory(self.work)
        os.chmod(self.work, 0o700)
        os.chmod(self.source, 0o644)
        with self.assertRaises(recovery.RecoveryError):
            recovery.inspect_sqlite(self.source)
        os.chmod(self.source, 0o600)
        alias = self.directory / 'hardlink'
        alias.hardlink_to(self.source)
        with self.assertRaises(recovery.RecoveryError):
            recovery.inspect_sqlite(alias)

    def test_lazy_managed_tables_can_be_absent_but_partial_dependency_cannot(self):
        with local_database(self.source) as connection:
            connection.execute('DROP TABLE managed_agent_deployments')
            connection.execute('DROP TABLE managed_agent_revisions')
            connection.execute('DROP TABLE managed_agent_enrollments')
        state = recovery.inspect_sqlite(self.source)
        self.assertEqual(len(state['tables']), 40)
        with local_database(self.source) as connection:
            connection.executescript(native_sqlite_schema())
            connection.execute('DROP TABLE managed_agent_deployments')
        with self.assertRaises(recovery.RecoveryError):
            recovery.inspect_sqlite(self.source)

    def test_group_snapshot_column_upgrade_preserves_recovery_inventory(self):
        legacy = native_group_schema().replace("initial_sequences_json TEXT NOT NULL DEFAULT '{}',", '')
        with local_database(self.source) as connection:
            connection.executescript(legacy)
            connection.execute("INSERT INTO managed_agent_groups VALUES ('tenant_a','legacy','Legacy',100)")
            connection.execute("ALTER TABLE managed_group_rollouts ADD COLUMN initial_sequences_json TEXT NOT NULL DEFAULT '{}'")
        state = recovery.inspect_sqlite(self.source)
        self.assertEqual(len(state['tables']), 47)
        self.assertEqual(state['tables']['managed_agent_groups']['rows'][0][1], ['text', 'legacy'])

    def test_populated_group_recovery_control(self):
        with local_database(self.source) as connection:
            connection.executescript(native_group_schema())
            connection.execute("INSERT INTO managed_agent_enrollments(tenant_id,agent_id,token_hash,created_at_unix,revoked_at_unix) VALUES ('tenant_a','agent_1',X'0102',100,NULL)")
            connection.execute("INSERT INTO managed_agent_groups VALUES ('tenant_a','grp_1','Group 1',100)")
            connection.execute("INSERT INTO managed_agent_group_members VALUES ('tenant_a','grp_1','agent_1',1,100)")
            connection.execute("INSERT INTO managed_group_revisions VALUES ('tenant_a','grp_1','v1','default: allow\\n','sha_v1',100)")
            connection.execute("INSERT INTO managed_group_rollouts (tenant_id,group_id,rollout_id,revision,policy_sha256,issuer_key_id,phase,pilot_agents_json,standard_agents_json,active_deployments_json,previous_revisions_json,failure_reason,created_at_unix,updated_at_unix) VALUES ('tenant_a','grp_1','r_1','v1','sha_v1',NULL,'completed','[]','[]','{}','{}',NULL,100,100)")
        state = recovery.inspect_sqlite(self.source)
        self.assertEqual(len(state['tables']), 47)
        self.assertEqual(state['tables']['managed_agent_groups']['rows'],
                         [[['text', 'tenant_a'], ['text', 'grp_1'], ['text', 'Group 1'], ['integer', 100]]])
        with local_database(self.source) as connection:
            connection.execute('DROP TABLE managed_agent_group_members')
        with self.assertRaisesRegex(recovery.RecoveryError, 'Incomplete managed group schema'):
            recovery.inspect_sqlite(self.source)

    def test_postgres_alias_and_populated_guards_precede_restore_executor(self):
        # Genuine age archive decoding plus the actual production guard ordering.
        recipient = self.age_identity()
        state = {'backend': 'postgres', 'schema_version':28,
                 'schema':recovery.inventory().get('postgres_schema'),
                 'tables': {name: [] for name in recovery.inventory()['postgres_tables']},
                 'sequences': {name: {'last_value':1,'is_called':False}
                               for name in recovery.inventory()['postgres_sequences']}}
        source_id = {'system_identifier': '123', 'database_oid': '456', 'database_name': 'source'}
        with recovery.temporary(self.work) as directory:
            dump = directory / 'database.dump'
            recovery.write_private(dump, b'custom-format-placeholder')
            plain = recovery.pack_archive(directory, 'postgres', source_id, state, dump)
            recovery.encrypt_archive(plain, self.archive, recipient, directory, AGE)
        for mode in ('alias', 'populated'):
            calls = []
            class FakeBackend:
                def __init__(self, *args, **kwargs):
                    pass
                def identity(self):
                    # Different route/URL never changes observed cluster+DBOID.
                    return dict(source_id) if mode == 'alias' else dict(source_id, database_oid='789')
                def require_owned(self):
                    calls.append('owned')
                def require_empty(self):
                    calls.append('empty')
                    raise recovery.RecoveryError('PostgreSQL restore target is populated.')
                def invoke(self, argv):
                    calls.append(argv)
                    raise AssertionError('no executor may run for rejected targets')
            with self.subTest(mode=mode), patch.object(recovery, 'PostgresBackend', FakeBackend):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.restore_postgres(self.archive,
                        'postgresql://owned:private@127.0.0.1:5555/alias?sslmode=disable',
                        self.identity, workdir=self.work, age=AGE)
                self.assertEqual(calls, [] if mode == 'alias' else ['owned', 'empty'])
        self.assertEqual(list(self.work.iterdir()), [])

    def test_pg_url_environment_scrubbing_and_source_quiescence(self):
        environment = recovery.postgres_environment('postgresql://owned:private@127.0.0.1:5555/source?sslmode=disable')
        self.assertEqual(environment['PGDATABASE'], 'source')
        self.assertEqual(environment['PGPORT'], '5555')
        self.assertEqual(environment['PGHOST'], '127.0.0.1')
        self.assertEqual(environment['PGUSER'], 'owned')
        self.assertEqual(environment['PGPASSWORD'], 'private')
        with patch.dict(os.environ, {'PGHOST': 'unowned.example', 'PGOPTIONS': '-c bogus=on', 'AWS_SECRET_ACCESS_KEY': 'secret'}):
            child = recovery.child_environment(environment, self.work)
        self.assertEqual(child['PGHOST'], '127.0.0.1')
        self.assertEqual(child['PGDATABASE'], 'source')
        self.assertEqual(child['PGPASSWORD'], 'private')
        self.assertNotIn('PGOPTIONS', child)
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', child)
        for value in ('postgresql://host/db', 'postgresql://host/db?sslmode=disable',
                      'postgresql://127.0.0.1/db?sslmode=disable&host=unowned.example',
                      'postgresql://owned:private@127.0.0.1:0/db?sslmode=disable',
                      'postgresql://owned:secret%0Avalue@127.0.0.1/db?sslmode=disable'):
            with self.assertRaises(recovery.RecoveryError):
                recovery.postgres_environment(value)
        with patch.object(recovery, 'PostgresBackend') as backend:
            with self.assertRaises(recovery.RecoveryError):
                recovery.backup_postgres('unused', self.archive, 'unused', workdir=self.work)
            backend.assert_not_called()

    def test_unknown_sqlite_explicit_schema_and_application_versions_refused(self):
        for pragma in ('user_version', 'application_id'):
            with self.subTest(pragma=pragma):
                with local_database(self.source) as connection:
                    connection.execute('PRAGMA ' + pragma + '=27')
                with self.assertRaisesRegex(recovery.RecoveryError, 'unsupported explicit schema'):
                    recovery.inspect_sqlite(self.source)
                with local_database(self.source) as connection:
                    connection.execute('PRAGMA ' + pragma + '=0')

    def test_pg_empty_target_also_refuses_views_functions_types_and_extra_schemas(self):
        backend = recovery.PostgresBackend('postgresql://owned:private@127.0.0.1:5555/target?sslmode=disable', directory=self.work)
        with patch.object(backend, 'catalog', return_value={'tables': [], 'sequences': [], 'unexpected': 0}), \
             patch.object(backend, 'sql', return_value='1'):
            with self.assertRaises(recovery.RecoveryError):
                backend.require_empty()


if __name__ == '__main__':
    unittest.main()
