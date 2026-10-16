# SPDX-License-Identifier: Apache-2.0
"""Owner-private, age-encrypted Console recovery for the accepted schema.

No application startup, migration, signing key, trust-root update, dispatcher or
provider is launched here. PostgreSQL backups require all source writers stopped;
pg_dump supplies the consistent transaction and before/after snapshots detect
observed violations. Restoring verifies every private row and sequence before a
caller may start the recovered Console. Public receipts never contain rows/URLs.
"""
from contextlib import closing, contextmanager
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import time
from urllib.parse import parse_qsl, unquote, urlsplit

INVENTORY_PATH = Path(__file__).parent / 'fixtures' / 'console_recovery_inventory_v1.json'
FORMAT_VERSION = 1
MAX_FILE = 256 * 1024 * 1024
NAME = re.compile(r'[a-z_][a-z0-9_]{0,62}\Z')
RECIPIENT = re.compile(r'age1[0-9a-z]{58}\Z')
FILES = {'manifest.json', 'inventory.json', 'state.json', 'database.dump'}


class RecoveryError(Exception):
    """A public-safe fixed diagnostic; subprocess output is never interpolated."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def strict_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate key')
            value[key] = item
        return value
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise RecoveryError('Invalid recovery JSON.') from None


def inventory():
    value = strict_json(INVENTORY_PATH.read_bytes())
    if value.get('format_version') != FORMAT_VERSION or value.get('postgres_schema_version') != 27:
        raise RecoveryError('Unsupported recovery inventory.')
    return value


def private_directory(path):
    if os.name != 'posix':
        raise RecoveryError('Recovery requires POSIX owner-only file permissions.')
    try:
        path = Path(path).absolute()
        metadata = path.lstat()
        if (path.resolve() != path or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
            raise ValueError
    except (OSError, ValueError, RuntimeError):
        raise RecoveryError('Recovery directories must be real owner-only directories (0700).') from None
    return path


def private_file(path):
    try:
        path = Path(path).absolute()
        private_directory(path.parent)
        metadata = path.lstat()
        if (path.resolve() != path or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1):
            raise ValueError
    except (OSError, ValueError, RuntimeError):
        raise RecoveryError('Recovery files must be real owner-only files (0600) without aliases.') from None
    return path


def new_private_file(path):
    path = Path(path).absolute()
    private_directory(path.parent)
    try:
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise RecoveryError('Refusing an existing or redirected recovery artifact.') from None


def write_private(path, data):
    fd = new_private_file(path)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        raise RecoveryError('Could not write a private recovery artifact.') from None


@contextmanager
def temporary(workdir):
    parent = private_directory(workdir)
    # Python's mkdtemp reserves mode 0700 atomically. Native tools inherit this
    # directory as their scratch path; every plaintext artifact is removed.
    with tempfile.TemporaryDirectory(prefix='console-recovery-', dir=parent) as name:
        yield private_directory(name)


def child_environment(overrides, temporary_directory):
    allowed = {'PATH', 'SYSTEMROOT', 'WINDIR', 'LANG', 'LC_ALL',
               'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH'}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment.update({key: str(temporary_directory) for key in ('HOME', 'TMPDIR', 'TMP', 'TEMP')})
    environment.update(overrides)
    return environment


def checked(argv, *, directory, environment=None, stdin=None):
    try:
        result = subprocess.run([str(x) for x in argv], input=stdin,
            cwd=directory, env=child_environment(environment or {}, directory),
            capture_output=True, timeout=300, check=True)
        if len(result.stdout) > MAX_FILE or len(result.stderr) > MAX_FILE:
            raise RecoveryError('Recovery tool output exceeded its limit.')
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        raise RecoveryError('A recovery tool failed; private output was withheld.') from None


def validate_columns(actual, expected):
    if actual != expected:
        raise RecoveryError('Console schema columns or types do not match the versioned inventory.')


def encode_sqlite(value):
    # Preserve SQLite storage classes, including BLOB hashes and bool-vs-integer
    # distinctions in the serialized inventory. JSON alone is insufficient.
    if value is None:
        return ['null', None]
    if type(value) is bytes:
        return ['blob', value.hex()]
    if type(value) is int:
        return ['integer', value]
    if type(value) is float and math.isfinite(value):
        return ['real', value.hex()]
    if type(value) is str:
        return ['text', value]
    raise RecoveryError('An unsupported SQLite value was encountered.')


@contextmanager
def sqlite_connection(path):
    path = private_file(path)
    try:
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=10)
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA query_only=ON')
        try:
            yield connection
        finally:
            connection.close()
    except sqlite3.Error:
        raise RecoveryError('Could not open the selected SQLite source read-only.') from None


def normalize_sql(sql):
    # Preserve quoted SQL strings and identifiers, ignore formatting outside.
    return ''.join(re.findall(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|[^\s'\"]+", sql))


def inspect_sqlite(path):
    definition = inventory()
    try:
        with sqlite_connection(path) as connection:
            connection.execute('BEGIN')
            if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise RecoveryError('SQLite integrity verification failed.')
            if connection.execute('PRAGMA foreign_key_check').fetchall():
                raise RecoveryError('SQLite foreign key verification failed.')
            objects = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
            if any(row[0] not in {'table', 'index', 'trigger'} for row in objects):
                raise RecoveryError('Unsupported SQLite schema objects.')
            tables = {row[1] for row in objects if row[0] == 'table'}
            expected = definition['sqlite_tables']
            optional = set(definition['sqlite_optional_tables'])
            if not set(expected) - optional <= tables or not tables <= set(expected):
                raise RecoveryError('SQLite tables do not match the versioned inventory.')
            if ('managed_agent_revisions' in tables) != ('managed_agent_deployments' in tables):
                raise RecoveryError('Incomplete managed Agent schema.')
            if 'managed_agent_revisions' in tables and 'managed_agent_enrollments' not in tables:
                raise RecoveryError('Incomplete managed Agent schema.')
            group_tables = {'managed_agent_groups', 'managed_agent_group_members',
                            'managed_group_revisions', 'managed_group_rollouts'}
            if tables & group_tables and not group_tables <= tables:
                raise RecoveryError('Incomplete managed group schema.')
            if group_tables <= tables and 'managed_agent_enrollments' not in tables:
                raise RecoveryError('Incomplete managed Agent schema.')
            expected_objects = {name: value for name, value in definition['sqlite_objects'].items()
                                if value['table'] in tables}
            actual_objects = {name: {'type': kind, 'table': table,
                              'ddl_sha256': digest(normalize_sql(sql).encode())}
                              for kind, name, table, sql in objects}
            if actual_objects != expected_objects:
                raise RecoveryError('SQLite schema objects differ from accepted native schema.')
            state = {'backend': 'sqlite', 'schema_contract': definition['sqlite_schema_contract'],
                     'schema': objects, 'tables': {}, 'sequences': {}}
            for name in sorted(tables):
                columns = connection.execute(f'PRAGMA table_xinfo("{name}")').fetchall()
                if any(row[6] != 0 for row in columns):
                    raise RecoveryError('Unsupported generated or hidden SQLite columns.')
                validate_columns({row[1]: row[2].upper() for row in columns}, expected[name])
                rows = [[encode_sqlite(cell) for cell in row]
                        for row in connection.execute(f'SELECT * FROM "{name}"')]
                state['tables'][name] = {'columns': [row[1] for row in columns],
                                         'rows': sorted(rows, key=canonical)}
            if connection.execute("SELECT 1 FROM sqlite_schema WHERE name='sqlite_sequence'").fetchone():
                state['sequences'] = dict(connection.execute('SELECT name,seq FROM sqlite_sequence ORDER BY name'))
            if not set(state['sequences']) <= tables:
                raise RecoveryError('Unexpected SQLite sequence state.')
            state['pragmas'] = {name: connection.execute('PRAGMA ' + name).fetchone()[0]
                                for name in ('user_version', 'application_id', 'encoding')}
            if state['pragmas']['user_version'] != 0 or state['pragmas']['application_id'] != 0:
                raise RecoveryError('SQLite has an unsupported explicit schema or application version.')
            connection.rollback()
            return state
    except sqlite3.Error:
        raise RecoveryError('SQLite schema or private state verification failed.') from None


def sqlite_identity(path):
    metadata = private_file(path).stat()
    return {'device': metadata.st_dev, 'inode': metadata.st_ino}


def receipt(phase, backend, started, state=None, archive=None):
    value = {'format_version': FORMAT_VERSION, 'status': 'passed', 'phase': phase,
             'backend': backend, 'duration_seconds': round(time.monotonic() - started, 6),
             'inventory_sha256': digest(canonical(inventory())),
             'operator_signing_and_trust_restored': False, 'plaintext_temporary_cleaned': True}
    if state is not None:
        value.update(private_state_sha256=digest(canonical(state)),
                     tables_verified=len(state['tables']), sequences_verified=len(state['sequences']))
    if archive is not None:
        value['encrypted_archive_sha256'] = digest(Path(archive).read_bytes())
    return value


def pack_archive(directory, backend, identity, state, dump):
    raw_inventory = canonical(inventory())
    raw_state = canonical(state)
    files = {'inventory.json': raw_inventory, 'state.json': raw_state, 'database.dump': dump.read_bytes()}
    if any(len(data) > MAX_FILE for data in files.values()):
        raise RecoveryError('Recovery archive exceeds the supported size limit.')
    manifest = {'format_version': FORMAT_VERSION, 'backend': backend,
                'source_identity': identity, 'accepted_source': inventory()['accepted_source'],
                'schema_version': 27, 'inventory_sha256': digest(raw_inventory),
                'files': {name: {'bytes': len(data), 'sha256': digest(data)} for name, data in files.items()}}
    files['manifest.json'] = canonical(manifest)
    path = directory / 'archive.tar'
    fd = new_private_file(path)
    with os.fdopen(fd, 'wb') as handle, tarfile.open(fileobj=handle, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.uid, member.gid, member.mtime = len(data), 0o600, 0, 0, 0
            archive.addfile(member, io.BytesIO(data))
    return path


def encrypt_archive(plain, output, recipient, directory, age):
    if not isinstance(recipient, str) or not RECIPIENT.fullmatch(recipient):
        raise RecoveryError('An explicit native age recipient is required.')
    # Reserve the final path before invoking native tools. Never overwrite an
    # old backup; failed encryption removes only this newly owned reservation.
    fd = new_private_file(output)
    os.close(fd)
    encrypted = directory / 'encrypted.age'
    try:
        checked([age, '--encrypt', '--recipient', recipient, '--output', encrypted, plain], directory=directory)
        os.chmod(encrypted, 0o600)
        private_file(encrypted)
        with Path(output).open('wb') as target, encrypted.open('rb') as source:
            shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())
    except Exception:
        Path(output).unlink(missing_ok=True)
        raise



def validate_private_state(state, backend):
    definition = inventory()
    if (not isinstance(state, dict) or state.get('backend') != backend
            or not isinstance(state.get('tables'), dict) or not isinstance(state.get('sequences'), dict)):
        raise RecoveryError('Invalid recovery private inventory.')
    if backend != 'postgres':
        return  # SQLite's full image is independently inspected before target creation.
    if (set(state) != {'backend', 'schema_version', 'tables', 'sequences', 'schema'}
            or type(state['schema_version']) is not int or state['schema_version'] != 27
            or canonical(state.get('schema')) != canonical(definition.get('postgres_schema'))
            or not isinstance(state.get('schema'),dict)
            or set(state['tables']) != set(definition['postgres_tables'])
            or set(state['sequences']) != set(definition['postgres_sequences'])):
        raise RecoveryError('Incomplete PostgreSQL private inventory.')
    for name, rows in state['tables'].items():
        columns = definition['postgres_tables'][name]
        if not isinstance(rows, list):
            raise RecoveryError('Invalid PostgreSQL private table inventory.')
        for row in rows:
            if not isinstance(row, dict) or set(row) != set(columns):
                raise RecoveryError('Incomplete PostgreSQL private row inventory.')
            for key, value in row.items():
                expected_type = columns[key]
                if value is None:
                    continue
                valid = ((expected_type in {'BIGINT', 'BIGSERIAL', 'INTEGER'} and type(value) is int)
                         or (expected_type == 'BOOLEAN' and type(value) is bool)
                         or (expected_type in {'TEXT', 'BYTEA'} and type(value) is str))
                if not valid:
                    raise RecoveryError('Invalid PostgreSQL private row types.')
    for value in state['sequences'].values():
        if (not isinstance(value, dict) or set(value) != {'last_value', 'is_called'}
                or type(value['last_value']) is not int or type(value['is_called']) is not bool):
            raise RecoveryError('Invalid PostgreSQL private sequence inventory.')


@contextmanager
def decrypted_archive(archive, identity, *, workdir, age='age'):
    archive, identity = private_file(archive), private_file(identity)
    if archive.stat().st_size > MAX_FILE * 4:
        raise RecoveryError('Encrypted archive exceeds its supported size limit.')
    with temporary(workdir) as directory:
        plain = directory / 'archive.tar'
        checked([age, '--decrypt', '--identity', identity, '--output', plain, archive], directory=directory)
        os.chmod(plain, 0o600)
        members = {}
        payload_end = 0
        try:
            with tarfile.open(plain, 'r:') as container:
                for member in container:
                    if (member.name not in FILES or member.name in members or not member.isfile()
                            or member.size < 0 or member.size > MAX_FILE
                            or member.linkname or member.pax_headers):
                        raise RecoveryError('Invalid or unexpected recovery archive member.')
                    data = container.extractfile(member).read(MAX_FILE + 1)
                    if len(data) != member.size:
                        raise RecoveryError('Truncated recovery archive member.')
                    members[member.name] = data
                    payload_end = member.offset_data + ((member.size + 511) // 512) * 512
            with plain.open('rb') as container:
                container.seek(payload_end)
                trailer = container.read()
                if len(trailer) < 1024 or any(trailer) or plain.stat().st_size % 512:
                    raise RecoveryError('Recovery archive has invalid trailing data.')
        except (tarfile.TarError, OSError, EOFError):
            raise RecoveryError('Invalid or truncated recovery archive.') from None
        if set(members) != FILES:
            raise RecoveryError('Incomplete recovery archive.')
        manifest = strict_json(members['manifest.json'])
        required = {'format_version', 'backend', 'source_identity', 'accepted_source', 'schema_version',
                    'inventory_sha256', 'files'}
        if (not isinstance(manifest, dict) or set(manifest) != required
                or type(manifest['format_version']) is not int or manifest['format_version'] != FORMAT_VERSION
                or type(manifest['schema_version']) is not int or manifest['schema_version'] != 27
                or manifest['backend'] not in {'sqlite', 'postgres'}
                or manifest['accepted_source'] != inventory()['accepted_source']
                or not isinstance(manifest['source_identity'], dict)):
            raise RecoveryError('Unsupported recovery schema or manifest.')
        expected_inventory = canonical(inventory())
        if (members['inventory.json'] != expected_inventory
                or manifest['inventory_sha256'] != digest(expected_inventory)):
            raise RecoveryError('Recovery inventory is incompatible.')
        if not isinstance(manifest['files'], dict) or set(manifest['files']) != FILES - {'manifest.json'}:
            raise RecoveryError('Recovery manifest file inventory is incomplete.')
        for name, metadata in manifest['files'].items():
            if (not isinstance(metadata, dict) or set(metadata) != {'bytes', 'sha256'}
                    or type(metadata['bytes']) is not int or metadata['bytes'] != len(members[name])
                    or metadata['sha256'] != digest(members[name])):
                raise RecoveryError('Recovery archive integrity verification failed.')
        state = strict_json(members['state.json'])
        validate_private_state(state, manifest['backend'])
        dump = directory / 'database.dump'
        write_private(dump, members['database.dump'])
        yield manifest, state, dump, directory


def backup_sqlite(source, output, recipient, *, workdir, age='age'):
    started = time.monotonic()
    source = private_file(source)
    identity = sqlite_identity(source)
    with temporary(workdir) as directory:
        dump = directory / 'sqlite.backup'
        fd = new_private_file(dump)
        os.close(fd)
        try:
            # SQLite online backup includes committed WAL content and supplies a
            # coherent database image without copying a live main file alone.
            with sqlite_connection(source) as original, closing(sqlite3.connect(dump)) as copied:
                deadline = time.monotonic() + 300
                def progress(_status, _remaining, _total):
                    if time.monotonic() > deadline:
                        raise RecoveryError('Consistent SQLite backup exceeded its time bound.')
                original.backup(copied, pages=256, sleep=0.01, progress=progress)
            state = inspect_sqlite(dump)
        except sqlite3.Error:
            raise RecoveryError('Consistent SQLite backup failed.') from None
        if sqlite_identity(source) != identity:
            raise RecoveryError('SQLite source identity changed during backup.')
        plain = pack_archive(directory, 'sqlite', identity, state, dump)
        encrypt_archive(plain, output, recipient, directory, age)
    return receipt('backup', 'sqlite', started, state, output)


def restore_sqlite(archive, target, identity, *, workdir, age='age'):
    started = time.monotonic()
    target = Path(target).absolute()
    private_directory(target.parent)
    # Existing empty SQLite files are refused as well: a fresh explicit filename
    # is the only supported target reservation. Hardlinks/symlinks cannot alias.
    if any(path.exists() or path.is_symlink() for path in
           (target, Path(str(target) + '-wal'), Path(str(target) + '-shm'), Path(str(target) + '-journal'))):
        raise RecoveryError('SQLite restore requires a fresh nonexistent target and sidecars.')
    with decrypted_archive(archive, identity, workdir=workdir, age=age) as (manifest, state, dump, _):
        if manifest['backend'] != 'sqlite':
            raise RecoveryError('Recovery backend does not match the selected target.')
        if canonical(inspect_sqlite(dump)) != canonical(state):
            raise RecoveryError('SQLite dump does not match its complete private inventory.')
        fd = new_private_file(target)
        try:
            with os.fdopen(fd, 'wb') as restored, dump.open('rb') as original:
                shutil.copyfileobj(original, restored)
                restored.flush()
                os.fsync(restored.fileno())
            if canonical(inspect_sqlite(target)) != canonical(state):
                raise RecoveryError('Restored SQLite rows or sequences differ.')
        except Exception:
            target.unlink(missing_ok=True)
            raise
    return receipt('restore', 'sqlite', started, state, archive)


def postgres_environment(url):
    try:
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, strict_parsing=True)
        options = dict(pairs)
        user = unquote(parsed.username or '', errors='strict')
        password = unquote(parsed.password or '', errors='strict')
        database = unquote(parsed.path[1:], errors='strict')
        port = parsed.port if parsed.port is not None else 5432
        if (parsed.scheme not in {'postgres', 'postgresql'} or not parsed.hostname
                or not parsed.path.startswith('/') or not NAME.fullmatch(database) or parsed.fragment
                or not user or not 1 <= port <= 65535
                or not re.fullmatch(r'[A-Za-z0-9_.:-]+', parsed.hostname)
                or any(char in user + password + database + ''.join(options.values()) for char in '\x00\r\n')
                or len(options) != len(pairs)
                or set(options) - {'sslmode', 'sslrootcert', 'connect_timeout'}
                or options.get('sslmode') not in {'verify-full', 'verify-ca', 'disable'}
                or (options.get('sslmode') == 'disable' and parsed.hostname not in {'127.0.0.1', '::1'})
                or any(char in url for char in '\x00\r\n')):
            raise ValueError
    except (ValueError, TypeError):
        raise RecoveryError('Explicit PostgreSQL URL with verified TLS or literal-loopback disable is required.') from None
    result = {'PGHOST': parsed.hostname, 'PGPORT': str(port), 'PGUSER': user,
              'PGPASSWORD': password, 'PGDATABASE': database, 'PGSSLMODE': options['sslmode'],
              'PGCONNECT_TIMEOUT': '10', 'PGAPPNAME': 'soup-wall-console-recovery'}
    if 'sslrootcert' in options:
        result['PGSSLROOTCERT'] = options['sslrootcert']
    if 'connect_timeout' in options:
        if not options['connect_timeout'].isdigit() or not 1 <= int(options['connect_timeout']) <= 300:
            raise RecoveryError('PostgreSQL connect timeout must be between 1 and 300 seconds.')
        result['PGCONNECT_TIMEOUT'] = options['connect_timeout']
    return result


class PostgresBackend:
    def __init__(self, url, *, directory, psql='psql', runner=checked):
        self.environment = postgres_environment(url)
        self.directory = private_directory(directory)
        self.psql, self.runner = psql, runner

    def invoke(self, argv, stdin=None):
        return self.runner(argv, directory=self.directory, environment=self.environment, stdin=stdin)

    def sql(self, query):
        return self.invoke([self.psql, '--no-psqlrc', '--quiet', '--no-align', '--tuples-only',
                            '--set', 'ON_ERROR_STOP=1'], query.encode()).decode().strip()

    def identity(self):
        result = strict_json(self.sql("SELECT json_build_object('system_identifier',"
            "(SELECT system_identifier::text FROM pg_control_system()),'database_oid',"
            "(SELECT oid::text FROM pg_database WHERE datname=current_database()),"
            "'database_name',current_database());"))
        if (not isinstance(result, dict) or set(result) != {'system_identifier','database_oid','database_name'}
                or not all(isinstance(result[key], str) and result[key] for key in result)
                or not result['system_identifier'].isdigit() or not result['database_oid'].isdigit()):
            raise RecoveryError('PostgreSQL actual database identity could not be established.')
        return result

    def require_owned(self):
        result = self.sql("SELECT (datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user)) "
            "AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) "
            "FROM pg_database WHERE datname=current_database();")
        if result != 't':
            raise RecoveryError('Recovery requires the selected database owner without superuser privileges.')
        # Recovery runs exclusively: other sessions would race source quiescence
        # or target validation. No backend is terminated or role changed here.
        if self.sql("SELECT COUNT(*) FROM pg_stat_activity WHERE datid=(SELECT oid FROM pg_database "
                    "WHERE datname=current_database()) AND pid<>pg_backend_pid() "
                    "AND backend_type='client backend';") != '0':
            raise RecoveryError('Console recovery requires all other database clients stopped.')

    def catalog(self):
        result = strict_json(self.sql("SELECT json_build_object('tables',"
            "(SELECT COALESCE(json_agg(tablename ORDER BY tablename),'[]'::json) FROM pg_tables WHERE schemaname='public'),"
            "'sequences',(SELECT COALESCE(json_agg(sequencename ORDER BY sequencename),'[]'::json) "
            "FROM pg_sequences WHERE schemaname='public'),'unexpected',"
            "(SELECT COUNT(*) FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') "
            "AND left(nspname,3)<>'pg_'));"))
        if (not isinstance(result, dict) or set(result) != {'tables', 'sequences', 'unexpected'}
                or type(result['unexpected']) is not int or result['unexpected'] != 0
                or any(not isinstance(result[key], list) or len(set(result[key])) != len(result[key])
                       or any(not isinstance(name, str) or not NAME.fullmatch(name) for name in result[key])
                       for key in ('tables', 'sequences'))):
            raise RecoveryError('Unsupported PostgreSQL schema catalog.')
        return result

    def require_empty(self):
        catalog = self.catalog()
        if catalog['tables'] or catalog['sequences']:
            raise RecoveryError('PostgreSQL restore target is populated.')
        # Tables alone do not establish emptiness: preexisting routines, views,
        # types and extension objects must not survive or influence the restore.
        result = self.sql("SELECT (SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='public') + (SELECT COUNT(*) FROM pg_proc p JOIN pg_namespace n "
            "ON n.oid=p.pronamespace WHERE n.nspname='public') + (SELECT COUNT(*) FROM pg_type t "
            "JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public') "
            "+ (SELECT COUNT(*) FROM pg_extension WHERE extname<>'plpgsql');")
        if result != '0':
            raise RecoveryError('PostgreSQL restore target contains schema objects.')

    def logical_schema(self):
        """Complete native logical DDL, excluding physical OIDs, owners and rows.

        This is compared to a reviewed fresh native schema in the versioned
        inventory, then retained in the encrypted private equality witness.
        Python sorting removes dependence on the source database collation.
        """
        queries = {
            'tables': "SELECT c.relname AS name,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,c.relreplident "
                "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','f')",
            'columns': "SELECT c.relname AS table_name,a.attname AS name,a.attnum AS position,"
                "format_type(a.atttypid,a.atttypmod) AS data_type,a.attnotnull AS not_null,"
                "pg_get_expr(d.adbin,d.adrelid,false) AS default_expr,a.attidentity,a.attgenerated,"
                "CASE WHEN a.attcollation=0 THEN NULL ELSE cn.nspname||'.'||coll.collname END AS collation "
                "FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                "LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum "
                "LEFT JOIN pg_collation coll ON coll.oid=a.attcollation LEFT JOIN pg_namespace cn ON cn.oid=coll.collnamespace "
                "WHERE n.nspname='public' AND c.relkind IN ('r','p','f') AND a.attnum>0 AND NOT a.attisdropped",
            'constraints': "SELECT c.relname AS table_name,x.conname AS name,x.contype,pg_get_constraintdef(x.oid,false) AS definition "
                "FROM pg_constraint x JOIN pg_namespace n ON n.oid=x.connamespace LEFT JOIN pg_class c ON c.oid=x.conrelid "
                "WHERE n.nspname='public'",
            'indexes': "SELECT c.relname AS name,pg_get_indexdef(c.oid) AS definition FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('i','I')",
            'triggers': "SELECT c.relname AS table_name,t.tgname AS name,t.tgenabled,pg_get_triggerdef(t.oid,false) AS definition "
                "FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='public' AND NOT t.tgisinternal",
            'functions': "SELECT p.proname AS name,pg_get_functiondef(p.oid) AS definition FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'",
            'types': "SELECT t.typname AS name,t.typtype,t.typcategory,t.typelem::regtype::text AS element,"
                "t.typbasetype::regtype::text AS base,t.typnotnull FROM pg_type t "
                "JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public'",
            'sequences': "SELECT c.relname AS name,s.seqtypid::regtype::text AS data_type,s.seqstart,s.seqincrement,"
                "s.seqmax,s.seqmin,s.seqcache,s.seqcycle FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid "
                "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'",
            'views': "SELECT c.relname AS name,c.relkind,pg_get_viewdef(c.oid,false) AS definition FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('v','m')",
            'policies': "SELECT c.relname AS table_name,p.polname AS name,p.polpermissive,p.polcmd,"
                "pg_get_expr(p.polqual,p.polrelid,false) AS using_expr,pg_get_expr(p.polwithcheck,p.polrelid,false) AS check_expr "
                "FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='public'",
            'extensions': "SELECT e.extname AS name,e.extversion,n.nspname AS schema_name FROM pg_extension e "
                "JOIN pg_namespace n ON n.oid=e.extnamespace",
        }
        items = ["'" + name + "',(SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (" + query + ') x)'
                 for name, query in queries.items()]
        result = strict_json(self.sql("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL search_path=pg_catalog; "
            "SELECT jsonb_build_object(" + ','.join(items) + '); COMMIT;'))
        if (not isinstance(result, dict) or set(result) != set(queries)
                or any(not isinstance(rows,list) or any(not isinstance(row,dict) for row in rows)
                       for rows in result.values())):
            raise RecoveryError('Invalid PostgreSQL logical schema inventory.')
        return {name: sorted(rows,key=canonical) for name,rows in result.items()}

    def snapshot(self):
        definition = inventory()
        catalog = self.catalog()
        if (set(catalog['tables']) != set(definition['postgres_tables'])
                or set(catalog['sequences']) != set(definition['postgres_sequences'])):
            raise RecoveryError('PostgreSQL tables or sequences do not match the versioned inventory.')
        versions = strict_json(self.sql("SELECT json_agg(version ORDER BY version) FROM llm_firewall_schema_migrations;"))
        if (not isinstance(versions,list) or versions != list(range(1, 28))
                or any(type(value) is not int for value in versions)):
            raise RecoveryError('PostgreSQL schema must have exactly accepted migrations 1 through 27.')
        columns = strict_json(self.sql("SELECT json_object_agg(table_name,columns) FROM "
            "(SELECT table_name,json_object_agg(column_name,udt_name) AS columns FROM information_schema.columns "
            "WHERE table_schema='public' GROUP BY table_name) t;"))
        types = {'TEXT':'text', 'BIGINT':'int8', 'INTEGER':'int4', 'BOOLEAN':'bool', 'BYTEA':'bytea', 'BIGSERIAL':'int8'}
        expected = {name: {key: types[value] for key, value in values.items()}
                    for name, values in definition['postgres_tables'].items()}
        validate_columns(columns, expected)
        schema = self.logical_schema()
        if canonical(schema) != canonical(definition.get('postgres_schema')):
            raise RecoveryError('PostgreSQL logical DDL differs from the accepted native schema.')
        def map_sql(names, sequence=False):
            items = []
            for name in sorted(names):
                if sequence:
                    value = f"(SELECT jsonb_build_object('last_value',last_value,'is_called',is_called) FROM public.{name})"
                else:
                    value = f"(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM public.{name} t)"
                items.append(f"SELECT '{name}'::text AS name,{value} AS value")
            return "(SELECT jsonb_object_agg(name,value) FROM (" + ' UNION ALL '.join(items) + ') t)'
        value = strict_json(self.sql("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
            "SET LOCAL TIME ZONE 'UTC'; SELECT jsonb_build_object('backend','postgres',"
            "'schema_version',27,'tables'," + map_sql(catalog['tables']) + ",'sequences'," +
            map_sql(catalog['sequences'], True) + '); COMMIT;'))
        value['schema'] = schema
        for rows in value['tables'].values():
            if not isinstance(rows,list):
                raise RecoveryError('Invalid PostgreSQL private table inventory.')
            rows.sort(key=canonical)
        validate_private_state(value, 'postgres')
        return value


def same_postgres_database(first, second):
    return (first['system_identifier'], first['database_oid']) == (second['system_identifier'], second['database_oid'])


def backup_postgres(source_url, output, recipient, *, workdir, age='age', psql='psql',
                    pg_dump='pg_dump', source_quiesced=False):
    started = time.monotonic()
    if source_quiesced is not True:
        raise RecoveryError('PostgreSQL backup requires explicit confirmation that all source writers are stopped.')
    with temporary(workdir) as directory:
        backend = PostgresBackend(source_url, directory=directory, psql=psql)
        backend.require_owned()
        identity = backend.identity()
        state = backend.snapshot()
        dump = directory / 'database.dump'
        backend.invoke([pg_dump, '--format=custom', '--no-owner', '--no-privileges', '--file', dump])
        os.chmod(dump, 0o600)
        private_file(dump)
        backend.require_owned()
        if backend.identity() != identity or canonical(backend.snapshot()) != canonical(state):
            raise RecoveryError('PostgreSQL source changed during backup.')
        plain = pack_archive(directory, 'postgres', identity, state, dump)
        encrypt_archive(plain, output, recipient, directory, age)
    return receipt('backup', 'postgres', started, state, output)


def restore_postgres(archive, target_url, identity, *, workdir, age='age', psql='psql',
                     pg_restore='pg_restore'):
    started = time.monotonic()
    with decrypted_archive(archive, identity, workdir=workdir, age=age) as (manifest, state, dump, directory):
        if manifest['backend'] != 'postgres':
            raise RecoveryError('Recovery backend does not match the selected target.')
        source_identity = manifest['source_identity']
        if (set(source_identity) != {'system_identifier','database_oid','database_name'}
                or any(not isinstance(value,str) or not value for value in source_identity.values())):
            raise RecoveryError('Invalid PostgreSQL source identity.')
        backend = PostgresBackend(target_url, directory=directory, psql=psql)
        target_identity = backend.identity()
        if same_postgres_database(source_identity, target_identity):
            raise RecoveryError('Source aliases are forbidden as PostgreSQL recovery targets.')
        backend.require_owned()
        backend.require_empty()
        # Validate the custom archive structure before any target statement. No
        # --clean, migration, owner alteration or unsupported compatibility edit.
        backend.invoke([pg_restore, '--list', dump])
        if backend.identity() != target_identity:
            raise RecoveryError('PostgreSQL target identity changed before restoration.')
        backend.require_empty()
        backend.invoke([pg_restore, '--single-transaction', '--exit-on-error', '--no-owner',
                        '--no-privileges', '--dbname', '', dump])
        # Empty conninfo makes libpq use the explicitly decomposed PGHOST,
        # PGDATABASE and credential environment; no URI/password enters argv.
        backend.require_owned()
        if backend.identity() != target_identity or canonical(backend.snapshot()) != canonical(state):
            raise RecoveryError('Restored PostgreSQL rows or sequences differ; do not start the recovered Console.')
    return receipt('restore', 'postgres', started, state, archive)
