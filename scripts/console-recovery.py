#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Encrypted Console backup and verified restore; no migrations or startup."""
import argparse
import json
import os
from pathlib import Path
import sys
from console_recovery import (RecoveryError, backup_sqlite, restore_sqlite,
                              backup_postgres, restore_postgres)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['backup', 'restore'])
    parser.add_argument('--backend', choices=['sqlite', 'postgres'], required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--workdir', type=Path, required=True, help='existing private 0700 scratch parent')
    parser.add_argument('--database', type=Path, help='explicit SQLite source or fresh target')
    parser.add_argument('--database-url-env', help='name of environment variable holding explicit PostgreSQL URL')
    parser.add_argument('--recipient', help='native age public recipient for backup')
    parser.add_argument('--identity', type=Path, help='private external age identity for restore')
    parser.add_argument('--source-quiesced', action='store_true', help='all PostgreSQL source writers are stopped')
    parser.add_argument('--age', default='age')
    parser.add_argument('--psql', default='psql')
    parser.add_argument('--pg-dump', default='pg_dump')
    parser.add_argument('--pg-restore', default='pg_restore')
    args = parser.parse_args(argv)
    try:
        options = {'workdir': args.workdir, 'age': args.age}
        if args.operation == 'backup' and not args.recipient:
            raise RecoveryError('Backup requires an explicit recipient.')
        if args.operation == 'restore' and not args.identity:
            raise RecoveryError('Restore requires an external private identity.')
        if args.backend == 'sqlite':
            if not args.database or args.database_url_env:
                raise RecoveryError('SQLite requires only an explicitly selected database path.')
            if args.operation == 'backup':
                value = backup_sqlite(args.database, args.archive, args.recipient, **options)
            else:
                value = restore_sqlite(args.archive, args.database, args.identity, **options)
        else:
            if args.database or not args.database_url_env or not os.environ.get(args.database_url_env):
                raise RecoveryError('PostgreSQL requires only an explicit database URL environment variable.')
            url = os.environ[args.database_url_env]
            options['psql'] = args.psql
            if args.operation == 'backup':
                value = backup_postgres(url, args.archive, args.recipient, pg_dump=args.pg_dump,
                    source_quiesced=args.source_quiesced, **options)
            else:
                value = restore_postgres(args.archive, url, args.identity, pg_restore=args.pg_restore, **options)
    except RecoveryError as error:
        print(json.dumps({'format_version':1,'status':'failed','reason':str(error)}))
        return 1
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print(json.dumps({'format_version':1,'status':'failed','reason':'Recovery failed; private details withheld.'}))
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
