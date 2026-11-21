"""Non-destructive SQLite backup and restore verification (no secrets printed).

Without --database, constructs a temporary synthetic dataset for a safe demo.
With --database, reads an existing SQLite database via read-only URI and
backs up to temporary storage, then restores into memory to compare content.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.models import Base
from app.services import create_assessment


def _data_digest(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    for line in connection.iterdump():
        digest.update(line.encode('utf-8'))
        digest.update(b'\n')
    return digest.hexdigest()


def verify(database: Path) -> dict:
    database = database.resolve(strict=True)
    if not database.is_file():
        raise ValueError('Database must be a regular file')
    # SQLite's online backup API is safe with write-ahead logging, unlike cp.
    source = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
    try:
        with TemporaryDirectory(prefix='arbitrator-restore-') as directory:
            snapshot = Path(directory) / 'snapshot.sqlite3'
            destination = sqlite3.connect(snapshot)
            try:
                source.backup(destination)
            finally:
                destination.close()
            restored = sqlite3.connect(':memory:')
            backup_source = sqlite3.connect(snapshot)
            try:
                backup_source.backup(restored)
                tables = [row[0] for row in restored.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
                consistency = restored.execute('PRAGMA integrity_check').fetchone()[0]
                foreign_key_problems = list(restored.execute('PRAGMA foreign_key_check'))
                match = _data_digest(source) == _data_digest(restored)
                counts = {name: restored.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]
                          for name in tables}
                result = {'restored': consistency == 'ok' and match and not foreign_key_problems,
                          'integrity_check': consistency, 'content_digest_matches': match,
                          'foreign_key_violations': len(foreign_key_problems),
                          'tables_checked': len(tables), 'table_row_counts': counts,
                          'note': 'Temporary backup deleted after verification; live database was never overwritten.'}
            finally:
                backup_source.close()
                restored.close()
    finally:
        source.close()
    if not result['restored']:
        raise RuntimeError('Backup/restore verification failed')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--database', type=Path, help='Existing SQLite file; default creates a synthetic DB')
    p.add_argument('--output', type=Path)
    args=p.parse_args()
    if args.database is None:
        with TemporaryDirectory(prefix='arbitrator-fixture-') as directory:
            path = Path(directory) / 'synthetic.sqlite3'
            engine = create_engine('sqlite:///' + str(path))
            Base.metadata.create_all(engine)
            with Session(engine) as db:
                create_assessment(db, 'Synthetic backup test', 'Fixture')
            engine.dispose()
            result = verify(path)
    else:
        result = verify(args.database)
    rendered=json.dumps(result, indent=2)+'\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered)


if __name__=='__main__': main()
