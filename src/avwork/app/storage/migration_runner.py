from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3


@dataclass(frozen=True)
class MigrationResult:
    applied_files: list[str]


def run_sqlite_migrations(conn: sqlite3.Connection, migrations_dir: Path) -> MigrationResult:
    migrations_dir = Path(migrations_dir)
    applied: list[str] = []
    if not migrations_dir.exists():
        return MigrationResult(applied_files=[])

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            filename TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    already = {row[0] for row in conn.execute('SELECT filename FROM schema_migrations').fetchall()}
    for path in sorted(migrations_dir.glob('*.sql')):
        if path.name in already:
            continue
        sql = path.read_text(encoding='utf-8')
        sql = sql.replace('JSONB', 'TEXT')
        sql = re.sub(r"'\{\}'::jsonb", "'{}'", sql)
        try:
            with conn:
                conn.executescript(sql)
                conn.execute('INSERT INTO schema_migrations(filename) VALUES (?)', (path.name,))
            applied.append(path.name)
        except sqlite3.OperationalError as exc:
            message = str(exc).lower()
            tolerated = (
                'duplicate column name',
                'index',
            )
            if any(token in message for token in tolerated) and 'already exists' in message or 'duplicate column name' in message:
                with conn:
                    conn.execute('INSERT OR IGNORE INTO schema_migrations(filename) VALUES (?)', (path.name,))
                applied.append(path.name)
                continue
            raise
    return MigrationResult(applied_files=applied)
