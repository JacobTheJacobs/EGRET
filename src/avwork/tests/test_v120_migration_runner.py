from __future__ import annotations

import sqlite3
from pathlib import Path

from app.storage.migration_runner import run_sqlite_migrations


def test_sqlite_migrations_are_applied_once(tmp_path: Path) -> None:
    migrations_dir = tmp_path / 'migrations'
    migrations_dir.mkdir()
    (migrations_dir / '0001_first.sql').write_text('CREATE TABLE IF NOT EXISTS sample(id INTEGER PRIMARY KEY);', encoding='utf-8')
    (migrations_dir / '0002_second.sql').write_text('ALTER TABLE sample ADD COLUMN name TEXT;', encoding='utf-8')
    conn = sqlite3.connect(':memory:')

    first = run_sqlite_migrations(conn, migrations_dir)
    assert first.applied_files == ['0001_first.sql', '0002_second.sql']
    second = run_sqlite_migrations(conn, migrations_dir)
    assert second.applied_files == []
    cols = [row[1] for row in conn.execute('PRAGMA table_info(sample)').fetchall()]
    assert cols == ['id', 'name']
