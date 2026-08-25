from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.storage.migration_runner import MigrationResult, run_sqlite_migrations
from app.storage.repositories.sqlite import SqliteDatabase, SqliteRepositories


@dataclass(frozen=True)
class BootstrapState:
    database: SqliteDatabase
    repositories: SqliteRepositories
    migrations: MigrationResult


def bootstrap_application(db_path: Path | str = ':memory:') -> BootstrapState:
    db = SqliteDatabase(db_path)
    migrations = run_sqlite_migrations(db.conn, Path(__file__).resolve().parent / 'migrations')
    repos = SqliteRepositories.from_database(db)
    return BootstrapState(database=db, repositories=repos, migrations=migrations)
