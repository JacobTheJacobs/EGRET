from __future__ import annotations

from datetime import datetime, timezone

from app.models.quarantine_record import QuarantineRecord
from app.storage.repositories.sqlite import SqliteRepositories


def test_quarantine_record_can_be_restored_and_deleted() -> None:
    repos = SqliteRepositories(':memory:')
    now = datetime.now(timezone.utc)
    record = repos.quarantine.create_record(
        QuarantineRecord(
            quarantine_record_id='q_1',
            asset_id='asset-1',
            sha256='abc',
            original_path='/tmp/bad.exe',
            quarantine_path='/quarantine/abc_bad.exe',
            reason='test',
            created_ts=now,
            updated_ts=now,
        )
    )
    restored = repos.quarantine.update_record(record.quarantine_record_id, restored=True, updated_ts=now)
    assert restored is not None
    assert restored.restored is True
    deleted = repos.quarantine.update_record(record.quarantine_record_id, deleted=True, updated_ts=now)
    assert deleted is not None
    assert deleted.deleted is True
