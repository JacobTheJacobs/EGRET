from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PurePosixPath
from uuid import uuid4

from app.models.quarantine_record import QuarantineRecord
from app.storage.repositories.interfaces import QuarantineRepository


class QuarantineService:
    def __init__(self, repo: QuarantineRepository) -> None:
        self.repo = repo

    def quarantine(self, *, asset_id: str, sha256: str, original_path: str, reason: str, malware_verdict_id: str | None = None) -> QuarantineRecord:
        now = datetime.now(timezone.utc)
        safe_name = PurePosixPath(original_path).name or 'artifact.bin'
        record = QuarantineRecord(
            quarantine_record_id=f'q_{uuid4().hex[:12]}',
            asset_id=asset_id,
            sha256=sha256,
            original_path=original_path,
            quarantine_path=f'/quarantine/{sha256[:12]}_{safe_name}',
            reason=reason,
            restored=False,
            deleted=False,
            created_ts=now,
            updated_ts=now,
            malware_verdict_id=malware_verdict_id,
        )
        return self.repo.create_record(record)
