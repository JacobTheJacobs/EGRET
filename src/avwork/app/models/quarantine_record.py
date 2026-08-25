from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class QuarantineRecord(BaseModel):
    quarantine_record_id: str
    asset_id: str
    sha256: str
    original_path: str
    quarantine_path: str
    reason: str
    restored: bool = False
    deleted: bool = False
    created_ts: datetime
    updated_ts: datetime
    malware_verdict_id: Optional[str] = None
