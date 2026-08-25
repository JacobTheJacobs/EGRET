from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class FileEvent(BaseModel):
    file_event_id: str
    asset_id: str
    session_id: str
    process_identity_id: Optional[str] = None
    path: str
    sha256: str
    file_size: int = 0
    file_type: Optional[str] = None
    origin_kind: Optional[str] = Field(default=None, description='download, email, local, archive_extract, removable_media')
    origin_source: Optional[str] = None
    signer_name: Optional[str] = None
    signer_status: Optional[str] = None
    event_kind: str = Field(description='write, open, execute, demand_scan')
    ts: datetime

    @field_validator('event_kind')
    @classmethod
    def validate_event_kind(cls, value: str) -> str:
        allowed = {'write', 'open', 'execute', 'demand_scan'}
        if value not in allowed:
            raise ValueError(f'event_kind must be one of {sorted(allowed)}')
        return value
