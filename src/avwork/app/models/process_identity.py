from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ProcessIdentity(BaseModel):
    process_identity_id: str
    asset_id: str
    session_id: str
    process_id: int
    parent_process_id: Optional[int] = None
    process_name: str
    process_path: str
    executable_hash: Optional[str] = None
    signer_name: Optional[str] = None
    signer_status: Optional[str] = Field(default=None, description="trusted, unsigned, unknown, revoked")
    package_id: Optional[str] = None
    service_name: Optional[str] = None
    first_seen_ts: Optional[datetime] = None
    last_seen_ts: Optional[datetime] = None
