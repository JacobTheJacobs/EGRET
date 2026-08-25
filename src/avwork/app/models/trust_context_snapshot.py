from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class TrustContextSnapshot(BaseModel):
    trust_context_snapshot_id: str
    asset_id: str
    session_id: str
    snapshot_ts: datetime
    risky_ble_signature_counter: bool = False
    rogue_ble_counter_reuse: bool = False
    trust_score: Optional[float] = None
    drift_score: Optional[float] = None
    supporting_context_json: dict = Field(default_factory=dict)
