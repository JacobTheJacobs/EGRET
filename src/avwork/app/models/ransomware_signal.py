from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class RansomwareSignal(BaseModel):
    ransomware_signal_id: str
    asset_id: str
    session_id: str
    process_identity_id: str | None = None
    signal_kind: str
    severity: str = Field(description="low, medium, high, critical")
    protected_path: str | None = None
    indicators_json: dict[str, Any] = Field(default_factory=dict)
    action_recommendation: str
    created_ts: datetime

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, value: str) -> str:
        allowed = {'low', 'medium', 'high', 'critical'}
        if value not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}")
        return value
