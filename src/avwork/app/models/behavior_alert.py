from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class BehaviorAlert(BaseModel):
    behavior_alert_id: str
    asset_id: str
    session_id: str
    process_identity_id: str | None = None
    chain_id: str | None = None
    alert_kind: str
    severity: str = Field(description="low, medium, high, critical")
    indicators_json: dict[str, Any] = Field(default_factory=dict)
    recommendation: str
    created_ts: datetime

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if value not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}")
        return value
