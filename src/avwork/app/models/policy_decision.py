from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class PolicyDecision(BaseModel):
    policy_decision_id: str
    connection_id: str
    matched_rule_id: Optional[str] = None
    decision: str = Field(description="allow, deny, ask, defer")
    decision_source: str = Field(description="user_prompt, user_rule, admin_rule, system_default, recommendation")
    prompt_shown: bool = False
    prompt_response: Optional[str] = None
    user_reason: Optional[str] = None
    expires_at: Optional[datetime] = None
    confidence_score: Optional[float] = None
    recommendation_kind: Optional[str] = None
    created_ts: datetime

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, value: str) -> str:
        allowed = {"allow", "deny", "ask", "defer"}
        if value not in allowed:
            raise ValueError(f"decision must be one of {sorted(allowed)}")
        return value

    @field_validator("decision_source")
    @classmethod
    def validate_source(cls, value: str) -> str:
        allowed = {"user_prompt", "user_rule", "admin_rule", "system_default", "recommendation"}
        if value not in allowed:
            raise ValueError(f"decision_source must be one of {sorted(allowed)}")
        return value
