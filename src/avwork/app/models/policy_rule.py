from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class PolicyConditions(BaseModel):
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    signer_name: Optional[str] = None
    signer_status: Optional[str] = None
    domain: Optional[str] = None
    domain_suffix: Optional[str] = None
    domain_suffix_not_in: List[str] = Field(default_factory=list)
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: Optional[str] = None
    network_zone: Optional[str] = None


class PolicyRule(BaseModel):
    rule_id: str
    rule_name: str
    enabled: bool = True
    priority: int = 100
    source: str = Field(description="user, admin, system")
    action: str = Field(description="allow, deny, ask, observe_only")
    ttl_seconds: Optional[int] = None
    created_ts: datetime
    updated_ts: datetime
    created_by: Optional[str] = None
    conditions: PolicyConditions
    explanation_template: Optional[str] = None

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str) -> str:
        allowed = {"allow", "deny", "ask", "observe_only"}
        if value not in allowed:
            raise ValueError(f"action must be one of {sorted(allowed)}")
        return value

    @field_validator("ttl_seconds")
    @classmethod
    def validate_ttl_seconds(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value <= 0:
            raise ValueError("ttl_seconds must be positive when provided")
        return value
