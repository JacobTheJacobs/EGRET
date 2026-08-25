from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class EnforcementEvent(BaseModel):
    enforcement_event_id: str
    rule_id: str
    backend: str = Field(description='macos, windows, linux')
    action: str = Field(description='allow, deny')
    status: str = Field(description='pending, applied, failed, skipped, stale')
    connection_id: Optional[str] = None
    policy_decision_id: Optional[str] = None
    message: Optional[str] = None
    command_preview: list[str] = Field(default_factory=list)
    backend_rule_ref: Optional[str] = None
    execution_mode: Optional[str] = Field(default='simulated', description='simulated, executed')
    backend_state: Optional[str] = Field(default='unknown', description='present, missing, unknown')
    applied_ts: datetime
    effective_until: Optional[datetime] = None

    @field_validator('backend')
    @classmethod
    def validate_backend(cls, value: str) -> str:
        allowed = {'macos', 'windows', 'linux'}
        if value not in allowed:
            raise ValueError(f'backend must be one of {sorted(allowed)}')
        return value

    @field_validator('action')
    @classmethod
    def validate_action(cls, value: str) -> str:
        allowed = {'allow', 'deny'}
        if value not in allowed:
            raise ValueError(f'action must be one of {sorted(allowed)}')
        return value

    @field_validator('status')
    @classmethod
    def validate_status(cls, value: str) -> str:
        allowed = {'pending', 'applied', 'failed', 'skipped', 'stale'}
        if value not in allowed:
            raise ValueError(f'status must be one of {sorted(allowed)}')
        return value

    @field_validator('execution_mode')
    @classmethod
    def validate_execution_mode(cls, value: Optional[str]) -> Optional[str]:
        allowed = {'simulated', 'executed'}
        if value is not None and value not in allowed:
            raise ValueError(f'execution_mode must be one of {sorted(allowed)}')
        return value

    @field_validator('backend_state')
    @classmethod
    def validate_backend_state(cls, value: Optional[str]) -> Optional[str]:
        allowed = {'present', 'missing', 'unknown'}
        if value is not None and value not in allowed:
            raise ValueError(f'backend_state must be one of {sorted(allowed)}')
        return value
