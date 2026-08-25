from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class RemediationAction(BaseModel):
    remediation_action_id: str
    asset_id: str
    session_id: str
    process_identity_id: str | None = None
    related_object_id: str | None = None
    action_kind: str = Field(description="quarantine_file, kill_process_tree, isolate_process, remove_persistence, rollback_candidate")
    target_type: str = Field(description="file, process, alert, signal")
    status: str = Field(description="pending, completed, failed")
    backend_result: str | None = None
    initiated_by: str
    created_ts: datetime
    completed_ts: datetime | None = None

    @field_validator('status')
    @classmethod
    def validate_status(cls, value: str) -> str:
        allowed = {'pending', 'completed', 'failed'}
        if value not in allowed:
            raise ValueError(f"status must be one of {sorted(allowed)}")
        return value
