from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class TrainingFeedbackEvent(BaseModel):
    training_feedback_event_id: str
    connection_id: str
    label: str
    label_source: str = Field(description='user_prompt, user_rule, admin_rule, system_default, recommendation, investigation')
    features_hash: str
    generated_ts: datetime
    superseded_by: Optional[str] = None

    @field_validator('label_source')
    @classmethod
    def validate_label_source(cls, value: str) -> str:
        allowed = {'user_prompt', 'user_rule', 'admin_rule', 'system_default', 'recommendation', 'investigation'}
        if value not in allowed:
            raise ValueError(f'label_source must be one of {sorted(allowed)}')
        return value
