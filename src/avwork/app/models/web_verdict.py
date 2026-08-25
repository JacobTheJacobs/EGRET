from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class WebVerdict(BaseModel):
    web_verdict_id: str
    asset_id: str
    process_identity_id: Optional[str] = None
    url: str
    domain: str
    category: str = Field(description='benign, malicious, phishing, suspicious')
    verdict: str = Field(description='allow, block, warn')
    source: str = Field(description='reputation, policy, heuristic')
    confidence_score: float = 0.0
    created_ts: datetime

    @field_validator('category')
    @classmethod
    def validate_category(cls, value: str) -> str:
        allowed = {'benign', 'malicious', 'phishing', 'suspicious'}
        if value not in allowed:
            raise ValueError(f'category must be one of {sorted(allowed)}')
        return value

    @field_validator('verdict')
    @classmethod
    def validate_verdict(cls, value: str) -> str:
        allowed = {'allow', 'block', 'warn'}
        if value not in allowed:
            raise ValueError(f'verdict must be one of {sorted(allowed)}')
        return value
