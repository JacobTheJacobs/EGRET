from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ConnectionEvent(BaseModel):
    connection_id: str
    schema_version: int = 1
    asset_id: str
    session_id: str
    process_identity_id: str
    destination_identity_id: Optional[str] = None
    start_ts: datetime
    end_ts: Optional[datetime] = None
    direction: str = Field(description="outbound or inbound")
    protocol: Optional[str] = None
    transport: str = Field(description="tcp, udp, quic, etc.")
    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    remote_ip: str
    remote_port: int
    interface_name: Optional[str] = None
    network_zone: str = Field(description="public_internet, private_lan, loopback, vpn, etc.")
    vpn_state: Optional[str] = None
    bytes_out: Optional[int] = 0
    bytes_in: Optional[int] = 0
    duration_ms: Optional[int] = None
    trust_context_snapshot_id: Optional[str] = None
    matched_rule_id: Optional[str] = None
    policy_decision_id: Optional[str] = None
    first_seen_on_asset: Optional[bool] = None
    first_seen_in_fleet: Optional[bool] = None
    prevalence_on_asset: Optional[float] = None
    prevalence_in_fleet: Optional[float] = None
    flow_risk_score: Optional[float] = None
    rule_suggestion_score: Optional[float] = None
    anomaly_score: Optional[float] = None

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError("connection_event schema_version must equal 1 for v12.0")
        return value

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, value: str) -> str:
        allowed = {"outbound", "inbound"}
        if value not in allowed:
            raise ValueError(f"direction must be one of {sorted(allowed)}")
        return value

    @field_validator("remote_port", "local_port")
    @classmethod
    def validate_port(cls, value: Optional[int]) -> Optional[int]:
        if value is None:
            return value
        if not 1 <= value <= 65535:
            raise ValueError("ports must be in the range 1..65535")
        return value
