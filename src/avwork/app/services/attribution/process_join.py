from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

from app.models.process_identity import ProcessIdentity


@dataclass(frozen=True)
class OutboundSocketEvent:
    asset_id: str
    session_id: str
    process_id: int
    remote_ip: str
    remote_port: int
    observed_at: datetime


@dataclass(frozen=True)
class ProcessSnapshot:
    asset_id: str
    session_id: str
    process_id: int
    parent_process_id: Optional[int]
    process_name: str
    process_path: str
    signer_name: Optional[str]
    signer_status: Optional[str]
    observed_at: datetime


@dataclass(frozen=True)
class ProcessJoinResult:
    process_identity: Optional[ProcessIdentity]
    confidence: float
    reason: str


class ProcessJoiner:
    def __init__(self, max_clock_skew_seconds: int = 30) -> None:
        self.max_clock_skew = timedelta(seconds=max_clock_skew_seconds)

    def correlate(self, socket_event: OutboundSocketEvent, process_events: Iterable[ProcessSnapshot]) -> ProcessJoinResult:
        candidates = [
            event for event in process_events
            if event.asset_id == socket_event.asset_id
            and event.session_id == socket_event.session_id
            and event.process_id == socket_event.process_id
            and abs(event.observed_at - socket_event.observed_at) <= self.max_clock_skew
        ]
        if not candidates:
            return ProcessJoinResult(process_identity=None, confidence=0.0, reason="no_matching_process_snapshot")

        candidates.sort(key=lambda event: abs(event.observed_at - socket_event.observed_at))
        best = candidates[0]
        delta = abs(best.observed_at - socket_event.observed_at)
        confidence = max(0.0, 1.0 - (delta / self.max_clock_skew))
        process_identity = ProcessIdentity(
            process_identity_id=f"{best.asset_id}:{best.session_id}:{best.process_id}",
            asset_id=best.asset_id,
            session_id=best.session_id,
            process_id=best.process_id,
            parent_process_id=best.parent_process_id,
            process_name=best.process_name,
            process_path=best.process_path,
            signer_name=best.signer_name,
            signer_status=best.signer_status,
        )
        return ProcessJoinResult(process_identity=process_identity, confidence=confidence, reason="matched_by_asset_session_pid_and_time")
