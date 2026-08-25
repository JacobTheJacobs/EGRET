from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable, Optional

from app.models.connection_event import ConnectionEvent
from app.models.trust_context_snapshot import TrustContextSnapshot


@dataclass(frozen=True)
class TrustSnapshotJoinResult:
    snapshot: Optional[TrustContextSnapshot]
    matched: bool
    reason: str


class TrustSnapshotJoiner:
    def __init__(self, max_age_seconds: int = 900) -> None:
        self.max_age = timedelta(seconds=max_age_seconds)

    def select_snapshot(
        self,
        connection: ConnectionEvent,
        snapshots: Iterable[TrustContextSnapshot],
    ) -> TrustSnapshotJoinResult:
        candidates = []
        for snapshot in snapshots:
            if snapshot.asset_id != connection.asset_id:
                continue
            if snapshot.session_id != connection.session_id:
                continue
            delta = connection.start_ts - snapshot.snapshot_ts
            if delta.total_seconds() < 0:
                continue
            if delta > self.max_age:
                continue
            candidates.append((delta, snapshot))

        if not candidates:
            return TrustSnapshotJoinResult(snapshot=None, matched=False, reason='no_recent_trust_snapshot')

        candidates.sort(key=lambda item: item[0])
        return TrustSnapshotJoinResult(snapshot=candidates[0][1], matched=True, reason='matched_latest_snapshot_before_connection')

    def attach_snapshot_id(
        self,
        connection: ConnectionEvent,
        snapshots: Iterable[TrustContextSnapshot],
    ) -> ConnectionEvent:
        result = self.select_snapshot(connection, snapshots)
        if not result.snapshot:
            return connection
        return connection.model_copy(update={'trust_context_snapshot_id': result.snapshot.trust_context_snapshot_id})
