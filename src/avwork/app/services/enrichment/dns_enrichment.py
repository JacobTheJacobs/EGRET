from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

from app.models.connection_event import ConnectionEvent


@dataclass(frozen=True)
class DnsAnswerEvent:
    asset_id: str
    session_id: str
    query_name: str
    answers: tuple[str, ...]
    observed_at: datetime
    ttl_seconds: int = 300
    canonical_name: Optional[str] = None
    resolver_source: str = "local_dns"


@dataclass(frozen=True)
class DnsEnrichmentResult:
    matched_domain: Optional[str]
    canonical_name: Optional[str]
    resolver_source: Optional[str]
    confidence: float
    reason: str


class DnsEnricher:
    def __init__(self, max_observation_window_seconds: int = 900) -> None:
        self.max_observation_window = timedelta(seconds=max_observation_window_seconds)

    def correlate(
        self,
        connection: ConnectionEvent,
        dns_events: Iterable[DnsAnswerEvent],
    ) -> DnsEnrichmentResult:
        if connection.direction != "outbound":
            return DnsEnrichmentResult(
                matched_domain=None,
                canonical_name=None,
                resolver_source=None,
                confidence=0.0,
                reason="unsupported_direction",
            )

        candidates: list[tuple[timedelta, DnsAnswerEvent]] = []
        for event in dns_events:
            if event.asset_id != connection.asset_id or event.session_id != connection.session_id:
                continue
            delta = connection.start_ts - event.observed_at
            if delta < timedelta(seconds=0):
                continue
            ttl_bound = timedelta(seconds=min(event.ttl_seconds, int(self.max_observation_window.total_seconds())))
            if delta > ttl_bound:
                continue
            if connection.remote_ip not in event.answers:
                continue
            candidates.append((delta, event))

        if not candidates:
            return DnsEnrichmentResult(
                matched_domain=None,
                canonical_name=None,
                resolver_source=None,
                confidence=0.0,
                reason="no_recent_dns_answer_for_remote_ip",
            )

        candidates.sort(key=lambda item: item[0])
        best_delta, best_event = candidates[0]
        max_window_seconds = max(1, min(best_event.ttl_seconds, int(self.max_observation_window.total_seconds())))
        confidence = max(0.0, 1.0 - (best_delta.total_seconds() / max_window_seconds))
        return DnsEnrichmentResult(
            matched_domain=best_event.query_name,
            canonical_name=best_event.canonical_name or best_event.query_name,
            resolver_source=best_event.resolver_source,
            confidence=round(confidence, 4),
            reason="matched_recent_dns_answer_for_remote_ip",
        )
