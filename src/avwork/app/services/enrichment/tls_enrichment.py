from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

from app.models.connection_event import ConnectionEvent


@dataclass(frozen=True)
class TlsHandshakeEvent:
    asset_id: str
    session_id: str
    remote_ip: str
    remote_port: int
    observed_at: datetime
    sni: Optional[str] = None
    alpn: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_fingerprint: Optional[str] = None


@dataclass(frozen=True)
class TlsEnrichmentResult:
    sni: Optional[str]
    alpn: Optional[str]
    certificate_subject: Optional[str]
    certificate_issuer: Optional[str]
    certificate_fingerprint: Optional[str]
    confidence: float
    reason: str


class TlsEnricher:
    def __init__(self, max_clock_skew_seconds: int = 30) -> None:
        self.max_clock_skew = timedelta(seconds=max_clock_skew_seconds)

    def correlate(
        self,
        connection: ConnectionEvent,
        handshakes: Iterable[TlsHandshakeEvent],
    ) -> TlsEnrichmentResult:
        candidates: list[tuple[timedelta, TlsHandshakeEvent]] = []
        for event in handshakes:
            if event.asset_id != connection.asset_id or event.session_id != connection.session_id:
                continue
            if event.remote_ip != connection.remote_ip or event.remote_port != connection.remote_port:
                continue
            delta = abs(event.observed_at - connection.start_ts)
            if delta > self.max_clock_skew:
                continue
            candidates.append((delta, event))

        if not candidates:
            return TlsEnrichmentResult(
                sni=None,
                alpn=None,
                certificate_subject=None,
                certificate_issuer=None,
                certificate_fingerprint=None,
                confidence=0.0,
                reason="no_matching_tls_handshake",
            )

        candidates.sort(key=lambda item: item[0])
        best_delta, best = candidates[0]
        confidence = max(0.0, 1.0 - (best_delta / self.max_clock_skew))
        return TlsEnrichmentResult(
            sni=best.sni,
            alpn=best.alpn,
            certificate_subject=best.certificate_subject,
            certificate_issuer=best.certificate_issuer,
            certificate_fingerprint=best.certificate_fingerprint,
            confidence=round(confidence, 4),
            reason="matched_tls_handshake_by_asset_session_ip_port_and_time",
        )
