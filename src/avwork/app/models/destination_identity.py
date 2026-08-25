from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class DestinationIdentity(BaseModel):
    destination_identity_id: str
    canonical_name: Optional[str] = None
    matched_domain: Optional[str] = None
    sni: Optional[str] = None
    ip: str
    port: int
    protocol: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_fingerprint: Optional[str] = None
    service_fingerprint: Optional[str] = None
    resolver_source: Optional[str] = None
    first_seen_ts: Optional[datetime] = None
    last_seen_ts: Optional[datetime] = None
