from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse
from uuid import uuid4

from app.models.web_verdict import WebVerdict
from app.services.av.reputation import url_reputation
from app.storage.repositories.interfaces import WebVerdictRepository


class UrlReputationService:
    def __init__(self, repo: WebVerdictRepository) -> None:
        self.repo = repo

    def check(self, *, asset_id: str, url: str, process_identity_id: str | None = None) -> WebVerdict:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        category, verdict, confidence = url_reputation(domain)
        item = WebVerdict(
            web_verdict_id=f'wv_{uuid4().hex[:12]}',
            asset_id=asset_id,
            process_identity_id=process_identity_id,
            url=url,
            domain=domain,
            category=category,
            verdict=verdict,
            source='reputation',
            confidence_score=confidence,
            created_ts=datetime.now(timezone.utc),
        )
        return self.repo.create_web_verdict(item)
