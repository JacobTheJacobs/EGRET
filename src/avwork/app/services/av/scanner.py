from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.models.file_event import FileEvent
from app.models.malware_verdict import MalwareVerdict
from app.models.quarantine_record import QuarantineRecord
from app.services.av.quarantine import QuarantineService
from app.services.av.reputation import file_reputation
from app.services.av.signatures import match_content_signature
from app.storage.repositories.interfaces import FileEventRepository, MalwareVerdictRepository, QuarantineRepository


@dataclass
class ScanOutcome:
    file_event: FileEvent
    verdict: MalwareVerdict
    quarantine_record: QuarantineRecord | None = None


class ScannerService:
    def __init__(
        self,
        *,
        file_events: FileEventRepository,
        verdicts: MalwareVerdictRepository,
        quarantine: QuarantineRepository,
    ) -> None:
        self.file_events = file_events
        self.verdicts = verdicts
        self.quarantine_service = QuarantineService(quarantine)

    def scan_bytes(
        self,
        *,
        asset_id: str,
        session_id: str,
        path: str,
        content: bytes,
        process_identity_id: str | None = None,
        signer_name: str | None = None,
        signer_status: str | None = None,
        origin_kind: str | None = None,
        origin_source: str | None = None,
        event_kind: str = 'demand_scan',
        quarantine_on_malicious: bool = True,
    ) -> ScanOutcome:
        now = datetime.now(timezone.utc)
        sha256 = hashlib.sha256(content).hexdigest()
        file_event = FileEvent(
            file_event_id=f'fe_{uuid4().hex[:12]}',
            asset_id=asset_id,
            session_id=session_id,
            process_identity_id=process_identity_id,
            path=path,
            sha256=sha256,
            file_size=len(content),
            file_type=Path(path).suffix.lstrip('.') or None,
            origin_kind=origin_kind,
            origin_source=origin_source,
            signer_name=signer_name,
            signer_status=signer_status,
            event_kind=event_kind,
            ts=now,
        )
        self.file_events.create_file_event(file_event)

        signature_name, family_name = match_content_signature(content)
        rep = file_reputation(sha256, signer_name=signer_name)

        verdict = 'clean'
        verdict_source = 'allowlist' if rep and rep.reputation_score < 0.1 else 'heuristic'
        confidence = 0.1
        reputation_score = rep.reputation_score if rep else None
        cloud_lookup_hit = rep.cloud_lookup_hit if rep else False
        sig_name = signature_name or (rep.signature_name if rep else None)
        fam_name = family_name or (rep.family_name if rep else None)

        lowered_path = path.lower()
        if signature_name:
            verdict = 'malicious'
            verdict_source = 'signature'
            confidence = 0.99
        elif rep and rep.reputation_score >= 0.95:
            verdict = 'malicious'
            verdict_source = 'reputation'
            confidence = rep.reputation_score
        elif origin_kind == 'download' and (lowered_path.endswith('.scr') or lowered_path.endswith('.js')) and signer_status in {None, 'unsigned', 'unknown'}:
            verdict = 'suspicious'
            verdict_source = 'heuristic'
            confidence = 0.72
        elif rep and rep.reputation_score < 0.1:
            verdict = 'clean'
            verdict_source = 'allowlist'
            confidence = 0.92

        verdict_obj = MalwareVerdict(
            malware_verdict_id=f'mv_{uuid4().hex[:12]}',
            file_event_id=file_event.file_event_id,
            sha256=sha256,
            verdict=verdict,
            verdict_source=verdict_source,
            signature_name=sig_name,
            family_name=fam_name,
            confidence_score=confidence,
            reputation_score=reputation_score,
            cloud_lookup_hit=cloud_lookup_hit,
            created_ts=now,
        )
        self.verdicts.create_verdict(verdict_obj)

        quarantine_record = None
        if quarantine_on_malicious and verdict == 'malicious':
            quarantine_record = self.quarantine_service.quarantine(
                asset_id=asset_id,
                sha256=sha256,
                original_path=path,
                reason=sig_name or fam_name or 'malicious_file',
                malware_verdict_id=verdict_obj.malware_verdict_id,
            )
        return ScanOutcome(file_event=file_event, verdict=verdict_obj, quarantine_record=quarantine_record)

    def scan_base64(self, *, asset_id: str, session_id: str, path: str, content_base64: str, **kwargs) -> ScanOutcome:
        return self.scan_bytes(asset_id=asset_id, session_id=session_id, path=path, content=base64.b64decode(content_base64.encode('utf-8')), **kwargs)
