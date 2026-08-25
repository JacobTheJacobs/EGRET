from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_file_event_repository, get_malware_verdict_repository, get_quarantine_repository
from app.services.av.on_access import OnAccessProtectionService
from app.services.av.scanner import ScannerService
from app.storage.repositories.interfaces import FileEventRepository, MalwareVerdictRepository, QuarantineRepository

router = APIRouter(prefix='/api/v1/scans', tags=['scans'])


class ContentScanRequest(BaseModel):
    asset_id: str
    session_id: str
    path: str
    content_base64: str
    origin_kind: str | None = None
    origin_source: str | None = None
    signer_name: str | None = None
    signer_status: str | None = None
    process_identity_id: str | None = None


@router.get('/modes')
def list_scan_modes() -> dict:
    return {'items': ['demand_scan', 'download_scan', 'execute_scan', 'on_access_write', 'on_access_execute']}


@router.post('/on-access/write')
def on_access_write(
    payload: ContentScanRequest,
    files: Annotated[FileEventRepository, Depends(get_file_event_repository)],
    verdicts: Annotated[MalwareVerdictRepository, Depends(get_malware_verdict_repository)],
    quarantine: Annotated[QuarantineRepository, Depends(get_quarantine_repository)],
) -> dict:
    scanner = ScannerService(file_events=files, verdicts=verdicts, quarantine=quarantine)
    decision = OnAccessProtectionService(scanner).scan_write(**payload.model_dump())
    return {
        'mode': decision.mode,
        'action': decision.action,
        'reason': decision.reason,
        'file_event': decision.outcome.file_event.model_dump(mode='json'),
        'verdict': decision.outcome.verdict.model_dump(mode='json'),
        'quarantine_record': decision.outcome.quarantine_record.model_dump(mode='json') if decision.outcome.quarantine_record else None,
    }


@router.post('/on-access/execute')
def on_access_execute(
    payload: ContentScanRequest,
    files: Annotated[FileEventRepository, Depends(get_file_event_repository)],
    verdicts: Annotated[MalwareVerdictRepository, Depends(get_malware_verdict_repository)],
    quarantine: Annotated[QuarantineRepository, Depends(get_quarantine_repository)],
) -> dict:
    scanner = ScannerService(file_events=files, verdicts=verdicts, quarantine=quarantine)
    decision = OnAccessProtectionService(scanner).scan_execute(**payload.model_dump())
    return {
        'mode': decision.mode,
        'action': decision.action,
        'reason': decision.reason,
        'file_event': decision.outcome.file_event.model_dump(mode='json'),
        'verdict': decision.outcome.verdict.model_dump(mode='json'),
        'quarantine_record': decision.outcome.quarantine_record.model_dump(mode='json') if decision.outcome.quarantine_record else None,
    }
