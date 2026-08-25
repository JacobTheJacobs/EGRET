from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.api.deps import get_behavior_alert_repository, get_file_event_repository, get_malware_verdict_repository, get_quarantine_repository, get_web_verdict_repository
from app.services.av.realtime import RealtimeProtectionService
from app.services.av.scanner import ScannerService
from app.storage.repositories.interfaces import BehaviorAlertRepository, FileEventRepository, MalwareVerdictRepository, QuarantineRepository, WebVerdictRepository

router = APIRouter(prefix='/api/v1/files', tags=['files'])


class ScanRequest(BaseModel):
    asset_id: str
    session_id: str
    path: str
    content_base64: str
    process_identity_id: str | None = None
    signer_name: str | None = None
    signer_status: str | None = None
    origin_kind: str | None = None
    origin_source: str | None = None
    event_kind: str = 'demand_scan'
    quarantine_on_malicious: bool = True


@router.get('')
def list_file_events(
    repo: Annotated[FileEventRepository, Depends(get_file_event_repository)],
    asset_id: str | None = None,
    verdict: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
) -> dict:
    items, total = repo.list_file_events(asset_id=asset_id, verdict=verdict, page=page, page_size=page_size)
    return {'items': [item.model_dump(mode='json') for item in items], 'page': page, 'page_size': page_size, 'total': total}


@router.post('/scan')
def scan_file(
    payload: ScanRequest,
    file_events: Annotated[FileEventRepository, Depends(get_file_event_repository)],
    verdicts: Annotated[MalwareVerdictRepository, Depends(get_malware_verdict_repository)],
    quarantine: Annotated[QuarantineRepository, Depends(get_quarantine_repository)],
) -> dict:
    outcome = ScannerService(file_events=file_events, verdicts=verdicts, quarantine=quarantine).scan_base64(**payload.model_dump())
    return {
        'file_event': outcome.file_event.model_dump(mode='json'),
        'verdict': outcome.verdict.model_dump(mode='json'),
        'quarantine_record': outcome.quarantine_record.model_dump(mode='json') if outcome.quarantine_record else None,
    }


class DownloadScanRequest(BaseModel):
    asset_id: str
    session_id: str
    path: str
    url: str
    content_base64: str
    process_identity_id: str | None = None
    process_name: str | None = None
    signer_name: str | None = None
    signer_status: str | None = None
    quarantine_on_malicious: bool = True


class ExecuteScanRequest(BaseModel):
    asset_id: str
    session_id: str
    path: str
    content_base64: str
    process_identity_id: str | None = None
    process_name: str | None = None
    parent_process_name: str | None = None
    signer_name: str | None = None
    signer_status: str | None = None
    origin_kind: str | None = None
    network_destination: str | None = None
    quarantine_on_malicious: bool = True


@router.post('/download-scan')
def download_scan(
    payload: DownloadScanRequest,
    file_events: Annotated[FileEventRepository, Depends(get_file_event_repository)],
    verdicts: Annotated[MalwareVerdictRepository, Depends(get_malware_verdict_repository)],
    quarantine: Annotated[QuarantineRepository, Depends(get_quarantine_repository)],
    web_repo: Annotated[WebVerdictRepository, Depends(get_web_verdict_repository)],
    behavior_repo: Annotated[BehaviorAlertRepository, Depends(get_behavior_alert_repository)],
) -> dict:
    import base64
    outcome = RealtimeProtectionService(
        file_events=file_events, verdicts=verdicts, quarantine=quarantine, web_verdicts=web_repo, behavior_alerts=behavior_repo
    ).scan_download(
        asset_id=payload.asset_id,
        session_id=payload.session_id,
        path=payload.path,
        url=payload.url,
        content=base64.b64decode(payload.content_base64.encode('utf-8')),
        process_identity_id=payload.process_identity_id,
        process_name=payload.process_name,
        signer_name=payload.signer_name,
        signer_status=payload.signer_status,
        quarantine_on_malicious=payload.quarantine_on_malicious,
    )
    return {
        'file_event': outcome.scan.file_event.model_dump(mode='json'),
        'verdict': outcome.scan.verdict.model_dump(mode='json'),
        'quarantine_record': outcome.scan.quarantine_record.model_dump(mode='json') if outcome.scan.quarantine_record else None,
        'web_verdict': outcome.web_verdict.model_dump(mode='json') if outcome.web_verdict else None,
        'behavior_alert': outcome.behavior_alert.model_dump(mode='json') if outcome.behavior_alert else None,
    }


@router.post('/execute-scan')
def execute_scan(
    payload: ExecuteScanRequest,
    file_events: Annotated[FileEventRepository, Depends(get_file_event_repository)],
    verdicts: Annotated[MalwareVerdictRepository, Depends(get_malware_verdict_repository)],
    quarantine: Annotated[QuarantineRepository, Depends(get_quarantine_repository)],
    web_repo: Annotated[WebVerdictRepository, Depends(get_web_verdict_repository)],
    behavior_repo: Annotated[BehaviorAlertRepository, Depends(get_behavior_alert_repository)],
) -> dict:
    import base64
    outcome = RealtimeProtectionService(
        file_events=file_events, verdicts=verdicts, quarantine=quarantine, web_verdicts=web_repo, behavior_alerts=behavior_repo
    ).scan_execute(
        asset_id=payload.asset_id,
        session_id=payload.session_id,
        path=payload.path,
        content=base64.b64decode(payload.content_base64.encode('utf-8')),
        process_identity_id=payload.process_identity_id,
        process_name=payload.process_name,
        parent_process_name=payload.parent_process_name,
        signer_name=payload.signer_name,
        signer_status=payload.signer_status,
        origin_kind=payload.origin_kind,
        network_destination=payload.network_destination,
        quarantine_on_malicious=payload.quarantine_on_malicious,
    )
    return {
        'file_event': outcome.scan.file_event.model_dump(mode='json'),
        'verdict': outcome.scan.verdict.model_dump(mode='json'),
        'quarantine_record': outcome.scan.quarantine_record.model_dump(mode='json') if outcome.scan.quarantine_record else None,
        'behavior_alert': outcome.behavior_alert.model_dump(mode='json') if outcome.behavior_alert else None,
    }
