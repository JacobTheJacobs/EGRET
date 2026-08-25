from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_behavior_alert_repository, get_malware_verdict_repository, get_ransomware_signal_repository, get_web_verdict_repository
from app.services.behavior.detector import BehaviorDetectorService, BehaviorObservation
from app.storage.repositories.interfaces import BehaviorAlertRepository, MalwareVerdictRepository, RansomwareSignalRepository, WebVerdictRepository

router = APIRouter(prefix='/api/v1/threats', tags=['threats'])


@router.get('')
def list_threats(
    verdicts: Annotated[MalwareVerdictRepository, Depends(get_malware_verdict_repository)],
    web: Annotated[WebVerdictRepository, Depends(get_web_verdict_repository)],
    behavior: Annotated[BehaviorAlertRepository, Depends(get_behavior_alert_repository)],
    ransomware: Annotated[RansomwareSignalRepository, Depends(get_ransomware_signal_repository)],
    asset_id: str | None = None,
) -> dict:
    malware_items = [item.model_dump(mode='json') for item in verdicts.list_verdicts(asset_id=asset_id, malicious_only=True)]
    web_items = [item.model_dump(mode='json') for item in web.list_web_verdicts(asset_id=asset_id, blocked_only=True)]
    behavior_items = [item.model_dump(mode='json') for item in behavior.list_alerts(asset_id=asset_id)]
    ransomware_items = [item.model_dump(mode='json') for item in ransomware.list_signals(asset_id=asset_id)]
    return {
        'malware_verdicts': malware_items,
        'web_verdicts': web_items,
        'behavior_alerts': behavior_items,
        'ransomware_signals': ransomware_items,
        'total': len(malware_items) + len(web_items) + len(behavior_items) + len(ransomware_items),
    }


class BehaviorEvaluateRequest(BaseModel):
    asset_id: str
    session_id: str
    process_identity_id: str | None = None
    process_name: str | None = None
    parent_process_name: str | None = None
    signer_status: str | None = None
    origin_kind: str | None = None
    file_verdict: str | None = None
    launches_shell: bool = False
    writes_persistence: bool = False
    touches_protected_dirs: bool = False
    network_destination: str | None = None


@router.post('/behavior-evaluate')
def behavior_evaluate(
    payload: BehaviorEvaluateRequest,
    repo: Annotated[BehaviorAlertRepository, Depends(get_behavior_alert_repository)],
) -> dict:
    alert = BehaviorDetectorService(repo).evaluate(BehaviorObservation(**payload.model_dump()))
    return {'behavior_alert': alert.model_dump(mode='json') if alert else None}
