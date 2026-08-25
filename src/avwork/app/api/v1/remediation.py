from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import get_behavior_alert_repository, get_remediation_action_repository, get_ransomware_signal_repository
from app.api.errors import not_found
from app.services.av.remediation import RemediationService
from app.storage.repositories.interfaces import BehaviorAlertRepository, RemediationActionRepository, RansomwareSignalRepository

router = APIRouter(prefix='/api/v1/remediation', tags=['remediation'])


@router.get('')
def list_remediation_actions(
    repo: Annotated[RemediationActionRepository, Depends(get_remediation_action_repository)],
    asset_id: str | None = None,
) -> dict:
    return {'items': [item.model_dump(mode='json') for item in repo.list_actions(asset_id=asset_id)]}


@router.post('/behavior/{behavior_alert_id}')
def remediate_behavior_alert(
    behavior_alert_id: str,
    behavior_repo: Annotated[BehaviorAlertRepository, Depends(get_behavior_alert_repository)],
    repo: Annotated[RemediationActionRepository, Depends(get_remediation_action_repository)],
) -> dict:
    alert = behavior_repo.get_alert(behavior_alert_id)
    if alert is None:
        raise not_found(code='behavior_alert_not_found', message='No behavior alert exists for the supplied behavior_alert_id.', extra={'behavior_alert_id': behavior_alert_id})
    action = RemediationService(repo).from_behavior_alert(alert)
    return action.model_dump(mode='json')


@router.post('/ransomware/{ransomware_signal_id}')
def remediate_ransomware_signal(
    ransomware_signal_id: str,
    signals: Annotated[RansomwareSignalRepository, Depends(get_ransomware_signal_repository)],
    repo: Annotated[RemediationActionRepository, Depends(get_remediation_action_repository)],
) -> dict:
    signal = signals.get_signal(ransomware_signal_id)
    if signal is None:
        raise not_found(code='ransomware_signal_not_found', message='No ransomware signal exists for the supplied ransomware_signal_id.', extra={'ransomware_signal_id': ransomware_signal_id})
    action = RemediationService(repo).from_ransomware_signal(signal)
    return action.model_dump(mode='json')
