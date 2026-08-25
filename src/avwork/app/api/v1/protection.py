from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import (
    get_behavior_alert_repository,
    get_file_event_repository,
    get_malware_verdict_repository,
    get_quarantine_repository,
    get_remediation_action_repository,
    get_ransomware_signal_repository,
    get_web_verdict_repository,
)
from app.services.av.fp_tuning import FalsePositiveTuningService
from app.services.av.updater import ContentUpdaterService
from app.services.web.url_reputation import UrlReputationService
from app.storage.repositories.interfaces import (
    BehaviorAlertRepository,
    FileEventRepository,
    MalwareVerdictRepository,
    QuarantineRepository,
    RemediationActionRepository,
    RansomwareSignalRepository,
    WebVerdictRepository,
)

router = APIRouter(prefix='/api/v1/protection', tags=['protection'])


class WebCheckRequest(BaseModel):
    asset_id: str
    url: str
    process_identity_id: str | None = None


@router.get('/status')
def protection_status(
    files: Annotated[FileEventRepository, Depends(get_file_event_repository)],
    verdicts: Annotated[MalwareVerdictRepository, Depends(get_malware_verdict_repository)],
    quarantine: Annotated[QuarantineRepository, Depends(get_quarantine_repository)],
    web: Annotated[WebVerdictRepository, Depends(get_web_verdict_repository)],
    behavior: Annotated[BehaviorAlertRepository, Depends(get_behavior_alert_repository)],
    ransomware: Annotated[RansomwareSignalRepository, Depends(get_ransomware_signal_repository)],
    remediation: Annotated[RemediationActionRepository, Depends(get_remediation_action_repository)],
) -> dict:
    _, total_files = files.list_file_events(page=1, page_size=1)
    malicious = len(verdicts.list_verdicts(malicious_only=True))
    active_quarantine = len([item for item in quarantine.list_records() if not item.restored and not item.deleted])
    blocked_web = len(web.list_web_verdicts(blocked_only=True))
    behavior_count = len(behavior.list_alerts())
    ransomware_count = len(ransomware.list_signals())
    remediation_count = len(remediation.list_actions())
    update_status = ContentUpdaterService().status()
    tuning = FalsePositiveTuningService(verdicts=verdicts, quarantine=quarantine).summary()
    return {
        'status': 'ok',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'av': {
            'file_events': total_files,
            'malware_verdicts': malicious,
            'active_quarantine': active_quarantine,
            'blocked_web_events': blocked_web,
            'behavior_alerts': behavior_count,
            'ransomware_signals': ransomware_count,
            'remediation_actions': remediation_count,
            'real_time_modes': ['demand_scan', 'download_scan', 'execute_scan', 'on_access_write', 'on_access_execute', 'behavior_blocker_ready', 'ransomware_guard_ready', 'remediation_ready'],
            'content_updates': update_status.__dict__,
            'tuning': tuning.__dict__,
        },
    }


@router.post('/web-check')
def web_check(payload: WebCheckRequest, repo: Annotated[WebVerdictRepository, Depends(get_web_verdict_repository)]) -> dict:
    item = UrlReputationService(repo).check(**payload.model_dump())
    return item.model_dump(mode='json')
