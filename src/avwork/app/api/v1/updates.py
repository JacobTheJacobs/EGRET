from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from typing import Annotated

from fastapi import Depends

from app.api.deps import get_malware_verdict_repository, get_quarantine_repository
from app.services.av.fp_tuning import FalsePositiveTuningService
from app.services.av.updater import ContentUpdaterService
from app.storage.repositories.interfaces import MalwareVerdictRepository, QuarantineRepository

router = APIRouter(prefix='/api/v1/updates', tags=['updates'])


class ContentPackInstallRequest(BaseModel):
    content_base64: str | None = None
    content_json: dict | None = None


@router.get('/content/status')
def content_status() -> dict:
    return ContentUpdaterService().status().__dict__


@router.post('/content/install')
def install_content_pack(payload: ContentPackInstallRequest) -> dict:
    updater = ContentUpdaterService()
    if payload.content_json is not None:
        pack = updater.install_json(payload.content_json)
    elif payload.content_base64 is not None:
        pack = updater.install_base64_json(payload.content_base64)
    else:
        raise HTTPException(status_code=400, detail='Either content_json or content_base64 must be supplied.')
    return {'installed': True, 'pack': pack, 'status': updater.status().__dict__}


@router.get('/tuning/summary')
def tuning_summary(
    verdicts: Annotated[MalwareVerdictRepository, Depends(get_malware_verdict_repository)],
    quarantine: Annotated[QuarantineRepository, Depends(get_quarantine_repository)],
) -> dict:
    summary = FalsePositiveTuningService(verdicts=verdicts, quarantine=quarantine).summary()
    return summary.__dict__
