from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_quarantine_repository
from app.api.errors import not_found
from app.storage.repositories.interfaces import QuarantineRepository

router = APIRouter(prefix='/api/v1/quarantine', tags=['quarantine'])


class QuarantineUpdateRequest(BaseModel):
    restored: bool | None = None
    deleted: bool | None = None


@router.get('')
def list_quarantine(repo: Annotated[QuarantineRepository, Depends(get_quarantine_repository)], asset_id: str | None = None) -> dict:
    return {'items': [item.model_dump(mode='json') for item in repo.list_records(asset_id=asset_id)]}


@router.patch('/{quarantine_record_id}')
def update_quarantine(quarantine_record_id: str, payload: QuarantineUpdateRequest, repo: Annotated[QuarantineRepository, Depends(get_quarantine_repository)]) -> dict:
    record = repo.update_record(quarantine_record_id, restored=payload.restored, deleted=payload.deleted, updated_ts=datetime.now(timezone.utc))
    if record is None:
        raise not_found(code='quarantine_record_not_found', message='No quarantine record exists for the supplied quarantine_record_id.', extra={'quarantine_record_id': quarantine_record_id})
    return record.model_dump(mode='json')
