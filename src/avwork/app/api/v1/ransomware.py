from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_ransomware_signal_repository
from app.services.ransomware.detector import RansomwareDetectorService, RansomwareObservation
from app.storage.repositories.interfaces import RansomwareSignalRepository

router = APIRouter(prefix='/api/v1/ransomware', tags=['ransomware'])


class RansomwareEvaluateRequest(BaseModel):
    asset_id: str
    session_id: str
    process_identity_id: str | None = None
    process_name: str | None = None
    signer_status: str | None = None
    protected_path: str | None = None
    modified_files_count: int = 0
    rename_delete_burst_count: int = 0
    entropy_spike: bool = False
    touches_protected_dirs: bool = False
    canary_touched: bool = False


@router.get('/signals')
def list_ransomware_signals(
    repo: Annotated[RansomwareSignalRepository, Depends(get_ransomware_signal_repository)],
    asset_id: str | None = None,
) -> dict:
    return {'items': [item.model_dump(mode='json') for item in repo.list_signals(asset_id=asset_id)]}


@router.post('/evaluate')
def evaluate_ransomware(
    payload: RansomwareEvaluateRequest,
    repo: Annotated[RansomwareSignalRepository, Depends(get_ransomware_signal_repository)],
) -> dict:
    signal = RansomwareDetectorService(repo).evaluate(RansomwareObservation(**payload.model_dump()))
    return {'ransomware_signal': signal.model_dump(mode='json') if signal else None}
