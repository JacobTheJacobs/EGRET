from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import (
    get_connection_repository,
    get_decision_repository,
    get_destination_repository,
    get_process_repository,
    get_rule_repository,
    get_trust_repository,
)
from app.services.investigations.timeline_builder import InvestigationTimelineService
from app.storage.repositories.interfaces import (
    ConnectionRepository,
    DecisionRepository,
    DestinationIdentityRepository,
    ProcessIdentityRepository,
    RuleRepository,
    TrustSnapshotRepository,
)

router = APIRouter(prefix='/api/v1/investigations', tags=['investigations'])


def get_timeline_service(
    connections: Annotated[ConnectionRepository, Depends(get_connection_repository)],
    processes: Annotated[ProcessIdentityRepository, Depends(get_process_repository)],
    destinations: Annotated[DestinationIdentityRepository, Depends(get_destination_repository)],
    decisions: Annotated[DecisionRepository, Depends(get_decision_repository)],
    rules: Annotated[RuleRepository, Depends(get_rule_repository)],
    trust: Annotated[TrustSnapshotRepository, Depends(get_trust_repository)],
) -> InvestigationTimelineService:
    return InvestigationTimelineService(
        connections=connections,
        processes=processes,
        destinations=destinations,
        decisions=decisions,
        rules=rules,
        trust=trust,
    )


@router.get('/assets/{asset_id}/timeline')
def get_asset_timeline(
    asset_id: str,
    service: Annotated[InvestigationTimelineService, Depends(get_timeline_service)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
) -> dict:
    return service.build_asset_timeline(asset_id=asset_id, page=page, page_size=page_size)
