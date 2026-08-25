from __future__ import annotations

import os
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import get_connection_repository, get_decision_repository, get_destination_repository, get_process_repository, get_rule_repository, get_trust_repository
from app.api.errors import not_found
from app.services.capture.host_connections import HostConnectionCaptureService
from app.services.capture.decision_writer import CaptureDecisionWriter
from app.services.capture.reverse_dns import ReverseDnsResolver
from app.services.investigations.connection_details import ConnectionDetailsService
from app.storage.adapters.legacy_flow_adapter import LegacyFlowDualWriter
from app.storage.repositories.interfaces import ConnectionRepository, DecisionRepository, DestinationIdentityRepository, ProcessIdentityRepository, RuleRepository, TrustSnapshotRepository

#: Shared so the PTR cache persists between capture calls. Set
#: EGRET_REVERSE_DNS=0 to skip name resolution entirely (tests use this to
#: stay offline).
_RESOLVER = ReverseDnsResolver() if os.environ.get('EGRET_REVERSE_DNS', '1') != '0' else None

router = APIRouter(prefix='/api/v1/connections', tags=['connections'])


class HostCaptureRequest(BaseModel):
    limit: int = Field(default=100, ge=1, le=500)
    asset_id: str | None = None
    session_id: str | None = None


def get_connection_details_service(
    connections: Annotated[ConnectionRepository, Depends(get_connection_repository)],
    processes: Annotated[ProcessIdentityRepository, Depends(get_process_repository)],
    destinations: Annotated[DestinationIdentityRepository, Depends(get_destination_repository)],
    decisions: Annotated[DecisionRepository, Depends(get_decision_repository)],
    rules: Annotated[RuleRepository, Depends(get_rule_repository)],
    trust: Annotated[TrustSnapshotRepository, Depends(get_trust_repository)],
) -> ConnectionDetailsService:
    return ConnectionDetailsService(connections=connections, processes=processes, destinations=destinations, decisions=decisions, rules=rules, trust=trust)


@router.get('')
def list_connections(
    repo: Annotated[ConnectionRepository, Depends(get_connection_repository)],
    details: Annotated[ConnectionDetailsService, Depends(get_connection_details_service)],
    asset_id: str | None = None,
    process_name: str | None = None,
    domain: str | None = None,
    ip: str | None = None,
    port: int | None = None,
    verdict: str | None = None,
    network_zone: str | None = None,
    start_ts: datetime | None = None,
    end_ts: datetime | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
) -> dict:
    items, total = repo.list_connections(asset_id=asset_id, process_name=process_name, domain=domain, ip=ip, port=port, verdict=verdict, network_zone=network_zone, start_ts=start_ts, end_ts=end_ts, page=page, page_size=page_size)
    rows = [details.build_row(item.connection_id) for item in items]
    return {'items': [row for row in rows if row is not None], 'page': page, 'page_size': page_size, 'total': total}


@router.post('/capture-host')
def capture_host_connections(
    payload: HostCaptureRequest | None,
    connections: Annotated[ConnectionRepository, Depends(get_connection_repository)],
    processes: Annotated[ProcessIdentityRepository, Depends(get_process_repository)],
    destinations: Annotated[DestinationIdentityRepository, Depends(get_destination_repository)],
    rules: Annotated[RuleRepository, Depends(get_rule_repository)],
    decisions: Annotated[DecisionRepository, Depends(get_decision_repository)],
) -> dict:
    request = payload or HostCaptureRequest()
    writer = LegacyFlowDualWriter(connections=connections, processes=processes, destinations=destinations)
    decision_writer = CaptureDecisionWriter(rules=rules, decisions=decisions)
    return HostConnectionCaptureService(writer, resolver=_RESOLVER, decisions=decision_writer).capture(limit=request.limit, asset_id=request.asset_id, session_id=request.session_id).to_dict()


@router.get('/{connection_id}')
def get_connection_detail(connection_id: str, details: Annotated[ConnectionDetailsService, Depends(get_connection_details_service)]) -> dict:
    try:
        payload = details.build_detail(connection_id)
    except LookupError as exc:
        raise HTTPException(status_code=500, detail={'error': {'code': 'integrity_error', 'message': str(exc)}}) from exc
    if payload is None:
        raise not_found(code='connection_not_found', message='No connection exists for the supplied connection_id.', extra={'connection_id': connection_id})
    return payload
