from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import get_connection_repository, get_destination_repository, get_process_repository, get_trust_repository
from app.api.security import require_ingest_token
from app.models.trust_context_snapshot import TrustContextSnapshot
from app.storage.adapters.legacy_flow_adapter import LegacyFlowDualWriter, LegacyFlowRecord
from app.storage.repositories.interfaces import ConnectionRepository, DestinationIdentityRepository, ProcessIdentityRepository, TrustSnapshotRepository

router = APIRouter(prefix='/api/v1/ingest', tags=['ingest'])


class ConnectionFlowIngest(BaseModel):
    asset_id: str
    session_id: str
    process_id: int
    process_name: str
    process_path: str
    start_ts: datetime
    remote_ip: str
    remote_port: int = Field(ge=1, le=65535)
    transport: str
    network_zone: str
    connection_id: str | None = None
    direction: str = 'outbound'
    protocol: str | None = None
    end_ts: datetime | None = None
    local_ip: str | None = None
    local_port: int | None = Field(default=None, ge=1, le=65535)
    bytes_out: int | None = 0
    bytes_in: int | None = 0
    duration_ms: int | None = None
    signer_name: str | None = None
    signer_status: str | None = None
    executable_hash: str | None = None
    parent_process_id: int | None = None
    package_id: str | None = None
    service_name: str | None = None
    matched_domain: str | None = None
    sni: str | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_fingerprint: str | None = None
    service_fingerprint: str | None = None
    resolver_source: str | None = None
    interface_name: str | None = None
    vpn_state: str | None = None
    first_seen_on_asset: bool | None = None
    first_seen_in_fleet: bool | None = None
    prevalence_on_asset: float | None = None
    prevalence_in_fleet: float | None = None
    flow_risk_score: float | None = None
    rule_suggestion_score: float | None = None
    anomaly_score: float | None = None
    trust_context_snapshot_id: str | None = None


class ConnectionIngestRequest(BaseModel):
    records: list[ConnectionFlowIngest] = Field(min_length=1, max_length=1000)


class TrustSnapshotIngestRequest(BaseModel):
    snapshots: list[TrustContextSnapshot] = Field(min_length=1, max_length=1000)


def _writer(
    connections: ConnectionRepository,
    processes: ProcessIdentityRepository,
    destinations: DestinationIdentityRepository,
) -> LegacyFlowDualWriter:
    return LegacyFlowDualWriter(connections=connections, processes=processes, destinations=destinations)


@router.post('/connections')
def ingest_connections(
    payload: ConnectionIngestRequest,
    _auth: Annotated[None, Depends(require_ingest_token)],
    connections: Annotated[ConnectionRepository, Depends(get_connection_repository)],
    processes: Annotated[ProcessIdentityRepository, Depends(get_process_repository)],
    destinations: Annotated[DestinationIdentityRepository, Depends(get_destination_repository)],
) -> dict:
    writer = _writer(connections, processes, destinations)
    events = []
    for record in payload.records:
        event = writer.write(LegacyFlowRecord(**record.model_dump(exclude={'trust_context_snapshot_id'})))
        if record.trust_context_snapshot_id:
            event = connections.upsert_connection(event.model_copy(update={'trust_context_snapshot_id': record.trust_context_snapshot_id}))
        events.append(event)
    return {
        'ingested': len(events),
        'connection_ids': [event.connection_id for event in events],
        'items': [event.model_dump(mode='json') for event in events],
    }


@router.post('/trust-snapshots')
def ingest_trust_snapshots(
    payload: TrustSnapshotIngestRequest,
    _auth: Annotated[None, Depends(require_ingest_token)],
    trust: Annotated[TrustSnapshotRepository, Depends(get_trust_repository)],
) -> dict:
    snapshots = [trust.upsert_snapshot(snapshot) for snapshot in payload.snapshots]
    return {
        'ingested': len(snapshots),
        'trust_context_snapshot_ids': [snapshot.trust_context_snapshot_id for snapshot in snapshots],
        'items': [snapshot.model_dump(mode='json') for snapshot in snapshots],
    }
