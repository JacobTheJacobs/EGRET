from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.process_identity import ProcessIdentity
from app.storage.repositories.interfaces import (
    ConnectionRepository,
    DestinationIdentityRepository,
    ProcessIdentityRepository,
)


def _stable_id(prefix: str, *parts: object) -> str:
    digest = hashlib.sha256('|'.join(str(part or '') for part in parts).encode('utf-8')).hexdigest()[:16]
    return f'{prefix}_{digest}'


#: Public alias so producers can mint identities matching this adapter's scheme.
stable_id = _stable_id


@dataclass(frozen=True)
class LegacyFlowRecord:
    asset_id: str
    session_id: str
    process_id: int
    process_name: str
    process_path: str
    start_ts: datetime
    remote_ip: str
    remote_port: int
    transport: str
    network_zone: str
    connection_id: str | None = None
    direction: str = 'outbound'
    protocol: str | None = None
    end_ts: datetime | None = None
    local_ip: str | None = None
    local_port: int | None = None
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


class LegacyFlowDualWriter:
    def __init__(
        self,
        *,
        connections: ConnectionRepository,
        processes: ProcessIdentityRepository,
        destinations: DestinationIdentityRepository,
    ) -> None:
        self.connections = connections
        self.processes = processes
        self.destinations = destinations

    def write(self, record: LegacyFlowRecord) -> ConnectionEvent:
        process_identity_id = _stable_id('pi', record.asset_id, record.session_id, record.process_id, record.process_path)
        destination_identity_id = _stable_id(
            'di',
            record.remote_ip,
            record.remote_port,
            record.matched_domain or record.sni,
            record.protocol or record.transport,
        )
        connection_id = record.connection_id or _stable_id(
            'ce', record.asset_id, record.session_id, process_identity_id, record.start_ts.isoformat(), record.remote_ip, record.remote_port
        )

        process = ProcessIdentity(
            process_identity_id=process_identity_id,
            asset_id=record.asset_id,
            session_id=record.session_id,
            process_id=record.process_id,
            parent_process_id=record.parent_process_id,
            process_name=record.process_name,
            process_path=record.process_path,
            executable_hash=record.executable_hash,
            signer_name=record.signer_name,
            signer_status=record.signer_status,
            package_id=record.package_id,
            service_name=record.service_name,
            first_seen_ts=record.start_ts,
            last_seen_ts=record.end_ts or record.start_ts,
        )
        self.processes.upsert_process_identity(process)

        destination = DestinationIdentity(
            destination_identity_id=destination_identity_id,
            canonical_name=record.matched_domain or record.sni,
            matched_domain=record.matched_domain,
            sni=record.sni,
            ip=record.remote_ip,
            port=record.remote_port,
            protocol=record.protocol,
            certificate_subject=record.certificate_subject,
            certificate_issuer=record.certificate_issuer,
            certificate_fingerprint=record.certificate_fingerprint,
            service_fingerprint=record.service_fingerprint,
            resolver_source=record.resolver_source,
            first_seen_ts=record.start_ts,
            last_seen_ts=record.end_ts or record.start_ts,
        )
        self.destinations.upsert_destination_identity(destination)

        event = ConnectionEvent(
            connection_id=connection_id,
            asset_id=record.asset_id,
            session_id=record.session_id,
            process_identity_id=process_identity_id,
            destination_identity_id=destination_identity_id,
            start_ts=record.start_ts,
            end_ts=record.end_ts,
            direction=record.direction,
            protocol=record.protocol,
            transport=record.transport,
            local_ip=record.local_ip,
            local_port=record.local_port,
            remote_ip=record.remote_ip,
            remote_port=record.remote_port,
            interface_name=record.interface_name,
            network_zone=record.network_zone,
            vpn_state=record.vpn_state,
            bytes_out=record.bytes_out,
            bytes_in=record.bytes_in,
            duration_ms=record.duration_ms,
            first_seen_on_asset=record.first_seen_on_asset,
            first_seen_in_fleet=record.first_seen_in_fleet,
            prevalence_on_asset=record.prevalence_on_asset,
            prevalence_in_fleet=record.prevalence_in_fleet,
            flow_risk_score=record.flow_risk_score,
            rule_suggestion_score=record.rule_suggestion_score,
            anomaly_score=record.anomaly_score,
        )
        self.connections.upsert_connection(event)
        return event
