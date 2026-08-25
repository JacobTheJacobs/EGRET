from __future__ import annotations

import ipaddress
import json
import platform
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable

from app.services.capture.decision_writer import CaptureDecisionWriter
from app.services.capture.process_enrichment import ProcessEnricher
from app.services.capture.proc_sockets import build_inode_owner_map, read_sockets, username_for_uid
from app.services.capture.reverse_dns import ReverseDnsResolver
from app.storage.adapters.legacy_flow_adapter import LegacyFlowDualWriter, LegacyFlowRecord, stable_id


@dataclass(frozen=True)
class HostSocketObservation:
    process_id: int
    process_name: str
    process_path: str
    local_ip: str | None
    local_port: int | None
    remote_ip: str
    remote_port: int
    transport: str = 'tcp'
    # Provenance: what the binary is, not just who opened the socket.
    executable_hash: str | None = None
    package_id: str | None = None
    signer_name: str | None = None
    signer_status: str | None = None
    parent_process_id: int | None = None
    service_name: str | None = None


@dataclass(frozen=True)
class HostCaptureSummary:
    status: str
    source: str
    captured: int
    skipped: int
    connection_ids: list[str]
    message: str | None = None

    def to_dict(self) -> dict:
        return {
            'status': self.status,
            'source': self.source,
            'captured': self.captured,
            'skipped': self.skipped,
            'connection_ids': self.connection_ids,
            'message': self.message,
        }


Collector = Callable[[], Iterable[HostSocketObservation]]


class HostConnectionCaptureService:
    def __init__(
        self,
        writer: LegacyFlowDualWriter,
        collector: Collector | None = None,
        resolver: ReverseDnsResolver | None = None,
        decisions: CaptureDecisionWriter | None = None,
    ) -> None:
        self.writer = writer
        self.collector = collector
        # Optional so tests stay offline; the API layer supplies a real resolver.
        self.resolver = resolver
        # Optional so capture still works before policy storage is wired up.
        self.decisions = decisions

    def capture(
        self,
        *,
        limit: int = 100,
        asset_id: str | None = None,
        session_id: str | None = None,
        now: datetime | None = None,
    ) -> HostCaptureSummary:
        timestamp = now or datetime.now(timezone.utc)
        host_asset_id = asset_id or socket.gethostname() or 'local-host'
        host_session_id = session_id or f'host-capture-{timestamp.strftime("%Y%m%d")}'
        source = self._source_name()
        try:
            observations = list(self.collector() if self.collector else self._collect())
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            return HostCaptureSummary(
                status='unavailable',
                source=source,
                captured=0,
                skipped=0,
                connection_ids=[],
                message=str(exc),
            )

        candidates = [item for item in observations[:limit] if _is_capture_candidate(item)]
        skipped = len(observations[:limit]) - len(candidates)
        hostnames = self._resolve_hostnames(candidates, timestamp)

        captured: list[str] = []
        seen_connection_ids: set[str] = set()
        for observation in candidates:
            hostname = hostnames.get(observation.remote_ip)
            event = self.writer.write(
                LegacyFlowRecord(
                    # Identity is the socket 4-tuple, not the moment we polled.
                    # Hashing the poll timestamp minted a new row for the same
                    # socket on every capture, growing the table without bound.
                    connection_id=_socket_identity(host_asset_id, observation),
                    asset_id=host_asset_id,
                    session_id=host_session_id,
                    process_id=observation.process_id,
                    process_name=observation.process_name or f'pid-{observation.process_id}',
                    process_path=observation.process_path or observation.process_name or f'pid-{observation.process_id}',
                    start_ts=timestamp,
                    remote_ip=observation.remote_ip,
                    remote_port=observation.remote_port,
                    transport=observation.transport,
                    protocol=_infer_protocol(observation.transport, observation.remote_port),
                    local_ip=observation.local_ip,
                    local_port=observation.local_port,
                    network_zone=_network_zone(observation.remote_ip),
                    matched_domain=hostname,
                    resolver_source='reverse_dns' if hostname else None,
                    executable_hash=observation.executable_hash,
                    package_id=observation.package_id,
                    signer_name=observation.signer_name,
                    signer_status=observation.signer_status,
                    parent_process_id=observation.parent_process_id,
                    service_name=observation.service_name,
                    first_seen_on_asset=True,
                    flow_risk_score=_risk_score(observation.remote_ip, observation.remote_port),
                    rule_suggestion_score=0.35,
                    anomaly_score=0.15,
                )
            )
            if event.connection_id in seen_connection_ids:
                skipped += 1
                continue
            seen_connection_ids.add(event.connection_id)
            self._record_decision(event, timestamp)
            captured.append(event.connection_id)
        return HostCaptureSummary(status='ok', source=source, captured=len(captured), skipped=skipped, connection_ids=captured)

    def _record_decision(self, event, now: datetime) -> None:
        """Run the rule engine over a captured connection and store the verdict."""
        if self.decisions is None:
            return
        process = self.writer.processes.get_process_identity(event.process_identity_id)
        if process is None:
            return
        destination = (
            self.writer.destinations.get_destination_identity(event.destination_identity_id)
            if event.destination_identity_id
            else None
        )
        self.decisions.decide(connection=event, process=process, destination=destination, now=now)

    def _resolve_hostnames(
        self, observations: list[HostSocketObservation], now: datetime
    ) -> dict[str, str]:
        """Map remote addresses to hostnames, or an empty map when disabled."""
        if self.resolver is None:
            return {}
        try:
            return self.resolver.resolve_many((item.remote_ip for item in observations), now=now)
        except OSError:
            # Name resolution is an enrichment, never a reason to lose a capture.
            return {}

    def _source_name(self) -> str:
        system = platform.system().lower()
        if system == 'windows':
            return 'Get-NetTCPConnection'
        if system == 'linux':
            return 'ss'
        return system or 'unsupported'

    def _collect(self) -> Iterable[HostSocketObservation]:
        system = platform.system().lower()
        if system == 'windows':
            return _collect_windows()
        if system == 'linux':
            return _collect_linux()
        raise OSError(f'host connection capture is not implemented for {platform.system()}')


def _collect_windows() -> list[HostSocketObservation]:
    command = [
        'powershell',
        '-NoProfile',
        '-Command',
        (
            "$ErrorActionPreference='SilentlyContinue'; "
            "Get-NetTCPConnection -State Established | "
            "Where-Object { $_.RemoteAddress -and $_.RemotePort -gt 0 } | "
            "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,"
            "@{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},"
            "@{Name='ProcessPath';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} | "
            "ConvertTo-Json -Depth 3"
        ),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)
    output = completed.stdout.strip()
    if not output:
        return []
    rows = json.loads(output)
    if isinstance(rows, dict):
        rows = [rows]
    observations = []
    for row in rows:
        observations.append(
            HostSocketObservation(
                process_id=int(row.get('OwningProcess') or 0),
                process_name=str(row.get('ProcessName') or ''),
                process_path=str(row.get('ProcessPath') or ''),
                local_ip=_empty_to_none(row.get('LocalAddress')),
                local_port=_to_int(row.get('LocalPort')),
                remote_ip=str(row.get('RemoteAddress') or ''),
                remote_port=int(row.get('RemotePort') or 0),
            )
        )
    return observations


#: Provenance lookups are expensive on first sight and free thereafter, so the
#: enricher is module-level to keep its caches across captures.
_ENRICHER = ProcessEnricher()


def _collect_linux() -> list[HostSocketObservation]:
    """Enumerate sockets from /proc, attributing each to a process or account."""
    owners = build_inode_owner_map()
    observations = []
    for entry in read_sockets():
        account = username_for_uid(entry.uid)
        owner = owners.get(entry.inode)
        if owner is not None:
            pid, name, path = owner
        else:
            # The socket exists but its process is not ours to inspect. Naming
            # the owning account still identifies it far better than 'unknown'.
            pid = 0
            name = account or 'unknown'
            path = f'uid:{entry.uid}' if account is None else f'account:{account}'
        provenance = _ENRICHER.enrich(pid=pid, path=path, account=account)
        observations.append(
            HostSocketObservation(
                process_id=pid,
                process_name=name,
                process_path=path,
                local_ip=entry.local_ip,
                local_port=entry.local_port,
                remote_ip=entry.remote_ip,
                remote_port=entry.remote_port,
                transport=entry.transport,
                executable_hash=provenance.executable_hash,
                package_id=provenance.package_id,
                signer_name=provenance.signer_name,
                signer_status=provenance.signer_status,
                parent_process_id=provenance.parent_process_id,
                service_name=provenance.service_name,
            )
        )
    return observations


def _socket_identity(asset_id: str, observation: HostSocketObservation) -> str:
    """Stable connection id for one socket, independent of when it was polled.

    Keyed on the canonical 4-tuple plus transport, so re-polling an established
    socket upserts the existing row while a genuinely new socket gets its own.
    """
    return stable_id(
        'ce',
        asset_id,
        observation.transport,
        observation.local_ip,
        observation.local_port,
        observation.remote_ip,
        observation.remote_port,
    )


def _is_capture_candidate(observation: HostSocketObservation) -> bool:
    if observation.remote_port <= 0 or not observation.remote_ip:
        return False
    try:
        ip = ipaddress.ip_address(observation.remote_ip)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)


def _network_zone(remote_ip: str) -> str:
    try:
        ip = ipaddress.ip_address(remote_ip)
    except ValueError:
        return 'unknown'
    if ip.is_loopback:
        return 'loopback'
    if ip.is_private:
        return 'private_lan'
    return 'public_internet'


def _infer_protocol(transport: str, remote_port: int) -> str:
    if transport == 'udp' and remote_port == 443:
        return 'quic'
    if remote_port == 443:
        return 'tls'
    if remote_port == 80:
        return 'http'
    if remote_port == 53:
        return 'dns'
    return transport


def _risk_score(remote_ip: str, remote_port: int) -> float:
    zone = _network_zone(remote_ip)
    if zone == 'public_internet' and remote_port not in {80, 443, 53, 123}:
        return 0.55
    if zone == 'public_internet':
        return 0.32
    return 0.18


def _empty_to_none(value: object) -> str | None:
    text = str(value or '')
    return text or None


def _to_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
