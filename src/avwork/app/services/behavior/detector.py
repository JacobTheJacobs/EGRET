from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from app.models.behavior_alert import BehaviorAlert
from app.storage.repositories.interfaces import BehaviorAlertRepository


@dataclass
class BehaviorObservation:
    asset_id: str
    session_id: str
    process_identity_id: str | None = None
    process_name: str | None = None
    parent_process_name: str | None = None
    signer_status: str | None = None
    origin_kind: str | None = None
    file_verdict: str | None = None
    launches_shell: bool = False
    writes_persistence: bool = False
    touches_protected_dirs: bool = False
    network_destination: str | None = None
    indicators: dict[str, object] = field(default_factory=dict)


class BehaviorDetectorService:
    def __init__(self, repo: BehaviorAlertRepository) -> None:
        self.repo = repo

    def evaluate(self, obs: BehaviorObservation) -> BehaviorAlert | None:
        unsigned = obs.signer_status in {None, 'unsigned', 'unknown'}
        process_name = (obs.process_name or '').lower()
        parent_name = (obs.parent_process_name or '').lower()
        recommendation = 'monitor'
        alert_kind = None
        severity = None

        if obs.launches_shell and parent_name in {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'soffice.bin'}:
            alert_kind = 'office_shell_spawn'
            severity = 'critical'
            recommendation = 'block_process_tree'
        elif obs.writes_persistence and unsigned:
            alert_kind = 'persistence_abuse'
            severity = 'high'
            recommendation = 'block_and_quarantine'
        elif obs.touches_protected_dirs and obs.file_verdict in {'suspicious', 'malicious'}:
            alert_kind = 'ransomware_precursor'
            severity = 'critical'
            recommendation = 'kill_process_tree'
        elif obs.origin_kind == 'download' and obs.file_verdict in {'suspicious', 'malicious'} and unsigned:
            alert_kind = 'downloaded_payload_execution'
            severity = 'high' if obs.file_verdict == 'suspicious' else 'critical'
            recommendation = 'block_execute' if obs.file_verdict == 'suspicious' else 'quarantine_and_block'
        elif obs.network_destination and obs.file_verdict in {'suspicious', 'malicious'}:
            alert_kind = 'malware_phone_home'
            severity = 'high'
            recommendation = 'isolate_process'
        elif process_name in {'powershell.exe', 'pwsh', 'wscript.exe', 'cscript.exe'} and obs.writes_persistence:
            alert_kind = 'script_persistence_abuse'
            severity = 'high'
            recommendation = 'block_script_host'

        if alert_kind is None:
            return None

        alert = BehaviorAlert(
            behavior_alert_id=f'ba_{uuid4().hex[:12]}',
            asset_id=obs.asset_id,
            session_id=obs.session_id,
            process_identity_id=obs.process_identity_id,
            chain_id=f'chain_{uuid4().hex[:8]}',
            alert_kind=alert_kind,
            severity=severity,
            indicators_json={
                'process_name': obs.process_name,
                'parent_process_name': obs.parent_process_name,
                'signer_status': obs.signer_status,
                'origin_kind': obs.origin_kind,
                'file_verdict': obs.file_verdict,
                'launches_shell': obs.launches_shell,
                'writes_persistence': obs.writes_persistence,
                'touches_protected_dirs': obs.touches_protected_dirs,
                'network_destination': obs.network_destination,
                **obs.indicators,
            },
            recommendation=recommendation,
            created_ts=datetime.now(timezone.utc),
        )
        return self.repo.create_alert(alert)
