from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from app.models.ransomware_signal import RansomwareSignal
from app.storage.repositories.interfaces import RansomwareSignalRepository


@dataclass
class RansomwareObservation:
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


class RansomwareDetectorService:
    def __init__(self, repo: RansomwareSignalRepository) -> None:
        self.repo = repo

    def evaluate(self, obs: RansomwareObservation) -> RansomwareSignal | None:
        unsigned = obs.signer_status in {None, 'unsigned', 'unknown'}
        signal_kind = None
        severity = None
        action_recommendation = 'monitor'
        indicators = {
            'process_name': obs.process_name,
            'signer_status': obs.signer_status,
            'modified_files_count': obs.modified_files_count,
            'rename_delete_burst_count': obs.rename_delete_burst_count,
            'entropy_spike': obs.entropy_spike,
            'touches_protected_dirs': obs.touches_protected_dirs,
            'canary_touched': obs.canary_touched,
        }

        if obs.canary_touched:
            signal_kind = 'canary_trip'
            severity = 'critical'
            action_recommendation = 'kill_and_rollback'
        elif obs.modified_files_count >= 25 and obs.entropy_spike and obs.touches_protected_dirs:
            signal_kind = 'mass_encryption'
            severity = 'critical'
            action_recommendation = 'kill_and_rollback'
        elif obs.rename_delete_burst_count >= 20 and obs.touches_protected_dirs and unsigned:
            signal_kind = 'rename_delete_burst'
            severity = 'high'
            action_recommendation = 'kill_process_tree'
        elif obs.modified_files_count >= 10 and obs.touches_protected_dirs and unsigned:
            signal_kind = 'protected_folder_abuse'
            severity = 'high'
            action_recommendation = 'block_protected_write'

        if signal_kind is None:
            return None

        signal = RansomwareSignal(
            ransomware_signal_id=f"rs_{uuid4().hex[:12]}",
            asset_id=obs.asset_id,
            session_id=obs.session_id,
            process_identity_id=obs.process_identity_id,
            signal_kind=signal_kind,
            severity=severity,
            protected_path=obs.protected_path,
            indicators_json=indicators,
            action_recommendation=action_recommendation,
            created_ts=datetime.now(timezone.utc),
        )
        return self.repo.create_signal(signal)
