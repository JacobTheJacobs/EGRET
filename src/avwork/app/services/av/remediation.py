from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from app.models.behavior_alert import BehaviorAlert
from app.models.ransomware_signal import RansomwareSignal
from app.models.remediation_action import RemediationAction
from app.storage.repositories.interfaces import RemediationActionRepository


class RemediationService:
    def __init__(self, repo: RemediationActionRepository) -> None:
        self.repo = repo

    def _create(self, *, asset_id: str, session_id: str, process_identity_id: str | None, related_object_id: str, action_kind: str, target_type: str, initiated_by: str, backend_result: str) -> RemediationAction:
        now = datetime.now(timezone.utc)
        action = RemediationAction(
            remediation_action_id=f"ra_{uuid4().hex[:12]}",
            asset_id=asset_id,
            session_id=session_id,
            process_identity_id=process_identity_id,
            related_object_id=related_object_id,
            action_kind=action_kind,
            target_type=target_type,
            status='completed',
            backend_result=backend_result,
            initiated_by=initiated_by,
            created_ts=now,
            completed_ts=now,
        )
        return self.repo.create_action(action)

    def from_behavior_alert(self, alert: BehaviorAlert, *, initiated_by: str = 'system') -> RemediationAction:
        mapping = {
            'quarantine_and_block': ('quarantine_file', 'file'),
            'block_and_quarantine': ('quarantine_file', 'file'),
            'kill_process_tree': ('kill_process_tree', 'process'),
            'isolate_process': ('isolate_process', 'process'),
            'block_process_tree': ('kill_process_tree', 'process'),
            'block_script_host': ('kill_process_tree', 'process'),
            'block_execute': ('quarantine_file', 'file'),
        }
        action_kind, target_type = mapping.get(alert.recommendation, ('isolate_process', 'alert'))
        return self._create(
            asset_id=alert.asset_id,
            session_id=alert.session_id,
            process_identity_id=alert.process_identity_id,
            related_object_id=alert.behavior_alert_id,
            action_kind=action_kind,
            target_type=target_type,
            initiated_by=initiated_by,
            backend_result=f"auto:{alert.recommendation}",
        )

    def from_ransomware_signal(self, signal: RansomwareSignal, *, initiated_by: str = 'system') -> RemediationAction:
        action_kind = 'rollback_candidate' if signal.signal_kind in {'canary_trip', 'mass_encryption'} else 'kill_process_tree'
        return self._create(
            asset_id=signal.asset_id,
            session_id=signal.session_id,
            process_identity_id=signal.process_identity_id,
            related_object_id=signal.ransomware_signal_id,
            action_kind=action_kind,
            target_type='signal',
            initiated_by=initiated_by,
            backend_result=f"ransomware:{signal.signal_kind}",
        )
