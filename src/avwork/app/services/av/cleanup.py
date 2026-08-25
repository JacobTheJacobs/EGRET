from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from app.models.quarantine_record import QuarantineRecord
from app.models.remediation_action import RemediationAction
from app.storage.repositories.interfaces import QuarantineRepository, RemediationActionRepository


class CleanupAutomationService:
    def __init__(self, *, quarantine: QuarantineRepository, remediation: RemediationActionRepository) -> None:
        self.quarantine = quarantine
        self.remediation = remediation

    def plan_for_quarantine(self, record: QuarantineRecord, *, initiated_by: str = 'system') -> list[RemediationAction]:
        now = datetime.now(timezone.utc)
        actions: list[RemediationAction] = []
        for action_kind, target_type in [('remove_persistence', 'process'), ('delete_quarantined_copy', 'file')]:
            action = RemediationAction(
                remediation_action_id=f'ra_{uuid4().hex[:12]}',
                asset_id=record.asset_id,
                session_id='quarantine',
                process_identity_id=None,
                related_object_id=record.quarantine_record_id,
                action_kind=action_kind,
                target_type=target_type,
                status='completed',
                backend_result=f'cleanup:{action_kind}',
                initiated_by=initiated_by,
                created_ts=now,
                completed_ts=now,
            )
            actions.append(self.remediation.create_action(action))
        return actions

    def auto_delete_if_marked(self, quarantine_record_id: str) -> QuarantineRecord | None:
        record = self.quarantine.get_record(quarantine_record_id)
        if record is None:
            return None
        if record.deleted:
            return record
        return self.quarantine.update_record(quarantine_record_id, deleted=True, updated_ts=datetime.now(timezone.utc))
