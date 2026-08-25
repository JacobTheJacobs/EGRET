from __future__ import annotations

from datetime import datetime
from typing import Protocol

from app.models.behavior_alert import BehaviorAlert
from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.enforcement_event import EnforcementEvent
from app.models.file_event import FileEvent
from app.models.malware_verdict import MalwareVerdict
from app.models.policy_decision import PolicyDecision
from app.models.policy_rule import PolicyRule
from app.models.process_identity import ProcessIdentity
from app.models.quarantine_record import QuarantineRecord
from app.models.remediation_action import RemediationAction
from app.models.ransomware_signal import RansomwareSignal
from app.models.training_feedback_event import TrainingFeedbackEvent
from app.models.trust_context_snapshot import TrustContextSnapshot
from app.models.web_verdict import WebVerdict


class ConnectionRepository(Protocol):
    def list_connections(
        self,
        *,
        asset_id: str | None = None,
        process_name: str | None = None,
        domain: str | None = None,
        ip: str | None = None,
        port: int | None = None,
        verdict: str | None = None, signer_status_not: str | None = None,
        network_zone: str | None = None,
        start_ts: datetime | None = None,
        end_ts: datetime | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[ConnectionEvent], int]: ...

    def get_connection(self, connection_id: str) -> ConnectionEvent | None: ...

    def upsert_connection(self, event: ConnectionEvent) -> ConnectionEvent: ...


class ProcessIdentityRepository(Protocol):
    def get_process_identity(self, process_identity_id: str) -> ProcessIdentity | None: ...

    def upsert_process_identity(self, identity: ProcessIdentity) -> ProcessIdentity: ...


class DestinationIdentityRepository(Protocol):
    def get_destination_identity(self, destination_identity_id: str) -> DestinationIdentity | None: ...

    def upsert_destination_identity(self, identity: DestinationIdentity) -> DestinationIdentity: ...


class DecisionRepository(Protocol):
    def create_decision(self, decision: PolicyDecision) -> PolicyDecision: ...

    def get_latest_decision_for_connection(self, connection_id: str) -> PolicyDecision | None: ...

    def expire_decisions(self, now: datetime) -> int: ...


class RuleRepository(Protocol):
    def create_rule(self, rule: PolicyRule) -> PolicyRule: ...

    def update_rule(self, rule_id: str, **updates) -> PolicyRule | None: ...

    def delete_rule(self, rule_id: str) -> bool: ...

    def list_rules(self) -> list[PolicyRule]: ...

    def get_rule(self, rule_id: str) -> PolicyRule | None: ...

    def expire_rules(self, now: datetime) -> int: ...


class TrustSnapshotRepository(Protocol):
    def list_snapshots(self, *, asset_id: str, session_id: str) -> list[TrustContextSnapshot]: ...

    def list_snapshots_for_asset(self, *, asset_id: str, session_id: str | None = None) -> list[TrustContextSnapshot]: ...

    def get_snapshot(self, trust_context_snapshot_id: str) -> TrustContextSnapshot | None: ...

    def upsert_snapshot(self, snapshot: TrustContextSnapshot) -> TrustContextSnapshot: ...


class TrainingFeedbackRepository(Protocol):
    def create_feedback_event(self, event: TrainingFeedbackEvent) -> TrainingFeedbackEvent: ...


class FileEventRepository(Protocol):
    def create_file_event(self, event: FileEvent) -> FileEvent: ...

    def get_file_event(self, file_event_id: str) -> FileEvent | None: ...

    def list_file_events(
        self,
        *,
        asset_id: str | None = None,
        verdict: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[FileEvent], int]: ...


class MalwareVerdictRepository(Protocol):
    def create_verdict(self, verdict: MalwareVerdict) -> MalwareVerdict: ...

    def list_verdicts(self, *, asset_id: str | None = None, malicious_only: bool = False) -> list[MalwareVerdict]: ...

    def latest_verdict_for_file_event(self, file_event_id: str) -> MalwareVerdict | None: ...


class QuarantineRepository(Protocol):
    def create_record(self, record: QuarantineRecord) -> QuarantineRecord: ...

    def list_records(self, *, asset_id: str | None = None) -> list[QuarantineRecord]: ...

    def get_record(self, quarantine_record_id: str) -> QuarantineRecord | None: ...

    def update_record(self, quarantine_record_id: str, **updates) -> QuarantineRecord | None: ...


class WebVerdictRepository(Protocol):
    def create_web_verdict(self, verdict: WebVerdict) -> WebVerdict: ...

    def list_web_verdicts(self, *, asset_id: str | None = None, blocked_only: bool = False) -> list[WebVerdict]: ...


class BehaviorAlertRepository(Protocol):
    def create_alert(self, alert: BehaviorAlert) -> BehaviorAlert: ...

    def list_alerts(self, *, asset_id: str | None = None, min_severity: str | None = None) -> list[BehaviorAlert]: ...

    def get_alert(self, behavior_alert_id: str) -> BehaviorAlert | None: ...


class RansomwareSignalRepository(Protocol):
    def create_signal(self, signal: RansomwareSignal) -> RansomwareSignal: ...

    def list_signals(self, *, asset_id: str | None = None, min_severity: str | None = None) -> list[RansomwareSignal]: ...

    def get_signal(self, ransomware_signal_id: str) -> RansomwareSignal | None: ...


class RemediationActionRepository(Protocol):
    def create_action(self, action: RemediationAction) -> RemediationAction: ...

    def list_actions(self, *, asset_id: str | None = None, status: str | None = None) -> list[RemediationAction]: ...

    def get_action(self, remediation_action_id: str) -> RemediationAction | None: ...


class EnforcementRepository(Protocol):
    def create_event(self, event: EnforcementEvent) -> EnforcementEvent: ...

    def list_events(self, *, rule_id: str | None = None, connection_id: str | None = None, policy_decision_id: str | None = None) -> list[EnforcementEvent]: ...

    def latest_event_for_rule(self, rule_id: str) -> EnforcementEvent | None: ...
