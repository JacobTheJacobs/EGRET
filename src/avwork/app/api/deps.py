from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from app.config.env import getenv_compat
from app.storage.bootstrap import BootstrapState, bootstrap_application
from app.storage.repositories.interfaces import (
    BehaviorAlertRepository,
    ConnectionRepository,
    DecisionRepository,
    DestinationIdentityRepository,
    EnforcementRepository,
    FileEventRepository,
    MalwareVerdictRepository,
    ProcessIdentityRepository,
    QuarantineRepository,
    RemediationActionRepository,
    RansomwareSignalRepository,
    RuleRepository,
    TrainingFeedbackRepository,
    TrustSnapshotRepository,
    WebVerdictRepository,
)


@lru_cache(maxsize=1)
def get_bootstrap_state() -> BootstrapState:
    db_path = getenv_compat('EGRET_DB_PATH', 'EDGE_NET_GUARDIAN_DB_PATH', default=':memory:')
    return bootstrap_application(Path(db_path))


def get_connection_repository() -> ConnectionRepository:
    return get_bootstrap_state().repositories.connections


def get_process_repository() -> ProcessIdentityRepository:
    return get_bootstrap_state().repositories.processes


def get_destination_repository() -> DestinationIdentityRepository:
    return get_bootstrap_state().repositories.destinations


def get_decision_repository() -> DecisionRepository:
    return get_bootstrap_state().repositories.decisions


def get_rule_repository() -> RuleRepository:
    return get_bootstrap_state().repositories.rules


def get_trust_repository() -> TrustSnapshotRepository:
    return get_bootstrap_state().repositories.trust


def get_training_feedback_repository() -> TrainingFeedbackRepository:
    return get_bootstrap_state().repositories.feedback


def get_enforcement_repository() -> EnforcementRepository:
    return get_bootstrap_state().repositories.enforcement


def get_file_event_repository() -> FileEventRepository:
    return get_bootstrap_state().repositories.files


def get_malware_verdict_repository() -> MalwareVerdictRepository:
    return get_bootstrap_state().repositories.malware_verdicts


def get_quarantine_repository() -> QuarantineRepository:
    return get_bootstrap_state().repositories.quarantine


def get_web_verdict_repository() -> WebVerdictRepository:
    return get_bootstrap_state().repositories.web_verdicts


def get_behavior_alert_repository() -> BehaviorAlertRepository:
    return get_bootstrap_state().repositories.behavior_alerts


def get_ransomware_signal_repository() -> RansomwareSignalRepository:
    return get_bootstrap_state().repositories.ransomware_signals


def get_remediation_action_repository() -> RemediationActionRepository:
    return get_bootstrap_state().repositories.remediation_actions


def reset_bootstrap_state() -> None:
    try:
        state = get_bootstrap_state()
    except Exception:
        get_bootstrap_state.cache_clear()
        return
    state.database.close()
    get_bootstrap_state.cache_clear()
