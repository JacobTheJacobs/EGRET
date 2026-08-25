from datetime import datetime, timedelta, timezone

from app.models.policy_decision import PolicyDecision
from app.models.policy_rule import PolicyConditions, PolicyRule
from app.services.policy.conflicts import RuleConflictDetector
from app.services.policy.expiry_cleanup import ExpiryCleanupService
from app.storage.repositories.sqlite import SqliteRepositories


BASE_TS = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)


def test_rule_conflict_detector_finds_overlap_action_conflict() -> None:
    rules = [
        PolicyRule(
            rule_id='r_allow',
            rule_name='Allow Firefox org',
            enabled=True,
            priority=100,
            source='user',
            action='allow',
            created_ts=BASE_TS,
            updated_ts=BASE_TS,
            conditions=PolicyConditions(process_name='Firefox', domain_suffix='.org'),
        ),
        PolicyRule(
            rule_id='r_block',
            rule_name='Block Firefox org',
            enabled=True,
            priority=90,
            source='admin',
            action='deny',
            created_ts=BASE_TS,
            updated_ts=BASE_TS,
            conditions=PolicyConditions(process_name='Firefox', domain_suffix='.org'),
        ),
    ]
    conflicts = RuleConflictDetector().detect(rules)
    assert len(conflicts) == 1
    assert conflicts[0].conflict_type == 'overlap_action_conflict'


def test_rule_conflict_detector_finds_shadowed_rule() -> None:
    rules = [
        PolicyRule(
            rule_id='r_specific',
            rule_name='Allow Firefox on LAN',
            enabled=True,
            priority=100,
            source='user',
            action='allow',
            created_ts=BASE_TS,
            updated_ts=BASE_TS,
            conditions=PolicyConditions(process_name='Firefox', network_zone='private_lan'),
        ),
        PolicyRule(
            rule_id='r_broad',
            rule_name='Allow Firefox anywhere',
            enabled=True,
            priority=80,
            source='user',
            action='allow',
            created_ts=BASE_TS,
            updated_ts=BASE_TS,
            conditions=PolicyConditions(process_name='Firefox'),
        ),
    ]
    conflicts = RuleConflictDetector().detect(rules)
    assert len(conflicts) == 1
    assert conflicts[0].conflict_type == 'shadowed_rule'
    assert conflicts[0].left_rule_id == 'r_specific'


def test_expiry_cleanup_disables_expired_rules_and_deletes_expired_decisions() -> None:
    repos = SqliteRepositories(':memory:')
    repos.rules.create_rule(
        PolicyRule(
            rule_id='r_temp',
            rule_name='Temporary block',
            enabled=True,
            priority=100,
            source='user',
            action='deny',
            ttl_seconds=60,
            created_ts=BASE_TS - timedelta(minutes=10),
            updated_ts=BASE_TS - timedelta(minutes=10),
            conditions=PolicyConditions(process_name='Firefox'),
        )
    )
    repos.decisions.create_decision(
        PolicyDecision(
            policy_decision_id='pd_old',
            connection_id='c_old',
            decision='deny',
            decision_source='user_prompt',
            expires_at=BASE_TS - timedelta(minutes=1),
            created_ts=BASE_TS - timedelta(minutes=5),
        )
    )
    result = ExpiryCleanupService(rules=repos.rules, decisions=repos.decisions).run(now=BASE_TS)
    assert result.expired_rule_count == 1
    assert result.expired_decision_count == 1
    rule = repos.rules.get_rule('r_temp')
    assert rule is not None
    assert rule.enabled is False
    assert repos.decisions.get_latest_decision_for_connection('c_old') is None
