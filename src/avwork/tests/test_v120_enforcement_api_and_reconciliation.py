from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.api import deps
from app.main import create_app
from app.models.policy_rule import PolicyConditions, PolicyRule
from app.services.enforcement.applier import EnforcementService

BASE_TS = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)


def test_reconciliation_flags_rule_changes_after_enforcement() -> None:
    deps.reset_bootstrap_state()
    state = deps.get_bootstrap_state()
    rule = state.repositories.rules.create_rule(
        PolicyRule(
            rule_id='r_100',
            rule_name='Allow Sync',
            enabled=True,
            priority=100,
            source='user',
            action='allow',
            created_ts=BASE_TS - timedelta(minutes=5),
            updated_ts=BASE_TS - timedelta(minutes=5),
            conditions=PolicyConditions(process_name='SyncAgent', domain_suffix='.example.test'),
        )
    )
    EnforcementService(state.repositories.enforcement).apply_rule(rule, backend='macos', now=BASE_TS - timedelta(minutes=4))
    state.repositories.rules.update_rule('r_100', updated_ts=BASE_TS)
    client = TestClient(create_app())
    issues = client.get('/api/v1/enforcement/reconciliation').json()['items']
    assert issues[0]['rule_id'] == 'r_100'
    assert issues[0]['status'] == 'stale_plan'
    reapplied = client.post('/api/v1/enforcement/apply/rules/r_100', json={'backend': 'windows'})
    assert reapplied.status_code == 200
    assert reapplied.json()['backend'] == 'windows'
    deps.reset_bootstrap_state()
