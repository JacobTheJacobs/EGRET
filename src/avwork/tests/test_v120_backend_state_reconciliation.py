from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.api import deps
from app.main import create_app
from app.models.policy_rule import PolicyConditions, PolicyRule


BASE_TS = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)


def test_reconciliation_flags_backend_missing_state(tmp_path: Path) -> None:
    os.environ['EDGE_NET_GUARDIAN_BACKEND_STATE_DIR'] = str(tmp_path / 'backend-state')
    deps.reset_bootstrap_state()
    state = deps.get_bootstrap_state()
    state.repositories.rules.create_rule(
        PolicyRule(
            rule_id='r_missing',
            rule_name='Allow Sync',
            enabled=True,
            priority=100,
            source='user',
            action='allow',
            created_ts=BASE_TS,
            updated_ts=BASE_TS,
            conditions=PolicyConditions(process_name='SyncAgent', domain_suffix='.example.test'),
        )
    )
    client = TestClient(create_app())
    issues = client.get('/api/v1/enforcement/reconciliation').json()['items']
    assert issues[0]['rule_id'] == 'r_missing'
    assert issues[0]['status'] in {'pending_apply', 'backend_missing'}
    apply_resp = client.post('/api/v1/enforcement/apply/rules/r_missing', json={'backend': 'windows', 'execute': True})
    assert apply_resp.status_code == 200
    issues_after = client.get('/api/v1/enforcement/reconciliation').json()['items']
    assert issues_after == []
    deps.reset_bootstrap_state()
