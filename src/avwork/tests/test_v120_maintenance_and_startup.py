from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.jobs.maintenance import run_maintenance_cycle
from app.jobs.startup import run_startup_tasks
from app.models.policy_decision import PolicyDecision
from app.models.policy_rule import PolicyConditions, PolicyRule
from app.storage.bootstrap import bootstrap_application


BASE_TS = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)


def test_maintenance_expires_and_reapplies(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv('EGRET_INGEST_TOKEN', 'startup-test-token')
    os.environ['EDGE_NET_GUARDIAN_BACKEND_STATE_DIR'] = str(tmp_path / 'backend-state')
    state = bootstrap_application(tmp_path / 'test.sqlite')
    state.repositories.rules.create_rule(
        PolicyRule(
            rule_id='r_temp',
            rule_name='Temp block',
            enabled=True,
            priority=100,
            source='user',
            action='deny',
            ttl_seconds=60,
            created_ts=BASE_TS - timedelta(hours=1),
            updated_ts=BASE_TS - timedelta(hours=1),
            conditions=PolicyConditions(process_name='Updater'),
        )
    )
    state.repositories.decisions.create_decision(
        PolicyDecision(
            policy_decision_id='pd_temp',
            connection_id='c_1',
            decision='deny',
            decision_source='user_prompt',
            prompt_shown=True,
            created_ts=BASE_TS - timedelta(hours=1),
            expires_at=BASE_TS - timedelta(minutes=1),
        )
    )
    # non-expiring rule needs a backend apply from maintenance
    state.repositories.rules.create_rule(
        PolicyRule(
            rule_id='r_perm',
            rule_name='Permanent allow',
            enabled=True,
            priority=100,
            source='user',
            action='allow',
            created_ts=BASE_TS,
            updated_ts=BASE_TS,
            conditions=PolicyConditions(process_name='Browser'),
        )
    )
    summary = run_maintenance_cycle(state.repositories, now=BASE_TS)
    assert summary.expired_rules == 1
    assert summary.expired_decisions == 1
    assert summary.reapplied_rules >= 1
    startup = run_startup_tasks(state)
    assert startup.maintenance.generated_at
    assert startup.security['ingest_token_configured'] is True
    assert startup.security['secret_values_exposed'] is False
    state.database.close()
