from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from app.models.policy_rule import PolicyConditions, PolicyRule
from app.services.enforcement.backends import get_backend_adapter


BASE_TS = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)


def make_rule() -> PolicyRule:
    return PolicyRule(
        rule_id='r_exec_1',
        rule_name='Block Example',
        enabled=True,
        priority=100,
        source='user',
        action='deny',
        created_ts=BASE_TS,
        updated_ts=BASE_TS,
        conditions=PolicyConditions(process_name='Browser', domain_suffix='.example.test'),
    )


def test_backend_adapter_round_trip(tmp_path: Path) -> None:
    os.environ['EDGE_NET_GUARDIAN_BACKEND_STATE_DIR'] = str(tmp_path)
    adapter = get_backend_adapter('linux')
    rule = make_rule()
    result = adapter.apply_rule(rule, command_preview=['nft add rule ...'], execute=True)
    assert result.status == 'applied'
    assert result.execution_mode == 'simulated'
    state = adapter.read_rule_state(rule)
    assert state.state == 'present'
    assert state.details['action'] == 'deny'
