from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import create_app
from app.models.policy_rule import PolicyRule, PolicyConditions
from app.services.enforcement.backends import get_backend_adapter
from app.services.enforcement.capabilities import probe_backend_capability


def make_rule() -> PolicyRule:
    now = datetime.now(timezone.utc)
    return PolicyRule(
        rule_id='r_native',
        rule_name='Block unknown',
        enabled=True,
        priority=100,
        source='user',
        action='deny',
        ttl_seconds=None,
        created_ts=now,
        updated_ts=now,
        created_by='tester',
        conditions=PolicyConditions(process_name='TestApp', remote_ip='1.2.3.4'),
    )


def test_probe_backend_capability_reflects_missing_binary(monkeypatch):
    monkeypatch.setenv('EDGE_NET_GUARDIAN_ENABLE_NATIVE_EXECUTION', '1')
    monkeypatch.setenv('PATH', '')
    cap = probe_backend_capability('linux')
    assert cap.backend == 'linux'
    assert cap.native_execution_enabled is True
    assert 'nft' in cap.missing_binaries
    assert cap.runnable is False


def test_native_execution_uses_fake_binary(tmp_path, monkeypatch):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    nft = bin_dir / 'nft'
    nft.write_text('#!/bin/sh\necho native nft ok\n', encoding='utf-8')
    nft.chmod(0o755)

    monkeypatch.setenv('EDGE_NET_GUARDIAN_ENABLE_NATIVE_EXECUTION', '1')
    monkeypatch.setenv('PATH', str(bin_dir))
    monkeypatch.setenv('EDGE_NET_GUARDIAN_BACKEND_STATE_DIR', str(tmp_path / 'state'))

    adapter = get_backend_adapter('linux')
    result = adapter.apply_rule(make_rule(), command_preview=[], execute=True)
    assert result.execution_mode == 'executed'
    assert 'native nft ok' in result.message


def test_health_status_includes_capabilities(tmp_path, monkeypatch):
    monkeypatch.setenv('EDGE_NET_GUARDIAN_DB_PATH', str(tmp_path / 'eng.sqlite3'))
    monkeypatch.setenv('EDGE_NET_GUARDIAN_ENABLE_NATIVE_EXECUTION', '0')
    app = create_app()
    client = TestClient(app)
    response = client.get('/api/v1/health/status')
    assert response.status_code == 200
    payload = response.json()
    assert 'enforcement_capabilities' in payload
    assert any(item['backend'] == 'macos' for item in payload['enforcement_capabilities'])


def test_backend_state_uses_latest_event_backend(tmp_path, monkeypatch):
    monkeypatch.setenv('EDGE_NET_GUARDIAN_DB_PATH', str(tmp_path / 'eng.sqlite3'))
    monkeypatch.setenv('EDGE_NET_GUARDIAN_BACKEND_STATE_DIR', str(tmp_path / 'state'))
    app = create_app()
    client = TestClient(app)

    now = datetime.now(timezone.utc).isoformat()
    rule_payload = {
        'rule_id': 'r_backend',
        'rule_name': 'Allow linux',
        'enabled': True,
        'priority': 100,
        'source': 'user',
        'action': 'allow',
        'ttl_seconds': None,
        'created_ts': now,
        'updated_ts': now,
        'created_by': 'tester',
        'conditions': {'process_name': 'curl', 'remote_ip': '9.9.9.9'},
    }
    created = client.post('/api/v1/rules', json=rule_payload)
    assert created.status_code == 200
    rule_id = created.json()['rule_id']
    assert client.post(f'/api/v1/enforcement/apply/rules/{rule_id}', json={'backend': 'linux', 'execute': False}).status_code == 200
    state = client.get(f'/api/v1/enforcement/backend-state/{rule_id}')
    assert state.status_code == 200
    assert state.json()['backend'] == 'linux'
