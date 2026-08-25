from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from app.api import deps
from app.main import create_app
from app.services.demo.sample_data import seed_demo_data
from app.storage.bootstrap import bootstrap_application


def test_demo_seed_populates_connection_rows(tmp_path: Path) -> None:
    state = bootstrap_application(tmp_path / 'demo.sqlite3')
    try:
        result = seed_demo_data(state.repositories)
        assert result.inserted_connections == 3
        assert result.inserted_file_events == 3
        assert result.inserted_malware_verdicts == 3
        assert result.inserted_quarantine_records == 1
        assert result.inserted_web_verdicts == 2
        assert result.inserted_behavior_alerts == 1
        assert result.inserted_ransomware_signals == 1
        assert result.inserted_remediation_actions == 2
        assert result.inserted_rules == 2
        assert result.inserted_enforcement_events == 1
        items, total = state.repositories.connections.list_connections(page=1, page_size=10)
        assert total == 3
        assert {item.connection_id for item in items} == {
            'demo_conn_browser_cdn',
            'demo_conn_sync_unknown',
            'demo_conn_unsigned_beacon',
        }
        again = seed_demo_data(state.repositories)
        assert again.inserted_connections == 0
    finally:
        state.database.close()


def test_demo_seed_script_makes_connections_visible_in_app(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / 'demo.sqlite3'
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, 'scripts/seed_demo_data.py', '--db-path', str(db_path)],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload['inserted_connections'] == 3
    assert payload['inserted_file_events'] == 3
    assert payload['inserted_ransomware_signals'] == 1

    deps.reset_bootstrap_state()
    monkeypatch.setenv('EGRET_DB_PATH', str(db_path))
    client = TestClient(create_app())
    rows = client.get('/api/v1/connections').json()['items']
    assert len(rows) == 3
    assert {row['asset_id'] for row in rows} == {'demo-macbook'}
    assert {row['session_id'] for row in rows} == {'demo-session'}
    assert {row['process']['name'] for row in rows} >= {'Firefox', 'SyncAgent', 'UpdaterHelper'}
    assert {row['verdict'] for row in rows} >= {'allow', 'ask', 'deny'}
    timeline = client.get('/api/v1/investigations/assets/demo-macbook/timeline').json()
    assert timeline['total_connections'] == 3
    assert {item['kind'] for item in timeline['items']} >= {'connection', 'decision', 'trust_snapshot'}
    assert client.get('/api/v1/files').json()['total'] == 3
    threats = client.get('/api/v1/threats').json()
    assert threats['total'] == 6
    assert len(threats['malware_verdicts']) == 2
    assert len(threats['web_verdicts']) == 2
    assert len(threats['behavior_alerts']) == 1
    assert len(threats['ransomware_signals']) == 1
    assert len(client.get('/api/v1/quarantine').json()['items']) == 1
    assert len(client.get('/api/v1/ransomware/signals').json()['items']) == 1
    assert len(client.get('/api/v1/remediation').json()['items']) == 2
    assert len(client.get('/api/v1/rules').json()['items']) == 2
    assert len(client.get('/api/v1/enforcement/events').json()['items']) == 1
    protection = client.get('/api/v1/protection/status').json()['av']
    assert protection['file_events'] == 3
    assert protection['active_quarantine'] == 1
    assert protection['remediation_actions'] == 2
    deps.reset_bootstrap_state()


def test_install_preflight_can_seed_demo_data(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    subprocess.run([sys.executable, 'scripts/finalize_release_candidate.py', '--skip-tests', '--skip-frontend'], cwd=root, check=True)
    result = subprocess.run(
        [sys.executable, 'scripts/install_preflight.py', '--data-dir', str(tmp_path / 'runtime'), '--seed-demo-data'],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload['demo_seed']['inserted_connections'] == 3
    assert payload['demo_seed']['inserted_file_events'] == 3
    assert payload['demo_seed']['inserted_rules'] == 2
    assert Path(payload['db_path']).exists()
