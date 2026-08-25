from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.api import deps
from app.main import create_app


def test_live_connection_ingest_feeds_connections_and_investigations(tmp_path: Path, monkeypatch) -> None:
    deps.reset_bootstrap_state()
    monkeypatch.setenv('EGRET_DB_PATH', str(tmp_path / 'live-ingest.sqlite3'))
    monkeypatch.setenv('EGRET_INGEST_TOKEN', 'test-ingest-token')
    client = TestClient(create_app())
    headers = {'X-Egret-Ingest-Token': 'test-ingest-token'}

    trust = client.post(
        '/api/v1/ingest/trust-snapshots',
        headers=headers,
        json={
            'snapshots': [
                {
                    'trust_context_snapshot_id': 'trust_live_api_1',
                    'asset_id': 'live-api-host',
                    'session_id': 'live-api-session',
                    'snapshot_ts': '2026-07-09T12:00:00+00:00',
                    'trust_score': 0.77,
                    'drift_score': 0.21,
                    'supporting_context_json': {'source': 'test-live-ingest'},
                }
            ]
        },
    )
    assert trust.status_code == 200
    assert trust.json()['ingested'] == 1

    ingested = client.post(
        '/api/v1/ingest/connections',
        headers=headers,
        json={
            'records': [
                {
                    'connection_id': 'conn_live_api_1',
                    'asset_id': 'live-api-host',
                    'session_id': 'live-api-session',
                    'process_id': 5150,
                    'process_name': 'SensorAgent',
                    'process_path': '/opt/egret/sensor-agent',
                    'signer_name': 'Egret Sensor',
                    'signer_status': 'trusted',
                    'start_ts': '2026-07-09T12:00:30+00:00',
                    'remote_ip': '198.51.100.42',
                    'remote_port': 443,
                    'transport': 'tcp',
                    'protocol': 'tls',
                    'matched_domain': 'live.example.test',
                    'sni': 'live.example.test',
                    'network_zone': 'public_internet',
                    'trust_context_snapshot_id': 'trust_live_api_1',
                }
            ]
        },
    )
    assert ingested.status_code == 200
    assert ingested.json()['connection_ids'] == ['conn_live_api_1']

    rows = client.get('/api/v1/connections').json()['items']
    assert len(rows) == 1
    assert rows[0]['connection_id'] == 'conn_live_api_1'
    assert rows[0]['asset_id'] == 'live-api-host'
    assert rows[0]['destination']['matched_domain'] == 'live.example.test'

    detail = client.get('/api/v1/connections/conn_live_api_1').json()
    assert detail['trust_context']['trust_context_snapshot_id'] == 'trust_live_api_1'
    assert detail['trust_context']['trust_score'] == 0.77

    timeline = client.get('/api/v1/investigations/assets/live-api-host/timeline').json()
    assert {item['kind'] for item in timeline['items']} >= {'connection', 'trust_snapshot'}
    deps.reset_bootstrap_state()


def test_live_ingest_requires_configured_valid_token(tmp_path: Path, monkeypatch) -> None:
    deps.reset_bootstrap_state()
    monkeypatch.setenv('EGRET_DB_PATH', str(tmp_path / 'auth-ingest.sqlite3'))
    monkeypatch.delenv('EGRET_INGEST_TOKEN', raising=False)
    monkeypatch.delenv('EDGE_NET_GUARDIAN_INGEST_TOKEN', raising=False)
    client = TestClient(create_app())
    payload = {
        'snapshots': [
            {
                'trust_context_snapshot_id': 'trust_auth_1',
                'asset_id': 'auth-host',
                'session_id': 'auth-session',
                'snapshot_ts': '2026-07-09T12:00:00+00:00',
            }
        ]
    }

    unconfigured = client.post('/api/v1/ingest/trust-snapshots', json=payload)
    assert unconfigured.status_code == 503
    assert unconfigured.json()['detail']['error']['code'] == 'ingest_token_not_configured'

    monkeypatch.setenv('EGRET_INGEST_TOKEN', 'expected-token')
    missing = client.post('/api/v1/ingest/trust-snapshots', json=payload)
    assert missing.status_code == 401
    assert missing.json()['detail']['error']['code'] == 'invalid_ingest_token'

    invalid = client.post('/api/v1/ingest/trust-snapshots', headers={'Authorization': 'Bearer wrong-token'}, json=payload)
    assert invalid.status_code == 401
    assert invalid.json()['detail']['error']['code'] == 'invalid_ingest_token'

    valid = client.post('/api/v1/ingest/trust-snapshots', headers={'Authorization': 'Bearer expected-token'}, json=payload)
    assert valid.status_code == 200
    assert valid.json()['ingested'] == 1
    deps.reset_bootstrap_state()
