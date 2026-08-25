from __future__ import annotations

import base64

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import files as files_api
from app.api.v1 import protection as protection_api
from app.api.v1 import quarantine as quarantine_api
from app.api.v1 import threats as threats_api
from app.storage.repositories.sqlite import SqliteRepositories


def build_client(repos: SqliteRepositories) -> TestClient:
    app = FastAPI()
    app.include_router(files_api.router)
    app.include_router(threats_api.router)
    app.include_router(quarantine_api.router)
    app.include_router(protection_api.router)
    app.dependency_overrides[files_api.get_file_event_repository] = lambda: repos.files
    app.dependency_overrides[files_api.get_malware_verdict_repository] = lambda: repos.malware_verdicts
    app.dependency_overrides[files_api.get_quarantine_repository] = lambda: repos.quarantine
    app.dependency_overrides[threats_api.get_malware_verdict_repository] = lambda: repos.malware_verdicts
    app.dependency_overrides[threats_api.get_web_verdict_repository] = lambda: repos.web_verdicts
    app.dependency_overrides[threats_api.get_behavior_alert_repository] = lambda: repos.behavior_alerts
    app.dependency_overrides[quarantine_api.get_quarantine_repository] = lambda: repos.quarantine
    app.dependency_overrides[protection_api.get_file_event_repository] = lambda: repos.files
    app.dependency_overrides[protection_api.get_malware_verdict_repository] = lambda: repos.malware_verdicts
    app.dependency_overrides[protection_api.get_quarantine_repository] = lambda: repos.quarantine
    app.dependency_overrides[protection_api.get_web_verdict_repository] = lambda: repos.web_verdicts
    app.dependency_overrides[protection_api.get_behavior_alert_repository] = lambda: repos.behavior_alerts
    return TestClient(app)


def test_scan_api_threats_and_protection_status() -> None:
    repos = SqliteRepositories(':memory:')
    client = build_client(repos)
    eicar = base64.b64encode(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*').decode('utf-8')
    scan = client.post('/api/v1/files/scan', json={
        'asset_id': 'asset-1',
        'session_id': 'session-1',
        'path': '/Users/me/Downloads/eicar.com',
        'content_base64': eicar,
        'origin_kind': 'download',
        'signer_status': 'unsigned',
    })
    assert scan.status_code == 200
    payload = scan.json()
    assert payload['verdict']['verdict'] == 'malicious'
    assert payload['quarantine_record'] is not None

    web = client.post('/api/v1/protection/web-check', json={'asset_id': 'asset-1', 'url': 'https://evil.example/pay'})
    assert web.status_code == 200
    assert web.json()['verdict'] == 'block'

    threats = client.get('/api/v1/threats', params={'asset_id': 'asset-1'})
    assert threats.status_code == 200
    threat_payload = threats.json()
    assert len(threat_payload['malware_verdicts']) == 1
    assert len(threat_payload['web_verdicts']) == 1

    status = client.get('/api/v1/protection/status')
    assert status.status_code == 200
    av = status.json()['av']
    assert av['file_events'] == 1
    assert av['malware_verdicts'] == 1
    assert av['active_quarantine'] == 1
    assert av['blocked_web_events'] == 1
