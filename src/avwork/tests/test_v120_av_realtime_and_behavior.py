from __future__ import annotations

import base64

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import files as files_api
from app.api.v1 import protection as protection_api
from app.api.v1 import threats as threats_api
from app.storage.repositories.sqlite import SqliteRepositories


def build_client(repos: SqliteRepositories) -> TestClient:
    app = FastAPI()
    app.include_router(files_api.router)
    app.include_router(threats_api.router)
    app.include_router(protection_api.router)
    app.dependency_overrides[files_api.get_file_event_repository] = lambda: repos.files
    app.dependency_overrides[files_api.get_malware_verdict_repository] = lambda: repos.malware_verdicts
    app.dependency_overrides[files_api.get_quarantine_repository] = lambda: repos.quarantine
    app.dependency_overrides[files_api.get_web_verdict_repository] = lambda: repos.web_verdicts
    app.dependency_overrides[files_api.get_behavior_alert_repository] = lambda: repos.behavior_alerts
    app.dependency_overrides[threats_api.get_malware_verdict_repository] = lambda: repos.malware_verdicts
    app.dependency_overrides[threats_api.get_web_verdict_repository] = lambda: repos.web_verdicts
    app.dependency_overrides[threats_api.get_behavior_alert_repository] = lambda: repos.behavior_alerts
    app.dependency_overrides[protection_api.get_file_event_repository] = lambda: repos.files
    app.dependency_overrides[protection_api.get_malware_verdict_repository] = lambda: repos.malware_verdicts
    app.dependency_overrides[protection_api.get_quarantine_repository] = lambda: repos.quarantine
    app.dependency_overrides[protection_api.get_web_verdict_repository] = lambda: repos.web_verdicts
    app.dependency_overrides[protection_api.get_behavior_alert_repository] = lambda: repos.behavior_alerts
    return TestClient(app)


def test_download_scan_creates_web_and_behavior_signals() -> None:
    repos = SqliteRepositories(':memory:')
    client = build_client(repos)
    content = base64.b64encode(b'console.log("benign download")').decode('utf-8')
    response = client.post('/api/v1/files/download-scan', json={
        'asset_id': 'asset-1',
        'session_id': 'session-1',
        'path': '/Users/me/Downloads/setup.js',
        'url': 'https://evil.example/setup.js',
        'content_base64': content,
        'process_name': 'Safari',
        'signer_status': 'unsigned',
    })
    assert response.status_code == 200
    payload = response.json()
    assert payload['web_verdict']['verdict'] == 'block'
    assert payload['verdict']['verdict'] == 'suspicious'
    assert payload['behavior_alert'] is not None
    assert payload['behavior_alert']['alert_kind'] == 'downloaded_payload_execution'

    status = client.get('/api/v1/protection/status')
    assert status.status_code == 200
    assert status.json()['av']['behavior_alerts'] == 1


def test_execute_scan_and_behavior_api() -> None:
    repos = SqliteRepositories(':memory:')
    client = build_client(repos)
    eicar = base64.b64encode(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*').decode('utf-8')
    response = client.post('/api/v1/files/execute-scan', json={
        'asset_id': 'asset-9',
        'session_id': 'session-9',
        'path': 'C:/Users/me/Downloads/eicar.com',
        'content_base64': eicar,
        'process_name': 'powershell.exe',
        'parent_process_name': 'WINWORD.EXE',
        'origin_kind': 'download',
        'signer_status': 'unsigned',
        'network_destination': 'evil.example',
    })
    assert response.status_code == 200
    payload = response.json()
    assert payload['verdict']['verdict'] == 'malicious'
    assert payload['quarantine_record'] is not None
    assert payload['behavior_alert'] is not None

    threat_listing = client.get('/api/v1/threats', params={'asset_id': 'asset-9'})
    assert threat_listing.status_code == 200
    listed = threat_listing.json()
    assert len(listed['behavior_alerts']) >= 1

    behavior_api = client.post('/api/v1/threats/behavior-evaluate', json={
        'asset_id': 'asset-9',
        'session_id': 'session-9',
        'process_name': 'powershell.exe',
        'writes_persistence': True,
        'signer_status': 'unsigned',
    })
    assert behavior_api.status_code == 200
    assert behavior_api.json()['behavior_alert']['alert_kind'] in {'persistence_abuse', 'script_persistence_abuse'}
