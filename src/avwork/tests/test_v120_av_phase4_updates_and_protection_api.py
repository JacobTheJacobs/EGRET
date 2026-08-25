from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import protection as protection_api
from app.api.v1 import updates as updates_api
from app.storage.repositories.sqlite import SqliteRepositories


def build_client(repos: SqliteRepositories) -> TestClient:
    app = FastAPI()
    app.include_router(protection_api.router)
    app.include_router(updates_api.router)
    app.dependency_overrides[protection_api.get_file_event_repository] = lambda: repos.files
    app.dependency_overrides[protection_api.get_malware_verdict_repository] = lambda: repos.malware_verdicts
    app.dependency_overrides[protection_api.get_quarantine_repository] = lambda: repos.quarantine
    app.dependency_overrides[protection_api.get_web_verdict_repository] = lambda: repos.web_verdicts
    app.dependency_overrides[protection_api.get_behavior_alert_repository] = lambda: repos.behavior_alerts
    app.dependency_overrides[protection_api.get_ransomware_signal_repository] = lambda: repos.ransomware_signals
    app.dependency_overrides[protection_api.get_remediation_action_repository] = lambda: repos.remediation_actions
    app.dependency_overrides[updates_api.get_malware_verdict_repository] = lambda: repos.malware_verdicts
    app.dependency_overrides[updates_api.get_quarantine_repository] = lambda: repos.quarantine
    return TestClient(app)


def test_updates_install_and_protection_status(tmp_path: Path) -> None:
    os.environ['EDGE_NET_GUARDIAN_CONTENT_DIR'] = str(tmp_path)
    repos = SqliteRepositories(':memory:')
    client = build_client(repos)
    payload = {'version': 'pack-api-1', 'signatures': [], 'malicious_hashes': {}, 'trusted_signers': [], 'malicious_domains': ['api-bad.example'], 'phishing_domains': []}
    resp = client.post('/api/v1/updates/content/install', json={'content_json': payload})
    assert resp.status_code == 200
    assert resp.json()['status']['version'] == 'pack-api-1'

    status = client.get('/api/v1/protection/status')
    assert status.status_code == 200
    av = status.json()['av']
    assert av['content_updates']['version'] == 'pack-api-1'
    assert 'estimated_false_positive_rate' in av['tuning']
