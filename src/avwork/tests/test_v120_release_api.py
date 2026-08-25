from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def test_release_api_endpoints_respond() -> None:
    client = TestClient(create_app())
    manifest = client.get('/api/v1/release/manifest')
    assert manifest.status_code == 200
    assert manifest.json()['name'] == 'egret'

    readiness = client.get('/api/v1/release/rollout-readiness')
    assert readiness.status_code == 200
    assert 'items' in readiness.json()
