from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_release_final_status_endpoint() -> None:
    client = TestClient(app)
    response = client.get('/api/v1/release/final-status')
    assert response.status_code == 200
    payload = response.json()
    assert payload['engineering_bundle_complete'] is True
    assert 'external_rollout_steps_remaining' in payload
