from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def test_compiled_ui_routes_are_served_when_build_exists() -> None:
    client = TestClient(create_app())
    root = client.get('/', follow_redirects=False)
    assert root.status_code in {307, 308}
    assert root.headers['location'] == '/connections'

    response = client.get('/connections')
    assert response.status_code == 200
    assert 'text/html' in response.headers['content-type']
    assert 'Egret' in response.text


def test_compiled_ui_assets_are_served() -> None:
    client = TestClient(create_app())
    index = client.get('/connections').text
    marker = 'src="/assets/'
    assert marker in index
    asset = index.split(marker, 1)[1].split('"', 1)[0]
    response = client.get(f'/assets/{asset}')
    assert response.status_code == 200
