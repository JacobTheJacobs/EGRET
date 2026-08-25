from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app


def test_health_status_returns_counts(monkeypatch):
    monkeypatch.delenv('EGRET_INGEST_TOKEN', raising=False)
    monkeypatch.delenv('EDGE_NET_GUARDIAN_INGEST_TOKEN', raising=False)
    client = TestClient(create_app())
    response = client.get('/api/v1/health/status')
    assert response.status_code == 200
    payload = response.json()
    assert payload['status'] == 'ok'
    assert 'counts' in payload
    assert 'bootstrap' in payload
    assert payload['security']['ingest_token_configured'] is False
    assert payload['security']['secret_values_exposed'] is False


def test_health_status_reports_ingest_readiness_without_secret(monkeypatch):
    token = 'health-test-token'
    monkeypatch.setenv('EGRET_INGEST_TOKEN', token)
    client = TestClient(create_app())
    response = client.get('/api/v1/health/status')
    assert response.status_code == 200
    payload = response.json()
    assert payload['security']['ingest_token_configured'] is True
    assert 'X-Egret-Ingest-Token' in payload['security']['ingest_auth_headers']
    assert token not in json.dumps(payload)


def test_package_release_script_builds_manifest():
    root = Path(__file__).resolve().parents[1]
    dist = root / 'dist'
    if dist.exists():
        for p in dist.iterdir():
            p.unlink()
    subprocess.run([sys.executable, str(root / 'scripts' / 'package_release.py')], check=True, cwd=root)
    manifest = json.loads((dist / 'release-manifest.json').read_text(encoding='utf-8'))
    assert manifest['artifact'] == 'egret-v12-release-candidate.zip'
    assert len(manifest['sha256']) == 64
    assert manifest['included_root_files'] == ['README.md', 'requirements.txt', 'package.json', 'bun.lock', 'tsconfig.json', 'index.html', 'vite.config.ts']
    assert manifest['file_count'] > 0
    with zipfile.ZipFile(dist / manifest['artifact']) as archive:
        names = set(archive.namelist())
    assert 'README.md' in names
    assert 'requirements.txt' in names
    assert 'package.json' in names
    assert 'bun.lock' in names
    assert 'tsconfig.json' in names
    assert 'index.html' in names
    assert 'vite.config.ts' in names
    assert any(name.startswith('app/web/dist/assets/') and name.endswith('.js') for name in names)
    assert 'app/web/dist/index.html' in names
    assert 'scripts/verify_production.py' in names
    assert 'scripts/install_preflight.py' in names
    assert 'scripts/generate_service_config.py' in names
    assert 'scripts/seed_demo_data.py' in names
    assert 'scripts/live_smoke_test.py' in names
    assert 'runtime/content/default-pack.json' in names
    assert 'installers/linux/install.sh' in names


def test_release_archive_boots_compiled_ui_from_clean_extract(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    subprocess.run([sys.executable, str(root / 'scripts' / 'package_release.py')], check=True, cwd=root)
    manifest = json.loads((root / 'dist' / 'release-manifest.json').read_text(encoding='utf-8'))
    extract_dir = tmp_path / 'release'
    with zipfile.ZipFile(root / 'dist' / manifest['artifact']) as archive:
        archive.extractall(extract_dir)

    script = (
        "from fastapi.testclient import TestClient\n"
        "from app.main import create_app\n"
        "client = TestClient(create_app())\n"
        "root = client.get('/', follow_redirects=False)\n"
        "assert root.headers['location'] == '/connections'\n"
        "response = client.get('/connections')\n"
        "assert response.status_code == 200\n"
        "assert 'Egret' in response.text\n"
        "print('clean-release-ui-ok')\n"
    )
    result = subprocess.run(
        [sys.executable, '-c', script],
        cwd=extract_dir,
        capture_output=True,
        text=True,
        check=True,
    )
    assert 'clean-release-ui-ok' in result.stdout
