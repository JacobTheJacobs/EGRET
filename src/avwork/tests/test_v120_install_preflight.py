from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_install_preflight_prepares_runtime_with_signed_release(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    subprocess.run([sys.executable, 'scripts/finalize_release_candidate.py', '--skip-tests', '--skip-frontend'], cwd=root, check=True)
    data_dir = tmp_path / 'runtime'
    result = subprocess.run(
        [sys.executable, 'scripts/install_preflight.py', '--data-dir', str(data_dir)],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload['status'] == 'ok'
    assert Path(payload['db_path']).exists()
    assert Path(payload['content_dir']).exists()
    assert Path(payload['backend_state_dir']).exists()
    assert Path(payload['service_configs']['systemd_unit']).exists()
    assert Path(payload['service_configs']['launchd_plist']).exists()
    assert Path(payload['service_configs']['windows_script']).exists()
    assert payload['release']['artifact_signature_valid'] is True
    assert payload['release']['manifest_signature_valid'] is True
    assert payload['environment']['EGRET_DB_PATH'].endswith('egret.sqlite3')
    token_file = Path(payload['ingest_token_file'])
    assert token_file.exists()
    token = token_file.read_text(encoding='utf-8').strip()
    assert len(token) >= 32
    assert payload['ingest_token_preview'] == token[-6:]
    assert token not in result.stdout
    assert payload['security']['ingest_token_configured'] is True
    assert payload['security']['ingest_token_file'] == str(token_file)
    assert payload['security']['secret_values_exposed'] is False
    systemd = Path(payload['service_configs']['systemd_unit']).read_text(encoding='utf-8')
    assert f'EGRET_INGEST_TOKEN={token}' in systemd


def test_install_preflight_requires_signatures_unless_skipped(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    artifact = tmp_path / 'artifact.zip'
    manifest = tmp_path / 'release-manifest.json'
    artifact.write_bytes(b'unsigned')
    manifest.write_text('{}', encoding='utf-8')
    failed = subprocess.run(
        [
            sys.executable,
            'scripts/install_preflight.py',
            '--data-dir',
            str(tmp_path / 'runtime-fail'),
            '--artifact',
            str(artifact),
            '--manifest',
            str(manifest),
        ],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert failed.returncode != 0
    assert 'release signature verification failed' in failed.stdout

    ok = subprocess.run(
        [
            sys.executable,
            'scripts/install_preflight.py',
            '--data-dir',
            str(tmp_path / 'runtime-ok'),
            '--artifact',
            str(artifact),
            '--manifest',
            str(manifest),
            '--skip-signature-check',
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(ok.stdout)
    assert payload['release']['signature_check_skipped'] is True


def test_install_preflight_reuses_existing_ingest_token(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    subprocess.run([sys.executable, 'scripts/finalize_release_candidate.py', '--skip-tests', '--skip-frontend'], cwd=root, check=True)
    data_dir = tmp_path / 'runtime'
    data_dir.mkdir()
    token_file = data_dir / 'ingest-token'
    token_file.write_text('existing-token-value\n', encoding='utf-8')
    result = subprocess.run(
        [sys.executable, 'scripts/install_preflight.py', '--data-dir', str(data_dir)],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload['ingest_token_generated'] is False
    assert payload['ingest_token_preview'] == '-value'
    assert token_file.read_text(encoding='utf-8').strip() == 'existing-token-value'
