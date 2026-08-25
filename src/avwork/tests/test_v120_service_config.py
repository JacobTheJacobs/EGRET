from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.services.install.service_config import ServiceConfigInput, write_service_configs


def test_service_config_generation_writes_all_platform_artifacts(tmp_path: Path) -> None:
    data_dir = tmp_path / 'data'
    paths = write_service_configs(
        ServiceConfigInput(
            app_dir=tmp_path / 'app',
            data_dir=data_dir,
            db_path=data_dir / 'egret.sqlite3',
            content_dir=data_dir / 'content',
            backend_state_dir=data_dir / 'backend-state',
            python_executable='python',
            ingest_token='test-ingest-token',
        ),
        tmp_path / 'service',
    )
    systemd = paths.systemd_unit.read_text(encoding='utf-8')
    launchd = paths.launchd_plist.read_text(encoding='utf-8')
    windows = paths.windows_script.read_text(encoding='utf-8')
    assert 'ExecStart=python -m uvicorn app.main:app --host 127.0.0.1 --port 8000' in systemd
    assert 'Environment="EGRET_DB_PATH=' in systemd
    assert 'Environment="EGRET_INGEST_TOKEN=test-ingest-token"' in systemd
    assert '<string>com.egret.agent</string>' in launchd
    assert '<key>EGRET_CONTENT_DIR</key>' in launchd
    assert '<key>EGRET_INGEST_TOKEN</key><string>test-ingest-token</string>' in launchd
    assert 'New-Service -Name $ServiceName' in windows
    assert 'EGRET_BACKEND_STATE_DIR' in windows
    assert 'EGRET_INGEST_TOKEN' in windows


def test_generate_service_config_script_outputs_paths(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            'scripts/generate_service_config.py',
            '--data-dir',
            str(tmp_path / 'data'),
            '--output-dir',
            str(tmp_path / 'service'),
            '--ingest-token',
            'script-token',
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert Path(payload['systemd_unit']).exists()
    assert Path(payload['launchd_plist']).exists()
    assert Path(payload['windows_script']).exists()
    assert 'EGRET_INGEST_TOKEN=script-token' in Path(payload['systemd_unit']).read_text(encoding='utf-8')
