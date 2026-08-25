from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.frontend_tool import frontend_command


def test_live_smoke_script_runs_real_http_server(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    subprocess.run(frontend_command('build'), cwd=root, check=True)
    result = subprocess.run(
        [sys.executable, 'scripts/live_smoke_test.py', '--db-path', str(tmp_path / 'live-smoke.sqlite3')],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload['status'] == 'ok'
    assert payload['counts']['connections'] == 1
    assert payload['counts']['threats'] == 4
    assert payload['counts']['rules_after'] == 2
    assert payload['patched_rule_enabled'] is False
    assert payload['ui_html_status'] == 200
    assert payload['ui_has_bundle'] is True
    assert payload['generated']['connection_id'] == 'live_conn_sensor_example'
