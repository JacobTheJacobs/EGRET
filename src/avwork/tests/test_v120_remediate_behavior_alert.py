from __future__ import annotations

import base64
import os

from fastapi.testclient import TestClient

from app.api import deps
from app.main import create_app


EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def test_behavior_alert_can_be_remediated(tmp_path):
    deps.reset_bootstrap_state()
    os.environ['EDGE_NET_GUARDIAN_DB_PATH'] = str(tmp_path / 'behavior.sqlite')
    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            '/api/v1/files/download-scan',
            json={
                'asset_id': 'asset-b',
                'session_id': 'sess-b',
                'path': '/tmp/bad.bin',
                'url': 'https://phish.bad.example/payload.bin',
                'content_base64': base64.b64encode(EICAR).decode('utf-8'),
                'process_name': 'browser.exe',
                'signer_status': 'unsigned',
            },
        )
        assert response.status_code == 200
        alert = response.json()['behavior_alert']
        assert alert is not None
        rem = client.post(f"/api/v1/remediation/behavior/{alert['behavior_alert_id']}")
        assert rem.status_code == 200
        action = rem.json()
        assert action['action_kind'] == 'quarantine_file'
        assert action['related_object_id'] == alert['behavior_alert_id']
    deps.reset_bootstrap_state()
