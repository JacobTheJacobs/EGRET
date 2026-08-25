from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import deps
from app.main import create_app


def test_ransomware_signal_and_remediation_flow(tmp_path):
    deps.reset_bootstrap_state()
    db_path = tmp_path / 'phase3.sqlite'
    import os
    os.environ['EDGE_NET_GUARDIAN_DB_PATH'] = str(db_path)
    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            '/api/v1/ransomware/evaluate',
            json={
                'asset_id': 'asset-1',
                'session_id': 'sess-1',
                'process_identity_id': 'proc-1',
                'process_name': 'evilcrypt.exe',
                'signer_status': 'unsigned',
                'protected_path': '/Users/shared/Documents',
                'modified_files_count': 42,
                'rename_delete_burst_count': 31,
                'entropy_spike': True,
                'touches_protected_dirs': True,
                'canary_touched': True,
            },
        )
        assert response.status_code == 200
        signal = response.json()['ransomware_signal']
        assert signal['signal_kind'] == 'canary_trip'
        assert signal['severity'] == 'critical'

        rem = client.post(f"/api/v1/remediation/ransomware/{signal['ransomware_signal_id']}")
        assert rem.status_code == 200
        action = rem.json()
        assert action['action_kind'] == 'rollback_candidate'
        assert action['status'] == 'completed'

        listed = client.get('/api/v1/ransomware/signals', params={'asset_id': 'asset-1'})
        assert listed.status_code == 200
        assert len(listed.json()['items']) == 1

        actions = client.get('/api/v1/remediation', params={'asset_id': 'asset-1'})
        assert actions.status_code == 200
        assert len(actions.json()['items']) == 1
    deps.reset_bootstrap_state()


def test_protection_status_includes_ransomware_and_remediation(tmp_path):
    deps.reset_bootstrap_state()
    import os
    os.environ['EDGE_NET_GUARDIAN_DB_PATH'] = str(tmp_path / 'status.sqlite')
    app = create_app()
    with TestClient(app) as client:
        signal = client.post(
            '/api/v1/ransomware/evaluate',
            json={
                'asset_id': 'asset-2',
                'session_id': 'sess-2',
                'process_name': 'unknown.exe',
                'signer_status': 'unsigned',
                'touches_protected_dirs': True,
                'modified_files_count': 12,
            },
        ).json()['ransomware_signal']
        assert signal['signal_kind'] == 'protected_folder_abuse'
        rem = client.post(f"/api/v1/remediation/ransomware/{signal['ransomware_signal_id']}")
        assert rem.status_code == 200

        status = client.get('/api/v1/protection/status')
        assert status.status_code == 200
        av = status.json()['av']
        assert av['ransomware_signals'] == 1
        assert av['remediation_actions'] == 1
        assert 'ransomware_guard_ready' in av['real_time_modes']
        assert 'remediation_ready' in av['real_time_modes']
    deps.reset_bootstrap_state()
