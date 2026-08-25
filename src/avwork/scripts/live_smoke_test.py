from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return int(sock.getsockname()[1])


def request_json(method: str, url: str, payload: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    body = json.dumps(payload).encode('utf-8') if payload is not None else None
    request_headers = headers.copy() if headers else {}
    if body is not None:
        request_headers['content-type'] = 'application/json'
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers=request_headers,
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode('utf-8'))


def request_text(url: str) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=10) as response:
        return int(response.status), response.read().decode('utf-8')


def wait_for_server(base_url: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 20
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = ''
            if process.stdout is not None:
                output = process.stdout.read()
            raise RuntimeError(f'uvicorn exited before readiness check completed:\n{output}')
        try:
            payload = request_json('GET', f'{base_url}/healthz')
            if payload == {'status': 'ok'}:
                return
        except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f'uvicorn did not become ready: {last_error}')


def assert_count(name: str, actual: int, expected: int) -> None:
    if actual != expected:
        raise AssertionError(f'{name} expected {expected}, got {actual}')


def ingest_headers(token: str) -> dict[str, str]:
    return {'X-Egret-Ingest-Token': token}


def populate_live_data(base_url: str, ingest_token: str) -> dict[str, Any]:
    asset_id = 'live-host-1'
    session_id = 'live-session-1'
    request_json(
        'POST',
        f'{base_url}/api/v1/ingest/trust-snapshots',
        {
            'snapshots': [
                {
                    'trust_context_snapshot_id': 'live_trust_1',
                    'asset_id': asset_id,
                    'session_id': session_id,
                    'snapshot_ts': '2026-07-09T10:59:30+00:00',
                    'risky_ble_signature_counter': False,
                    'rogue_ble_counter_reuse': False,
                    'trust_score': 0.82,
                    'drift_score': 0.18,
                    'supporting_context_json': {'source': 'live-smoke-http'},
                }
            ]
        },
        headers=ingest_headers(ingest_token),
    )
    ingested = request_json(
        'POST',
        f'{base_url}/api/v1/ingest/connections',
        {
            'records': [
                {
                    'connection_id': 'live_conn_sensor_example',
                    'asset_id': asset_id,
                    'session_id': session_id,
                    'process_id': 4242,
                    'process_name': 'LiveSensor',
                    'process_path': '/usr/local/bin/live-sensor',
                    'signer_name': 'Egret Sensor',
                    'signer_status': 'trusted',
                    'start_ts': '2026-07-09T11:00:00+00:00',
                    'remote_ip': '93.184.216.34',
                    'remote_port': 443,
                    'transport': 'tcp',
                    'protocol': 'tls',
                    'matched_domain': 'example.org',
                    'sni': 'example.org',
                    'certificate_subject': 'CN=example.org',
                    'certificate_issuer': 'CN=Example CA',
                    'network_zone': 'public_internet',
                    'bytes_out': 1200,
                    'bytes_in': 5400,
                    'flow_risk_score': 0.44,
                    'first_seen_on_asset': True,
                    'prevalence_on_asset': 0.1,
                    'trust_context_snapshot_id': 'live_trust_1',
                }
            ]
        },
        headers=ingest_headers(ingest_token),
    )
    connection_id = ingested['connection_ids'][0]
    decision = request_json(
        'POST',
        f'{base_url}/api/v1/decisions',
        {
            'connection_id': connection_id,
            'action': 'block',
            'ttl_seconds': 3600,
            'persist_as_rule': True,
            'user_reason': 'Live smoke test block decision',
            'process_name': 'LiveSensor',
            'domain_suffix': 'example.org',
            'network_zone': 'public_internet',
            'enforce_execute': False,
        },
    )
    eicar = base64.b64encode(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*').decode('utf-8')
    execute_scan = request_json(
        'POST',
        f'{base_url}/api/v1/files/execute-scan',
        {
            'asset_id': asset_id,
            'session_id': session_id,
            'path': 'C:/Users/live/Downloads/eicar.com',
            'content_base64': eicar,
            'process_name': 'powershell.exe',
            'parent_process_name': 'WINWORD.EXE',
            'origin_kind': 'download',
            'signer_status': 'unsigned',
            'network_destination': 'evil.example',
        },
    )
    web = request_json('POST', f'{base_url}/api/v1/protection/web-check', {'asset_id': asset_id, 'url': 'https://evil.example/pay'})
    ransomware = request_json(
        'POST',
        f'{base_url}/api/v1/ransomware/evaluate',
        {
            'asset_id': asset_id,
            'session_id': session_id,
            'process_identity_id': ingested['items'][0]['process_identity_id'],
            'process_name': 'evilcrypt.exe',
            'signer_status': 'unsigned',
            'protected_path': '/Users/live/Documents',
            'modified_files_count': 42,
            'rename_delete_burst_count': 31,
            'entropy_spike': True,
            'touches_protected_dirs': True,
            'canary_touched': True,
        },
    )
    remediation = request_json(
        'POST',
        f"{base_url}/api/v1/remediation/ransomware/{ransomware['ransomware_signal']['ransomware_signal_id']}",
    )
    return {
        'asset_id': asset_id,
        'session_id': session_id,
        'connection_id': connection_id,
        'decision': decision,
        'execute_scan': execute_scan,
        'web': web,
        'ransomware': ransomware,
        'remediation': remediation,
    }


def run_live_smoke(db_path: Path) -> dict[str, Any]:
    db_path.parent.mkdir(parents=True, exist_ok=True)

    port = find_free_port()
    base_url = f'http://127.0.0.1:{port}'
    env = os.environ.copy()
    env['EGRET_DB_PATH'] = str(db_path)
    env['EGRET_INGEST_TOKEN'] = 'live-smoke-ingest-token'
    process = subprocess.Popen(
        [sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', str(port)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding='utf-8',
        errors='replace',
    )
    try:
        wait_for_server(base_url, process)
        generated = populate_live_data(base_url, env['EGRET_INGEST_TOKEN'])
        asset_id = generated['asset_id']
        connections = request_json('GET', f'{base_url}/api/v1/connections')
        files = request_json('GET', f'{base_url}/api/v1/files')
        threats = request_json('GET', f'{base_url}/api/v1/threats')
        quarantine = request_json('GET', f'{base_url}/api/v1/quarantine')
        ransomware = request_json('GET', f'{base_url}/api/v1/ransomware/signals')
        remediation = request_json('GET', f'{base_url}/api/v1/remediation')
        rules_before = request_json('GET', f'{base_url}/api/v1/rules')
        enforcement = request_json('GET', f'{base_url}/api/v1/enforcement/events')
        timeline = request_json('GET', f'{base_url}/api/v1/investigations/assets/{asset_id}/timeline')
        html_status, html = request_text(f'{base_url}/connections')

        assert_count('connections', len(connections['items']), 1)
        if {item['asset_id'] for item in connections['items']} != {asset_id}:
            raise AssertionError('connection rows must expose live asset_id values')
        assert_count('files', int(files['total']), 1)
        assert_count('threats', int(threats['total']), 4)
        assert_count('quarantine', len(quarantine['items']), 1)
        assert_count('ransomware', len(ransomware['items']), 1)
        assert_count('remediation', len(remediation['items']), 1)
        assert_count('rules_before', len(rules_before['items']), 1)
        if len(enforcement['items']) < 1:
            raise AssertionError('expected at least one live enforcement event')
        if len(timeline['items']) < 3:
            raise AssertionError('expected live investigation timeline to include connections, decisions, and trust snapshots')
        if html_status != 200 or '/assets/' not in html:
            raise AssertionError('compiled UI shell was not served with built assets')

        created = request_json(
            'POST',
            f'{base_url}/api/v1/rules',
            {
                'rule_name': 'Live smoke deny example.org',
                'enabled': True,
                'priority': 123,
                'source': 'user',
                'action': 'deny',
                'conditions': {'domain_suffix': 'example.org', 'network_zone': 'public_internet'},
                'created_by': 'live-smoke-test',
                'apply_immediately': False,
                'enforce_execute': False,
            },
        )
        updated = request_json('PATCH', f"{base_url}/api/v1/rules/{created['rule_id']}", {'enabled': False})
        rules_after = request_json('GET', f'{base_url}/api/v1/rules')
        if not any(item['rule_id'] == created['rule_id'] for item in rules_after['items']):
            raise AssertionError('created rule was not persisted')
        if updated['enabled'] is not False:
            raise AssertionError('patched rule state was not persisted')

        return {
            'status': 'ok',
            'base_url': base_url,
            'db_path': str(db_path),
            'generated': {
                'connection_id': generated['connection_id'],
                'policy_decision_id': generated['decision']['policy_decision_id'],
                'file_event_id': generated['execute_scan']['file_event']['file_event_id'],
                'web_verdict_id': generated['web']['web_verdict_id'],
                'ransomware_signal_id': generated['ransomware']['ransomware_signal']['ransomware_signal_id'],
                'remediation_action_id': generated['remediation']['remediation_action_id'],
            },
            'counts': {
                'connections': len(connections['items']),
                'files': int(files['total']),
                'threats': int(threats['total']),
                'quarantine': len(quarantine['items']),
                'ransomware': len(ransomware['items']),
                'remediation': len(remediation['items']),
                'rules_before': len(rules_before['items']),
                'rules_after': len(rules_after['items']),
                'enforcement_events': len(enforcement['items']),
                'timeline_items': len(timeline['items']),
            },
            'created_rule': created['rule_id'],
            'patched_rule_enabled': updated['enabled'],
            'ui_html_status': html_status,
            'ui_has_bundle': '/assets/' in html,
        }
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run a live Egret HTTP smoke test against uvicorn and SQLite.')
    parser.add_argument('--db-path', type=Path, default=None, help='SQLite path to use. Defaults to a temporary database.')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.db_path is not None:
        summary = run_live_smoke(args.db_path.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix='egret-live-smoke-') as tmp:
            summary = run_live_smoke(Path(tmp) / 'live-smoke.sqlite3')
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
