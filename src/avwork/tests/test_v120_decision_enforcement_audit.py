from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.api import deps
from app.main import create_app
from app.storage.adapters.legacy_flow_adapter import LegacyFlowDualWriter, LegacyFlowRecord

BASE_TS = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)


def test_persisted_decision_emits_enforcement_event() -> None:
    deps.reset_bootstrap_state()
    state = deps.get_bootstrap_state()
    writer = LegacyFlowDualWriter(
        connections=state.repositories.connections,
        processes=state.repositories.processes,
        destinations=state.repositories.destinations,
    )
    event = writer.write(
        LegacyFlowRecord(
            asset_id='asset-1',
            session_id='session-1',
            process_id=301,
            process_name='Updater',
            process_path='/usr/bin/updater',
            signer_name='Example Corp',
            signer_status='trusted',
            start_ts=BASE_TS,
            remote_ip='203.0.113.10',
            remote_port=443,
            transport='tcp',
            protocol='tls',
            matched_domain='bad.invalid',
            network_zone='public_internet',
        )
    )
    client = TestClient(create_app())
    response = client.post(
        '/api/v1/decisions',
        json={
            'connection_id': event.connection_id,
            'action': 'block',
            'ttl_seconds': 3600,
            'persist_as_rule': True,
            'process_name': 'Updater',
            'domain_suffix': '.invalid',
            'network_zone': 'public_internet',
            'enforcement_backend': 'linux',
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload['rule_id'] is not None
    assert payload['enforcement_event']['backend'] == 'linux'
    assert payload['enforcement_event']['status'] == 'applied'
    events = client.get('/api/v1/enforcement/events').json()['items']
    assert len(events) == 1
    assert events[0]['policy_decision_id'] == payload['policy_decision_id']
    deps.reset_bootstrap_state()
