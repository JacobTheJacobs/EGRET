from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import connections as connections_api
from app.api.v1 import decisions as decisions_api
from app.models.trust_context_snapshot import TrustContextSnapshot
from app.storage.adapters.legacy_flow_adapter import LegacyFlowDualWriter, LegacyFlowRecord
from app.storage.repositories.sqlite import SqliteRepositories


BASE_TS = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)


def build_client(repos: SqliteRepositories) -> TestClient:
    app = FastAPI()
    app.include_router(connections_api.router)
    app.include_router(decisions_api.router)
    app.dependency_overrides[connections_api.get_connection_repository] = lambda: repos.connections
    app.dependency_overrides[connections_api.get_process_repository] = lambda: repos.processes
    app.dependency_overrides[connections_api.get_destination_repository] = lambda: repos.destinations
    app.dependency_overrides[connections_api.get_decision_repository] = lambda: repos.decisions
    app.dependency_overrides[connections_api.get_rule_repository] = lambda: repos.rules
    app.dependency_overrides[connections_api.get_trust_repository] = lambda: repos.trust
    app.dependency_overrides[decisions_api.get_connection_repository] = lambda: repos.connections
    app.dependency_overrides[decisions_api.get_decision_repository] = lambda: repos.decisions
    app.dependency_overrides[decisions_api.get_rule_repository] = lambda: repos.rules
    return TestClient(app)


def make_legacy_record() -> LegacyFlowRecord:
    return LegacyFlowRecord(
        asset_id='asset-1',
        session_id='session-1',
        process_id=123,
        process_name='Firefox',
        process_path='/Applications/Firefox.app',
        signer_name='Mozilla',
        signer_status='trusted',
        start_ts=BASE_TS,
        remote_ip='1.1.1.1',
        remote_port=443,
        transport='tcp',
        protocol='tls',
        matched_domain='example.org',
        sni='example.org',
        certificate_subject='CN=example.org',
        certificate_issuer='CN=Example CA',
        network_zone='public_internet',
        flow_risk_score=0.42,
        first_seen_on_asset=False,
        prevalence_on_asset=0.8,
    )


def test_legacy_dual_write_populates_connection_process_and_destination() -> None:
    repos = SqliteRepositories(':memory:')
    writer = LegacyFlowDualWriter(
        connections=repos.connections,
        processes=repos.processes,
        destinations=repos.destinations,
    )
    event = writer.write(make_legacy_record())

    stored = repos.connections.get_connection(event.connection_id)
    assert stored is not None
    assert stored.destination_identity_id is not None

    process = repos.processes.get_process_identity(stored.process_identity_id)
    assert process is not None
    assert process.process_name == 'Firefox'

    destination = repos.destinations.get_destination_identity(stored.destination_identity_id)
    assert destination is not None
    assert destination.matched_domain == 'example.org'


def test_connections_list_and_detail_are_backed_by_live_repositories() -> None:
    repos = SqliteRepositories(':memory:')
    writer = LegacyFlowDualWriter(
        connections=repos.connections,
        processes=repos.processes,
        destinations=repos.destinations,
    )
    event = writer.write(make_legacy_record())
    repos.trust.upsert_snapshot(
        TrustContextSnapshot(
            trust_context_snapshot_id='t_1',
            asset_id='asset-1',
            session_id='session-1',
            snapshot_ts=BASE_TS - timedelta(minutes=2),
            trust_score=0.91,
            drift_score=0.04,
            risky_ble_signature_counter=False,
            rogue_ble_counter_reuse=False,
        )
    )
    # Attach snapshot after insert to simulate dual-write phase enrichment.
    repos.connections.upsert_connection(event.model_copy(update={'trust_context_snapshot_id': 't_1'}))

    client = build_client(repos)
    list_response = client.get('/api/v1/connections')
    assert list_response.status_code == 200
    payload = list_response.json()
    assert payload['total'] == 1
    row = payload['items'][0]
    assert row['process']['name'] == 'Firefox'
    assert row['destination']['matched_domain'] == 'example.org'
    assert row['verdict'] == 'ask'
    assert row['explanation_preview'] in {'Signed by Mozilla (trusted)', 'Destination has been seen before on this asset'}

    detail_response = client.get(f"/api/v1/connections/{event.connection_id}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail['process']['process_name'] == 'Firefox'
    assert detail['destination']['certificate_subject'] == 'CN=example.org'
    assert detail['trust_context']['trust_score'] == 0.91
    assert detail['explanation']['headline'].startswith('Firefox connected to example.org')
    assert 'Destination has been seen before on this asset' in detail['explanation']['user_factors']


def test_post_decision_persists_rule_and_changes_verdict_filtering() -> None:
    repos = SqliteRepositories(':memory:')
    writer = LegacyFlowDualWriter(
        connections=repos.connections,
        processes=repos.processes,
        destinations=repos.destinations,
    )
    event = writer.write(make_legacy_record())
    client = build_client(repos)

    response = client.post(
        '/api/v1/decisions',
        json={
            'connection_id': event.connection_id,
            'action': 'block',
            'ttl_seconds': 3600,
            'persist_as_rule': True,
            'user_reason': 'Unexpected outbound destination',
            'process_name': 'Firefox',
            'domain_suffix': '.org',
            'network_zone': 'public_internet',
        },
    )
    assert response.status_code == 200
    decision_payload = response.json()
    assert decision_payload['decision'] == 'deny'
    assert decision_payload['rule_id'] is not None

    detail = client.get(f'/api/v1/connections/{event.connection_id}').json()
    assert detail['policy']['decision'] == 'deny'
    assert detail['policy']['matched_rule_id'] == decision_payload['rule_id']
    assert detail['policy']['matched_rule']['action'] == 'deny'

    filtered = client.get('/api/v1/connections', params={'verdict': 'deny'}).json()
    assert filtered['total'] == 1
    assert filtered['items'][0]['verdict'] == 'deny'
