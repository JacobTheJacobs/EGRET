from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import connections as connections_api
from app.services.capture.host_connections import HostConnectionCaptureService, HostSocketObservation
from app.storage.adapters.legacy_flow_adapter import LegacyFlowDualWriter
from app.storage.repositories.sqlite import SqliteRepositories


FIXED_TS = datetime(2026, 7, 9, 14, 0, 0, tzinfo=timezone.utc)


def fake_observations() -> list[HostSocketObservation]:
    return [
        HostSocketObservation(
            process_id=4242,
            process_name='chrome',
            process_path='/usr/bin/chrome',
            local_ip='192.168.1.10',
            local_port=55123,
            remote_ip='93.184.216.34',
            remote_port=443,
        ),
        HostSocketObservation(
            process_id=1,
            process_name='loopback',
            process_path='/bin/loopback',
            local_ip='127.0.0.1',
            local_port=5000,
            remote_ip='127.0.0.1',
            remote_port=5001,
        ),
        HostSocketObservation(
            process_id=4242,
            process_name='chrome',
            process_path='/usr/bin/chrome',
            local_ip='192.168.1.10',
            local_port=55123,
            remote_ip='93.184.216.34',
            remote_port=443,
        ),
    ]


def test_host_capture_persists_live_socket_rows() -> None:
    repos = SqliteRepositories(':memory:')
    writer = LegacyFlowDualWriter(connections=repos.connections, processes=repos.processes, destinations=repos.destinations)
    summary = HostConnectionCaptureService(writer, collector=fake_observations).capture(
        asset_id='host-1',
        session_id='session-1',
        now=FIXED_TS,
    )

    assert summary.status == 'ok'
    assert summary.captured == 1
    assert summary.skipped == 2
    rows, total = repos.connections.list_connections(page=1, page_size=10)
    assert total == 1
    assert rows[0].asset_id == 'host-1'
    assert rows[0].remote_ip == '93.184.216.34'
    assert rows[0].remote_port == 443
    assert rows[0].protocol == 'tls'


def test_capture_host_endpoint_writes_connections(monkeypatch) -> None:
    repos = SqliteRepositories(':memory:')
    app = FastAPI()
    app.include_router(connections_api.router)
    app.dependency_overrides[connections_api.get_connection_repository] = lambda: repos.connections
    app.dependency_overrides[connections_api.get_process_repository] = lambda: repos.processes
    app.dependency_overrides[connections_api.get_destination_repository] = lambda: repos.destinations
    app.dependency_overrides[connections_api.get_decision_repository] = lambda: repos.decisions
    app.dependency_overrides[connections_api.get_rule_repository] = lambda: repos.rules
    app.dependency_overrides[connections_api.get_trust_repository] = lambda: repos.trust
    monkeypatch.setattr(connections_api.HostConnectionCaptureService, '_collect', lambda self: fake_observations())

    client = TestClient(app)
    response = client.post('/api/v1/connections/capture-host', json={'asset_id': 'host-api', 'session_id': 'session-api', 'limit': 10})

    assert response.status_code == 200
    payload = response.json()
    assert payload['status'] == 'ok'
    assert payload['captured'] == 1
    assert payload['connection_ids']
    listed = client.get('/api/v1/connections').json()
    assert listed['total'] == 1
    assert listed['items'][0]['process']['name'] == 'chrome'


def test_repeated_capture_upserts_instead_of_duplicating_rows() -> None:
    """Polling the same established socket must not mint a new row each time."""
    repos = SqliteRepositories(':memory:')
    writer = LegacyFlowDualWriter(
        connections=repos.connections, processes=repos.processes, destinations=repos.destinations
    )
    service = HostConnectionCaptureService(writer, collector=fake_observations)

    first = service.capture(asset_id='host-1', session_id='session-1', now=FIXED_TS)
    later = datetime(2026, 7, 9, 14, 5, 0, tzinfo=timezone.utc)
    second = service.capture(asset_id='host-1', session_id='session-1', now=later)

    assert first.connection_ids == second.connection_ids

    _items, total = repos.connections.list_connections(page=1, page_size=50)
    assert total == 1


def test_reverse_dns_hostname_lands_on_the_destination() -> None:
    """A resolved PTR name is what makes domain-scoped rules possible."""

    class StubResolver:
        def resolve_many(self, ips, now=None):
            return {'93.184.216.34': 'example.test'}

    repos = SqliteRepositories(':memory:')
    writer = LegacyFlowDualWriter(
        connections=repos.connections, processes=repos.processes, destinations=repos.destinations
    )
    summary = HostConnectionCaptureService(
        writer, collector=fake_observations, resolver=StubResolver()
    ).capture(asset_id='host-1', session_id='session-1', now=FIXED_TS)

    event = repos.connections.get_connection(summary.connection_ids[0])
    assert event is not None
    destination = repos.destinations.get_destination_identity(event.destination_identity_id)
    assert destination is not None
    assert destination.matched_domain == 'example.test'
    assert destination.resolver_source == 'reverse_dns'


def test_repeated_capture_does_not_duplicate_unchanged_decisions() -> None:
    """Re-polling must not append a decision row when the verdict is unchanged."""
    from app.services.capture.decision_writer import CaptureDecisionWriter

    repos = SqliteRepositories(':memory:')
    writer = LegacyFlowDualWriter(
        connections=repos.connections, processes=repos.processes, destinations=repos.destinations
    )
    service = HostConnectionCaptureService(
        writer,
        collector=fake_observations,
        decisions=CaptureDecisionWriter(rules=repos.rules, decisions=repos.decisions),
    )

    summary = service.capture(asset_id='host-1', session_id='session-1', now=FIXED_TS)
    first = repos.decisions.get_latest_decision_for_connection(summary.connection_ids[0])
    assert first is not None

    later = datetime(2026, 7, 9, 14, 5, 0, tzinfo=timezone.utc)
    service.capture(asset_id='host-1', session_id='session-1', now=later)
    second = repos.decisions.get_latest_decision_for_connection(summary.connection_ids[0])

    # Same decision object reused, not a new row for an identical verdict.
    assert second is not None
    assert second.policy_decision_id == first.policy_decision_id
