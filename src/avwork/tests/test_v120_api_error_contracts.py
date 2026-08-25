from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import connections as connections_api
from app.api.v1 import decisions as decisions_api
from app.api.v1 import rules as rules_api
from app.models.policy_rule import PolicyConditions, PolicyRule
from app.storage.repositories.sqlite import SqliteRepositories


BASE_TS = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)


def build_client(repos: SqliteRepositories) -> TestClient:
    app = FastAPI()
    app.include_router(connections_api.router)
    app.include_router(decisions_api.router)
    app.include_router(rules_api.router)
    app.dependency_overrides[connections_api.get_connection_repository] = lambda: repos.connections
    app.dependency_overrides[connections_api.get_process_repository] = lambda: repos.processes
    app.dependency_overrides[connections_api.get_destination_repository] = lambda: repos.destinations
    app.dependency_overrides[connections_api.get_decision_repository] = lambda: repos.decisions
    app.dependency_overrides[connections_api.get_rule_repository] = lambda: repos.rules
    app.dependency_overrides[connections_api.get_trust_repository] = lambda: repos.trust
    app.dependency_overrides[decisions_api.get_connection_repository] = lambda: repos.connections
    app.dependency_overrides[decisions_api.get_decision_repository] = lambda: repos.decisions
    app.dependency_overrides[decisions_api.get_rule_repository] = lambda: repos.rules
    app.dependency_overrides[rules_api.get_rule_repository] = lambda: repos.rules
    return TestClient(app)


def test_missing_connection_returns_structured_not_found() -> None:
    repos = SqliteRepositories(':memory:')
    client = build_client(repos)
    response = client.get('/api/v1/connections/does-not-exist')
    assert response.status_code == 404
    payload = response.json()
    assert payload['detail']['error']['code'] == 'connection_not_found'


def test_invalid_decision_payload_returns_structured_bad_request() -> None:
    repos = SqliteRepositories(':memory:')
    client = build_client(repos)
    response = client.post(
        '/api/v1/decisions',
        json={'connection_id': 'missing', 'action': 'explode', 'persist_as_rule': False},
    )
    assert response.status_code == 400
    payload = response.json()
    assert payload['detail']['error']['code'] == 'invalid_decision_action'


def test_rules_conflicts_endpoint_returns_conflicts() -> None:
    repos = SqliteRepositories(':memory:')
    repos.rules.create_rule(
        PolicyRule(
            rule_id='r1',
            rule_name='Allow Firefox org',
            enabled=True,
            priority=100,
            source='user',
            action='allow',
            created_ts=BASE_TS,
            updated_ts=BASE_TS,
            conditions=PolicyConditions(process_name='Firefox', domain_suffix='.org'),
        )
    )
    repos.rules.create_rule(
        PolicyRule(
            rule_id='r2',
            rule_name='Deny Firefox org',
            enabled=True,
            priority=100,
            source='user',
            action='deny',
            created_ts=BASE_TS,
            updated_ts=BASE_TS,
            conditions=PolicyConditions(process_name='Firefox', domain_suffix='.org'),
        )
    )
    client = build_client(repos)
    response = client.get('/api/v1/rules/conflicts')
    assert response.status_code == 200
    items = response.json()['items']
    assert len(items) == 1
    assert items[0]['conflict_type'] == 'overlap_action_conflict'
