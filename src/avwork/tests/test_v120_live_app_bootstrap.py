from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import os

from fastapi.testclient import TestClient

from app.api import deps
from app.main import create_app
from app.models.policy_decision import PolicyDecision
from app.models.trust_context_snapshot import TrustContextSnapshot
from app.storage.adapters.legacy_flow_adapter import LegacyFlowDualWriter, LegacyFlowRecord

BASE_TS = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)


def make_legacy_record() -> LegacyFlowRecord:
    return LegacyFlowRecord(
        asset_id='asset-1',
        session_id='session-1',
        process_id=404,
        process_name='SyncAgent',
        process_path='/usr/local/bin/sync-agent',
        signer_name='Example Corp',
        signer_status='trusted',
        start_ts=BASE_TS,
        remote_ip='198.51.100.20',
        remote_port=443,
        transport='tcp',
        protocol='tls',
        matched_domain='sync.example.test',
        sni='sync.example.test',
        certificate_subject='CN=sync.example.test',
        certificate_issuer='CN=Example Test CA',
        network_zone='public_internet',
        flow_risk_score=0.31,
        first_seen_on_asset=False,
        prevalence_on_asset=0.76,
    )


def test_bootstrapped_app_serves_live_connections_and_timeline(tmp_path: Path) -> None:
    db_path = tmp_path / 'eng-v12.sqlite'
    deps.reset_bootstrap_state()
    os.environ['EDGE_NET_GUARDIAN_DB_PATH'] = str(db_path)
    state = deps.get_bootstrap_state()
    writer = LegacyFlowDualWriter(
        connections=state.repositories.connections,
        processes=state.repositories.processes,
        destinations=state.repositories.destinations,
    )
    event = writer.write(make_legacy_record())
    state.repositories.trust.upsert_snapshot(
        TrustContextSnapshot(
            trust_context_snapshot_id='t_200',
            asset_id='asset-1',
            session_id='session-1',
            snapshot_ts=BASE_TS - timedelta(minutes=1),
            trust_score=0.84,
            drift_score=0.12,
        )
    )
    state.repositories.decisions.create_decision(
        PolicyDecision(
            policy_decision_id='pd_200',
            connection_id=event.connection_id,
            decision='allow',
            decision_source='user_rule',
            prompt_shown=False,
            created_ts=BASE_TS + timedelta(seconds=5),
        )
    )

    client = TestClient(create_app())
    assert client.get('/healthz').json() == {'status': 'ok'}
    rows = client.get('/api/v1/connections').json()['items']
    assert len(rows) == 1
    detail = client.get(f'/api/v1/connections/{event.connection_id}').json()
    assert detail['process']['process_name'] == 'SyncAgent'
    timeline = client.get('/api/v1/investigations/assets/asset-1/timeline').json()
    kinds = [item['kind'] for item in timeline['items']]
    assert 'connection' in kinds
    assert 'decision' in kinds
    assert 'trust_snapshot' in kinds
    deps.reset_bootstrap_state()
