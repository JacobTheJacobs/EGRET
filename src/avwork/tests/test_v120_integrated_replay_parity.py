from datetime import datetime, timedelta, timezone

from app.models.policy_rule import PolicyConditions, PolicyRule
from app.models.trust_context_snapshot import TrustContextSnapshot
from app.services.investigations.connection_details import ConnectionDetailsService
from app.storage.adapters.legacy_flow_adapter import LegacyFlowDualWriter, LegacyFlowRecord
from app.storage.repositories.sqlite import SqliteRepositories
from app.telemetry.replay.prompt_reconstruction import PromptReconstructor
from app.telemetry.replay.verdict_reconstruction import VerdictReconstructor


BASE_TS = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)


def make_legacy_record() -> LegacyFlowRecord:
    return LegacyFlowRecord(
        asset_id='asset-1',
        session_id='session-1',
        process_id=123,
        process_name='Updater',
        process_path='/usr/bin/updater',
        signer_name=None,
        signer_status='unsigned',
        start_ts=BASE_TS,
        remote_ip='203.0.113.10',
        remote_port=443,
        transport='tcp',
        protocol='tls',
        matched_domain='unknown-updates.invalid',
        sni='unknown-updates.invalid',
        certificate_subject='CN=unknown-updates.invalid',
        certificate_issuer='CN=Unknown CA',
        network_zone='public_internet',
        flow_risk_score=0.88,
        first_seen_on_asset=True,
        prevalence_on_asset=0.0,
    )


def test_integrated_detail_matches_reconstructed_prompt_and_verdict() -> None:
    repos = SqliteRepositories(':memory:')
    writer = LegacyFlowDualWriter(connections=repos.connections, processes=repos.processes, destinations=repos.destinations)
    event = writer.write(make_legacy_record())
    repos.trust.upsert_snapshot(
        TrustContextSnapshot(
            trust_context_snapshot_id='t_1',
            asset_id='asset-1',
            session_id='session-1',
            snapshot_ts=BASE_TS - timedelta(minutes=1),
            rogue_ble_counter_reuse=True,
            trust_score=0.2,
            drift_score=0.9,
        )
    )
    repos.connections.upsert_connection(event.model_copy(update={'trust_context_snapshot_id': 't_1'}))
    rule = repos.rules.create_rule(
        PolicyRule(
            rule_id='r_block_updater',
            rule_name='Block updater invalid',
            enabled=True,
            priority=120,
            source='user',
            action='deny',
            created_ts=BASE_TS - timedelta(minutes=30),
            updated_ts=BASE_TS - timedelta(minutes=30),
            conditions=PolicyConditions(process_name='Updater', domain_suffix='.invalid', network_zone='public_internet'),
        )
    )
    connection = repos.connections.get_connection(event.connection_id)
    process = repos.processes.get_process_identity(connection.process_identity_id)
    destination = repos.destinations.get_destination_identity(connection.destination_identity_id)
    trust = repos.trust.get_snapshot('t_1')
    verdict = VerdictReconstructor().reconstruct(connection=connection, process=process, destination=destination, rules=[rule])
    prompt = PromptReconstructor().reconstruct(
        connection=connection,
        process=process,
        destination=destination,
        matched_verdict=verdict.verdict,
        trust_snapshot=trust,
    )

    detail = ConnectionDetailsService(
        connections=repos.connections,
        processes=repos.processes,
        destinations=repos.destinations,
        decisions=repos.decisions,
        rules=repos.rules,
        trust=repos.trust,
    ).build_detail(event.connection_id)
    assert detail is not None
    assert verdict.verdict == 'deny'
    assert prompt.recommendation == 'deny'
    assert prompt.should_prompt is False
    assert detail['explanation']['headline'].startswith('Updater connected to unknown-updates.invalid')
    assert any('Wireless trust context is degraded by BLE counter reuse' == f for f in detail['explanation']['user_factors'])
