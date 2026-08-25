from datetime import datetime, timedelta

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.process_identity import ProcessIdentity
from app.models.trust_context_snapshot import TrustContextSnapshot
from app.services.prompting.prompt_selector import PromptSelector
from app.services.trust.snapshot_join import TrustSnapshotJoiner


BASE_TS = datetime(2026, 4, 14, 12, 0, 0)


def make_connection() -> ConnectionEvent:
    return ConnectionEvent(
        connection_id='c_1',
        asset_id='asset-1',
        session_id='session-1',
        process_identity_id='p_1',
        start_ts=BASE_TS,
        direction='outbound',
        transport='tcp',
        remote_ip='1.1.1.1',
        remote_port=443,
        network_zone='public_internet',
        protocol='tls',
        flow_risk_score=0.4,
    )


def make_process() -> ProcessIdentity:
    return ProcessIdentity(
        process_identity_id='p_1',
        asset_id='asset-1',
        session_id='session-1',
        process_id=123,
        process_name='Firefox',
        process_path='/Applications/Firefox.app',
        signer_name='Mozilla',
        signer_status='trusted',
    )


def make_destination() -> DestinationIdentity:
    return DestinationIdentity(
        destination_identity_id='d_1',
        matched_domain='example.org',
        sni='example.org',
        ip='1.1.1.1',
        port=443,
        protocol='tls',
    )


def test_trust_snapshot_join_selects_latest_matching_snapshot() -> None:
    joiner = TrustSnapshotJoiner(max_age_seconds=600)
    connection = make_connection()
    snapshots = [
        TrustContextSnapshot(
            trust_context_snapshot_id='t_old',
            asset_id='asset-1',
            session_id='session-1',
            snapshot_ts=BASE_TS - timedelta(minutes=9),
            trust_score=0.9,
        ),
        TrustContextSnapshot(
            trust_context_snapshot_id='t_new',
            asset_id='asset-1',
            session_id='session-1',
            snapshot_ts=BASE_TS - timedelta(minutes=1),
            trust_score=0.72,
            risky_ble_signature_counter=True,
        ),
    ]

    result = joiner.select_snapshot(connection, snapshots)
    assert result.matched is True
    assert result.snapshot is not None
    assert result.snapshot.trust_context_snapshot_id == 't_new'
    assert result.snapshot.risky_ble_signature_counter is True

    updated = joiner.attach_snapshot_id(connection, snapshots)
    assert updated.trust_context_snapshot_id == 't_new'


def test_explicit_rule_suppresses_prompt_even_with_degraded_trust() -> None:
    selector = PromptSelector()
    result = selector.select(
        connection=make_connection(),
        process=make_process(),
        destination=make_destination(),
        matched_verdict='allow',
        trust_snapshot=None,
    )
    assert result.should_prompt is False
    assert result.recommendation == 'allow'
    assert 'existing_rule_applies' in result.reasons
