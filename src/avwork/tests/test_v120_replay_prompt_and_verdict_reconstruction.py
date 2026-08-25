from datetime import datetime, timedelta

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.policy_decision import PolicyDecision
from app.models.policy_rule import PolicyConditions, PolicyRule
from app.models.process_identity import ProcessIdentity
from app.models.trust_context_snapshot import TrustContextSnapshot
from app.services.learning.replay_export import ReplayExporter
from app.telemetry.replay.prompt_reconstruction import PromptReconstructor
from app.telemetry.replay.verdict_reconstruction import VerdictReconstructor


BASE_TS = datetime(2026, 4, 14, 12, 0, 0)


def make_connection() -> ConnectionEvent:
    return ConnectionEvent(
        connection_id='c_replay',
        asset_id='asset-1',
        session_id='session-1',
        process_identity_id='p_replay',
        start_ts=BASE_TS,
        direction='outbound',
        transport='tcp',
        remote_ip='203.0.113.10',
        remote_port=443,
        network_zone='public_internet',
        protocol='tls',
        first_seen_on_asset=True,
        flow_risk_score=0.88,
    )


def make_process() -> ProcessIdentity:
    return ProcessIdentity(
        process_identity_id='p_replay',
        asset_id='asset-1',
        session_id='session-1',
        process_id=444,
        process_name='Updater',
        process_path='/usr/bin/updater',
        signer_status='unsigned',
    )


def make_destination() -> DestinationIdentity:
    return DestinationIdentity(
        destination_identity_id='d_replay',
        matched_domain='unknown-updates.invalid',
        sni='unknown-updates.invalid',
        ip='203.0.113.10',
        port=443,
        protocol='tls',
    )


def test_replay_reconstructs_prompt_when_no_rule_matches() -> None:
    reconstructor = PromptReconstructor()
    selection = reconstructor.reconstruct(
        connection=make_connection(),
        process=make_process(),
        destination=make_destination(),
        matched_verdict=None,
        trust_snapshot=TrustContextSnapshot(
            trust_context_snapshot_id='t_replay',
            asset_id='asset-1',
            session_id='session-1',
            snapshot_ts=BASE_TS - timedelta(minutes=2),
            rogue_ble_counter_reuse=True,
            trust_score=0.25,
        ),
    )
    assert selection.should_prompt is True
    assert selection.recommendation == 'block'


def test_replay_reconstructs_matched_rule_and_exports_label_and_explanation() -> None:
    verdict_reconstructor = VerdictReconstructor()
    rule = PolicyRule(
        rule_id='r_block_updater',
        rule_name='Block updater to unknown domain',
        enabled=True,
        priority=120,
        source='user',
        action='deny',
        created_ts=BASE_TS - timedelta(hours=1),
        updated_ts=BASE_TS - timedelta(hours=1),
        created_by='user',
        conditions=PolicyConditions(process_name='Updater', domain_suffix='.invalid', network_zone='public_internet'),
    )
    result = verdict_reconstructor.reconstruct(
        connection=make_connection(),
        process=make_process(),
        destination=make_destination(),
        rules=[rule],
    )
    assert result.verdict == 'deny'
    assert result.matched_rule is not None
    assert result.matched_rule.rule_id == 'r_block_updater'

    prompt_selection = PromptReconstructor().reconstruct(
        connection=make_connection(),
        process=make_process(),
        destination=make_destination(),
        matched_verdict=result.verdict,
        trust_snapshot=None,
    )
    decision = PolicyDecision(
        policy_decision_id='pd_replay',
        connection_id='c_replay',
        matched_rule_id='r_block_updater',
        decision='deny',
        decision_source='user_rule',
        created_ts=BASE_TS,
    )
    export = ReplayExporter().export(
        connection=make_connection(),
        process=make_process(),
        destination=make_destination(),
        decision=decision,
        selection=prompt_selection,
        trust_snapshot=None,
    )
    assert export['label'] == 'auto_blocked_by_rule'
    assert export['explanation']['headline'].startswith('Updater connected to')
    assert export['explanation']['confidence_score'] >= 0.0
