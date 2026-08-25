from datetime import datetime, timedelta

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.policy_decision import PolicyDecision
from app.models.process_identity import ProcessIdentity
from app.models.training_feedback_event import TrainingFeedbackEvent
from app.models.trust_context_snapshot import TrustContextSnapshot
from app.services.learning.feature_writer import TrainingFeatureWriter


BASE_TS = datetime(2026, 4, 14, 12, 0, 0)


def make_connection() -> ConnectionEvent:
    return ConnectionEvent(
        connection_id='c_feedback',
        asset_id='asset-1',
        session_id='session-1',
        process_identity_id='p_feedback',
        start_ts=BASE_TS,
        direction='outbound',
        transport='tcp',
        remote_ip='8.8.8.8',
        remote_port=443,
        network_zone='public_internet',
        protocol='tls',
        flow_risk_score=0.82,
    )


def make_process() -> ProcessIdentity:
    return ProcessIdentity(
        process_identity_id='p_feedback',
        asset_id='asset-1',
        session_id='session-1',
        process_id=321,
        process_name='Updater',
        process_path='/usr/bin/updater',
        signer_status='unsigned',
    )


def make_destination() -> DestinationIdentity:
    return DestinationIdentity(
        destination_identity_id='d_feedback',
        matched_domain='updates.example.net',
        sni='updates.example.net',
        ip='8.8.8.8',
        port=443,
        protocol='tls',
    )


def test_prompted_decision_emits_training_feedback_event() -> None:
    writer = TrainingFeatureWriter()
    decision = PolicyDecision(
        policy_decision_id='pd_1',
        connection_id='c_feedback',
        decision='deny',
        decision_source='user_prompt',
        prompt_shown=True,
        prompt_response='block',
        expires_at=BASE_TS + timedelta(hours=1),
        created_ts=BASE_TS,
    )
    event = writer.build_feedback_event(
        connection=make_connection(),
        process=make_process(),
        destination=make_destination(),
        decision=decision,
        trust_snapshot=TrustContextSnapshot(
            trust_context_snapshot_id='t_1',
            asset_id='asset-1',
            session_id='session-1',
            snapshot_ts=BASE_TS - timedelta(minutes=1),
            rogue_ble_counter_reuse=True,
            trust_score=0.31,
        ),
        now=BASE_TS,
    )
    assert isinstance(event, TrainingFeedbackEvent)
    assert event.label == 'prompted_block_temp'
    assert event.label_source == 'user_prompt'
    assert len(event.features_hash) == 64


def test_rule_based_decision_maps_to_auto_allow_label() -> None:
    writer = TrainingFeatureWriter()
    decision = PolicyDecision(
        policy_decision_id='pd_2',
        connection_id='c_feedback',
        matched_rule_id='r_123',
        decision='allow',
        decision_source='user_rule',
        created_ts=BASE_TS,
    )
    event = writer.build_feedback_event(
        connection=make_connection(),
        process=make_process(),
        destination=make_destination(),
        decision=decision,
        now=BASE_TS,
    )
    assert event.label == 'auto_allowed_by_rule'


def test_relabel_supersedes_prior_event() -> None:
    writer = TrainingFeatureWriter()
    prior = TrainingFeedbackEvent(
        training_feedback_event_id='tf_old',
        connection_id='c_feedback',
        label='uncertain',
        label_source='system_default',
        features_hash='a' * 64,
        generated_ts=BASE_TS,
    )
    replacement = TrainingFeedbackEvent(
        training_feedback_event_id='tf_new',
        connection_id='c_feedback',
        label='later_marked_benign',
        label_source='investigation',
        features_hash='b' * 64,
        generated_ts=BASE_TS + timedelta(minutes=5),
    )
    superseded = writer.supersede_event(prior, replacement)
    assert superseded.superseded_by == 'tf_new'
