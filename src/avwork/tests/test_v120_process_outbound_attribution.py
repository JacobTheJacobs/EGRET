from datetime import datetime, timedelta

from app.services.attribution.process_join import OutboundSocketEvent, ProcessJoiner, ProcessSnapshot


def test_join_outbound_socket_to_exact_process_identity() -> None:
    observed_at = datetime(2026, 4, 13, 10, 0, 0)
    socket_event = OutboundSocketEvent(
        asset_id="asset-1",
        session_id="sess-1",
        process_id=123,
        remote_ip="17.253.144.10",
        remote_port=443,
        observed_at=observed_at,
    )
    snapshot = ProcessSnapshot(
        asset_id="asset-1",
        session_id="sess-1",
        process_id=123,
        parent_process_id=1,
        process_name="Safari",
        process_path="/Applications/Safari.app/Contents/MacOS/Safari",
        signer_name="Apple",
        signer_status="trusted",
        observed_at=observed_at + timedelta(seconds=2),
    )

    result = ProcessJoiner(max_clock_skew_seconds=30).correlate(socket_event, [snapshot])

    assert result.process_identity is not None
    assert result.process_identity.process_name == "Safari"
    assert result.process_identity.signer_status == "trusted"
    assert result.process_identity.parent_process_id == 1
    assert result.confidence > 0.9


def test_join_returns_no_match_when_pid_or_session_do_not_align() -> None:
    observed_at = datetime(2026, 4, 13, 10, 0, 0)
    socket_event = OutboundSocketEvent(
        asset_id="asset-1",
        session_id="sess-1",
        process_id=123,
        remote_ip="1.1.1.1",
        remote_port=443,
        observed_at=observed_at,
    )
    snapshot = ProcessSnapshot(
        asset_id="asset-1",
        session_id="sess-2",
        process_id=123,
        parent_process_id=1,
        process_name="Safari",
        process_path="/Applications/Safari.app/Contents/MacOS/Safari",
        signer_name="Apple",
        signer_status="trusted",
        observed_at=observed_at,
    )

    result = ProcessJoiner(max_clock_skew_seconds=30).correlate(socket_event, [snapshot])

    assert result.process_identity is None
    assert result.confidence == 0.0
    assert result.reason == "no_matching_process_snapshot"
