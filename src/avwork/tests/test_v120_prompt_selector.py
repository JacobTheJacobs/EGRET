from datetime import datetime

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.process_identity import ProcessIdentity
from app.services.prompting.prompt_selector import PromptSelector, TrustSnapshot


NOW = datetime(2026, 4, 13, 10, 0, 0)


def make_connection(*, flow_risk_score: float = 0.1, first_seen_on_asset: bool = False, rule_suggestion_score: float = 0.1) -> ConnectionEvent:
    return ConnectionEvent(
        connection_id="c1",
        asset_id="asset-1",
        session_id="sess-1",
        process_identity_id="pi-1",
        start_ts=NOW,
        direction="outbound",
        protocol="tls",
        transport="tcp",
        remote_ip="93.184.216.34",
        remote_port=443,
        network_zone="public_internet",
        flow_risk_score=flow_risk_score,
        first_seen_on_asset=first_seen_on_asset,
        rule_suggestion_score=rule_suggestion_score,
    )


def make_process(*, signer_status: str = "trusted") -> ProcessIdentity:
    return ProcessIdentity(
        process_identity_id="pi-1",
        asset_id="asset-1",
        session_id="sess-1",
        process_id=111,
        process_name="Updater",
        process_path="/Applications/Updater",
        signer_name="Vendor",
        signer_status=signer_status,
    )


def make_destination() -> DestinationIdentity:
    return DestinationIdentity(
        destination_identity_id="di-1",
        matched_domain="example.com",
        ip="93.184.216.34",
        port=443,
        protocol="tls",
    )


def test_prompt_selector_skips_prompt_when_existing_rule_applies() -> None:
    result = PromptSelector().select(
        connection=make_connection(),
        process=make_process(),
        destination=make_destination(),
        matched_verdict="allow",
    )

    assert result.should_prompt is False
    assert result.recommendation == "allow"


def test_prompt_selector_prompts_for_high_risk_or_untrusted_context() -> None:
    result = PromptSelector().select(
        connection=make_connection(flow_risk_score=0.9, first_seen_on_asset=True),
        process=make_process(signer_status="unsigned"),
        destination=make_destination(),
        matched_verdict=None,
        trust_snapshot=TrustSnapshot(rogue_ble_counter_reuse=True),
    )

    assert result.should_prompt is True
    assert result.recommendation == "block"
    assert result.severity == "high"
    assert "process_signer_is_untrusted" in result.reasons
