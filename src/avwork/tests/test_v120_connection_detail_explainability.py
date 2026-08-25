from datetime import datetime

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.process_identity import ProcessIdentity
from app.services.prompting.explanation_builder import ExplanationBuilder
from app.services.prompting.prompt_selector import PromptSelectionResult, TrustSnapshot


NOW = datetime(2026, 4, 13, 10, 0, 0)


def test_explanation_builder_returns_human_readable_payload() -> None:
    connection = ConnectionEvent(
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
        first_seen_on_asset=True,
        flow_risk_score=0.81,
    )
    process = ProcessIdentity(
        process_identity_id="pi-1",
        asset_id="asset-1",
        session_id="sess-1",
        process_id=111,
        process_name="Updater",
        process_path="/Applications/Updater",
        signer_name="Vendor",
        signer_status="trusted",
    )
    destination = DestinationIdentity(
        destination_identity_id="di-1",
        matched_domain="example.com",
        sni="example.com",
        ip="93.184.216.34",
        port=443,
        protocol="tls",
        certificate_subject="CN=example.com",
        certificate_issuer="Example CA",
        certificate_fingerprint="ABCDEF1234567890",
    )
    selection = PromptSelectionResult(
        should_prompt=True,
        recommendation="ask",
        severity="medium",
        reasons=["connection_is_first_seen_on_asset"],
    )

    explanation = ExplanationBuilder().build(
        connection=connection,
        process=process,
        destination=destination,
        selection=selection,
        trust_snapshot=TrustSnapshot(risky_ble_signature_counter=True, trust_score=0.62),
    )

    assert explanation.headline.startswith("Updater connected to example.com")
    assert explanation.confidence_score > 0
    assert any("Signed by Vendor" in factor for factor in explanation.user_factors)
    assert any("CN=example.com" in factor for factor in explanation.user_factors)
    assert "trust_score=0.620" in explanation.machine_factors
