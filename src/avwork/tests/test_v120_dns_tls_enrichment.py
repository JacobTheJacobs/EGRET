from datetime import datetime, timedelta

from app.models.connection_event import ConnectionEvent
from app.services.enrichment.dns_enrichment import DnsAnswerEvent, DnsEnricher
from app.services.enrichment.tls_enrichment import TlsEnricher, TlsHandshakeEvent


NOW = datetime(2026, 4, 13, 10, 0, 0)


def make_connection() -> ConnectionEvent:
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
    )


def test_dns_enricher_matches_recent_answer_for_remote_ip() -> None:
    connection = make_connection()
    event = DnsAnswerEvent(
        asset_id="asset-1",
        session_id="sess-1",
        query_name="example.com",
        answers=("93.184.216.34",),
        observed_at=NOW - timedelta(seconds=5),
        ttl_seconds=300,
    )

    result = DnsEnricher().correlate(connection, [event])

    assert result.matched_domain == "example.com"
    assert result.confidence > 0.9
    assert result.reason == "matched_recent_dns_answer_for_remote_ip"


def test_tls_enricher_matches_handshake_by_ip_port_and_time() -> None:
    connection = make_connection()
    event = TlsHandshakeEvent(
        asset_id="asset-1",
        session_id="sess-1",
        remote_ip="93.184.216.34",
        remote_port=443,
        observed_at=NOW + timedelta(seconds=2),
        sni="example.com",
        certificate_subject="CN=example.com",
        certificate_issuer="Example CA",
        certificate_fingerprint="ABCD1234567890",
    )

    result = TlsEnricher().correlate(connection, [event])

    assert result.sni == "example.com"
    assert result.certificate_subject == "CN=example.com"
    assert result.confidence > 0.9
