from datetime import datetime, timedelta

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.policy_rule import PolicyConditions, PolicyRule
from app.models.process_identity import ProcessIdentity
from app.services.policy.evaluator import EvaluationContext, PolicyEvaluator


NOW = datetime(2026, 4, 13, 10, 0, 0)


def make_context() -> EvaluationContext:
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
    )
    process = ProcessIdentity(
        process_identity_id="pi-1",
        asset_id="asset-1",
        session_id="sess-1",
        process_id=111,
        process_name="AdobeUpdater",
        process_path="/Applications/AdobeUpdater",
        signer_name="Adobe",
        signer_status="trusted",
    )
    destination = DestinationIdentity(
        destination_identity_id="di-1",
        matched_domain="telemetry.bad.example",
        ip="93.184.216.34",
        port=443,
        protocol="tls",
    )
    return EvaluationContext(connection=connection, process=process, destination=destination)


def make_rule(*, rule_id: str, action: str, priority: int, created_ts: datetime, ttl_seconds=None, **conditions) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        rule_name=rule_id,
        enabled=True,
        priority=priority,
        source="user",
        action=action,
        ttl_seconds=ttl_seconds,
        created_ts=created_ts,
        updated_ts=created_ts,
        conditions=PolicyConditions(**conditions),
    )


def test_domain_and_process_rule_beats_process_only_rule() -> None:
    context = make_context()
    rules = [
        make_rule(rule_id="process-only", action="allow", priority=100, created_ts=NOW, process_name="Adobe*"),
        make_rule(
            rule_id="process-plus-domain",
            action="deny",
            priority=100,
            created_ts=NOW,
            process_name="Adobe*",
            domain_suffix=".bad.example",
        ),
    ]

    result = PolicyEvaluator(now=NOW).evaluate(context, rules)

    assert result.matched_rule is not None
    assert result.matched_rule.rule_id == "process-plus-domain"
    assert result.verdict == "deny"


def test_deny_wins_over_allow_at_same_specificity() -> None:
    context = make_context()
    rules = [
        make_rule(rule_id="allow-rule", action="allow", priority=100, created_ts=NOW, process_name="Adobe*", remote_port=443),
        make_rule(rule_id="deny-rule", action="deny", priority=100, created_ts=NOW, process_name="Adobe*", remote_port=443),
    ]

    result = PolicyEvaluator(now=NOW).evaluate(context, rules)

    assert result.matched_rule is not None
    assert result.matched_rule.rule_id == "deny-rule"
    assert result.verdict == "deny"


def test_expired_temp_rule_no_longer_matches() -> None:
    context = make_context()
    rules = [
        make_rule(
            rule_id="expired-temp",
            action="deny",
            priority=100,
            created_ts=NOW - timedelta(hours=2),
            ttl_seconds=3600,
            process_name="Adobe*",
        ),
    ]

    result = PolicyEvaluator(now=NOW).evaluate(context, rules)

    assert result.matched_rule is None
    assert result.verdict == "ask"


def test_domain_suffix_respects_label_boundary() -> None:
    """A rule for example.com must not be claimed by evilexample.com."""
    from app.services.av.blocklists import domain_matches_entry

    for suffix in ('1e100.net', '.1e100.net'):
        assert domain_matches_entry('wr-in-f188.1e100.net', suffix)
        assert domain_matches_entry('1e100.net', suffix)
        # Without a label boundary these would match on a bare endswith().
        assert not domain_matches_entry('evil1e100.net', suffix)
        assert not domain_matches_entry('attacker-1e100.net', suffix)
