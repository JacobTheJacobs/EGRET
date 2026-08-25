"""Evaluate captured connections against policy rules and persist the verdict.

Without this the rule engine never runs on the live path: ``PolicyEvaluator``
was only reachable from offline replay, so a rule the user created had no effect
on what the UI showed and every connection stayed at ``ask`` forever.

Decisions are written as ``policy_decision`` rows rather than computed on read,
matching the schema the rest of the product already assumes (the decisions API,
enforcement events, and the training labeler all key off ``decision_source``).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.policy_decision import PolicyDecision
from app.models.process_identity import ProcessIdentity
from app.services.policy.evaluator import EvaluationContext, PolicyEvaluator
from app.storage.repositories.interfaces import DecisionRepository, RuleRepository

#: Rule sources map onto the decision_source vocabulary of PolicyDecision.
_SOURCE_BY_RULE_SOURCE = {
    'admin': 'admin_rule',
    'user': 'user_rule',
    'system': 'system_default',
}


class CaptureDecisionWriter:
    """Applies the rule engine to freshly captured connections."""

    def __init__(self, rules: RuleRepository, decisions: DecisionRepository) -> None:
        self.rules = rules
        self.decisions = decisions

    def decide(
        self,
        *,
        connection: ConnectionEvent,
        process: ProcessIdentity,
        destination: DestinationIdentity | None,
        now: datetime | None = None,
    ) -> PolicyDecision:
        moment = now or datetime.now(timezone.utc)
        evaluator = PolicyEvaluator(now=moment)
        result = evaluator.evaluate(
            EvaluationContext(connection=connection, process=process, destination=destination),
            self.rules.list_rules(),
        )

        matched = result.matched_rule
        expires_at = None
        if matched is not None and matched.ttl_seconds:
            expires_at = matched.created_ts + timedelta(seconds=matched.ttl_seconds)

        matched_rule_id = matched.rule_id if matched else None
        # Capture re-evaluates every established socket on every poll. Writing a
        # row each time would grow policy_decision without bound for verdicts
        # that never changed, so only an actual change is recorded — which is
        # also what makes the table a usable audit trail.
        previous = self.decisions.get_latest_decision_for_connection(connection.connection_id)
        if (
            previous is not None
            and previous.decision == result.verdict
            and previous.matched_rule_id == matched_rule_id
        ):
            return previous

        decision = PolicyDecision(
            policy_decision_id=f'pd_{uuid4().hex[:12]}',
            connection_id=connection.connection_id,
            matched_rule_id=matched_rule_id,
            decision=result.verdict,
            decision_source=(
                _SOURCE_BY_RULE_SOURCE.get(matched.source, 'user_rule') if matched else 'system_default'
            ),
            prompt_shown=result.verdict == 'ask',
            expires_at=expires_at,
            created_ts=moment,
        )
        return self.decisions.create_decision(decision)
