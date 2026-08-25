from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from typing import Iterable, Optional

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.policy_rule import PolicyRule
from app.models.process_identity import ProcessIdentity
from app.services.av.blocklists import domain_matches_entry
from app.services.policy.specificity import compare_rules


@dataclass(frozen=True)
class EvaluationContext:
    connection: ConnectionEvent
    process: ProcessIdentity
    destination: Optional[DestinationIdentity] = None


@dataclass(frozen=True)
class EvaluationResult:
    matched_rule: Optional[PolicyRule]
    verdict: str
    reason: str


class PolicyEvaluator:
    def __init__(self, now: Optional[datetime] = None) -> None:
        self.now = now or datetime.now(timezone.utc)

    def evaluate(self, context: EvaluationContext, rules: Iterable[PolicyRule]) -> EvaluationResult:
        candidates = []
        for rule in rules:
            if not rule.enabled:
                continue
            if self._is_expired(rule):
                continue
            if self._matches(context, rule):
                candidates.append(rule)

        if not candidates:
            return EvaluationResult(matched_rule=None, verdict="ask", reason="no_matching_rule")

        candidates.sort(key=compare_rules, reverse=True)
        winner = candidates[0]
        return EvaluationResult(matched_rule=winner, verdict=winner.action, reason="matched_rule")

    def _is_expired(self, rule: PolicyRule) -> bool:
        if not rule.ttl_seconds:
            return False
        return self.now > (rule.created_ts + timedelta(seconds=rule.ttl_seconds))

    def _matches(self, context: EvaluationContext, rule: PolicyRule) -> bool:
        c = rule.conditions
        p = context.process
        d = context.destination
        e = context.connection

        if c.process_name and not fnmatch(p.process_name, c.process_name):
            return False
        if c.process_path and not fnmatch(p.process_path, c.process_path):
            return False
        if c.signer_name and p.signer_name != c.signer_name:
            return False
        if c.signer_status and p.signer_status != c.signer_status:
            return False
        if c.domain:
            if d is None or d.matched_domain != c.domain:
                return False
        # Suffix matching must respect the label boundary. A bare endswith()
        # would make a rule for "1e100.net" also match "evil1e100.net", so an
        # allow decision could be claimed by an attacker-registered domain.
        # domain_matches_entry is the same helper the blocklists use.
        if c.domain_suffix:
            if d is None or not d.matched_domain or not domain_matches_entry(d.matched_domain, c.domain_suffix):
                return False
        if c.domain_suffix_not_in and d is not None and d.matched_domain:
            for blocked_suffix in c.domain_suffix_not_in:
                if domain_matches_entry(d.matched_domain, blocked_suffix):
                    return False
        if c.remote_ip and e.remote_ip != c.remote_ip:
            return False
        if c.remote_port and e.remote_port != c.remote_port:
            return False
        if c.protocol and e.protocol != c.protocol:
            return False
        if c.network_zone and e.network_zone != c.network_zone:
            return False
        return True
