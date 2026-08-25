from __future__ import annotations

from dataclasses import dataclass

from app.models.enforcement_event import EnforcementEvent
from app.models.policy_rule import PolicyRule
from app.services.enforcement.backends import get_backend_adapter
from app.services.enforcement.compiler import default_backend


@dataclass(frozen=True)
class ReconciliationIssue:
    rule_id: str
    status: str
    summary: str
    backend: str
    observed_backend_state: str | None = None
    latest_enforcement_event_id: str | None = None


class EnforcementReconciler:
    def reconcile(self, rules: list[PolicyRule], events: list[EnforcementEvent]) -> list[ReconciliationIssue]:
        latest_by_rule: dict[str, EnforcementEvent] = {}
        for event in sorted(events, key=lambda e: e.applied_ts):
            latest_by_rule[event.rule_id] = event

        issues: list[ReconciliationIssue] = []
        for rule in rules:
            if not rule.enabled or rule.action not in {'allow', 'deny'}:
                continue
            latest = latest_by_rule.get(rule.rule_id)
            backend = latest.backend if latest else default_backend()
            adapter = get_backend_adapter(backend)
            observed = adapter.read_rule_state(rule)
            if latest is None:
                issues.append(
                    ReconciliationIssue(
                        rule_id=rule.rule_id,
                        status='pending_apply',
                        summary='No enforcement event exists for this enforceable rule.',
                        backend=backend,
                        observed_backend_state=observed.state,
                    )
                )
                continue
            if observed.state != 'present':
                issues.append(
                    ReconciliationIssue(
                        rule_id=rule.rule_id,
                        status='backend_missing',
                        summary='Backend does not currently report the rule as present.',
                        backend=backend,
                        observed_backend_state=observed.state,
                        latest_enforcement_event_id=latest.enforcement_event_id,
                    )
                )
                continue
            if latest.status in {'failed', 'stale'}:
                issues.append(
                    ReconciliationIssue(
                        rule_id=rule.rule_id,
                        status='reapply_needed',
                        summary='Latest enforcement status is not healthy.',
                        backend=backend,
                        observed_backend_state=observed.state,
                        latest_enforcement_event_id=latest.enforcement_event_id,
                    )
                )
                continue
            if latest.applied_ts < rule.updated_ts:
                issues.append(
                    ReconciliationIssue(
                        rule_id=rule.rule_id,
                        status='stale_plan',
                        summary='Rule changed after the latest enforcement plan was recorded.',
                        backend=backend,
                        observed_backend_state=observed.state,
                        latest_enforcement_event_id=latest.enforcement_event_id,
                    )
                )
        return issues
