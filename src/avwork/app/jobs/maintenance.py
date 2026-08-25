from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from app.services.enforcement.applier import EnforcementService
from app.services.enforcement.reconciliation import EnforcementReconciler
from app.storage.repositories.sqlite import SqliteRepositories


@dataclass(frozen=True)
class MaintenanceSummary:
    expired_rules: int
    expired_decisions: int
    reapplied_rules: int
    generated_at: str


def run_maintenance_cycle(repositories: SqliteRepositories, *, now: datetime | None = None, auto_reapply: bool = True) -> MaintenanceSummary:
    now = now or datetime.now(timezone.utc)
    expired_rules = repositories.rules.expire_rules(now)
    expired_decisions = repositories.decisions.expire_decisions(now)
    reapplied = 0
    if auto_reapply:
        issues = EnforcementReconciler().reconcile(repositories.rules.list_rules(), repositories.enforcement.list_events())
        for issue in issues:
            if issue.status not in {'pending_apply', 'backend_missing', 'reapply_needed', 'stale_plan'}:
                continue
            rule = repositories.rules.get_rule(issue.rule_id)
            if rule is None:
                continue
            EnforcementService(repositories.enforcement).apply_rule(rule, backend=issue.backend, now=now)
            reapplied += 1
    return MaintenanceSummary(
        expired_rules=expired_rules,
        expired_decisions=expired_decisions,
        reapplied_rules=reapplied,
        generated_at=now.isoformat(),
    )
