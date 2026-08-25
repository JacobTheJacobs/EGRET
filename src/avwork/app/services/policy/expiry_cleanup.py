from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from app.storage.repositories.interfaces import DecisionRepository, RuleRepository


@dataclass(frozen=True)
class ExpiryCleanupResult:
    expired_rule_count: int
    expired_decision_count: int


class ExpiryCleanupService:
    def __init__(
        self,
        *,
        rules: RuleRepository,
        decisions: DecisionRepository,
    ) -> None:
        self.rules = rules
        self.decisions = decisions

    def run(self, now: datetime | None = None) -> ExpiryCleanupResult:
        current_time = now or datetime.now(timezone.utc)
        expired_rule_count = self.rules.expire_rules(current_time)
        expired_decision_count = self.decisions.expire_decisions(current_time)
        return ExpiryCleanupResult(
            expired_rule_count=expired_rule_count,
            expired_decision_count=expired_decision_count,
        )
