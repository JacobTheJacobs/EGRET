from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.models.enforcement_event import EnforcementEvent
from app.models.policy_rule import PolicyRule
from app.services.enforcement.backends import get_backend_adapter
from app.services.enforcement.compiler import compile_rule_for_backend, default_backend
from app.storage.repositories.interfaces import EnforcementRepository


class EnforcementService:
    def __init__(self, repo: EnforcementRepository) -> None:
        self.repo = repo

    def apply_rule(
        self,
        rule: PolicyRule,
        *,
        backend: str | None = None,
        connection_id: str | None = None,
        policy_decision_id: str | None = None,
        now: datetime | None = None,
        execute: bool = True,
    ) -> EnforcementEvent:
        now = now or datetime.now(timezone.utc)
        selected = backend or default_backend()
        if rule.action not in {'allow', 'deny'}:
            event = EnforcementEvent(
                enforcement_event_id=f'enf_{uuid4().hex[:12]}',
                rule_id=rule.rule_id,
                backend=selected,
                action='allow',
                status='skipped',
                connection_id=connection_id,
                policy_decision_id=policy_decision_id,
                message='Rule action is not enforceable at OS level.',
                command_preview=[],
                execution_mode='simulated',
                backend_state='unknown',
                applied_ts=now,
            )
            return self.repo.create_event(event)

        plan = compile_rule_for_backend(rule, selected)
        adapter = get_backend_adapter(selected)
        result = adapter.apply_rule(rule, command_preview=plan.command_preview, execute=execute)
        event = EnforcementEvent(
            enforcement_event_id=f'enf_{uuid4().hex[:12]}',
            rule_id=rule.rule_id,
            backend=selected,
            action=rule.action,
            status=result.status,
            connection_id=connection_id,
            policy_decision_id=policy_decision_id,
            message=result.message,
            command_preview=result.command_preview,
            backend_rule_ref=result.backend_rule_ref,
            execution_mode=result.execution_mode,
            backend_state=result.backend_state,
            applied_ts=now,
            effective_until=(now + timedelta(seconds=rule.ttl_seconds)) if rule.ttl_seconds else None,
        )
        return self.repo.create_event(event)
