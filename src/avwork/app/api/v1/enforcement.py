from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_enforcement_repository, get_rule_repository
from app.api.errors import not_found
from app.services.enforcement.applier import EnforcementService
from app.services.enforcement.backends import get_backend_adapter
from app.services.enforcement.capabilities import probe_all_backends, probe_backend_capability
from app.services.enforcement.reconciliation import EnforcementReconciler
from app.storage.repositories.interfaces import EnforcementRepository, RuleRepository

router = APIRouter(prefix='/api/v1/enforcement', tags=['enforcement'])


class ApplyRuleRequest(BaseModel):
    backend: Optional[str] = None
    execute: bool = True


def _backend_for_rule(rule_id: str, repo: EnforcementRepository) -> str:
    events = repo.list_events(rule_id=rule_id)
    if events:
        return events[-1].backend
    return 'macos'


@router.get('/events')
def list_enforcement_events(
    repo: Annotated[EnforcementRepository, Depends(get_enforcement_repository)],
    rule_id: str | None = None,
    connection_id: str | None = None,
    policy_decision_id: str | None = None,
) -> dict:
    return {
        'items': [
            item.model_dump(mode='json')
            for item in repo.list_events(
                rule_id=rule_id,
                connection_id=connection_id,
                policy_decision_id=policy_decision_id,
            )
        ]
    }


@router.get('/capabilities')
def capabilities() -> dict:
    items = [cap.to_dict() for cap in probe_all_backends()]
    return {'items': items, 'generated_at': datetime.now(timezone.utc).isoformat()}


@router.get('/capabilities/{backend}')
def capability(backend: str) -> dict:
    return probe_backend_capability(backend).to_dict()


@router.get('/backend-state/{rule_id}')
def backend_state(
    rule_id: str,
    rules: Annotated[RuleRepository, Depends(get_rule_repository)],
    events: Annotated[EnforcementRepository, Depends(get_enforcement_repository)],
) -> dict:
    rule = rules.get_rule(rule_id)
    if rule is None:
        raise not_found(code='rule_not_found', message='No rule exists for the supplied rule_id.', extra={'rule_id': rule_id})
    backend = _backend_for_rule(rule_id, events)
    adapter = get_backend_adapter(backend)
    state = adapter.read_rule_state(rule)
    return {
        'backend': state.backend,
        'rule_id': state.rule_id,
        'backend_rule_ref': state.backend_rule_ref,
        'state': state.state,
        'observed_at': state.observed_at.isoformat(),
        'details': state.details,
    }


@router.get('/reconciliation')
def reconcile_enforcement(
    rules: Annotated[RuleRepository, Depends(get_rule_repository)],
    events: Annotated[EnforcementRepository, Depends(get_enforcement_repository)],
) -> dict:
    issues = EnforcementReconciler().reconcile(rules.list_rules(), events.list_events())
    return {'items': [issue.__dict__ for issue in issues], 'generated_at': datetime.now(timezone.utc).isoformat()}


@router.post('/apply/rules/{rule_id}')
def apply_rule(
    rule_id: str,
    payload: ApplyRuleRequest,
    rules: Annotated[RuleRepository, Depends(get_rule_repository)],
    events: Annotated[EnforcementRepository, Depends(get_enforcement_repository)],
) -> dict:
    rule = rules.get_rule(rule_id)
    if rule is None:
        raise not_found(code='rule_not_found', message='No rule exists for the supplied rule_id.', extra={'rule_id': rule_id})
    event = EnforcementService(events).apply_rule(rule, backend=payload.backend, execute=payload.execute)
    return event.model_dump(mode='json')
