from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_enforcement_repository, get_rule_repository
from app.api.errors import not_found
from app.models.policy_rule import PolicyConditions, PolicyRule
from app.services.enforcement.applier import EnforcementService
from app.services.policy.conflicts import RuleConflictDetector
from app.storage.repositories.interfaces import EnforcementRepository, RuleRepository

router = APIRouter(prefix='/api/v1/rules', tags=['rules'])


class RuleCreateRequest(BaseModel):
    rule_name: str
    enabled: bool = True
    priority: int = 100
    source: str = 'user'
    action: str
    ttl_seconds: Optional[int] = None
    created_by: Optional[str] = 'user'
    conditions: PolicyConditions
    explanation_template: Optional[str] = None
    apply_immediately: bool = False
    enforcement_backend: Optional[str] = None
    enforce_execute: bool = True


class RuleUpdateRequest(BaseModel):
    rule_name: Optional[str] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    ttl_seconds: Optional[int] = None
    conditions: Optional[PolicyConditions] = None
    explanation_template: Optional[str] = None
    apply_immediately: bool = False
    enforcement_backend: Optional[str] = None
    enforce_execute: bool = True


@router.get('')
def list_rules(repo: Annotated[RuleRepository, Depends(get_rule_repository)]) -> dict:
    return {'items': [item.model_dump(mode='json') for item in repo.list_rules()]}


@router.get('/conflicts')
def list_rule_conflicts(repo: Annotated[RuleRepository, Depends(get_rule_repository)]) -> dict:
    return {'items': RuleConflictDetector().detect(repo.list_rules())}


@router.post('')
def create_rule(payload: RuleCreateRequest, repo: Annotated[RuleRepository, Depends(get_rule_repository)], enforcement: Annotated[EnforcementRepository, Depends(get_enforcement_repository)]) -> dict:
    now = datetime.now(timezone.utc)
    created = repo.create_rule(PolicyRule(rule_id=f'r_{uuid4().hex[:12]}', rule_name=payload.rule_name, enabled=payload.enabled, priority=payload.priority, source=payload.source, action=payload.action, ttl_seconds=payload.ttl_seconds, created_ts=now, updated_ts=now, created_by=payload.created_by, conditions=payload.conditions, explanation_template=payload.explanation_template))
    response = created.model_dump(mode='json')
    if payload.apply_immediately:
        event = EnforcementService(enforcement).apply_rule(created, backend=payload.enforcement_backend, now=now, execute=payload.enforce_execute)
        response['enforcement_event'] = event.model_dump(mode='json')
    return response


@router.patch('/{rule_id}')
def update_rule(rule_id: str, payload: RuleUpdateRequest, repo: Annotated[RuleRepository, Depends(get_rule_repository)]) -> dict:
    updates = payload.model_dump(exclude_unset=True)
    updates['updated_ts'] = datetime.now(timezone.utc)
    updated = repo.update_rule(rule_id, **updates)
    if updated is None:
        raise not_found(code='rule_not_found', message='No rule exists for the supplied rule_id.', extra={'rule_id': rule_id})
    return updated.model_dump(mode='json')


@router.delete('/{rule_id}')
def delete_rule(rule_id: str, repo: Annotated[RuleRepository, Depends(get_rule_repository)]) -> dict:
    deleted = repo.delete_rule(rule_id)
    if not deleted:
        raise not_found(code='rule_not_found', message='No rule exists for the supplied rule_id.', extra={'rule_id': rule_id})
    return {'deleted': True, 'rule_id': rule_id}
