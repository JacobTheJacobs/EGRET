from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import get_connection_repository, get_decision_repository, get_enforcement_repository, get_rule_repository
from app.api.errors import bad_request, not_found
from app.models.policy_decision import PolicyDecision
from app.services.enforcement.applier import EnforcementService
from app.models.policy_rule import PolicyConditions, PolicyRule
from app.storage.repositories.interfaces import ConnectionRepository, DecisionRepository, EnforcementRepository, RuleRepository

router = APIRouter(prefix='/api/v1/decisions', tags=['decisions'])


class DecisionCreateRequest(BaseModel):
    connection_id: str
    action: str = Field(description='allow, block, ask, defer')
    ttl_seconds: Optional[int] = None
    persist_as_rule: bool = False
    user_reason: Optional[str] = None
    enforcement_backend: Optional[str] = None
    enforce_execute: bool = True
    process_name: Optional[str] = None
    domain_suffix: Optional[str] = None
    network_zone: Optional[str] = None


@router.post('')
def create_decision(
    payload: DecisionCreateRequest,
    connections: Annotated[ConnectionRepository, Depends(get_connection_repository)],
    decisions: Annotated[DecisionRepository, Depends(get_decision_repository)],
    rules: Annotated[RuleRepository, Depends(get_rule_repository)],
    enforcement: Annotated[EnforcementRepository, Depends(get_enforcement_repository)],
) -> dict:
    if payload.action not in {'allow', 'block', 'ask', 'defer'}:
        raise bad_request(code='invalid_decision_action', message='action must be one of allow, block, ask, defer', field='action')
    if payload.ttl_seconds is not None and payload.ttl_seconds <= 0:
        raise bad_request(code='invalid_ttl_seconds', message='ttl_seconds must be positive when provided', field='ttl_seconds')
    connection = connections.get_connection(payload.connection_id)
    if connection is None:
        raise not_found(code='connection_not_found', message='No connection exists for the supplied connection_id.', extra={'connection_id': payload.connection_id})
    if payload.persist_as_rule and not any([payload.process_name, payload.domain_suffix, payload.network_zone]):
        raise bad_request(code='rule_scope_required', message='persist_as_rule requires at least one rule-scoping field.', extra={'required_any_of': ['process_name', 'domain_suffix', 'network_zone']})
    now = datetime.now(timezone.utc)
    rule_id = None
    enforcement_event = None
    if payload.persist_as_rule:
        action = 'deny' if payload.action == 'block' else 'allow'
        rule = PolicyRule(rule_id=f'r_{uuid4().hex[:12]}', rule_name=f'{action.title()} rule for {payload.process_name or "connection"}', enabled=True, priority=100, source='user', action=action, ttl_seconds=payload.ttl_seconds, created_ts=now, updated_ts=now, created_by='user', conditions=PolicyConditions(process_name=payload.process_name, domain_suffix=payload.domain_suffix, network_zone=payload.network_zone))
        rules.create_rule(rule)
        rule_id = rule.rule_id
    decision = PolicyDecision(policy_decision_id=f'pd_{uuid4().hex[:12]}', connection_id=payload.connection_id, matched_rule_id=rule_id, decision='deny' if payload.action == 'block' else payload.action, decision_source='user_prompt', prompt_shown=True, prompt_response=payload.action, user_reason=payload.user_reason, expires_at=(now + timedelta(seconds=payload.ttl_seconds)) if payload.ttl_seconds else None, created_ts=now)
    created = decisions.create_decision(decision)
    if rule_id is not None:
        applied_rule = rules.get_rule(rule_id)
        if applied_rule is not None:
            enforcement_event = EnforcementService(enforcement).apply_rule(
                applied_rule,
                backend=payload.enforcement_backend,
                connection_id=payload.connection_id,
                policy_decision_id=created.policy_decision_id,
                now=now,
                execute=payload.enforce_execute,
            )
    return {'policy_decision_id': created.policy_decision_id, 'rule_id': rule_id, 'decision': created.decision, 'expires_at': created.expires_at.isoformat() if created.expires_at else None, 'enforcement_event': enforcement_event.model_dump(mode='json') if enforcement_event else None}
