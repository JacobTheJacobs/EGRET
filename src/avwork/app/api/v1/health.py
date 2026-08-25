from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import get_bootstrap_state, get_connection_repository, get_rule_repository
from app.api.security import ingest_security_status
from app.services.enforcement.capabilities import probe_all_backends
from app.storage.repositories.interfaces import ConnectionRepository, RuleRepository

router = APIRouter(prefix='/api/v1/health', tags=['health'])


@router.get('/status')
def status(
    connections: Annotated[ConnectionRepository, Depends(get_connection_repository)],
    rules: Annotated[RuleRepository, Depends(get_rule_repository)],
) -> dict:
    _, total_connections = connections.list_connections(page=1, page_size=1)
    # Counted server-side over the whole table. Deriving these in the client
    # from a fetched page silently under-reports once the table outgrows one
    # page, so the figures would disagree with the connection total beside them.
    _, awaiting_decision = connections.list_connections(page=1, page_size=1, verdict='ask')
    _, unpackaged = connections.list_connections(page=1, page_size=1, signer_status_not='trusted')
    total_rules = len(rules.list_rules())
    state = get_bootstrap_state()
    return {
        'status': 'ok',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'bootstrap': {
            'db_path': str(state.database.path),
            'applied_migrations': getattr(state.migrations, 'applied', []),
        },
        'counts': {
            'connections': total_connections,
            'rules': total_rules,
            'awaiting_decision': awaiting_decision,
            'unpackaged': unpackaged,
        },
        'security': ingest_security_status(),
        'enforcement_capabilities': [cap.to_dict() for cap in probe_all_backends()],
    }
