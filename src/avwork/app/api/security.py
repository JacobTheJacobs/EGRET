from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Header, HTTPException, status

from app.api.errors import error_detail
from app.config.env import getenv_compat

INGEST_AUTH_HEADERS = ('X-Egret-Ingest-Token', 'Authorization: Bearer')


def ingest_security_status() -> dict:
    expected = getenv_compat('EGRET_INGEST_TOKEN', 'EDGE_NET_GUARDIAN_INGEST_TOKEN')
    return {
        'ingest_token_configured': bool(expected),
        'ingest_auth_headers': list(INGEST_AUTH_HEADERS),
        'secret_values_exposed': False,
    }


def require_ingest_token(
    x_egret_ingest_token: Annotated[str | None, Header(alias='X-Egret-Ingest-Token')] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    expected = getenv_compat('EGRET_INGEST_TOKEN', 'EDGE_NET_GUARDIAN_INGEST_TOKEN')
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=error_detail(
                code='ingest_token_not_configured',
                message='Set EGRET_INGEST_TOKEN before accepting live telemetry ingest.',
            ),
        )
    bearer = None
    if authorization and authorization.lower().startswith('bearer '):
        bearer = authorization[7:].strip()
    supplied = x_egret_ingest_token or bearer
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={'WWW-Authenticate': 'Bearer'},
            detail=error_detail(
                code='invalid_ingest_token',
                message='A valid ingest token is required for live telemetry writes.',
            ),
        )
