from __future__ import annotations

from fastapi import HTTPException, status


def error_detail(*, code: str, message: str, field: str | None = None, extra: dict | None = None) -> dict:
    detail = {
        'error': {
            'code': code,
            'message': message,
        }
    }
    if field is not None:
        detail['error']['field'] = field
    if extra:
        detail['error']['extra'] = extra
    return detail


def bad_request(*, code: str, message: str, field: str | None = None, extra: dict | None = None) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=error_detail(code=code, message=message, field=field, extra=extra),
    )


def not_found(*, code: str, message: str, extra: dict | None = None) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=error_detail(code=code, message=message, extra=extra),
    )


def conflict(*, code: str, message: str, extra: dict | None = None) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=error_detail(code=code, message=message, extra=extra),
    )
