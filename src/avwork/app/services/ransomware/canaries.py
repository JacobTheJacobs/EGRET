from __future__ import annotations

PROTECTED_CANARY_PATHS = [
    '/Users/shared/Documents/.edge_canary',
    'C:/Users/Public/Documents/.edge_canary',
    '/srv/shared/.edge_canary',
]


def default_canary_paths() -> list[str]:
    return list(PROTECTED_CANARY_PATHS)
