from __future__ import annotations

import os


def getenv_compat(name: str, *legacy_names: str, default: str | None = None) -> str | None:
    """Read an environment variable, falling back through renamed predecessors.

    Deployments predating the rename to Egret may still set the original
    EDGE_NET_GUARDIAN_* names. Names are tried left to right, current first.
    """
    for candidate in (name, *legacy_names):
        value = os.getenv(candidate)
        if value is not None:
            return value
    return default
