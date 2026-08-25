"""Resolve which JavaScript package runner drives the frontend build.

The project pins ``bun`` in package.json, but the same scripts run fine under
``npm``. Preferring bun and falling back to npm keeps release tooling and tests
usable on hosts that only have Node installed.
"""

from __future__ import annotations

import shutil

RUNNERS = ('bun', 'npm')


def frontend_runner() -> list[str]:
    """Return the argv prefix for running a package.json script."""
    for runner in RUNNERS:
        if shutil.which(runner):
            return [runner, 'run']
    raise SystemExit(f'no JavaScript package runner found (looked for: {", ".join(RUNNERS)})')


def frontend_command(script: str) -> list[str]:
    """Return the full argv for a named package.json script."""
    return frontend_runner() + [script]
