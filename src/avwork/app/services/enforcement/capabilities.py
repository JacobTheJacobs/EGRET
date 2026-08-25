from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from app.config.env import getenv_compat
from app.services.enforcement.backends import get_backend_adapter
from app.services.enforcement.binary_resolution import resolve_binary


@dataclass(frozen=True)
class BackendCapability:
    backend: str
    native_execution_enabled: bool
    required_binaries: list[str]
    available_binaries: list[str]
    missing_binaries: list[str]
    runnable: bool

    def to_dict(self) -> dict:
        return {
            'backend': self.backend,
            'native_execution_enabled': self.native_execution_enabled,
            'required_binaries': list(self.required_binaries),
            'available_binaries': list(self.available_binaries),
            'missing_binaries': list(self.missing_binaries),
            'runnable': self.runnable,
        }


def probe_backend_capability(backend: str) -> BackendCapability:
    adapter = get_backend_adapter(backend)
    required = list(adapter.required_binaries())
    available: list[str] = []
    missing: list[str] = []
    for binary in required:
        if resolve_binary(binary):
            available.append(binary)
        else:
            missing.append(binary)
    enabled = getenv_compat('EGRET_ENABLE_NATIVE_EXECUTION', 'EDGE_NET_GUARDIAN_ENABLE_NATIVE_EXECUTION', default='0') == '1'
    return BackendCapability(
        backend=backend,
        native_execution_enabled=enabled,
        required_binaries=required,
        available_binaries=available,
        missing_binaries=missing,
        runnable=enabled and not missing,
    )


def probe_all_backends(backends: Iterable[str] = ('macos', 'windows', 'linux')) -> list[BackendCapability]:
    return [probe_backend_capability(backend) for backend in backends]
