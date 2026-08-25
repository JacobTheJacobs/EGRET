from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from app.models.policy_rule import PolicyConditions, PolicyRule
from app.services.enforcement.backends import get_backend_adapter
from app.services.enforcement.capabilities import BackendCapability, probe_backend_capability


@dataclass(frozen=True)
class ValidationCheck:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict:
        return {'name': self.name, 'passed': self.passed, 'detail': self.detail}


@dataclass(frozen=True)
class HostValidationResult:
    backend: str
    validated_at: datetime
    runnable: bool
    ready_for_native_validation: bool
    command_preview: list[str]
    checks: list[ValidationCheck]

    def to_dict(self) -> dict:
        return {
            'backend': self.backend,
            'validated_at': self.validated_at.isoformat(),
            'runnable': self.runnable,
            'ready_for_native_validation': self.ready_for_native_validation,
            'command_preview': list(self.command_preview),
            'checks': [check.to_dict() for check in self.checks],
        }


def build_validation_rule(backend: str) -> PolicyRule:
    return PolicyRule(
        rule_id=f'validate_{backend}_outbound_tls',
        rule_name=f'Validate {backend} outbound TLS rule',
        enabled=True,
        priority=100,
        source='system',
        action='deny',
        created_ts=datetime.now(timezone.utc),
        updated_ts=datetime.now(timezone.utc),
        conditions=PolicyConditions(
            process_name='ValidationAgent',
            process_path='/opt/egret/bin/validation-agent',
            domain='validation.example.test',
            remote_port=443,
            protocol='tls',
            network_zone='public_internet',
        ),
    )


def validate_backend_host(backend: str, capability: BackendCapability | None = None) -> HostValidationResult:
    capability = capability or probe_backend_capability(backend)
    adapter = get_backend_adapter(backend)
    rule = build_validation_rule(backend)
    preview = adapter.command_preview_for_rule(rule)
    checks = [
        ValidationCheck(
            name='required_binaries',
            passed=len(capability.missing_binaries) == 0,
            detail='All required binaries available.' if not capability.missing_binaries else f"Missing: {', '.join(capability.missing_binaries)}",
        ),
        ValidationCheck(
            name='native_execution_enabled',
            passed=capability.native_execution_enabled,
            detail='Native execution enabled.' if capability.native_execution_enabled else 'Set EGRET_ENABLE_NATIVE_EXECUTION=1 to enable.',
        ),
        ValidationCheck(
            name='command_preview',
            passed=bool(preview),
            detail='Backend emitted native command preview.' if preview else 'Backend emitted no commands.',
        ),
    ]
    ready = all(check.passed for check in checks)
    return HostValidationResult(
        backend=backend,
        validated_at=datetime.now(timezone.utc),
        runnable=capability.runnable,
        ready_for_native_validation=ready,
        command_preview=preview,
        checks=checks,
    )


def validate_all_backends(backends: Iterable[str] = ('macos', 'windows', 'linux')) -> list[HostValidationResult]:
    return [validate_backend_host(backend) for backend in backends]
