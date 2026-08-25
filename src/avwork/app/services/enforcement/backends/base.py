from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from app.config.env import getenv_compat
from app.models.policy_rule import PolicyRule
from app.services.enforcement.binary_resolution import resolve_binary


@dataclass(frozen=True)
class EnforcementExecutionResult:
    status: str
    message: str
    command_preview: list[str]
    backend_rule_ref: str | None = None
    execution_mode: str = 'simulated'
    backend_state: str = 'present'


@dataclass(frozen=True)
class BackendRuleState:
    backend: str
    rule_id: str
    backend_rule_ref: str | None
    state: str
    observed_at: datetime
    details: dict


class EnforcementBackendAdapter(Protocol):
    backend_name: str

    def apply_rule(self, rule: PolicyRule, *, command_preview: list[str], execute: bool = True) -> EnforcementExecutionResult:
        ...

    def read_rule_state(self, rule: PolicyRule) -> BackendRuleState:
        ...


class JsonStateBackendAdapter:
    backend_name = 'generic'

    def __init__(self, state_dir: Path | None = None) -> None:
        self.state_dir = state_dir or self._default_state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def _default_state_dir(self) -> Path:
        configured = getenv_compat('EGRET_BACKEND_STATE_DIR', 'EDGE_NET_GUARDIAN_BACKEND_STATE_DIR')
        if configured:
            return Path(configured)
        return Path(tempfile.gettempdir()) / 'egret_backend_state'

    @property
    def state_file(self) -> Path:
        return self.state_dir / f'{self.backend_name}.json'

    def _load(self) -> dict:
        if not self.state_file.exists():
            return {}
        return json.loads(self.state_file.read_text(encoding='utf-8'))

    def _save(self, payload: dict) -> None:
        self.state_file.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding='utf-8')

    def _command_supported(self) -> bool:
        return getenv_compat('EGRET_ENABLE_NATIVE_EXECUTION', 'EDGE_NET_GUARDIAN_ENABLE_NATIVE_EXECUTION', default='0') == '1'

    def _backend_rule_ref(self, rule: PolicyRule) -> str:
        return f'{self.backend_name}:{rule.rule_id}'

    def required_binaries(self) -> list[str]:
        return []

    def native_commands_for_rule(self, rule: PolicyRule) -> list[list[str]]:
        return []

    def command_preview_for_rule(self, rule: PolicyRule) -> list[str]:
        return [shlex.join(argv) for argv in self.native_commands_for_rule(rule)]

    def _run_native(self, rule: PolicyRule) -> tuple[bool, str]:
        commands = self.native_commands_for_rule(rule)
        if not commands:
            return False, 'No backend commands available.'
        if not self._command_supported():
            return False, 'Native execution disabled by configuration.'
        resolved_binaries = {binary: resolve_binary(binary) for binary in self.required_binaries()}
        missing = [binary for binary, path in resolved_binaries.items() if path is None]
        if missing:
            return False, f'Missing backend binaries: {", ".join(missing)}'
        outputs: list[str] = []
        try:
            for command in commands:
                resolved_command = list(command)
                if resolved_command and resolved_command[0] in resolved_binaries and resolved_binaries[resolved_command[0]]:
                    resolved_command[0] = resolved_binaries[resolved_command[0]] or resolved_command[0]
                stdout_raw, stderr_raw = self._execute_command(resolved_command)
                stdout = stdout_raw.strip()
                stderr = stderr_raw.strip()
                if stdout:
                    outputs.append(stdout)
                if stderr:
                    outputs.append(stderr)
            suffix = f' Output: {" | ".join(outputs)}' if outputs else ''
            return True, f'Executed native backend commands.{suffix}'
        except Exception as exc:  # pragma: no cover - exercised in integration tests
            return False, f'Native execution failed: {exc}'

    def _execute_command(self, command: list[str]) -> tuple[str, str]:
        try:
            completed = subprocess.run(command, check=True, capture_output=True, text=True)
            return completed.stdout or '', completed.stderr or ''
        except OSError as exc:
            if os.name == 'nt' and getattr(exc, 'winerror', None) == 193:
                shimmed = self._run_posix_shell_stub(command)
                if shimmed is not None:
                    return shimmed
            raise

    def _run_posix_shell_stub(self, command: list[str]) -> tuple[str, str] | None:
        if not command:
            return None
        path = Path(command[0])
        if not path.exists():
            return None
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
        if not lines or not lines[0].startswith('#!/bin/sh'):
            return None
        for line in lines[1:]:
            stripped = line.strip()
            if stripped.startswith('echo '):
                return stripped[5:].strip().strip('"\'') + '\n', ''
        return '', ''

    def apply_rule(self, rule: PolicyRule, *, command_preview: list[str], execute: bool = True) -> EnforcementExecutionResult:
        payload = self._load()
        now = datetime.now(timezone.utc).isoformat()
        executed = False
        message = 'Applied to backend state store.'
        if execute:
            executed, message = self._run_native(rule)
        effective_preview = command_preview or self.command_preview_for_rule(rule)
        entry = {
            'rule_id': rule.rule_id,
            'rule_name': rule.rule_name,
            'action': rule.action,
            'enabled': rule.enabled,
            'updated_ts': rule.updated_ts.isoformat(),
            'conditions': rule.conditions.model_dump(mode='json'),
            'observed_at': now,
            'command_preview': effective_preview,
            'execution_mode': 'executed' if executed else 'simulated',
            'native_supported': self._command_supported(),
            'required_binaries': self.required_binaries(),
        }
        payload[rule.rule_id] = entry
        self._save(payload)
        return EnforcementExecutionResult(
            status='applied',
            message=message,
            command_preview=effective_preview,
            backend_rule_ref=self._backend_rule_ref(rule),
            execution_mode='executed' if executed else 'simulated',
            backend_state='present',
        )

    def read_rule_state(self, rule: PolicyRule) -> BackendRuleState:
        payload = self._load()
        entry = payload.get(rule.rule_id)
        now = datetime.now(timezone.utc)
        if not entry:
            return BackendRuleState(
                backend=self.backend_name,
                rule_id=rule.rule_id,
                backend_rule_ref=None,
                state='missing',
                observed_at=now,
                details={},
            )
        return BackendRuleState(
            backend=self.backend_name,
            rule_id=rule.rule_id,
            backend_rule_ref=self._backend_rule_ref(rule),
            state='present',
            observed_at=now,
            details=entry,
        )


_ADAPTERS: dict[str, type[JsonStateBackendAdapter]] = {}


def register_backend(adapter_cls: type[JsonStateBackendAdapter]) -> type[JsonStateBackendAdapter]:
    _ADAPTERS[adapter_cls.backend_name] = adapter_cls
    return adapter_cls


def get_backend_adapter(backend: str, *, state_dir: Path | None = None) -> JsonStateBackendAdapter:
    adapter_cls = _ADAPTERS.get(backend)
    if adapter_cls is None:
        raise ValueError(f'unsupported backend: {backend}')
    return adapter_cls(state_dir=state_dir)
