from __future__ import annotations

from app.models.policy_rule import PolicyRule
from app.services.enforcement.backends.base import JsonStateBackendAdapter, register_backend
from app.services.enforcement.native_commands import build_windows_commands


@register_backend
class WindowsBackendAdapter(JsonStateBackendAdapter):
    backend_name = 'windows'

    def required_binaries(self) -> list[str]:
        return ['powershell']

    def native_commands_for_rule(self, rule: PolicyRule) -> list[list[str]]:
        return build_windows_commands(rule)
