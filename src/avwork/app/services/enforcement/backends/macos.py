from __future__ import annotations

from app.models.policy_rule import PolicyRule
from app.services.enforcement.backends.base import JsonStateBackendAdapter, register_backend
from app.services.enforcement.native_commands import build_macos_commands


@register_backend
class MacOSBackendAdapter(JsonStateBackendAdapter):
    backend_name = 'macos'

    def required_binaries(self) -> list[str]:
        return ['pfctl', 'socketfilterfw']

    def native_commands_for_rule(self, rule: PolicyRule) -> list[list[str]]:
        return build_macos_commands(rule)
