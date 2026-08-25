from __future__ import annotations

from app.models.policy_rule import PolicyRule
from app.services.enforcement.backends.base import JsonStateBackendAdapter, register_backend
from app.services.enforcement.native_commands import build_linux_commands


@register_backend
class LinuxBackendAdapter(JsonStateBackendAdapter):
    backend_name = 'linux'

    def required_binaries(self) -> list[str]:
        return ['nft']

    def native_commands_for_rule(self, rule: PolicyRule) -> list[list[str]]:
        return build_linux_commands(rule)
