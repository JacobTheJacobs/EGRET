from __future__ import annotations

import platform
from dataclasses import dataclass

from app.models.policy_rule import PolicyRule


@dataclass(frozen=True)
class EnforcementPlan:
    backend: str
    command_preview: list[str]
    target_summary: str


def default_backend() -> str:
    system = platform.system().lower()
    if system == 'darwin':
        return 'macos'
    if system == 'windows':
        return 'windows'
    return 'linux'


def _summary(rule: PolicyRule) -> str:
    parts: list[str] = []
    c = rule.conditions
    if c.process_name:
        parts.append(f'process={c.process_name}')
    if c.domain:
        parts.append(f'domain={c.domain}')
    if c.domain_suffix:
        parts.append(f'domain_suffix={c.domain_suffix}')
    if c.remote_ip:
        parts.append(f'ip={c.remote_ip}')
    if c.remote_port:
        parts.append(f'port={c.remote_port}')
    if c.network_zone:
        parts.append(f'zone={c.network_zone}')
    return ', '.join(parts) if parts else 'any outbound target'


def compile_rule_for_backend(rule: PolicyRule, backend: str) -> EnforcementPlan:
    action = 'block' if rule.action == 'deny' else 'allow'
    summary = _summary(rule)
    if backend == 'macos':
        cmds = [
            f'# network extension hook for {rule.rule_id}',
            f'/usr/libexec/networkextensionctl apply --action {action} --match "{summary}"',
        ]
    elif backend == 'windows':
        cmds = [
            f'# WFP/Firewall hook for {rule.rule_id}',
            f"New-NetFirewallRule -DisplayName '{rule.rule_name}' -Direction Outbound -Action {action.title()} -Program '{rule.conditions.process_path or '*'}'",
        ]
    elif backend == 'linux':
        cmds = [
            f'# nftables hook for {rule.rule_id}',
            f'nft add rule inet egret outbound meta skuid 0 counter {action}',
            f'# target: {summary}',
        ]
    else:
        raise ValueError('unsupported backend')
    return EnforcementPlan(backend=backend, command_preview=cmds, target_summary=summary)
