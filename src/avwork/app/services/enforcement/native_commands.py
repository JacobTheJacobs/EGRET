from __future__ import annotations

from app.models.policy_rule import PolicyRule


def _app_match(rule: PolicyRule) -> str:
    return rule.conditions.process_path or rule.conditions.process_name or 'any'


def _addr_match(rule: PolicyRule) -> str:
    if rule.conditions.remote_ip:
        return rule.conditions.remote_ip
    if rule.conditions.domain:
        return rule.conditions.domain
    if rule.conditions.domain_suffix:
        return f'*.{rule.conditions.domain_suffix}'
    return 'any'


def build_macos_commands(rule: PolicyRule) -> list[list[str]]:
    action = 'block' if rule.action == 'deny' else 'pass'
    target = _addr_match(rule)
    label = f'egret::{rule.rule_id}'
    anchor = f'{action} out quick to {target}'
    return [
        ['pfctl', '-a', label, '-sr'],
        ['pfctl', '-a', label, '-f', '-', anchor],
        ['socketfilterfw', '--add', _app_match(rule)],
    ]


def build_windows_commands(rule: PolicyRule) -> list[list[str]]:
    action = 'Block' if rule.action == 'deny' else 'Allow'
    target = _addr_match(rule)
    app = rule.conditions.process_path or '*'
    return [[
        'powershell', '-NoProfile', '-Command',
        (
            f"New-NetFirewallRule -DisplayName 'Egret {rule.rule_id}' -Direction Outbound "
            f"-Action {action} -Program '{app}' -RemoteAddress '{target}'"
        ),
    ]]


def build_linux_commands(rule: PolicyRule) -> list[list[str]]:
    action = 'drop' if rule.action == 'deny' else 'accept'
    target = rule.conditions.remote_ip or '0.0.0.0/0'
    command = ['nft', 'add', 'rule', 'inet', 'egret', 'outbound', 'ip', 'daddr', target]
    if rule.conditions.remote_port:
        command.extend(['tcp', 'dport', str(rule.conditions.remote_port)])
    command.extend(['counter', action, 'comment', f'Egret {rule.rule_id}'])
    return [command]
