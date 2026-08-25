from datetime import datetime, timezone

from app.models.policy_rule import PolicyConditions, PolicyRule
from app.services.enforcement.compiler import compile_rule_for_backend


def make_rule() -> PolicyRule:
    now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    return PolicyRule(
        rule_id='r_1',
        rule_name='Block Updater invalid',
        enabled=True,
        priority=100,
        source='user',
        action='deny',
        created_ts=now,
        updated_ts=now,
        conditions=PolicyConditions(process_name='Updater', domain_suffix='.invalid', network_zone='public_internet'),
    )


def test_compile_rule_for_each_backend() -> None:
    rule = make_rule()
    mac = compile_rule_for_backend(rule, 'macos')
    win = compile_rule_for_backend(rule, 'windows')
    linux = compile_rule_for_backend(rule, 'linux')
    assert any('networkextensionctl' in cmd for cmd in mac.command_preview)
    assert any('New-NetFirewallRule' in cmd for cmd in win.command_preview)
    assert any('nft add rule' in cmd for cmd in linux.command_preview)
