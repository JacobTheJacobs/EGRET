from __future__ import annotations

from datetime import datetime, timezone

from app.models.policy_rule import PolicyConditions, PolicyRule
from app.services.enforcement.backends import get_backend_adapter


def make_rule() -> PolicyRule:
    now = datetime.now(timezone.utc)
    return PolicyRule(
        rule_id='r_native',
        rule_name='Block Test',
        enabled=True,
        priority=100,
        source='user',
        action='deny',
        created_ts=now,
        updated_ts=now,
        conditions=PolicyConditions(process_name='curl', remote_ip='1.2.3.4', remote_port=443),
    )


def test_macos_command_preview_contains_pf_or_socketfilterfw(tmp_path):
    adapter = get_backend_adapter('macos', state_dir=tmp_path)
    preview = adapter.command_preview_for_rule(make_rule())
    assert any('pfctl' in cmd or 'socketfilterfw' in cmd for cmd in preview)


def test_windows_command_preview_contains_netfirewall(tmp_path):
    adapter = get_backend_adapter('windows', state_dir=tmp_path)
    preview = adapter.command_preview_for_rule(make_rule())
    assert any('New-NetFirewallRule' in cmd for cmd in preview)


def test_linux_command_preview_contains_nft(tmp_path):
    adapter = get_backend_adapter('linux', state_dir=tmp_path)
    preview = adapter.command_preview_for_rule(make_rule())
    assert any(cmd.startswith('nft ') for cmd in preview)
