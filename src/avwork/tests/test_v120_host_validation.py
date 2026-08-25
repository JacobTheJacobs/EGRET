from __future__ import annotations

import os
from pathlib import Path

from app.services.enforcement.host_validation import validate_backend_host


def test_host_validation_reports_missing_binaries_when_disabled(tmp_path: Path) -> None:
    os.environ['EDGE_NET_GUARDIAN_ENABLE_NATIVE_EXECUTION'] = '0'
    result = validate_backend_host('linux')
    assert result.backend == 'linux'
    assert result.command_preview
    checks = {check.name: check for check in result.checks}
    assert checks['native_execution_enabled'].passed is False
    assert result.ready_for_native_validation is False


def test_host_validation_can_be_ready_with_fake_binary(monkeypatch, tmp_path: Path) -> None:
    fake_nft = tmp_path / 'nft'
    fake_nft.write_text('#!/bin/sh\necho nft-ok\n', encoding='utf-8')
    fake_nft.chmod(0o755)
    monkeypatch.setenv('PATH', f"{tmp_path}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv('EDGE_NET_GUARDIAN_ENABLE_NATIVE_EXECUTION', '1')
    result = validate_backend_host('linux')
    assert result.ready_for_native_validation is True
