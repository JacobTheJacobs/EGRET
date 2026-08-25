from __future__ import annotations

import json
from pathlib import Path

from app.services.release.signing import sign_file, sign_file_stub, verify_signature


def test_sign_release_writes_sha256_attestation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv('EGRET_RELEASE_SIGNING_KEY', raising=False)
    artifact = tmp_path / 'artifact.zip'
    artifact.write_bytes(b'egret')
    signature = sign_file(artifact)
    assert signature.exists()
    payload = json.loads(signature.read_text(encoding='utf-8'))
    assert payload['algorithm'] == 'sha256-attestation'
    assert payload['sha256'] == payload['signature']
    assert verify_signature(artifact)


def test_sign_release_writes_hmac_signature_when_key_is_configured(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv('EGRET_RELEASE_SIGNING_KEY', 'test-secret')
    monkeypatch.setenv('EGRET_RELEASE_SIGNING_KEY_ID', 'test-key')
    artifact = tmp_path / 'artifact.zip'
    artifact.write_bytes(b'egret')
    signature = sign_file_stub(artifact)
    payload = json.loads(signature.read_text(encoding='utf-8'))
    assert payload['algorithm'] == 'hmac-sha256'
    assert payload['key_id'] == 'test-key'
    assert payload['signature'] != payload['sha256']
    assert verify_signature(artifact)
