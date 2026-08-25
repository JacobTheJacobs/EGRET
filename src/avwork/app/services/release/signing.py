from __future__ import annotations

import hmac
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _signature_payload(path: Path, digest: str) -> dict:
    signing_key = os.getenv('EGRET_RELEASE_SIGNING_KEY')
    payload = {
        'artifact': path.name,
        'sha256': digest,
        'signed_at': datetime.now(timezone.utc).isoformat(),
    }
    if signing_key:
        key_id = os.getenv('EGRET_RELEASE_SIGNING_KEY_ID', 'local')
        payload.update(
            {
                'algorithm': 'hmac-sha256',
                'key_id': key_id,
                'signature': hmac.new(signing_key.encode('utf-8'), digest.encode('utf-8'), hashlib.sha256).hexdigest(),
            }
        )
    else:
        payload.update(
            {
                'algorithm': 'sha256-attestation',
                'key_id': None,
                'signature': digest,
            }
        )
    return payload


def sign_file(path: Path) -> Path:
    digest = _sha256(path)
    signature_path = path.with_suffix(path.suffix + '.sig')
    signature_path.write_text(json.dumps(_signature_payload(path, digest), indent=2, sort_keys=True), encoding='utf-8')
    return signature_path


def verify_signature(path: Path, signature_path: Path | None = None) -> bool:
    signature_path = signature_path or path.with_suffix(path.suffix + '.sig')
    payload = json.loads(signature_path.read_text(encoding='utf-8'))
    digest = _sha256(path)
    if payload.get('sha256') != digest:
        return False
    algorithm = payload.get('algorithm')
    if algorithm == 'sha256-attestation':
        return payload.get('signature') == digest
    if algorithm == 'hmac-sha256':
        signing_key = os.getenv('EGRET_RELEASE_SIGNING_KEY')
        if not signing_key:
            return False
        expected = hmac.new(signing_key.encode('utf-8'), digest.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac.compare_digest(str(payload.get('signature')), expected)
    return False


def sign_file_stub(path: Path) -> Path:
    return sign_file(path)
