from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.config.env import getenv_compat


def get_content_dir() -> Path:
    raw = getenv_compat('EGRET_CONTENT_DIR', 'EDGE_NET_GUARDIAN_CONTENT_DIR')
    if raw:
        path = Path(raw)
    else:
        path = Path(__file__).resolve().parents[3] / 'runtime' / 'content'
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_active_pack_path() -> Path:
    return get_content_dir() / 'active-pack.json'


def load_active_pack() -> dict[str, Any]:
    path = get_active_pack_path()
    if not path.exists():
        return {
            'version': 'builtin-1',
            'signatures': [],
            'malicious_hashes': {},
            'trusted_signers': [],
            'malicious_domains': [],
            'phishing_domains': [],
        }
    return json.loads(path.read_text(encoding='utf-8'))


def install_content_pack(pack: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        'version': pack.get('version', 'custom'),
        'signatures': pack.get('signatures', []),
        'malicious_hashes': pack.get('malicious_hashes', {}),
        'trusted_signers': pack.get('trusted_signers', []),
        'malicious_domains': pack.get('malicious_domains', []),
        'phishing_domains': pack.get('phishing_domains', []),
    }
    get_active_pack_path().write_text(json.dumps(normalized, indent=2, sort_keys=True), encoding='utf-8')
    return normalized
