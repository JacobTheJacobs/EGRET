from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from app.services.av.content_unpack import install_content_pack, load_active_pack, get_active_pack_path


@dataclass(frozen=True)
class ContentPackStatus:
    version: str
    installed: bool
    path: str
    signatures: int
    malicious_hashes: int
    malicious_domains: int
    phishing_domains: int
    updated_at: str | None


class ContentUpdaterService:
    def status(self) -> ContentPackStatus:
        pack = load_active_pack()
        path = get_active_pack_path()
        updated_at = None
        if path.exists():
            updated_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
        return ContentPackStatus(
            version=str(pack.get('version', 'builtin-1')),
            installed=path.exists(),
            path=str(path),
            signatures=len(pack.get('signatures', [])),
            malicious_hashes=len(pack.get('malicious_hashes', {})),
            malicious_domains=len(pack.get('malicious_domains', [])),
            phishing_domains=len(pack.get('phishing_domains', [])),
            updated_at=updated_at,
        )

    def install_json(self, payload: dict) -> dict:
        return install_content_pack(payload)

    def install_base64_json(self, content_base64: str) -> dict:
        decoded = base64.b64decode(content_base64.encode('utf-8')).decode('utf-8')
        payload = json.loads(decoded)
        return self.install_json(payload)
