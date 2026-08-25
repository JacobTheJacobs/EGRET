from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from app.services.av.reputation import file_reputation, url_reputation
from app.services.av.signatures import match_content_signature
from app.services.av.updater import ContentUpdaterService


def test_content_pack_install_changes_signature_and_reputation(tmp_path: Path) -> None:
    os.environ['EDGE_NET_GUARDIAN_CONTENT_DIR'] = str(tmp_path)
    updater = ContentUpdaterService()
    payload = {
        'version': 'pack-1',
        'signatures': [{'marker': 'CUSTOM-THREAT-MARKER', 'signature_name': 'Custom.Signature', 'family_name': 'Custom.Family'}],
        'malicious_hashes': {
            hashlib.sha256(b'custom-malware').hexdigest(): {'signature_name': 'Custom.Hash', 'family_name': 'Custom.HashFamily'}
        },
        'trusted_signers': ['Trusted Labs'],
        'malicious_domains': ['bad-custom.example'],
        'phishing_domains': ['phish-custom.example'],
    }
    encoded = base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')
    updater.install_base64_json(encoded)

    assert updater.status().version == 'pack-1'
    sig_name, family = match_content_signature(b'hello CUSTOM-THREAT-MARKER world')
    assert sig_name == 'Custom.Signature'
    assert family == 'Custom.Family'
    rep = file_reputation(hashlib.sha256(b'custom-malware').hexdigest())
    assert rep is not None and rep.signature_name == 'Custom.Hash'
    assert url_reputation('bad-custom.example')[1] == 'block'
    assert url_reputation('phish-custom.example')[0] == 'phishing'
