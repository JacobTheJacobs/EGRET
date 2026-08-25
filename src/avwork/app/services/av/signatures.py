from __future__ import annotations

from app.services.av.content_unpack import load_active_pack

EICAR_MARKER = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

KNOWN_SIGNATURES = {
    'eicar_test_file': EICAR_MARKER,
}


def match_content_signature(content: bytes) -> tuple[str | None, str | None]:
    text = content.decode('utf-8', errors='ignore')
    if EICAR_MARKER in text:
        return 'EICAR-Test-File', 'Test.EICAR'
    pack = load_active_pack()
    for item in pack.get('signatures', []):
        marker = item.get('marker')
        if marker and marker in text:
            return item.get('signature_name', 'Content-Pack-Signature'), item.get('family_name', 'Custom.Threat')
    return None, None
