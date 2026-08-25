from __future__ import annotations

import base64

from app.services.av.scanner import ScannerService
from app.storage.repositories.sqlite import SqliteRepositories


def test_scanner_detects_eicar_and_quarantines() -> None:
    repos = SqliteRepositories(':memory:')
    content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    outcome = ScannerService(file_events=repos.files, verdicts=repos.malware_verdicts, quarantine=repos.quarantine).scan_bytes(
        asset_id='asset-1',
        session_id='session-1',
        path='/Users/me/Downloads/eicar.com',
        content=content,
        origin_kind='download',
        signer_status='unsigned',
    )
    assert outcome.verdict.verdict == 'malicious'
    assert outcome.verdict.signature_name == 'EICAR-Test-File'
    assert outcome.quarantine_record is not None
    assert outcome.quarantine_record.original_path.endswith('eicar.com')


def test_scanner_allowlists_trusted_signer_when_no_bad_signal() -> None:
    repos = SqliteRepositories(':memory:')
    outcome = ScannerService(file_events=repos.files, verdicts=repos.malware_verdicts, quarantine=repos.quarantine).scan_bytes(
        asset_id='asset-1',
        session_id='session-1',
        path='/Applications/Safari.app/Contents/MacOS/Safari',
        content=b'normal binary content',
        signer_name='Apple',
        signer_status='trusted',
        event_kind='execute',
    )
    assert outcome.verdict.verdict == 'clean'
    assert outcome.verdict.verdict_source == 'allowlist'
    assert outcome.quarantine_record is None
