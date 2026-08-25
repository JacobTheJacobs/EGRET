from __future__ import annotations

from app.services.av.cleanup import CleanupAutomationService
from app.services.av.on_access import OnAccessProtectionService
from app.services.av.scanner import ScannerService
from app.storage.repositories.sqlite import SqliteRepositories


def test_on_access_write_and_cleanup() -> None:
    repos = SqliteRepositories(':memory:')
    scanner = ScannerService(file_events=repos.files, verdicts=repos.malware_verdicts, quarantine=repos.quarantine)
    service = OnAccessProtectionService(scanner, protected_roots=['/Users'])
    eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    decision = service.scan_write(asset_id='asset-1', session_id='session-1', path='/Users/me/Documents/eicar.com', content=eicar, signer_status='unsigned')
    assert decision.action == 'quarantine'
    assert decision.outcome.quarantine_record is not None

    actions = CleanupAutomationService(quarantine=repos.quarantine, remediation=repos.remediation_actions).plan_for_quarantine(decision.outcome.quarantine_record)
    assert len(actions) == 2
    assert {item.action_kind for item in actions} == {'remove_persistence', 'delete_quarantined_copy'}
