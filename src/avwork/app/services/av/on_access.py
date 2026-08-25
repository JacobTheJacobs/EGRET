from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.services.av.scanner import ScanOutcome, ScannerService


@dataclass(frozen=True)
class OnAccessDecision:
    mode: str
    action: str
    reason: str
    outcome: ScanOutcome


class OnAccessProtectionService:
    def __init__(self, scanner: ScannerService, protected_roots: list[str] | None = None) -> None:
        self.scanner = scanner
        self.protected_roots = protected_roots or ['/Users', '/home', '/var/data']

    def _path_is_protected(self, path: str) -> bool:
        normalized = Path(path).as_posix()
        return any(normalized.startswith(root) for root in self.protected_roots)

    def scan_write(self, *, asset_id: str, session_id: str, path: str, content: bytes, **kwargs) -> OnAccessDecision:
        outcome = self.scanner.scan_bytes(
            asset_id=asset_id,
            session_id=session_id,
            path=path,
            content=content,
            event_kind='write',
            **kwargs,
        )
        if outcome.verdict.verdict == 'malicious':
            return OnAccessDecision(mode='write', action='quarantine', reason='malicious_write_blocked', outcome=outcome)
        if self._path_is_protected(path) and outcome.verdict.verdict == 'suspicious':
            return OnAccessDecision(mode='write', action='block', reason='protected_folder_suspicious_write', outcome=outcome)
        return OnAccessDecision(mode='write', action='allow', reason='clean_or_low_risk_write', outcome=outcome)

    def scan_execute(self, *, asset_id: str, session_id: str, path: str, content: bytes, **kwargs) -> OnAccessDecision:
        outcome = self.scanner.scan_bytes(
            asset_id=asset_id,
            session_id=session_id,
            path=path,
            content=content,
            event_kind='execute',
            **kwargs,
        )
        if outcome.verdict.verdict == 'malicious':
            return OnAccessDecision(mode='execute', action='quarantine', reason='malicious_execute_blocked', outcome=outcome)
        if outcome.verdict.verdict == 'suspicious':
            return OnAccessDecision(mode='execute', action='block', reason='suspicious_execute_requires_review', outcome=outcome)
        return OnAccessDecision(mode='execute', action='allow', reason='execute_allowed', outcome=outcome)
