from __future__ import annotations

from dataclasses import dataclass

from app.storage.repositories.interfaces import MalwareVerdictRepository, QuarantineRepository


@dataclass(frozen=True)
class TuningSummary:
    malicious_verdicts: int
    suspicious_verdicts: int
    restored_quarantine: int
    deleted_quarantine: int
    estimated_false_positive_rate: float


class FalsePositiveTuningService:
    def __init__(self, *, verdicts: MalwareVerdictRepository, quarantine: QuarantineRepository) -> None:
        self.verdicts = verdicts
        self.quarantine = quarantine

    def summary(self, *, asset_id: str | None = None) -> TuningSummary:
        verdicts = self.verdicts.list_verdicts(asset_id=asset_id, malicious_only=False)
        malicious = sum(1 for item in verdicts if item.verdict == 'malicious')
        suspicious = sum(1 for item in verdicts if item.verdict == 'suspicious')
        quarantine = self.quarantine.list_records(asset_id=asset_id)
        restored = sum(1 for item in quarantine if item.restored)
        deleted = sum(1 for item in quarantine if item.deleted)
        denominator = max(1, malicious + suspicious)
        estimated_fp = restored / denominator
        return TuningSummary(
            malicious_verdicts=malicious,
            suspicious_verdicts=suspicious,
            restored_quarantine=restored,
            deleted_quarantine=deleted,
            estimated_false_positive_rate=round(estimated_fp, 4),
        )
