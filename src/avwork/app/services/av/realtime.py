from __future__ import annotations

from dataclasses import dataclass

from app.models.behavior_alert import BehaviorAlert
from app.models.web_verdict import WebVerdict
from app.services.av.scanner import ScanOutcome, ScannerService
from app.services.behavior.detector import BehaviorDetectorService, BehaviorObservation
from app.services.web.url_reputation import UrlReputationService
from app.storage.repositories.interfaces import BehaviorAlertRepository, FileEventRepository, MalwareVerdictRepository, QuarantineRepository, WebVerdictRepository


@dataclass
class RealtimeProtectionOutcome:
    scan: ScanOutcome
    web_verdict: WebVerdict | None = None
    behavior_alert: BehaviorAlert | None = None


class RealtimeProtectionService:
    def __init__(
        self,
        *,
        file_events: FileEventRepository,
        verdicts: MalwareVerdictRepository,
        quarantine: QuarantineRepository,
        web_verdicts: WebVerdictRepository,
        behavior_alerts: BehaviorAlertRepository,
    ) -> None:
        self.scanner = ScannerService(file_events=file_events, verdicts=verdicts, quarantine=quarantine)
        self.web = UrlReputationService(web_verdicts)
        self.behavior = BehaviorDetectorService(behavior_alerts)

    def scan_download(
        self,
        *,
        asset_id: str,
        session_id: str,
        path: str,
        url: str,
        content: bytes,
        process_identity_id: str | None = None,
        process_name: str | None = None,
        signer_name: str | None = None,
        signer_status: str | None = None,
        quarantine_on_malicious: bool = True,
    ) -> RealtimeProtectionOutcome:
        web_verdict = self.web.check(asset_id=asset_id, url=url, process_identity_id=process_identity_id)
        scan = self.scanner.scan_bytes(
            asset_id=asset_id,
            session_id=session_id,
            path=path,
            content=content,
            process_identity_id=process_identity_id,
            signer_name=signer_name,
            signer_status=signer_status,
            origin_kind='download',
            origin_source=url,
            event_kind='write',
            quarantine_on_malicious=quarantine_on_malicious,
        )
        alert = None
        if web_verdict.verdict in {'block', 'warn'} or scan.verdict.verdict in {'suspicious', 'malicious'}:
            alert = self.behavior.evaluate(BehaviorObservation(
                asset_id=asset_id,
                session_id=session_id,
                process_identity_id=process_identity_id,
                process_name=process_name,
                signer_status=signer_status,
                origin_kind='download',
                file_verdict=scan.verdict.verdict,
                indicators={'download_url': url, 'web_verdict': web_verdict.verdict, 'web_category': web_verdict.category},
            ))
        return RealtimeProtectionOutcome(scan=scan, web_verdict=web_verdict, behavior_alert=alert)

    def scan_execute(
        self,
        *,
        asset_id: str,
        session_id: str,
        path: str,
        content: bytes,
        process_identity_id: str | None = None,
        process_name: str | None = None,
        parent_process_name: str | None = None,
        signer_name: str | None = None,
        signer_status: str | None = None,
        origin_kind: str | None = None,
        network_destination: str | None = None,
        quarantine_on_malicious: bool = True,
    ) -> RealtimeProtectionOutcome:
        scan = self.scanner.scan_bytes(
            asset_id=asset_id,
            session_id=session_id,
            path=path,
            content=content,
            process_identity_id=process_identity_id,
            signer_name=signer_name,
            signer_status=signer_status,
            origin_kind=origin_kind,
            origin_source=network_destination,
            event_kind='execute',
            quarantine_on_malicious=quarantine_on_malicious,
        )
        alert = self.behavior.evaluate(BehaviorObservation(
            asset_id=asset_id,
            session_id=session_id,
            process_identity_id=process_identity_id,
            process_name=process_name,
            parent_process_name=parent_process_name,
            signer_status=signer_status,
            origin_kind=origin_kind,
            file_verdict=scan.verdict.verdict,
            network_destination=network_destination,
            indicators={'path': path},
        ))
        return RealtimeProtectionOutcome(scan=scan, web_verdict=None, behavior_alert=alert)
