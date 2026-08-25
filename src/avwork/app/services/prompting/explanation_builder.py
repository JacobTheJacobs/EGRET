from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.process_identity import ProcessIdentity
from app.services.enrichment.certificate_summary import summarize_certificate
from app.services.prompting.prompt_selector import PromptSelectionResult, TrustSnapshot


@dataclass(frozen=True)
class ExplanationPayload:
    headline: str
    short_rationale: str
    confidence_score: float
    user_factors: list[str] = field(default_factory=list)
    machine_factors: list[str] = field(default_factory=list)


class ExplanationBuilder:
    def build(
        self,
        *,
        connection: ConnectionEvent,
        process: ProcessIdentity,
        destination: Optional[DestinationIdentity],
        selection: PromptSelectionResult,
        trust_snapshot: Optional[TrustSnapshot] = None,
    ) -> ExplanationPayload:
        trust_snapshot = trust_snapshot or TrustSnapshot()
        destination_name = None
        if destination:
            destination_name = destination.matched_domain or destination.sni or destination.ip
        else:
            destination_name = connection.remote_ip

        protocol = connection.protocol or connection.transport.upper()
        headline = f"{process.process_name} connected to {destination_name} over {protocol}"

        user_factors: list[str] = []
        machine_factors: list[str] = []

        if process.signer_name:
            signer_phrase = f"Signed by {process.signer_name}"
            if process.signer_status:
                signer_phrase += f" ({process.signer_status})"
            user_factors.append(signer_phrase)
            machine_factors.append(f"signer_status={process.signer_status or 'unknown'}")
        elif process.signer_status:
            user_factors.append(f"Signer status: {process.signer_status}")
            machine_factors.append(f"signer_status={process.signer_status}")

        if connection.first_seen_on_asset is True:
            user_factors.append("First time this connection has been seen on this asset")
            machine_factors.append("first_seen_on_asset=true")
        elif connection.prevalence_on_asset is not None:
            user_factors.append("Destination has been seen before on this asset")
            machine_factors.append(f"prevalence_on_asset={connection.prevalence_on_asset:.3f}")

        if destination and (destination.matched_domain or destination.sni):
            user_factors.append(f"Resolved destination: {destination.matched_domain or destination.sni}")
            machine_factors.append(f"destination_name={destination.matched_domain or destination.sni}")

        if destination:
            cert_summary = summarize_certificate(
                subject=destination.certificate_subject,
                issuer=destination.certificate_issuer,
                fingerprint=destination.certificate_fingerprint,
            )
            if cert_summary != "No certificate details available":
                user_factors.append(cert_summary)
                machine_factors.append(
                    f"certificate_present={bool(destination.certificate_fingerprint or destination.certificate_subject)}"
                )

        if trust_snapshot.risky_ble_signature_counter:
            user_factors.append("Wireless trust context is degraded by risky BLE signature counter behavior")
            machine_factors.append("risky_ble_signature_counter=true")
        if trust_snapshot.rogue_ble_counter_reuse:
            user_factors.append("Wireless trust context is degraded by BLE counter reuse")
            machine_factors.append("rogue_ble_counter_reuse=true")
        if trust_snapshot.trust_score is not None:
            machine_factors.append(f"trust_score={trust_snapshot.trust_score:.3f}")
        if connection.flow_risk_score is not None:
            machine_factors.append(f"flow_risk_score={connection.flow_risk_score:.3f}")

        rationale = self._build_rationale(selection)
        confidence_score = self._compute_confidence(
            process=process,
            connection=connection,
            destination=destination,
            selection=selection,
            trust_snapshot=trust_snapshot,
        )
        return ExplanationPayload(
            headline=headline,
            short_rationale=rationale,
            confidence_score=confidence_score,
            user_factors=user_factors,
            machine_factors=machine_factors,
        )

    def _build_rationale(self, selection: PromptSelectionResult) -> str:
        if selection.recommendation == "block":
            return "The connection is novel or risky enough to justify a blocking prompt."
        if selection.recommendation == "allow":
            return "The connection looks routine enough to allow without interrupting the user."
        return "The connection is not clearly benign or clearly risky, so the app should ask the user."

    def _compute_confidence(
        self,
        *,
        process: ProcessIdentity,
        connection: ConnectionEvent,
        destination: Optional[DestinationIdentity],
        selection: PromptSelectionResult,
        trust_snapshot: TrustSnapshot,
    ) -> float:
        score = 0.5
        if process.signer_status == "trusted":
            score += 0.15
        if process.signer_status in {"unsigned", "revoked"}:
            score -= 0.2
        if destination and (destination.matched_domain or destination.sni):
            score += 0.1
        if connection.first_seen_on_asset:
            score -= 0.05
        if connection.flow_risk_score is not None:
            score += max(-0.25, min(0.25, 0.25 - connection.flow_risk_score / 2))
        if trust_snapshot.risky_ble_signature_counter:
            score -= 0.05
        if trust_snapshot.rogue_ble_counter_reuse:
            score -= 0.1
        if selection.severity == "high":
            score += 0.05
        return round(max(0.0, min(0.99, score)), 3)
