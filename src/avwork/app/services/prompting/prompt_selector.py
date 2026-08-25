from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.process_identity import ProcessIdentity


@dataclass(frozen=True)
class TrustSnapshot:
    trust_score: Optional[float] = None
    drift_score: Optional[float] = None
    risky_ble_signature_counter: bool = False
    rogue_ble_counter_reuse: bool = False


@dataclass(frozen=True)
class PromptSelectionResult:
    should_prompt: bool
    recommendation: str
    severity: str
    reasons: list[str] = field(default_factory=list)


class PromptSelector:
    def __init__(
        self,
        *,
        risk_prompt_threshold: float = 0.75,
        suggestion_allow_threshold: float = 0.2,
    ) -> None:
        self.risk_prompt_threshold = risk_prompt_threshold
        self.suggestion_allow_threshold = suggestion_allow_threshold

    def select(
        self,
        *,
        connection: ConnectionEvent,
        process: ProcessIdentity,
        destination: Optional[DestinationIdentity],
        matched_verdict: Optional[str],
        trust_snapshot: Optional[TrustSnapshot] = None,
    ) -> PromptSelectionResult:
        reasons: list[str] = []
        trust_snapshot = trust_snapshot or TrustSnapshot()

        if matched_verdict in {"allow", "deny", "observe_only"}:
            return PromptSelectionResult(
                should_prompt=False,
                recommendation=matched_verdict,
                severity="info",
                reasons=["existing_rule_applies"],
            )

        if process.signer_status in {"unsigned", "revoked"}:
            reasons.append("process_signer_is_untrusted")
        if connection.first_seen_on_asset:
            reasons.append("connection_is_first_seen_on_asset")
        if connection.first_seen_in_fleet:
            reasons.append("connection_is_first_seen_in_fleet")
        if connection.flow_risk_score is not None and connection.flow_risk_score >= self.risk_prompt_threshold:
            reasons.append("flow_risk_score_above_threshold")
        if trust_snapshot.risky_ble_signature_counter:
            reasons.append("risky_ble_signature_counter_context")
        if trust_snapshot.rogue_ble_counter_reuse:
            reasons.append("rogue_ble_counter_reuse_context")
        if destination and destination.matched_domain is None and destination.sni is None:
            reasons.append("destination_name_is_unresolved")

        if reasons:
            severity = "high" if any(
                reason in {
                    "process_signer_is_untrusted",
                    "flow_risk_score_above_threshold",
                    "rogue_ble_counter_reuse_context",
                }
                for reason in reasons
            ) else "medium"
            recommendation = "block" if severity == "high" else "ask"
            return PromptSelectionResult(
                should_prompt=True,
                recommendation=recommendation,
                severity=severity,
                reasons=reasons,
            )

        if connection.rule_suggestion_score is not None and connection.rule_suggestion_score <= self.suggestion_allow_threshold:
            return PromptSelectionResult(
                should_prompt=False,
                recommendation="allow",
                severity="info",
                reasons=["low_rule_suggestion_score"],
            )

        return PromptSelectionResult(
            should_prompt=True,
            recommendation="ask",
            severity="low",
            reasons=["novel_connection_without_rule"],
        )
