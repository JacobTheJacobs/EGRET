from __future__ import annotations

from typing import Optional

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.process_identity import ProcessIdentity
from app.models.trust_context_snapshot import TrustContextSnapshot
from app.services.prompting.prompt_selector import PromptSelectionResult, PromptSelector, TrustSnapshot


class PromptReconstructor:
    def __init__(self, selector: Optional[PromptSelector] = None) -> None:
        self.selector = selector or PromptSelector()

    def reconstruct(
        self,
        *,
        connection: ConnectionEvent,
        process: ProcessIdentity,
        destination: Optional[DestinationIdentity],
        matched_verdict: Optional[str],
        trust_snapshot: Optional[TrustContextSnapshot] = None,
    ) -> PromptSelectionResult:
        selector_snapshot = None
        if trust_snapshot:
            selector_snapshot = TrustSnapshot(
                trust_score=trust_snapshot.trust_score,
                drift_score=trust_snapshot.drift_score,
                risky_ble_signature_counter=trust_snapshot.risky_ble_signature_counter,
                rogue_ble_counter_reuse=trust_snapshot.rogue_ble_counter_reuse,
            )
        return self.selector.select(
            connection=connection,
            process=process,
            destination=destination,
            matched_verdict=matched_verdict,
            trust_snapshot=selector_snapshot,
        )
