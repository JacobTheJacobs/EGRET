from __future__ import annotations

from typing import Optional

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.policy_decision import PolicyDecision
from app.models.process_identity import ProcessIdentity
from app.models.trust_context_snapshot import TrustContextSnapshot
from app.services.learning.feature_writer import TrainingFeatureWriter
from app.services.prompting.explanation_builder import ExplanationBuilder, ExplanationPayload
from app.services.prompting.prompt_selector import PromptSelectionResult


class ReplayExporter:
    def __init__(self, feature_writer: Optional[TrainingFeatureWriter] = None, explanation_builder: Optional[ExplanationBuilder] = None) -> None:
        self.feature_writer = feature_writer or TrainingFeatureWriter()
        self.explanation_builder = explanation_builder or ExplanationBuilder()

    def export(
        self,
        *,
        connection: ConnectionEvent,
        process: ProcessIdentity,
        destination: Optional[DestinationIdentity],
        decision: PolicyDecision,
        selection: PromptSelectionResult,
        trust_snapshot: Optional[TrustContextSnapshot] = None,
    ) -> dict:
        feedback = self.feature_writer.build_feedback_event(
            connection=connection,
            process=process,
            destination=destination,
            decision=decision,
            trust_snapshot=trust_snapshot,
        )
        explanation = self.explanation_builder.build(
            connection=connection,
            process=process,
            destination=destination,
            selection=selection,
            trust_snapshot=trust_snapshot,
        )
        return {
            'label': feedback.label,
            'label_source': feedback.label_source,
            'features_hash': feedback.features_hash,
            'explanation': explanation.__dict__,
        }
