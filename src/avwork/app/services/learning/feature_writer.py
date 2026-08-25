from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.policy_decision import PolicyDecision
from app.models.process_identity import ProcessIdentity
from app.models.training_feedback_event import TrainingFeedbackEvent
from app.models.trust_context_snapshot import TrustContextSnapshot
from app.services.learning.labeler import DecisionLabeler


@dataclass(frozen=True)
class FeatureBundle:
    connection: dict
    process: dict
    destination: Optional[dict]
    trust_context: Optional[dict]
    policy_decision: dict


class TrainingFeatureWriter:
    def __init__(self, labeler: Optional[DecisionLabeler] = None) -> None:
        self.labeler = labeler or DecisionLabeler()

    def build_feedback_event(
        self,
        *,
        connection: ConnectionEvent,
        process: ProcessIdentity,
        destination: Optional[DestinationIdentity],
        decision: PolicyDecision,
        trust_snapshot: Optional[TrustContextSnapshot] = None,
        now: Optional[datetime] = None,
    ) -> TrainingFeedbackEvent:
        bundle = FeatureBundle(
            connection=connection.model_dump(mode='json', exclude_none=True),
            process=process.model_dump(mode='json', exclude_none=True),
            destination=destination.model_dump(mode='json', exclude_none=True) if destination else None,
            trust_context=trust_snapshot.model_dump(mode='json', exclude_none=True) if trust_snapshot else None,
            policy_decision=decision.model_dump(mode='json', exclude_none=True),
        )
        serialized = json.dumps(bundle.__dict__, sort_keys=True, separators=(',', ':'))
        features_hash = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
        return TrainingFeedbackEvent(
            training_feedback_event_id=f'tf_{uuid4().hex[:12]}',
            connection_id=connection.connection_id,
            label=self.labeler.label_for_decision(decision),
            label_source=decision.decision_source,
            features_hash=features_hash,
            generated_ts=now or datetime.now(timezone.utc),
        )

    def supersede_event(self, prior: TrainingFeedbackEvent, replacement: TrainingFeedbackEvent) -> TrainingFeedbackEvent:
        return prior.model_copy(update={'superseded_by': replacement.training_feedback_event_id})
