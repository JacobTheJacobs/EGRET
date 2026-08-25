from __future__ import annotations

from typing import Iterable, Optional

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.policy_rule import PolicyRule
from app.models.process_identity import ProcessIdentity
from app.services.policy.evaluator import EvaluationContext, EvaluationResult, PolicyEvaluator


class VerdictReconstructor:
    def __init__(self, evaluator: Optional[PolicyEvaluator] = None) -> None:
        self.evaluator = evaluator or PolicyEvaluator()

    def reconstruct(
        self,
        *,
        connection: ConnectionEvent,
        process: ProcessIdentity,
        destination: Optional[DestinationIdentity],
        rules: Iterable[PolicyRule],
    ) -> EvaluationResult:
        return self.evaluator.evaluate(
            EvaluationContext(
                connection=connection,
                process=process,
                destination=destination,
            ),
            rules,
        )
