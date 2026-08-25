from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

from app.models.policy_rule import PolicyConditions, PolicyRule
from app.services.policy.specificity import score_conditions


@dataclass(frozen=True)
class RuleConflict:
    left_rule_id: str
    right_rule_id: str
    conflict_type: str
    summary: str


class RuleConflictDetector:
    def detect(self, rules: list[PolicyRule]) -> list[RuleConflict]:
        conflicts: list[RuleConflict] = []
        active_rules = [rule for rule in rules if rule.enabled]
        for left, right in combinations(active_rules, 2):
            if not self._overlaps(left.conditions, right.conditions):
                continue
            if left.action != right.action:
                conflicts.append(
                    RuleConflict(
                        left_rule_id=left.rule_id,
                        right_rule_id=right.rule_id,
                        conflict_type='overlap_action_conflict',
                        summary='Overlapping rules resolve to different actions.',
                    )
                )
                continue
            more_specific, less_specific = self._shadow_pair(left, right)
            if more_specific and less_specific:
                conflicts.append(
                    RuleConflict(
                        left_rule_id=more_specific.rule_id,
                        right_rule_id=less_specific.rule_id,
                        conflict_type='shadowed_rule',
                        summary='A more specific rule is likely to shadow a broader rule with the same action.',
                    )
                )
        return conflicts

    def _shadow_pair(self, left: PolicyRule, right: PolicyRule) -> tuple[PolicyRule | None, PolicyRule | None]:
        left_score = score_conditions(left.conditions)
        right_score = score_conditions(right.conditions)
        if left.action != right.action:
            return (None, None)
        if left_score == right_score:
            return (None, None)
        if left_score > right_score and self._contains(left.conditions, right.conditions):
            return (left, right)
        if right_score > left_score and self._contains(right.conditions, left.conditions):
            return (right, left)
        return (None, None)

    def _contains(self, more_specific: PolicyConditions, broader: PolicyConditions) -> bool:
        for field_name in PolicyConditions.model_fields.keys():
            broad_value = getattr(broader, field_name)
            specific_value = getattr(more_specific, field_name)
            if broad_value in (None, '', []):
                continue
            if specific_value != broad_value:
                return False
        return True

    def _overlaps(self, left: PolicyConditions, right: PolicyConditions) -> bool:
        for field_name in PolicyConditions.model_fields.keys():
            left_value = getattr(left, field_name)
            right_value = getattr(right, field_name)
            if left_value in (None, '', []) or right_value in (None, '', []):
                continue
            if field_name == 'domain_suffix_not_in':
                # Conservative overlap handling: different exclusion lists still overlap.
                continue
            if left_value != right_value:
                return False
        return True
