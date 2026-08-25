from __future__ import annotations

from app.models.policy_decision import PolicyDecision


class DecisionLabeler:
    def label_for_decision(self, decision: PolicyDecision) -> str:
        ttl = decision.expires_at is not None
        if decision.decision_source == 'user_prompt':
            if decision.decision == 'allow':
                return 'prompted_allow_temp' if ttl else 'prompted_allow_perm'
            if decision.decision == 'deny':
                return 'prompted_block_temp' if ttl else 'prompted_block_perm'
            if decision.decision == 'defer':
                return 'deferred'
            return 'prompted_ask'
        if decision.decision_source in {'user_rule', 'admin_rule'}:
            if decision.decision == 'allow':
                return 'auto_allowed_by_rule'
            if decision.decision == 'deny':
                return 'auto_blocked_by_rule'
        if decision.decision_source == 'recommendation':
            return 'later_marked_suspicious' if decision.decision == 'deny' else 'later_marked_benign'
        return 'uncertain'
