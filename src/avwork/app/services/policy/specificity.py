from __future__ import annotations

from app.models.policy_rule import PolicyConditions, PolicyRule


FIELD_WEIGHTS = {
    "process_name": 30,
    "process_path": 35,
    "signer_name": 20,
    "signer_status": 10,
    "domain": 30,
    "domain_suffix": 25,
    "remote_ip": 30,
    "remote_port": 15,
    "protocol": 10,
    "network_zone": 10,
}


def score_conditions(conditions: PolicyConditions) -> int:
    score = 0
    for field_name, weight in FIELD_WEIGHTS.items():
        value = getattr(conditions, field_name)
        if value not in (None, "", []):
            score += weight
    if conditions.domain_suffix_not_in:
        score += 10
    return score


def compare_rules(rule: PolicyRule) -> tuple[int, int, int]:
    """Higher tuple wins."""
    action_bias = 1 if rule.action == "deny" else 0
    return (score_conditions(rule.conditions), rule.priority, action_bias)
