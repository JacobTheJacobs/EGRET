from __future__ import annotations

from dataclasses import asdict

from app.services.prompting.explanation_builder import ExplanationBuilder
from app.services.prompting.prompt_selector import PromptSelector, TrustSnapshot
from app.storage.repositories.interfaces import (
    ConnectionRepository,
    DecisionRepository,
    DestinationIdentityRepository,
    ProcessIdentityRepository,
    RuleRepository,
    TrustSnapshotRepository,
)


class ConnectionDetailsService:
    def __init__(
        self,
        *,
        connections: ConnectionRepository,
        processes: ProcessIdentityRepository,
        destinations: DestinationIdentityRepository,
        decisions: DecisionRepository,
        rules: RuleRepository,
        trust: TrustSnapshotRepository,
        prompt_selector: PromptSelector | None = None,
        explanation_builder: ExplanationBuilder | None = None,
    ) -> None:
        self.connections = connections
        self.processes = processes
        self.destinations = destinations
        self.decisions = decisions
        self.rules = rules
        self.trust = trust
        self.prompt_selector = prompt_selector or PromptSelector()
        self.explanation_builder = explanation_builder or ExplanationBuilder()

    def build_row(self, connection_id: str) -> dict | None:
        detail = self.build_detail(connection_id)
        if detail is None:
            return None
        return {
            'connection_id': detail['connection']['connection_id'],
            'asset_id': detail['connection']['asset_id'],
            'session_id': detail['connection']['session_id'],
            'start_ts': detail['connection']['start_ts'],
            'process': {
                'name': detail['process']['process_name'],
                'path': detail['process'].get('process_path'),
                'signer_name': detail['process'].get('signer_name'),
                'signer_status': detail['process'].get('signer_status'),
                'package_id': detail['process'].get('package_id'),
            },
            'destination': {
                'matched_domain': detail['destination'].get('matched_domain') if detail['destination'] else None,
                'ip': detail['destination'].get('ip') if detail['destination'] else detail['connection']['remote_ip'],
                'port': detail['destination'].get('port') if detail['destination'] else detail['connection']['remote_port'],
                'protocol': detail['destination'].get('protocol') if detail['destination'] else detail['connection'].get('protocol'),
                'sni': detail['destination'].get('sni') if detail['destination'] else None,
                'certificate_subject': detail['destination'].get('certificate_subject') if detail['destination'] else None,
                'certificate_issuer': detail['destination'].get('certificate_issuer') if detail['destination'] else None,
            },
            'verdict': detail['policy']['decision'] or 'ask',
            'verdict_source': detail['policy']['decision_source'],
            'network_zone': detail['connection']['network_zone'],
            'flow_risk_score': detail['connection'].get('flow_risk_score'),
            'rule_suggestion_score': detail['connection'].get('rule_suggestion_score'),
            'trust_flags': {
                'risky_ble_signature_counter': detail['trust_context'].get('risky_ble_signature_counter', False),
                'rogue_ble_counter_reuse': detail['trust_context'].get('rogue_ble_counter_reuse', False),
            },
            'explanation_preview': (
                detail['explanation']['user_factors'][0]
                if detail['explanation']['user_factors']
                else detail['explanation']['short_rationale']
            ),
        }

    def build_detail(self, connection_id: str) -> dict | None:
        connection = self.connections.get_connection(connection_id)
        if connection is None:
            return None
        process = self.processes.get_process_identity(connection.process_identity_id)
        if process is None:
            raise LookupError(f'missing process_identity for {connection.process_identity_id}')
        destination = None
        if connection.destination_identity_id:
            destination = self.destinations.get_destination_identity(connection.destination_identity_id)
        decision = self.decisions.get_latest_decision_for_connection(connection.connection_id)
        trust_snapshot = None
        if connection.trust_context_snapshot_id:
            trust_snapshot = self.trust.get_snapshot(connection.trust_context_snapshot_id)
        matched_verdict = decision.decision if decision else None
        selection = self.prompt_selector.select(
            connection=connection,
            process=process,
            destination=destination,
            matched_verdict=matched_verdict,
            trust_snapshot=(
                TrustSnapshot(
                    trust_score=trust_snapshot.trust_score,
                    drift_score=trust_snapshot.drift_score,
                    risky_ble_signature_counter=trust_snapshot.risky_ble_signature_counter,
                    rogue_ble_counter_reuse=trust_snapshot.rogue_ble_counter_reuse,
                )
                if trust_snapshot
                else None
            ),
        )
        explanation = self.explanation_builder.build(
            connection=connection,
            process=process,
            destination=destination,
            selection=selection,
            trust_snapshot=(
                TrustSnapshot(
                    trust_score=trust_snapshot.trust_score,
                    drift_score=trust_snapshot.drift_score,
                    risky_ble_signature_counter=trust_snapshot.risky_ble_signature_counter,
                    rogue_ble_counter_reuse=trust_snapshot.rogue_ble_counter_reuse,
                )
                if trust_snapshot
                else None
            ),
        )
        matched_rule = self.rules.get_rule(decision.matched_rule_id) if decision and decision.matched_rule_id else None
        return {
            'connection': connection.model_dump(mode='json'),
            'process': process.model_dump(mode='json'),
            'destination': destination.model_dump(mode='json') if destination else None,
            'policy': {
                'matched_rule_id': decision.matched_rule_id if decision else connection.matched_rule_id,
                'matched_rule': matched_rule.model_dump(mode='json') if matched_rule else None,
                'decision': decision.decision if decision else None,
                'decision_source': decision.decision_source if decision else None,
                'expires_at': decision.expires_at.isoformat() if decision and decision.expires_at else None,
            },
            'trust_context': trust_snapshot.model_dump(mode='json') if trust_snapshot else {},
            'explanation': asdict(explanation),
            'related_events': [],
        }
