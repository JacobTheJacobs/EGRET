from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.storage.repositories.interfaces import (
    ConnectionRepository,
    DecisionRepository,
    DestinationIdentityRepository,
    ProcessIdentityRepository,
    RuleRepository,
    TrustSnapshotRepository,
)


@dataclass
class InvestigationTimelineService:
    connections: ConnectionRepository
    processes: ProcessIdentityRepository
    destinations: DestinationIdentityRepository
    decisions: DecisionRepository
    rules: RuleRepository
    trust: TrustSnapshotRepository

    def build_asset_timeline(self, asset_id: str, page: int = 1, page_size: int = 100) -> dict[str, Any]:
        events: list[dict[str, Any]] = []
        connections, total = self.connections.list_connections(asset_id=asset_id, page=page, page_size=page_size)
        seen_sessions: set[str] = set()
        for connection in connections:
            process = self.processes.get_process_identity(connection.process_identity_id)
            destination = self.destinations.get_destination_identity(connection.destination_identity_id) if connection.destination_identity_id else None
            decision = self.decisions.get_latest_decision_for_connection(connection.connection_id)
            rule = self.rules.get_rule(decision.matched_rule_id) if decision and decision.matched_rule_id else None
            seen_sessions.add(connection.session_id)
            events.append({
                'kind': 'connection',
                'ts': connection.start_ts.isoformat(),
                'asset_id': connection.asset_id,
                'session_id': connection.session_id,
                'connection_id': connection.connection_id,
                'title': f"{process.process_name if process else 'Unknown process'} connected to {destination.matched_domain if destination and destination.matched_domain else connection.remote_ip}",
                'summary': {
                    'process_name': process.process_name if process else None,
                    'destination': destination.matched_domain if destination else connection.remote_ip,
                    'verdict': decision.decision if decision else 'ask',
                    'matched_rule_id': decision.matched_rule_id if decision else None,
                    'rule_action': rule.action if rule else None,
                },
            })
            if decision is not None:
                events.append({
                    'kind': 'decision',
                    'ts': decision.created_ts.isoformat(),
                    'asset_id': connection.asset_id,
                    'session_id': connection.session_id,
                    'connection_id': connection.connection_id,
                    'title': f"Decision {decision.decision} for {process.process_name if process else connection.connection_id}",
                    'summary': {
                        'decision': decision.decision,
                        'decision_source': decision.decision_source,
                        'matched_rule_id': decision.matched_rule_id,
                        'user_reason': decision.user_reason,
                    },
                })
        for session_id in sorted(seen_sessions):
            for snapshot in self.trust.list_snapshots_for_asset(asset_id=asset_id, session_id=session_id):
                events.append({
                    'kind': 'trust_snapshot',
                    'ts': snapshot.snapshot_ts.isoformat(),
                    'asset_id': snapshot.asset_id,
                    'session_id': snapshot.session_id,
                    'trust_context_snapshot_id': snapshot.trust_context_snapshot_id,
                    'title': 'Trust context updated',
                    'summary': {
                        'trust_score': snapshot.trust_score,
                        'drift_score': snapshot.drift_score,
                        'risky_ble_signature_counter': snapshot.risky_ble_signature_counter,
                        'rogue_ble_counter_reuse': snapshot.rogue_ble_counter_reuse,
                    },
                })
        events.sort(key=lambda e: e['ts'], reverse=True)
        return {'asset_id': asset_id, 'items': events, 'page': page, 'page_size': page_size, 'total_connections': total}
