from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.models.behavior_alert import BehaviorAlert
from app.models.enforcement_event import EnforcementEvent
from app.models.file_event import FileEvent
from app.models.malware_verdict import MalwareVerdict
from app.models.policy_decision import PolicyDecision
from app.models.policy_rule import PolicyConditions, PolicyRule
from app.models.quarantine_record import QuarantineRecord
from app.models.ransomware_signal import RansomwareSignal
from app.models.remediation_action import RemediationAction
from app.models.trust_context_snapshot import TrustContextSnapshot
from app.models.web_verdict import WebVerdict
from app.storage.adapters.legacy_flow_adapter import LegacyFlowDualWriter, LegacyFlowRecord
from app.storage.repositories.sqlite import SqliteRepositories

BASE_TS = datetime(2026, 7, 8, 15, 0, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class DemoSeedResult:
    inserted_connections: int
    inserted_decisions: int
    inserted_trust_snapshots: int
    inserted_file_events: int
    inserted_malware_verdicts: int
    inserted_quarantine_records: int
    inserted_web_verdicts: int
    inserted_behavior_alerts: int
    inserted_ransomware_signals: int
    inserted_remediation_actions: int
    inserted_rules: int
    inserted_enforcement_events: int

    def to_dict(self) -> dict:
        return {
            'inserted_connections': self.inserted_connections,
            'inserted_decisions': self.inserted_decisions,
            'inserted_trust_snapshots': self.inserted_trust_snapshots,
            'inserted_file_events': self.inserted_file_events,
            'inserted_malware_verdicts': self.inserted_malware_verdicts,
            'inserted_quarantine_records': self.inserted_quarantine_records,
            'inserted_web_verdicts': self.inserted_web_verdicts,
            'inserted_behavior_alerts': self.inserted_behavior_alerts,
            'inserted_ransomware_signals': self.inserted_ransomware_signals,
            'inserted_remediation_actions': self.inserted_remediation_actions,
            'inserted_rules': self.inserted_rules,
            'inserted_enforcement_events': self.inserted_enforcement_events,
        }


def _empty_result() -> DemoSeedResult:
    return DemoSeedResult(
        inserted_connections=0,
        inserted_decisions=0,
        inserted_trust_snapshots=0,
        inserted_file_events=0,
        inserted_malware_verdicts=0,
        inserted_quarantine_records=0,
        inserted_web_verdicts=0,
        inserted_behavior_alerts=0,
        inserted_ransomware_signals=0,
        inserted_remediation_actions=0,
        inserted_rules=0,
        inserted_enforcement_events=0,
    )


def demo_records() -> list[LegacyFlowRecord]:
    return [
        LegacyFlowRecord(
            connection_id='demo_conn_browser_cdn',
            asset_id='demo-macbook',
            session_id='demo-session',
            process_id=410,
            process_name='Firefox',
            process_path='/Applications/Firefox.app/Contents/MacOS/firefox',
            signer_name='Mozilla Corporation',
            signer_status='trusted',
            start_ts=BASE_TS,
            remote_ip='104.18.12.34',
            remote_port=443,
            transport='tcp',
            protocol='tls',
            matched_domain='updates.mozilla.org',
            sni='updates.mozilla.org',
            certificate_subject='CN=updates.mozilla.org',
            certificate_issuer='CN=Public TLS CA',
            network_zone='public_internet',
            bytes_out=18420,
            bytes_in=412880,
            duration_ms=2400,
            first_seen_on_asset=False,
            prevalence_on_asset=0.91,
            flow_risk_score=0.18,
            rule_suggestion_score=0.24,
        ),
        LegacyFlowRecord(
            connection_id='demo_conn_sync_unknown',
            asset_id='demo-macbook',
            session_id='demo-session',
            process_id=811,
            process_name='SyncAgent',
            process_path='/usr/local/bin/sync-agent',
            signer_name='Example Corp',
            signer_status='trusted',
            start_ts=BASE_TS + timedelta(seconds=30),
            remote_ip='198.51.100.20',
            remote_port=443,
            transport='tcp',
            protocol='tls',
            matched_domain='sync.example.test',
            sni='sync.example.test',
            certificate_subject='CN=sync.example.test',
            certificate_issuer='CN=Example Test CA',
            network_zone='public_internet',
            bytes_out=9120,
            bytes_in=223400,
            duration_ms=1880,
            first_seen_on_asset=True,
            prevalence_on_asset=0.12,
            flow_risk_score=0.57,
            rule_suggestion_score=0.72,
        ),
        LegacyFlowRecord(
            connection_id='demo_conn_unsigned_beacon',
            asset_id='demo-macbook',
            session_id='demo-session',
            process_id=1337,
            process_name='UpdaterHelper',
            process_path='/Users/demo/Library/LaunchAgents/updater-helper',
            signer_name=None,
            signer_status='unsigned',
            start_ts=BASE_TS + timedelta(seconds=80),
            remote_ip='203.0.113.66',
            remote_port=8443,
            transport='tcp',
            protocol='tls',
            matched_domain='telemetry.bad-demo.test',
            sni='telemetry.bad-demo.test',
            certificate_subject='CN=telemetry.bad-demo.test',
            certificate_issuer='CN=Unknown Issuer',
            network_zone='public_internet',
            bytes_out=64000,
            bytes_in=3200,
            duration_ms=920,
            first_seen_on_asset=True,
            first_seen_in_fleet=True,
            prevalence_on_asset=0.01,
            prevalence_in_fleet=0.0,
            flow_risk_score=0.91,
            rule_suggestion_score=0.94,
            anomaly_score=0.88,
        ),
    ]


def seed_demo_data(repos: SqliteRepositories) -> DemoSeedResult:
    existing, total = repos.connections.list_connections(page=1, page_size=1)
    if total > 0 or existing:
        return _empty_result()
    writer = LegacyFlowDualWriter(connections=repos.connections, processes=repos.processes, destinations=repos.destinations)
    inserted_connections = 0
    process_ids_by_connection: dict[str, str | None] = {}
    for record in demo_records():
        event = writer.write(record)
        process_ids_by_connection[event.connection_id] = event.process_identity_id
        inserted_connections += 1
        snapshot_id = f'demo_trust_{event.connection_id}'
        repos.trust.upsert_snapshot(
            TrustContextSnapshot(
                trust_context_snapshot_id=snapshot_id,
                asset_id=event.asset_id,
                session_id=event.session_id,
                snapshot_ts=event.start_ts - timedelta(seconds=10),
                risky_ble_signature_counter=event.connection_id == 'demo_conn_unsigned_beacon',
                rogue_ble_counter_reuse=False,
                trust_score=0.28 if event.connection_id == 'demo_conn_unsigned_beacon' else 0.86,
                drift_score=0.74 if event.connection_id == 'demo_conn_unsigned_beacon' else 0.11,
                supporting_context_json={'source': 'egret-demo'},
            )
        )
        repos.connections.upsert_connection(event.model_copy(update={'trust_context_snapshot_id': snapshot_id}))

    decisions = [
        PolicyDecision(
            policy_decision_id='demo_decision_browser_cdn',
            connection_id='demo_conn_browser_cdn',
            decision='allow',
            decision_source='system_default',
            prompt_shown=False,
            confidence_score=0.88,
            recommendation_kind='known_signed_app',
            created_ts=BASE_TS + timedelta(seconds=2),
        ),
        PolicyDecision(
            policy_decision_id='demo_decision_sync_unknown',
            connection_id='demo_conn_sync_unknown',
            decision='ask',
            decision_source='recommendation',
            prompt_shown=True,
            confidence_score=0.62,
            recommendation_kind='new_destination',
            created_ts=BASE_TS + timedelta(seconds=35),
        ),
        PolicyDecision(
            policy_decision_id='demo_decision_unsigned_beacon',
            connection_id='demo_conn_unsigned_beacon',
            decision='deny',
            decision_source='recommendation',
            prompt_shown=True,
            confidence_score=0.93,
            recommendation_kind='unsigned_high_risk',
            created_ts=BASE_TS + timedelta(seconds=85),
        ),
    ]
    for decision in decisions:
        repos.decisions.create_decision(decision)

    file_events = [
        FileEvent(
            file_event_id='demo_file_eicar_download',
            asset_id='demo-macbook',
            session_id='demo-session',
            process_identity_id=process_ids_by_connection.get('demo_conn_unsigned_beacon'),
            path='/Users/demo/Downloads/eicar.com',
            sha256='275a021bbfb6480f2cdd6bb9f0a2d1e1f5f8fbbf12f3b9c3c4d5e6f708192a3b',
            file_size=68,
            file_type='dos-executable',
            origin_kind='download',
            origin_source='https://telemetry.bad-demo.test/dropper/eicar.com',
            signer_name=None,
            signer_status='unsigned',
            event_kind='write',
            ts=BASE_TS + timedelta(seconds=92),
        ),
        FileEvent(
            file_event_id='demo_file_signed_app_execute',
            asset_id='demo-macbook',
            session_id='demo-session',
            process_identity_id=process_ids_by_connection.get('demo_conn_browser_cdn'),
            path='/Applications/Firefox.app/Contents/MacOS/firefox',
            sha256='3f9f2b8c4e8e8b0a6d8b5f3a1a5e4c2d9f7a6b3c2d1e0f9876543210abcdeff',
            file_size=141721600,
            file_type='mach-o',
            origin_kind='local',
            origin_source='installed_application',
            signer_name='Mozilla Corporation',
            signer_status='trusted',
            event_kind='execute',
            ts=BASE_TS + timedelta(seconds=3),
        ),
        FileEvent(
            file_event_id='demo_file_sync_helper_scan',
            asset_id='demo-macbook',
            session_id='demo-session',
            process_identity_id=process_ids_by_connection.get('demo_conn_sync_unknown'),
            path='/usr/local/bin/sync-agent',
            sha256='a5cfde1234567890b5cfde1234567890c5cfde1234567890d5cfde1234567890',
            file_size=7340032,
            file_type='elf',
            origin_kind='archive_extract',
            origin_source='/Users/demo/Downloads/sync-agent.tar.gz',
            signer_name='Example Corp',
            signer_status='trusted',
            event_kind='demand_scan',
            ts=BASE_TS + timedelta(seconds=39),
        ),
    ]
    for event in file_events:
        repos.files.create_file_event(event)

    malware_verdicts = [
        MalwareVerdict(
            malware_verdict_id='demo_malware_eicar',
            file_event_id='demo_file_eicar_download',
            sha256='275a021bbfb6480f2cdd6bb9f0a2d1e1f5f8fbbf12f3b9c3c4d5e6f708192a3b',
            verdict='malicious',
            verdict_source='signature',
            signature_name='EICAR-Test-File',
            family_name='Test.Malware.EICAR',
            confidence_score=0.99,
            reputation_score=0.01,
            cloud_lookup_hit=True,
            created_ts=BASE_TS + timedelta(seconds=94),
        ),
        MalwareVerdict(
            malware_verdict_id='demo_malware_signed_clean',
            file_event_id='demo_file_signed_app_execute',
            sha256='3f9f2b8c4e8e8b0a6d8b5f3a1a5e4c2d9f7a6b3c2d1e0f9876543210abcdeff',
            verdict='clean',
            verdict_source='allowlist',
            signature_name=None,
            family_name=None,
            confidence_score=0.96,
            reputation_score=0.94,
            cloud_lookup_hit=True,
            created_ts=BASE_TS + timedelta(seconds=4),
        ),
        MalwareVerdict(
            malware_verdict_id='demo_malware_sync_suspicious',
            file_event_id='demo_file_sync_helper_scan',
            sha256='a5cfde1234567890b5cfde1234567890c5cfde1234567890d5cfde1234567890',
            verdict='suspicious',
            verdict_source='reputation',
            signature_name='LowPrevalence.Signed.Tool',
            family_name=None,
            confidence_score=0.71,
            reputation_score=0.22,
            cloud_lookup_hit=True,
            created_ts=BASE_TS + timedelta(seconds=42),
        ),
    ]
    for verdict in malware_verdicts:
        repos.malware_verdicts.create_verdict(verdict)

    quarantine_records = [
        QuarantineRecord(
            quarantine_record_id='demo_quarantine_eicar',
            asset_id='demo-macbook',
            sha256='275a021bbfb6480f2cdd6bb9f0a2d1e1f5f8fbbf12f3b9c3c4d5e6f708192a3b',
            original_path='/Users/demo/Downloads/eicar.com',
            quarantine_path='/Library/Application Support/Egret/Quarantine/demo_quarantine_eicar.bin',
            reason='Signature match: EICAR-Test-File',
            restored=False,
            deleted=False,
            created_ts=BASE_TS + timedelta(seconds=96),
            updated_ts=BASE_TS + timedelta(seconds=96),
            malware_verdict_id='demo_malware_eicar',
        ),
    ]
    for record in quarantine_records:
        repos.quarantine.create_record(record)

    web_verdicts = [
        WebVerdict(
            web_verdict_id='demo_web_bad_beacon',
            asset_id='demo-macbook',
            process_identity_id=process_ids_by_connection.get('demo_conn_unsigned_beacon'),
            url='https://telemetry.bad-demo.test/beacon',
            domain='telemetry.bad-demo.test',
            category='malicious',
            verdict='block',
            source='reputation',
            confidence_score=0.95,
            created_ts=BASE_TS + timedelta(seconds=87),
        ),
        WebVerdict(
            web_verdict_id='demo_web_sync_warn',
            asset_id='demo-macbook',
            process_identity_id=process_ids_by_connection.get('demo_conn_sync_unknown'),
            url='https://sync.example.test/api/v1/bootstrap',
            domain='sync.example.test',
            category='suspicious',
            verdict='warn',
            source='heuristic',
            confidence_score=0.66,
            created_ts=BASE_TS + timedelta(seconds=37),
        ),
    ]
    for verdict in web_verdicts:
        repos.web_verdicts.create_web_verdict(verdict)

    behavior_alerts = [
        BehaviorAlert(
            behavior_alert_id='demo_behavior_unsigned_persistence',
            asset_id='demo-macbook',
            session_id='demo-session',
            process_identity_id=process_ids_by_connection.get('demo_conn_unsigned_beacon'),
            chain_id='demo-chain-unsigned-updater',
            alert_kind='persistence_and_beaconing',
            severity='high',
            indicators_json={
                'writes_launch_agent': True,
                'unsigned_process': True,
                'low_prevalence_destination': 'telemetry.bad-demo.test',
                'egress_bytes': 64000,
            },
            recommendation='Block outbound traffic, quarantine the downloaded payload, and remove the launch agent.',
            created_ts=BASE_TS + timedelta(seconds=100),
        ),
    ]
    for alert in behavior_alerts:
        repos.behavior_alerts.create_alert(alert)

    ransomware_signals = [
        RansomwareSignal(
            ransomware_signal_id='demo_ransomware_canary_trip',
            asset_id='demo-macbook',
            session_id='demo-session',
            process_identity_id=process_ids_by_connection.get('demo_conn_unsigned_beacon'),
            signal_kind='canary_file_modified',
            severity='critical',
            protected_path='/Users/demo/Documents',
            indicators_json={
                'canary_touched': True,
                'rename_delete_burst_count': 43,
                'modified_files_count': 118,
                'entropy_spike': True,
            },
            action_recommendation='Isolate process tree and preserve rollback candidates for encrypted files.',
            created_ts=BASE_TS + timedelta(seconds=106),
        ),
    ]
    for signal in ransomware_signals:
        repos.ransomware_signals.create_signal(signal)

    remediation_actions = [
        RemediationAction(
            remediation_action_id='demo_remediation_quarantine_payload',
            asset_id='demo-macbook',
            session_id='demo-session',
            process_identity_id=process_ids_by_connection.get('demo_conn_unsigned_beacon'),
            related_object_id='demo_quarantine_eicar',
            action_kind='quarantine_file',
            target_type='file',
            status='completed',
            backend_result='Payload moved to Egret quarantine.',
            initiated_by='egret-demo',
            created_ts=BASE_TS + timedelta(seconds=97),
            completed_ts=BASE_TS + timedelta(seconds=98),
        ),
        RemediationAction(
            remediation_action_id='demo_remediation_isolate_process',
            asset_id='demo-macbook',
            session_id='demo-session',
            process_identity_id=process_ids_by_connection.get('demo_conn_unsigned_beacon'),
            related_object_id='demo_ransomware_canary_trip',
            action_kind='isolate_process',
            target_type='signal',
            status='pending',
            backend_result='Awaiting operator approval for process isolation.',
            initiated_by='ransomware_guard',
            created_ts=BASE_TS + timedelta(seconds=108),
            completed_ts=None,
        ),
    ]
    for action in remediation_actions:
        repos.remediation_actions.create_action(action)

    rules = [
        PolicyRule(
            rule_id='demo_rule_block_bad_demo',
            rule_name='Block unsigned updater beacon',
            enabled=True,
            priority=900,
            source='system',
            action='deny',
            ttl_seconds=None,
            created_ts=BASE_TS + timedelta(seconds=88),
            updated_ts=BASE_TS + timedelta(seconds=88),
            created_by='egret-demo',
            conditions=PolicyConditions(process_name='UpdaterHelper', domain='telemetry.bad-demo.test', protocol='tls'),
            explanation_template='Unsigned updater beacon matched a known-bad demo destination.',
        ),
        PolicyRule(
            rule_id='demo_rule_allow_mozilla_updates',
            rule_name='Allow signed Mozilla update traffic',
            enabled=True,
            priority=400,
            source='system',
            action='allow',
            ttl_seconds=None,
            created_ts=BASE_TS + timedelta(seconds=5),
            updated_ts=BASE_TS + timedelta(seconds=5),
            created_by='egret-demo',
            conditions=PolicyConditions(process_name='Firefox', signer_name='Mozilla Corporation', domain_suffix='mozilla.org', protocol='tls'),
            explanation_template='Trusted signed browser update traffic.',
        ),
    ]
    for rule in rules:
        repos.rules.create_rule(rule)

    enforcement_events = [
        EnforcementEvent(
            enforcement_event_id='demo_enforcement_block_bad_demo',
            rule_id='demo_rule_block_bad_demo',
            backend='linux',
            action='deny',
            status='applied',
            connection_id='demo_conn_unsigned_beacon',
            policy_decision_id='demo_decision_unsigned_beacon',
            message='Simulated nftables deny rule for telemetry.bad-demo.test:8443.',
            command_preview=['nft', 'add', 'rule', 'inet', 'egret', 'output', 'ip daddr 203.0.113.66 tcp dport 8443 drop'],
            backend_rule_ref='demo:nftables:demo_rule_block_bad_demo',
            execution_mode='simulated',
            backend_state='present',
            applied_ts=BASE_TS + timedelta(seconds=90),
            effective_until=None,
        ),
    ]
    for event in enforcement_events:
        repos.enforcement.create_event(event)

    return DemoSeedResult(
        inserted_connections=inserted_connections,
        inserted_decisions=len(decisions),
        inserted_trust_snapshots=inserted_connections,
        inserted_file_events=len(file_events),
        inserted_malware_verdicts=len(malware_verdicts),
        inserted_quarantine_records=len(quarantine_records),
        inserted_web_verdicts=len(web_verdicts),
        inserted_behavior_alerts=len(behavior_alerts),
        inserted_ransomware_signals=len(ransomware_signals),
        inserted_remediation_actions=len(remediation_actions),
        inserted_rules=len(rules),
        inserted_enforcement_events=len(enforcement_events),
    )
