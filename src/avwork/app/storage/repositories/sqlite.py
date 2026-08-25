from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from app.models.connection_event import ConnectionEvent
from app.models.destination_identity import DestinationIdentity
from app.models.enforcement_event import EnforcementEvent
from app.models.behavior_alert import BehaviorAlert
from app.models.file_event import FileEvent
from app.models.malware_verdict import MalwareVerdict
from app.models.quarantine_record import QuarantineRecord
from app.models.web_verdict import WebVerdict
from app.models.remediation_action import RemediationAction
from app.models.ransomware_signal import RansomwareSignal
from app.models.policy_decision import PolicyDecision
from app.models.policy_rule import PolicyConditions, PolicyRule
from app.models.process_identity import ProcessIdentity
from app.models.training_feedback_event import TrainingFeedbackEvent
from app.models.trust_context_snapshot import TrustContextSnapshot


def _ensure_parent(path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def _row_to_model(model_cls, row: sqlite3.Row | None, *, json_fields: dict[str, Any] | None = None):
    if row is None:
        return None
    payload = dict(row)
    for field_name, default in (json_fields or {}).items():
        raw = payload.get(field_name)
        if raw is None:
            payload[field_name] = default() if callable(default) else default
        elif isinstance(raw, str):
            payload[field_name] = json.loads(raw)
    return model_cls(**payload)


class _LockedRows(list):
    """A materialised result set that still answers the cursor API."""

    def fetchall(self) -> list:
        return list(self)

    def fetchone(self):
        return self[0] if self else None


class _LockedConnection:
    """Serialises access to one sqlite3 connection shared across threads.

    A single connection is shared by every repository while FastAPI runs sync
    endpoints on a threadpool, so concurrent requests drive it from several
    threads at once. SQLite's serialized mode protects the C library, but the
    Python-side cursor and commit state are still shared mutable objects, and
    overlapping requests raised ``sqlite3.InterfaceError: bad parameter or other
    API misuse``.

    Queries are run to completion under the lock and returned materialised, so
    no lazy fetch can escape it and interleave with another thread's statement.
    """

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def execute(self, sql: str, parameters=()) -> _LockedRows:
        with self._lock:
            return _LockedRows(self._conn.execute(sql, parameters).fetchall())

    def executescript(self, script: str):
        with self._lock:
            return self._conn.executescript(script)

    def commit(self) -> None:
        with self._lock:
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def cursor(self):
        return self._conn.cursor()

    def rollback(self) -> None:
        with self._lock:
            self._conn.rollback()

    def __enter__(self):
        # sqlite3 connections are transaction context managers; the migration
        # runner relies on that. Hold the lock for the whole transaction.
        self._lock.acquire()
        self._conn.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            return self._conn.__exit__(exc_type, exc, tb)
        finally:
            self._lock.release()

    @property
    def row_factory(self):
        return self._conn.row_factory

    @row_factory.setter
    def row_factory(self, value) -> None:
        self._conn.row_factory = value


class SqliteDatabase:
    def __init__(self, path: str | Path = ':memory:') -> None:
        self.path = str(path)
        if self.path != ':memory:':
            _ensure_parent(self.path)
        raw = sqlite3.connect(
            self.path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            check_same_thread=False,
        )
        raw.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.conn = _LockedConnection(raw, self._lock)
        self._bootstrap()

    def _bootstrap(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS process_identity (
                process_identity_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                process_id INTEGER NOT NULL,
                parent_process_id INTEGER NULL,
                process_name TEXT NOT NULL,
                process_path TEXT NOT NULL,
                executable_hash TEXT NULL,
                signer_name TEXT NULL,
                signer_status TEXT NULL,
                package_id TEXT NULL,
                service_name TEXT NULL,
                first_seen_ts TEXT NULL,
                last_seen_ts TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_process_identity_asset_session_pid
                ON process_identity(asset_id, session_id, process_id);
            CREATE INDEX IF NOT EXISTS idx_process_identity_name
                ON process_identity(process_name);

            CREATE TABLE IF NOT EXISTS destination_identity (
                destination_identity_id TEXT PRIMARY KEY,
                canonical_name TEXT NULL,
                matched_domain TEXT NULL,
                sni TEXT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NULL,
                certificate_subject TEXT NULL,
                certificate_issuer TEXT NULL,
                certificate_fingerprint TEXT NULL,
                service_fingerprint TEXT NULL,
                resolver_source TEXT NULL,
                first_seen_ts TEXT NULL,
                last_seen_ts TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_destination_identity_ip_port
                ON destination_identity(ip, port);
            CREATE INDEX IF NOT EXISTS idx_destination_identity_domain
                ON destination_identity(matched_domain, sni);

            CREATE TABLE IF NOT EXISTS connection_event (
                connection_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL CHECK (schema_version = 1),
                asset_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                process_identity_id TEXT NOT NULL,
                destination_identity_id TEXT NULL,
                start_ts TEXT NOT NULL,
                end_ts TEXT NULL,
                direction TEXT NOT NULL CHECK (direction IN ('outbound', 'inbound')),
                protocol TEXT NULL,
                transport TEXT NOT NULL,
                local_ip TEXT NULL,
                local_port INTEGER NULL CHECK (local_port BETWEEN 1 AND 65535),
                remote_ip TEXT NOT NULL,
                remote_port INTEGER NOT NULL CHECK (remote_port BETWEEN 1 AND 65535),
                interface_name TEXT NULL,
                network_zone TEXT NOT NULL,
                vpn_state TEXT NULL,
                bytes_out INTEGER NULL DEFAULT 0,
                bytes_in INTEGER NULL DEFAULT 0,
                duration_ms INTEGER NULL,
                trust_context_snapshot_id TEXT NULL,
                matched_rule_id TEXT NULL,
                policy_decision_id TEXT NULL,
                first_seen_on_asset INTEGER NULL,
                first_seen_in_fleet INTEGER NULL,
                prevalence_on_asset REAL NULL,
                prevalence_in_fleet REAL NULL,
                flow_risk_score REAL NULL,
                rule_suggestion_score REAL NULL,
                anomaly_score REAL NULL
            );
            CREATE INDEX IF NOT EXISTS idx_connection_event_asset_ts
                ON connection_event(asset_id, start_ts DESC);
            CREATE INDEX IF NOT EXISTS idx_connection_event_process
                ON connection_event(process_identity_id, start_ts DESC);
            CREATE INDEX IF NOT EXISTS idx_connection_event_remote
                ON connection_event(remote_ip, remote_port);
            CREATE INDEX IF NOT EXISTS idx_connection_event_zone_ts
                ON connection_event(network_zone, start_ts DESC);

            CREATE TABLE IF NOT EXISTS policy_rule (
                rule_id TEXT PRIMARY KEY,
                rule_name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL,
                source TEXT NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'ask', 'observe_only')),
                ttl_seconds INTEGER NULL CHECK (ttl_seconds IS NULL OR ttl_seconds > 0),
                created_ts TEXT NOT NULL,
                updated_ts TEXT NOT NULL,
                created_by TEXT NULL,
                conditions_json TEXT NOT NULL,
                explanation_template TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_policy_rule_enabled_priority ON policy_rule(enabled, priority DESC);
            CREATE INDEX IF NOT EXISTS idx_policy_rule_created_ts ON policy_rule(created_ts DESC);

            CREATE TABLE IF NOT EXISTS policy_decision (
                policy_decision_id TEXT PRIMARY KEY,
                connection_id TEXT NOT NULL,
                matched_rule_id TEXT NULL,
                decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'ask', 'defer')),
                decision_source TEXT NOT NULL CHECK (decision_source IN ('user_prompt', 'user_rule', 'admin_rule', 'system_default', 'recommendation')),
                prompt_shown INTEGER NOT NULL DEFAULT 0,
                prompt_response TEXT NULL,
                user_reason TEXT NULL,
                expires_at TEXT NULL,
                confidence_score REAL NULL,
                recommendation_kind TEXT NULL,
                created_ts TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_policy_decision_connection ON policy_decision(connection_id, created_ts DESC);
            CREATE INDEX IF NOT EXISTS idx_policy_decision_expires_at ON policy_decision(expires_at);

            CREATE TABLE IF NOT EXISTS trust_context_snapshot (
                trust_context_snapshot_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                snapshot_ts TEXT NOT NULL,
                risky_ble_signature_counter INTEGER NOT NULL DEFAULT 0,
                rogue_ble_counter_reuse INTEGER NOT NULL DEFAULT 0,
                trust_score REAL NULL,
                drift_score REAL NULL,
                supporting_context_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_trust_context_snapshot_asset_session_ts
                ON trust_context_snapshot(asset_id, session_id, snapshot_ts DESC);

            CREATE TABLE IF NOT EXISTS enforcement_event (
                enforcement_event_id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                backend TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                connection_id TEXT NULL,
                policy_decision_id TEXT NULL,
                message TEXT NULL,
                command_preview TEXT NOT NULL DEFAULT '[]',
                backend_rule_ref TEXT NULL,
                execution_mode TEXT NULL DEFAULT 'simulated',
                backend_state TEXT NULL DEFAULT 'unknown',
                applied_ts TEXT NOT NULL,
                effective_until TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_enforcement_event_rule_applied
                ON enforcement_event(rule_id, applied_ts DESC);
            CREATE INDEX IF NOT EXISTS idx_enforcement_event_connection
                ON enforcement_event(connection_id);
            CREATE INDEX IF NOT EXISTS idx_enforcement_event_decision
                ON enforcement_event(policy_decision_id);


            CREATE TABLE IF NOT EXISTS file_event (
                file_event_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                process_identity_id TEXT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                file_size INTEGER NOT NULL DEFAULT 0,
                file_type TEXT NULL,
                origin_kind TEXT NULL,
                origin_source TEXT NULL,
                signer_name TEXT NULL,
                signer_status TEXT NULL,
                event_kind TEXT NOT NULL,
                ts TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_file_event_asset_ts ON file_event(asset_id, ts DESC);
            CREATE INDEX IF NOT EXISTS idx_file_event_sha256 ON file_event(sha256);

            CREATE TABLE IF NOT EXISTS malware_verdict (
                malware_verdict_id TEXT PRIMARY KEY,
                file_event_id TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                verdict TEXT NOT NULL,
                verdict_source TEXT NOT NULL,
                signature_name TEXT NULL,
                family_name TEXT NULL,
                confidence_score REAL NOT NULL DEFAULT 0,
                reputation_score REAL NULL,
                cloud_lookup_hit INTEGER NOT NULL DEFAULT 0,
                created_ts TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_malware_verdict_file_event ON malware_verdict(file_event_id, created_ts DESC);
            CREATE INDEX IF NOT EXISTS idx_malware_verdict_verdict ON malware_verdict(verdict, created_ts DESC);

            CREATE TABLE IF NOT EXISTS quarantine_record (
                quarantine_record_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                reason TEXT NOT NULL,
                restored INTEGER NOT NULL DEFAULT 0,
                deleted INTEGER NOT NULL DEFAULT 0,
                created_ts TEXT NOT NULL,
                updated_ts TEXT NOT NULL,
                malware_verdict_id TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_quarantine_record_asset_created ON quarantine_record(asset_id, created_ts DESC);

            CREATE TABLE IF NOT EXISTS web_verdict (
                web_verdict_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                process_identity_id TEXT NULL,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                category TEXT NOT NULL,
                verdict TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence_score REAL NOT NULL DEFAULT 0,
                created_ts TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_web_verdict_asset_created ON web_verdict(asset_id, created_ts DESC);
            CREATE INDEX IF NOT EXISTS idx_web_verdict_verdict ON web_verdict(verdict, created_ts DESC);



            CREATE TABLE IF NOT EXISTS behavior_alert (
                behavior_alert_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                process_identity_id TEXT NULL,
                chain_id TEXT NULL,
                alert_kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                indicators_json TEXT NOT NULL DEFAULT '{}',
                recommendation TEXT NOT NULL,
                created_ts TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_behavior_alert_asset_created ON behavior_alert(asset_id, created_ts DESC);
            CREATE INDEX IF NOT EXISTS idx_behavior_alert_severity ON behavior_alert(severity, created_ts DESC);


            CREATE TABLE IF NOT EXISTS ransomware_signal (
                ransomware_signal_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                process_identity_id TEXT NULL,
                signal_kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                protected_path TEXT NULL,
                indicators_json TEXT NOT NULL DEFAULT '{}',
                action_recommendation TEXT NOT NULL,
                created_ts TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ransomware_signal_asset_created ON ransomware_signal(asset_id, created_ts DESC);
            CREATE INDEX IF NOT EXISTS idx_ransomware_signal_severity ON ransomware_signal(severity, created_ts DESC);

            CREATE TABLE IF NOT EXISTS remediation_action (
                remediation_action_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                process_identity_id TEXT NULL,
                related_object_id TEXT NULL,
                action_kind TEXT NOT NULL,
                target_type TEXT NOT NULL,
                status TEXT NOT NULL,
                backend_result TEXT NULL,
                initiated_by TEXT NOT NULL,
                created_ts TEXT NOT NULL,
                completed_ts TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_remediation_action_asset_created ON remediation_action(asset_id, created_ts DESC);
            CREATE INDEX IF NOT EXISTS idx_remediation_action_status ON remediation_action(status, created_ts DESC);

            CREATE TABLE IF NOT EXISTS training_feedback_event (
                training_feedback_event_id TEXT PRIMARY KEY,
                connection_id TEXT NOT NULL,
                label TEXT NOT NULL,
                label_source TEXT NOT NULL,
                features_hash TEXT NOT NULL,
                generated_ts TEXT NOT NULL,
                superseded_by TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_training_feedback_event_connection_id
                ON training_feedback_event(connection_id, generated_ts DESC);
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def cursor(self):
        # Held for the whole transaction: commit() on a shared connection would
        # otherwise flush another thread's half-finished writes.
        with self._lock:
            cur = self.conn.cursor()
            try:
                yield cur
                self.conn.commit()
            finally:
                cur.close()


def _serialize(model) -> dict[str, Any]:
    data = model.model_dump(mode='json')
    for field in ('conditions', 'supporting_context_json'):
        if field in data and data[field] is not None:
            data[field] = json.dumps(data[field], sort_keys=True)
    return data


class SqliteConnectionRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def upsert_connection(self, event: ConnectionEvent) -> ConnectionEvent:
        data = event.model_dump(mode='json')
        columns = ', '.join(data.keys())
        placeholders = ', '.join(':' + key for key in data.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in data.keys() if key != 'connection_id')
        with self.db.cursor() as cur:
            cur.execute(
                f"INSERT INTO connection_event ({columns}) VALUES ({placeholders}) "
                f"ON CONFLICT(connection_id) DO UPDATE SET {updates}",
                data,
            )
        return event

    def get_connection(self, connection_id: str) -> ConnectionEvent | None:
        row = self.db.conn.execute(
            'SELECT * FROM connection_event WHERE connection_id = ?',
            (connection_id,),
        ).fetchone()
        return _row_to_model(ConnectionEvent, row)

    def list_connections(
        self,
        *,
        asset_id: str | None = None,
        process_name: str | None = None,
        domain: str | None = None,
        ip: str | None = None,
        port: int | None = None,
        verdict: str | None = None,
        signer_status_not: str | None = None,
        network_zone: str | None = None,
        start_ts: datetime | None = None,
        end_ts: datetime | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[ConnectionEvent], int]:
        filters: list[str] = []
        params: list[Any] = []
        joins = [
            'LEFT JOIN process_identity pi ON pi.process_identity_id = ce.process_identity_id',
            'LEFT JOIN destination_identity di ON di.destination_identity_id = ce.destination_identity_id',
            "LEFT JOIN (SELECT pd1.* FROM policy_decision pd1 JOIN (SELECT connection_id, MAX(created_ts) AS created_ts FROM policy_decision GROUP BY connection_id) latest ON latest.connection_id = pd1.connection_id AND latest.created_ts = pd1.created_ts) pd ON pd.connection_id = ce.connection_id",
        ]
        if asset_id:
            filters.append('ce.asset_id = ?')
            params.append(asset_id)
        if process_name:
            filters.append('pi.process_name LIKE ?')
            params.append(process_name.replace('*', '%'))
        if domain:
            filters.append('(di.matched_domain = ? OR di.sni = ?)')
            params.extend([domain, domain])
        if ip:
            filters.append('ce.remote_ip = ?')
            params.append(ip)
        if port:
            filters.append('ce.remote_port = ?')
            params.append(port)
        if verdict:
            # A connection with no decision row is presented as 'ask' by the
            # detail layer, so the filter must treat NULL the same way; the
            # ingest endpoints create connections without evaluating policy.
            if verdict == 'ask':
                filters.append('(pd.decision = ? OR pd.decision IS NULL)')
            else:
                filters.append('pd.decision = ?')
            params.append(verdict)
        if signer_status_not:
            filters.append('(pi.signer_status IS NULL OR pi.signer_status != ?)')
            params.append(signer_status_not)
        if network_zone:
            filters.append('ce.network_zone = ?')
            params.append(network_zone)
        if start_ts:
            filters.append('ce.start_ts >= ?')
            params.append(start_ts.isoformat())
        if end_ts:
            filters.append('ce.start_ts <= ?')
            params.append(end_ts.isoformat())
        where = ('WHERE ' + ' AND '.join(filters)) if filters else ''
        count_sql = 'SELECT COUNT(*) AS n FROM connection_event ce ' + ' '.join(joins) + ' ' + where
        total = int(self.db.conn.execute(count_sql, params).fetchone()['n'])
        offset = (page - 1) * page_size
        sql = 'SELECT ce.* FROM connection_event ce ' + ' '.join(joins) + ' ' + where + ' ORDER BY ce.start_ts DESC LIMIT ? OFFSET ?'
        rows = self.db.conn.execute(sql, [*params, page_size, offset]).fetchall()
        return [_row_to_model(ConnectionEvent, row) for row in rows], total


class SqliteProcessIdentityRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def upsert_process_identity(self, identity: ProcessIdentity) -> ProcessIdentity:
        data = identity.model_dump(mode='json')
        columns = ', '.join(data.keys())
        placeholders = ', '.join(':' + key for key in data.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in data.keys() if key != 'process_identity_id')
        with self.db.cursor() as cur:
            cur.execute(
                f"INSERT INTO process_identity ({columns}) VALUES ({placeholders}) "
                f"ON CONFLICT(process_identity_id) DO UPDATE SET {updates}",
                data,
            )
        return identity

    def get_process_identity(self, process_identity_id: str) -> ProcessIdentity | None:
        row = self.db.conn.execute(
            'SELECT * FROM process_identity WHERE process_identity_id = ?',
            (process_identity_id,),
        ).fetchone()
        return _row_to_model(ProcessIdentity, row)


class SqliteDestinationIdentityRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def upsert_destination_identity(self, identity: DestinationIdentity) -> DestinationIdentity:
        data = identity.model_dump(mode='json')
        columns = ', '.join(data.keys())
        placeholders = ', '.join(':' + key for key in data.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in data.keys() if key != 'destination_identity_id')
        with self.db.cursor() as cur:
            cur.execute(
                f"INSERT INTO destination_identity ({columns}) VALUES ({placeholders}) "
                f"ON CONFLICT(destination_identity_id) DO UPDATE SET {updates}",
                data,
            )
        return identity

    def get_destination_identity(self, destination_identity_id: str) -> DestinationIdentity | None:
        row = self.db.conn.execute(
            'SELECT * FROM destination_identity WHERE destination_identity_id = ?',
            (destination_identity_id,),
        ).fetchone()
        return _row_to_model(DestinationIdentity, row)


class SqliteDecisionRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def create_decision(self, decision: PolicyDecision) -> PolicyDecision:
        data = decision.model_dump(mode='json')
        columns = ', '.join(data.keys())
        placeholders = ', '.join(':' + key for key in data.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in data.keys() if key != 'policy_decision_id')
        with self.db.cursor() as cur:
            cur.execute(
                f"INSERT INTO policy_decision ({columns}) VALUES ({placeholders}) "
                f"ON CONFLICT(policy_decision_id) DO UPDATE SET {updates}",
                data,
            )
        return decision

    def get_latest_decision_for_connection(self, connection_id: str) -> PolicyDecision | None:
        row = self.db.conn.execute(
            'SELECT * FROM policy_decision WHERE connection_id = ? ORDER BY created_ts DESC LIMIT 1',
            (connection_id,),
        ).fetchone()
        return _row_to_model(PolicyDecision, row)

    def expire_decisions(self, now: datetime) -> int:
        with self.db.cursor() as cur:
            cur.execute(
                "DELETE FROM policy_decision WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (now.isoformat(),),
            )
            return int(cur.rowcount or 0)


class SqliteRuleRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def create_rule(self, rule: PolicyRule) -> PolicyRule:
        payload = rule.model_dump(mode='json')
        payload['conditions_json'] = json.dumps(payload.pop('conditions'), sort_keys=True)
        columns = ', '.join(payload.keys())
        placeholders = ', '.join(':' + key for key in payload.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in payload.keys() if key != 'rule_id')
        with self.db.cursor() as cur:
            cur.execute(
                f"INSERT INTO policy_rule ({columns}) VALUES ({placeholders}) "
                f"ON CONFLICT(rule_id) DO UPDATE SET {updates}",
                payload,
            )
        return rule

    def update_rule(self, rule_id: str, **updates) -> PolicyRule | None:
        current = self.get_rule(rule_id)
        if current is None:
            return None
        payload = current.model_dump(mode='python')
        if 'conditions' in updates and updates['conditions'] is not None:
            payload['conditions'] = updates.pop('conditions')
        payload.update({k: v for k, v in updates.items() if v is not None})
        updated = PolicyRule(**payload)
        return self.create_rule(updated)

    def delete_rule(self, rule_id: str) -> bool:
        with self.db.cursor() as cur:
            cur.execute('DELETE FROM policy_rule WHERE rule_id = ?', (rule_id,))
            return bool(cur.rowcount)

    def list_rules(self) -> list[PolicyRule]:
        rows = self.db.conn.execute('SELECT * FROM policy_rule ORDER BY priority DESC, created_ts DESC').fetchall()
        items: list[PolicyRule] = []
        for row in rows:
            payload = dict(row)
            payload['conditions'] = PolicyConditions(**json.loads(payload.pop('conditions_json')))
            items.append(PolicyRule(**payload))
        return items

    def get_rule(self, rule_id: str) -> PolicyRule | None:
        row = self.db.conn.execute('SELECT * FROM policy_rule WHERE rule_id = ?', (rule_id,)).fetchone()
        if row is None:
            return None
        payload = dict(row)
        payload['conditions'] = PolicyConditions(**json.loads(payload.pop('conditions_json')))
        return PolicyRule(**payload)

    def expire_rules(self, now: datetime) -> int:
        with self.db.cursor() as cur:
            cur.execute(
                "UPDATE policy_rule SET enabled = 0, updated_ts = ? WHERE enabled = 1 AND ttl_seconds IS NOT NULL AND datetime(created_ts, '+' || ttl_seconds || ' seconds') <= datetime(?)",
                (now.isoformat(), now.isoformat()),
            )
            return int(cur.rowcount or 0)


class SqliteTrustSnapshotRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def list_snapshots(self, *, asset_id: str, session_id: str) -> list[TrustContextSnapshot]:
        rows = self.db.conn.execute(
            'SELECT * FROM trust_context_snapshot WHERE asset_id = ? AND session_id = ? ORDER BY snapshot_ts DESC',
            (asset_id, session_id),
        ).fetchall()
        return [_row_to_model(TrustContextSnapshot, row, json_fields={'supporting_context_json': dict}) for row in rows]

    def list_snapshots_for_asset(self, *, asset_id: str, session_id: str | None = None) -> list[TrustContextSnapshot]:
        sql = 'SELECT * FROM trust_context_snapshot WHERE asset_id = ?'
        params: list[Any] = [asset_id]
        if session_id is not None:
            sql += ' AND session_id = ?'
            params.append(session_id)
        sql += ' ORDER BY snapshot_ts DESC'
        rows = self.db.conn.execute(sql, tuple(params)).fetchall()
        return [_row_to_model(TrustContextSnapshot, row, json_fields={'supporting_context_json': dict}) for row in rows]

    def get_snapshot(self, trust_context_snapshot_id: str) -> TrustContextSnapshot | None:
        row = self.db.conn.execute(
            'SELECT * FROM trust_context_snapshot WHERE trust_context_snapshot_id = ?',
            (trust_context_snapshot_id,),
        ).fetchone()
        return _row_to_model(TrustContextSnapshot, row, json_fields={'supporting_context_json': dict})

    def upsert_snapshot(self, snapshot: TrustContextSnapshot) -> TrustContextSnapshot:
        payload = snapshot.model_dump(mode='json')
        payload['supporting_context_json'] = json.dumps(payload['supporting_context_json'], sort_keys=True)
        columns = ', '.join(payload.keys())
        placeholders = ', '.join(':' + key for key in payload.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in payload.keys() if key != 'trust_context_snapshot_id')
        with self.db.cursor() as cur:
            cur.execute(
                f"INSERT INTO trust_context_snapshot ({columns}) VALUES ({placeholders}) "
                f"ON CONFLICT(trust_context_snapshot_id) DO UPDATE SET {updates}",
                payload,
            )
        return snapshot


class SqliteTrainingFeedbackRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def create_feedback_event(self, event: TrainingFeedbackEvent) -> TrainingFeedbackEvent:
        payload = event.model_dump(mode='json')
        columns = ', '.join(payload.keys())
        placeholders = ', '.join(':' + key for key in payload.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in payload.keys() if key != 'training_feedback_event_id')
        with self.db.cursor() as cur:
            cur.execute(
                f"INSERT INTO training_feedback_event ({columns}) VALUES ({placeholders}) "
                f"ON CONFLICT(training_feedback_event_id) DO UPDATE SET {updates}",
                payload,
            )
        return event


class SqliteFileEventRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def create_file_event(self, event: FileEvent) -> FileEvent:
        payload = event.model_dump(mode='json')
        cols = ', '.join(payload.keys())
        placeholders = ', '.join(':' + key for key in payload.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in payload.keys() if key != 'file_event_id')
        with self.db.cursor() as cur:
            cur.execute(
                f"INSERT INTO file_event ({cols}) VALUES ({placeholders}) ON CONFLICT(file_event_id) DO UPDATE SET {updates}",
                payload,
            )
        return event

    def get_file_event(self, file_event_id: str) -> FileEvent | None:
        row = self.db.conn.execute('SELECT * FROM file_event WHERE file_event_id = ?', (file_event_id,)).fetchone()
        return _row_to_model(FileEvent, row)

    def list_file_events(self, *, asset_id: str | None = None, verdict: str | None = None, page: int = 1, page_size: int = 50) -> tuple[list[FileEvent], int]:
        filters: list[str] = []
        params: list[Any] = []
        joins = ['LEFT JOIN (SELECT mv1.* FROM malware_verdict mv1 JOIN (SELECT file_event_id, MAX(created_ts) AS created_ts FROM malware_verdict GROUP BY file_event_id) latest ON latest.file_event_id = mv1.file_event_id AND latest.created_ts = mv1.created_ts) mv ON mv.file_event_id = fe.file_event_id']
        if asset_id:
            filters.append('fe.asset_id = ?')
            params.append(asset_id)
        if verdict:
            filters.append('mv.verdict = ?')
            params.append(verdict)
        where = ('WHERE ' + ' AND '.join(filters)) if filters else ''
        count_sql = 'SELECT COUNT(*) AS n FROM file_event fe ' + ' '.join(joins) + ' ' + where
        total = int(self.db.conn.execute(count_sql, params).fetchone()['n'])
        offset = (page - 1) * page_size
        sql = 'SELECT fe.* FROM file_event fe ' + ' '.join(joins) + ' ' + where + ' ORDER BY fe.ts DESC LIMIT ? OFFSET ?'
        rows = self.db.conn.execute(sql, [*params, page_size, offset]).fetchall()
        return ([_row_to_model(FileEvent, row) for row in rows], total)


class SqliteMalwareVerdictRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def create_verdict(self, verdict: MalwareVerdict) -> MalwareVerdict:
        payload = verdict.model_dump(mode='json')
        cols = ', '.join(payload.keys())
        placeholders = ', '.join(':' + key for key in payload.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in payload.keys() if key != 'malware_verdict_id')
        with self.db.cursor() as cur:
            cur.execute(
                f"INSERT INTO malware_verdict ({cols}) VALUES ({placeholders}) ON CONFLICT(malware_verdict_id) DO UPDATE SET {updates}",
                payload,
            )
        return verdict

    def latest_verdict_for_file_event(self, file_event_id: str) -> MalwareVerdict | None:
        row = self.db.conn.execute('SELECT * FROM malware_verdict WHERE file_event_id = ? ORDER BY created_ts DESC LIMIT 1', (file_event_id,)).fetchone()
        return _row_to_model(MalwareVerdict, row)

    def list_verdicts(self, *, asset_id: str | None = None, malicious_only: bool = False) -> list[MalwareVerdict]:
        filters: list[str] = []
        params: list[Any] = []
        joins = ['LEFT JOIN file_event fe ON fe.file_event_id = mv.file_event_id']
        if asset_id:
            filters.append('fe.asset_id = ?')
            params.append(asset_id)
        if malicious_only:
            filters.append("mv.verdict IN ('malicious', 'suspicious')")
        where = ('WHERE ' + ' AND '.join(filters)) if filters else ''
        rows = self.db.conn.execute('SELECT mv.* FROM malware_verdict mv ' + ' '.join(joins) + ' ' + where + ' ORDER BY mv.created_ts DESC', params).fetchall()
        return [_row_to_model(MalwareVerdict, row) for row in rows]


class SqliteQuarantineRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def create_record(self, record: QuarantineRecord) -> QuarantineRecord:
        payload = record.model_dump(mode='json')
        cols = ', '.join(payload.keys())
        placeholders = ', '.join(':' + key for key in payload.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in payload.keys() if key != 'quarantine_record_id')
        with self.db.cursor() as cur:
            cur.execute(
                f"INSERT INTO quarantine_record ({cols}) VALUES ({placeholders}) ON CONFLICT(quarantine_record_id) DO UPDATE SET {updates}",
                payload,
            )
        return record

    def list_records(self, *, asset_id: str | None = None) -> list[QuarantineRecord]:
        if asset_id:
            rows = self.db.conn.execute('SELECT * FROM quarantine_record WHERE asset_id = ? ORDER BY created_ts DESC', (asset_id,)).fetchall()
        else:
            rows = self.db.conn.execute('SELECT * FROM quarantine_record ORDER BY created_ts DESC').fetchall()
        return [_row_to_model(QuarantineRecord, row) for row in rows]

    def get_record(self, quarantine_record_id: str) -> QuarantineRecord | None:
        row = self.db.conn.execute('SELECT * FROM quarantine_record WHERE quarantine_record_id = ?', (quarantine_record_id,)).fetchone()
        return _row_to_model(QuarantineRecord, row)

    def update_record(self, quarantine_record_id: str, **updates) -> QuarantineRecord | None:
        current = self.get_record(quarantine_record_id)
        if current is None:
            return None
        payload = current.model_dump(mode='python')
        payload.update({k: v for k, v in updates.items() if v is not None})
        updated = QuarantineRecord(**payload)
        return self.create_record(updated)


class SqliteWebVerdictRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def create_web_verdict(self, verdict: WebVerdict) -> WebVerdict:
        payload = verdict.model_dump(mode='json')
        cols = ', '.join(payload.keys())
        placeholders = ', '.join(':' + key for key in payload.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in payload.keys() if key != 'web_verdict_id')
        with self.db.cursor() as cur:
            cur.execute(
                f"INSERT INTO web_verdict ({cols}) VALUES ({placeholders}) ON CONFLICT(web_verdict_id) DO UPDATE SET {updates}",
                payload,
            )
        return verdict

    def list_web_verdicts(self, *, asset_id: str | None = None, blocked_only: bool = False) -> list[WebVerdict]:
        filters: list[str] = []
        params: list[Any] = []
        if asset_id:
            filters.append('asset_id = ?')
            params.append(asset_id)
        if blocked_only:
            filters.append("verdict IN ('block', 'warn')")
        where = ('WHERE ' + ' AND '.join(filters)) if filters else ''
        rows = self.db.conn.execute('SELECT * FROM web_verdict ' + where + ' ORDER BY created_ts DESC', params).fetchall()
        return [_row_to_model(WebVerdict, row) for row in rows]


class SqliteBehaviorAlertRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def create_alert(self, alert: BehaviorAlert) -> BehaviorAlert:
        payload = alert.model_dump(mode='json')
        payload['indicators_json'] = json.dumps(payload['indicators_json'], sort_keys=True)
        cols = ', '.join(payload.keys())
        placeholders = ', '.join(':' + key for key in payload.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in payload.keys() if key != 'behavior_alert_id')
        with self.db.cursor() as cur:
            cur.execute(
                f"INSERT INTO behavior_alert ({cols}) VALUES ({placeholders}) ON CONFLICT(behavior_alert_id) DO UPDATE SET {updates}",
                payload,
            )
        return alert

    def list_alerts(self, *, asset_id: str | None = None, min_severity: str | None = None) -> list[BehaviorAlert]:
        severity_rank = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        filters: list[str] = []
        params: list[Any] = []
        if asset_id:
            filters.append('asset_id = ?')
            params.append(asset_id)
        where = ('WHERE ' + ' AND '.join(filters)) if filters else ''
        rows = self.db.conn.execute('SELECT * FROM behavior_alert ' + where + ' ORDER BY created_ts DESC', params).fetchall()
        alerts = [_row_to_model(BehaviorAlert, row, json_fields={'indicators_json': dict}) for row in rows]
        if min_severity:
            threshold = severity_rank[min_severity]
            alerts = [item for item in alerts if severity_rank[item.severity] >= threshold]
        return alerts

    def get_alert(self, behavior_alert_id: str) -> BehaviorAlert | None:
        row = self.db.conn.execute('SELECT * FROM behavior_alert WHERE behavior_alert_id = ?', (behavior_alert_id,)).fetchone()
        return _row_to_model(BehaviorAlert, row, json_fields={'indicators_json': dict})


class SqliteRansomwareSignalRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def create_signal(self, signal: RansomwareSignal) -> RansomwareSignal:
        payload = signal.model_dump(mode='json')
        payload['indicators_json'] = json.dumps(payload['indicators_json'], sort_keys=True)
        cols = ', '.join(payload.keys())
        placeholders = ', '.join(':' + key for key in payload.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in payload.keys() if key != 'ransomware_signal_id')
        with self.db.cursor() as cur:
            cur.execute(f"INSERT INTO ransomware_signal ({cols}) VALUES ({placeholders}) ON CONFLICT(ransomware_signal_id) DO UPDATE SET {updates}", payload)
        return signal

    def list_signals(self, *, asset_id: str | None = None, min_severity: str | None = None) -> list[RansomwareSignal]:
        severity_rank = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        filters: list[str] = []
        params: list[Any] = []
        if asset_id:
            filters.append('asset_id = ?')
            params.append(asset_id)
        where = ('WHERE ' + ' AND '.join(filters)) if filters else ''
        rows = self.db.conn.execute('SELECT * FROM ransomware_signal ' + where + ' ORDER BY created_ts DESC', params).fetchall()
        items = [_row_to_model(RansomwareSignal, row, json_fields={'indicators_json': dict}) for row in rows]
        if min_severity:
            threshold = severity_rank[min_severity]
            items = [item for item in items if severity_rank[item.severity] >= threshold]
        return items

    def get_signal(self, ransomware_signal_id: str) -> RansomwareSignal | None:
        row = self.db.conn.execute('SELECT * FROM ransomware_signal WHERE ransomware_signal_id = ?', (ransomware_signal_id,)).fetchone()
        return _row_to_model(RansomwareSignal, row, json_fields={'indicators_json': dict})


class SqliteRemediationActionRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def create_action(self, action: RemediationAction) -> RemediationAction:
        payload = action.model_dump(mode='json')
        cols = ', '.join(payload.keys())
        placeholders = ', '.join(':' + key for key in payload.keys())
        updates = ', '.join(f"{key}=excluded.{key}" for key in payload.keys() if key != 'remediation_action_id')
        with self.db.cursor() as cur:
            cur.execute(f"INSERT INTO remediation_action ({cols}) VALUES ({placeholders}) ON CONFLICT(remediation_action_id) DO UPDATE SET {updates}", payload)
        return action

    def list_actions(self, *, asset_id: str | None = None, status: str | None = None) -> list[RemediationAction]:
        filters: list[str] = []
        params: list[Any] = []
        if asset_id:
            filters.append('asset_id = ?')
            params.append(asset_id)
        if status:
            filters.append('status = ?')
            params.append(status)
        where = ('WHERE ' + ' AND '.join(filters)) if filters else ''
        rows = self.db.conn.execute('SELECT * FROM remediation_action ' + where + ' ORDER BY created_ts DESC', params).fetchall()
        return [_row_to_model(RemediationAction, row) for row in rows]

    def get_action(self, remediation_action_id: str) -> RemediationAction | None:
        row = self.db.conn.execute('SELECT * FROM remediation_action WHERE remediation_action_id = ?', (remediation_action_id,)).fetchone()
        return _row_to_model(RemediationAction, row)


class SqliteEnforcementRepository:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    def create_event(self, event: EnforcementEvent) -> EnforcementEvent:
        with self.db.cursor() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO enforcement_event (
                    enforcement_event_id, rule_id, backend, action, status, connection_id, policy_decision_id,
                    message, command_preview, backend_rule_ref, execution_mode, backend_state, applied_ts, effective_until
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.enforcement_event_id,
                    event.rule_id,
                    event.backend,
                    event.action,
                    event.status,
                    event.connection_id,
                    event.policy_decision_id,
                    event.message,
                    json.dumps(event.command_preview),
                    event.backend_rule_ref,
                    event.execution_mode,
                    event.backend_state,
                    event.applied_ts.isoformat(),
                    event.effective_until.isoformat() if event.effective_until else None,
                ),
            )
        return event

    def list_events(self, *, rule_id: str | None = None, connection_id: str | None = None, policy_decision_id: str | None = None) -> list[EnforcementEvent]:
        clauses: list[str] = []
        args: list[object] = []
        if rule_id:
            clauses.append('rule_id = ?')
            args.append(rule_id)
        if connection_id:
            clauses.append('connection_id = ?')
            args.append(connection_id)
        if policy_decision_id:
            clauses.append('policy_decision_id = ?')
            args.append(policy_decision_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ''
        query = 'SELECT * FROM enforcement_event' + where + ' ORDER BY applied_ts DESC'
        with self.db.cursor() as cur:
            rows = cur.execute(query, args).fetchall()
        return [_row_to_model(EnforcementEvent, row, json_fields={'command_preview': list}) for row in rows]

    def latest_event_for_rule(self, rule_id: str) -> EnforcementEvent | None:
        with self.db.cursor() as cur:
            row = cur.execute('SELECT * FROM enforcement_event WHERE rule_id = ? ORDER BY applied_ts DESC LIMIT 1', (rule_id,)).fetchone()
        return _row_to_model(EnforcementEvent, row, json_fields={'command_preview': list})


class SqliteRepositories:
    def __init__(self, path: str | Path = ':memory:') -> None:
        self.db = SqliteDatabase(path)
        self.connections = SqliteConnectionRepository(self.db)
        self.processes = SqliteProcessIdentityRepository(self.db)
        self.destinations = SqliteDestinationIdentityRepository(self.db)
        self.decisions = SqliteDecisionRepository(self.db)
        self.rules = SqliteRuleRepository(self.db)
        self.trust = SqliteTrustSnapshotRepository(self.db)
        self.feedback = SqliteTrainingFeedbackRepository(self.db)
        self.enforcement = SqliteEnforcementRepository(self.db)
        self.files = SqliteFileEventRepository(self.db)
        self.malware_verdicts = SqliteMalwareVerdictRepository(self.db)
        self.quarantine = SqliteQuarantineRepository(self.db)
        self.web_verdicts = SqliteWebVerdictRepository(self.db)
        self.behavior_alerts = SqliteBehaviorAlertRepository(self.db)
        self.ransomware_signals = SqliteRansomwareSignalRepository(self.db)
        self.remediation_actions = SqliteRemediationActionRepository(self.db)
        self.training = self.feedback

    @classmethod
    def from_database(cls, db: SqliteDatabase) -> 'SqliteRepositories':
        self = cls.__new__(cls)
        self.db = db
        self.connections = SqliteConnectionRepository(db)
        self.processes = SqliteProcessIdentityRepository(db)
        self.destinations = SqliteDestinationIdentityRepository(db)
        self.decisions = SqliteDecisionRepository(db)
        self.rules = SqliteRuleRepository(db)
        self.trust = SqliteTrustSnapshotRepository(db)
        self.feedback = SqliteTrainingFeedbackRepository(db)
        self.enforcement = SqliteEnforcementRepository(db)
        self.files = SqliteFileEventRepository(db)
        self.malware_verdicts = SqliteMalwareVerdictRepository(db)
        self.quarantine = SqliteQuarantineRepository(db)
        self.web_verdicts = SqliteWebVerdictRepository(db)
        self.behavior_alerts = SqliteBehaviorAlertRepository(db)
        self.ransomware_signals = SqliteRansomwareSignalRepository(db)
        self.remediation_actions = SqliteRemediationActionRepository(db)
        self.training = self.feedback
        return self

    def close(self) -> None:
        self.db.close()
