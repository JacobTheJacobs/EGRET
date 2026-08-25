from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone

from app.models.process_identity import ProcessIdentity
from app.storage.repositories.sqlite import SqliteRepositories

NOW = datetime(2026, 8, 7, 12, 0, 0, tzinfo=timezone.utc)


def test_shared_connection_survives_concurrent_readers_and_writers(tmp_path) -> None:
    """One connection is shared across FastAPI's threadpool.

    Without serialisation, overlapping requests raise
    ``sqlite3.InterfaceError: bad parameter or other API misuse``.
    """
    repos = SqliteRepositories(str(tmp_path / 'concurrent.sqlite3'))

    def write_then_read(index: int) -> str | None:
        identity = ProcessIdentity(
            process_identity_id=f'pi_{index}',
            asset_id='host-1',
            session_id='session-1',
            process_id=index,
            process_name=f'proc{index}',
            process_path=f'/usr/bin/proc{index}',
            first_seen_ts=NOW,
            last_seen_ts=NOW,
        )
        repos.processes.upsert_process_identity(identity)
        stored = repos.processes.get_process_identity(f'pi_{index}')
        return stored.process_name if stored else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(write_then_read, range(64)))

    assert results == [f'proc{i}' for i in range(64)]


def test_connection_with_no_decision_counts_as_awaiting(tmp_path) -> None:
    """The ingest endpoints create connections without evaluating policy.

    The detail layer presents those as 'ask', so the verdict filter must treat a
    missing decision the same way or Health disagrees with the table beside it.
    """
    from app.storage.adapters.legacy_flow_adapter import LegacyFlowDualWriter, LegacyFlowRecord

    repos = SqliteRepositories(str(tmp_path / 'undecided.sqlite3'))
    writer = LegacyFlowDualWriter(
        connections=repos.connections, processes=repos.processes, destinations=repos.destinations
    )
    writer.write(
        LegacyFlowRecord(
            asset_id='host-1', session_id='session-1', process_id=1,
            process_name='ingested', process_path='/usr/bin/ingested', start_ts=NOW,
            remote_ip='9.9.9.9', remote_port=443, transport='tcp',
            network_zone='public_internet',
        )
    )

    _, awaiting = repos.connections.list_connections(page=1, page_size=1, verdict='ask')
    assert awaiting == 1
