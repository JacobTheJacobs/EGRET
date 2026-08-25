from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from app.storage.adapters.legacy_flow_adapter import LegacyFlowDualWriter, LegacyFlowRecord
from app.storage.repositories.sqlite import SqliteRepositories


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Backfill legacy flow records into connection_event v1 using sqlite repositories.')
    parser.add_argument('--input-jsonl', required=True, help='Path to a JSONL file of legacy flow records.')
    parser.add_argument('--sqlite-db', required=True, help='Path to the sqlite database file to populate.')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repos = SqliteRepositories(args.sqlite_db)
    writer = LegacyFlowDualWriter(
        connections=repos.connections,
        processes=repos.processes,
        destinations=repos.destinations,
    )
    count = 0
    input_path = Path(args.input_jsonl)
    with input_path.open('r', encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            payload['start_ts'] = datetime.fromisoformat(payload['start_ts'])
            if payload.get('end_ts'):
                payload['end_ts'] = datetime.fromisoformat(payload['end_ts'])
            writer.write(LegacyFlowRecord(**payload))
            count += 1
    print(f'Backfilled {count} legacy flow records into {args.sqlite_db}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
