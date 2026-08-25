from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.demo.sample_data import seed_demo_data
from app.storage.bootstrap import bootstrap_application


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Seed demo Egret telemetry into a local SQLite database.')
    parser.add_argument('--db-path', type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    state = bootstrap_application(args.db_path)
    try:
        result = seed_demo_data(state.repositories)
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    finally:
        state.database.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
