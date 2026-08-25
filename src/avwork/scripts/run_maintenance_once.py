from __future__ import annotations

from pathlib import Path
import json
import sys

from app.storage.bootstrap import bootstrap_application
from app.jobs.maintenance import run_maintenance_cycle


def main(argv: list[str]) -> int:
    db_path = Path(argv[1]) if len(argv) > 1 else Path(':memory:')
    state = bootstrap_application(db_path)
    summary = run_maintenance_cycle(state.repositories)
    print(json.dumps(summary.__dict__, indent=2, sort_keys=True))
    state.database.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
