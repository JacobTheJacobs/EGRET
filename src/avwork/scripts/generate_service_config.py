from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.install.service_config import ServiceConfigInput, write_service_configs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Generate Egret host service configuration files.')
    parser.add_argument('--app-dir', type=Path, default=ROOT)
    parser.add_argument('--data-dir', type=Path, default=Path(tempfile.gettempdir()) / 'egret')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist' / 'service')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--ingest-token', default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data_dir = args.data_dir.resolve()
    config = ServiceConfigInput(
        app_dir=args.app_dir.resolve(),
        data_dir=data_dir,
        db_path=data_dir / 'egret.sqlite3',
        content_dir=data_dir / 'content',
        backend_state_dir=data_dir / 'backend-state',
        host=args.host,
        port=args.port,
        python_executable=args.python,
        ingest_token=args.ingest_token,
    )
    paths = write_service_configs(config, args.output_dir.resolve())
    print(json.dumps(paths.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
