from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.enforcement.host_validation import validate_backend_host


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Validate one backend on the current host.')
    parser.add_argument('--backend', required=True, choices=['macos', 'windows', 'linux'])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = validate_backend_host(args.backend)
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.ready_for_native_validation else 2


if __name__ == '__main__':
    raise SystemExit(main())
