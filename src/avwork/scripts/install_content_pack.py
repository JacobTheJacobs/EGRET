from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.av.updater import ContentUpdaterService


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('pack_path')
    args = parser.parse_args()
    pack = json.loads(Path(args.pack_path).read_text(encoding='utf-8'))
    status = ContentUpdaterService().install_json(pack)
    print(json.dumps(status, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
