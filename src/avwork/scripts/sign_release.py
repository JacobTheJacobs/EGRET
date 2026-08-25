from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.release.signing import sign_file


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit('usage: python scripts/sign_release.py <artifact>')
    artifact = Path(sys.argv[1]).resolve()
    if not artifact.exists():
        raise SystemExit(f'artifact not found: {artifact}')
    print(sign_file(artifact))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
