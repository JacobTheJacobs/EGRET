from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.release.manifest import generate_release_manifest


if __name__ == '__main__':
    out = ROOT / 'dist' / 'release-manifest.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    manifest = generate_release_manifest(ROOT)
    out.write_text(json.dumps(manifest.to_dict(), indent=2), encoding='utf-8')
    print(out)
