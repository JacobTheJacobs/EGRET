from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.enforcement.host_validation import validate_all_backends


if __name__ == '__main__':
    print(json.dumps([item.to_dict() for item in validate_all_backends()], indent=2))
