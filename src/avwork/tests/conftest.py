from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Keep the suite offline and deterministic: host capture must not perform real
# PTR lookups against whatever sockets happen to be open on the test machine.
os.environ.setdefault('EGRET_REVERSE_DNS', '0')
