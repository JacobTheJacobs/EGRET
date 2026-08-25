from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_finalize_release_candidate_creates_manifest_and_signature(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, 'scripts/finalize_release_candidate.py', '--skip-tests'],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout.splitlines()[-1] if result.stdout.strip().startswith('{') is False else result.stdout)
    manifest = Path(payload['manifest'])
    assert manifest.exists()
    assert Path(payload['artifact']).exists()
    assert Path(payload['artifact_signature']).exists()
    assert Path(payload['manifest_signature']).exists()
    assert payload['frontend_verified'] is True
