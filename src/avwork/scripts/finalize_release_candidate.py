from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.release.manifest import generate_release_manifest
from app.services.release.signing import sign_file
from scripts.frontend_tool import frontend_command


def run(cmd: list[str]) -> None:
    completed = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace')
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, end='')
        if completed.stderr:
            print(completed.stderr, end='', file=sys.stderr)
        raise SystemExit(completed.returncode)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Finalize Egret v12 release candidate.')
    parser.add_argument('--skip-tests', action='store_true', help='Skip pytest before packaging.')
    parser.add_argument('--skip-frontend', action='store_true', help='Skip frontend typecheck/build before packaging.')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    if not args.skip_tests:
        run([sys.executable, '-m', 'pytest', '-q'])
    if not args.skip_frontend:
        run(frontend_command('typecheck'))
        run(frontend_command('build'))
    run([sys.executable, 'scripts/package_release.py'])
    manifest_path = dist / 'release-manifest.json'
    manifest = generate_release_manifest(ROOT, version='12.0.0-final-candidate').to_dict()
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    artifact = dist / 'egret-v12-release-candidate.zip'
    artifact_signature = None
    if artifact.exists():
        artifact_signature = sign_file(artifact)
    manifest_signature = sign_file(manifest_path)
    print(json.dumps({
        'status': 'ok',
        'artifact': str(artifact),
        'artifact_signature': str(artifact_signature) if artifact_signature else None,
        'manifest': str(manifest_path),
        'manifest_signature': str(manifest_signature),
        'tests_verified': not args.skip_tests,
        'frontend_verified': not args.skip_frontend,
    }, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
