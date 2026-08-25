from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.release.signing import verify_signature
from scripts.frontend_tool import frontend_command

REQUIRED_ARCHIVE_PATHS = [
    'README.md',
    'requirements.txt',
    'package.json',
    'bun.lock',
    'tsconfig.json',
    'index.html',
    'vite.config.ts',
    'app/web/dist/index.html',
    'scripts/sign_release.py',
    'scripts/finalize_release_candidate.py',
    'scripts/install_preflight.py',
    'scripts/generate_service_config.py',
    'scripts/seed_demo_data.py',
    'scripts/live_smoke_test.py',
    'runtime/content/default-pack.json',
    'installers/linux/install.sh',
    'installers/macos/install.sh',
    'installers/windows/install.ps1',
    '.github/workflows/v12-ci.yml',
    '.github/workflows/release-candidate.yml',
    '.github/workflows/native-validation-matrix.yml',
]


def run(cmd: list[str], *, cwd: Path = ROOT) -> None:
    completed = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding='utf-8', errors='replace')
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, end='')
        if completed.stderr:
            print(completed.stderr, end='', file=sys.stderr)
        raise SystemExit(completed.returncode)


def clean_extract_boot_check(artifact: Path) -> None:
    with tempfile.TemporaryDirectory(prefix='egret-release-') as tmp:
        extract_dir = Path(tmp) / 'release'
        with zipfile.ZipFile(artifact) as archive:
            archive.extractall(extract_dir)
        script = (
            "from fastapi.testclient import TestClient\n"
            "from app.main import create_app\n"
            "client = TestClient(create_app())\n"
            "root = client.get('/', follow_redirects=False)\n"
            "assert root.headers['location'] == '/connections'\n"
            "response = client.get('/connections')\n"
            "assert response.status_code == 200\n"
            "assert 'Egret' in response.text\n"
        )
        run([sys.executable, '-c', script], cwd=extract_dir)


def inspect_archive(artifact: Path) -> dict:
    with zipfile.ZipFile(artifact) as archive:
        names = set(archive.namelist())
    missing = [path for path in REQUIRED_ARCHIVE_PATHS if path not in names]
    has_js = any(name.startswith('app/web/dist/assets/') and name.endswith('.js') for name in names)
    has_css = any(name.startswith('app/web/dist/assets/') and name.endswith('.css') for name in names)
    if missing or not has_js or not has_css:
        raise SystemExit(
            json.dumps(
                {
                    'archive_valid': False,
                    'missing': missing,
                    'has_compiled_js': has_js,
                    'has_compiled_css': has_css,
                },
                indent=2,
            )
        )
    return {'file_count': len(names), 'has_compiled_js': has_js, 'has_compiled_css': has_css}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run Egret production readiness checks.')
    parser.add_argument('--skip-tests', action='store_true', help='Skip pytest. Use only after tests already passed in the same pipeline.')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run(frontend_command('typecheck'))
    run(frontend_command('build'))
    if not args.skip_tests:
        run([sys.executable, '-m', 'pytest', '-q'])
    run([sys.executable, 'scripts/live_smoke_test.py'])
    run([sys.executable, 'scripts/finalize_release_candidate.py', '--skip-tests'])
    artifact = ROOT / 'dist' / 'egret-v12-release-candidate.zip'
    manifest = ROOT / 'dist' / 'release-manifest.json'
    archive_summary = inspect_archive(artifact)
    clean_extract_boot_check(artifact)
    artifact_signature_valid = verify_signature(artifact)
    manifest_signature_valid = verify_signature(manifest)
    if not artifact_signature_valid or not manifest_signature_valid:
        raise SystemExit('release signature verification failed')
    print(
        json.dumps(
            {
                'status': 'ok',
                'artifact': str(artifact),
                'manifest': str(manifest),
                'artifact_signature_valid': artifact_signature_valid,
                'manifest_signature_valid': manifest_signature_valid,
                'clean_extract_boot': True,
                'archive': archive_summary,
            },
            indent=2,
        )
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
