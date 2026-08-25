from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'
DIST.mkdir(exist_ok=True)
OUT = DIST / 'egret-v12-release-candidate.zip'
MANIFEST = DIST / 'release-manifest.json'

INCLUDE_TOP = ['app', 'docs', 'scripts', 'tests', 'installers', 'runtime', '.github']
INCLUDE_FILES = ['README.md', 'requirements.txt', 'package.json', 'bun.lock', 'tsconfig.json', 'index.html', 'vite.config.ts']
REQUIRED_PACKAGE_PATHS = [
    *INCLUDE_FILES,
    'app/web/dist/index.html',
    'scripts/verify_production.py',
    'scripts/install_preflight.py',
    'scripts/generate_service_config.py',
    'scripts/seed_demo_data.py',
    'scripts/live_smoke_test.py',
    'runtime/content/default-pack.json',
    'installers/linux/install.sh',
    'installers/macos/install.sh',
    'installers/windows/install.ps1',
]


def validate_required_paths() -> None:
    missing = [name for name in REQUIRED_PACKAGE_PATHS if not (ROOT / name).exists()]
    if missing:
        raise SystemExit(f'missing required release paths: {", ".join(missing)}')


def iter_files():
    for name in INCLUDE_FILES:
        path = ROOT / name
        if path.exists() and path.is_file():
            yield path
    for top in INCLUDE_TOP:
        path = ROOT / top
        if path.exists():
            for file in path.rglob('*'):
                if file.is_file() and '__pycache__' not in file.parts and not file.name.endswith('.pyc'):
                    yield file


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    validate_required_paths()
    files = list(iter_files())
    with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file in files:
            zf.write(file, file.relative_to(ROOT))
    manifest = {
        'artifact': OUT.name,
        'sha256': sha256(OUT),
        'included_roots': INCLUDE_TOP,
        'included_root_files': INCLUDE_FILES,
        'file_count': len(files),
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
