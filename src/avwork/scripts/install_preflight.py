from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.enforcement.capabilities import probe_all_backends
from app.services.demo.sample_data import seed_demo_data
from app.services.install.service_config import ServiceConfigInput, write_service_configs
from app.services.release.signing import verify_signature
from app.storage.bootstrap import bootstrap_application


def default_data_dir() -> Path:
    configured = os.getenv('EGRET_DATA_DIR')
    if configured:
        return Path(configured)
    return Path(tempfile.gettempdir()) / 'egret'


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Prepare local Egret runtime state before host install/startup.')
    parser.add_argument('--data-dir', type=Path, default=default_data_dir(), help='Writable runtime state directory.')
    parser.add_argument('--artifact', type=Path, default=ROOT / 'dist' / 'egret-v12-release-candidate.zip')
    parser.add_argument('--manifest', type=Path, default=ROOT / 'dist' / 'release-manifest.json')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--ingest-token', default=None, help='Use a specific live telemetry ingest token. Defaults to env, existing token file, or a generated secret.')
    parser.add_argument('--seed-demo-data', action='store_true', help='Seed clearly marked demo telemetry when the database is empty.')
    parser.add_argument('--skip-signature-check', action='store_true', help='Allow unsigned local development installs.')
    return parser.parse_args()


def verify_release_files(artifact: Path, manifest: Path, *, skip_signature_check: bool) -> dict:
    artifact_exists = artifact.exists()
    manifest_exists = manifest.exists()
    artifact_signature_valid = False
    manifest_signature_valid = False
    if artifact_exists and not skip_signature_check:
        try:
            artifact_signature_valid = verify_signature(artifact)
        except FileNotFoundError:
            artifact_signature_valid = False
    if manifest_exists and not skip_signature_check:
        try:
            manifest_signature_valid = verify_signature(manifest)
        except FileNotFoundError:
            manifest_signature_valid = False
    if not skip_signature_check and (not artifact_signature_valid or not manifest_signature_valid):
        print(
            json.dumps(
                {
                    'status': 'failed',
                    'reason': 'release signature verification failed',
                    'artifact_exists': artifact_exists,
                    'manifest_exists': manifest_exists,
                    'artifact_signature_valid': artifact_signature_valid,
                    'manifest_signature_valid': manifest_signature_valid,
                },
                indent=2,
            )
        )
        raise SystemExit(1)
    return {
        'artifact': str(artifact),
        'manifest': str(manifest),
        'artifact_exists': artifact_exists,
        'manifest_exists': manifest_exists,
        'signature_check_skipped': skip_signature_check,
        'artifact_signature_valid': artifact_signature_valid,
        'manifest_signature_valid': manifest_signature_valid,
    }


def ensure_ingest_token(data_dir: Path, explicit_token: str | None) -> tuple[str, Path, bool]:
    token_file = data_dir / 'ingest-token'
    if explicit_token:
        token = explicit_token
        generated = False
    elif os.getenv('EGRET_INGEST_TOKEN'):
        token = os.environ['EGRET_INGEST_TOKEN']
        generated = False
    elif token_file.exists():
        token = token_file.read_text(encoding='utf-8').strip()
        generated = False
    else:
        token = secrets.token_urlsafe(32)
        generated = True
    token_file.write_text(token + '\n', encoding='utf-8')
    try:
        token_file.chmod(0o600)
    except OSError:
        pass
    return token, token_file, generated


def main() -> int:
    args = parse_args()
    data_dir = args.data_dir.resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    content_dir = data_dir / 'content'
    backend_state_dir = data_dir / 'backend-state'
    service_config_dir = data_dir / 'service'
    content_dir.mkdir(exist_ok=True)
    backend_state_dir.mkdir(exist_ok=True)
    db_path = data_dir / 'egret.sqlite3'
    ingest_token, ingest_token_file, ingest_token_generated = ensure_ingest_token(data_dir, args.ingest_token)
    release = verify_release_files(args.artifact.resolve(), args.manifest.resolve(), skip_signature_check=args.skip_signature_check)
    service_configs = write_service_configs(
        ServiceConfigInput(
            app_dir=ROOT,
            data_dir=data_dir,
            db_path=db_path,
            content_dir=content_dir,
            backend_state_dir=backend_state_dir,
            host=args.host,
            port=args.port,
            python_executable=args.python,
            ingest_token=ingest_token,
        ),
        service_config_dir,
    )
    state = bootstrap_application(db_path)
    try:
        demo_seed = seed_demo_data(state.repositories).to_dict() if args.seed_demo_data else None
        payload = {
            'status': 'ok',
            'data_dir': str(data_dir),
            'db_path': str(db_path),
            'content_dir': str(content_dir),
            'backend_state_dir': str(backend_state_dir),
            'ingest_token_file': str(ingest_token_file),
            'ingest_token_generated': ingest_token_generated,
            'ingest_token_preview': ingest_token[-6:],
            'security': {
                'ingest_token_configured': True,
                'ingest_token_file': str(ingest_token_file),
                'secret_values_exposed': False,
            },
            'service_config_dir': str(service_config_dir),
            'service_configs': service_configs.to_dict(),
            'demo_seed': demo_seed,
            'applied_migrations': state.migrations.applied_files,
            'release': release,
            'enforcement_capabilities': [cap.to_dict() for cap in probe_all_backends()],
            'environment': {
                'EGRET_DB_PATH': str(db_path),
                'EGRET_CONTENT_DIR': str(content_dir),
                'EGRET_BACKEND_STATE_DIR': str(backend_state_dir),
                'EGRET_INGEST_TOKEN_FILE': str(ingest_token_file),
            },
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    finally:
        state.database.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
