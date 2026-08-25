from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter

from app.services.enforcement.host_validation import validate_all_backends
from app.services.release.manifest import generate_release_manifest

router = APIRouter(prefix='/api/v1/release', tags=['release'])


@router.get('/manifest')
def manifest() -> dict:
    root = Path(__file__).resolve().parents[3]
    return generate_release_manifest(root).to_dict()


@router.get('/rollout-readiness')
def rollout_readiness() -> dict:
    results = validate_all_backends()
    ready = sum(1 for result in results if result.ready_for_native_validation)
    return {
        'status': 'ready' if ready == len(results) else 'needs-attention',
        'ready_backends': ready,
        'total_backends': len(results),
        'items': [result.to_dict() for result in results],
    }


@router.get('/final-status')
def final_status() -> dict:
    results = validate_all_backends()
    ready = sum(1 for result in results if result.ready_for_native_validation)
    return {
        'engineering_bundle_complete': True,
        'external_rollout_steps_remaining': [
            'real host validation on target operating systems',
            'production signing/notarization',
            'distribution/installer publishing',
            'merge and rollout in the production repo',
        ],
        'native_validation_ready_backends': ready,
        'native_validation_total_backends': len(results),
        'items': [result.to_dict() for result in results],
    }
