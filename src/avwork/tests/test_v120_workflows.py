from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ci_workflow_runs_python_and_frontend_gates() -> None:
    workflow = (ROOT / '.github' / 'workflows' / 'v12-ci.yml').read_text(encoding='utf-8')
    assert 'pip install -r requirements.txt' in workflow
    assert 'bun install --frozen-lockfile' in workflow
    assert 'bun run typecheck' in workflow
    assert 'bun run build' in workflow
    assert 'python -m pytest -q' in workflow


def test_release_workflow_finalizes_and_uploads_candidate() -> None:
    workflow = (ROOT / '.github' / 'workflows' / 'release-candidate.yml').read_text(encoding='utf-8')
    assert 'python scripts/verify_production.py' in workflow
    assert 'dist/egret-v12-release-candidate.zip' in workflow
    assert 'dist/release-manifest.json.sig' in workflow


def test_production_verify_script_covers_release_gates() -> None:
    script = (ROOT / 'scripts' / 'verify_production.py').read_text(encoding='utf-8')
    assert "run(frontend_command('typecheck'))" in script
    assert "run(frontend_command('build'))" in script
    assert "run([sys.executable, '-m', 'pytest', '-q'])" in script
    assert "scripts/finalize_release_candidate.py" in script
    assert "scripts/live_smoke_test.py" in script
    assert 'clean_extract_boot_check(artifact)' in script
    assert 'verify_signature(artifact)' in script
    assert 'verify_signature(manifest)' in script
    assert "'scripts/install_preflight.py'" in script
    assert "'scripts/generate_service_config.py'" in script
    assert "'scripts/seed_demo_data.py'" in script
    assert "'scripts/live_smoke_test.py'" in script


def test_native_validation_matrix_uses_matching_operating_systems() -> None:
    workflow = (ROOT / '.github' / 'workflows' / 'native-validation-matrix.yml').read_text(encoding='utf-8')
    assert 'backend: macos' in workflow
    assert 'os: macos-latest' in workflow
    assert 'backend: windows' in workflow
    assert 'os: windows-latest' in workflow
    assert 'backend: linux' in workflow
    assert 'os: ubuntu-latest' in workflow
    assert "EGRET_ENABLE_NATIVE_EXECUTION: '1'" in workflow
    assert 'sudo apt-get update && sudo apt-get install -y nftables' in workflow
