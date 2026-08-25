from __future__ import annotations

from pathlib import Path

from app.services.release.manifest import generate_release_manifest


def test_release_manifest_includes_docs_and_workflows(tmp_path: Path) -> None:
    (tmp_path / 'docs').mkdir()
    (tmp_path / '.github' / 'workflows').mkdir(parents=True)
    (tmp_path / 'docs' / 'release-notes-v12.0.md').write_text('# notes', encoding='utf-8')
    (tmp_path / '.github' / 'workflows' / 'v12-ci.yml').write_text('name: ci', encoding='utf-8')
    (tmp_path / 'package.json').write_text('{}', encoding='utf-8')
    (tmp_path / 'bun.lock').write_text('', encoding='utf-8')
    (tmp_path / 'tsconfig.json').write_text('{}', encoding='utf-8')
    (tmp_path / 'index.html').write_text('<div></div>', encoding='utf-8')
    (tmp_path / 'vite.config.ts').write_text('export default {}', encoding='utf-8')
    manifest = generate_release_manifest(tmp_path, version='12.0.0-test')
    payload = manifest.to_dict()
    assert payload['version'] == '12.0.0-test'
    assert payload['name'] == 'egret'
    assert 'docs/release-notes-v12.0.md' in payload['included_docs']
    assert '.github/workflows/v12-ci.yml' in payload['included_workflows']
    assert payload['included_root_files'] == ['bun.lock', 'index.html', 'package.json', 'tsconfig.json', 'vite.config.ts']
    assert 'enforcement_capabilities' in payload
