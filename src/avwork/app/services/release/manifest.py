from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.services.enforcement.capabilities import probe_all_backends

ROOT_RELEASE_FILES = ('README.md', 'requirements.txt', 'package.json', 'bun.lock', 'tsconfig.json', 'index.html', 'vite.config.ts')


@dataclass(frozen=True)
class ReleaseManifest:
    name: str
    version: str
    generated_at: str
    included_docs: list[str]
    included_workflows: list[str]
    included_installers: list[str]
    included_runtime: list[str]
    included_root_files: list[str]
    enforcement_capabilities: list[dict]
    notes: list[str]

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'version': self.version,
            'generated_at': self.generated_at,
            'included_docs': list(self.included_docs),
            'included_workflows': list(self.included_workflows),
            'included_installers': list(self.included_installers),
            'included_runtime': list(self.included_runtime),
            'included_root_files': list(self.included_root_files),
            'enforcement_capabilities': list(self.enforcement_capabilities),
            'notes': list(self.notes),
        }


def generate_release_manifest(root: Path, *, version: str = '12.0.0-rc1') -> ReleaseManifest:
    docs_dir = root / 'docs'
    workflows_dir = root / '.github' / 'workflows'
    docs = sorted(path.relative_to(root).as_posix() for path in docs_dir.glob('*.md')) if docs_dir.exists() else []
    workflows = sorted(path.relative_to(root).as_posix() for path in workflows_dir.glob('*.yml')) if workflows_dir.exists() else []
    installers_dir = root / 'installers'
    installers = sorted(path.relative_to(root).as_posix() for path in installers_dir.rglob('*') if path.is_file()) if installers_dir.exists() else []
    runtime_dir = root / 'runtime'
    runtime = sorted(path.relative_to(root).as_posix() for path in runtime_dir.rglob('*') if path.is_file()) if runtime_dir.exists() else []
    root_files = sorted(name for name in ROOT_RELEASE_FILES if (root / name).exists())
    return ReleaseManifest(
        name='egret',
        version=version,
        generated_at=datetime.now(timezone.utc).isoformat(),
        included_docs=docs,
        included_workflows=workflows,
        included_installers=installers,
        included_runtime=runtime,
        included_root_files=root_files,
        enforcement_capabilities=[cap.to_dict() for cap in probe_all_backends()],
        notes=[
            'Release manifest generated from repo workspace.',
            'Native execution may still require host-level validation and signing.',
        ],
    )
