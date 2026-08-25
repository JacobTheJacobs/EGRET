from __future__ import annotations

import os
import shutil
from pathlib import Path


def resolve_binary(binary: str) -> str | None:
    resolved = shutil.which(binary)
    if resolved:
        return resolved

    raw_path = os.getenv('PATH', '')
    for candidate_dir in _candidate_path_entries(raw_path):
        candidate = Path(candidate_dir) / binary
        if candidate.exists():
            return str(candidate)
        if os.name == 'nt':
            for suffix in ('.exe', '.cmd', '.bat', '.ps1'):
                candidate_with_suffix = candidate.with_name(candidate.name + suffix)
                if candidate_with_suffix.exists():
                    return str(candidate_with_suffix)
    return None


def _candidate_path_entries(raw_path: str) -> list[str]:
    entries = [item for item in raw_path.split(os.pathsep) if item]
    if os.name != 'nt':
        return entries

    candidates = set(entries)
    for index, char in enumerate(raw_path):
        if char not in {':', ';'}:
            continue
        prefix = raw_path[:index]
        suffix = raw_path[index + 1 :]
        if prefix:
            candidates.add(prefix)
        if suffix:
            candidates.update(item for item in suffix.split(os.pathsep) if item)
    return [item for item in candidates if item]
