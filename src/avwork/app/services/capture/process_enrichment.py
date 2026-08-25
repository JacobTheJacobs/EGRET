"""Answer *what* is connecting, not just *who*.

``ProcessIdentity`` already models executable hash, package ownership, signer
status, parent pid, and owning account — every one of them was left NULL by host
capture, so the UI could name a process but never say whether it was trustworthy.

Linux has no per-binary code signature to check. The equivalent trust signal is
package provenance: a binary owned by a distro package arrived through a signed
repository, while an unpackaged binary in a home directory reaching the network
is exactly the shape of a threat worth prompting about.

Every lookup is cached: package queries by path, hashes by (path, mtime, size).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass, field

#: Hashing exists to support reputation lookups; a binary far larger than any
#: real executable is not worth stalling a capture over.
MAX_HASH_BYTES = 256 * 1024 * 1024

#: The enricher is module-level and long-lived, so its caches need ceilings.
MAX_CACHE_ENTRIES = 2048

#: Paths owned by the system, used when no package manager is available.
_SYSTEM_PREFIXES = ('/usr/bin/', '/usr/sbin/', '/usr/lib/', '/bin/', '/sbin/', '/lib/')


@dataclass(frozen=True)
class ProcessProvenance:
    executable_hash: str | None = None
    package_id: str | None = None
    signer_name: str | None = None
    signer_status: str | None = None
    parent_process_id: int | None = None
    service_name: str | None = None


@dataclass
class ProcessEnricher:
    """Resolves provenance for executables seen during capture."""

    _package_cache: dict[str, tuple[str | None, str | None]] = field(default_factory=dict, repr=False)
    _hash_cache: dict[tuple[str, int, int], str] = field(default_factory=dict, repr=False)
    _dpkg: str | None = field(default=None, repr=False)
    _dpkg_resolved: bool = field(default=False, repr=False)

    def enrich(self, *, pid: int, path: str, account: str | None) -> ProcessProvenance:
        package_id, signer_name = self._package_for(path)
        return ProcessProvenance(
            executable_hash=self._hash_for(path),
            package_id=package_id,
            signer_name=signer_name,
            signer_status=self._signer_status(path, package_id),
            parent_process_id=_parent_pid(pid) if pid else None,
            service_name=account,
        )

    # -- provenance --------------------------------------------------------
    def _signer_status(self, path: str, package_id: str | None) -> str:
        if package_id:
            # Arrived via a signed distribution repository.
            return 'trusted'
        if not path or not path.startswith('/') or not os.path.isfile(path):
            return 'unknown'
        if path.startswith(_SYSTEM_PREFIXES):
            # System location but unclaimed by any package: worth noticing.
            return 'unknown'
        return 'unsigned'

    def _package_for(self, path: str) -> tuple[str | None, str | None]:
        if not path or not path.startswith('/'):
            return None, None
        cached = self._package_cache.get(path)
        if cached is not None:
            return cached

        result: tuple[str | None, str | None] = (None, None)
        dpkg = self._dpkg_path()
        if dpkg is not None:
            try:
                completed = subprocess.run(
                    [dpkg, '-S', path], capture_output=True, text=True, timeout=5, check=False
                )
            except (OSError, subprocess.SubprocessError):
                completed = None
            if completed is not None and completed.returncode == 0 and ':' in completed.stdout:
                package = completed.stdout.split(':', 1)[0].strip()
                if package:
                    result = (package, 'distribution package')

        if len(self._package_cache) >= MAX_CACHE_ENTRIES:
            self._package_cache.clear()
        self._package_cache[path] = result
        return result

    def _dpkg_path(self) -> str | None:
        if not self._dpkg_resolved:
            self._dpkg = shutil.which('dpkg')
            self._dpkg_resolved = True
        return self._dpkg

    # -- hashing -----------------------------------------------------------
    def _hash_for(self, path: str) -> str | None:
        if not path or not path.startswith('/'):
            return None
        try:
            info = os.stat(path)
        except OSError:
            return None
        if info.st_size > MAX_HASH_BYTES:
            return None

        key = (path, int(info.st_mtime), info.st_size)
        cached = self._hash_cache.get(key)
        if cached is not None:
            return cached

        digest = hashlib.sha256()
        try:
            with open(path, 'rb') as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                    digest.update(chunk)
        except OSError:
            return None

        value = digest.hexdigest()
        if len(self._hash_cache) >= MAX_CACHE_ENTRIES:
            self._hash_cache.clear()
        self._hash_cache[key] = value
        return value


def _parent_pid(pid: int) -> int | None:
    try:
        with open(f'/proc/{pid}/stat', 'r', encoding='utf-8') as handle:
            content = handle.read()
    except OSError:
        return None
    # The comm field is parenthesised and may contain spaces, so split after it.
    closing = content.rfind(')')
    if closing == -1:
        return None
    fields = content[closing + 2 :].split()
    if len(fields) < 2:
        return None
    try:
        return int(fields[1])
    except ValueError:
        return None
