"""Linux socket enumeration straight from ``/proc``.

Replaces shelling out to ``ss``. Identifying *who* is connecting is the whole
point of the product, and ``ss`` reports a process only for sockets owned by the
calling uid — everything else came back as ``unknown``.

``/proc/net/{tcp,tcp6,udp,udp6}`` is world-readable and carries the owning uid
and socket inode for *every* socket on the host. Mapping inode to pid still
needs ``/proc/<pid>/fd``, which is restricted, so this module degrades in one
step instead of falling off a cliff:

1. process name and path, when ``/proc/<pid>/fd`` is readable;
2. otherwise the owning account (``root``, ``systemd-resolve``, …), which is
   still an identity;
3. ``unknown`` only when the uid itself cannot be resolved.

Run the backend as root and step 1 covers everything.
"""

from __future__ import annotations

import glob
import os
import pwd
import socket
import struct
from dataclasses import dataclass

#: TCP_ESTABLISHED, and the equivalent for connected UDP sockets.
_ESTABLISHED = '01'

_PROC_NET_FILES = (
    ('/proc/net/tcp', 'tcp', False),
    ('/proc/net/tcp6', 'tcp', True),
    ('/proc/net/udp', 'udp', False),
    ('/proc/net/udp6', 'udp', True),
)


@dataclass(frozen=True)
class ProcSocket:
    transport: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    uid: int
    inode: str


def _parse_address(token: str, is_ipv6: bool) -> tuple[str, int] | None:
    """Decode a ``HEXADDR:HEXPORT`` field from /proc/net."""
    if ':' not in token:
        return None
    raw_address, raw_port = token.rsplit(':', 1)
    try:
        port = int(raw_port, 16)
    except ValueError:
        return None

    try:
        if is_ipv6:
            # Sixteen bytes stored as four little-endian 32-bit words.
            words = struct.unpack('<4I', bytes.fromhex(raw_address))
            packed = struct.pack('>4I', *words)
            address = socket.inet_ntop(socket.AF_INET6, packed)
        else:
            packed = struct.pack('<I', int(raw_address, 16))
            address = socket.inet_ntop(socket.AF_INET, packed)
    except (ValueError, OSError, struct.error):
        return None
    return address, port


def read_sockets() -> list[ProcSocket]:
    """Every established socket on the host, with its owning uid."""
    sockets: list[ProcSocket] = []
    for path, transport, is_ipv6 in _PROC_NET_FILES:
        try:
            with open(path, 'r', encoding='utf-8') as handle:
                lines = handle.read().splitlines()[1:]
        except OSError:
            continue

        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != _ESTABLISHED:
                continue
            local = _parse_address(fields[1], is_ipv6)
            remote = _parse_address(fields[2], is_ipv6)
            if local is None or remote is None or remote[1] == 0:
                continue
            try:
                uid = int(fields[7])
            except ValueError:
                continue
            sockets.append(
                ProcSocket(
                    transport=transport,
                    local_ip=local[0],
                    local_port=local[1],
                    remote_ip=remote[0],
                    remote_port=remote[1],
                    uid=uid,
                    inode=fields[9],
                )
            )
    return sockets


def build_inode_owner_map() -> dict[str, tuple[int, str, str]]:
    """Map socket inode to ``(pid, process_name, process_path)``.

    Only covers processes whose ``/proc/<pid>/fd`` this user may read; as root
    that is every process on the host.
    """
    owners: dict[str, tuple[int, str, str]] = {}
    for fd_dir in glob.glob('/proc/[0-9]*/fd'):
        pid_text = fd_dir.split('/')[2]
        try:
            entries = os.listdir(fd_dir)
        except OSError:
            continue  # not ours to read

        inodes = []
        for entry in entries:
            try:
                link = os.readlink(f'{fd_dir}/{entry}')
            except OSError:
                continue
            if link.startswith('socket:['):
                inodes.append(link[8:-1])
        if not inodes:
            continue

        try:
            pid = int(pid_text)
        except ValueError:
            continue
        name = _read_comm(pid_text)
        path = _read_exe(pid_text) or name
        for inode in inodes:
            owners[inode] = (pid, name, path)
    return owners


def username_for_uid(uid: int) -> str | None:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def _read_comm(pid_text: str) -> str:
    try:
        with open(f'/proc/{pid_text}/comm', 'r', encoding='utf-8') as handle:
            return handle.read().strip()
    except OSError:
        return ''


def _read_exe(pid_text: str) -> str:
    try:
        return os.readlink(f'/proc/{pid_text}/exe')
    except OSError:
        return ''
