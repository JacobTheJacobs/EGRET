"""Best-effort reverse DNS for captured host connections.

Host capture reads sockets from ``/proc``, which reports addresses but never
names. Without a name there is nothing to write a domain rule against, so every
new CDN address produces a fresh prompt. A PTR lookup is not as good as the SNI
a real packet path would see, but it is enough to make ``domain_suffix`` rules
viable and it needs no privileges.

Lookups are cached (including failures) so repeated polls cost nothing, and the
whole batch runs under a wall-clock deadline so a slow resolver can never stall
a capture.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

DEFAULT_TTL_SECONDS = 3600
DEFAULT_TIMEOUT_SECONDS = 2.0
DEFAULT_MAX_WORKERS = 16
#: The resolver outlives every capture, so its cache needs a ceiling.
MAX_CACHE_ENTRIES = 4096


@dataclass
class _CacheEntry:
    hostname: str | None
    expires_at: datetime


@dataclass
class ReverseDnsResolver:
    """Threaded PTR resolver with a TTL cache.

    Only globally routable addresses are looked up; private, loopback, and
    link-local addresses have no meaningful PTR record and would only add
    latency.
    """

    ttl_seconds: int = DEFAULT_TTL_SECONDS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_workers: int = DEFAULT_MAX_WORKERS
    _cache: dict[str, _CacheEntry] = field(default_factory=dict, repr=False)

    def resolve_many(self, ips: Iterable[str], now: datetime | None = None) -> dict[str, str]:
        """Return ``{ip: hostname}`` for every address that resolved."""
        moment = now or datetime.now(timezone.utc)
        resolved: dict[str, str] = {}
        pending: list[str] = []

        for ip in {candidate for candidate in ips if candidate}:
            entry = self._cache.get(ip)
            if entry is not None and entry.expires_at > moment:
                if entry.hostname:
                    resolved[ip] = entry.hostname
                continue
            if not _is_resolvable(ip):
                self._remember(ip, None, moment)
                continue
            pending.append(ip)

        if not pending:
            return resolved

        # The pool is deliberately not used as a context manager: __exit__ calls
        # shutdown(wait=True), which blocks on in-flight lookups and would make
        # the deadline below meaningless. A hung resolver must not stall a
        # capture, so abandoned threads are left to finish on their own and the
        # pool is torn down without waiting.
        pool = ThreadPoolExecutor(max_workers=min(self.max_workers, len(pending)))
        try:
            futures = {pool.submit(self._lookup, ip): ip for ip in pending}
            try:
                for future in as_completed(futures, timeout=self.timeout_seconds):
                    ip = futures[future]
                    hostname = future.result()
                    self._remember(ip, hostname, moment)
                    if hostname:
                        resolved[ip] = hostname
            except FuturesTimeoutError:
                for future, ip in futures.items():
                    if not future.done():
                        # Cache the miss briefly so the next poll is not stalled again.
                        self._remember(ip, None, moment, ttl_seconds=60)
                        future.cancel()
        finally:
            pool.shutdown(wait=False)

        return resolved

    def _lookup(self, ip: str) -> str | None:
        # No socket.setdefaulttimeout here: it is process-global and would apply
        # to the web server's own sockets. The resolver's own timeout governs,
        # and an abandoned thread finishes harmlessly in the background.
        try:
            hostname, _aliases, _addresses = socket.gethostbyaddr(ip)
        except (OSError, socket.herror, socket.gaierror):
            return None
        hostname = hostname.strip().rstrip('.')
        return hostname or None

    def _remember(self, ip: str, hostname: str | None, now: datetime, ttl_seconds: int | None = None) -> None:
        ttl = self.ttl_seconds if ttl_seconds is None else ttl_seconds
        if len(self._cache) >= MAX_CACHE_ENTRIES:
            self._evict(now)
        self._cache[ip] = _CacheEntry(hostname=hostname, expires_at=now + timedelta(seconds=ttl))

    def _evict(self, now: datetime) -> None:
        """Drop expired entries, then oldest-first if that was not enough."""
        for ip in [ip for ip, entry in self._cache.items() if entry.expires_at <= now]:
            del self._cache[ip]
        overflow = len(self._cache) - MAX_CACHE_ENTRIES + 1
        if overflow > 0:
            for ip in sorted(self._cache, key=lambda k: self._cache[k].expires_at)[:overflow]:
                del self._cache[ip]


def _is_resolvable(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast
