from __future__ import annotations


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip('.')
    if domain.startswith('*.'):
        domain = domain[2:]
    # Rules are written both ways — ".example.com" and "example.com" — and both
    # must mean the same thing. Keeping the leading dot would turn the boundary
    # check below into an impossible "..example.com" comparison.
    return domain.lstrip('.')


def domain_matches_entry(domain: str, entry: str) -> bool:
    normalized_domain = normalize_domain(domain)
    normalized_entry = normalize_domain(entry)
    if not normalized_domain or not normalized_entry:
        return False
    return normalized_domain == normalized_entry or normalized_domain.endswith(f'.{normalized_entry}')


def domain_matches_any(domain: str, entries: set[str] | list[str] | tuple[str, ...]) -> bool:
    return any(domain_matches_entry(domain, entry) for entry in entries)
