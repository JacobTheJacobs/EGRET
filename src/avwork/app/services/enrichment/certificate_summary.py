from __future__ import annotations

from typing import Optional


def summarize_certificate(
    *,
    subject: Optional[str],
    issuer: Optional[str],
    fingerprint: Optional[str],
) -> str:
    pieces: list[str] = []
    if subject:
        pieces.append(f"Subject: {subject}")
    if issuer:
        pieces.append(f"Issuer: {issuer}")
    if fingerprint:
        short_fp = fingerprint[:12] + "…" if len(fingerprint) > 12 else fingerprint
        pieces.append(f"Fingerprint: {short_fp}")
    return " | ".join(pieces) if pieces else "No certificate details available"
