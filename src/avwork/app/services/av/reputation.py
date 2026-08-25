from __future__ import annotations

import hashlib
from dataclasses import dataclass

from app.services.av.blocklists import domain_matches_any, normalize_domain
from app.services.av.content_unpack import load_active_pack


MALICIOUS_HASHES = {
    hashlib.sha256(b'mimikatz-test-payload').hexdigest(): ('Malware.Test.Mimikatz', 'CredentialTheft.Test'),
}
TRUSTED_SIGNERS = {'Apple', 'Microsoft', 'Google', 'Mozilla'}
MALICIOUS_DOMAINS = {'evil.example', 'stealer.bad', 'malware.test'}
PHISHING_DOMAINS = {'login-microsoft.verify.bad', 'secure-banking-check.example'}


@dataclass(frozen=True)
class FileReputation:
    reputation_score: float
    cloud_lookup_hit: bool
    signature_name: str | None = None
    family_name: str | None = None


def _pack_data() -> tuple[dict[str, tuple[str, str]], set[str], set[str], set[str]]:
    pack = load_active_pack()
    malicious_hashes = {
        key: (value.get('signature_name', 'ContentPack.Signature'), value.get('family_name', 'Custom.Threat'))
        for key, value in pack.get('malicious_hashes', {}).items()
    }
    trusted_signers = set(pack.get('trusted_signers', []))
    malicious_domains = set(pack.get('malicious_domains', []))
    phishing_domains = set(pack.get('phishing_domains', []))
    return malicious_hashes, trusted_signers, malicious_domains, phishing_domains


def file_reputation(sha256: str, signer_name: str | None = None) -> FileReputation | None:
    pack_hashes, pack_trusted, _, _ = _pack_data()
    merged_hashes = {**MALICIOUS_HASHES, **pack_hashes}
    merged_signers = set(TRUSTED_SIGNERS) | pack_trusted
    if sha256 in merged_hashes:
        signature_name, family_name = merged_hashes[sha256]
        return FileReputation(reputation_score=0.99, cloud_lookup_hit=True, signature_name=signature_name, family_name=family_name)
    if signer_name and signer_name in merged_signers:
        return FileReputation(reputation_score=0.05, cloud_lookup_hit=True)
    return None


def url_reputation(domain: str) -> tuple[str, str, float]:
    _, _, pack_malicious, pack_phishing = _pack_data()
    domain = normalize_domain(domain)
    merged_malicious = set(MALICIOUS_DOMAINS) | pack_malicious
    merged_phishing = set(PHISHING_DOMAINS) | pack_phishing
    if domain_matches_any(domain, merged_malicious):
        return 'malicious', 'block', 0.99
    if domain_matches_any(domain, merged_phishing):
        return 'phishing', 'block', 0.98
    if domain.endswith('.zip-downloads.bad'):
        return 'suspicious', 'warn', 0.72
    return 'benign', 'allow', 0.05
