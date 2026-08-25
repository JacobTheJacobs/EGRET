from __future__ import annotations

from pathlib import Path

from app.services.av.blocklists import domain_matches_entry
from app.services.av.updater import ContentUpdaterService
from app.services.av.reputation import url_reputation


def test_domain_blocklist_matches_exact_and_subdomains() -> None:
    assert domain_matches_entry('evil.example', 'evil.example') is True
    assert domain_matches_entry('cdn.evil.example', 'evil.example') is True
    assert domain_matches_entry('evil.example.safe', 'evil.example') is False
    assert domain_matches_entry('cdn.evil.example.', '*.evil.example') is True


def test_content_pack_domain_blocks_subdomains(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv('EDGE_NET_GUARDIAN_CONTENT_DIR', str(tmp_path))
    ContentUpdaterService().install_json(
        {
            'version': 'egret-blocklists-1',
            'signatures': [],
            'malicious_hashes': {},
            'trusted_signers': [],
            'malicious_domains': ['evil.example'],
            'phishing_domains': ['login.example'],
        }
    )

    assert url_reputation('cdn.evil.example') == ('malicious', 'block', 0.99)
    assert url_reputation('secure.login.example') == ('phishing', 'block', 0.98)
