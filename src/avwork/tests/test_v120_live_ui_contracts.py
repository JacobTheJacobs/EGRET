from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_ui(path: str) -> str:
    return (ROOT / 'app' / 'ui' / path).read_text(encoding='utf-8')


def test_enforcement_page_uses_client_side_live_fetch() -> None:
    page = read_ui('enforcement/page.tsx')
    assert 'export default async function' not in page
    assert 'fetchEnforcementEvents()' in page
    assert 'fetchEnforcementReconciliation()' in page
    assert 'useEffect' in page


def test_rules_page_persists_edits_through_api() -> None:
    page = read_ui('rules/page.tsx')
    api = read_ui('rules/api.ts')
    assert 'createRule(rule)' in page
    assert 'updateRule(ruleId' in page
    assert 'r_${Date.now()}' not in page
    assert 'method: "POST"' in api
    assert 'method: "PATCH"' in api


def test_investigations_discovers_live_assets_from_connections() -> None:
    page = read_ui('investigations/page.tsx')
    timeline = read_ui('investigations/timeline.tsx')
    assert 'fetchConnections({ page_size: 100 })' in page
    assert 'setAssetId((current) => current || assets[0] || "")' in page
    assert 'JSON.stringify' not in timeline


def test_threats_page_renders_typed_live_sections() -> None:
    page = read_ui('threats/page.tsx')
    assert 'fetch("/api/v1/threats")' in page
    assert 'JSON.stringify' not in page
    assert 'Malware Verdicts' in page
    assert 'Web Verdicts' in page
    assert 'Behavior Alerts' in page
    assert 'Ransomware Signals' in page


def test_scans_page_submits_live_scans_and_refreshes_persisted_events() -> None:
    page = read_ui('scans/page.tsx')
    assert '"/api/v1/files/scan"' in page
    assert 'method: "POST"' in page
    assert '"/api/v1/files?page_size=8"' in page
    assert 'Run scan' in page
    assert 'Recent persisted file events' in page


def test_connections_page_captures_live_host_data_not_demo_seed() -> None:
    page = read_ui('connections/page.tsx')
    api = read_ui('connections/api.ts')
    assert 'captureHostConnections' in page
    assert 'Capture host connections now' in page
    assert 'seed_demo_data.py' not in page
    assert 'scripts/seed_demo_data.py' not in page
    assert 'connections/capture-host' in api
    assert 'method: "POST"' in api
