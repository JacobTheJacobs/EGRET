# Egret

Egret combines outbound network control, Little Snitch-style visibility, policy enforcement, threat detection, quarantine, remediation, release tooling, and Linux packet-path work from the in-tree `littlesnitch-linux` source.

Included:
- unified outbound control plane
- live Connections, Rules, Trust, Investigations, Enforcement, Health, Release, Files, Threats, Quarantine, Protection, Scans, and Updates surfaces
- sqlite-backed integration path
- replay, training feedback, and release manifest generation
- native backend capability probing and guarded execution paths
- installer scripts, runtime content packs, release finalization scripts, and reproducible Python dependencies

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
bun install
bun run typecheck
bun run build
python scripts/live_smoke_test.py
python scripts/verify_production.py --skip-tests
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Fresh databases start empty until telemetry is imported. For a local demo dataset:

```bash
python scripts/seed_demo_data.py --db-path ./egret.sqlite3
EGRET_DB_PATH=./egret.sqlite3 uvicorn app.main:app --host 127.0.0.1 --port 8000
```

For live telemetry, run the app against a persistent `EGRET_DB_PATH`, set `EGRET_INGEST_TOKEN`, and POST sensor data with either `X-Egret-Ingest-Token: <token>` or `Authorization: Bearer <token>`:

- `POST /api/v1/ingest/connections` for process-aware network flow records.
- `POST /api/v1/ingest/trust-snapshots` for trust context attached to connection rows and investigations.

`python scripts/install_preflight.py` creates or reuses `<data-dir>/ingest-token`, injects it into generated systemd/launchd/Windows service configs, and prints only the token file path plus a short preview.

## Release

```bash
python scripts/finalize_release_candidate.py
python scripts/live_smoke_test.py
python scripts/verify_production.py --skip-tests
python scripts/validate_native_backends.py
```

Native execution is disabled unless `EGRET_ENABLE_NATIVE_EXECUTION=1` is explicitly set. Legacy `EDGE_NET_GUARDIAN_ENABLE_NATIVE_EXECUTION=1` is still accepted during migration. Real host validation, platform signing, notarization, and installer distribution still require the target production infrastructure.
