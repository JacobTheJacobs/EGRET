# Egret Release Checklist

## Pre-release
- Run full pytest suite
- Run `bun install`, `bun run typecheck`, and `bun run build`
- Run `python scripts/verify_production.py --skip-tests`
- Install from `requirements.txt` in a clean virtual environment
- Verify migration bootstrap on a fresh database
- Verify health endpoint returns migration summary
- Verify enforcement apply path works in simulated mode on all supported backends
- Verify native execution remains disabled by default
- Verify runtime content packs and installer scripts are present in the release archive
- Verify compiled UI assets are present in `app/web/dist`
- Run `python scripts/install_preflight.py --data-dir <writable-runtime-dir>`
- Review generated service files under `<writable-runtime-dir>/service`
- Set `EGRET_RELEASE_SIGNING_KEY` and `EGRET_RELEASE_SIGNING_KEY_ID` in the release environment when producing keyed release signatures

## Release
- Package source bundle
- Generate release signatures with `python scripts/finalize_release_candidate.py` or `python scripts/sign_release.py <artifact>`
- Publish release notes
- Publish support runbook
- Record artifact checksums

## Post-release
- Monitor health/status endpoint
- Review enforcement reconciliation drift
- Review prompt volume and false block reports
