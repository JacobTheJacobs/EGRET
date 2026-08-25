# Egret v12 Support Runbook

## Key endpoints
- `/healthz`
- `/api/v1/health/status`
- `/api/v1/enforcement/reconciliation`

## Safe defaults
- Native OS execution is disabled unless `EGRET_ENABLE_NATIVE_EXECUTION=1`
- Legacy `EDGE_NET_GUARDIAN_ENABLE_NATIVE_EXECUTION=1` is still accepted for compatibility.
- Enforcement remains audited even in simulated mode

## First checks
1. Check health status and migration list.
2. Check connection and rule counts.
3. Check enforcement events and reconciliation.
4. Re-run maintenance once if expiries look stale.
