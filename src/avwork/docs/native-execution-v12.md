# Egret native execution in v12

## Summary
v12 now includes executable backend adapters for macOS, Windows, and Linux. Native execution remains opt-in and requires platform binaries plus appropriate privileges.

## Enablement
Set:

```bash
EGRET_ENABLE_NATIVE_EXECUTION=1
```

Then verify capability status through `GET /api/v1/health/status` or `GET /api/v1/enforcement/capabilities`.
The legacy `EDGE_NET_GUARDIAN_ENABLE_NATIVE_EXECUTION` variable is still accepted during migration.

## Backend requirements
- macOS: `pfctl`, `socketfilterfw`
- Windows: `powershell`
- Linux: `nft`

## Safety model
- when execution is disabled, rules are still compiled, audited, and stored in backend state
- when execution is enabled but binaries are missing, the audit trail records the missing prerequisite
- execution remains previewable before apply
