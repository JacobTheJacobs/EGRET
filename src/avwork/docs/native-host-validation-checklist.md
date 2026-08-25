# Native Host Validation Checklist

## Goal
Validate that each backend can execute native firewall commands safely on a real host before enabling broad rollout.

## Per-host checks
- Confirm the backend binaries exist and are in PATH.
- Confirm the host is in a maintenance or test ring.
- Confirm `EGRET_ENABLE_NATIVE_EXECUTION=1` is set intentionally.
- Run `python scripts/validate_native_backends.py`.
- Review the command preview for the target backend.
- Apply one temporary validation rule and verify backend state.
- Roll back the validation rule and confirm cleanup.

## Backend notes
### macOS
- Validate `pfctl` and `socketfilterfw` availability.
- Confirm a rollback path is documented before applying any native rule.

### Windows
- Validate PowerShell execution policy for firewall rule creation.
- Confirm rule cleanup rights are present for the operator account.

### Linux
- Validate `nft` exists and the target table/chain are present or bootstrapped.
- Confirm rule cleanup and service restart behavior are documented.
