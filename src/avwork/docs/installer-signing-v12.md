# Installer and Signing Plan for v12

## Packaging outputs
- application bundle or service package
- migrations bundle
- release manifest
- detached JSON release signature or attestation

## Production signing path
- set `EGRET_RELEASE_SIGNING_KEY` and `EGRET_RELEASE_SIGNING_KEY_ID` in the release environment for keyed HMAC release signatures
- sign native helper binaries separately where required
- attach release manifest to the signed artifact
- verify signatures during install and startup

## Installer integration goals
- run `python scripts/install_preflight.py` after release finalization
- create or verify writable data directories
- run safe migration bootstrap before first start
- verify release artifact and manifest signatures unless explicitly skipped for local development
- verify enforcement backend prerequisites
- emit startup health summary with runtime environment paths
- generate systemd, launchd, and Windows service configuration files under the runtime data directory
