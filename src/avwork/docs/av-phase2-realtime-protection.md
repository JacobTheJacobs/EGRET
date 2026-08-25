# AV Phase 2 — Realtime protection and first behavior blocker

This pack extends the baseline AV layer with:
- download scanning with URL reputation correlation
- execute-time scanning
- stored behavior alerts
- a first behavior blocker for:
  - downloaded payload execution
  - persistence abuse
  - office-to-shell spawn chains
  - ransomware precursors
  - malware phone-home patterns

Key APIs:
- `POST /api/v1/files/download-scan`
- `POST /api/v1/files/execute-scan`
- `POST /api/v1/threats/behavior-evaluate`
- `GET /api/v1/threats`
- `GET /api/v1/protection/status`
