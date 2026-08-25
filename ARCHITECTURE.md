# Egret Architecture

Egret is an outbound control plane and Linux network monitor: it identifies which process is talking to the network, what that binary actually is, and applies allow/deny policy to it.

The repo has two source lines:
*   `src/avwork`: the Python/FastAPI control plane, SQLite state, policy logic, capture, AV services, and the React/TSX web UI.
*   `egret-qt`: the compiled C++/Qt6 desktop client, driven entirely by the REST API.

`littlesnitch-linux` is **not** part of this repository. It is GPL-2.0 source from Objective Development, kept out of the tree so its licence does not attach to this project; clone it alongside if you need the packet-path reference.

## Tech Stack
*   **Backend:** Python 3.13 with FastAPI
*   **Database:** SQLite (Managed via raw `.sql` migrations in `app/storage/migrations`)
*   **Frontend:** React / TSX (`app/ui`) served from `app/web/dist`, plus a C++/Qt6 desktop client in `egret-qt`
*   **Host Capture:** `/proc/net/{tcp,tcp6,udp,udp6}` read directly — no `ss` subprocess — with inode-to-pid attribution from `/proc/<pid>/fd`
*   **Provenance:** package ownership (`dpkg -S`) and SHA-256 of each executable, since Linux has no per-binary code signature
*   **Linux Packet Path:** not implemented; enforcement is observe-only
*   **Installers:** Cross-platform scripts (macOS `install.sh`, Linux `install.sh`, Windows `install.ps1`)

## Core System Boundaries

### 1. API Layer (`app/api/v1`)
Exposes RESTful endpoints for the frontend and CLI integrations. Key routing namespaces include:
*   `connections`, `decisions`, `rules`, `investigations`
*   `enforcement`, `files`, `threats`, `quarantine`
*   `protection`, `remediation`, `ransomware`, `scans`
*   `updates`, `health`, `release`

### 2. Services (`app/services`)
Contains the core business and domain logic of the application.
*   **Antivirus (AV):** Realtime protection, on-access scanning, remediation, signature updates, and unpacking.
    *   Blocklist matching follows the Little Snitch Linux behavior: a listed domain matches both the exact host and subdomains.
*   **Behavior:** Anomaly detection, behavioral alerting.
*   **Enforcement:** Compiles network policies and delegates to OS-specific backends:
    *   **macOS:** `pfctl`, `socketfilterfw`
    *   **Windows:** PowerShell
    *   **Linux:** `nftables` (`nft`), generated but not executed unless `EGRET_ENABLE_NATIVE_EXECUTION=1`
*   **Enrichment:** Certificate parsing, DNS enrichment, TLS metadata extraction.
*   **Investigations:** Connection timeline builders and explainability.
*   **Policy:** Evaluates security rules, handles specificity conflicts, and expiry cleanups.
*   **Ransomware:** Signal detection and canary file management.
*   **Prompting & Learning:** LLM explanation builders, feature labeling, and replay extraction.

### 3. Storage Layer (`app/storage`)
Handles state persistence directly via SQLite.
*   **Migrations:** Ordered SQL files defining the schema (e.g., `0118_process_identity_v1.sql`).
*   **Repositories:** Database access patterns utilizing raw SQL and interfaces.

### 4. Telemetry (`app/telemetry`)
Handles system event capture, training feedback reconstruction, and event replays for auditing.

### 5. UI Components (`app/ui`)
React-based components using TypeScript (`.tsx`). It is grouped by feature modules (e.g., `connections/`, `enforcement/`, `rules/`, `quarantine/`).

## Execution & Native Capabilities
*   Native execution defaults to an audit/preview mode.
*   To enable live native enforcement, use the environment variable:
    `EDGE_NET_GUARDIAN_ENABLE_NATIVE_EXECUTION=1`
*   State synchronization handles applying compiled rules to the actual host firewall.

## Known Gaps
These are the honest limits of the current build, in rough priority order:

*   **Enforcement does not block.** Rule verdicts are evaluated, stored, and previewed, but no packet is ever dropped. Two command generators exist and disagree: `native_commands.py` emits valid host commands and runs only when native execution is enabled, while `compiler.py` produces display-only strings that are *not* valid to execute. Keep them in sync when changing either.
*   **No sensors behind the detection layer.** The antivirus, ransomware, and behaviour services are scoring functions with full test coverage and nothing feeding them: there is no filesystem watcher anywhere in the tree, and the signature content pack is a placeholder. They only produce output for telemetry posted by hand.
*   **Root-owned processes cannot be named** unless the backend runs privileged, because `/proc/<pid>/fd` is restricted. Capture falls back to the owning account name.
*   **Capture is a poll, not an interception.** Sockets are sampled on an interval, so short-lived connections can be missed entirely and nothing is ever held pending a user decision. Closing that gap needs a kernel-level path (eBPF), which is why the upstream reference is worth keeping nearby.

## Release & CI Pipeline
*   Release packaging creates signed manifests and binaries.
*   GitHub Actions (`.github/workflows`) handles validation matrices, CI tests, and Release Candidate builds.
