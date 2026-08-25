# AI Instructions for Egret

This project is the cumulative codebase for Egret (formerly Edge Net Guardian v12). When assisting with this project, strictly follow these conventions and architectural guidelines.

## 1. Project Paradigm
*   **Language:** Python 3.13 for backend, TypeScript for the web UI, C++/Qt6 for the native desktop client.
*   **Framework:** FastAPI for routing. Avoid using heavy ORMs (like SQLAlchemy); rely on the existing SQLite repository pattern and raw SQL queries.
*   **Native Code:** Do not blindly assume native execution is enabled. Handle enforcement cleanly using the `app/services/enforcement/backends/` adapters.

## 2. Code Organization & Patterns
*   **Services:** Always place business logic inside `app/services/`. Do not put logic directly in API route handlers (`app/api/v1/`).
*   **Storage & Migrations:** If a schema change is required, create a new explicitly ordered SQL migration file in `app/storage/migrations/`. Do not use automatic schema generation tools. Keep repository files (`app/storage/repositories/`) updated to map SQL responses to Python models.
*   **Web UI:** Build components in `app/ui/<feature>/`. Favor modular TypeScript files. Ensure `api.ts` clients match FastAPI router contracts. Built output lands in `app/web/dist/` and is served by `app/main.py`.
*   **Native UI:** `egret-qt/` is a compiled C++/Qt6 client that talks to the backend over HTTP only — it never imports `app.services` or opens the SQLite database. Target Qt 6.2 (Ubuntu 22.04) so no 6.4+ APIs. Prompting is opt-in and rate-limited by design: an unthrottled queue over a full connection list makes the desktop unusable.

## 3. Security & Safety
*   **Platform Specificity:** Do not inject Unix paths or commands into Windows logic and vice versa. Always utilize the platform-aware abstractions in `app/services/enforcement/backends`.
*   **Execution Flags:** Respect `EGRET_ENABLE_NATIVE_EXECUTION` (legacy `EDGE_NET_GUARDIAN_ENABLE_NATIVE_EXECUTION` is still accepted during migration). Test natively-modifying code in dry-run mode first if possible.
*   **Command Generation:** Real host commands come from `app/services/enforcement/native_commands.py`. The strings in `app/services/enforcement/compiler.py` are display previews only and are not valid to execute — keep the two in sync when changing either.
*   **Testing:** Maintain and expand `pytest` coverage inside `tests/`. New features must include tests reflecting the comprehensive nature of the v12 rollout (e.g., `test_v120_*.py`).

## 4. Dependencies
*   Assume the project relies heavily on core Python utilities and explicit imports rather than "magic" frameworks.
*   The frontend pins `bun` in `package.json`, but build tooling resolves a runner via `scripts/frontend_tool.py` and falls back to `npm`. Do not hardcode `bun` in scripts or tests.
*   Consult `docs/` (such as `docs/native-execution-v12.md` and `docs/antivirus-expansion-v12.md`) if unsure about the implementation constraints of a domain.
