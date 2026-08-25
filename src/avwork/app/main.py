from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api import deps
from app.api.v1.connections import router as connections_router
from app.api.v1.decisions import router as decisions_router
from app.api.v1.enforcement import router as enforcement_router
from app.api.v1.files import router as files_router
from app.api.v1.health import router as health_router
from app.api.v1.ingest import router as ingest_router
from app.api.v1.investigations import router as investigations_router
from app.api.v1.protection import router as protection_router
from app.api.v1.quarantine import router as quarantine_router
from app.api.v1.release import router as release_router
from app.api.v1.remediation import router as remediation_router
from app.api.v1.scans import router as scans_router
from app.api.v1.updates import router as updates_router
from app.api.v1.ransomware import router as ransomware_router
from app.api.v1.threats import router as threats_router
from app.api.v1.rules import router as rules_router
from app.jobs.maintenance import run_maintenance_cycle
from app.jobs.startup import run_startup_tasks

UI_ROUTES = (
    '/behavior',
    '/connections',
    '/enforcement',
    '/files',
    '/health',
    '/investigations',
    '/protection',
    '/quarantine',
    '/ransomware',
    '/release',
    '/remediation',
    '/rules',
    '/scans',
    '/threats',
    '/updates',
)


#: How often expired rules and decisions are swept out. Running this only at
#: startup meant a "deny for 5 minutes" rule stayed listed as active until the
#: process restarted -- policy evaluation ignored it, but the UI still showed it.
MAINTENANCE_INTERVAL_SECONDS = 60


async def _maintenance_loop(state, interval: float) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            # Sync repository work belongs off the event loop.
            await asyncio.to_thread(run_maintenance_cycle, state.repositories)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a sweep failure must not kill the server
            logging.getLogger(__name__).exception('maintenance cycle failed')


@asynccontextmanager
async def lifespan(app: FastAPI):
    state = deps.get_bootstrap_state()
    app.state.bootstrap = state
    app.state.startup_summary = run_startup_tasks(state)

    interval = float(os.environ.get('EGRET_MAINTENANCE_INTERVAL', MAINTENANCE_INTERVAL_SECONDS))
    task = asyncio.create_task(_maintenance_loop(state, interval)) if interval > 0 else None
    try:
        yield
    finally:
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task


def create_app() -> FastAPI:
    app = FastAPI(title='Egret', lifespan=lifespan)
    ui_dist = Path(__file__).resolve().parent / 'web' / 'dist'
    ui_index = ui_dist / 'index.html'
    ui_assets = ui_dist / 'assets'
    if ui_assets.exists():
        app.mount('/assets', StaticFiles(directory=ui_assets), name='ui-assets')

    app.include_router(connections_router)
    app.include_router(ingest_router)
    app.include_router(decisions_router)
    app.include_router(rules_router)
    app.include_router(investigations_router)
    app.include_router(enforcement_router)
    app.include_router(files_router)
    app.include_router(threats_router)
    app.include_router(quarantine_router)
    app.include_router(protection_router)
    app.include_router(remediation_router)
    app.include_router(ransomware_router)
    app.include_router(scans_router)
    app.include_router(updates_router)
    app.include_router(health_router)
    app.include_router(release_router)

    @app.get('/healthz')
    def healthz() -> dict[str, str]:
        return {'status': 'ok'}

    @app.get('/', include_in_schema=False)
    def root():
        return RedirectResponse(url='/connections' if ui_index.exists() else '/docs')

    def ui_app():
        if ui_index.exists():
            return FileResponse(ui_index)
        return RedirectResponse(url='/docs')

    for route in UI_ROUTES:
        app.add_api_route(route, ui_app, methods=['GET'], include_in_schema=False)

    return app


app = create_app()
