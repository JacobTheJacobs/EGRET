from __future__ import annotations

from dataclasses import dataclass

from app.api.security import ingest_security_status
from app.jobs.maintenance import MaintenanceSummary, run_maintenance_cycle
from app.storage.bootstrap import BootstrapState


@dataclass(frozen=True)
class StartupSummary:
    maintenance: MaintenanceSummary
    security: dict


def run_startup_tasks(state: BootstrapState) -> StartupSummary:
    maintenance = run_maintenance_cycle(state.repositories)
    return StartupSummary(maintenance=maintenance, security=ingest_security_status())
