import React from "react";
import { createRoot } from "react-dom/client";

import BehaviorPage from "./behavior/page";
import ConnectionsPage from "./connections/page";
import EnforcementPage from "./enforcement/page";
import FilesPage from "./files/page";
import HealthPage from "./health/page";
import InvestigationsPage from "./investigations/page";
import ProtectionPage from "./protection/page";
import QuarantinePage from "./quarantine/page";
import RansomwarePage from "./ransomware/page";
import ReleasePage from "./release/page";
import RemediationPage from "./remediation/page";
import RulesPage from "./rules/page";
import ScansPage from "./scans/page";
import ThreatsPage from "./threats/page";
import UpdatesPage from "./updates/page";
import "./styles.css";

const routes: Record<string, React.ComponentType> = {
  "/behavior": BehaviorPage,
  "/connections": ConnectionsPage,
  "/enforcement": EnforcementPage,
  "/files": FilesPage,
  "/health": HealthPage,
  "/investigations": InvestigationsPage,
  "/protection": ProtectionPage,
  "/quarantine": QuarantinePage,
  "/ransomware": RansomwarePage,
  "/release": ReleasePage,
  "/remediation": RemediationPage,
  "/rules": RulesPage,
  "/scans": ScansPage,
  "/threats": ThreatsPage,
  "/updates": UpdatesPage,
};

function AppRouter(): React.ReactElement {
  const Page = routes[window.location.pathname] ?? ConnectionsPage;
  return <Page />;
}

createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <AppRouter />
  </React.StrictMode>,
);
