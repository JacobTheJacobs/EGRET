import React from "react";

export type AppSection =
  | "connections"
  | "rules"
  | "investigations"
  | "enforcement"
  | "files"
  | "threats"
  | "quarantine"
  | "protection"
  | "behavior"
  | "ransomware"
  | "remediation"
  | "scans"
  | "updates"
  | "health"
  | "release";

const labels: Record<AppSection, string> = {
  connections: "Connections",
  rules: "Rules",
  investigations: "Investigations",
  enforcement: "Enforcement",
  files: "Files",
  threats: "Threats",
  quarantine: "Quarantine",
  protection: "Protection",
  behavior: "Behavior",
  ransomware: "Ransomware",
  remediation: "Remediation",
  scans: "Scans",
  updates: "Updates",
  health: "Health",
  release: "Release",
};

type Props = {
  active: AppSection;
  children: React.ReactNode;
};

export function AppShell({ active, children }: Props) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl p-6">
        <header className="mb-6 flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-slate-800 pb-3">
          <span className="text-sm font-semibold tracking-tight text-sky-300">Egret</span>
          <nav className="flex flex-wrap gap-1">
            {Object.entries(labels).map(([key, label]) => (
              <a
                key={key}
                href={`/${key}`}
                className={`rounded-lg px-2.5 py-1 text-xs ${active === key ? "bg-sky-500 text-slate-950" : "text-slate-400 hover:text-slate-100"}`}
              >
                {label}
              </a>
            ))}
          </nav>
        </header>
        {children}
      </div>
    </div>
  );
}
