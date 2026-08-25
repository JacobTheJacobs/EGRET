import React from "react";
import type { ConnectionRow } from "./types";

type Props = {
  rows: ConnectionRow[];
  onSelect: (row: ConnectionRow) => void;
};

function VerdictBadge({ verdict }: { verdict: string }) {
  const classes =
    verdict === "deny"
      ? "bg-red-100 text-red-700"
      : verdict === "allow"
        ? "bg-emerald-100 text-emerald-700"
        : "bg-amber-100 text-amber-700";
  return <span className={`rounded-full px-2 py-1 text-xs font-medium ${classes}`}>{verdict}</span>;
}

export function ConnectionTable({ rows, onSelect }: Props) {
  return (
    <div className="overflow-hidden rounded-2xl bg-white shadow-sm">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead className="bg-slate-50 text-left text-slate-500">
          <tr>
            <th className="px-4 py-3 font-medium">App</th>
            <th className="px-4 py-3 font-medium">Destination</th>
            <th className="px-4 py-3 font-medium">Protocol</th>
            <th className="px-4 py-3 font-medium">Verdict</th>
            <th className="px-4 py-3 font-medium">Risk</th>
            <th className="px-4 py-3 font-medium">Trust</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rows.map((row) => {
            const destination = row.destination.matched_domain || row.destination.sni || row.destination.ip;
            const trustFlag = row.trust_flags?.rogue_ble_counter_reuse
              ? "BLE reuse"
              : row.trust_flags?.risky_ble_signature_counter
                ? "BLE risk"
                : "Healthy";
            return (
              <tr key={row.connection_id} className="cursor-pointer hover:bg-slate-50" onClick={() => onSelect(row)}>
                <td className="px-4 py-3">
                  <div className="font-medium text-slate-900">{row.process.name}</div>
                  <div className="text-xs text-slate-500">{row.process.signer_name || row.process.signer_status || "Unknown signer"}</div>
                </td>
                <td className="px-4 py-3">
                  <div className="font-medium text-slate-900">{destination}</div>
                  <div className="text-xs text-slate-500">{row.destination.ip}:{row.destination.port}</div>
                </td>
                <td className="px-4 py-3 text-slate-700">{row.destination.protocol || row.network_zone}</td>
                <td className="px-4 py-3"><VerdictBadge verdict={row.verdict} /></td>
                <td className="px-4 py-3 text-slate-700">
                  {typeof row.flow_risk_score === "number" ? row.flow_risk_score.toFixed(2) : "—"}
                </td>
                <td className="px-4 py-3 text-slate-700">{trustFlag}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
