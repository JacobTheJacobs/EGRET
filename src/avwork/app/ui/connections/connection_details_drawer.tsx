import React, { useEffect, useState } from "react";
import { fetchConnectionDetail } from "./api";
import type { ConnectionDetail } from "./types";

type Props = {
  connectionId: string | null;
  onClose: () => void;
};

export function ConnectionDetailsDrawer({ connectionId, onClose }: Props) {
  const [detail, setDetail] = useState<ConnectionDetail | null>(null);

  useEffect(() => {
    if (!connectionId) {
      setDetail(null);
      return;
    }
    void fetchConnectionDetail(connectionId).then(setDetail).catch(() => setDetail(null));
  }, [connectionId]);

  if (!connectionId) {
    return null;
  }

  if (!detail) {
    return (
      <div className="fixed inset-y-0 right-0 z-20 w-full max-w-xl border-l bg-white p-6 shadow-2xl">
        <div className="mb-6 flex items-start justify-between">
          <h2 className="text-xl font-semibold text-slate-900">Loading connection details…</h2>
          <button className="rounded-xl border px-3 py-2 text-sm" onClick={onClose}>Close</button>
        </div>
      </div>
    );
  }

  const process = detail.process as { process_name?: string; process_path?: string; signer_name?: string; signer_status?: string };
  const destination = (detail.destination || {}) as {
    matched_domain?: string;
    sni?: string;
    ip?: string;
    port?: number;
    protocol?: string;
    certificate_subject?: string;
    certificate_issuer?: string;
  };

  const destinationName = destination.matched_domain || destination.sni || destination.ip || "Unknown destination";
  return (
    <div className="fixed inset-y-0 right-0 z-20 w-full max-w-xl overflow-y-auto border-l bg-white p-6 shadow-2xl">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h2 className="text-xl font-semibold text-slate-900">{process.process_name || "Unknown process"}</h2>
          <p className="text-sm text-slate-500">{destinationName}</p>
        </div>
        <button className="rounded-xl border px-3 py-2 text-sm" onClick={onClose}>Close</button>
      </div>

      <div className="space-y-5 text-sm">
        <section>
          <h3 className="mb-2 font-medium text-slate-900">Connection</h3>
          <div className="rounded-2xl bg-slate-50 p-4 text-slate-700">
            <div>{destination.ip}:{destination.port}</div>
            <div>{destination.protocol || (detail.connection.protocol as string) || "Unknown protocol"}</div>
            <div>{String(detail.connection.network_zone || "unknown")}</div>
          </div>
        </section>

        <section>
          <h3 className="mb-2 font-medium text-slate-900">Identity</h3>
          <div className="rounded-2xl bg-slate-50 p-4 text-slate-700">
            <div>{process.process_path || "Path unavailable"}</div>
            <div>{process.signer_name || "Unknown signer"}</div>
            <div>{process.signer_status || "Unknown trust status"}</div>
          </div>
        </section>

        <section>
          <h3 className="mb-2 font-medium text-slate-900">Explanation</h3>
          <div className="rounded-2xl bg-slate-50 p-4 text-slate-700">
            <div className="font-medium text-slate-900">{detail.explanation.headline}</div>
            <div className="mt-2">{detail.explanation.short_rationale}</div>
            <ul className="mt-3 list-disc space-y-1 pl-5">
              {detail.explanation.user_factors.map((factor) => (
                <li key={factor}>{factor}</li>
              ))}
            </ul>
          </div>
        </section>

        <section>
          <h3 className="mb-2 font-medium text-slate-900">Certificate</h3>
          <div className="rounded-2xl bg-slate-50 p-4 text-slate-700">
            <div>{destination.certificate_subject || "No subject"}</div>
            <div>{destination.certificate_issuer || "No issuer"}</div>
          </div>
        </section>
      </div>
    </div>
  );
}
