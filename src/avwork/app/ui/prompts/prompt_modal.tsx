import React from "react";

type Props = {
  headline: string;
  rationale: string;
  onAllow: () => void;
  onBlock: () => void;
  onLater: () => void;
};

export function PromptModal({ headline, rationale, onAllow, onBlock, onLater }: Props) {
  return (
    <div className="rounded-2xl bg-white p-6 shadow-2xl">
      <h2 className="text-xl font-semibold text-slate-900">{headline}</h2>
      <p className="mt-2 text-sm text-slate-600">{rationale}</p>
      <div className="mt-6 flex gap-3">
        <button className="rounded-xl bg-emerald-600 px-4 py-2 text-sm text-white" onClick={onAllow}>Allow</button>
        <button className="rounded-xl bg-red-600 px-4 py-2 text-sm text-white" onClick={onBlock}>Block</button>
        <button className="rounded-xl border px-4 py-2 text-sm" onClick={onLater}>Ask later</button>
      </div>
    </div>
  );
}
