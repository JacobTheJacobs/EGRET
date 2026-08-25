export type TimelineItem = {
  kind: "connection" | "decision" | "trust_snapshot";
  ts: string;
  title: string;
  summary: Record<string, unknown>;
};

export async function fetchAssetTimeline(assetId: string): Promise<TimelineItem[]> {
  const response = await fetch(`/api/v1/investigations/assets/${assetId}/timeline`);
  if (!response.ok) throw new Error(`Failed to fetch timeline: ${response.status}`);
  const payload = await response.json();
  return payload.items ?? [];
}
