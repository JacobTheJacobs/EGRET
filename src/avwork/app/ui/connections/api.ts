import type { ConnectionDetail, ConnectionFilters, ConnectionRow, DecisionCreateRequest, DecisionCreateResponse, HostCaptureSummary } from "./types";

function buildQuery(filters: ConnectionFilters): string {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") {
      return;
    }
    params.set(key, String(value));
  });
  const query = params.toString();
  return query ? `?${query}` : "";
}

export async function fetchConnections(filters: ConnectionFilters = {}): Promise<ConnectionRow[]> {
  const response = await fetch(`/api/v1/connections${buildQuery(filters)}`);
  if (!response.ok) throw new Error(`Failed to fetch connections: ${response.status}`);
  const payload = await response.json();
  return payload.items ?? [];
}

export async function fetchConnectionDetail(connectionId: string): Promise<ConnectionDetail> {
  const response = await fetch(`/api/v1/connections/${connectionId}`);
  if (!response.ok) throw new Error(`Failed to fetch connection detail: ${response.status}`);
  return response.json();
}

export async function submitDecision(payload: DecisionCreateRequest): Promise<DecisionCreateResponse> {
  const response = await fetch(`/api/v1/decisions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(`Failed to submit decision: ${response.status}`);
  return response.json();
}

export async function captureHostConnections(limit = 100): Promise<HostCaptureSummary> {
  const response = await fetch(`/api/v1/connections/capture-host`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ limit }),
  });
  if (!response.ok) throw new Error(`Failed to capture host connections: ${response.status}`);
  return response.json();
}
