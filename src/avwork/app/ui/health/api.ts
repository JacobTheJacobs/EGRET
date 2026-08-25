export type BackendCapability = {
  backend: string;
  native_execution_enabled: boolean;
  required_binaries: string[];
  available_binaries: string[];
  missing_binaries: string[];
  runnable: boolean;
};

export type HealthStatus = {
  status: string;
  generated_at: string;
  bootstrap: { db_path: string; applied_migrations: string[] };
  counts: { connections: number; rules: number };
  security: {
    ingest_token_configured: boolean;
    ingest_auth_headers: string[];
    secret_values_exposed: boolean;
  };
  enforcement_capabilities: BackendCapability[];
};

export async function fetchHealthStatus(baseUrl = ''): Promise<HealthStatus> {
  const response = await fetch(`${baseUrl}/api/v1/health/status`, { cache: 'no-store' });
  if (!response.ok) throw new Error(`Failed to fetch health: ${response.status}`);
  return response.json();
}
