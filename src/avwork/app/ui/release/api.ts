export async function fetchReleaseManifest() {
  const response = await fetch('/api/v1/release/manifest');
  if (!response.ok) {
    throw new Error('Failed to load release manifest');
  }
  return response.json();
}

export async function fetchRolloutReadiness() {
  const response = await fetch('/api/v1/release/rollout-readiness');
  if (!response.ok) {
    throw new Error('Failed to load rollout readiness');
  }
  return response.json();
}
