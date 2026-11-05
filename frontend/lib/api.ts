// Mirrors the FastAPI schemas at http://localhost:8000/docs.
// Keep these in step with the backend models: they are the contract.

export type Incident = {
  incident_id: string;
  rule: string;
  scenario_id: string;
  host: string;
  src_ip: string;
  event_ids: string[];
  first_seen: string;
  last_seen: string;
  status: string;
};

export type SecurityEvent = {
  event_id: string;
  scenario_id: string;
  timestamp: string;
  host: string;
  event_type: "login" | "sudo" | "cron_create";
  result: "success" | "failure";
  username: string | null;
  src_ip: string | null;
  command: string | null;
  raw: string;
};

export type Finding = {
  statement: string;
  event_ids: string[];
  techniques: string[];
};

export type IncidentReport = {
  classification: "true_positive" | "false_positive" | "inconclusive";
  incident_type: string;
  compromised: boolean;
  summary: string;
  findings: Finding[];
  attacker_ip: string | null;
  affected_host: string | null;
  target_user: string | null;
  confidence: "low" | "medium" | "high";
  gaps: string[];
};

export type StoredInvestigation = {
  investigation_id: number;
  incident_id: string;
  status: "complete" | "rejected" | "incomplete" | "no_progress";
  report: IncidentReport | null;
  validation: { violations: { kind: string; detail: string }[] } | null;
  steps: { index: number; tool: string; events_returned: number }[];
  observed_event_ids: string[];
  elapsed_ms: number;
  model: string;
  created_at: string;
};

export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

/** Throws on non-2xx so callers never silently render an error body as data. */
async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`GET ${path} failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export function listIncidents() {
  return get<Incident[]>("/incidents");
}

export function getIncident(incidentId: string) {
  return get<{ incident: Incident; events: SecurityEvent[] }>(`/incidents/${incidentId}`);
}

export function getLatestInvestigation(incidentId: string) {
  return get<StoredInvestigation>(`/incidents/${incidentId}/investigation`);
}
