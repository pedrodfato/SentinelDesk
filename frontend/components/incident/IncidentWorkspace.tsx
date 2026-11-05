"use client";

import { useState } from "react";

import type { Incident, InvestigationView, SecurityEvent } from "@/lib/api";
import { runInvestigation } from "@/lib/api";
import { Panel, PanelHeader } from "@/components/ui";
import { AnalysisPanel } from "./AnalysisPanel";
import { Timeline } from "./Timeline";

/**
 * Holds the investigation state for one incident: the Investigate action, the
 * result, and which events a hovered finding points at. The timeline (left) and
 * the analysis (right) are driven from here so a finding can light its evidence.
 */
export function IncidentWorkspace({
  incident,
  alertEvents,
  initialInvestigation,
}: {
  incident: Incident;
  alertEvents: SecurityEvent[];
  initialInvestigation: InvestigationView | null;
}) {
  const [investigation, setInvestigation] = useState(initialInvestigation);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [highlighted, setHighlighted] = useState<Set<string>>(new Set());

  async function investigate() {
    if (running) return; // guard: the call is slow and billed, never fire twice
    setRunning(true);
    setError(null);
    try {
      setInvestigation(await runInvestigation(incident.incident_id));
    } catch {
      setError("The investigation could not be completed. Is the API running?");
    } finally {
      setRunning(false);
    }
  }

  // Before an investigation the timeline is the alert's events; after one it is
  // the fuller pool the agent observed (the login that succeeded, sudo, cron).
  const timelineEvents = investigation?.observed_events ?? alertEvents;

  return (
    <div className="grid gap-6 lg:grid-cols-[1.1fr_1fr]">
      <Panel className="h-fit">
        <PanelHeader title="Timeline" meta={`${timelineEvents.length} events`} />
        <Timeline events={timelineEvents} highlighted={highlighted} />
      </Panel>

      <Panel className="h-fit">
        <PanelHeader
          title="Analysis"
          meta={investigation ? `run #${investigation.investigation_id}` : "AI agent"}
        />
        <AnalysisPanel
          investigation={investigation}
          running={running}
          error={error}
          onInvestigate={investigate}
          onSelectFinding={(eventIds) => setHighlighted(new Set(eventIds))}
        />
      </Panel>
    </div>
  );
}
