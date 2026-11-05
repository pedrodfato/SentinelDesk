import { Suspense } from "react";

import { IncidentRow } from "@/components/IncidentRow";
import { EmptyState, ErrorState, Panel, PanelHeader, SkeletonRows } from "@/components/ui";
import { listIncidents } from "@/lib/api";

export default function Page() {
  return (
    <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-10">
      <header className="mb-8">
        {/* The display face is the one flourish that survives into the product,
            and it is allowed only here, where nobody has to scan it. */}
        <h1 className="text-4xl font-semibold tracking-tighter text-foreground">Incidents</h1>
        <p className="mt-1.5 text-sm text-muted">
          Raised by deterministic rules. Investigated on request.
        </p>
      </header>

      <Panel>
        <PanelHeader title="Open" meta="Newest first" />
        <Suspense fallback={<SkeletonRows rows={4} />}>
          <IncidentList />
        </Suspense>
      </Panel>
    </main>
  );
}

async function IncidentList() {
  let incidents;
  try {
    incidents = await listIncidents();
  } catch (error) {
    // An unreachable API and an empty queue look identical if you let them.
    return (
      <ErrorState
        title="Could not reach the API."
        detail={error instanceof Error ? error.message : String(error)}
      />
    );
  }

  if (incidents.length === 0) {
    return (
      <EmptyState
        title="No incidents."
        hint="Ingest a scenario: python -m backend.pipeline --scenario bruteforce"
      />
    );
  }

  return (
    <div className="divide-y divide-border">
      {incidents.map((incident) => (
        <IncidentRow key={incident.incident_id} incident={incident} />
      ))}
    </div>
  );
}
