import { ArrowLeft } from "@phosphor-icons/react/dist/ssr";
import Link from "next/link";
import { notFound } from "next/navigation";

import { IncidentWorkspace } from "@/components/incident/IncidentWorkspace";
import { Badge, ErrorState, Mono } from "@/components/ui";
import { getIncident, getLatestInvestigation } from "@/lib/api";

function ruleLabel(rule: string) {
  return rule.replaceAll("_", " ");
}

export default async function IncidentDetailPage(props: PageProps<"/incidents/[id]">) {
  const { id } = await props.params;

  let detail;
  let investigation;
  try {
    // One round trip would do, but two reads keep each endpoint single-purpose.
    [detail, investigation] = await Promise.all([
      getIncident(id),
      getLatestInvestigation(id),
    ]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // A 404 from the incident fetch means the incident is gone; anything else is the API.
    if (message.includes("404")) notFound();
    return (
      <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-10">
        <ErrorState title="Could not reach the API." detail={message} />
      </main>
    );
  }

  const { incident, events } = detail;

  return (
    <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-10">
      <Link
        href="/incidents"
        className="inline-flex items-center gap-1.5 text-sm text-muted transition-colors hover:text-foreground"
      >
        <ArrowLeft size={14} />
        Incidents
      </Link>

      <header className="mt-6 mb-8 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight text-foreground">
              {ruleLabel(incident.rule)}
            </h1>
            <Badge tone={incident.status === "open" ? "warning" : "neutral"}>
              {incident.status}
            </Badge>
          </div>
          <div className="mt-2">
            <Mono dim>
              {incident.src_ip} → {incident.host} · {incident.incident_id}
            </Mono>
          </div>
        </div>
      </header>

      <IncidentWorkspace
        incident={incident}
        alertEvents={events}
        initialInvestigation={investigation}
      />
    </main>
  );
}
