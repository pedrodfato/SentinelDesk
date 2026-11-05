import Link from "next/link";

import type { Incident } from "@/lib/api";
import { Badge, Mono } from "@/components/ui";

/** A rule name is a slug in the database and a sentence to a human. */
function ruleLabel(rule: string) {
  return rule.replaceAll("_", " ");
}

function formatWindow(firstSeen: string, lastSeen: string) {
  const start = new Date(firstSeen);
  const seconds = Math.max(
    1,
    Math.round((new Date(lastSeen).getTime() - start.getTime()) / 1000),
  );
  const clock = start.toISOString().slice(11, 19);
  return `${clock} · ${seconds}s`;
}

export function IncidentRow({ incident }: { incident: Incident }) {
  return (
    <Link
      href={`/incidents/${incident.incident_id}`}
      className="group grid grid-cols-[auto_1fr_auto] items-center gap-x-4 px-5 py-3.5 transition-colors hover:bg-surface-raised"
    >
      <Badge tone={incident.status === "open" ? "warning" : "neutral"}>{incident.status}</Badge>

      <div className="min-w-0">
        <div className="truncate text-sm text-foreground group-hover:text-accent">
          {ruleLabel(incident.rule)}
        </div>
        <div className="mt-0.5 truncate">
          <Mono dim>
            {incident.src_ip} → {incident.host} · {incident.event_ids.length} events
          </Mono>
        </div>
      </div>

      <div className="text-right">
        <Mono>{formatWindow(incident.first_seen, incident.last_seen)}</Mono>
        <div className="mt-0.5">
          <Mono dim>{incident.incident_id}</Mono>
        </div>
      </div>
    </Link>
  );
}
