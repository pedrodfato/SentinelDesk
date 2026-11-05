import { Check, Terminal, X } from "@phosphor-icons/react/dist/ssr";

import type { SecurityEvent } from "@/lib/api";
import { Mono } from "@/components/ui";

const TYPE_LABEL: Record<SecurityEvent["event_type"], string> = {
  login: "login",
  sudo: "sudo",
  cron_create: "cron",
};

function clock(timestamp: string) {
  return new Date(timestamp).toISOString().slice(11, 19);
}

function Outcome({ event }: { event: SecurityEvent }) {
  if (event.event_type !== "login") {
    return <Terminal size={14} className="text-muted" />;
  }
  return event.result === "success" ? (
    <Check size={14} className="text-warning" weight="bold" />
  ) : (
    <X size={14} className="text-faint" />
  );
}

/**
 * The observed events in time order. When a finding is selected, the events it
 * cites stay lit and the rest dim, so the reader sees exactly what backs the claim.
 */
export function Timeline({
  events,
  highlighted,
}: {
  events: SecurityEvent[];
  highlighted: Set<string>;
}) {
  const dimming = highlighted.size > 0;

  return (
    <ol className="divide-y divide-border">
      {events.map((event) => {
        const lit = highlighted.has(event.event_id);
        return (
          <li
            key={event.event_id}
            className={`grid grid-cols-[auto_1fr_auto] items-center gap-x-4 px-5 py-3 transition-opacity ${
              dimming && !lit ? "opacity-35" : "opacity-100"
            } ${lit ? "bg-accent/[0.06]" : ""}`}
          >
            <span className="grid size-7 place-items-center rounded-md border border-border bg-surface">
              <Outcome event={event} />
            </span>
            <div className="min-w-0">
              <div className="truncate text-sm text-foreground">
                {TYPE_LABEL[event.event_type]}
                {event.event_type === "login" ? ` ${event.result}` : ""}
                {event.username ? (
                  <span className="text-muted"> · {event.username}</span>
                ) : null}
              </div>
              <div className="mt-0.5 truncate">
                <Mono dim>
                  {event.src_ip ? `${event.src_ip} · ` : ""}
                  {event.host}
                </Mono>
              </div>
            </div>
            <div className="text-right">
              <Mono>{clock(event.timestamp)}</Mono>
              <div className="mt-0.5">
                <Mono dim>{event.event_id.split("-").at(-1)}</Mono>
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
