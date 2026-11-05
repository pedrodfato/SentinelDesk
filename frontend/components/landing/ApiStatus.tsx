"use client";

import { useEffect, useState } from "react";

import { API_URL } from "@/lib/api";

const STATES = {
  checking: { label: "Checking API", dot: "bg-faint" },
  up: { label: "API online", dot: "bg-ok" },
  down: { label: "API offline", dot: "bg-danger" },
} as const;

/** A real health check, so the dot reports state instead of decorating. */
export function ApiStatus() {
  const [state, setState] = useState<keyof typeof STATES>("checking");

  useEffect(() => {
    let cancelled = false;
    fetch(`${API_URL}/health`, { cache: "no-store" })
      .then((response) => !cancelled && setState(response.ok ? "up" : "down"))
      .catch(() => !cancelled && setState("down"));
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <span className="inline-flex items-center gap-2 rounded-full bg-surface-raised px-3.5 py-1.5 text-[13px] text-foreground">
      <span className={`size-2 rounded-full ${STATES[state].dot}`} aria-hidden="true" />
      {STATES[state].label}
    </span>
  );
}
