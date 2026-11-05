import type { ReactNode } from "react";

/** Status colour is data, not decoration: the same meaning gets the same hue everywhere. */
const TONES = {
  neutral: "border-border-strong text-muted",
  accent: "border-accent-dim text-accent",
  danger: "border-danger/40 text-danger",
  warning: "border-warning/40 text-warning",
  ok: "border-ok/40 text-ok",
} as const;

export type Tone = keyof typeof TONES;

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: Tone }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide ${TONES[tone]}`}
    >
      {children}
    </span>
  );
}

/** Ids, ips and timestamps: scanned character by character, so mono and tabular. */
export function Mono({ children, dim = false }: { children: ReactNode; dim?: boolean }) {
  return (
    <span className={`font-mono tabular text-[13px] ${dim ? "text-faint" : "text-muted"}`}>
      {children}
    </span>
  );
}

export function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-border bg-surface ${className}`}>
      {children}
    </section>
  );
}

export function PanelHeader({ title, meta }: { title: string; meta?: ReactNode }) {
  return (
    <header className="flex items-baseline justify-between border-b border-border px-5 py-3">
      <h2 className="text-sm font-medium text-foreground">{title}</h2>
      {meta ? <div className="text-xs text-faint">{meta}</div> : null}
    </header>
  );
}

/** Empty, loading and error are three different answers and must look different. */
export function EmptyState({ title, hint }: { title: string; hint?: ReactNode }) {
  return (
    <div className="px-5 py-16 text-center">
      <p className="text-sm text-muted">{title}</p>
      {hint ? <p className="mt-2 text-xs text-faint">{hint}</p> : null}
    </div>
  );
}

export function ErrorState({ title, detail }: { title: string; detail?: string }) {
  return (
    <div className="px-5 py-16 text-center">
      <p className="text-sm text-danger">{title}</p>
      {detail ? <p className="mt-2 font-mono text-xs text-faint">{detail}</p> : null}
    </div>
  );
}

export function SkeletonRows({ rows = 3 }: { rows?: number }) {
  return (
    <div className="divide-y divide-border">
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="flex items-center gap-4 px-5 py-4">
          <div className="h-3 w-44 animate-pulse rounded bg-surface-raised" />
          <div className="h-3 w-28 animate-pulse rounded bg-surface-raised" />
          <div className="ml-auto h-3 w-20 animate-pulse rounded bg-surface-raised" />
        </div>
      ))}
    </div>
  );
}
