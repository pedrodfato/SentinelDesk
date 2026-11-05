import type { ReactNode } from "react";

// The stored trace of inc_71525327e539 from the evaluation run: two tool
// rounds, 8.8s, 10,440 input and 571 output tokens. Rendered as the log it is,
// without imitation window chrome.
type Line = { at: string; kind: string; body: ReactNode };

const Val = ({ children }: { children: ReactNode }) => (
  <span className="text-foreground">{children}</span>
);

const LINES: Line[] = [
  {
    at: "09:25:23",
    kind: "alert",
    body: (
      <>
        8 failed logins from <Val>45.33.10.2</Val> on <Val>web-01</Val>
      </>
    ),
  },
  {
    at: "09:25:24",
    kind: "step 1",
    body: (
      <>
        search_events(host=<span className="text-accent">&quot;web-01&quot;</span>){" "}
        <span className="text-faint">→ 11 events</span>
      </>
    ),
  },
  {
    at: "09:25:26",
    kind: "step 2",
    body: (
      <>
        list_techniques() <span className="text-faint">→ 4 known</span>
      </>
    ),
  },
  {
    at: "09:25:31",
    kind: "report",
    body: <span className="text-warning">true_positive, compromised, confidence high</span>,
  },
  {
    at: "09:25:31",
    kind: "check",
    body: <span className="text-ok">11 of 11 events observed, 4 of 4 techniques known</span>,
  },
];

export function Terminal() {
  return (
    <figure className="min-w-0 overflow-hidden rounded-xl border border-border-strong bg-surface shadow-[0_30px_80px_-40px_rgb(0_0_0/0.9)]">
      <figcaption className="flex items-baseline justify-between gap-4 border-b border-border px-5 py-3.5 font-mono text-[12px]">
        <span className="text-foreground">inc_71525327e539</span>
        <span className="text-faint">investigation trace</span>
      </figcaption>

      <div className="space-y-3 overflow-x-auto px-5 py-6 font-mono text-[12.5px] leading-relaxed text-muted">
        <p className="term-line whitespace-nowrap" style={{ animationDelay: "200ms" }}>
          <span className="text-accent">$</span>{" "}
          <span className="text-foreground">sentineldesk investigate inc_71525327e539</span>
        </p>
        {LINES.map((line, index) => (
          <p
            key={index}
            className="term-line grid grid-cols-[auto_7ch_1fr] gap-x-3 whitespace-nowrap"
            style={{ animationDelay: `${500 + index * 280}ms` }}
          >
            <span className="text-[11px] text-faint">{line.at}</span>
            <span className="text-faint">{line.kind}</span>
            <span>{line.body}</span>
          </p>
        ))}
      </div>

      <div
        className="term-line flex items-baseline justify-between gap-4 border-t border-border px-5 py-4"
        style={{ animationDelay: `${500 + LINES.length * 280}ms` }}
      >
        <span className="text-sm font-medium text-ok">Report accepted</span>
        <span className="tabular font-mono text-[12px] text-muted">8.8s, $0.0035</span>
      </div>
    </figure>
  );
}
