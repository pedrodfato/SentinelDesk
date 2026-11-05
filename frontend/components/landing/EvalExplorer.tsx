"use client";

import {
  BracketsCurly,
  Check,
  Copy,
  CurrencyDollar,
  FileCode,
  Fingerprint,
  SealCheck,
  ShieldWarning,
  Siren,
  StackSimple,
  Target,
  Timer,
  type Icon,
} from "@phosphor-icons/react";
import { useState } from "react";

// Source lines are the real code from backend/src/backend; results are from
// evals/20261105T171517Z-gemini-3.1-flash-lite.json (3 scenarios, 2 investigations).
type Metric = {
  id: string;
  label: string;
  icon: Icon;
  file: string;
  source: string;
  result: string;
};

const METRICS: Metric[] = [
  {
    id: "evidence",
    label: "Evidence",
    icon: Fingerprint,
    file: "evaluation.py",
    source: `evidence = Scores.of(
    report.cited_event_ids(),
    set(truth.malicious_event_ids),
)
# precision: cited ids that belong to the attack
# recall: attack ids the report managed to cite`,
    result: `{
  "evidence_precision": 1.0,
  "evidence_recall": 1.0,
  "investigations": 2
}`,
  },
  {
    id: "techniques",
    label: "Techniques",
    icon: Target,
    file: "evaluation.py",
    source: `techniques = Scores.of(
    report.cited_techniques(),
    set(truth.expected_techniques),
)
# recall was 0.875 until the agent could list the catalogue:
# it only confirmed ids it guessed, and never guessed T1548.003`,
    result: `{
  "technique_precision": 1.0,
  "technique_recall": 1.0,
  "technique_recall_before_fix": 0.875
}`,
  },
  {
    id: "compromise",
    label: "Compromise",
    icon: ShieldWarning,
    file: "evaluation.py",
    source: `compromise_correct = (
    report is not None
    and report.compromised == truth.compromised
)`,
    result: `{
  "ssh_bruteforce_success": { "expected": true, "reported": true },
  "failed_ssh_bruteforce": { "expected": false, "reported": false }
}`,
  },
  {
    id: "detection",
    label: "Detection",
    icon: Siren,
    file: "evaluation.py",
    source: `alerts = detect_bruteforce(events)
detection.append(
    DetectionScore(
        scenario_id=truth.scenario_id,
        should_alert=truth.is_malicious,
        did_alert=bool(alerts),
    )
)`,
    result: `{
  "ssh_bruteforce_success": "alert",
  "failed_ssh_bruteforce": "alert",
  "benign_admin_typos": "silent",
  "detection_accuracy": 1.0
}`,
  },
  {
    id: "grounding",
    label: "Grounding",
    icon: SealCheck,
    file: "report.py",
    source: `for event_id in sorted(cited - observed_events.keys()):
    violations.append(
        Violation(
            kind="unknown_event",
            detail=f"{event_id} was cited but no tool returned it",
        )
    )`,
    result: `{
  "unsupported_claim_rate": 0.0,
  "rejected_reports": 0
}`,
  },
  {
    id: "steps",
    label: "Steps",
    icon: StackSimple,
    file: "investigation.py",
    source: `MAX_STEPS = 8

for index in range(1, max_steps + 1):
    turn = model.next_turn(conversation, TOOL_SCHEMAS)
    if turn.report is not None:
        status = "complete"
        break`,
    result: `{
  "ssh_bruteforce_success": { "steps": 2, "status": "complete" },
  "failed_ssh_bruteforce": { "steps": 2, "status": "complete" }
}`,
  },
  {
    id: "latency",
    label: "Latency",
    icon: Timer,
    file: "evaluation.py",
    source: `started = time.monotonic()
result = investigate(incident_id, model)
latency = int((time.monotonic() - started) * 1000)`,
    result: `{
  "ssh_bruteforce_success": 8827,
  "failed_ssh_bruteforce": 7717,
  "p50_latency_ms": 8827
}`,
  },
  {
    id: "cost",
    label: "Cost",
    icon: CurrencyDollar,
    file: "evaluation.py",
    source: `def _cost(runs):
    millions_in = sum(r.input_tokens for r in runs) / 1_000_000
    millions_out = sum(r.output_tokens for r in runs) / 1_000_000
    return millions_in * INPUT_PRICE + millions_out * OUTPUT_PRICE
# gemini-3.1-flash-lite: $0.25 in, $1.50 out per 1M tokens`,
    result: `{
  "total_input_tokens": 18934,
  "total_output_tokens": 985,
  "estimated_cost_usd": 0.006211
}`,
  },
];

const TOKEN =
  /(#.*$)|(f?"[^"]*"|'[^']*')|\b(def|for|in|if|is|not|and|None|return|break|true|false)\b/g;

/** Just enough colour to read the code: strings, keywords, comments. */
function highlight(line: string) {
  const parts: React.ReactNode[] = [];
  let last = 0;
  for (const match of line.matchAll(TOKEN)) {
    const at = match.index ?? 0;
    if (at > last) parts.push(line.slice(last, at));
    const [text, comment, string] = match;
    const tone = comment ? "text-faint" : string ? "text-accent" : "text-foreground";
    parts.push(
      <span key={at} className={tone}>
        {text}
      </span>,
    );
    last = at + text.length;
  }
  if (last < line.length) parts.push(line.slice(last));
  return parts;
}

export function EvalExplorer() {
  const [metricId, setMetricId] = useState("techniques");
  const [view, setView] = useState<"source" | "result">("source");
  const [copied, setCopied] = useState(false);

  const metric = METRICS.find((item) => item.id === metricId) ?? METRICS[0];
  const text = view === "source" ? metric.source : metric.result;
  const lines = text.split("\n");

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard refused (insecure context or permissions): nothing to undo.
    }
  }

  return (
    <div>
      <div
        role="tablist"
        aria-label="Metric"
        // Mobile: one row that scrolls sideways, bleeding to the screen edge, with
        // a fade on the right as the cue that more sits off-screen.
        // From md up: the row wraps and centres, nothing scrolls.
        className="no-scrollbar -mx-6 flex snap-x snap-mandatory gap-3 overflow-x-auto px-6 pb-1 [mask-image:linear-gradient(to_right,black_82%,transparent)] md:mx-auto md:max-w-4xl md:flex-wrap md:justify-center md:gap-y-5 md:overflow-visible md:px-0 md:[mask-image:none]"
      >
        {METRICS.map((item) => {
          const active = item.id === metric.id;
          const ItemIcon = item.icon;
          return (
            <button
              key={item.id}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={(event) => {
                setMetricId(item.id);
                // A half-visible tab on mobile slides fully into view when picked.
                event.currentTarget.scrollIntoView({ block: "nearest", inline: "nearest" });
              }}
              className="group flex w-20 shrink-0 snap-start flex-col items-center gap-2.5 focus-visible:outline-none"
            >
              <span
                className={`grid size-14 place-items-center rounded-xl border transition-colors group-focus-visible:outline-2 group-focus-visible:outline-offset-2 group-focus-visible:outline-accent group-active:translate-y-px ${
                  active
                    ? "border-border-strong bg-surface-raised text-accent shadow-[inset_0_1px_0_color-mix(in_oklab,var(--foreground)_10%,transparent)]"
                    : "border-border bg-surface text-muted group-hover:border-border-strong group-hover:text-foreground"
                }`}
              >
                <ItemIcon size={22} weight={active ? "fill" : "regular"} />
              </span>
              <span
                className={`text-[13px] transition-colors ${
                  active ? "font-medium text-foreground" : "text-muted group-hover:text-foreground"
                }`}
              >
                {item.label}
              </span>
            </button>
          );
        })}
      </div>

      <div className="mt-14 overflow-hidden rounded-2xl border border-border bg-surface">
        <div className="flex items-center justify-between gap-4 border-b border-border px-4 py-3">
          <div className="flex gap-1.5" role="tablist" aria-label="View">
            {(
              [
                ["source", metric.file, FileCode],
                ["result", "baseline.json", BracketsCurly],
              ] as const
            ).map(([key, label, TabIcon]) => (
              <button
                key={key}
                type="button"
                role="tab"
                aria-selected={view === key}
                onClick={() => setView(key)}
                className={`inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-[13px] transition-colors focus-visible:outline-2 focus-visible:outline-accent ${
                  view === key
                    ? "border border-border-strong bg-surface-raised text-foreground"
                    : "border border-transparent text-muted hover:text-foreground"
                }`}
              >
                <TabIcon size={14} />
                {label}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={copy}
            aria-label={copied ? "Copied" : "Copy to clipboard"}
            className="grid size-8 place-items-center rounded-md border border-border-strong text-muted transition-colors hover:text-foreground active:translate-y-px"
          >
            {copied ? <Check size={15} className="text-ok" /> : <Copy size={15} />}
          </button>
        </div>

        <pre
          key={`${metric.id}-${view}`}
          className="swap-in min-h-[17rem] overflow-x-auto py-6 font-mono text-[13px] leading-7 text-muted"
        >
          <code>
            {lines.map((line, index) => (
              <span key={index} className="grid grid-cols-[3.5rem_1fr]">
                <span className="select-none pr-5 text-right text-faint/70">{index + 1}</span>
                <span className="whitespace-pre pr-6">{highlight(line)}</span>
              </span>
            ))}
          </code>
        </pre>
      </div>
    </div>
  );
}
