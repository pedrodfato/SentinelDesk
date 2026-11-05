import { Play, Warning } from "@phosphor-icons/react/dist/ssr";

import type { Finding, InvestigationView } from "@/lib/api";
import { Badge, type Tone } from "@/components/ui";
import { TECHNIQUE_NAMES } from "./mitre";

const CLASSIFICATION: Record<string, { label: string; tone: Tone }> = {
  true_positive: { label: "True positive", tone: "danger" },
  false_positive: { label: "False positive", tone: "ok" },
  inconclusive: { label: "Inconclusive", tone: "warning" },
};

function InvestigateButton({ onClick, running }: { onClick: () => void; running: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={running}
      className="inline-flex items-center gap-2 rounded-lg bg-accent-fill px-4 py-2.5 text-sm font-medium text-foreground shadow-[inset_0_1px_0_color-mix(in_oklab,var(--foreground)_18%,transparent)] transition-colors hover:bg-accent active:translate-y-px disabled:cursor-not-allowed disabled:opacity-60"
    >
      <Play size={15} weight="fill" />
      {running ? "Investigating…" : "Investigate"}
    </button>
  );
}

function RunningState() {
  return (
    <div className="space-y-3 px-5 py-6">
      {["w-24", "w-full", "w-5/6", "w-2/3"].map((width, index) => (
        <div
          key={index}
          className={`h-3 animate-pulse rounded bg-surface-raised ${width}`}
        />
      ))}
      <p className="pt-2 text-xs text-faint">
        The agent is searching the window, attributing techniques and writing a report. This
        takes a few seconds.
      </p>
    </div>
  );
}

function FindingRow({
  finding,
  onSelect,
}: {
  finding: Finding;
  onSelect: (eventIds: string[]) => void;
}) {
  return (
    <button
      type="button"
      onMouseEnter={() => onSelect(finding.event_ids)}
      onFocus={() => onSelect(finding.event_ids)}
      onClick={() => onSelect(finding.event_ids)}
      className="block w-full border-l-2 border-accent-dim py-2 pl-4 text-left transition-colors hover:border-accent hover:bg-surface-raised/40 focus-visible:outline-2 focus-visible:outline-accent"
    >
      <p className="text-sm text-foreground">{finding.statement}</p>
      <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[11px] text-faint">
        <span>{finding.event_ids.length} events</span>
        {finding.techniques.map((technique) => (
          <span key={technique} className="text-accent" title={TECHNIQUE_NAMES[technique]}>
            {technique}
          </span>
        ))}
      </p>
    </button>
  );
}

/**
 * The analysis side: an empty state with the action, a skeleton while the agent
 * runs, or the finished report. A rejected report shows its violations first,
 * never hidden, because a failed check is the thing an analyst most needs to see.
 */
export function AnalysisPanel({
  investigation,
  running,
  error,
  onInvestigate,
  onSelectFinding,
}: {
  investigation: InvestigationView | null;
  running: boolean;
  error: string | null;
  onInvestigate: () => void;
  onSelectFinding: (eventIds: string[]) => void;
}) {
  if (running) return <RunningState />;

  if (!investigation) {
    return (
      <div className="px-5 py-12 text-center">
        <p className="text-sm text-muted">Not investigated yet.</p>
        <p className="mx-auto mt-2 max-w-xs text-xs text-faint">
          Run the agent to classify this incident and ground every finding in the events it
          retrieved.
        </p>
        {error ? <p className="mt-3 text-xs text-danger">{error}</p> : null}
        <div className="mt-6 flex justify-center">
          <InvestigateButton onClick={onInvestigate} running={running} />
        </div>
      </div>
    );
  }

  const { report, validation, steps, elapsed_ms, model } = investigation;
  const violations = validation?.violations ?? [];
  const classification = report ? CLASSIFICATION[report.classification] : null;
  const allTechniques = [
    ...new Set(report?.findings.flatMap((finding) => finding.techniques) ?? []),
  ];

  return (
    <div className="divide-y divide-border">
      {violations.length > 0 ? (
        <div className="flex gap-3 bg-danger/[0.07] px-5 py-4">
          <Warning size={18} className="mt-0.5 shrink-0 text-danger" />
          <div>
            <p className="text-sm font-medium text-danger">
              Report rejected by the validator
            </p>
            <ul className="mt-1.5 space-y-1 text-xs text-muted">
              {violations.map((violation, index) => (
                <li key={index}>{violation.detail}</li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}

      {report ? (
        <>
          <div className="space-y-4 px-5 py-5">
            <div className="flex flex-wrap items-center gap-2">
              {classification ? (
                <Badge tone={classification.tone}>{classification.label}</Badge>
              ) : null}
              <Badge tone={report.compromised ? "danger" : "ok"}>
                {report.compromised ? "Compromised" : "No compromise"}
              </Badge>
              <Badge tone="neutral">{report.confidence} confidence</Badge>
            </div>
            <p className="text-sm leading-relaxed text-foreground">{report.summary}</p>
          </div>

          <div className="px-5 py-5">
            <h3 className="text-xs font-medium uppercase tracking-wide text-faint">Findings</h3>
            <div
              className="mt-3 space-y-1"
              onMouseLeave={() => onSelectFinding([])}
            >
              {report.findings.map((finding, index) => (
                <FindingRow key={index} finding={finding} onSelect={onSelectFinding} />
              ))}
            </div>
          </div>

          {allTechniques.length > 0 ? (
            <div className="px-5 py-5">
              <h3 className="text-xs font-medium uppercase tracking-wide text-faint">
                MITRE ATT&CK
              </h3>
              <ul className="mt-3 space-y-2">
                {allTechniques.map((technique) => (
                  <li key={technique} className="flex items-baseline gap-3 text-sm">
                    <span className="font-mono text-accent">{technique}</span>
                    <span className="text-muted">{TECHNIQUE_NAMES[technique] ?? "unknown"}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {report.gaps.length > 0 ? (
            <div className="px-5 py-5">
              <h3 className="text-xs font-medium uppercase tracking-wide text-faint">Gaps</h3>
              <ul className="mt-3 space-y-1.5 text-sm text-muted">
                {report.gaps.map((gap, index) => (
                  <li key={index}>{gap}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </>
      ) : (
        <div className="px-5 py-6">
          <p className="text-sm text-muted">
            The agent stopped with status{" "}
            <span className="font-mono text-foreground">{investigation.status}</span> and produced
            no report.
          </p>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 px-5 py-3 font-mono text-[11px] text-faint">
        <span>
          {steps.length} tool {steps.length === 1 ? "step" : "steps"} ·{" "}
          {(elapsed_ms / 1000).toFixed(1)}s · {model}
        </span>
        <InvestigateButtonSmall onClick={onInvestigate} running={running} />
      </div>
    </div>
  );
}

function InvestigateButtonSmall({ onClick, running }: { onClick: () => void; running: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={running}
      className="rounded-md border border-border-strong px-2.5 py-1 text-muted transition-colors hover:text-foreground active:translate-y-px disabled:opacity-60"
    >
      Re-investigate
    </button>
  );
}
