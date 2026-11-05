import {
  BracketsCurly,
  CaretRight,
  Cpu,
  Crosshair,
  ShieldCheck,
} from "@phosphor-icons/react/dist/ssr";
import Link from "next/link";
import type { ReactNode } from "react";

import { ApiStatus } from "@/components/landing/ApiStatus";
import { EvalExplorer } from "@/components/landing/EvalExplorer";
import {
  FeatureCard,
  HostileInputVisual,
  ScopeVisual,
  TimelineVisual,
  ValidatorVisual,
} from "@/components/landing/FeatureCard";
import { Terminal } from "@/components/landing/Terminal";
import { API_URL } from "@/lib/api";

const NAV = [
  ["Evaluation", "#evaluation"],
  ["Pipeline", "#pipeline"],
  ["Defenses", "#defenses"],
] as const;

// One label per intent: every link into the product says "Open console".
const CONSOLE_LABEL = "Open console";

// Only links that lead somewhere real. Stack entries are facts, not links.
const FOOTER_COLUMNS: { title: string; items: { label: string; href?: string }[] }[] = [
  {
    title: "Product",
    items: [
      { label: "Console", href: "/incidents" },
      { label: "Evaluation", href: "#evaluation" },
      { label: "Pipeline", href: "#pipeline" },
      { label: "Defenses", href: "#defenses" },
    ],
  },
  {
    title: "API",
    items: [
      { label: "Reference", href: `${API_URL}/docs` },
      { label: "Incidents", href: `${API_URL}/incidents` },
      { label: "Health", href: `${API_URL}/health` },
    ],
  },
  {
    title: "Stack",
    items: [
      { label: "FastAPI" },
      { label: "PostgreSQL" },
      { label: "Gemini" },
      { label: "Next.js" },
    ],
  },
];

export default function LandingPage() {
  return (
    <main className="flex-1">
      <Nav />
      <Hero />

      <section id="evaluation" className="scroll-mt-16">
        <div className="mx-auto max-w-5xl px-6 py-28 text-center">
          <span className="relative mx-auto grid size-28 place-items-center rounded-[1.75rem] border border-border-strong bg-[linear-gradient(160deg,var(--surface-raised),var(--background))] shadow-[inset_0_1px_0_color-mix(in_oklab,var(--foreground)_12%,transparent),0_24px_60px_-28px_color-mix(in_oklab,var(--accent)_55%,transparent)]">
            <ShieldCheck size={52} weight="duotone" className="text-accent" />
            <span className="absolute left-2.5 top-2 rounded bg-background/70 px-1.5 font-mono text-[10px] text-muted">
              n=2
            </span>
          </span>
          <h2 className="mt-10 text-5xl font-semibold tracking-tighter text-balance md:text-6xl">
            Graded against <span className="text-accent">an answer key</span>
          </h2>
          <p className="mx-auto mt-5 max-w-2xl text-[17px] leading-relaxed text-muted">
            Every scenario ships with its ground truth. Pick a metric to see the code that
            computes it and the number it produced.
          </p>
          <div className="mt-14 text-left">
            <EvalExplorer />
          </div>
        </div>
      </section>

      <section id="pipeline" className="scroll-mt-16">
        <div className="mx-auto max-w-7xl px-6 py-28">
          <h2 className="text-5xl font-semibold leading-[1.04] tracking-tighter md:text-6xl">
            Evidence first,
            <br />
            <span className="text-muted">prose second</span>
          </h2>
          <p className="mt-5 max-w-xl text-[17px] leading-relaxed text-muted">
            Most security copilots write a convincing paragraph and leave the checking to you.
            Here the checking runs first.
          </p>
          <div className="mt-14 grid gap-10 md:grid-cols-2">
            <FeatureCard
              visual={<ValidatorVisual />}
              icon={<ShieldCheck size={22} />}
              title="Grounded validator"
              body="Every cited event must have come back from a tool in that investigation. Unknown techniques and unsupported compromise claims are rejected in code."
            />
            <FeatureCard
              visual={<TimelineVisual />}
              icon={<Cpu size={22} />}
              title="Bounded investigation"
              body="A rule raises the incident, the agent widens the search on its own, and the loop stops at eight steps. Every tool call is stored with its arguments."
            />
          </div>
        </div>
      </section>

      <section id="defenses" className="scroll-mt-16">
        <div className="mx-auto max-w-7xl px-6 py-28">
          <h2 className="max-w-3xl text-4xl font-semibold leading-[1.08] tracking-tighter text-balance md:text-5xl">
            Logs are written by the attacker too
          </h2>
          <p className="mt-5 max-w-xl text-[15px] leading-relaxed text-muted">
            A username can hold an instruction. The defenses sit in the architecture, where a
            persuasive string has nothing to reach.
          </p>

          <div className="mt-14 grid overflow-hidden rounded-xl border border-border bg-surface md:grid-cols-2">
            <Defense
              icon={<BracketsCurly size={20} />}
              title="Quoted, never obeyed"
              body="Tool output reaches the model wrapped and labelled as untrusted data. No tool can mark anything benign, so the instruction has nothing to call."
              visual={<HostileInputVisual />}
            />
            <Defense
              icon={<Crosshair size={20} />}
              title="Scope the model cannot change"
              body="The model picks the window and the filters. The data boundary comes from the incident and goes straight into the query."
              visual={<ScopeVisual />}
              divided
            />
          </div>
        </div>
      </section>

      <Closing />
      <Footer />
    </main>
  );
}

function Nav() {
  return (
    <header className="sticky top-0 z-20 bg-background/70 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-6 px-6">
        <Link href="/" className="flex items-center gap-2.5">
          <span className="grid size-7 place-items-center rounded-md bg-accent-fill text-foreground">
            <ShieldCheck size={16} weight="bold" />
          </span>
          <span className="text-[15px] font-semibold tracking-tight">SentinelDesk</span>
        </Link>
        <nav className="hidden items-center gap-8 text-sm text-muted md:flex">
          {NAV.map(([label, href]) => (
            <a key={href} href={href} className="transition-colors hover:text-foreground">
              {label}
            </a>
          ))}
        </nav>
        <Link
          href="/incidents"
          className="rounded-lg border border-border-strong bg-surface-raised/60 px-4 py-2 text-sm font-medium text-foreground transition-colors hover:border-foreground/30 active:translate-y-px"
        >
          {CONSOLE_LABEL}
        </Link>
      </div>
    </header>
  );
}

function Hero() {
  return (
    <section id="top" className="relative -mt-16 flex min-h-[100dvh] items-center overflow-hidden">
      <div className="hero-light" aria-hidden="true">
        <div className="hero-light__source" />
        <div className="hero-light__beam" />
        <div className="hero-light__ribbon" />
      </div>

      <div className="relative mx-auto grid w-full max-w-7xl items-center gap-14 px-6 pb-16 pt-28 lg:grid-cols-[1.15fr_1fr]">
        <div className="min-w-0">
          <a
            href="#evaluation"
            className="inline-flex items-center gap-1.5 rounded-full border border-border-strong bg-surface/60 px-3.5 py-1.5 text-[13px] text-foreground transition-colors hover:border-foreground/30"
          >
            Baseline: zero unsupported claims
            <CaretRight size={12} className="text-muted" />
          </a>
          <h1 className="mt-8 text-6xl font-semibold leading-[0.98] tracking-tighter md:text-7xl">
            Every finding
            <br />
            <span className="text-accent">cites its evidence.</span>
          </h1>
          <p className="mt-7 max-w-lg text-lg leading-relaxed text-muted">
            An AI agent investigates each incident from evidence it retrieved itself. Code
            rejects any claim it cannot prove.
          </p>
          <div className="mt-10 flex flex-wrap items-center gap-6">
            <PrimaryButton href="/incidents">{CONSOLE_LABEL}</PrimaryButton>
            <a
              href="#pipeline"
              className="text-sm font-medium text-muted transition-colors hover:text-foreground"
            >
              How it works
            </a>
          </div>
        </div>
        <Terminal />
      </div>
    </section>
  );
}

function Closing() {
  return (
    <section className="relative overflow-hidden pt-28">
      <div className="mx-auto max-w-7xl px-6 text-center">
        <h2 className="text-5xl font-semibold leading-[1.02] tracking-tighter md:text-7xl">
          Open an incident.
          <br />
          <span className="text-muted">Read the proof.</span>
        </h2>
        <div className="mt-10 flex justify-center">
          <Link
            href="/incidents"
            className="inline-flex items-center gap-2 rounded-lg border border-border-strong bg-surface-raised px-5 py-3 text-sm font-medium text-foreground transition-colors hover:border-foreground/30 active:translate-y-px"
          >
            {CONSOLE_LABEL}
            <CaretRight size={13} className="text-muted" />
          </Link>
        </div>
      </div>

      {/* Cropped by the footer's top edge, the way a stamp runs off a page. */}
      <div className="mt-24 h-[8.5vw] overflow-hidden" aria-hidden="true">
        <p className="wordmark select-none whitespace-nowrap text-center text-[15vw] font-bold leading-[0.8] tracking-tighter">
          SentinelDesk
        </p>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="relative border-t border-border-strong bg-[linear-gradient(to_bottom,var(--surface),var(--background)_60%)]">
      <div className="mx-auto grid max-w-7xl gap-12 px-6 pb-16 pt-14 md:grid-cols-[1.4fr_repeat(3,1fr)]">
        <div className="space-y-6">
          <p className="max-w-xs text-sm leading-relaxed text-muted">
            Synthetic data only. No production systems are touched.
          </p>
          <ApiStatus />
        </div>
        {FOOTER_COLUMNS.map((column) => (
          <div key={column.title}>
            <h3 className="text-sm font-medium text-foreground">{column.title}</h3>
            <ul className="mt-5 space-y-3.5 text-sm text-muted">
              {column.items.map((item) => (
                <li key={item.label}>
                  {item.href ? (
                    <a href={item.href} className="transition-colors hover:text-foreground">
                      {item.label}
                    </a>
                  ) : (
                    item.label
                  )}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </footer>
  );
}

function Defense({
  icon,
  title,
  body,
  visual,
  divided = false,
}: {
  icon: ReactNode;
  title: string;
  body: string;
  visual: ReactNode;
  divided?: boolean;
}) {
  return (
    <div
      className={`flex min-w-0 flex-col gap-6 p-6 sm:p-8 ${
        divided ? "border-t border-border md:border-l md:border-t-0" : ""
      }`}
    >
      <div className="md:h-[9.5rem]">{visual}</div>
      <div>
        <span className="text-foreground">{icon}</span>
        <h3 className="mt-3 text-lg font-medium tracking-tight">{title}</h3>
        <p className="mt-2 max-w-md text-sm leading-relaxed text-muted">{body}</p>
      </div>
    </div>
  );
}

function PrimaryButton({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link
      href={href}
      className="inline-flex items-center rounded-lg bg-accent-fill px-5 py-3 text-sm font-medium text-foreground shadow-[inset_0_1px_0_color-mix(in_oklab,var(--foreground)_18%,transparent)] transition-colors hover:bg-accent active:translate-y-px"
    >
      {children}
    </Link>
  );
}
