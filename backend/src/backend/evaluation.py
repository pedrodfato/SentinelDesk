"""Measure the system against the answer key.

Two layers are scored separately on purpose. The detection rule is
deterministic, so a miss there is an application-logic bug. The investigation
is not, so a miss there is a model or prompt problem. Collapsing them into one
number would hide which half to fix.
"""

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

from backend import db
from backend.detection import detect_bruteforce
from backend.investigation import Model, investigate
from backend.synthetic import GroundTruth, SecurityEvent
from backend.pipeline import SCENARIOS

# Per million tokens. Set from the provider's current price list; left unset the
# run reports tokens only, rather than inventing a number.
INPUT_PRICE = os.environ.get("LLM_INPUT_PRICE_PER_MTOK")
OUTPUT_PRICE = os.environ.get("LLM_OUTPUT_PRICE_PER_MTOK")


class Scores(BaseModel):
    precision: float
    recall: float

    @classmethod
    def of(cls, predicted: set[str], expected: set[str]) -> "Scores":
        if not predicted and not expected:
            return cls(precision=1.0, recall=1.0)
        hits = len(predicted & expected)
        return cls(
            precision=hits / len(predicted) if predicted else 0.0,
            recall=hits / len(expected) if expected else 0.0,
        )


class DetectionScore(BaseModel):
    scenario_id: str
    should_alert: bool
    did_alert: bool

    @property
    def correct(self) -> bool:
        return self.should_alert == self.did_alert


class InvestigationScore(BaseModel):
    scenario_id: str
    status: str
    classification_correct: bool
    compromise_correct: bool
    evidence: Scores
    techniques: Scores
    unsupported_claim_rate: float
    violations: list[str]
    steps: int
    latency_ms: int
    input_tokens: int
    output_tokens: int


class EvalReport(BaseModel):
    ran_at: datetime
    model: str
    detection: list[DetectionScore]
    investigations: list[InvestigationScore]

    @property
    def detection_accuracy(self) -> float:
        return _mean([score.correct for score in self.detection])

    def summary(self) -> dict:
        runs = self.investigations
        return {
            "detection_accuracy": self.detection_accuracy,
            "classification_accuracy": _mean([r.classification_correct for r in runs]),
            "compromise_accuracy": _mean([r.compromise_correct for r in runs]),
            "evidence_precision": _mean([r.evidence.precision for r in runs]),
            "evidence_recall": _mean([r.evidence.recall for r in runs]),
            "technique_precision": _mean([r.techniques.precision for r in runs]),
            "technique_recall": _mean([r.techniques.recall for r in runs]),
            "unsupported_claim_rate": _mean([r.unsupported_claim_rate for r in runs]),
            "rejected_reports": sum(1 for r in runs if r.status == "rejected"),
            "p50_latency_ms": _median([r.latency_ms for r in runs]),
            "total_input_tokens": sum(r.input_tokens for r in runs),
            "total_output_tokens": sum(r.output_tokens for r in runs),
            "estimated_cost_usd": _cost(runs),
        }


def _mean(values: list) -> float:
    return round(sum(float(v) for v in values) / len(values), 3) if values else 0.0


def _median(values: list[int]) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


def _cost(runs: list[InvestigationScore]) -> float | None:
    if INPUT_PRICE is None or OUTPUT_PRICE is None:
        return None
    millions_in = sum(r.input_tokens for r in runs) / 1_000_000
    millions_out = sum(r.output_tokens for r in runs) / 1_000_000
    return round(millions_in * float(INPUT_PRICE) + millions_out * float(OUTPUT_PRICE), 6)


def _ingest(name: str, seed: int) -> tuple[list[SecurityEvent], GroundTruth]:
    events, truth = SCENARIOS[name](seed=seed)
    db.store_events(events)
    db.store_incidents(detect_bruteforce(events))
    return events, truth


def run_eval(model_factory, model_name: str, seed: int = 42) -> EvalReport:
    """`model_factory` returns a fresh model per investigation, so token counts stay per run."""
    db.init_schema()
    detection: list[DetectionScore] = []
    investigations: list[InvestigationScore] = []

    for name in SCENARIOS:
        events, truth = _ingest(name, seed)
        alerts = detect_bruteforce(events)
        detection.append(
            DetectionScore(
                scenario_id=truth.scenario_id,
                should_alert=truth.is_malicious,
                did_alert=bool(alerts),
            )
        )

        for alert in alerts:
            incident_id = db.incident_id_for(alert)
            model = model_factory()
            started = time.monotonic()
            result = investigate(incident_id, model)
            latency = int((time.monotonic() - started) * 1000)

            report = result.report
            usage = getattr(model, "usage", None)
            investigations.append(
                InvestigationScore(
                    scenario_id=truth.scenario_id,
                    status=result.status,
                    classification_correct=(
                        report is not None
                        and (report.classification != "false_positive") == truth.is_malicious
                    ),
                    compromise_correct=(
                        report is not None and report.compromised == truth.compromised
                    ),
                    evidence=Scores.of(
                        report.cited_event_ids() if report else set(),
                        set(truth.malicious_event_ids),
                    ),
                    techniques=Scores.of(
                        report.cited_techniques() if report else set(),
                        set(truth.expected_techniques),
                    ),
                    unsupported_claim_rate=(
                        result.validation.unsupported_claim_rate if result.validation else 0.0
                    ),
                    violations=[v.kind for v in result.validation.violations]
                    if result.validation
                    else [],
                    steps=len(result.steps),
                    latency_ms=latency,
                    input_tokens=getattr(usage, "input_tokens", 0),
                    output_tokens=getattr(usage, "output_tokens", 0),
                )
            )

    return EvalReport(
        ran_at=datetime.now(timezone.utc),
        model=model_name,
        detection=detection,
        investigations=investigations,
    )


def print_report(report: EvalReport) -> None:
    print(f"\nmodel: {report.model}   ran at {report.ran_at.isoformat(timespec='seconds')}")

    print("\ndetection (deterministic)")
    for score in report.detection:
        mark = "ok  " if score.correct else "MISS"
        print(f"  {mark} {score.scenario_id:26} expected={score.should_alert} got={score.did_alert}")

    print("\ninvestigations")
    for run in report.investigations:
        print(f"  {run.scenario_id:26} status={run.status}")
        print(
            f"      classification={'ok' if run.classification_correct else 'WRONG'}"
            f"  compromise={'ok' if run.compromise_correct else 'WRONG'}"
            f"  violations={run.violations or 'none'}"
        )
        print(
            f"      evidence  P={run.evidence.precision:.2f} R={run.evidence.recall:.2f}"
            f"   technique P={run.techniques.precision:.2f} R={run.techniques.recall:.2f}"
        )
        print(
            f"      steps={run.steps}  {run.latency_ms}ms"
            f"  tokens={run.input_tokens}/{run.output_tokens}"
        )

    print("\nsummary")
    for key, value in report.summary().items():
        print(f"  {key:26} {value if value is not None else 'price not configured'}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Score the system against ground truth.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, default=Path("evals"))
    args = parser.parse_args()

    from backend.llm import DEFAULT_MODEL, GeminiModel

    report = run_eval(GeminiModel, DEFAULT_MODEL, seed=args.seed)
    print_report(report)

    args.out.mkdir(parents=True, exist_ok=True)
    stamp = report.ran_at.strftime("%Y%m%dT%H%M%SZ")
    path = args.out / f"{stamp}-{report.model}.json"
    path.write_text(
        json.dumps({**report.model_dump(mode="json"), "summary": report.summary()}, indent=2),
        encoding="utf-8",
    )
    print(f"\nsaved to {path}")


if __name__ == "__main__":
    main()
