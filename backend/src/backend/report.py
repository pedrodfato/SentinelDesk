"""The investigation's output contract, and the deterministic checks it must survive.

The model writes the report. It does not get to decide whether the report is
trustworthy: that is settled here, in code, against evidence the tools actually
returned.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from backend.events import EventType, Outcome, SecurityEvent

Classification = Literal["true_positive", "false_positive", "inconclusive"]
Confidence = Literal["low", "medium", "high"]

# Deliberately small: only techniques this system can actually evidence.
# A real ATT&CK import belongs with the knowledge base, not here.
TECHNIQUES = {
    "T1110.001": "Brute Force: Password Guessing",
    "T1078": "Valid Accounts",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1053.003": "Scheduled Task/Job: Cron",
}


class Finding(BaseModel):
    """One claim, and the events that back it."""

    model_config = ConfigDict(extra="forbid")

    statement: str
    event_ids: list[str] = Field(min_length=1)
    techniques: list[str] = []


class IncidentReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: Classification
    incident_type: str
    compromised: bool
    summary: str
    findings: list[Finding]
    attacker_ip: str | None = None
    affected_host: str | None = None
    target_user: str | None = None
    confidence: Confidence
    gaps: list[str] = []

    def cited_event_ids(self) -> set[str]:
        return {event_id for finding in self.findings for event_id in finding.event_ids}

    def cited_techniques(self) -> set[str]:
        return {technique for finding in self.findings for technique in finding.techniques}


class Violation(BaseModel):
    kind: Literal["unknown_event", "unknown_technique", "unsupported_compromise"]
    detail: str


class ValidationResult(BaseModel):
    violations: list[Violation] = []
    cited_events: int = 0

    @property
    def ok(self) -> bool:
        return not self.violations

    @property
    def unsupported_claim_rate(self) -> float:
        """Share of cited evidence the tools never returned. Feeds the eval."""
        if not self.cited_events:
            return 0.0
        invented = sum(1 for v in self.violations if v.kind == "unknown_event")
        return invented / self.cited_events


def validate_report(
    report: IncidentReport,
    observed_events: dict[str, SecurityEvent],
) -> ValidationResult:
    """Check the report against what the tools actually returned.

    `observed_events` is the investigation's evidence pool: every event any tool
    handed back, keyed by id. An event that exists in the database but was never
    observed still counts as invented, because the model could not have read it.
    """
    violations: list[Violation] = []
    cited = report.cited_event_ids()

    for event_id in sorted(cited - observed_events.keys()):
        violations.append(
            Violation(
                kind="unknown_event",
                detail=f"{event_id} was cited but no tool returned it",
            )
        )

    for technique in sorted(report.cited_techniques() - TECHNIQUES.keys()):
        violations.append(
            Violation(
                kind="unknown_technique",
                detail=f"{technique} is not a technique this system recognises",
            )
        )

    if report.compromised:
        supported = any(
            event.event_type is EventType.LOGIN and event.result is Outcome.SUCCESS
            for event_id in cited
            if (event := observed_events.get(event_id)) is not None
        )
        if not supported:
            violations.append(
                Violation(
                    kind="unsupported_compromise",
                    detail="compromise claimed without a successful login among the cited events",
                )
            )

    return ValidationResult(violations=violations, cited_events=len(cited))
