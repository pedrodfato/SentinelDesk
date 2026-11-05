"""Deterministic detection rules.

Rules decide *what deserves a look*. They never decide what happened: that is
the investigation's job. Keeping this layer free of the LLM is what makes
alerts reproducible and auditable.
"""

from collections import defaultdict
from datetime import datetime

from pydantic import BaseModel

from backend.events import EventType, Outcome, SecurityEvent

BRUTEFORCE_RULE = "ssh_bruteforce_attempt"
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 60


class Alert(BaseModel):
    """One rule firing on one (source ip, host) pair."""

    rule: str
    host: str
    src_ip: str
    event_ids: list[str]
    first_seen: datetime
    last_seen: datetime


def detect_bruteforce(
    events: list[SecurityEvent],
    threshold: int = DEFAULT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> list[Alert]:
    """Flag `threshold` failed logins from one source ip within `window_seconds`.

    Thresholds are validated against the synthetic scenarios: the attack fires,
    the benign admin typing their password wrong does not.
    """
    by_origin: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if (
            event.event_type is EventType.LOGIN
            and event.result is Outcome.FAILURE
            and event.src_ip is not None
        ):
            by_origin[(event.src_ip, event.host)].append(event)

    alerts = []
    for (src_ip, host), failures in sorted(by_origin.items()):
        failures.sort(key=lambda e: e.timestamp)
        flagged: list[SecurityEvent] = []
        seen_ids = set()
        for start in range(len(failures) - threshold + 1):
            window = failures[start : start + threshold]
            span = (window[-1].timestamp - window[0].timestamp).total_seconds()
            if span <= window_seconds:
                for event in window:
                    if event.event_id not in seen_ids:
                        seen_ids.add(event.event_id)
                        flagged.append(event)

        if flagged:
            alerts.append(
                Alert(
                    rule=BRUTEFORCE_RULE,
                    host=host,
                    src_ip=src_ip,
                    event_ids=[event.event_id for event in flagged],
                    first_seen=flagged[0].timestamp,
                    last_seen=flagged[-1].timestamp,
                )
            )
    return alerts
