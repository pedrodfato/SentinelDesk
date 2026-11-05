"""Integration tests. They need the Postgres container running, and skip if it is not."""

from datetime import timedelta

import psycopg
import pytest

from backend.db import (
    connect,
    events_by_ids,
    events_in_window,
    incident_id_for,
    init_schema,
    latest_investigation,
    store_events,
    store_incidents,
    store_investigation,
)
from backend.detection import detect_bruteforce
from backend.investigation import Investigation
from backend.report import Finding, IncidentReport
from backend.synthetic import (
    generate_bruteforce_scenario,
    generate_failed_bruteforce_scenario,
)


@pytest.fixture(scope="module", autouse=True)
def database():
    try:
        init_schema()
    except psycopg.OperationalError as exc:
        pytest.skip(f"Postgres unavailable: {exc}")
    with connect() as conn:
        conn.execute("TRUNCATE events, incidents, investigations")
    yield


@pytest.fixture
def scenario():
    return generate_bruteforce_scenario(seed=42)


def test_storing_events_twice_inserts_them_once(scenario):
    events, _ = scenario
    assert store_events(events) == len(events)
    assert store_events(events) == 0


def test_stored_event_round_trips_unchanged(scenario):
    events, _ = scenario
    store_events(events)
    stored = {e.event_id: e for e in events_by_ids([e.event_id for e in events])}
    assert stored == {e.event_id: e for e in events}


def test_window_query_filters_by_source_ip(scenario):
    events, truth = scenario
    store_events(events)
    window_start = events[0].timestamp - timedelta(minutes=1)
    window_end = events[-1].timestamp + timedelta(minutes=1)

    found = events_in_window(
        truth.scenario_id, window_start, window_end, src_ip=truth.attacker_ip
    )

    assert found
    assert {e.src_ip for e in found} == {truth.attacker_ip}
    assert found == sorted(found, key=lambda e: e.timestamp)


def test_incident_id_is_stable_so_reingestion_cannot_duplicate(scenario):
    events, _ = scenario
    alerts = detect_bruteforce(events)
    store_events(events)

    first_ids = store_incidents(alerts)
    second_ids = store_incidents(alerts)

    assert first_ids == second_ids == [incident_id_for(alerts[0])]
    with connect() as conn:
        count = conn.execute("SELECT count(*) FROM incidents").fetchone()[0]
    assert count == 1


def test_different_scenarios_get_different_incidents():
    """Two scenarios share rule, origin and start time: only the evidence differs."""
    attack_events, _ = generate_bruteforce_scenario(seed=42)
    failed_events, _ = generate_failed_bruteforce_scenario(seed=42)
    store_events(attack_events + failed_events)

    attack_ids = store_incidents(detect_bruteforce(attack_events))
    failed_ids = store_incidents(detect_bruteforce(failed_events))

    assert attack_ids != failed_ids
    with connect() as conn:
        rows = conn.execute("SELECT incident_id FROM incidents").fetchall()
    assert len(rows) == 2


def test_investigations_accumulate_and_latest_wins(scenario):
    """Re-running an incident is the audit trail, so rows add up instead of replacing."""
    events, _ = scenario
    store_events(events)
    incident_id = store_incidents(detect_bruteforce(events))[0]

    assert latest_investigation(incident_id) is None

    first = Investigation(incident_id=incident_id, status="incomplete", elapsed_ms=10)
    second = Investigation(
        incident_id=incident_id,
        status="complete",
        elapsed_ms=20,
        report=IncidentReport(
            classification="true_positive",
            incident_type="successful_ssh_bruteforce",
            compromised=False,
            summary="second run",
            findings=[Finding(statement="failures", event_ids=[events[0].event_id])],
            confidence="low",
        ),
    )
    store_investigation(first, "fake-model")
    store_investigation(second, "fake-model")

    row = latest_investigation(incident_id)
    assert row["status"] == "complete"
    assert row["report"]["summary"] == "second run"
    assert row["elapsed_ms"] == 20


def test_investigation_without_a_report_still_stores(scenario):
    """An incomplete run is a real outcome, not an error: it must survive the round trip."""
    events, _ = scenario
    store_events(events)
    incident_id = store_incidents(detect_bruteforce(events))[0]

    store_investigation(
        Investigation(incident_id=incident_id, status="incomplete", elapsed_ms=5), "fake-model"
    )

    row = latest_investigation(incident_id)
    assert row["report"] is None
    assert row["status"] == "incomplete"
